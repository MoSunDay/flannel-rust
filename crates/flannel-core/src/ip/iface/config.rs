//! Mutating address/route helpers. Port of the configuration half of
//! flannel `pkg/ip/iface.go` (upstream cdf76059): `EnsureV4/V6
//! AddressOnLink` and `AddBlackholeV4/V6Route`. Needs NET_ADMIN.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::bail;
use futures::stream::TryStreamExt;
use netlink_packet_route::route::{RouteMessage, RouteType};
use netlink_packet_route::AddressFamily;
use rtnetlink::RouteMessageBuilder;
use tracing::info;

use crate::ip::{IP4Net, IP6Net, IP4};

use super::{addr_ip, is_link_local_unicast, link_name, nlerr, route_dst, Netlink};

/// Existing v4 addresses of a link (family-filtered dump).
async fn iface_v4_addrs(
    nl: &Netlink,
    index: u32,
) -> anyhow::Result<Vec<netlink_packet_route::address::AddressMessage>> {
    let mut addrs = nl
        .handle
        .address()
        .get()
        .set_link_index_filter(index)
        .execute();
    let mut out = Vec::new();
    while let Some(addr) = addrs.try_next().await.map_err(nlerr)? {
        if addr.header.family == AddressFamily::Inet {
            out.push(addr);
        }
    }
    Ok(out)
}

async fn iface_v6_addrs(
    nl: &Netlink,
    index: u32,
) -> anyhow::Result<Vec<netlink_packet_route::address::AddressMessage>> {
    let mut addrs = nl
        .handle
        .address()
        .get()
        .set_link_index_filter(index)
        .execute();
    let mut out = Vec::new();
    while let Some(addr) = addrs.try_next().await.map_err(nlerr)? {
        if addr.header.family == AddressFamily::Inet6 {
            out.push(addr);
        }
    }
    Ok(out)
}

async fn name_of(nl: &Netlink, index: u32) -> anyhow::Result<String> {
    let mut links = nl.handle.link().get().match_index(index).execute();
    match links.try_next().await.map_err(nlerr)? {
        Some(link) => Ok(link_name(&link)),
        None => bail!("no such network interface with index {index}"),
    }
}

/// Go `EnsureV4AddressOnLink`: on `link`, keep exactly one IPv4 address
/// inside `ipn` and make it equal to `ipa` (remove other `ipn` members,
/// add `ipa` when missing).
pub async fn ensure_v4_address_on_link(
    nl: &Netlink,
    ipa: IP4Net,
    ipn: IP4Net,
    link_index: u32,
) -> anyhow::Result<()> {
    let name = name_of(nl, link_index).await?;
    let want_ip = IpAddr::V4(ipa.ip.to_std());
    let want_prefix = ipa.prefix_len as u8;

    let mut has_addr = false;
    for existing in iface_v4_addrs(nl, link_index).await? {
        let Some(eip) = addr_ip(&existing) else {
            continue;
        };
        if eip == want_ip && existing.header.prefix_len == want_prefix {
            has_addr = true;
            continue;
        }
        if let IpAddr::V4(v4) = eip {
            if ipn.contains(IP4(u32::from(v4))) {
                if let Err(e) = nl.handle.address().del(existing.clone()).execute().await {
                    bail!(
                        "failed to remove IP address {}/{} from {name}: {}",
                        v4,
                        existing.header.prefix_len,
                        nlerr(e)
                    );
                }
                info!(
                    "removed IP address {}/{} from {name}",
                    v4, existing.header.prefix_len
                );
            }
        }
    }

    if !has_addr {
        if let Err(e) = nl
            .handle
            .address()
            .add(link_index, want_ip, want_prefix)
            .execute()
            .await
        {
            bail!("failed to add IP address {ipa} to {name}: {}", nlerr(e));
        }
    }
    Ok(())
}

/// Go `EnsureV6AddressOnLink`: on `link`, keep exactly one non
/// link-local IPv6 address and make it equal to `ipa`; when multiple
/// addresses exist the extra ones are removed (the error messages tell
/// callers about it via `ipn`).
pub async fn ensure_v6_address_on_link(
    nl: &Netlink,
    ipa: IP6Net,
    ipn: IP6Net,
    link_index: u32,
) -> anyhow::Result<()> {
    let name = name_of(nl, link_index).await?;
    let want_ip = IpAddr::V6(ipa.ip.to_std());
    let want_prefix = ipa.prefix_len as u8;

    let existing_addrs = iface_v6_addrs(nl, link_index).await?;
    let mut only_link_local = true;
    let mut cleared = false;
    // Go reassigns existingAddrs inside a `range` (snapshot iteration);
    // `cleared` tracks that reassignment.
    for existing in &existing_addrs {
        let Some(eip) = addr_ip(existing) else {
            continue;
        };
        if is_link_local_unicast(eip) {
            continue;
        }
        if eip == want_ip && existing.header.prefix_len == want_prefix {
            return Ok(());
        }
        if let Err(e) = nl.handle.address().del(existing.clone()).execute().await {
            bail!(
                "failed to remove v6 IP address {ipn} from {name}: {}",
                nlerr(e)
            );
        }
        cleared = true;
        only_link_local = false;
    }
    if only_link_local {
        cleared = true;
    }

    if cleared {
        if let Err(e) = nl
            .handle
            .address()
            .add(link_index, want_ip, want_prefix)
            .execute()
            .await
        {
            bail!("failed to add v6 IP address {ipn} to {name}: {}", nlerr(e));
        }
    }
    Ok(())
}

/// True when a blackhole route for `dst` already exists in any table
/// (Go's `RouteListFiltered` with `RT_FILTER_DST|RT_FILTER_TYPE`).
async fn has_blackhole_route(
    nl: &Netlink,
    family: AddressFamily,
    dst: IpAddr,
    prefix_len: u8,
) -> anyhow::Result<bool> {
    let mut routes = nl.handle.route().get(RouteMessage::default()).execute();
    while let Some(route) = routes.try_next().await.map_err(nlerr)? {
        if route.header.address_family == family
            && route.header.kind == RouteType::BlackHole
            && route.header.destination_prefix_length == prefix_len
            && route_dst(&route) == Some(dst)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Go `AddBlackholeV4Route`: add a v4 blackhole route for `dst` unless
/// one already exists. Needs NET_ADMIN.
pub async fn add_blackhole_v4_route(nl: &Netlink, dst: IP4Net) -> anyhow::Result<()> {
    let dst_ip = IpAddr::V4(dst.ip.to_std());
    let prefix = dst.prefix_len as u8;
    if has_blackhole_route(nl, AddressFamily::Inet, dst_ip, prefix).await? {
        return Ok(());
    }
    let route = RouteMessageBuilder::<Ipv4Addr>::new()
        .destination_prefix(dst.ip.to_std(), prefix)
        .kind(RouteType::BlackHole)
        .build();
    nl.handle.route().add(route).execute().await.map_err(nlerr)
}

/// Go `AddBlackholeV6Route`: add a v6 blackhole route for `dst` unless
/// one already exists. Needs NET_ADMIN.
pub async fn add_blackhole_v6_route(nl: &Netlink, dst: IP6Net) -> anyhow::Result<()> {
    let dst_ip = IpAddr::V6(dst.ip.to_std());
    let prefix = dst.prefix_len as u8;
    if has_blackhole_route(nl, AddressFamily::Inet6, dst_ip, prefix).await? {
        return Ok(());
    }
    let route = RouteMessageBuilder::<Ipv6Addr>::new()
        .destination_prefix(dst.ip.to_std(), prefix)
        .kind(RouteType::BlackHole)
        .build();
    nl.handle.route().add(route).execute().await.map_err(nlerr)
}
