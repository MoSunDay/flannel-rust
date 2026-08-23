//! Read-only interface/route queries. Port of the lookup half of
//! flannel `pkg/ip/iface.go` (upstream cdf76059).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{anyhow, bail};
use futures::stream::TryStreamExt;
use netlink_packet_route::address::AddressMessage;
use netlink_packet_route::link::LinkMessage;
use netlink_packet_route::route::RouteMessage;
use netlink_packet_route::AddressFamily;
use rtnetlink::RouteMessageBuilder;

use super::{
    addr_ip, compare_addrs, is_global_unicast, is_link_local_unicast, link_mtu, link_name,
    net_iface_of, nlerr, route_dst, route_gateway, route_oif, route_pref_source, NetIface, Netlink,
};

/// Dump all links (Go `net.Interfaces()`; dump order == kernel order,
/// i.e. ascending ifindex).
pub async fn list_links(nl: &Netlink) -> anyhow::Result<Vec<LinkMessage>> {
    let mut links = nl.handle.link().get().execute();
    let mut out = Vec::new();
    while let Some(link) = links.try_next().await.map_err(nlerr)? {
        out.push(link);
    }
    Ok(out)
}

/// Addresses of one interface, filtered by family
/// (Go `netlink.AddrList(link, family)`).
async fn list_iface_addrs(
    nl: &Netlink,
    index: u32,
    family: AddressFamily,
) -> anyhow::Result<Vec<AddressMessage>> {
    let mut addrs = nl
        .handle
        .address()
        .get()
        .set_link_index_filter(index)
        .execute();
    let mut out = Vec::new();
    while let Some(addr) = addrs.try_next().await.map_err(nlerr)? {
        if addr.header.family == family {
            out.push(addr);
        }
    }
    Ok(out)
}

/// Dump all routes, every family (Go `netlink.RouteList(nil, family)`
/// dumps too; the family filter is applied by the callers).
async fn list_routes(nl: &Netlink) -> anyhow::Result<Vec<RouteMessage>> {
    let mut routes = nl.handle.route().get(RouteMessage::default()).execute();
    let mut out = Vec::new();
    while let Some(route) = routes.try_next().await.map_err(nlerr)? {
        out.push(route);
    }
    Ok(out)
}

/// Single route lookup for a destination (Go `netlink.RouteGet`).
async fn route_get(nl: &Netlink, ip: IpAddr) -> anyhow::Result<Vec<RouteMessage>> {
    let msg = match ip {
        IpAddr::V4(v4) => RouteMessageBuilder::<Ipv4Addr>::new()
            .destination_prefix(v4, 32)
            .build(),
        IpAddr::V6(v6) => RouteMessageBuilder::<Ipv6Addr>::new()
            .destination_prefix(v6, 128)
            .build(),
    };
    let mut routes = nl.handle.route().get(msg).execute();
    let mut out = Vec::new();
    while let Some(route) = routes.try_next().await.map_err(nlerr)? {
        out.push(route);
    }
    Ok(out)
}

fn iface_from_links(links: &[LinkMessage], index: u32) -> anyhow::Result<NetIface> {
    links
        .iter()
        .find(|l| l.header.index == index)
        .map(net_iface_of)
        .ok_or_else(|| anyhow!("no such network interface with index {index}"))
}

/// Go `GetInterfaceIP4Addrs`: global/link-local unicast, non-deprecated
/// IPv4 addresses, sorted in preferred usage order.
pub async fn get_iface_ip4_addrs(nl: &Netlink, iface: &NetIface) -> anyhow::Result<Vec<IpAddr>> {
    let mut addrs = list_iface_addrs(nl, iface.index, AddressFamily::Inet).await?;
    addrs.sort_by(compare_addrs);
    let ips: Vec<IpAddr> = addrs
        .iter()
        .filter_map(|a| {
            let ip = addr_ip(a)?;
            let v4 = ip.is_ipv4();
            let usable = is_global_unicast(ip) || is_link_local_unicast(ip);
            let deprecated = a
                .header
                .flags
                .contains(netlink_packet_route::address::AddressHeaderFlags::Deprecated);
            (v4 && usable && !deprecated).then_some(ip)
        })
        .collect();
    if ips.is_empty() {
        bail!("no IPv4 address found for given interface");
    }
    Ok(ips)
}

/// Go `GetInterfaceIP6Addrs`: global/link-local unicast, non-deprecated
/// IPv6 addresses, sorted in preferred usage order.
pub async fn get_iface_ip6_addrs(nl: &Netlink, iface: &NetIface) -> anyhow::Result<Vec<IpAddr>> {
    let mut addrs = list_iface_addrs(nl, iface.index, AddressFamily::Inet6).await?;
    addrs.sort_by(compare_addrs);
    let ips: Vec<IpAddr> = addrs
        .iter()
        .filter_map(|a| {
            let ip = addr_ip(a)?;
            let usable = is_global_unicast(ip) || is_link_local_unicast(ip);
            let deprecated = a
                .header
                .flags
                .contains(netlink_packet_route::address::AddressHeaderFlags::Deprecated);
            (usable && !deprecated).then_some(ip)
        })
        .collect();
    if ips.is_empty() {
        bail!("no IPv6 address found for given interface");
    }
    Ok(ips)
}

/// Go `GetInterfaceIP4AddrMatch`: succeed iff the interface owns the
/// IPv4 address.
pub async fn get_interface_ip4_addr_match(
    nl: &Netlink,
    iface: &NetIface,
    match_addr: Ipv4Addr,
) -> anyhow::Result<()> {
    let addrs = list_iface_addrs(nl, iface.index, AddressFamily::Inet).await?;
    for addr in &addrs {
        if let Some(IpAddr::V4(v4)) = addr_ip(addr) {
            if v4 == match_addr {
                return Ok(());
            }
        }
    }
    bail!("no IPv4 address found for given interface")
}

/// Go `GetInterfaceIP6AddrMatch`: succeed iff the interface owns the
/// IPv6 address.
pub async fn get_interface_ip6_addr_match(
    nl: &Netlink,
    iface: &NetIface,
    match_addr: Ipv6Addr,
) -> anyhow::Result<()> {
    let addrs = list_iface_addrs(nl, iface.index, AddressFamily::Inet6).await?;
    for addr in &addrs {
        if let Some(IpAddr::V6(v6)) = addr_ip(addr) {
            if v6 == match_addr {
                return Ok(());
            }
        }
    }
    bail!("no IPv6 address found for given interface")
}

fn default_gateway_iface(
    routes: Vec<RouteMessage>,
    family: AddressFamily,
    zero: IpAddr,
    no_iface_err: &'static str,
    no_route_err: &'static str,
) -> anyhow::Result<(NetIface, Option<IpAddr>)> {
    // Go: `route.Dst == nil || route.Dst.String() == "0.0.0.0/0"`.
    let is_default = |r: &RouteMessage| {
        r.header.address_family == family
            && match route_dst(r) {
                None => true,
                Some(dst) => dst == zero && r.header.destination_prefix_length == 0,
            }
    };
    for route in routes.iter().filter(|r| is_default(r)) {
        let oif = route_oif(route).unwrap_or(0);
        if oif == 0 {
            bail!("{no_iface_err}");
        }
        // Look the interface up lazily so the gateway can be reported
        // together with it (Go only returns the interface).
        return Ok((
            NetIface {
                index: oif,
                name: String::new(),
            },
            route_gateway(route),
        ));
    }
    bail!("{no_route_err}")
}

/// Go `GetDefaultGatewayInterface`: interface of the first IPv4 default
/// route, plus its gateway.
pub async fn get_default_gateway_interface(
    nl: &Netlink,
) -> anyhow::Result<(NetIface, Option<IpAddr>)> {
    let routes = list_routes(nl).await?;
    let (mut iface, gw) = default_gateway_iface(
        routes,
        AddressFamily::Inet,
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        "found default route but could not determine interface",
        "unable to find default route",
    )?;
    iface.name = link_name_by_index(nl, iface.index).await?;
    Ok((iface, gw))
}

/// Go `GetDefaultV6GatewayInterface`: interface of the first IPv6
/// default route, plus its gateway.
pub async fn get_default_v6_gateway_interface(
    nl: &Netlink,
) -> anyhow::Result<(NetIface, Option<IpAddr>)> {
    let routes = list_routes(nl).await?;
    let (mut iface, gw) = default_gateway_iface(
        routes,
        AddressFamily::Inet6,
        IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        "found default v6 route but could not determine interface",
        "unable to find default v6 route",
    )?;
    iface.name = link_name_by_index(nl, iface.index).await?;
    Ok((iface, gw))
}

async fn link_name_by_index(nl: &Netlink, index: u32) -> anyhow::Result<String> {
    let mut links = nl.handle.link().get().match_index(index).execute();
    match links.try_next().await.map_err(nlerr)? {
        Some(link) => Ok(link_name(&link)),
        None => bail!("no such network interface with index {index}"),
    }
}

/// Go `net.InterfaceByName` (used by `LookupExtIface` when `--iface`
/// is not an IP literal).
pub async fn get_interface_by_name(nl: &Netlink, name: &str) -> anyhow::Result<NetIface> {
    let mut links = nl.handle.link().get().match_name(name).execute();
    match links.try_next().await.map_err(nlerr)? {
        Some(link) => Ok(net_iface_of(&link)),
        None => bail!("no such network interface"),
    }
}

/// Go `GetInterfaceByIP`: first interface owning the IPv4 address
/// (address matching, not route lookup).
pub async fn get_interface_by_ip(nl: &Netlink, ip: Ipv4Addr) -> anyhow::Result<NetIface> {
    let links = list_links(nl).await?;
    let want = IpAddr::V4(ip);
    for link in &links {
        let index = link.header.index;
        let mut addrs = nl
            .handle
            .address()
            .get()
            .set_link_index_filter(index)
            .execute();
        while let Some(addr) = addrs.try_next().await.map_err(nlerr)? {
            if addr.header.family == AddressFamily::Inet && addr_ip(&addr) == Some(want) {
                return Ok(net_iface_of(link));
            }
        }
    }
    bail!("no interface with given IP found")
}

/// Go `GetInterfaceByIP6`: first interface owning the IPv6 address.
pub async fn get_interface_by_ip6(nl: &Netlink, ip: Ipv6Addr) -> anyhow::Result<NetIface> {
    let links = list_links(nl).await?;
    let want = IpAddr::V6(ip);
    for link in &links {
        let index = link.header.index;
        let mut addrs = nl
            .handle
            .address()
            .get()
            .set_link_index_filter(index)
            .execute();
        while let Some(addr) = addrs.try_next().await.map_err(nlerr)? {
            if addr.header.family == AddressFamily::Inet6 && addr_ip(&addr) == Some(want) {
                return Ok(net_iface_of(link));
            }
        }
    }
    bail!("no interface with given IPv6 found")
}

/// Go `GetInterfaceBySpecificIPRouting`: route lookup returns both the
/// output interface and the preferred source address.
pub async fn get_interface_by_specific_ip_routing(
    nl: &Netlink,
    ip: IpAddr,
) -> anyhow::Result<(NetIface, Option<IpAddr>)> {
    let routes = route_get(nl, ip)
        .await
        .map_err(|e| anyhow!("couldn't lookup route to {ip}: {e}"))?;
    let links = list_links(nl).await?;
    for route in &routes {
        let oif = route_oif(route).unwrap_or(0);
        if oif == 0 {
            bail!("couldn't lookup interface: no such network interface with index 0");
        }
        let iface =
            iface_from_links(&links, oif).map_err(|e| anyhow!("couldn't lookup interface: {e}"))?;
        return Ok((iface, route_pref_source(route)));
    }
    bail!("no interface with given IP found")
}

/// Go `DirectRouting`: exactly one route and no gateway, i.e. the
/// destination is directly connected.
pub async fn direct_routing(nl: &Netlink, ip: IpAddr) -> anyhow::Result<bool> {
    let routes = route_get(nl, ip)
        .await
        .map_err(|e| anyhow!("couldn't lookup route to {ip}: {e}"))?;
    Ok(routes.len() == 1 && route_gateway(&routes[0]).is_none())
}

/// MTU of a link (0 when unknown), for `LookupExtIface`'s sanity check.
pub async fn get_link_mtu(nl: &Netlink, index: u32) -> anyhow::Result<u32> {
    let mut links = nl.handle.link().get().match_index(index).execute();
    match links.try_next().await.map_err(nlerr)? {
        Some(link) => Ok(link_mtu(&link)),
        None => bail!("no such network interface with index {index}"),
    }
}
