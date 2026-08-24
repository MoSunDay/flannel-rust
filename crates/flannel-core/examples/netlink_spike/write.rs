// Mutating netlink ops (split out of the netlink spike), runtime-gated
// on NET_ADMIN, plus list-back and teardown.

use std::net::{IpAddr, Ipv4Addr};

use futures::stream::TryStreamExt;
use netlink_packet_route::{
    address::AddressAttribute,
    neighbour::{NeighbourAttribute, NeighbourFlags},
    route::{RouteMessage, RouteType},
    AddressFamily,
};
use rtnetlink::{Error as RtError, Handle, LinkUnspec, LinkVxlan, RouteMessageBuilder};

use crate::read::{fmt_route, link_summary};
use crate::{
    mac_str, neigh_addr_str, rterr, DST_PORT, LINK_MTU, LINK_NAME, PEER_GW, PEER_MAC, PEER_SUBNET,
    PEER_VTEP, VNI, VTEP_ADDR,
};

/// True when a netlink request was rejected with EPERM (missing
/// CAP_NET_ADMIN / not in a netns we own).
fn is_eperm(err: &RtError) -> bool {
    matches!(err,
        RtError::NetlinkError(msg)
            if msg.code.is_some_and(|c| c.get() == -libc::EPERM))
}

// ---------- mutating part (runtime-gated on NET_ADMIN) ----------

async fn link_index_by_name(handle: &Handle, name: &str) -> anyhow::Result<u32> {
    let mut links = handle.link().get().match_name(name).execute();
    match links.try_next().await.map_err(rterr)? {
        Some(link) => Ok(link.header.index),
        None => anyhow::bail!("link {name} not found after creation"),
    }
}

pub async fn mutate(handle: &Handle, in_scratch_ns: bool) -> anyhow::Result<()> {
    // (a) vxlan create:
    //     ip link add flannel-spike type vxlan id 100 dstport 8472 learning off
    let msg = LinkVxlan::new(LINK_NAME, VNI)
        .port(DST_PORT)
        .learning(false)
        .build();
    if let Err(e) = handle.link().add(msg).execute().await {
        if is_eperm(&e) {
            println!(
                "[cap] SKIP: no NET_ADMIN (EPERM on link add); \
                 mutating ops skipped. All netlink code still compiled."
            );
            return Ok(());
        }
        return Err(rterr(e));
    }
    println!(
        "[mut] created vxlan '{LINK_NAME}' vni={VNI} dstport={DST_PORT} \
         learning=off (scratch_ns={in_scratch_ns})"
    );

    let ifindex = link_index_by_name(handle, LINK_NAME).await?;

    // (b) link set up + MTU
    handle
        .link()
        .set(
            LinkUnspec::new_with_index(ifindex)
                .mtu(LINK_MTU)
                .up()
                .build(),
        )
        .execute()
        .await
        .map_err(rterr)?;
    println!("[mut] set up + mtu={LINK_MTU}");

    // (c) address assign (/32 on the vxlan device, flannel-style)
    handle
        .address()
        .add(ifindex, IpAddr::V4(VTEP_ADDR), 32)
        .execute()
        .await
        .map_err(rterr)?;
    println!("[mut] assigned {VTEP_ADDR}/32 to ifindex {ifindex}");

    // (d) ARP neigh: NUD_PERMANENT + RTN_UNICAST (matches Go AddARP)
    handle
        .neighbours()
        .add(ifindex, IpAddr::V4(PEER_GW))
        .link_layer_address(&PEER_MAC)
        .kind(RouteType::Unicast)
        .replace()
        .execute()
        .await
        .map_err(rterr)?;
    println!("[mut] added ARP neigh {PEER_GW} -> {}", mac_str(&PEER_MAC));

    // (e) FDB entry: AF_BRIDGE + NTF_SELF, MAC -> physical VTEP
    //     (matches Go AddFDB). NeighbourFlags::Own is NTF_SELF.
    handle
        .neighbours()
        .add_bridge(ifindex, &PEER_MAC)
        .flags(NeighbourFlags::Own)
        .destination(IpAddr::V4(PEER_VTEP))
        .replace()
        .execute()
        .await
        .map_err(rterr)?;
    println!("[mut] added FDB {} -> {PEER_VTEP}", mac_str(&PEER_MAC));

    // (f) route add: peer subnet via peer overlay IP on vxlan, onlink
    let route = RouteMessageBuilder::<Ipv4Addr>::new()
        .destination_prefix(PEER_SUBNET, 24)
        .gateway(PEER_GW)
        .output_interface(ifindex)
        .onlink()
        .build();
    handle
        .route()
        .add(route.clone())
        .execute()
        .await
        .map_err(rterr)?;
    println!("[mut] added route {PEER_SUBNET}/24 via {PEER_GW} onlink");

    list_back(handle, ifindex, &route).await?;

    // Teardown: route del, then link del (removes addr/neigh/FDB too).
    handle.route().del(route).execute().await.map_err(rterr)?;
    println!("[del] route {PEER_SUBNET}/24 removed");
    handle.link().del(ifindex).execute().await.map_err(rterr)?;
    println!("[del] link '{LINK_NAME}' removed");
    println!("SPIKE OK: full rtnetlink round-trip succeeded");
    Ok(())
}

async fn list_back(handle: &Handle, ifindex: u32, route: &RouteMessage) -> anyhow::Result<()> {
    println!("--- list back ---");

    let mut links = handle.link().get().match_index(ifindex).execute();
    if let Some(link) = links.try_next().await.map_err(rterr)? {
        let (name, mtu) = link_summary(&link);
        println!(
            "[list] link idx={ifindex} name={name} mtu={mtu} flags={:?}",
            link.header.flags
        );
    }

    let mut addrs = handle.address().get().execute();
    while let Some(addr) = addrs.try_next().await.map_err(rterr)? {
        if addr.header.index != ifindex || addr.header.family != AddressFamily::Inet {
            continue;
        }
        let ip = addr.attributes.iter().find_map(|a| match a {
            AddressAttribute::Address(ip) => Some(ip.to_string()),
            _ => None,
        });
        println!(
            "[list] addr on ifindex {ifindex}: {}/{}",
            ip.unwrap_or_default(),
            addr.header.prefix_len
        );
    }

    for (family, label) in [
        (AddressFamily::Inet, "neigh"),
        (AddressFamily::Bridge, "fdb"),
    ] {
        let mut neighs = handle
            .neighbours()
            .get()
            .set_address_family(family)
            .execute();
        while let Some(n) = neighs.try_next().await.map_err(rterr)? {
            if n.header.ifindex != ifindex {
                continue;
            }
            let mut dst = String::new();
            let mut ll = String::new();
            for attr in &n.attributes {
                match attr {
                    NeighbourAttribute::Destination(d) => dst = neigh_addr_str(d),
                    NeighbourAttribute::LinkLayerAddress(mac) => ll = mac_str(mac.as_slice()),
                    _ => {}
                }
            }
            println!(
                "[list] {label} dst={dst} lladdr={ll} state={:?} flags={:?}",
                n.header.state, n.header.flags
            );
        }
    }

    // RTM_GETROUTE with a Destination attribute does a single lookup.
    let mut got = handle.route().get(route.clone()).execute();
    if let Some(r) = got.try_next().await.map_err(rterr)? {
        println!("[list] route lookup hit: {}", fmt_route(&r));
    }
    Ok(())
}
