// Netlink crate-stack spike for the flannel-rust vxlan backend.
//
// Exercises the exact API surface the network plane needs, on
// rtnetlink / netlink-packet-route / netns-rs:
//   * read-only: link / address / route dumps (async, tokio)
//   * mutating: vxlan create, link set (up + mtu), addr add, ARP neigh
//     add, FDB (AF_BRIDGE) neigh add, route add/get/del, link del --
//     everything listed back before teardown.
//
// Mutating ops are runtime-gated: on EPERM we print SKIP and exit 0,
// so the example still passes without NET_ADMIN.
//
// By default the mutating part runs inside a scratch netns created via
// netns-rs, so host networking is never touched. Set FLANNEL_SPIKE_NETNS=0
// to run in the current netns instead.

use std::net::{IpAddr, Ipv4Addr};

use futures::stream::TryStreamExt;
use netlink_packet_route::{
    address::AddressAttribute,
    link::{LinkAttribute, LinkMessage},
    neighbour::{NeighbourAddress, NeighbourAttribute, NeighbourFlags},
    route::{RouteAddress, RouteAttribute, RouteMessage, RouteType},
    AddressFamily,
};
use rtnetlink::{
    new_connection, Error as RtError, Handle, LinkUnspec, LinkVxlan, RouteMessageBuilder,
};

const NS_NAME: &str = "flannel-spike";
const LINK_NAME: &str = "flannel-spike";
const VNI: u32 = 100;
const DST_PORT: u16 = 8472;
const LINK_MTU: u32 = 1450;
// Address assigned to the vxlan device (flannel uses a /32 on vxlan).
const VTEP_ADDR: Ipv4Addr = Ipv4Addr::new(10, 42, 0, 1);
// Peer: overlay gateway IP (ARP entry), physical VTEP (FDB entry),
// and the peer subnet routed through the tunnel.
const PEER_MAC: [u8; 6] = [0x0a, 0x11, 0x22, 0x33, 0x44, 0x55];
const PEER_GW: Ipv4Addr = Ipv4Addr::new(10, 42, 1, 1);
const PEER_VTEP: Ipv4Addr = Ipv4Addr::new(192, 168, 77, 10);
const PEER_SUBNET: Ipv4Addr = Ipv4Addr::new(10, 42, 1, 0);

fn mac_str(mac: &[u8]) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Format a neighbour destination. For AF_BRIDGE dumps the kernel
/// returns NDA_DST as raw bytes (NeighbourAddress::Other), so decode
/// 4-byte values as IPv4.
fn neigh_addr_str(a: &NeighbourAddress) -> String {
    match a {
        NeighbourAddress::Inet(ip) => ip.to_string(),
        NeighbourAddress::Inet6(ip) => ip.to_string(),
        NeighbourAddress::Other(b) if b.len() == 4 => {
            Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string()
        }
        NeighbourAddress::Other(b) => format!("raw({b:?})"),
        _ => String::from("?"),
    }
}

fn rterr(e: RtError) -> anyhow::Error {
    anyhow::anyhow!("{e}")
}

/// True when a netlink request was rejected with EPERM (missing
/// CAP_NET_ADMIN / not in a netns we own).
fn is_eperm(err: &RtError) -> bool {
    matches!(err,
        RtError::NetlinkError(msg)
            if msg.code.is_some_and(|c| c.get() == -libc::EPERM))
}

fn main() -> anyhow::Result<()> {
    // Clean up a stale scratch netns left over by a crashed run.
    if let Ok(stale) = netns_rs::NetNs::get(NS_NAME) {
        let _ = stale.remove();
    }

    let want_ns = std::env::var("FLANNEL_SPIKE_NETNS")
        .map(|v| v != "0")
        .unwrap_or(true);
    let ns = if want_ns {
        match netns_rs::NetNs::new(NS_NAME) {
            Ok(ns) => {
                println!("[netns] created scratch netns '{NS_NAME}', mutating ops run inside it");
                Some(ns)
            }
            Err(e) => {
                println!("[netns] cannot create scratch netns ({e}); using current netns");
                None
            }
        }
    } else {
        println!("[netns] FLANNEL_SPIKE_NETNS=0; using current netns");
        None
    };

    let result = match &ns {
        // run() enters the netns on this thread for the closure, then
        // switches back; the closure creates its own runtime (run_async).
        Some(ns) => ns
            .run(|_| run_async(true))
            .map_err(|e| anyhow::anyhow!("netns run: {e}"))?,
        None => run_async(false),
    };

    if let Some(ns) = ns {
        ns.remove()
            .map_err(|e| anyhow::anyhow!("netns remove: {e}"))?;
        println!("[netns] scratch netns removed");
    }
    result
}

fn run_async(in_scratch_ns: bool) -> anyhow::Result<()> {
    // A *current-thread* runtime keeps every netlink socket creation on
    // this thread, i.e. inside the netns we already entered. A
    // multi-thread runtime could open the socket on another (host)
    // thread and talk to the wrong netns.
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async move {
            let (connection, handle, _) =
                new_connection().map_err(|e| anyhow::anyhow!("new_connection: {e}"))?;
            tokio::spawn(connection);
            survey(&handle).await?;
            mutate(&handle, in_scratch_ns).await
        })
}

// ---------- read-only survey: links, addresses, routes ----------

fn link_summary(msg: &LinkMessage) -> (String, u32) {
    let mut name = String::from("?");
    let mut mtu = 0;
    for attr in &msg.attributes {
        match attr {
            LinkAttribute::IfName(n) => name = n.clone(),
            LinkAttribute::Mtu(m) => mtu = *m,
            _ => {}
        }
    }
    (name, mtu)
}

async fn survey(handle: &Handle) -> anyhow::Result<()> {
    println!("=== read-only survey (works without NET_ADMIN) ===");

    let mut links = handle.link().get().execute();
    let mut total = 0usize;
    while let Some(link) = links.try_next().await.map_err(rterr)? {
        total += 1;
        if total <= 8 {
            let (name, mtu) = link_summary(&link);
            println!(
                "  link  idx={:<3} name={:<16} mtu={}",
                link.header.index, name, mtu
            );
        }
    }
    println!("  links: {total} total");

    let mut addrs = handle.address().get().execute();
    let mut shown = 0usize;
    while let Some(addr) = addrs.try_next().await.map_err(rterr)? {
        if addr.header.family != AddressFamily::Inet {
            continue;
        }
        if shown < 8 {
            let ip = addr.attributes.iter().find_map(|a| match a {
                AddressAttribute::Address(ip) => Some(ip.to_string()),
                _ => None,
            });
            println!(
                "  addr  ifindex={:<3} {}/{}",
                addr.header.index,
                ip.unwrap_or_default(),
                addr.header.prefix_len
            );
        }
        shown += 1;
    }
    println!("  addrs: {shown} ipv4 total");

    // RouteMessage::default() has no Destination attribute, so
    // RouteGetRequest performs a full dump (NLM_F_DUMP).
    let mut routes = handle.route().get(RouteMessage::default()).execute();
    let mut shown_routes = 0usize;
    while let Some(route) = routes.try_next().await.map_err(rterr)? {
        if shown_routes < 8 {
            println!("  route {}", fmt_route(&route));
        }
        shown_routes += 1;
    }
    println!("  routes: {shown_routes} total");
    Ok(())
}

fn route_attr_ip(attrs: &[RouteAttribute], want_dst: bool) -> Option<IpAddr> {
    attrs.iter().find_map(|a| {
        let route_addr = match a {
            RouteAttribute::Destination(r) if want_dst => Some(r),
            RouteAttribute::Gateway(r) if !want_dst => Some(r),
            _ => None,
        }?;
        match route_addr {
            RouteAddress::Inet(v4) => Some(IpAddr::V4(*v4)),
            RouteAddress::Inet6(v6) => Some(IpAddr::V6(*v6)),
            _ => None,
        }
    })
}

fn fmt_route(route: &RouteMessage) -> String {
    let dst = route_attr_ip(&route.attributes, true)
        .map(|i| i.to_string())
        .unwrap_or_else(|| "default".into());
    let gw = route_attr_ip(&route.attributes, false)
        .map(|i| format!(" via {i}"))
        .unwrap_or_default();
    let oif = route
        .attributes
        .iter()
        .find_map(|a| match a {
            RouteAttribute::Oif(i) => Some(*i),
            _ => None,
        })
        .map(|i| format!(" dev#{i}"))
        .unwrap_or_default();
    format!(
        "{}/{}{}{} table={}",
        dst, route.header.destination_prefix_length, gw, oif, route.header.table
    )
}

// ---------- mutating part (runtime-gated on NET_ADMIN) ----------

async fn link_index_by_name(handle: &Handle, name: &str) -> anyhow::Result<u32> {
    let mut links = handle.link().get().match_name(name).execute();
    match links.try_next().await.map_err(rterr)? {
        Some(link) => Ok(link.header.index),
        None => anyhow::bail!("link {name} not found after creation"),
    }
}

async fn mutate(handle: &Handle, in_scratch_ns: bool) -> anyhow::Result<()> {
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
