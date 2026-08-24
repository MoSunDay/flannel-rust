// Netlink crate-stack spike for the flannel-rust vxlan backend.
//
// Exercises the exact API surface the network plane needs, on
// rtnetlink / netlink-packet-route / netns-rs:
//   * read-only: link / address / route dumps (async, tokio) -- read.rs
//   * mutating: vxlan create, link set (up + mtu), addr add, ARP neigh
//     add, FDB (AF_BRIDGE) neigh add, route add/get/del, link del --
//     everything listed back before teardown -- write.rs
//
// Mutating ops are runtime-gated: on EPERM we print SKIP and exit 0,
// so the example still passes without NET_ADMIN.
//
// By default the mutating part runs inside a scratch netns created via
// netns-rs, so host networking is never touched. Set FLANNEL_SPIKE_NETNS=0
// to run in the current netns instead.
//
// Split into main.rs / read.rs / write.rs to keep every file small.

mod read;
mod write;

use std::net::Ipv4Addr;

use netlink_packet_route::neighbour::NeighbourAddress;
use rtnetlink::{new_connection, Error as RtError};

pub const NS_NAME: &str = "flannel-spike";
pub const LINK_NAME: &str = "flannel-spike";
pub const VNI: u32 = 100;
pub const DST_PORT: u16 = 8472;
pub const LINK_MTU: u32 = 1450;
// Address assigned to the vxlan device (flannel uses a /32 on vxlan).
pub const VTEP_ADDR: Ipv4Addr = Ipv4Addr::new(10, 42, 0, 1);
// Peer: overlay gateway IP (ARP entry), physical VTEP (FDB entry),
// and the peer subnet routed through the tunnel.
pub const PEER_MAC: [u8; 6] = [0x0a, 0x11, 0x22, 0x33, 0x44, 0x55];
pub const PEER_GW: Ipv4Addr = Ipv4Addr::new(10, 42, 1, 1);
pub const PEER_VTEP: Ipv4Addr = Ipv4Addr::new(192, 168, 77, 10);
pub const PEER_SUBNET: Ipv4Addr = Ipv4Addr::new(10, 42, 1, 0);

pub fn mac_str(mac: &[u8]) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Format a neighbour destination. For AF_BRIDGE dumps the kernel
/// returns NDA_DST as raw bytes (NeighbourAddress::Other), so decode
/// 4-byte values as IPv4.
pub fn neigh_addr_str(a: &NeighbourAddress) -> String {
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

pub fn rterr(e: RtError) -> anyhow::Error {
    anyhow::anyhow!("{e}")
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
            read::survey(&handle).await?;
            write::mutate(&handle, in_scratch_ns).await
        })
}
