//! Netlink-based interface/route helpers. Port of flannel
//! `pkg/ip/iface.go` (upstream cdf76059) onto rtnetlink 0.23 /
//! netlink-packet-route 0.33 (the API patterns verified in
//! `examples/netlink_spike.rs`).
//!
//! Go's vishvananda/netlink package opens a netlink socket per call; the
//! Rust port instead threads one small [`Netlink`] wrapper (owner of the
//! rtnetlink connection) through every helper, so one connection serves
//! a whole operation such as `ipmatch::lookup_ext_iface`. Error strings
//! mirror the Go originals.

pub mod config;
pub mod query;

pub use config::{
    add_blackhole_v4_route, add_blackhole_v6_route, ensure_v4_address_on_link,
    ensure_v6_address_on_link,
};
pub use query::{
    direct_routing, get_default_gateway_interface, get_default_v6_gateway_interface,
    get_iface_ip4_addrs, get_iface_ip6_addrs, get_interface_by_ip, get_interface_by_ip6,
    get_interface_by_name, get_interface_by_specific_ip_routing, get_interface_ip4_addr_match,
    get_interface_ip6_addr_match, get_link_mtu, list_links,
};

use std::cmp::Ordering;
use std::net::IpAddr;

use netlink_packet_route::address::{AddressAttribute, AddressHeaderFlags, AddressMessage};
use netlink_packet_route::link::{LinkAttribute, LinkMessage};
use netlink_packet_route::route::{RouteAttribute, RouteMessage};

/// Minimal interface description: the Rust stand-in for Go's
/// `*net.Interface` where only identity is needed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetIface {
    pub index: u32,
    pub name: String,
}

/// Thin owner of an rtnetlink connection. Constructed per operation via
/// `Netlink::new().await`; every helper in this module borrows it.
#[derive(Clone)]
pub struct Netlink {
    pub handle: rtnetlink::Handle,
}

impl Netlink {
    /// Open a netlink connection and spawn its connection task on the
    /// current tokio runtime.
    pub async fn new() -> anyhow::Result<Self> {
        let (connection, handle, _) = rtnetlink::new_connection()
            .map_err(|e| anyhow::anyhow!("failed to open netlink connection: {e}"))?;
        tokio::spawn(connection);
        Ok(Self { handle })
    }
}

/// Map an rtnetlink/netlink error into anyhow (display form, like the
/// spike's `rterr`).
pub(crate) fn nlerr(e: rtnetlink::Error) -> anyhow::Error {
    anyhow::anyhow!("{e}")
}

/// Address of an address message: `IFA_ADDRESS`, falling back to
/// `IFA_LOCAL` (point-to-point links carry the local address only).
pub(crate) fn addr_ip(msg: &AddressMessage) -> Option<IpAddr> {
    let mut local = None;
    for attr in &msg.attributes {
        match attr {
            AddressAttribute::Address(ip) => return Some(*ip),
            AddressAttribute::Local(ip) => local = Some(*ip),
            _ => {}
        }
    }
    local
}

/// Name of a link message (`?` placeholder when the attribute is
/// missing, like the spike's `link_summary`).
pub(crate) fn link_name(msg: &LinkMessage) -> String {
    msg.attributes
        .iter()
        .find_map(|a| match a {
            LinkAttribute::IfName(n) => Some(n.clone()),
            _ => None,
        })
        .unwrap_or_else(|| String::from("?"))
}

/// MTU of a link message (0 when the attribute is missing).
pub(crate) fn link_mtu(msg: &LinkMessage) -> u32 {
    msg.attributes
        .iter()
        .find_map(|a| match a {
            LinkAttribute::Mtu(m) => Some(*m),
            _ => None,
        })
        .unwrap_or(0)
}

/// Build a [`NetIface`] from a link dump entry.
pub(crate) fn net_iface_of(msg: &LinkMessage) -> NetIface {
    NetIface {
        index: msg.header.index,
        name: link_name(msg),
    }
}

fn route_attr_ip(route: &RouteMessage, want_dst: bool) -> Option<IpAddr> {
    route.attributes.iter().find_map(|a| {
        let addr = match a {
            RouteAttribute::Destination(r) if want_dst => r,
            RouteAttribute::Gateway(r) if !want_dst => r,
            _ => return None,
        };
        route_addr_to_ip(addr)
    })
}

pub(crate) fn route_addr_to_ip(addr: &netlink_packet_route::route::RouteAddress) -> Option<IpAddr> {
    use netlink_packet_route::route::RouteAddress;
    match addr {
        RouteAddress::Inet(v4) => Some(IpAddr::V4(*v4)),
        RouteAddress::Inet6(v6) => Some(IpAddr::V6(*v6)),
        _ => None,
    }
}

/// Route destination (`RTA_DST`), if any.
pub(crate) fn route_dst(route: &RouteMessage) -> Option<IpAddr> {
    route_attr_ip(route, true)
}

/// Route gateway (`RTA_GATEWAY`), if any.
pub(crate) fn route_gateway(route: &RouteMessage) -> Option<IpAddr> {
    route.attributes.iter().find_map(|a| match a {
        RouteAttribute::Gateway(g) => route_addr_to_ip(g),
        _ => None,
    })
}

/// Preferred source (`RTA_PREFSRC`), if any (Go: `route.Src`).
pub(crate) fn route_pref_source(route: &RouteMessage) -> Option<IpAddr> {
    route.attributes.iter().find_map(|a| match a {
        RouteAttribute::PrefSource(s) => route_addr_to_ip(s),
        _ => None,
    })
}

/// Output interface (`RTA_OIF`), if any.
pub(crate) fn route_oif(route: &RouteMessage) -> Option<u32> {
    route.attributes.iter().find_map(|a| match a {
        RouteAttribute::Oif(i) => Some(*i),
        _ => None,
    })
}

/// Go `net.IP.IsLinkLocalUnicast`: 169.254.0.0/16 (v4) or fe80::/10 (v6).
pub(crate) fn is_link_local_unicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, _, _] = v4.octets();
            a == 169 && b == 254
        }
        IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

/// Go `net.IP.IsGlobalUnicast`: not unspecified, loopback, multicast or
/// link-local unicast (note: broader than `std`'s unstable `is_global`).
pub(crate) fn is_global_unicast(ip: IpAddr) -> bool {
    !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast() && !is_link_local_unicast(ip)
}

/// Go `compareAddrs`: sort addresses in preferred usage order. Global
/// unicast beats link-local; permanent beats generated; non-temporary
/// beats temporary (`IFA_F_TEMPORARY` == `Secondary`, value 0x01).
pub(crate) fn compare_addrs(a: &AddressMessage, b: &AddressMessage) -> Ordering {
    let (Some(a_ip), Some(b_ip)) = (addr_ip(a), addr_ip(b)) else {
        return Ordering::Equal;
    };
    let (a_global, a_ll) = (is_global_unicast(a_ip), is_link_local_unicast(a_ip));
    let (b_global, b_ll) = (is_global_unicast(b_ip), is_link_local_unicast(b_ip));
    if a_global && b_ll {
        return Ordering::Less;
    }
    if a_ll && b_global {
        return Ordering::Greater;
    }
    let (af, bf) = (&a.header.flags, &b.header.flags);
    if af.contains(AddressHeaderFlags::Permanent) && !bf.contains(AddressHeaderFlags::Permanent) {
        return Ordering::Less;
    }
    if !af.contains(AddressHeaderFlags::Permanent) && bf.contains(AddressHeaderFlags::Permanent) {
        return Ordering::Greater;
    }
    if !af.contains(AddressHeaderFlags::Secondary) && bf.contains(AddressHeaderFlags::Secondary) {
        return Ordering::Less;
    }
    if af.contains(AddressHeaderFlags::Secondary) && !bf.contains(AddressHeaderFlags::Secondary) {
        return Ordering::Greater;
    }
    Ordering::Equal
}
