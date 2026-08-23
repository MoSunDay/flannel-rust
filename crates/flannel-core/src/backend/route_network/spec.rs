//! `RouteSpec`: the plain-data route description shared by the route
//! backends (part of the route_network.go port, upstream cdf76059), plus
//! the equality and bookkeeping helpers Go implements on
//! `[]netlink.Route`.

use crate::ip::iface::{route_dst, route_gateway, route_oif};
use netlink_packet_route::route::RouteMessage;
use netlink_packet_route::AddressFamily;
use rtnetlink::RouteMessageBuilder;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Subset of Go `netlink.Route` the route backends need: destination
/// network, gateway, outgoing interface, family, plus the onlink flag
/// (Go: `FLAG_ONLINK`, used only by ipip).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteSpec {
    /// Go `Route.Dst` (network address + mask).
    pub dst: IpAddr,
    pub prefix_len: u8,
    /// Go `Route.Gw`.
    pub gateway: IpAddr,
    /// Go `Route.LinkIndex`.
    pub link_index: u32,
    /// Go passes the family separately (`FAMILY_V4`/`FAMILY_V6`); it is
    /// carried here so a spec fully describes one netlink route.
    pub family: AddressFamily,
    /// Go `Flags: int(netlink.FLAG_ONLINK)`.
    pub onlink: bool,
}

/// Mimic Go `netlink.Route`'s `%v` format for the exact upstream log
/// strings (`Dst`/`Gw`/`Ifindex` fields).
impl fmt::Display for RouteSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{Ifindex: {} Dst: {}/{} Src: <nil> Gw: {}",
            self.link_index, self.dst, self.prefix_len, self.gateway
        )?;
        if self.onlink {
            // Go prints `ListFlags()` as `[onlink]` via `%s` on []string.
            write!(f, " Flags: [onlink]")?;
        }
        write!(f, " Table: main}}")
    }
}

fn ip4_of(ip: IpAddr) -> Ipv4Addr {
    match ip {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => Ipv4Addr::UNSPECIFIED,
    }
}

fn ip6_of(ip: IpAddr) -> Ipv6Addr {
    match ip {
        IpAddr::V6(v6) => v6,
        IpAddr::V4(_) => Ipv6Addr::UNSPECIFIED,
    }
}

impl RouteSpec {
    /// `{dst}/{prefix}` as Go prints `Route.Dst` (`*net.IPNet`).
    pub fn dst_net(&self) -> String {
        format!("{}/{}", self.dst, self.prefix_len)
    }

    /// Convert to the rtnetlink message for add/del (proto/scope default
    /// to boot/universe like Go's zero-value `netlink.Route`).
    pub fn to_message(&self) -> RouteMessage {
        match self.family {
            AddressFamily::Inet => {
                let mut b = RouteMessageBuilder::<Ipv4Addr>::new()
                    .destination_prefix(ip4_of(self.dst), self.prefix_len)
                    .output_interface(self.link_index);
                if let IpAddr::V4(g) = self.gateway {
                    b = b.gateway(g);
                }
                if self.onlink {
                    b = b.onlink();
                }
                b.build()
            }
            _ => {
                let mut b = RouteMessageBuilder::<Ipv6Addr>::new()
                    .destination_prefix(ip6_of(self.dst), self.prefix_len)
                    .output_interface(self.link_index);
                if let IpAddr::V6(g) = self.gateway {
                    b = b.gateway(g);
                }
                if self.onlink {
                    b = b.onlink();
                }
                b.build()
            }
        }
    }
}

/// Go `routeEqual`: Dst IP+mask, Gw and LinkIndex only; flags, protocol,
/// scope and table are intentionally not compared.
pub fn route_spec_equal(x: &RouteSpec, y: &RouteSpec) -> bool {
    x.dst == y.dst
        && x.prefix_len == y.prefix_len
        && x.gateway == y.gateway
        && x.link_index == y.link_index
}

/// Kernel-route variant of [`route_spec_equal`] (Go calls `routeEqual`
/// with a dumped `netlink.Route` on one side).
pub(crate) fn route_msg_matches(msg: &RouteMessage, spec: &RouteSpec) -> bool {
    route_dst(msg) == Some(spec.dst)
        && msg.header.destination_prefix_length == spec.prefix_len
        && route_gateway(msg) == Some(spec.gateway)
        && route_oif(msg) == Some(spec.link_index)
}

/// Approximate a [`RouteSpec`] from a kernel route (display only).
pub(crate) fn spec_of(msg: &RouteMessage) -> RouteSpec {
    RouteSpec {
        dst: route_dst(msg).unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        prefix_len: msg.header.destination_prefix_length,
        gateway: route_gateway(msg).unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        link_index: route_oif(msg).unwrap_or(0),
        family: msg.header.address_family,
        onlink: false,
    }
}

/// Go free `addToRouteList`: append unless an equal route is tracked.
pub(crate) fn add_to_route_list(routes: &mut Vec<RouteSpec>, route: &RouteSpec) {
    if !routes.iter().any(|r| route_spec_equal(r, route)) {
        routes.push(route.clone());
    }
}

/// Go free `removeFromRouteList`: drop the first equal entry.
pub(crate) fn remove_from_route_list(routes: &mut Vec<RouteSpec>, route: &RouteSpec) {
    if let Some(i) = routes.iter().position(|r| route_spec_equal(r, route)) {
        routes.remove(i);
    }
}

/// `removeFromRouteList` with a kernel route as the key (replacement).
pub(crate) fn remove_msg_from_route_list(routes: &mut Vec<RouteSpec>, msg: &RouteMessage) {
    if let Some(i) = routes.iter().position(|r| route_msg_matches(msg, r)) {
        routes.remove(i);
    }
}
