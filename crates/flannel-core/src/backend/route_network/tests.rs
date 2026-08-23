//! Unit tests for the route_network port: parity with the Go semantics of
//! pkg/backend/route_network.go (netns tests live in tests_netns.rs).

use super::spec::{
    add_to_route_list, remove_from_route_list, route_spec_equal, spec_of, RouteSpec,
};
use netlink_packet_route::AddressFamily;

fn lo_route(dst: &str, prefix_len: u8, gw: &str) -> RouteSpec {
    RouteSpec {
        dst: dst.parse().unwrap(),
        prefix_len,
        gateway: gw.parse().unwrap(),
        link_index: 1, // loopback always exists
        family: AddressFamily::Inet,
        onlink: false,
    }
}

#[test]
fn spec_display_mimics_go_route_string() {
    let r = lo_route("192.168.1.0", 24, "192.168.1.1");
    assert_eq!(
        r.to_string(),
        "{Ifindex: 1 Dst: 192.168.1.0/24 Src: <nil> Gw: 192.168.1.1 Table: main}"
    );
    // Go prints ListFlags() as "[onlink]" when FLAG_ONLINK is set.
    let mut flagged = r.clone();
    flagged.onlink = true;
    assert_eq!(
        flagged.to_string(),
        "{Ifindex: 1 Dst: 192.168.1.0/24 Src: <nil> Gw: 192.168.1.1 Flags: [onlink] Table: main}"
    );
}

#[test]
fn route_spec_equal_matches_go_route_equal() {
    // Go RouteEqual compares only Dst, Gw and LinkIndex.
    let a = lo_route("192.168.1.0", 24, "192.168.1.1");
    let mut b = a.clone();
    b.family = AddressFamily::Inet6; // ignored by Go RouteEqual
    assert!(route_spec_equal(&a, &b));

    let mut c = a.clone();
    c.gateway = "192.168.1.2".parse().unwrap();
    assert!(!route_spec_equal(&a, &c));

    let mut d = a.clone();
    d.prefix_len = 32;
    assert!(!route_spec_equal(&a, &d));

    let mut e = a.clone();
    e.link_index = 2;
    assert!(!route_spec_equal(&a, &e));
}

#[test]
fn add_route_list_dedups_equal_routes() {
    let mut list = Vec::new();
    let r1 = lo_route("192.168.1.0", 24, "192.168.1.1");
    let r1_dup = lo_route("192.168.1.0", 24, "192.168.1.1");
    let r2 = lo_route("192.168.1.0", 24, "192.168.1.2");

    add_to_route_list(&mut list, &r1);
    add_to_route_list(&mut list, &r1_dup); // already tracked: no-op
    assert_eq!(list.len(), 1);

    add_to_route_list(&mut list, &r2);
    assert_eq!(list.len(), 2);
    assert!(list.iter().any(|r| r.gateway == r1.gateway));
    assert!(list.iter().any(|r| r.gateway == r2.gateway));
}

#[test]
fn remove_route_list_drops_first_equal_entry() {
    let mut list = Vec::new();
    let r1 = lo_route("192.168.1.0", 24, "192.168.1.1");
    add_to_route_list(&mut list, &r1);
    remove_from_route_list(&mut list, &r1);
    assert!(list.is_empty());
    // Removing a missing route is a no-op.
    remove_from_route_list(&mut list, &r1);
    assert!(list.is_empty());
}

#[test]
fn spec_of_reads_kernel_route_fields() {
    let r = lo_route("192.168.0.0", 24, "192.168.0.1");
    let msg = r.to_message();
    let back = spec_of(&msg);
    assert_eq!(back.dst, r.dst);
    assert_eq!(back.prefix_len, r.prefix_len);
    assert_eq!(back.gateway, r.gateway);
    assert_eq!(back.link_index, r.link_index);
}

#[test]
fn to_message_carries_dst_gateway_oif_and_flags() {
    use crate::ip::iface::route_addr_to_ip;
    use netlink_packet_route::route::RouteAttribute;
    let mut r = lo_route("192.168.0.0", 24, "192.168.0.1");
    r.onlink = true;
    let m = r.to_message();
    assert_eq!(m.header.destination_prefix_length, 24);
    assert_eq!(m.header.address_family, AddressFamily::Inet);
    let mut dst = None;
    let mut gw = None;
    let mut oif = None;
    for a in &m.attributes {
        match a {
            RouteAttribute::Destination(d) => dst = route_addr_to_ip(d),
            RouteAttribute::Gateway(g) => gw = route_addr_to_ip(g),
            RouteAttribute::Oif(o) => oif = Some(*o),
            _ => {}
        }
    }
    assert_eq!(dst, Some("192.168.0.0".parse().unwrap()));
    assert_eq!(gw, Some("192.168.0.1".parse().unwrap()));
    assert_eq!(oif, Some(1));
    assert!(m
        .header
        .flags
        .contains(netlink_packet_route::route::RouteFlags::Onlink));
}

#[test]
fn to_message_supports_ipv6() {
    let mut r = lo_route("2001:db8::", 64, "2001:db8::1");
    r.family = AddressFamily::Inet6;
    let m = r.to_message();
    assert_eq!(m.header.address_family, AddressFamily::Inet6);
    assert_eq!(m.header.destination_prefix_length, 64);
}
