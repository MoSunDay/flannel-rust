use super::*;
use std::net::{Ipv4Addr, Ipv6Addr};

fn opts(public_ip: &str, public_ip_v6: &str) -> PublicIPOpts {
    PublicIPOpts {
        public_ip: public_ip.into(),
        public_ip_v6: public_ip_v6.into(),
    }
}

#[test]
fn get_ip_family_table() {
    let cases = [
        (true, false, IPV4_STACK),
        (false, true, IPV6_STACK),
        (true, true, DUAL_STACK),
    ];
    for (v4, v6, want) in cases {
        assert_eq!(get_ip_family(v4, v6).unwrap(), want, "v4={v4} v6={v6}");
    }
    assert_eq!(
        get_ip_family(false, false).unwrap_err().to_string(),
        "none defined stack"
    );
}

#[tokio::test]
async fn lookup_ext_iface_none_stack_rejected() {
    let nl = Netlink::new().await.unwrap();
    let err = lookup_ext_iface(&nl, "lo", "", "", NONE_STACK, &opts("", ""))
        .await
        .unwrap_err();
    assert_eq!(err.to_string(), "none matched ip stack");
}

#[tokio::test]
async fn lookup_ext_iface_invalid_regex_rejected() {
    let nl = Netlink::new().await.unwrap();
    let err = lookup_ext_iface(&nl, "", "(unclosed", "", IPV4_STACK, &opts("", ""))
        .await
        .unwrap_err();
    let want = "could not compile the IP address regex '(unclosed': ";
    assert!(err.to_string().starts_with(want), "got: {err}");
}

#[tokio::test]
async fn lookup_ext_iface_regex_no_match_lists_faces() {
    let nl = Netlink::new().await.unwrap();
    let err = lookup_ext_iface(&nl, "", "nomatchxyz", "", IPV4_STACK, &opts("", ""))
        .await
        .unwrap_err();
    let msg = err.to_string();
    let want = "could not match pattern nomatchxyz to any of the \
                available network interfaces (";
    assert!(msg.starts_with(want), "got: {msg}");
    // Go filters loopback too (127.0.0.1 is not IsGlobalUnicast): lo:[]
    assert!(msg.contains("lo:[]"), "got: {msg}");
}

// --- Scenario tests mirroring Go's match_test.go -------------------
// Need NET_ADMIN and the dummy module; run with
// `cargo test -p flannel-core ipmatch -- --ignored`.

fn ip_cmd(args: &str) {
    let status = std::process::Command::new("ip")
        .args(args.split_whitespace())
        .status()
        .unwrap();
    assert!(status.success(), "ip {args}");
}

fn setup_dummy() {
    ip_cmd("link add name dummy0 type dummy");
    ip_cmd("addr add 1.10.100.1 dev dummy0");
    ip_cmd("addr add 192.168.200.128 dev dummy0");
    ip_cmd("addr add 172.16.30.18 dev dummy0");
    ip_cmd("addr add 172.16.31.200 dev dummy0");
    ip_cmd("addr add 172.16.32.100 dev dummy0");
    ip_cmd("addr add 2001:db8::1/64 dev dummy0");
    ip_cmd("link set dummy0 up");
    ip_cmd("route add 172.16.32.254 via 172.16.32.100 dev dummy0");
}

fn teardown_dummy() {
    let _ = std::process::Command::new("ip")
        .args(["link", "set", "dummy0", "down"])
        .status();
    let _ = std::process::Command::new("ip")
        .args(["link", "delete", "dummy0"])
        .status();
    let _ = std::process::Command::new("ip")
        .args(["route", "del", "10.200.0.0/16"])
        .status();
}

#[tokio::test]
#[ignore]
async fn lookup_ext_iface_dummy_scenarios() {
    teardown_dummy();
    setup_dummy();
    let nl = Netlink::new().await.unwrap();
    let none = opts("", "");
    let v4 = |s: &str| Some(IpAddr::V4(s.parse::<Ipv4Addr>().unwrap()));

    // ByIfRegexForIPv4
    let ext = lookup_ext_iface(&nl, "", r"192\.168\.200\.\d+", "", IPV4_STACK, &none)
        .await
        .unwrap();
    assert_eq!(ext.iface_name, "dummy0");
    assert_eq!(ext.iface_addr, v4("192.168.200.128"));

    // ByIfRegexForName
    let ext = lookup_ext_iface(&nl, "", r"dummy\d+", "", IPV4_STACK, &none)
        .await
        .unwrap();
    assert_eq!(ext.iface_name, "dummy0");

    // ByName
    let ext = lookup_ext_iface(&nl, "dummy0", "", "", IPV4_STACK, &none)
        .await
        .unwrap();
    assert_eq!(ext.iface_name, "dummy0");

    // ByIPv4
    let ext = lookup_ext_iface(&nl, "172.16.30.18", "", "", IPV4_STACK, &none)
        .await
        .unwrap();
    assert_eq!(ext.iface_name, "dummy0");
    assert_eq!(ext.iface_addr, v4("172.16.30.18"));

    // ByIPv4DualStack
    let ext = lookup_ext_iface(&nl, "172.16.30.18", "", "", DUAL_STACK, &none)
        .await
        .unwrap();
    assert_eq!(ext.iface_name, "dummy0");
    assert_eq!(ext.iface_addr, v4("172.16.30.18"));
    assert_eq!(
        ext.iface_v6_addr,
        Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)))
    );

    // ByIfRegexMatchPublicIPv4
    let with_public = opts("172.16.30.18", "");
    let ext = lookup_ext_iface(&nl, "", r"172\.16\.30\.\d+", "", IPV4_STACK, &with_public)
        .await
        .unwrap();
    assert_eq!(ext.iface_name, "dummy0");
    assert_eq!(ext.ext_addr, v4("172.16.30.18"));

    // ByIfCanReach
    let ext = lookup_ext_iface(&nl, "", "", "172.16.32.254", IPV4_STACK, &none)
        .await
        .unwrap();
    assert_eq!(ext.iface_name, "dummy0");
    assert_eq!(ext.iface_addr, v4("172.16.32.100"));

    // Default gateway interface: whatever the host's default route is.
    let ext = lookup_ext_iface(&nl, "", "", "", IPV4_STACK, &none)
        .await
        .unwrap();
    assert!(!ext.iface_name.is_empty());

    // Smoke for ip::iface::config: ensure_v4_address_on_link replaces any
    // other address of dummy0 inside ipn, keeping only ipa.
    use crate::ip::iface::{add_blackhole_v4_route, ensure_v4_address_on_link};
    use crate::ip::{IP4Net, IP4};
    let dummy = get_interface_by_name(&nl, "dummy0").await.unwrap();
    let ipn = IP4Net {
        ip: IP4(u32::from(Ipv4Addr::new(10, 100, 0, 0))),
        prefix_len: 16,
    };
    let ipa = IP4Net {
        ip: IP4(u32::from(Ipv4Addr::new(10, 100, 0, 5))),
        prefix_len: 24,
    };
    ensure_v4_address_on_link(&nl, ipa, ipn, dummy.index)
        .await
        .unwrap();
    let addrs = get_iface_ip4_addrs(&nl, &dummy).await.unwrap();
    assert!(addrs.contains(&IpAddr::V4(Ipv4Addr::new(10, 100, 0, 5))));
    let ipa2 = IP4Net {
        ip: IP4(u32::from(Ipv4Addr::new(10, 100, 0, 6))),
        prefix_len: 24,
    };
    ensure_v4_address_on_link(&nl, ipa2, ipn, dummy.index)
        .await
        .unwrap();
    let addrs = get_iface_ip4_addrs(&nl, &dummy).await.unwrap();
    assert!(addrs.contains(&IpAddr::V4(Ipv4Addr::new(10, 100, 0, 6))));
    assert!(!addrs.contains(&IpAddr::V4(Ipv4Addr::new(10, 100, 0, 5))));

    // add_blackhole_v4_route is check-then-add: the second call no-ops.
    let bh = IP4Net {
        ip: IP4(u32::from(Ipv4Addr::new(10, 200, 0, 0))),
        prefix_len: 16,
    };
    add_blackhole_v4_route(&nl, bh).await.unwrap();
    add_blackhole_v4_route(&nl, bh).await.unwrap();

    teardown_dummy();
}
