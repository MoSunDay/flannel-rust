//! End-to-end tests for the wireguard generic-netlink client: full
//! configure/read/remove lifecycle against a real kernel device, plus
//! pure wire-format roundtrips. The kernel tests need the `wireguard`
//! module, CAP_NET_ADMIN and the `ip` binary (they panic clearly when
//! `ip` is missing).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::process::Command;

use super::{configure_device, nla_u32, parse_endpoint, parse_nlas, sockaddr_bytes};
use super::{WgAllowedIp, WgDeviceConfig, WgPeerConfig};
use super::{WGDEVICE_F_REPLACE_PEERS, WGPEER_F_REMOVE_ME, WGPEER_F_REPLACE_ALLOWEDIPS};
use crate::backend::wireguard::device::get_device;
use crate::backend::wireguard::keys;

// RFC 7748 test vector (Alice).
const ALICE_PUB_B64: &str = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=";

#[test]
fn sockaddr_roundtrip_v4() {
    let addr: SocketAddr = "1.2.3.4:51820".parse().unwrap();
    assert_eq!(parse_endpoint(&sockaddr_bytes(addr)), Some(addr));
}

#[test]
fn sockaddr_roundtrip_v6() {
    let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 51821);
    assert_eq!(parse_endpoint(&sockaddr_bytes(addr)), Some(addr));
}

#[test]
fn parse_nlas_reads_encoded_attrs() {
    let mut buf = nla_u32(7, 0xdeadbeef);
    buf.extend(nla_u32(9, 1));
    let nlas = parse_nlas(&buf);
    assert_eq!(nlas.len(), 2);
    assert_eq!(nlas[0].0, 7);
    assert_eq!(nlas[0].1, 0xdeadbeefu32.to_ne_bytes());
    assert_eq!(nlas[1].0, 9);
}

#[test]
fn parse_endpoint_rejects_unknown_family() {
    let mut b = sockaddr_bytes("1.2.3.4:1".parse().unwrap());
    b[0] = 0xff;
    assert_eq!(parse_endpoint(&b), None);
}

fn ip_cmd(args: &[&str]) -> std::process::Output {
    match Command::new("ip").args(args).output() {
        Ok(o) => o,
        Err(e) => panic!("`ip` command is required for wireguard kernel tests but is missing: {e}"),
    }
}

fn unique_link_name() -> String {
    // IFNAMSIZ is 16 (incl. NUL): keep it short.
    format!("wgrst{:06}", std::process::id() % 1_000_000)
}

#[test]
fn configure_get_lifecycle() {
    let name = unique_link_name();
    let add = ip_cmd(&["link", "add", &name, "type", "wireguard"]);
    if !add.status.success() {
        let err = String::from_utf8_lossy(&add.stderr).into_owned();
        panic!(
            "could not create wireguard link {name} (need wireguard module + CAP_NET_ADMIN): {err}"
        );
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        lifecycle_body(&name);
    }));

    let del = ip_cmd(&["link", "del", &name]);
    assert!(
        del.status.success(),
        "cleanup failed: {}",
        String::from_utf8_lossy(&del.stderr)
    );
    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }
}

fn lifecycle_body(name: &str) {
    let private_key = keys::Key::generate_private_key().expect("keygen works");
    let alice_pub = keys::Key::parse(ALICE_PUB_B64)
        .expect("alice pubkey parses")
        .0;
    let psk = [7u8; 32];

    let cfg = WgDeviceConfig {
        ifname: name.to_string(),
        private_key: Some(private_key.0),
        listen_port: Some(51820),
        flags: WGDEVICE_F_REPLACE_PEERS,
        peers: vec![WgPeerConfig {
            public_key: alice_pub,
            preshared_key: Some(psk),
            flags: WGPEER_F_REPLACE_ALLOWEDIPS,
            endpoint: Some("1.2.3.4:51820".parse().unwrap()),
            persistent_keepalive_interval: Some(25),
            allowed_ips: vec![WgAllowedIp {
                ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                cidr: 24,
            }],
        }],
    };
    configure_device(&cfg).expect("configure_device succeeds on existing device");

    let info = get_device(name).expect("get_device reads back the created device");
    assert!(info.ifindex > 0, "device has a kernel ifindex");
    assert_eq!(info.listen_port, 51820);
    assert_eq!(info.peers.len(), 1);
    let peer = &info.peers[0];
    assert_eq!(peer.public_key, alice_pub);
    assert_eq!(peer.endpoint, Some("1.2.3.4:51820".parse().unwrap()));
    assert_eq!(peer.persistent_keepalive_interval, 25);
    assert_eq!(
        peer.allowed_ips,
        vec![WgAllowedIp {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            cidr: 24
        }]
    );

    // Remove the peer again (WGPEER_F_REMOVE_ME).
    let rm = WgDeviceConfig {
        ifname: name.to_string(),
        private_key: None,
        listen_port: None,
        flags: 0,
        peers: vec![WgPeerConfig {
            public_key: alice_pub,
            preshared_key: None,
            flags: WGPEER_F_REMOVE_ME,
            endpoint: None,
            persistent_keepalive_interval: None,
            allowed_ips: Vec::new(),
        }],
    };
    configure_device(&rm).expect("remove-me configure succeeds");
    let info = get_device(name).expect("get_device after removal");
    assert!(info.peers.is_empty(), "peer was removed");
}

#[test]
fn configure_missing_device_fails() {
    let cfg = WgDeviceConfig {
        ifname: "wg-no-such-dev".to_string(),
        private_key: None,
        listen_port: None,
        flags: 0,
        peers: Vec::new(),
    };
    assert!(configure_device(&cfg).is_err());
}

#[test]
fn get_missing_device_fails() {
    let err = get_device("wg-no-such-dev").expect_err("missing device must error");
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
}
