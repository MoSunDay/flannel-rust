//! End-to-end tests for the wireguard generic-netlink client: full
//! configure/read/remove lifecycle against a real kernel device, plus
//! pure wire-format roundtrips. The kernel tests need the `wireguard`
//! module, CAP_NET_ADMIN and the `ip` binary (they panic clearly when
//! `ip` is missing).

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::process::Command;

use super::error_code_of;
use super::parse_family_ops;
use super::{
    configure_device, nla_nest, nla_u16, nla_u32, nla_u8, parse_endpoint, parse_nlas,
    sockaddr_bytes,
};
use super::{
    GenlSocket, CTRL_ATTR_FAMILY_ID, CTRL_ATTR_OPS, CTRL_ATTR_OP_FLAGS, CTRL_ATTR_OP_ID,
    CTRL_CMD_GETFAMILY, GENL_CMD_CAP_DO, GENL_CMD_CAP_DUMP, GENL_ID_CTRL, WG_GENL_NAME,
};
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

// --- synthetic CTRL_CMD_GETFAMILY payloads --------------------------------

// Op-flag bits the kernel reports in addition to the capability bits
// (include/uapi/linux/genetlink.h).
const GENL_UNS_ADMIN_PERM: u32 = 0x10;
const GENL_CMD_CAP_HASPOL: u32 = 0x08;

/// A CTRL_CMD_GETFAMILY reply: 4-byte genlmsghdr (cmd, version,
/// reserved) followed by the family id and a CTRL_ATTR_OPS nest whose
/// ops carry flags laid out per the uapi.
fn ctrl_getfamily_body(family_id: u16, ops: &[(u8, u32)]) -> Vec<u8> {
    let mut b = vec![CTRL_CMD_GETFAMILY, 1, 0, 0];
    b.extend(nla_u16(CTRL_ATTR_FAMILY_ID, family_id));
    let op_attrs: Vec<Vec<u8>> = ops
        .iter()
        .enumerate()
        .map(|(i, (id, flags))| {
            let mut op = nla_u8(CTRL_ATTR_OP_ID, *id);
            op.extend(nla_u32(CTRL_ATTR_OP_FLAGS, *flags));
            nla_nest((i + 1) as u16, &[op])
        })
        .collect();
    b.extend(nla_nest(CTRL_ATTR_OPS, &op_attrs));
    b
}

/// Attribute payload of the synthetic reply, i.e. everything after the
/// genlmsghdr that `resolve_family_ops` hands to `parse_family_ops`.
fn ctrl_getfamily_attrs(family_id: u16, ops: &[(u8, u32)]) -> Vec<u8> {
    ctrl_getfamily_body(family_id, ops)[4..].to_vec()
}

/// Capability bits follow include/uapi/linux/genetlink.h: DO is 0x02
/// (0x01 is GENL_ADMIN_PERM, which privileged ops also carry), DUMP is
/// 0x04. Swapping these would send every SET to GET_DEVICE (-EOPNOTSUPP).
#[test]
fn genl_cmd_cap_bits_match_uapi() {
    assert_eq!(GENL_CMD_CAP_DO, 0x02);
    assert_eq!(GENL_CMD_CAP_DUMP, 0x04);
    assert_eq!(GENL_CMD_CAP_DO & GENL_CMD_CAP_DUMP, 0);
}

/// The probed live-kernel op flags only make sense with the uapi bits:
/// GET_DEVICE is dump-capable (not do-capable), SET_DEVICE is
/// do-capable (not dump-capable). The 0x01/0x02 reading would leave
/// GET_DEVICE unmatched and make SET_DEVICE look dump-capable only, so
/// every SET would go to GET_DEVICE. Keep DO=0x02 / DUMP=0x04.
#[test]
fn probed_kernel_op_flags_map_to_uapi_bits() {
    const GET_DEVICE_FLAGS: u32 = 0x1c; // DUMP | HASPOL | UNS_ADMIN_PERM
    const SET_DEVICE_FLAGS: u32 = 0x1a; // DO | HASPOL | UNS_ADMIN_PERM
    assert_eq!(GET_DEVICE_FLAGS & GENL_CMD_CAP_DUMP, GENL_CMD_CAP_DUMP);
    assert_eq!(GET_DEVICE_FLAGS & GENL_CMD_CAP_DO, 0);
    assert_eq!(SET_DEVICE_FLAGS & GENL_CMD_CAP_DO, GENL_CMD_CAP_DO);
    assert_eq!(SET_DEVICE_FLAGS & GENL_CMD_CAP_DUMP, 0);
    assert_eq!(GET_DEVICE_FLAGS & (0x01 | 0x02), 0);
    assert_eq!(SET_DEVICE_FLAGS & 0x02, 0x02);
    assert_eq!(SET_DEVICE_FLAGS & 0x01, 0);
}

/// Layout probed on a live kernel: GET_DEVICE id 0 with
/// DUMP|HASPOL|UNSPEC_ADMIN_PERM (0x1c), SET_DEVICE id 1 with
/// DO|HASPOL|UNSPEC_ADMIN_PERM (0x1a).
#[test]
fn family_ops_resolve_mainline_kernel_layout() {
    const OPS: &[(u8, u32)] = &[
        (
            0,
            GENL_CMD_CAP_DUMP | GENL_CMD_CAP_HASPOL | GENL_UNS_ADMIN_PERM,
        ),
        (
            1,
            GENL_CMD_CAP_DO | GENL_CMD_CAP_HASPOL | GENL_UNS_ADMIN_PERM,
        ),
    ];
    assert_eq!(
        parse_family_ops("wireguard", &ctrl_getfamily_attrs(38, OPS)).unwrap(),
        (38, 0, 1)
    );
}

/// A dump-only op must never be picked as SET_DEVICE; set falls back
/// to the hardcoded id.
#[test]
fn family_ops_dump_only_op_is_not_set() {
    const OPS: &[(u8, u32)] = &[(0, GENL_CMD_CAP_DUMP)];
    assert_eq!(
        parse_family_ops("wireguard", &ctrl_getfamily_attrs(26, OPS)).unwrap(),
        (26, 0, 2)
    );
}

/// A do-only op must never be picked as GET_DEVICE; get falls back to
/// the hardcoded id.
#[test]
fn family_ops_do_only_op_is_not_get() {
    const OPS: &[(u8, u32)] = &[(1, GENL_CMD_CAP_DO)];
    assert_eq!(
        parse_family_ops("wireguard", &ctrl_getfamily_attrs(26, OPS)).unwrap(),
        (26, 1, 1)
    );
}

/// Regression guard: if the capability flags make GET and SET resolve
/// to the same command, fall back to the hardcoded ids (an error is
/// logged) instead of sending SETs to a dump-only op.
#[test]
fn family_ops_same_get_and_set_falls_back() {
    const OPS: &[(u8, u32)] = &[(7, GENL_CMD_CAP_DO | GENL_CMD_CAP_DUMP)];
    assert_eq!(
        parse_family_ops("wireguard", &ctrl_getfamily_attrs(26, OPS)).unwrap(),
        (26, 1, 2)
    );
}

/// No CTRL_ATTR_OPS at all: both ids use the hardcoded fallback.
#[test]
fn family_ops_without_ops_uses_hardcoded_fallback() {
    assert_eq!(
        parse_family_ops("wireguard", &ctrl_getfamily_attrs(26, &[])).unwrap(),
        (26, 1, 2)
    );
}

/// A reply without a family id is NotFound (resolve keeps looking at
/// the remaining messages).
#[test]
fn family_ops_without_family_id_is_not_found() {
    let err = parse_family_ops("wireguard", &[0, 0, 0]).expect_err("no family id");
    assert_eq!(err.kind(), io::ErrorKind::NotFound);
}

// --- NLMSG_ERROR body decoding -------------------------------------------

/// A truncated NLMSG_ERROR body must not panic (`body[0..4]` used to be
/// sliced unconditionally); it is an InvalidData error instead.
#[test]
fn short_nlmsg_error_body_is_error_not_panic() {
    for len in 0..4usize {
        let body = vec![0x42u8; len];
        let res = catch_unwind(AssertUnwindSafe(|| error_code_of(&body)));
        let err = res
            .expect("no panic on short NLMSG_ERROR body")
            .expect_err("short body must error");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
    assert_eq!(error_code_of(&(-95i32).to_ne_bytes()).unwrap(), -95);
    assert_eq!(error_code_of(&0i32.to_ne_bytes()).unwrap(), 0);
}

// --- real kernel (needs the wireguard family; GETFAMILY is unprivileged) --

/// The running kernel reports the wireguard ops; with the uapi
/// capability bits GET must resolve to the dump op and SET to the do
/// op. Equal ids would mean every SET fails with -EOPNOTSUPP.
#[test]
fn resolve_family_ops_on_real_kernel() {
    let mut sock = GenlSocket::new().expect("AF_NETLINK generic socket");
    let (fam, get_cmd, set_cmd) = sock
        .resolve_family_ops(WG_GENL_NAME)
        .expect("wireguard generic netlink family exists");
    assert_ne!(get_cmd, set_cmd, "GET and SET must be distinct ops");
    assert!(
        fam >= GENL_ID_CTRL,
        "family id comes from the dynamic range"
    );
}
