//! Live-kernel tests for xfrm.rs (container has CAP_NET_ADMIN; uses
//! throwaway 10.99.x.0/24 nets + unique reqids, cleaned up afterwards).

use super::{add_policy, del_policy, get_policy, update_policy, XfrmPolicySpec, DIR_IN, DIR_OUT};
use std::net::Ipv4Addr;

fn spec_pair(a: [u8; 4], b: [u8; 4], dir: u8, reqid: u32) -> XfrmPolicySpec {
    XfrmPolicySpec {
        src: Ipv4Addr::from(a).into(),
        src_prefix: 24,
        dst: Ipv4Addr::from(b).into(),
        dst_prefix: 24,
        dir,
        tunnel_src: Ipv4Addr::new(10, 99, 100, 1).into(),
        tunnel_dst: Ipv4Addr::new(10, 99, 100, 2).into(),
        reqid,
    }
}

fn spec(dir: u8, reqid: u32) -> XfrmPolicySpec {
    spec_pair([10, 99, 1, 0], [10, 99, 2, 0], dir, reqid)
}

/// Same shape handle_xfrm.go programs (both directions checked). Uses
/// its own selector pair so it cannot collide with the lifecycle test
/// when the harness runs both in parallel.
fn flannel_like_specs(reqid: u32) -> Vec<XfrmPolicySpec> {
    vec![
        spec_pair([10, 99, 3, 0], [10, 99, 4, 0], DIR_OUT, reqid),
        spec_pair([10, 99, 3, 0], [10, 99, 4, 0], DIR_IN, reqid),
    ]
}

fn ip_xfrm_policy() -> String {
    let out = std::process::Command::new("ip")
        .args(["xfrm", "policy"])
        .output()
        .expect("ip xfrm policy");
    String::from_utf8_lossy(&out.stdout).to_string()
}

#[test]
fn lifecycle_add_get_update_del() {
    let out_spec = spec(DIR_OUT, 91011);
    let in_spec = spec(DIR_IN, 91011);
    // best-effort cleanup in case a previous crashed run left policies
    let _ = del_policy(&out_spec);
    let _ = del_policy(&in_spec);
    // absent before add
    assert!(get_policy(&out_spec).unwrap().is_none());
    add_policy(&out_spec).expect("add out");
    add_policy(&in_spec).expect("add in");
    // duplicate add fails (EEXIST) like netlink.XfrmPolicyAdd
    assert!(add_policy(&out_spec).is_err());
    // present with the right fields (GETPOLICY reply round-trip)
    let pol = get_policy(&out_spec).unwrap().expect("policy exists");
    assert_eq!(pol.src_prefix, 24);
    assert_eq!(pol.dst_prefix, 24);
    assert_eq!(pol.dir, DIR_OUT);
    assert_eq!(pol.tmpls.len(), 1);
    let t = &pol.tmpls[0];
    assert_eq!(t.proto, 50); // ESP
    assert_eq!(t.mode, 1); // TUNNEL
    assert_eq!(t.reqid, 91011);
    // update keeps it queryable (flannel updates mtu-less selectors)
    update_policy(&out_spec).expect("update out");
    assert!(get_policy(&out_spec).unwrap().is_some());
    // cross-check via iproute2
    let dump = ip_xfrm_policy();
    assert!(
        dump.contains("src 10.99.1.0/24 dst 10.99.2.0/24"),
        "selector in dump: {dump}"
    );
    assert!(dump.contains("reqid 91011"), "reqid in dump: {dump}");
    // delete both directions
    del_policy(&out_spec).expect("del out");
    del_policy(&in_spec).expect("del in");
    assert!(get_policy(&out_spec).unwrap().is_none());
    // deleting again errors (ENOENT)
    assert!(del_policy(&out_spec).is_err());
}

#[test]
fn flannel_pair_both_directions() {
    let specs = flannel_like_specs(92022);
    for s in &specs {
        let _ = del_policy(s); // best-effort pre-cleanup (rerun safety)
    }
    for s in &specs {
        add_policy(s).expect("add");
    }
    for s in &specs {
        assert!(get_policy(s).unwrap().is_some());
    }
    for s in &specs {
        del_policy(s).expect("del");
        assert!(get_policy(s).unwrap().is_none());
    }
}

// --- reply-parsing robustness (no kernel needed) ---

use super::{parse_reply, short_reply_error, MAX_SHORT_REPLIES, NLMSG_DONE, NLMSG_ERROR};

/// One netlink message: mlen/mtype header + zeroed flags/seq/port, body
/// padded to the 4-byte alignment the kernel uses.
fn nlmsg(mtype: u16, body: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(16 + body.len());
    m.extend_from_slice(&((16 + body.len()) as u32).to_ne_bytes());
    m.extend_from_slice(&mtype.to_ne_bytes());
    m.extend_from_slice(&0u16.to_ne_bytes());
    m.extend_from_slice(&0u32.to_ne_bytes());
    m.extend_from_slice(&0u32.to_ne_bytes());
    m.extend_from_slice(body);
    m.resize((m.len() + 3) & !3, 0);
    m
}

#[test]
fn parse_reply_collects_bodies_and_ack() {
    let buf = [
        nlmsg(19, b"body0"),
        nlmsg(19, b"body1"),
        nlmsg(NLMSG_DONE, b""),
    ]
    .concat();
    let (bodies, done, shorts) = parse_reply(&buf).unwrap();
    assert_eq!(bodies, [b"body0".to_vec(), b"body1".to_vec()]);
    assert!(done);
    assert_eq!(shorts, 0);
}

#[test]
fn parse_reply_nonzero_error_is_os_error() {
    let buf = [nlmsg(19, b"x"), nlmsg(NLMSG_ERROR, &(-2i32).to_ne_bytes())].concat();
    let e = parse_reply(&buf).expect_err("nonzero NLMSG_ERROR");
    assert_eq!(e.raw_os_error(), Some(2)); // ENOENT, like the Go client
}

#[test]
fn parse_reply_skips_short_messages_without_panic() {
    // a length word below the 16-byte header minimum is skipped and
    // ends that recv pass (no body, no panic, not done)
    let short_len = [(8u32).to_ne_bytes().as_slice(), &[7u8; 16]].concat();
    let (bodies, done, shorts) = parse_reply(&short_len).unwrap();
    assert!(bodies.is_empty() && !done && shorts == 1);
    // a message whose body is truncated against the recv buffer
    let truncated = nlmsg(19, &[0u8; 40])[..16].to_vec();
    let (bodies, done, shorts) = parse_reply(&truncated).unwrap();
    assert!(bodies.is_empty() && !done && shorts == 1);
    // a NLMSG_ERROR too short to carry its 4-byte error code is
    // malformed too: skipped, not pushed as an empty reply body
    let (bodies, done, shorts) = parse_reply(&nlmsg(NLMSG_ERROR, b"")).unwrap();
    assert!(bodies.is_empty() && !done && shorts == 1);
}

#[test]
fn parse_reply_continues_after_short_nlmsg_error() {
    // skipping a short NLMSG_ERROR does not abort the pass: the real
    // ACK behind it still finishes the reply with no bodies
    let buf = [
        nlmsg(NLMSG_ERROR, b""),
        nlmsg(NLMSG_ERROR, &0i32.to_ne_bytes()),
    ]
    .concat();
    let (bodies, done, shorts) = parse_reply(&buf).unwrap();
    assert!(bodies.is_empty() && done && shorts == 1);
}

#[test]
fn parse_reply_empty_buffer() {
    let (bodies, done, shorts) = parse_reply(&[]).unwrap();
    assert!(bodies.is_empty() && !done && shorts == 0);
}

#[test]
fn short_reply_error_bails_at_the_bound() {
    // consecutive short replies accumulate toward the bail; just under
    // it is fine, at it the request fails instead of spinning forever.
    assert!(short_reply_error(0).is_none());
    assert!(short_reply_error(MAX_SHORT_REPLIES - 1).is_none());
    let e = short_reply_error(MAX_SHORT_REPLIES).expect("bail");
    assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
    assert!(e.to_string().contains("short replies"));
}
