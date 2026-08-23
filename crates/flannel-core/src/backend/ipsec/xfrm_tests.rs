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
