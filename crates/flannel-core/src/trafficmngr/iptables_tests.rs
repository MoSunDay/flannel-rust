//! Tests for the iptables `TrafficManager` port. Pure rule-builder
//! tests run anywhere; the lifecycle test needs root plus working
//! `iptables`/`iptables-restore` and skips itself otherwise.

use super::ip_tables::flannel_chain;
use super::ipt::{IPTables, Protocol};
use super::iptables_rules::masq_rules_with;
use super::*;
use crate::ip::{IP4Net, IP6Net};
use crate::lease::Lease;
use crate::trafficmngr::{IPTablesRule, TrafficManager, KUBE_PROXY_MARK};
use std::str::FromStr;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

fn expected_rule(table: &str, chain: &str, spec: &[&str]) -> IPTablesRule {
    IPTablesRule {
        table: table.to_string(),
        action: "-A".to_string(),
        chain: chain.to_string(),
        rulespec: spec.iter().map(|s| s.to_string()).collect(),
    }
}

#[test]
fn forward_rules_match_go() {
    let rules = forward_rules("10.244.0.0/16");
    let expected = vec![
        expected_rule(
            "filter",
            "FORWARD",
            &[
                "-m",
                "comment",
                "--comment",
                "flanneld forward",
                "-j",
                "FLANNEL-FWD",
            ],
        ),
        expected_rule(
            "filter",
            "FLANNEL-FWD",
            &[
                "-s",
                "10.244.0.0/16",
                "-m",
                "comment",
                "--comment",
                "flanneld forward",
                "-j",
                "ACCEPT",
            ],
        ),
        expected_rule(
            "filter",
            "FLANNEL-FWD",
            &[
                "-d",
                "10.244.0.0/16",
                "-m",
                "comment",
                "--comment",
                "flanneld forward",
                "-j",
                "ACCEPT",
            ],
        ),
    ];
    assert_eq!(rules, expected);
}

#[test]
fn masq_rules_without_random_fully_match_go() {
    let rules = masq_rules_with("10.244.0.0/16", "10.244.1.0/24", "224.0.0.0/4", true, false);
    let expected = vec![
        expected_rule(
            "nat",
            "POSTROUTING",
            &[
                "-m",
                "comment",
                "--comment",
                "flanneld masq",
                "-j",
                "FLANNEL-POSTRTG",
            ],
        ),
        expected_rule(
            "nat",
            "FLANNEL-POSTRTG",
            &[
                "-m",
                "mark",
                "--mark",
                KUBE_PROXY_MARK,
                "-m",
                "comment",
                "--comment",
                "flanneld masq",
                "-j",
                "RETURN",
            ],
        ),
        expected_rule(
            "nat",
            "FLANNEL-POSTRTG",
            &[
                "-s",
                "10.244.1.0/24",
                "-d",
                "10.244.0.0/16",
                "-m",
                "comment",
                "--comment",
                "flanneld masq",
                "-j",
                "RETURN",
            ],
        ),
        expected_rule(
            "nat",
            "FLANNEL-POSTRTG",
            &[
                "-s",
                "10.244.0.0/16",
                "-d",
                "10.244.1.0/24",
                "-m",
                "comment",
                "--comment",
                "flanneld masq",
                "-j",
                "RETURN",
            ],
        ),
        expected_rule(
            "nat",
            "FLANNEL-POSTRTG",
            &[
                "!",
                "-s",
                "10.244.0.0/16",
                "-d",
                "10.244.1.0/24",
                "-m",
                "comment",
                "--comment",
                "flanneld masq",
                "-j",
                "RETURN",
            ],
        ),
        expected_rule(
            "nat",
            "FLANNEL-POSTRTG",
            &[
                "-s",
                "10.244.0.0/16",
                "!",
                "-d",
                "224.0.0.0/4",
                "-m",
                "comment",
                "--comment",
                "flanneld masq",
                "-j",
                "MASQUERADE",
            ],
        ),
        expected_rule(
            "nat",
            "FLANNEL-POSTRTG",
            &[
                "!",
                "-s",
                "10.244.0.0/16",
                "-d",
                "10.244.0.0/16",
                "-m",
                "comment",
                "--comment",
                "flanneld masq",
                "-j",
                "MASQUERADE",
            ],
        ),
    ];
    assert_eq!(rules, expected);
}

#[test]
fn masq_rules_with_random_fully_match_go() {
    let rules = masq_rules_with("10.244.0.0/16", "10.244.1.0/24", "224.0.0.0/4", false, true);
    // Only the two MASQUERADE rules carry --random-fully.
    assert_eq!(rules.len(), 7);
    for r in &rules[..5] {
        assert!(!r.rulespec.iter().any(|s| s == "--random-fully"));
    }
    for r in &rules[5..] {
        assert_eq!(
            r.rulespec.last().map(String::as_str),
            Some("--random-fully")
        );
    }
}

#[test]
fn masq_rules_with_disable_flag_beats_support() {
    let rules = masq_rules_with("10.244.0.0/16", "10.244.1.0/24", "224.0.0.0/4", true, true);
    assert!(rules
        .iter()
        .all(|r| !r.rulespec.iter().any(|s| s == "--random-fully")));
}

#[test]
fn flannel_chain_detection() {
    let jump = expected_rule(
        "nat",
        "POSTROUTING",
        &[
            "-m",
            "comment",
            "--comment",
            "flanneld masq",
            "-j",
            "FLANNEL-POSTRTG",
        ],
    );
    assert_eq!(flannel_chain(&jump), Some("FLANNEL-POSTRTG"));
    let member = expected_rule(
        "filter",
        "FLANNEL-FWD",
        &["-s", "10.244.0.0/16", "-j", "ACCEPT"],
    );
    assert_eq!(flannel_chain(&member), Some("FLANNEL-FWD"));
    let other = expected_rule("filter", "FORWARD", &["-j", "ACCEPT"]);
    assert_eq!(flannel_chain(&other), None);
}

fn test_lease(subnet: IP4Net) -> Lease {
    Lease {
        enable_ipv4: true,
        enable_ipv6: false,
        subnet,
        ipv6_subnet: IP6Net::default(),
        attrs: LeaseAttrs::default(),
        expiration: UNIX_EPOCH,
        asof: 0,
    }
}

/// Best-effort removal of leftovers from earlier runs: the referring
/// jump rule must go first, otherwise `-X` fails with "resource busy".
async fn remove_leftovers(ipt: &IPTables) {
    for (table, builtin, chain, comment) in [
        ("nat", "POSTROUTING", "FLANNEL-POSTRTG", "flanneld masq"),
        ("filter", "FORWARD", "FLANNEL-FWD", "flanneld forward"),
    ] {
        let spec: Vec<String> = ["-m", "comment", "--comment", comment, "-j", chain]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let _ = ipt.delete(table, builtin, &spec).await;
        let _ = ipt.clear_and_delete_chain(table, chain).await;
    }
}

/// Existence probe with retries: this test shares kernel netfilter
/// state with the parallel nftables end-to-end test, and iptables-nft
/// 1.8.7 occasionally reports transient errors while another process
/// mutates the ruleset.
async fn rule_exists(ipt: &IPTables, r: &IPTablesRule) -> bool {
    let mut last = None;
    for _ in 0..10 {
        match ipt.exists(&r.table, &r.chain, &r.rulespec).await {
            Ok(b) => return b,
            Err(e) => last = Some(e),
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    panic!("rule existence check failed after retries: {last:?} (rule: {r:?})");
}

async fn chain_present(ipt: &IPTables, table: &str, chain: &str) -> bool {
    let mut last = None;
    for _ in 0..10 {
        match ipt.chain_exists(table, chain).await {
            Ok(b) => return b,
            Err(e) => last = Some(e),
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    panic!("chain existence check failed after retries: {last:?} ({table}/{chain})");
}

/// Full lifecycle against real iptables: init -> forward + masq rules
/// -> verify -> re-bootstrap (existing rules path) -> clean_up.
#[tokio::test]
async fn iptables_manager_lifecycle() {
    // Skip unless iptables is present and usable (needs root).
    let Ok(probe) = IPTables::new(Protocol::IPv4).await else {
        eprintln!("skipping: iptables binary not found");
        return;
    };
    if probe.chain_exists("filter", "INPUT").await.is_err() {
        eprintln!("skipping: iptables not usable without root");
        return;
    }
    remove_leftovers(&probe).await;

    let token = CancellationToken::new();
    let ctx: Ctx<'_> = &token;
    let mgr = IPTablesManager::new();
    mgr.init(ctx).await.unwrap();

    let network = IP4Net::from_str("10.15.0.0/16").unwrap();
    let v6_network = IP6Net::default(); // empty -> IPv6 side is skipped
    let lease = test_lease(IP4Net::from_str("10.15.20.0/24").unwrap());

    mgr.setup_and_ensure_forward_rules(ctx, network, v6_network, 3600)
        .await;
    // Different prev subnet: exercises the recycle (teardown) path too.
    mgr.setup_and_ensure_masq_rules(
        ctx,
        network,
        IP4Net::default(),
        network,
        v6_network,
        IP6Net::default(),
        v6_network,
        &lease,
        3600,
        false,
    )
    .await
    .unwrap();
    // Bootstrap again with rules already present (-D then -A rebuild).
    mgr.setup_and_ensure_masq_rules(
        ctx,
        network,
        lease.subnet,
        network,
        v6_network,
        lease.ipv6_subnet,
        v6_network,
        &lease,
        3600,
        false,
    )
    .await
    .unwrap();

    // Verify with a fresh iptables handle.
    let ipt = IPTables::new(Protocol::IPv4).await.unwrap();
    assert!(chain_present(&ipt, "nat", "FLANNEL-POSTRTG").await);
    assert!(chain_present(&ipt, "filter", "FLANNEL-FWD").await);
    for r in forward_rules(&network.to_string()) {
        assert!(rule_exists(&ipt, &r).await, "missing rule: {r:?}");
    }
    let masq = masq_rules(network, &lease, false).await;
    for r in &masq {
        assert!(rule_exists(&ipt, r).await, "missing rule: {r:?}");
    }

    mgr.clean_up(ctx).await.unwrap();
    // Faithful Go behavior: CleanUp flushes FLANNEL-POSTRTG, but `-X`
    // fails (the POSTROUTING jump rule still references the chain) and
    // the error is swallowed upstream, so the empty chain survives.
    assert!(chain_present(&ipt, "nat", "FLANNEL-POSTRTG").await);
    assert!(
        !rule_exists(&ipt, &masq[1]).await,
        "CleanUp must flush FLANNEL-POSTRTG"
    );
    // Remove the leftovers manually (jump rule first, then the chains);
    // Go's CleanUp also never touches the filter-table FLANNEL-FWD.
    remove_leftovers(&ipt).await;
    assert!(!chain_present(&ipt, "nat", "FLANNEL-POSTRTG").await);
    assert!(!chain_present(&ipt, "filter", "FLANNEL-FWD").await);
    // Stop the resync tasks.
    token.cancel();
}
