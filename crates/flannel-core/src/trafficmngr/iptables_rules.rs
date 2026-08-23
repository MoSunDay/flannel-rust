//! Flannel iptables rule-spec builders split out of `iptables.rs`
//! (Go `masqRules`/`masqIP6Rules`/`forwardRules`; pure, no side
//! effects).

use super::ipt::{IPTables, Protocol};
use crate::ip::{IP4Net, IP6Net};
use crate::lease::Lease;
use crate::trafficmngr::{IPTablesRule, KUBE_PROXY_MARK};

/// Go: `(*IPTablesManager).masqRules`.
pub async fn masq_rules(ccidr: IP4Net, lease: &Lease, disable: bool) -> Vec<IPTablesRule> {
    let supports = supports_random_fully(Protocol::IPv4).await;
    let (cidr, pod) = (ccidr.to_string(), lease.subnet.to_string());
    masq_rules_with(&cidr, &pod, "224.0.0.0/4", disable, supports)
}

/// Go: `(*IPTablesManager).masqIP6Rules`.
pub async fn masq_ip6_rules(ccidr: IP6Net, lease: &Lease, disable: bool) -> Vec<IPTablesRule> {
    let supports = supports_random_fully(Protocol::IPv6).await;
    let (cidr, pod) = (ccidr.to_string(), lease.ipv6_subnet.to_string());
    masq_rules_with(&cidr, &pod, "ff00::/8", disable, supports)
}

/// Go's probe: on construction error the flag stays false.
pub async fn supports_random_fully(proto: Protocol) -> bool {
    match IPTables::new(proto).await {
        Ok(ipt) => ipt.has_random_fully(),
        Err(_) => false,
    }
}

/// Shared body of Go's `masqRules` / `masqIP6Rules`, with
/// `supports_random_fully` injected (Go probes the iptables binary;
/// tests pass the flag directly).
pub fn masq_rules_with(
    cluster_cidr: &str,
    pod_cidr: &str,
    multicast: &str,
    ip_masq_random_fully_disable: bool,
    supports_random_fully: bool,
) -> Vec<IPTablesRule> {
    let random_fully = supports_random_fully && !ip_masq_random_fully_disable;
    let spec = |parts: &[&str], jump: &str| commented(parts, "flanneld masq", jump);
    let mut rules = vec![
        // Ensures the flannel rules run before any other node rules.
        rule("nat", "POSTROUTING", &spec(&[], "FLANNEL-POSTRTG")),
        // Do not masquerade kube-proxy marked traffic (double NAT bug).
        rule(
            "nat",
            "FLANNEL-POSTRTG",
            &spec(&["-m", "mark", "--mark", KUBE_PROXY_MARK], "RETURN"),
        ),
        // No NAT for traffic within the overlay network.
        rule(
            "nat",
            "FLANNEL-POSTRTG",
            &spec(&["-s", pod_cidr, "-d", cluster_cidr], "RETURN"),
        ),
        rule(
            "nat",
            "FLANNEL-POSTRTG",
            &spec(&["-s", cluster_cidr, "-d", pod_cidr], "RETURN"),
        ),
        // No masquerade for external traffic from a Node owning the pod IP.
        rule(
            "nat",
            "FLANNEL-POSTRTG",
            &spec(&["!", "-s", cluster_cidr, "-d", pod_cidr], "RETURN"),
        ),
    ];
    // NAT if it's not multicast traffic.
    let mut nat = rule(
        "nat",
        "FLANNEL-POSTRTG",
        &spec(&["-s", cluster_cidr, "!", "-d", multicast], "MASQUERADE"),
    );
    if random_fully {
        nat.rulespec.push("--random-fully".to_string());
    }
    rules.push(nat);
    // Masquerade anything headed towards flannel from the host.
    let mut host = rule(
        "nat",
        "FLANNEL-POSTRTG",
        &spec(&["!", "-s", cluster_cidr, "-d", cluster_cidr], "MASQUERADE"),
    );
    if random_fully {
        host.rulespec.push("--random-fully".to_string());
    }
    rules.push(host);
    rules
}

/// Go: `forwardRules`.
pub fn forward_rules(flannel_network: &str) -> Vec<IPTablesRule> {
    let spec = |parts: &[&str], jump: &str| commented(parts, "flanneld forward", jump);
    vec![
        // Ensures the flannel rules run before any other node rules.
        rule("filter", "FORWARD", &spec(&[], "FLANNEL-FWD")),
        // Allow forwarding to/from the flannel network range.
        rule(
            "filter",
            "FLANNEL-FWD",
            &spec(&["-s", flannel_network], "ACCEPT"),
        ),
        rule(
            "filter",
            "FLANNEL-FWD",
            &spec(&["-d", flannel_network], "ACCEPT"),
        ),
    ]
}

/// Appends the `-m comment --comment <comment> -j <jump>` tail carried
/// by every Go rule after its match parts.
pub fn commented(parts: &[&str], comment: &str, jump: &str) -> Vec<String> {
    let mut v: Vec<String> = parts.iter().map(|s| s.to_string()).collect();
    v.extend(["-m", "comment", "--comment", comment, "-j", jump].map(str::to_string));
    v
}

pub fn rule(table: &str, chain: &str, rulespec: &[String]) -> IPTablesRule {
    IPTablesRule {
        table: table.to_string(),
        action: "-A".to_string(), // all Go rules use -A
        chain: chain.to_string(),
        rulespec: rulespec.to_vec(),
    }
}
