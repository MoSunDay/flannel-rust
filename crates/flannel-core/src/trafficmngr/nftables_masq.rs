//! Masquerade-rule builders for [`super`] (Go: the rule bodies of
//! `addMasqRules` and utils.go's `checkRandomfully` transaction,
//! upstream cdf76059). Extracted from nftables.rs to keep files small.

use super::{chain_def, IPV4_TABLE, MASQUERADE_TEST_CHAIN};
use crate::trafficmngr::nft::{
    concat, Family, Transaction, NAT_TYPE, POSTROUTING_HOOK, SNAT_PRIORITY,
};

pub(super) const MASQ_FULLY_RANDOM: &str = "masquerade fully-random";
pub(super) const MASQ_PLAIN: &str = "masquerade";

/// Go: the six rules of `addMasqRules`, as pure text (in Go's order).
pub(super) fn masq_rule_texts(
    cluster_cidr: &str,
    pod_cidr: &str,
    family: &str,
    masquerade: &str,
) -> Vec<String> {
    let multicast_cidr = if family == Family::Ip6.as_str() {
        "ff00::/8"
    } else {
        "224.0.0.0/4"
    };
    vec![
        // Skip traffic marked by kube-proxy (double-NAT bug on some kernels).
        concat(&["meta mark", "0x4000", "return"]),
        // Don't NAT traffic within the overlay network.
        concat(&[
            family,
            "saddr",
            pod_cidr,
            family,
            "daddr",
            cluster_cidr,
            "return",
        ]),
        concat(&[
            family,
            "saddr",
            cluster_cidr,
            family,
            "daddr",
            pod_cidr,
            "return",
        ]),
        // External traffic from a node that owns the pod IP.
        concat(&[
            family,
            "saddr",
            "!=",
            pod_cidr,
            family,
            "daddr",
            cluster_cidr,
            "return",
        ]),
        // NAT unless it's multicast traffic.
        concat(&[
            family,
            "saddr",
            cluster_cidr,
            family,
            "daddr",
            "!=",
            multicast_cidr,
            masquerade,
        ]),
        // Masquerade anything headed towards flannel from the host.
        concat(&[
            family,
            "saddr",
            "!=",
            cluster_cidr,
            family,
            "daddr",
            cluster_cidr,
            masquerade,
        ]),
    ]
}

/// Go: the masqueradeTest transaction of `checkRandomfully` (utils.go).
pub(super) fn masquerade_test_tx(modern: bool) -> Transaction {
    let mut tx = Transaction::new(Family::Ip, IPV4_TABLE, modern);
    tx.add_chain(&chain_def(
        MASQUERADE_TEST_CHAIN,
        "chain to test if masquerade random fully is supported",
        NAT_TYPE,
        POSTROUTING_HOOK,
        SNAT_PRIORITY,
    ));
    tx.flush_chain(MASQUERADE_TEST_CHAIN);
    tx.add_rule(
        MASQUERADE_TEST_CHAIN,
        &concat(&["ip saddr", "!=", "127.0.0.1", MASQ_FULLY_RANDOM]),
    );
    tx
}
