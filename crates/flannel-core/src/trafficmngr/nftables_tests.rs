//! Tests for the nftables traffic manager ([`super`]).

use super::masq::MASQ_PLAIN;
use super::*;

/// Pins the exact forward-rule setup script (legacy syntax, as used
/// with this image's nft v1.0.2; modern differs only in chain attrs).
#[test]
fn forward_tx_renders_exact_script() {
    let tx = forward_tx(Family::Ip, false, "10.244.0.0/16");
    assert_eq!(
        tx.render(),
        [
            "add chain ip flannel-ipv4 forward { comment \"chain to accept flannel traffic\" ; type filter hook forward priority 0 ; }",
            "flush chain ip flannel-ipv4 forward",
            "add rule ip flannel-ipv4 forward ip saddr 10.244.0.0/16 accept",
            "add rule ip flannel-ipv4 forward ip daddr 10.244.0.0/16 accept",
        ]
        .join("\n")
            + "\n"
    );
}

#[test]
fn masq_rule_texts_fully_random_v4() {
    assert_eq!(
        masq_rule_texts("10.244.0.0/16", "10.244.1.0/24", "ip", MASQ_FULLY_RANDOM),
        vec![
            "meta mark 0x4000 return",
            "ip saddr 10.244.1.0/24 ip daddr 10.244.0.0/16 return",
            "ip saddr 10.244.0.0/16 ip daddr 10.244.1.0/24 return",
            "ip saddr != 10.244.1.0/24 ip daddr 10.244.0.0/16 return",
            "ip saddr 10.244.0.0/16 ip daddr != 224.0.0.0/4 masquerade fully-random",
            "ip saddr != 10.244.0.0/16 ip daddr 10.244.0.0/16 masquerade fully-random",
        ]
    );
}

#[test]
fn masq_rule_texts_plain_v6() {
    let rules = masq_rule_texts("fd00::/48", "fd00:0:0:1::/64", "ip6", MASQ_PLAIN);
    assert_eq!(rules[0], "meta mark 0x4000 return");
    assert_eq!(
        rules[4],
        "ip6 saddr fd00::/48 ip6 daddr != ff00::/8 masquerade"
    );
    assert_eq!(
        rules[5],
        "ip6 saddr != fd00::/48 ip6 daddr fd00::/48 masquerade"
    );
}

/// Pins the checkRandomfully transaction (modern/knftables shape).
#[test]
fn masquerade_test_tx_renders_exact_script() {
    let tx = masquerade_test_tx(true);
    assert_eq!(
        tx.render(),
        [
            "add chain ip flannel-ipv4 masqueradeTest { comment \"chain to test if masquerade random fully is supported\" ; type nat ; hook postrouting ; priority 100 ; }",
            "flush chain ip flannel-ipv4 masqueradeTest",
            "add rule ip flannel-ipv4 masqueradeTest ip saddr != 127.0.0.1 masquerade fully-random",
        ]
        .join("\n")
            + "\n"
    );
}

/// End-to-end against the real `nft` binary (this container has
/// CAP_NET_ADMIN). Uses 10.251.x to avoid collisions with
/// parallel iptables tests.
#[tokio::test]
async fn manager_end_to_end_on_real_nft() {
    use crate::lease::LeaseAttrs;
    use std::time::UNIX_EPOCH;
    use tokio_util::sync::CancellationToken;

    fn nft_list(table: &str) -> String {
        let out = std::process::Command::new("nft")
            .args(["list", "table", "ip", table])
            .output()
            .expect("spawn nft");
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    let token = CancellationToken::new();
    let mgr = NFTablesManager::new();
    mgr.init(&token).await.expect("init");

    let network: IP4Net = "10.251.0.0/16".parse().expect("parse cidr");
    mgr.setup_and_ensure_forward_rules(&token, network, IP6Net::default(), 60)
        .await;
    let listed = nft_list(IPV4_TABLE);
    assert!(
        listed.contains("ip saddr 10.251.0.0/16 accept"),
        "forward rule: {listed}"
    );

    let lease = Lease {
        enable_ipv4: true,
        enable_ipv6: false,
        subnet: "10.251.7.0/24".parse().expect("parse cidr"),
        ipv6_subnet: IP6Net::default(),
        attrs: LeaseAttrs::default(),
        expiration: UNIX_EPOCH,
        asof: 0,
    };
    let empty6 = IP6Net::default();
    mgr.setup_and_ensure_masq_rules(
        &token, network, network, network, empty6, empty6, empty6, &lease, 60, false,
    )
    .await
    .expect("masq rules");
    let listed = nft_list(IPV4_TABLE);
    assert!(listed.contains("postrtg"), "postrtg chain: {listed}");
    assert!(listed.contains("masquerade"), "masquerade rule: {listed}");

    mgr.clean_up(&token).await.expect("clean up");
    let status = std::process::Command::new("nft")
        .args(["list", "table", "ip", IPV4_TABLE])
        .status()
        .expect("spawn nft");
    assert!(!status.success(), "flannel-ipv4 table should be deleted");
}
