//! Traffic-manager closed loop through the real daemon: boot flanneld
//! with `--ip-masq`, verify the masquerade + forward rules exist (inside
//! a scratch netns, so host netfilter state is never touched), then
//! cancel and run the real `clean_up` (post-hook on the daemon thread,
//! still inside the netns) and verify the rules are gone.
//!
//! Two flavors: iptables and nftables (`EnableNFTables` net-conf key).

use crate::daemonctl::{DaemonHandle, DaemonSpec};
use crate::netutil::{self};
use crate::{E2EError, Scenario};
use serde_json::json;
use std::time::Duration;

const MASQ_SUBNET: &str = "10.244.0.0/16";

pub fn scenarios() -> Vec<Scenario> {
    vec![
        Scenario {
            name: "masq-iptables",
            desc: "ip-masq: FLANNEL-POSTRTG masq + FLANNEL-FWD rules, cleanup on exit",
            run: || Box::pin(run_iptables()),
        },
        Scenario {
            name: "masq-nftables",
            desc: "ip-masq with EnableNFTables: flannel-ipv4 table rules, cleanup on exit",
            run: || Box::pin(run_nftables()),
        },
    ]
}

async fn run_iptables() -> Result<(), E2EError> {
    run(false).await
}

async fn run_nftables() -> Result<(), E2EError> {
    run(true).await
}

async fn run(use_nft: bool) -> Result<(), E2EError> {
    let prefix = if use_nft { "masq-nft" } else { "masq-ipt" };
    let api = crate::apiserver::MockApiserver::start().await?;
    api.put_node("e2e-masq", "10.244.2.0/24").await;

    // Apiserver reachability: the masq netns has no host veth, so the
    // daemon talks to the apiserver through a solo link instead.
    let link = netutil::build_solo_link(prefix)?;
    let net_conf = json!({
        "Network": MASQ_SUBNET,
        "EnableNFTables": use_nft,
        "Backend": {"Type": "alloc"},
    });

    let hook_nft = use_nft;
    let mut daemon = DaemonHandle::spawn(
        DaemonSpec::new("e2e-masq", &api.url_on(&link.host_ip), net_conf)
            .in_netns(&link.ns.path())
            .iface(&link.ns_iface)
            .extra(&["--ip-masq"])
            .after_shutdown(Box::new(move || {
                Box::pin(async move {
                    let tm = flanneld::traffic::new_traffic_manager(hook_nft);
                    let cancel = tokio_util::sync::CancellationToken::new();
                    let _ = tm.clean_up(&cancel).await;
                })
            })),
    )?;
    daemon.wait_ready(Duration::from_secs(30)).await?;

    if use_nft {
        // Table + chains + masquerade rule visible via the real nft.
        netutil::wait_until("nft flannel-ipv4 table", Duration::from_secs(15), || {
            let tables = netutil::run_in_ns(&link.ns.name, "nft", &["list", "tables"])?;
            Ok(tables.contains("table ip flannel-ipv4"))
        })
        .await?;
        let table = netutil::run_in_ns(
            &link.ns.name,
            "nft",
            &["list", "table", "ip", "flannel-ipv4"],
        )?;
        assert!(
            table.contains("chain postrtg") && table.contains(&format!("saddr {MASQ_SUBNET}")),
            "nft table content mismatch:\n{table}"
        );
    } else {
        netutil::wait_until(
            "iptables FLANNEL-POSTRTG chain",
            Duration::from_secs(15),
            || {
                let nat = netutil::run_in_ns(&link.ns.name, "iptables-save", &["-t", "nat"])?;
                Ok(nat.contains("FLANNEL-POSTRTG"))
            },
        )
        .await?;
        let nat = netutil::run_in_ns(&link.ns.name, "iptables-save", &["-t", "nat"])?;
        assert!(
            nat.contains("10.244.0.0/16") && nat.contains("MASQUERADE"),
            "nat table content mismatch:\n{nat}"
        );
        let filter = netutil::run_in_ns(&link.ns.name, "iptables-save", &["-t", "filter"])?;
        assert!(
            filter.contains("FLANNEL-FWD"),
            "filter table missing FLANNEL-FWD:\n{filter}"
        );
    }

    // Clean shutdown runs the post-hook clean_up inside the netns.
    assert_eq!(daemon.shutdown(Duration::from_secs(15))?, 0);

    if use_nft {
        let tables = netutil::run_in_ns(&link.ns.name, "nft", &["list", "tables"])?;
        assert!(
            !tables.contains("flannel-ipv4"),
            "nft table must be removed by clean_up:\n{tables}"
        );
    } else {
        // Upstream CleanUp flushes the chain then deletes it (-F/-X); on
        // kernels where -X of a jump-referenced chain fails (nf_tables:
        // "Device or resource busy"), the empty FLANNEL-POSTRTG chain may
        // remain. Assert the *rules* are gone, not the chain header.
        let nat = netutil::run_in_ns(&link.ns.name, "iptables-save", &["-t", "nat"])?;
        assert!(
            !nat.contains("MASQUERADE"),
            "masquerade rules must be removed by clean_up:\n{nat}"
        );
        assert!(
            !nat.contains("10.244.0.0/16"),
            "flannel rule specs must be removed by clean_up:\n{nat}"
        );
    }
    Ok(())
}
