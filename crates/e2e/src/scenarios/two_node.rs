//! Two-node data-plane closed loop: two *real* flanneld instances, one
//! per netns (L2-adjacent on a shared host bridge), both learning the
//! peer's lease annotations through the mock apiserver's working watch,
//! then real CNI pods on each side and pod-to-pod ping over the
//! backend's actual data path (routes / vxlan / ipip / wireguard / udp).

use crate::cni;
use crate::daemonctl::{DaemonHandle, DaemonSpec};
use crate::netutil::{self, BridgeTopology};
use crate::{bins, E2EError, Scenario};
use anyhow::{anyhow, Result};
use serde_json::json;
use std::time::Duration;

const READY: Duration = Duration::from_secs(40);
const PING_RETRY: Duration = Duration::from_secs(30);

struct Case {
    name: &'static str,
    desc: &'static str,
    backend: serde_json::Value,
    overlay_dev: Option<&'static str>,
    /// Per-peer /24 kernel routes exist for host-gw/vxlan/ipip; the
    /// wireguard (cryptokey-routing trie) and udp (userspace proxy)
    /// backends only ever install the flannel-network route on the
    /// overlay device, so the peer wait is the network route instead.
    expect_peer_route: bool,
}

fn case_hostgw() -> Case {
    Case {
        name: "hostgw-datapath",
        desc: "host-gw: 2 nodes, pod-to-pod ping via kernel routes",
        backend: json!({"Type": "host-gw"}),
        overlay_dev: None,
        expect_peer_route: true,
    }
}
fn case_vxlan() -> Case {
    Case {
        name: "vxlan-datapath",
        desc: "vxlan: 2 nodes, pod-to-pod ping through flannel.1",
        backend: json!({"Type": "vxlan"}),
        overlay_dev: Some("flannel.1"),
        expect_peer_route: true,
    }
}
fn case_ipip() -> Case {
    Case {
        name: "ipip-datapath",
        desc: "ipip: 2 nodes, pod-to-pod ping through flannel.ipip",
        backend: json!({"Type": "ipip"}),
        overlay_dev: Some("flannel.ipip"),
        expect_peer_route: true,
    }
}
fn case_wireguard() -> Case {
    Case {
        name: "wireguard-datapath",
        desc: "wireguard: 2 nodes, pod-to-pod ping through flannel-wg (kernel)",
        backend: json!({"Type": "wireguard"}),
        overlay_dev: Some("flannel-wg"),
        expect_peer_route: false,
    }
}
fn case_udp() -> Case {
    Case {
        name: "udp-datapath",
        desc: "udp: 2 nodes, pod-to-pod ping through tun + userspace proxy",
        backend: json!({"Type": "udp"}),
        overlay_dev: Some("flannel0"),
        expect_peer_route: false,
    }
}

pub fn scenarios() -> Vec<Scenario> {
    vec![
        Scenario {
            name: case_hostgw().name,
            desc: case_hostgw().desc,
            run: || Box::pin(run_hostgw()),
        },
        Scenario {
            name: case_vxlan().name,
            desc: case_vxlan().desc,
            run: || Box::pin(run_vxlan()),
        },
        Scenario {
            name: case_ipip().name,
            desc: case_ipip().desc,
            run: || Box::pin(run_ipip()),
        },
        Scenario {
            name: case_wireguard().name,
            desc: case_wireguard().desc,
            run: || Box::pin(run_wireguard()),
        },
        Scenario {
            name: case_udp().name,
            desc: case_udp().desc,
            run: || Box::pin(run_udp()),
        },
    ]
}

/// Per-node WireGuard key file path (index = node position).
fn wgkey_file(dir: &tempfile::TempDir, i: usize) -> String {
    dir.path().join(format!("wgkey-{i}")).display().to_string()
}

async fn run_hostgw() -> Result<(), E2EError> {
    run_case(&case_hostgw()).await
}
async fn run_vxlan() -> Result<(), E2EError> {
    run_case(&case_vxlan()).await
}
async fn run_ipip() -> Result<(), E2EError> {
    run_case(&case_ipip()).await
}
async fn run_wireguard() -> Result<(), E2EError> {
    run_case(&case_wireguard()).await
}
async fn run_udp() -> Result<(), E2EError> {
    run_case(&case_udp()).await
}

async fn run_case(case: &Case) -> Result<(), E2EError> {
    let prefix = &case.name;
    let topo = netutil::build_bridge_topology(prefix)?;
    let api = crate::apiserver::MockApiserver::start().await?;
    for n in &topo.nodes {
        api.put_node(&n.name, &n.pod_cidr).await;
    }

    // WireGuard keys default to the node-local file /run/flannel/wgkey;
    // both daemons share this host's filesystem, so give each its own
    // key file (distinct keys are what makes the peers actually pair).
    let wgkey_dir = tempfile::tempdir()?;

    let flannel_bin = bins::flannel()?;
    let plugins = tempfile::tempdir()?;
    netutil::extract_cni_plugins(plugins.path())?;

    // Boot both daemons sequentially (NODE_NAME is process-global and is
    // consumed during subnet-manager creation; the readiness wait is the
    // barrier).
    let net_conf = json!({"Network": "10.244.0.0/16", "Backend": case.backend});
    let a = &topo.nodes[0];
    let mut da = DaemonHandle::spawn(
        DaemonSpec::new(&a.name, &api.url_on(&topo.bridge_ip), net_conf.clone())
            .in_netns(&a.ns.path())
            .iface(&a.ext_iface)
            .env("WIREGUARD_KEY_FILE", &wgkey_file(&wgkey_dir, 0)),
    )?;
    da.wait_ready(READY).await?;
    let b = &topo.nodes[1];
    let mut db = DaemonHandle::spawn(
        DaemonSpec::new(&b.name, &api.url_on(&topo.bridge_ip), net_conf)
            .in_netns(&b.ns.path())
            .iface(&b.ext_iface)
            .env("WIREGUARD_KEY_FILE", &wgkey_file(&wgkey_dir, 1)),
    )?;
    db.wait_ready(READY).await?;

    // Cross-subnet routes must appear on both sides (learned through the
    // apiserver watch, not preconfigured). host-gw/vxlan/ipip install a
    // per-peer /24 route; wireguard/udp keep only the flannel-network
    // route on the overlay device (peer dispatch is internal -- wg
    // cryptokey-routing trie / userspace proxy) and are proven by the
    // pod-to-pod ping below.
    let overlay_dev = case.overlay_dev.map(str::to_string);
    let expect_peer_route = case.expect_peer_route;
    let expect = [
        (a.name.clone(), a.ns.name.clone(), b.pod_cidr.clone()),
        (b.name.clone(), b.ns.name.clone(), a.pod_cidr.clone()),
    ];
    for (node, ns, peer_cidr) in expect {
        let ns_in = ns.clone();
        let dev = overlay_dev.clone();
        netutil::wait_until(
            &format!("route to {peer_cidr} on {node}"),
            READY,
            move || {
                let out = netutil::run_in_ns(&ns_in, "ip", &["-o", "route"])?;
                Ok(if expect_peer_route {
                    out.lines().any(|l| l.contains(&peer_cidr))
                } else {
                    let dev = dev
                        .as_deref()
                        .expect("non-peer-route backend has overlay dev");
                    out.lines()
                        .any(|l| l.contains("10.244.0.0/16") && l.contains(&format!("dev {dev}")))
                })
            },
        )
        .await
        .map_err(|e| anyhow!("{e}\nroutes on {node}:\n{}", netutil::dump_routes(&ns)))?;
    }

    // Real CNI ADD on both sides (bridge + host-local inside each node ns).
    let (pod_a_ip, pod_b_ip) = add_both_pods(&flannel_bin, &plugins, &topo, &da, &db).await?;
    // pod_cidr string check: "10.244.0.0/24".contains("10.244.0") is weak;
    // parse both and verify containment via IP4Net.
    let net_a: flannel_core::ip::IP4Net = a.pod_cidr.parse().map_err(anyhow::Error::from)?;
    let net_b: flannel_core::ip::IP4Net = b.pod_cidr.parse().map_err(anyhow::Error::from)?;
    assert!(
        net_a.contains(pod_a_ip.parse().map_err(anyhow::Error::from)?),
        "pod A ip {pod_a_ip} outside {net_a}"
    );
    assert!(
        net_b.contains(pod_b_ip.parse().map_err(anyhow::Error::from)?),
        "pod B ip {pod_b_ip} outside {net_b}"
    );

    // Pod-to-pod ping both directions (retry: wireguard handshake, FDB /
    // ARP warm-up).
    ping_retry(&a.pod_ns.name, &pod_b_ip).await?;
    ping_retry(&b.pod_ns.name, &pod_a_ip).await?;

    // Overlay proof: tx counter on the backend device must increase.
    if let Some(dev) = case.overlay_dev {
        let before = netutil::link_tx_packets(&a.ns.name, dev)?;
        let _ = netutil::ping_from_ns(&a.pod_ns.name, &pod_b_ip);
        let after = netutil::link_tx_packets(&a.ns.name, dev)?;
        assert!(
            after > before,
            "no traffic observed on overlay device {dev} ({before} -> {after})"
        );
    }

    // Cleanup: idempotent DEL, both daemons exit 0 on cancel.
    let (bin, cni_path, ns_a, ns_b, pod_a, pod_b, sf_a, sf_b) = (
        flannel_bin,
        plugins.path().to_path_buf(),
        a.ns.name.clone(),
        b.ns.name.clone(),
        a.pod_ns.path(),
        b.pod_ns.path(),
        da.subnet_file.clone(),
        db.subnet_file.clone(),
    );
    crate::blocking(move || {
        cni::cni_del(&bin, Some(&ns_a), &pod_a, &cni_path, &sf_a, "pod-a")?;
        cni::cni_del(&bin, Some(&ns_b), &pod_b, &cni_path, &sf_b, "pod-b")
    })
    .await?;
    assert_eq!(da.shutdown(Duration::from_secs(20))?, 0);
    assert_eq!(db.shutdown(Duration::from_secs(20))?, 0);
    Ok(())
}

async fn add_both_pods(
    flannel_bin: &std::path::Path,
    plugins: &tempfile::TempDir,
    topo: &BridgeTopology,
    da: &DaemonHandle,
    db: &DaemonHandle,
) -> Result<(String, String)> {
    let a = &topo.nodes[0];
    let b = &topo.nodes[1];
    let (bin, cni_path) = (flannel_bin.to_path_buf(), plugins.path().to_path_buf());
    let (ns_a, pod_a, sf_a) = (a.ns.name.clone(), a.pod_ns.path(), da.subnet_file.clone());
    let (ns_b, pod_b, sf_b) = (b.ns.name.clone(), b.pod_ns.path(), db.subnet_file.clone());
    crate::blocking(move || {
        let ra = cni::cni_add(&bin, Some(&ns_a), &pod_a, &cni_path, &sf_a, "pod-a")?;
        let rb = cni::cni_add(&bin, Some(&ns_b), &pod_b, &cni_path, &sf_b, "pod-b")?;
        let ipa = cni::eth0_ip(&ra).ok_or_else(|| anyhow!("pod-a eth0 address missing: {ra}"))?;
        let ipb = cni::eth0_ip(&rb).ok_or_else(|| anyhow!("pod-b eth0 address missing: {rb}"))?;
        Ok((ipa, ipb))
    })
    .await
}

async fn ping_retry(ns: &str, target: &str) -> Result<(), E2EError> {
    let (ns_owned, target_owned) = (ns.to_string(), target.to_string());
    netutil::wait_until(
        &format!("ping from {ns_owned} to {target_owned}"),
        PING_RETRY,
        move || Ok(netutil::ping_from_ns(&ns_owned, &target_owned).is_ok()),
    )
    .await
    .map_err(|e| anyhow!("{e}\nroutes in {ns}:\n{}", netutil::dump_routes(ns)))?;
    Ok(())
}
