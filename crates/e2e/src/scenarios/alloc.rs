//! Single-node closed loop with the `alloc` backend: mock apiserver ->
//! real flanneld (alloc) -> subnet.env -> real CNI ADD/DEL (bridge +
//! host-local) -> pod eth0 IP inside the leased subnet, lease
//! annotations + NetworkUnavailable status patch, clean shutdown.

use crate::cni;
use crate::daemonctl::{DaemonHandle, DaemonSpec};
use crate::netutil;
use crate::{bins, E2EError, Scenario};
use serde_json::json;
use std::time::Duration;

pub fn scenario() -> Scenario {
    Scenario {
        name: "alloc-closed-loop",
        desc: "daemon(alloc) -> subnet.env -> CNI ADD/DEL -> pod IP in lease, annotations, exit 0",
        run: || Box::pin(run()),
    }
}

async fn run() -> Result<(), E2EError> {
    let link = netutil::build_solo_link("alloc")?;
    let api = crate::apiserver::MockApiserver::start().await?;
    api.put_node("e2e-alloc", "10.244.9.0/24").await;

    let flannel_bin = bins::flannel()?;
    let plugins = tempfile::tempdir()?;
    netutil::extract_cni_plugins(plugins.path())?;

    let net_conf = json!({"Network": "10.244.0.0/16", "Backend": {"Type": "alloc"}});
    let mut daemon = DaemonHandle::spawn(
        DaemonSpec::new("e2e-alloc", &api.url_on(&link.host_ip), net_conf)
            .in_netns(&link.ns.path())
            .iface(&link.ns_iface),
    )?;

    // 1. Daemon boots, acquires the lease, writes subnet.env.
    let env = daemon.wait_ready(Duration::from_secs(30)).await?;
    let vars = daemon.subnet_env()?;
    assert_eq!(
        vars.get("FLANNEL_NETWORK").map(String::as_str),
        Some("10.244.0.0/16")
    );
    assert_eq!(
        vars.get("FLANNEL_SUBNET").map(String::as_str),
        Some("10.244.9.1/24")
    );
    assert_eq!(
        vars.get("FLANNEL_IPMASQ").map(String::as_str),
        Some("false")
    );
    assert!(
        vars.get("FLANNEL_MTU")
            .map(|m| m.parse::<u32>().unwrap_or(0))
            .unwrap_or(0)
            > 0
    );
    drop(env);

    // 2. Real CNI ADD inside the node netns -> pod eth0 in the lease.
    let bin = flannel_bin.clone();
    let node_ns = link.ns.name.clone();
    let pod_ns = link.pod_ns.path();
    let cni_path = plugins.path().to_path_buf();
    let subnet_file = daemon.subnet_file.clone();
    let result = crate::blocking({
        let (bin, node_ns, pod_ns, cni_path) = (
            bin.clone(),
            node_ns.clone(),
            pod_ns.clone(),
            cni_path.clone(),
        );
        move || {
            cni::cni_add(
                &bin,
                Some(&node_ns),
                &pod_ns,
                &cni_path,
                &subnet_file,
                "alloc-pod",
            )
        }
    })
    .await?;
    let pod_ip = cni::eth0_ip(&result)
        .ok_or_else(|| anyhow::anyhow!("CNI ADD result has no eth0 address"))?;
    let subnet: flannel_core::ip::IP4Net = "10.244.9.0/24".parse().map_err(anyhow::Error::from)?;
    let pod_v4: flannel_core::ip::IP4 = pod_ip.parse().map_err(anyhow::Error::from)?;
    assert!(
        subnet.contains(pod_v4),
        "pod IP {pod_ip} outside lease {subnet}"
    );

    // 3. DEL twice (idempotent) and the VERSION handshake.
    let (bin2, node_ns2, pod_ns2, cni_path2, subnet_file2) = (
        bin.clone(),
        node_ns.clone(),
        pod_ns.clone(),
        cni_path.clone(),
        daemon.subnet_file.clone(),
    );
    crate::blocking(move || {
        cni::cni_del(
            &bin2,
            Some(&node_ns2),
            &pod_ns2,
            &cni_path2,
            &subnet_file2,
            "alloc-pod",
        )
    })
    .await?;
    let (bin3, node_ns3, pod_ns3, cni_path3, subnet_file3) = (
        bin.clone(),
        node_ns.clone(),
        pod_ns.clone(),
        cni_path.clone(),
        daemon.subnet_file.clone(),
    );
    crate::blocking(move || {
        cni::cni_del(
            &bin3,
            Some(&node_ns3),
            &pod_ns3,
            &cni_path3,
            &subnet_file3,
            "alloc-pod",
        )
    })
    .await?;
    let (bin4, cni_path4) = (bin.clone(), cni_path.clone());
    let version = crate::blocking(move || cni::cni_version(&bin4, &cni_path4)).await?;
    let supported = version["supportedVersions"]
        .as_array()
        .map(|a| a.iter().any(|v| v == "0.4.0"))
        .unwrap_or(false);
    assert!(supported, "CNI VERSION must advertise 0.4.0: {version}");

    // 4. Lease annotations + NetworkUnavailable status patch.
    let ann = api.annotations("e2e-alloc").await;
    assert_eq!(
        ann["flannel.alpha.coreos.com/kube-subnet-manager"].as_str(),
        Some("true")
    );
    assert!(ann.get("flannel.alpha.coreos.com/backend-type").is_some());
    let patches = api.patches().await;
    let status_patched = patches
        .iter()
        .any(|(_, node, body)| node == "e2e-alloc" && body.get("status").is_some());
    assert!(
        status_patched,
        "daemon must patch NetworkUnavailable status"
    );

    // 5. Clean shutdown through the cancellation path (exit 0).
    let code = daemon.shutdown(Duration::from_secs(15))?;
    assert_eq!(code, 0, "flanneld must exit 0 on cancel");
    Ok(())
}
