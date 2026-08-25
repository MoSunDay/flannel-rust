//! CNI exec protocol against the real `flannel` meta-plugin binary:
//! ADD / DEL / VERSION. When `node_ns` is given the binary runs via
//! `ip netns exec <node_ns>` so the bridge/host-local delegate state
//! (bridge device, routes) lands in the node netns.

use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::path::Path;
use std::process::{Command, Stdio};

const NETCONF: &str = r#"{"cniVersion":"0.4.0","name":"e2e","type":"flannel"}"#;

fn run_cni(
    command: &str,
    flannel_bin: &Path,
    node_ns: Option<&str>,
    cni_netns: &Path,
    cni_path: &Path,
    subnet_file: &Path,
    container_id: &str,
) -> Result<(bool, String, String)> {
    use std::io::Write;
    let mut cmd = if let Some(ns) = node_ns {
        let mut c = Command::new("ip");
        c.args(["netns", "exec", ns]);
        c.arg(flannel_bin);
        c
    } else {
        Command::new(flannel_bin)
    };
    let mut child = cmd
        .env("CNI_COMMAND", command)
        .env("CNI_CONTAINERID", container_id)
        .env("CNI_NETNS", cni_netns)
        .env("CNI_IFNAME", "eth0")
        .env(
            "CNI_ARGS",
            "IgnoreUnknown=1;K8S_POD_NAMESPACE=e2e;K8S_POD_NAME=e2e",
        )
        .env("CNI_PATH", cni_path)
        .env("FLANNEL_SUBNET_FILE", subnet_file)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawning flannel for {command}"))?;
    child
        .stdin
        .take()
        .expect("stdin piped")
        .write_all(NETCONF.as_bytes())?;
    let out = child.wait_with_output().context("waiting for flannel")?;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    Ok((out.status.success(), stdout, stderr))
}

/// CNI ADD; returns the parsed result JSON (0.4.0 result with interfaces
/// and ips). Bails with the plugin stderr on failure.
pub fn cni_add(
    flannel_bin: &Path,
    node_ns: Option<&str>,
    pod_netns: &Path,
    cni_path: &Path,
    subnet_file: &Path,
    container_id: &str,
) -> Result<Value> {
    let (ok, stdout, stderr) = run_cni(
        "ADD",
        flannel_bin,
        node_ns,
        pod_netns,
        cni_path,
        subnet_file,
        container_id,
    )?;
    if !ok {
        bail!("CNI ADD failed: stdout={stdout:?} stderr={stderr:?}");
    }
    serde_json::from_str(&stdout).context("parsing CNI ADD result")
}

/// CNI DEL; the plugin must succeed even when state is already gone
/// (idempotency is asserted by calling it twice).
pub fn cni_del(
    flannel_bin: &Path,
    node_ns: Option<&str>,
    pod_netns: &Path,
    cni_path: &Path,
    subnet_file: &Path,
    container_id: &str,
) -> Result<()> {
    let (ok, _stdout, stderr) = run_cni(
        "DEL",
        flannel_bin,
        node_ns,
        pod_netns,
        cni_path,
        subnet_file,
        container_id,
    )?;
    if !ok {
        bail!("CNI DEL failed: stdout={_stdout:?} stderr={stderr:?}");
    }
    Ok(())
}

/// CNI VERSION handshake.
pub fn cni_version(flannel_bin: &Path, cni_path: &Path) -> Result<Value> {
    let (ok, stdout, stderr) = run_cni(
        "VERSION",
        flannel_bin,
        None,
        Path::new("/nonexistent"),
        cni_path,
        Path::new("/nonexistent"),
        "version-probe",
    )?;
    if !ok {
        bail!("CNI VERSION failed: {stderr}");
    }
    serde_json::from_str(&stdout).context("parsing CNI VERSION result")
}

/// First address bound to the `eth0` interface (without the prefix).
pub fn eth0_ip(result: &Value) -> Option<String> {
    let interfaces = result["interfaces"].as_array()?;
    let eth0_index = interfaces
        .iter()
        .position(|iface| iface["name"] == "eth0")?;
    result["ips"].as_array()?.iter().find_map(|ip| {
        if ip["interface"].as_u64() != Some(eth0_index as u64) {
            return None;
        }
        ip["address"]
            .as_str()
            .and_then(|a| a.split('/').next().map(str::to_string))
    })
}

/// Wipe host-local's default dataDir (`/var/lib/cni/networks`). The
/// directory lives in the host mount namespace, so it is shared by every
/// `ip netns exec`'d CNI ADD/DEL; a scenario that fails mid-way skips
/// DEL and leaks an allocation ("10.244.0.2 has been allocated to
/// pod-a") that would break the next scenario's ADD. Run before each
/// scenario.
pub fn clear_ipam_state() -> Result<()> {
    let dir = Path::new("/var/lib/cni/networks");
    std::fs::create_dir_all(dir)?;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let p = entry.path();
        if p.is_dir() {
            std::fs::remove_dir_all(&p)?;
        } else {
            std::fs::remove_file(&p)?;
        }
    }
    Ok(())
}
