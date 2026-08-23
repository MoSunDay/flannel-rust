//! `newSubnetManager`, `getConfig` and the br_netfilter sanity check.
//! Ports of the same-named main.go helpers (upstream cdf76059).

use crate::Options;
use flannel_core::kube::{KubeClient, KubeConfig};
use flannel_core::subnet::kube::new_subnet_manager;
use flannel_core::subnet::{Config, KubeSubnetManager};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// Go `/proc/sys/net/bridge/bridge-nf-call-iptables`.
pub const BR_NETFILTER_V4_PATH: &str = "/proc/sys/net/bridge/bridge-nf-call-iptables";
/// Go `/proc/sys/net/bridge/bridge-nf-call-ip6tables`.
pub const BR_NETFILTER_V6_PATH: &str = "/proc/sys/net/bridge/bridge-nf-call-ip6tables";

/// Go: `errors.Is(err, context.DeadlineExceeded)` around the kube
/// subnet manager constructor. The Rust kube port surfaces this as the
/// "context deadline exceeded" bail of `wait_synced` (informer initial
/// sync); reqwest-level timeouts render as "operation timed out".
/// Matching on the error text is the documented stand-in for Go's
/// typed `errors.Is` check (anyhow has no downcast target here).
pub fn is_timeout_like(err: &anyhow::Error) -> bool {
    let text = format!("{err:#}").to_ascii_lowercase();
    text.contains("deadline exceeded") || text.contains("timed out") || text.contains("timeout")
}

/// Go: `newSubnetManager(ctx)`. flannel-rust only ports the kube
/// branch; the etcd branch is rejected (accepted flags, no etcd code).
/// KubeConfig resolution mirrors Go's `BuildConfigFromFlags(kubeApiUrl,
/// kubeConfigFile)`.
pub async fn create_subnet_manager(
    opts: &Options,
    ctx: &CancellationToken,
) -> anyhow::Result<Arc<KubeSubnetManager>> {
    if !opts.kube_subnet_mgr {
        anyhow::bail!("flannel-rust only supports --kube-subnet-mgr (no etcd)");
    }
    let config: KubeConfig =
        flannel_core::kube::resolve(&opts.kube_api_url, &opts.kubeconfig_file)?;
    let client = KubeClient::new(config)?;
    new_subnet_manager(
        ctx,
        client,
        &opts.kube_annotation_prefix,
        &opts.net_config_path,
        opts.set_node_network_unavailable,
    )
    .await
}

/// Go: `getConfig(ctx, sm)` — retry every second until the network
/// config is available; return the "canceled" sentinel error when the
/// token fires first (Go: `errCanceled`, main exits 0).
///
/// Go's `config == nil` warning branch cannot occur: the Rust
/// `Manager::get_network_config` returns `Result<Config>` (the kube
/// implementation always answers with the parsed net-conf). Go's
/// stray `fmt.Println("timed out")` per retry is dropped on purpose.
pub async fn get_config(
    ctx: &CancellationToken,
    sm: &dyn flannel_core::subnet::Manager,
) -> anyhow::Result<Config> {
    loop {
        match sm.get_network_config(ctx).await {
            Ok(config) => {
                tracing::info!(
                    "Found network config - Backend type: {}",
                    config.backend_type
                );
                return Ok(config);
            }
            Err(e) => tracing::error!("Couldn't fetch network config: {e}"),
        }
        tokio::select! {
            _ = ctx.cancelled() => return Err(anyhow::anyhow!("canceled")),
            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
        }
    }
}

/// Go's br_netfilter probe: for each enabled family the corresponding
/// `/proc/sys/net/bridge/bridge-nf-call-*` file must exist (paths are
/// parameters so the check is testable). Go only fails on
/// `os.IsNotExist`; other stat errors pass, and the check is skipped
/// entirely when `EnableNFTables` is set (caller's responsibility) or
/// on Windows (not a Rust port target).
pub fn check_br_netfilter_paths(
    enable_ipv4: bool,
    enable_ipv6: bool,
    v4_path: &str,
    v6_path: &str,
) -> anyhow::Result<()> {
    if enable_ipv4 {
        check_exists(v4_path)?;
    }
    if enable_ipv6 {
        check_exists(v6_path)?;
    }
    Ok(())
}

fn check_exists(path: &str) -> anyhow::Result<()> {
    match std::fs::metadata(path) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err(anyhow::anyhow!("Failed to check br_netfilter: {e}"))
        }
        // Go: only os.IsNotExist(err) aborts; anything else passes.
        Err(_) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn br_netfilter_missing_path_fails() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope").display().to_string();
        let err = check_br_netfilter_paths(true, false, &missing, &missing)
            .unwrap_err()
            .to_string();
        assert!(err.starts_with("Failed to check br_netfilter: "), "{err}");
    }

    #[test]
    fn br_netfilter_existing_path_passes() {
        let dir = tempfile::tempdir().unwrap();
        let v4 = dir.path().join("v4");
        let v6 = dir.path().join("v6");
        std::fs::write(&v4, "1").unwrap();
        std::fs::write(&v6, "1").unwrap();
        check_br_netfilter_paths(
            true,
            true,
            &v4.display().to_string(),
            &v6.display().to_string(),
        )
        .unwrap();
        // Disabled families are not probed even with bogus paths.
        check_br_netfilter_paths(false, false, "/nonexistent/v4", "/nonexistent/v6").unwrap();
    }

    #[test]
    fn timeout_like_errors_detected() {
        let deadline = anyhow::anyhow!(
            "error waiting for nodeController to sync state: context deadline exceeded"
        );
        assert!(is_timeout_like(&deadline));
        let timeout = anyhow::anyhow!("http request failed: operation timed out");
        assert!(is_timeout_like(&timeout));
        let other = anyhow::anyhow!("connection refused");
        assert!(!is_timeout_like(&other));
    }
}
