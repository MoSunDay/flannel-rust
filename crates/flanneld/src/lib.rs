//! flanneld: the flannel node daemon. Port of flannel `main.go`
//! (upstream cdf76059). Functional style: plain `Options` data plus free
//! functions; traits only for the traffic-manager seam.
//!
//! Module layout:
//! - `flags_defs`: CLI flag registration and `Options` collection
//! - `daemon`: the `main()` orchestration port
//! - `subnet_mgr`: `newSubnetManager` + `getConfig` + br_netfilter check
//! - `iface_select`: external interface selection (`match.go` callers)
//! - `healthz`: healthz/readyz HTTP server
//! - `subnetfile`: previous-CIDR readers for subnet.env
//! - `traffic`: TrafficManager seam (noop until P3)
//! - `systemd`: sd_notify READY=1

pub mod daemon;
pub mod flags_defs;
pub mod healthz;
pub mod iface_select;
pub mod subnet_mgr;
pub mod subnetfile;
pub mod systemd;
pub mod traffic;

pub use flags_defs::Options;

/// Go `version.Version` equivalent for this port.
pub const VERSION: &str = "flannel-rust v0.1.0";

use tokio_util::sync::CancellationToken;

/// Daemon entry point (library form of Go `main()`). Returns the process
/// exit code; `Err` is reserved for truly unexpected failures (main maps
/// it to exit 1). Cancellation of `cancel` yields a clean exit 0, like
/// Go's signal-driven shutdown.
pub async fn run(opts: Options, cancel: CancellationToken) -> anyhow::Result<i32> {
    daemon::run(opts, cancel).await
}
