//! Port of the watch + stored-annotation accessors of pkg/subnet/kube
//! kube.go (upstream cdf76059): `WatchLeases`, `WatchLease`,
//! `GetStoredMacAddresses`, `GetStoredPublicIP`.
//!
//! Deviations from Go (documented):
//! - Go's `events` channel has one consumer; here the informer feeds an
//!   [`EventHub`] fan-out (bounded backlog + replay on subscribe,
//!   blocking backpressure: a stalled watcher slows the informer instead
//!   of losing its subscription) so `watch_leases` and `watch_lease` can
//!   run independently.
//! - Go's `WatchLease` returns `ErrUnimplemented`; this port implements
//!   it as a filter for the single subnet (sn, sn6).
//! - `GetStoredMacAddresses` reads the NORMALIZED annotation keys
//!   (`newAnnotations(prefix).BackendData/BackendV6Data`, i.e. the keys
//!   flannel itself writes); Go kube.go:711/719 builds the read key from
//!   the raw `--kube-annotation-prefix` + "/backend-data", which only
//!   coincides with the written key when normalization appends "/"
//!   (default prefix). For a prefix like `example.com/flannel`
//!   (normalized to `example.com/flannel-`) Go reads a key it never
//!   wrote; `GetStoredPublicIP` (kube.go:748-749) already reads the
//!   normalized keys. We always read the normalized keys.

use crate::ip::{IP4Net, IP6Net};
use crate::lease::{Event, LeaseWatchResult};
use crate::subnet::manager::Ctx;

use super::annotations::annotation;
use super::KubeSubnetManager;

/// Forward one internal event to the watcher channel as a single
/// LeaseWatchResult batch (Go: `receiver <- []lease.LeaseWatchResult{{
/// Events: []lease.Event{event}}}`).
async fn forward(
    tx: &tokio::sync::mpsc::Sender<Vec<LeaseWatchResult>>,
    event: Event,
) -> anyhow::Result<()> {
    tx.send(vec![LeaseWatchResult {
        events: vec![event],
        snapshot: Vec::new(),
    }])
    .await
    .map_err(|e| anyhow::anyhow!("watch receiver closed: {e}"))
}

/// Go: `WatchLeases`. Forwards every internal lease event until `ctx`
/// is cancelled; Go returns `ctx.Err()` there ("context canceled").
pub(crate) async fn watch_leases(
    mgr: &KubeSubnetManager,
    ctx: Ctx<'_>,
    tx: tokio::sync::mpsc::Sender<Vec<LeaseWatchResult>>,
) -> anyhow::Result<()> {
    let mut rx = mgr.hub.subscribe();
    loop {
        tokio::select! {
            biased;
            _ = ctx.cancelled() => {
                return Err(anyhow::anyhow!("context canceled"));
            }
            res = rx.recv() => {
                // Go blocks on `receiver <- ...` until ctx cancels; when
                // the downstream receiver is dropped we return instead.
                let Some(event) = res else { return Ok(()) };
                if forward(&tx, event).await.is_err() {
                    return Ok(());
                }
            }
        }
    }
}

/// Rust implementation of Go's `WatchLease` (Go: `ErrUnimplemented`):
/// forwards only events whose lease belongs to subnet `sn` (or `sn6`).
pub(crate) async fn watch_lease(
    mgr: &KubeSubnetManager,
    ctx: Ctx<'_>,
    sn: IP4Net,
    sn6: IP6Net,
    tx: tokio::sync::mpsc::Sender<Vec<LeaseWatchResult>>,
) -> anyhow::Result<()> {
    let mut rx = mgr.hub.subscribe();
    loop {
        tokio::select! {
            biased;
            _ = ctx.cancelled() => {
                return Err(anyhow::anyhow!("context canceled"));
            }
            res = rx.recv() => {
                let Some(event) = res else { return Ok(()) };
                // An unset (empty) filter net must not match: the
                // zero-value v6 subnet of a v4-only lease would
                // otherwise equal a zero-value `sn6` argument.
                let v4_match = !sn.empty() && event.lease.subnet == sn;
                let v6_match = !sn6.empty() && event.lease.ipv6_subnet == sn6;
                if !v4_match && !v6_match {
                    continue;
                }
                if forward(&tx, event).await.is_err() {
                    return Ok(());
                }
            }
        }
    }
}

/// Go: `GetStoredMacAddresses` (never errors; "" on any failure).
///
/// Quirk kept: Go trims the chars `"` and `}` from both ends of the raw
/// annotation (`{"VNI":1,"VtepMAC":"aa:bb.."}` -> `..,"VtepMAC":"aa:bb..`)
/// then splits on `:"` and takes part 1 when there are exactly 2 parts.
///
/// Reads the NORMALIZED keys `annotations.backend_data` /
/// `backend_v6_data` - the exact keys flannel patches onto the node -
/// instead of Go kube.go:711/719's raw-prefix
/// `fmt.Sprintf("%s/backend-data", ksm.annotationPrefix)`; see the
/// module-level deviation note.
pub(crate) async fn get_stored_mac_addresses(
    mgr: &KubeSubnetManager,
    _ctx: Ctx<'_>,
) -> (String, String) {
    let node = match mgr.client.get_node(&mgr.node_name).await {
        Ok(node) => node,
        Err(e) => {
            tracing::error!("Failed to get node for backend data: {e}");
            return (String::new(), String::new());
        }
    };

    let ann = &node.metadata.annotations;
    tracing::info!("List of node({}) annotations: {ann:?}", mgr.node_name);

    let macv4 = extract_mac(ann.get(&mgr.annotations.backend_data));
    let macv6 = extract_mac(ann.get(&mgr.annotations.backend_v6_data));
    (macv4, macv6)
}

fn extract_mac(value: Option<&String>) -> String {
    let Some(backend_data) = value else {
        return String::new();
    };
    // Go: strings.Trim(backendData, "\"}") trims both ends.
    let mac_str = backend_data.trim_matches(|c| c == '"' || c == '}');
    let parts: Vec<&str> = mac_str.split(":\"").collect();
    if parts.len() == 2 {
        parts[1].to_string()
    } else {
        String::new()
    }
}

/// Go: `GetStoredPublicIP` (never errors; "" on any failure). Reads the
/// normalized annotation keys (not the raw prefix ones).
pub(crate) async fn get_stored_public_ip(
    mgr: &KubeSubnetManager,
    _ctx: Ctx<'_>,
) -> (String, String) {
    let node = match mgr.client.get_node(&mgr.node_name).await {
        Ok(node) => node,
        Err(e) => {
            tracing::error!("Failed to get node for backend data: {e}");
            return (String::new(), String::new());
        }
    };

    let ann = &node.metadata.annotations;
    tracing::info!("List of node({}) annotations: {ann:?}", mgr.node_name);
    (
        annotation(ann, &mgr.annotations.backend_node_public_ip).to_string(),
        annotation(ann, &mgr.annotations.backend_node_public_ipv6).to_string(),
    )
}
