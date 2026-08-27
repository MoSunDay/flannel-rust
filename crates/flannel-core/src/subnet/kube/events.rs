//! Lease-event generation from node objects: ports Go
//! `handleAddLeaseEvent`, `handleUpdateLeaseEvent`, `enqueueLeaseEvent`
//! and `nodeToLease` (pkg/subnet/kube/kube.go, upstream cdf76059).
//!
//! Like Go, the handlers do NOT skip the own node here: own-lease
//! filtering happens downstream in `LeaseWatcher` (subnet/watch.rs).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::value::RawValue;
use tokio::sync::{mpsc, Semaphore};
use tokio_util::sync::CancellationToken;

use crate::ip::{IP4Net, IP6Net};
use crate::kube::Node;
use crate::lease::{Event, EventType, Lease, LeaseAttrs};

use super::annotations::{annotation, Annotations};

/// Shared environment of the lease-event handlers (Go: fields of the
/// `kubeSubnetManager` receiver). Pure data record, passed by reference.
pub(crate) struct EventEnv<'a> {
    pub(crate) ctx: &'a CancellationToken,
    pub(crate) tx: &'a mpsc::Sender<Event>,
    pub(crate) sem: &'a Arc<Semaphore>,
    pub(crate) annotations: &'a Annotations,
    pub(crate) enable_ipv4: bool,
    pub(crate) enable_ipv6: bool,
}

/// Go: `handleAddLeaseEvent(ctx, et, obj)`.
pub(crate) async fn handle_add_lease_event(env: &EventEnv<'_>, et: EventType, node: &Node) {
    let ann = &node.metadata.annotations;
    if annotation(ann, &env.annotations.subnet_kube_managed) != "true" {
        return;
    }
    let lease = match node_to_lease(node, env.annotations, env.enable_ipv4, env.enable_ipv6) {
        Ok(l) => l,
        Err(e) => {
            tracing::info!("Error turning node {:?} to lease: {e}", node.metadata.name);
            return;
        }
    };
    enqueue_lease_event(
        env.ctx,
        env.tx,
        env.sem,
        Event {
            event_type: et,
            lease,
        },
        &node.metadata.name,
    )
    .await;
}

/// Go: `handleUpdateLeaseEvent(ctx, oldObj, newObj)`: verifies anything
/// relevant changed (backend-data, backend-type, public-ip per family).
/// Ported exactly, including Go's sequential `changed` overwrites.
pub(crate) async fn handle_update_lease_event(env: &EventEnv<'_>, old: &Node, new: &Node) {
    let o = &old.metadata.annotations;
    let n = &new.metadata.annotations;
    if annotation(n, &env.annotations.subnet_kube_managed) != "true" {
        return;
    }
    let mut changed = true;
    if env.enable_ipv4
        && annotation(o, &env.annotations.backend_data)
            == annotation(n, &env.annotations.backend_data)
        && annotation(o, &env.annotations.backend_type)
            == annotation(n, &env.annotations.backend_type)
        && annotation(o, &env.annotations.backend_public_ip)
            == annotation(n, &env.annotations.backend_public_ip)
    {
        changed = false;
    }

    if env.enable_ipv6
        && annotation(o, &env.annotations.backend_v6_data)
            == annotation(n, &env.annotations.backend_v6_data)
        && annotation(o, &env.annotations.backend_type)
            == annotation(n, &env.annotations.backend_type)
        && annotation(o, &env.annotations.backend_public_ipv6)
            == annotation(n, &env.annotations.backend_public_ipv6)
    {
        changed = false;
    }

    if !changed {
        return; // No change to lease
    }

    let lease = match node_to_lease(new, env.annotations, env.enable_ipv4, env.enable_ipv6) {
        Ok(l) => l,
        Err(e) => {
            tracing::info!("Error turning node {:?} to lease: {e}", new.metadata.name);
            return;
        }
    };
    enqueue_lease_event(
        env.ctx,
        env.tx,
        env.sem,
        Event {
            event_type: EventType::Added,
            lease,
        },
        &new.metadata.name,
    )
    .await;
}

/// Go: `enqueueLeaseEvent(ctx, evt, nodeName)`. Try a non-blocking send;
/// when the channel is full, retry asynchronously with exponential
/// backoff (100ms doubling to 5s) bounded by a 100-slot semaphore.
///
/// Like Go's `asyncSendSemaphore.Acquire(ctx, 1)`, acquiring a retry
/// slot BLOCKS until one frees or `ctx` is done: when all 100 slots are
/// busy the informer handler waits instead of dropping the event.
///
/// Adaptation: Go's retry goroutine creates a ticker but its select has
/// no ticker.C case, i.e. it busy-spins; this port actually sleeps the
/// backoff duration instead (same bounds, no CPU burn).
pub(crate) async fn enqueue_lease_event(
    ctx: &CancellationToken,
    tx: &mpsc::Sender<Event>,
    sem: &Arc<Semaphore>,
    evt: Event,
    node_name: &str,
) {
    // Try to send immediately.
    match tx.try_send(evt.clone()) {
        Ok(()) => return,
        // Go: no consumer but channel open -> block until ctx done; here
        // the receiver is gone, so dropping matches the eventual outcome.
        Err(mpsc::error::TrySendError::Closed(_)) => return,
        Err(mpsc::error::TrySendError::Full(_)) => {
            tracing::info!("Channel buffer full, add event asynchronously");
        }
    }

    // Block until a retry slot is free or the context is done.
    let permit = tokio::select! {
        biased;
        _ = ctx.cancelled() => {
            tracing::error!(
                "Context cancelled while acquiring semaphore for node {node_name:?}"
            );
            return;
        }
        acquired = sem.clone().acquire_owned() => match acquired {
            Ok(permit) => permit,
            Err(e) => {
                tracing::error!(
                    "error in acquiring semaphore for async event send, dropping event: {e}"
                );
                return;
            }
        },
    };

    let ctx = ctx.clone();
    let tx = tx.clone();
    let node_name = node_name.to_string();
    tokio::spawn(async move {
        let mut backoff = Duration::from_millis(100);
        let max_backoff = Duration::from_secs(5);
        loop {
            tokio::select! {
                biased;
                _ = ctx.cancelled() => {
                    tracing::error!(
                        "Context cancelled while retrying lease event for node {:?}",
                        node_name
                    );
                    drop(permit);
                    return;
                }
                _ = tokio::time::sleep(backoff) => {}
            }
            match tx.try_send(evt.clone()) {
                Ok(()) => {
                    tracing::info!("Async requeued lease event for node {:?}", node_name);
                    drop(permit);
                    return;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    drop(permit);
                    return;
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    // events channel still full, retry with exp backoff.
                    backoff = (backoff * 2).min(max_backoff);
                }
            }
        }
    });
}

/// Go: `nodeToLease(n)`: updates the lease with information fetched from
/// the node, e.g. PodCIDR. Error strings are identical to Go.
pub(crate) fn node_to_lease(
    node: &Node,
    annotations: &Annotations,
    enable_ipv4: bool,
    enable_ipv6: bool,
) -> anyhow::Result<Lease> {
    let mut l = Lease {
        enable_ipv4: false,
        enable_ipv6: false,
        subnet: IP4Net::default(),
        ipv6_subnet: IP6Net::default(),
        attrs: LeaseAttrs::default(),
        expiration: UNIX_EPOCH,
        asof: 0,
    };
    let ann = &node.metadata.annotations;

    if enable_ipv4 {
        l.attrs.public_ip = annotation(ann, &annotations.backend_public_ip).parse()?;
        l.attrs.backend_data = raw_from_annotation(ann, &annotations.backend_data);

        let cidrs = &node.spec.pod_cidrs;
        let cidr: Option<IP4Net> = match cidrs.len() {
            0 => {
                let s = node.spec.pod_cidr.as_deref().unwrap_or("");
                if s.contains(':') {
                    None
                } else {
                    Some(s.parse()?)
                }
            }
            1 | 2 => {
                tracing::info!(
                    "Creating the node lease for IPv4. This is the n.Spec.PodCIDRs: {cidrs:?}"
                );
                let mut found = None;
                for pod_cidr in cidrs {
                    if pod_cidr.contains(':') {
                        continue; // Go: To4() == nil -> not IPv4
                    }
                    found = Some(pod_cidr.parse()?);
                    break;
                }
                found
            }
            _ => anyhow::bail!(
                "node {:?} pod cidrs should be IPv4/IPv6 only or dualstack",
                node.metadata.name
            ),
        };
        let Some(cidr) = cidr else {
            anyhow::bail!("missing IPv4 address on n.Spec.PodCIDRs");
        };
        l.subnet = cidr;
        l.enable_ipv4 = enable_ipv4;
    }

    if enable_ipv6 {
        l.attrs.public_ipv6 = Some(annotation(ann, &annotations.backend_public_ipv6).parse()?);
        l.attrs.backend_v6_data = raw_from_annotation(ann, &annotations.backend_v6_data);

        let cidrs = &node.spec.pod_cidrs;
        let ipv6_cidr: Option<IP6Net> = match cidrs.len() {
            0 => {
                let s = node.spec.pod_cidr.as_deref().unwrap_or("");
                if s.contains(':') {
                    Some(s.parse()?)
                } else {
                    None
                }
            }
            1 | 2 => {
                tracing::info!(
                    "Creating the node lease for IPv6. This is the n.Spec.PodCIDRs: {cidrs:?}"
                );
                let mut found = None;
                for pod_cidr in cidrs {
                    if !pod_cidr.contains(':') {
                        continue; // Go: To4() != nil -> not IPv6
                    }
                    found = Some(pod_cidr.parse()?);
                    break;
                }
                found
            }
            _ => anyhow::bail!(
                "node {:?} pod cidrs should be IPv4/IPv6 only or dualstack",
                node.metadata.name
            ),
        };
        let Some(ipv6_cidr) = ipv6_cidr else {
            anyhow::bail!("missing IPv6 address on n.Spec.PodCIDRs");
        };
        l.ipv6_subnet = ipv6_cidr;
        l.enable_ipv6 = enable_ipv6;
    }

    l.attrs.backend_type = annotation(ann, &annotations.backend_type).to_string();
    Ok(l)
}

/// Annotation value as raw JSON. Go keeps the bytes verbatim
/// (`json.RawMessage`); Rust's `RawValue` must be valid JSON, so a
/// missing or malformed annotation becomes `None` (documented deviation).
fn raw_from_annotation(ann: &BTreeMap<String, String>, key: &str) -> Option<Box<RawValue>> {
    let value = ann.get(key)?;
    RawValue::from_string(value.clone()).ok()
}

/// A lease built for the own node in `AcquireLease` expires in 24h (Go:
/// `time.Now().Add(24 * time.Hour)`).
pub(crate) fn lease_expiration_24h() -> SystemTime {
    SystemTime::now() + Duration::from_secs(24 * 60 * 60)
}
