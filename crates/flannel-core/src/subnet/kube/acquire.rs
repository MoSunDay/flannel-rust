//! Port of Go `AcquireLease` (pkg/subnet/kube/kube.go, upstream
//! cdf76059): wait for the own node (with podCIDRs assigned), set the
//! flannel annotations through a strategic-merge patch and derive the
//! lease from the pod CIDR(s).
//!
//! Interpreted Go semantics (documented deviations):
//! - Go errors out immediately when the node exists but has no podCIDR
//!   ("node %q pod cidr not assigned"). In k3as the podCIDR is allocated
//!   asynchronously (T4.3), so this port keeps polling until the
//!   podCIDR(s) matching the config's enable flags show up (Go's retry
//!   loops around AcquireLease are inside the caller there). Error
//!   strings for all other cases are identical.
//! - Go computes the patch with strategicpatch.CreateTwoWayMergePatch
//!   over the full node JSON; since only metadata.annotations change,
//!   the patch is exactly the key-level annotation diff.

use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::ip::{IP4Net, IP6Net};
use crate::kube::{Node, PatchType};
use crate::lease::{Lease, LeaseAttrs};
use crate::subnet::manager::Ctx;

use super::annotations::annotation;
use super::events::lease_expiration_24h;
use super::informer::sleep_cancellable;
use super::KubeSubnetManager;

/// Go: `wait.PollUntilContextTimeout(ctx, 3*time.Second, 30*time.Second, ...)`.
const POLL_INTERVAL: Duration = Duration::from_secs(3);
const POLL_TIMEOUT: Duration = Duration::from_secs(30);

/// Go: `AcquireLease`. Called once by the backend when registering.
pub(crate) async fn acquire_lease(
    mgr: &KubeSubnetManager,
    ctx: Ctx<'_>,
    attrs: &LeaseAttrs,
) -> anyhow::Result<Lease> {
    let bd = raw_to_string(&attrs.backend_data);
    let v6_bd = raw_to_string(&attrs.backend_v6_data);

    // Wait for the node to appear in the store (or directly via GET when
    // the informer is disabled) with podCIDR(s) matching the enable flags.
    let node = wait_for_node_with_cidrs(mgr, ctx).await?;

    let (cidr, ipv6_cidr) = acquire_pod_cidrs(mgr, &node)?;

    maybe_patch_annotations(mgr, ctx, attrs, &node, &bd, &v6_bd).await?;

    let mut lease = Lease {
        enable_ipv4: false,
        enable_ipv6: false,
        subnet: IP4Net::default(),
        ipv6_subnet: IP6Net::default(),
        attrs: attrs.clone(),
        expiration: lease_expiration_24h(),
        asof: 0,
    };
    if let Some(cidr) = cidr {
        if mgr.config.enable_ipv4 {
            if mgr.config.network.empty() || !mgr.config.network.contains_cidr(cidr) {
                anyhow::bail!(
                    "subnet \"{}\" specified in the flannel net config doesn't contain \
                     \"{}\" PodCIDR of the \"{}\" node",
                    mgr.config.network,
                    cidr,
                    mgr.node_name
                );
            }
            lease.subnet = cidr;
        }
    }
    if let Some(ipv6_cidr) = ipv6_cidr {
        if mgr.config.enable_ipv6 {
            if mgr.config.ipv6_network.empty() || !mgr.config.ipv6_network.contains_cidr(ipv6_cidr)
            {
                anyhow::bail!(
                    "subnet \"{}\" specified in the flannel net config doesn't contain \
                     \"{}\" IPv6 PodCIDR of the \"{}\" node",
                    mgr.config.ipv6_network,
                    ipv6_cidr,
                    mgr.node_name
                );
            }
            lease.ipv6_subnet = ipv6_cidr;
        }
    }
    // TODO - only vxlan, host-gw and wireguard backends support dual
    // stack now (Go comment kept).
    if attrs.backend_type != "vxlan"
        && attrs.backend_type != "host-gw"
        && attrs.backend_type != "wireguard"
    {
        lease.enable_ipv4 = true;
        lease.enable_ipv6 = false;
    }
    Ok(lease)
}

/// Go's `json.RawMessage.MarshalJSON` (nil marshals to "null").
fn raw_to_string(data: &Option<Box<serde_json::value::RawValue>>) -> String {
    match data {
        Some(raw) => raw.get().to_string(),
        None => "null".to_string(),
    }
}

/// Fetch the own node: informer store, or a direct GET when the informer
/// is disabled (Go `disableNodeInformer`, backend type "alloc").
async fn fetch_node(mgr: &KubeSubnetManager, ctx: Ctx<'_>) -> Option<Node> {
    if mgr.disable_node_informer {
        match mgr.client.get_node(&mgr.node_name).await {
            Ok(node) => return Some(node),
            Err(e) => {
                tracing::debug!("Failed to get node {:?}: {e}", mgr.node_name);
                return None;
            }
        }
    }
    match mgr.store.get(&mgr.node_name) {
        Some(node) => Some(node),
        None => {
            tracing::debug!("node {:?} does not exist ", mgr.node_name);
            if ctx.is_cancelled() {
                tracing::debug!("context cancelled while looking up node");
            }
            None
        }
    }
}

/// Parsed pod CIDRs of a node per Go's AcquireLease switch: 0 entries ->
/// the single podCIDR field; 1-2 entries -> each parsed; >=3 -> error.
fn acquire_pod_cidrs(
    mgr: &KubeSubnetManager,
    node: &Node,
) -> anyhow::Result<(Option<IP4Net>, Option<IP6Net>)> {
    let mut cidr: Option<IP4Net> = None;
    let mut ipv6_cidr: Option<IP6Net> = None;
    match node.spec.pod_cidrs.len() {
        0 => {
            // Empty podCIDR: not assigned yet (k3as assigns it later);
            // the caller keeps polling instead of Go's fast error.
            let s = node.spec.pod_cidr.as_deref().unwrap_or("");
            if s.contains(':') {
                ipv6_cidr = Some(s.parse()?);
            } else if !s.is_empty() {
                cidr = Some(s.parse()?);
            }
        }
        1 | 2 => {
            for pod_cidr in &node.spec.pod_cidrs {
                if pod_cidr.contains(':') {
                    ipv6_cidr = Some(pod_cidr.parse()?);
                } else {
                    cidr = Some(pod_cidr.parse()?);
                }
            }
        }
        _ => anyhow::bail!(
            "node \"{}\" pod cidrs should be IPv4/IPv6 only or dualstack",
            mgr.node_name
        ),
    }
    Ok((cidr, ipv6_cidr))
}

/// True when the parsed CIDRs satisfy the config's enable flags.
fn cidrs_ready(mgr: &KubeSubnetManager, cidr: &Option<IP4Net>, ipv6_cidr: &Option<IP6Net>) -> bool {
    (!mgr.config.enable_ipv4 || cidr.is_some()) && (!mgr.config.enable_ipv6 || ipv6_cidr.is_some())
}

/// Poll every 3s (max 30s, first attempt immediate, Go PollUntilContext
/// Timeout) until the own node exists with ready podCIDR(s).
async fn wait_for_node_with_cidrs(mgr: &KubeSubnetManager, ctx: Ctx<'_>) -> anyhow::Result<Node> {
    let deadline = Instant::now() + POLL_TIMEOUT;
    loop {
        if let Some(node) = fetch_node(mgr, ctx).await {
            match acquire_pod_cidrs(mgr, &node) {
                Ok((cidr, ipv6_cidr)) => {
                    if cidrs_ready(mgr, &cidr, &ipv6_cidr) {
                        return Ok(node);
                    }
                    // k3as: podCIDR not assigned yet; keep polling (Go
                    // returned "node %q pod cidr not assigned" here).
                    tracing::debug!(
                        "node {:?} has no podCIDR assigned yet, retrying",
                        mgr.node_name
                    );
                }
                // Malformed podCIDR(s): fail fast like Go.
                Err(e) => return Err(e),
            }
        }
        if ctx.is_cancelled() {
            anyhow::bail!(
                "timeout contacting kube-api, failed to get node \"{}\". \
                 Error: context canceled",
                mgr.node_name
            );
        }
        let now = Instant::now();
        if now >= deadline {
            anyhow::bail!(
                "timeout contacting kube-api, failed to get node \"{}\". \
                 Error: context deadline exceeded",
                mgr.node_name
            );
        }
        let sleep = POLL_INTERVAL.min(deadline - now);
        if !sleep_cancellable(sleep, ctx).await {
            anyhow::bail!(
                "timeout contacting kube-api, failed to get node \"{}\". \
                 Error: context canceled",
                mgr.node_name
            );
        }
    }
}

/// Go's annotation-diff + strategic-merge patch block of AcquireLease,
/// including the retry loop around the PATCH call.
async fn maybe_patch_annotations(
    mgr: &KubeSubnetManager,
    ctx: Ctx<'_>,
    attrs: &LeaseAttrs,
    node: &Node,
    bd: &str,
    v6_bd: &str,
) -> anyhow::Result<()> {
    let a = &mgr.annotations;
    let mut n = node.clone();
    let public_ip = attrs.public_ip.to_string();

    let needs_patch = {
        let ann = &node.metadata.annotations;
        let v4_changed = annotation(ann, &a.backend_data) != bd
            || annotation(ann, &a.backend_type) != attrs.backend_type.as_str()
            || annotation(ann, &a.backend_public_ip) != public_ip.as_str()
            || annotation(ann, &a.subnet_kube_managed) != "true"
            || (!annotation(ann, &a.backend_public_ip_overwrite).is_empty()
                && annotation(ann, &a.backend_public_ip_overwrite) != public_ip.as_str());
        let v6_changed = attrs.public_ipv6.is_some() && {
            let public_ipv6 = attrs.public_ipv6.unwrap().to_string();
            annotation(ann, &a.backend_v6_data) != v6_bd
                || annotation(ann, &a.backend_type) != attrs.backend_type.as_str()
                || annotation(ann, &a.backend_public_ipv6) != public_ipv6.as_str()
                || annotation(ann, &a.subnet_kube_managed) != "true"
                || (!annotation(ann, &a.backend_public_ipv6_overwrite).is_empty()
                    && annotation(ann, &a.backend_public_ipv6_overwrite) != public_ipv6.as_str())
        };
        v4_changed || v6_changed
    };

    if needs_patch {
        let ann = &mut n.metadata.annotations;
        ann.insert(a.backend_type.clone(), attrs.backend_type.clone());

        // TODO - only vxlan and host-gw backends support dual stack now.
        // Go (kube.go:434) spells this as `(vxlan && bd != "null")
        // || (wireguard && bd != "null") || backend_type != "vxlan"`;
        // boolean algebra reduces that to the condition below.
        if attrs.backend_type != "vxlan" || bd != "null" {
            ann.insert(a.backend_data.clone(), bd.to_string());
            let overwrite = annotation(ann, &a.backend_public_ip_overwrite).to_string();
            if !overwrite.is_empty() {
                if annotation(ann, &a.backend_public_ip) != overwrite {
                    tracing::info!(
                        "Overriding public ip with '{overwrite}' from node annotation '{}'",
                        a.backend_public_ip_overwrite
                    );
                    ann.insert(a.backend_public_ip.clone(), overwrite);
                }
            } else {
                ann.insert(a.backend_public_ip.clone(), public_ip);
            }
        }

        let public_ipv6 = attrs.public_ipv6.map(|ip| ip.to_string());
        if (attrs.backend_type == "vxlan" && v6_bd != "null")
            || (attrs.backend_type == "wireguard" && v6_bd != "null" && attrs.public_ipv6.is_some())
            || (attrs.backend_type == "host-gw" && attrs.public_ipv6.is_some())
            || (attrs.backend_type == "extension" && attrs.public_ipv6.is_some())
        {
            if let Some(v6) = public_ipv6.as_deref() {
                ann.insert(a.backend_v6_data.clone(), v6_bd.to_string());
                let overwrite = annotation(ann, &a.backend_public_ipv6_overwrite).to_string();
                if !overwrite.is_empty() {
                    if annotation(ann, &a.backend_public_ipv6) != overwrite {
                        tracing::info!(
                            "Overriding public ipv6 with '{overwrite}' from node annotation '{}'",
                            a.backend_public_ipv6_overwrite
                        );
                        ann.insert(a.backend_public_ipv6.clone(), overwrite);
                    }
                } else {
                    ann.insert(a.backend_public_ipv6.clone(), v6.to_string());
                }
            }
        }
        ann.insert(a.subnet_kube_managed.clone(), "true".to_string());

        // Go: strategicpatch.CreateTwoWayMergePatch(oldData, newData) —
        // only annotations changed, so the patch is the annotation diff.
        let mut changed = serde_json::Map::new();
        for (key, value) in n.metadata.annotations.iter() {
            if node.metadata.annotations.get(key).map(String::as_str) != Some(value.as_str()) {
                changed.insert(key.clone(), Value::String(value.clone()));
            }
        }
        let patch = json!({ "metadata": { "annotations": changed } });
        patch_with_retry(mgr, ctx, &patch).await?;
    }
    Ok(())
}

/// Go's second `wait.PollUntilContextTimeout` around the PATCH call:
/// retry every 3s up to 30s on any error; identical error string
/// ("failed to patch node" — distinct from the node-wait phase above so
/// a timeout names the operation that actually timed out).
async fn patch_with_retry(
    mgr: &KubeSubnetManager,
    ctx: Ctx<'_>,
    patch: &Value,
) -> anyhow::Result<()> {
    let deadline = Instant::now() + POLL_TIMEOUT;
    loop {
        match mgr
            .client
            .patch_node(&mgr.node_name, patch, PatchType::StrategicMerge)
            .await
        {
            Ok(_) => return Ok(()),
            Err(e) => {
                tracing::debug!("Failed to patch node {:?}: {e}", mgr.node_name)
            }
        }
        if ctx.is_cancelled() {
            anyhow::bail!(
                "timeout contacting kube-api, failed to patch node \"{}\". \
                 Error: context canceled",
                mgr.node_name
            );
        }
        let now = Instant::now();
        if now >= deadline {
            anyhow::bail!(
                "timeout contacting kube-api, failed to patch node \"{}\". \
                 Error: context deadline exceeded",
                mgr.node_name
            );
        }
        let sleep = POLL_INTERVAL.min(deadline - now);
        if !sleep_cancellable(sleep, ctx).await {
            anyhow::bail!(
                "timeout contacting kube-api, failed to patch node \"{}\". \
                 Error: context canceled",
                mgr.node_name
            );
        }
    }
}
