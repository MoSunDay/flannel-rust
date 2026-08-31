//! Parity-pinning tests for `handle_update_lease_event` (Go
//! `handleUpdateLeaseEvent`, pkg/subnet/kube/kube.go:312-339).
//!
//! Go starts `var changed = true` and lets each ENABLED family AND-clear
//! it (kube.go:318-335); because the v6 block runs after the v4 block,
//! dual-stack emits an event only when BOTH families changed and a
//! single-family change emits NONE. These tests pin that (surprising)
//! upstream behaviour so nobody "fixes" it by accident.

use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::Arc;

use tokio::sync::{mpsc, Semaphore};
use tokio_util::sync::CancellationToken;

use super::annotations::{new_annotations, Annotations};
use super::events::{handle_update_lease_event, EventEnv};
use crate::ip::IP4Net;
use crate::kube::{Node, NodeSpec, ObjectMeta};
use crate::lease::{Event, EventType};

const PREFIX: &str = "flannel.alpha.coreos.com";

/// `example.com/flannel` normalizes to `example.com/flannel-...` keys.
const CUSTOM_PREFIX: &str = "example.com/flannel";

fn key(suffix: &str) -> String {
    format!("{PREFIX}/{suffix}")
}

fn custom_key(suffix: &str) -> String {
    // new_annotations appends "-" to a slash-carrying prefix.
    format!("{CUSTOM_PREFIX}-{suffix}")
}

/// A fully populated managed node; `overrides` replace annotations.
fn node_with(overrides: &[(&str, &str)], custom_prefix: bool) -> Node {
    let build = |suffix: &str| {
        if custom_prefix {
            custom_key(suffix)
        } else {
            key(suffix)
        }
    };
    let mut ann = BTreeMap::new();
    ann.insert(build("kube-subnet-manager"), "true".into());
    ann.insert(build("backend-type"), "vxlan".into());
    ann.insert(
        build("backend-data"),
        r#"{"VNI":1,"VtepMAC":"aa:aa:aa:aa:aa:aa"}"#.into(),
    );
    ann.insert(
        build("backend-v6-data"),
        r#"{"VNI":2,"VtepMAC":"bb:bb:bb:bb:bb:bb"}"#.into(),
    );
    ann.insert(build("public-ip"), "10.0.0.1".into());
    ann.insert(build("public-ipv6"), "fd00::1".into());
    for (suffix, value) in overrides {
        ann.insert(build(suffix), (*value).into());
    }
    Node {
        metadata: ObjectMeta {
            name: "node1".into(),
            annotations: ann,
            ..Default::default()
        },
        spec: NodeSpec {
            pod_cidr: Some("10.244.1.0/24".into()),
            pod_cidrs: vec!["10.244.1.0/24".into(), "fd00:10:244::/64".into()],
        },
    }
}

/// Run `handle_update_lease_event` over one old/new pair and collect the
/// events it enqueued. `enqueue_lease_event` sends synchronously while
/// the channel has room, so no polling or sleeping is needed.
async fn update_events(
    annotations: &Annotations,
    enable_ipv4: bool,
    enable_ipv6: bool,
    old: &Node,
    new: &Node,
) -> Vec<Event> {
    let cancel = CancellationToken::new();
    let sem = Arc::new(Semaphore::new(8));
    let (tx, mut rx) = mpsc::channel(8);
    let env = EventEnv {
        ctx: &cancel,
        tx: &tx,
        sem: &sem,
        annotations,
        enable_ipv4,
        enable_ipv6,
    };
    handle_update_lease_event(&env, old, new).await;
    drop(tx);
    let mut events = Vec::new();
    while let Ok(event) = rx.try_recv() {
        events.push(event);
    }
    events
}

fn default_annotations() -> Annotations {
    new_annotations(PREFIX).unwrap()
}

fn managed() -> Node {
    node_with(&[], false)
}

/// A backend-data value distinct from the fixture default.
fn changed_vxlan_data() -> &'static str {
    r#"{"VNI":9,"VtepMAC":"cc:cc:cc:cc:cc:cc"}"#
}

/// v4-only: a backend-data change must enqueue exactly one Added event.
#[tokio::test]
async fn v4_only_backend_data_change_enqueues_event() {
    let annotations = default_annotations();
    let old = managed();
    let new = node_with(&[("backend-data", changed_vxlan_data())], false);
    let events = update_events(&annotations, true, false, &old, &new).await;
    assert_eq!(events.len(), 1, "changed backend-data must emit an event");
    assert_eq!(events[0].event_type, EventType::Added);
    assert_eq!(
        events[0].lease.subnet,
        IP4Net::from_str("10.244.1.0/24").unwrap()
    );
}

/// v4-only: identical nodes must stay silent.
#[tokio::test]
async fn v4_only_no_change_emits_nothing() {
    let annotations = default_annotations();
    let old = managed();
    let new = managed();
    let events = update_events(&annotations, true, false, &old, &new).await;
    assert!(events.is_empty(), "no relevant change, no event");
}

/// Dual-stack: both families changed -> event (neither block clears
/// `changed`).
#[tokio::test]
async fn dual_stack_both_families_changed_enqueues_event() {
    let annotations = default_annotations();
    let old = managed();
    let new = node_with(
        &[
            ("backend-data", changed_vxlan_data()),
            ("backend-v6-data", changed_vxlan_data()),
        ],
        false,
    );
    let events = update_events(&annotations, true, true, &old, &new).await;
    assert_eq!(events.len(), 1, "both families changed must emit an event");
    assert_eq!(events[0].event_type, EventType::Added);
}

/// Upstream parity quirk (kube.go:318-335): with dual-stack enabled, a
/// v6-only backend-v6-data change is CLEARED by the v4 block's
/// `changed = false` (all v4 annotations equal), so NO event is emitted.
/// Go behaves identically; do not "fix" this here.
#[tokio::test]
async fn dual_stack_v6_only_change_emits_nothing() {
    let annotations = default_annotations();
    let old = managed();
    let new = node_with(&[("backend-v6-data", changed_vxlan_data())], false);
    let events = update_events(&annotations, true, true, &old, &new).await;
    assert!(
        events.is_empty(),
        "upstream kube.go:318-335: in dual-stack a single-family change \
         clears `changed` and emits no event"
    );
}

/// The symmetric quirk: dual-stack, v4-only change also emits nothing
/// (the v6 block clears it after the v4 block kept `changed == true`).
#[tokio::test]
async fn dual_stack_v4_only_change_emits_nothing() {
    let annotations = default_annotations();
    let old = managed();
    let new = node_with(&[("backend-data", changed_vxlan_data())], false);
    let events = update_events(&annotations, true, true, &old, &new).await;
    assert!(events.is_empty(), "upstream kube.go:318-335 parity");
}

/// A node without `kube-subnet-manager: "true"` returns before any
/// comparison, even when everything else changed.
#[tokio::test]
async fn unmanaged_node_emits_nothing() {
    let annotations = default_annotations();
    let old = managed();
    let mut new = managed();
    new.metadata
        .annotations
        .insert(key("kube-subnet-manager"), "false".into());
    new.metadata
        .annotations
        .insert(key("backend-data"), changed_vxlan_data().into());
    let events = update_events(&annotations, true, false, &old, &new).await;
    assert!(events.is_empty(), "unmanaged node must emit no event");
}

/// Change detection happens on the NORMALIZED keys: with the custom
/// prefix `example.com/flannel` the handler compares
/// `example.com/flannel-backend-data` (what new_annotations builds and
/// what flannel writes), never the raw-prefix key.
#[tokio::test]
async fn custom_prefix_changes_are_detected_on_normalized_keys() {
    let annotations = new_annotations(CUSTOM_PREFIX).unwrap();
    assert_eq!(annotations.backend_data, custom_key("backend-data"));

    let old = node_with(&[], true);
    let new = node_with(&[("backend-data", changed_vxlan_data())], true);
    // Sanity: the fixtures only carry normalized keys.
    assert!(old
        .metadata
        .annotations
        .contains_key(&custom_key("backend-data")));
    assert!(!old.metadata.annotations.contains_key(&key("backend-data")));

    // v4-only custom-prefix node: a backend-data change must be seen.
    let events = update_events(&annotations, true, false, &old, &new).await;
    assert_eq!(events.len(), 1, "normalized-key change must be detected");
    assert_eq!(events[0].event_type, EventType::Added);
}
