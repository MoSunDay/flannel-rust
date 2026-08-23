//! Minimal Kubernetes API wire types (JSON), just enough for the kube
//! subnet manager: nodes, node lists, pods, watch frames, error status.
//!
//! Unknown JSON fields are ignored (serde default), so extra/newer fields
//! the apiserver sends are tolerated.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

/// Metadata present on every Kubernetes object (subset flannel needs).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ObjectMeta {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub uid: String,
    #[serde(default)]
    pub resource_version: Option<String>,
    #[serde(default)]
    pub annotations: BTreeMap<String, String>,
}

/// Node spec subset: assigned pod CIDRs.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NodeSpec {
    #[serde(default, rename = "podCIDR")]
    pub pod_cidr: Option<String>,
    #[serde(default, rename = "podCIDRs")]
    pub pod_cidrs: Vec<String>,
}

/// A Kubernetes node.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Node {
    #[serde(default)]
    pub metadata: ObjectMeta,
    #[serde(default)]
    pub spec: NodeSpec,
}

/// Pagination/cursor metadata of list responses.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListMeta {
    #[serde(default)]
    pub resource_version: Option<String>,
}

/// A list of nodes.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NodeList {
    #[serde(default)]
    pub metadata: ListMeta,
    #[serde(default)]
    pub items: Vec<Node>,
}

/// Pod spec subset: the node the pod is scheduled on.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PodSpec {
    #[serde(default)]
    pub node_name: Option<String>,
}

/// A Kubernetes pod.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Pod {
    #[serde(default)]
    pub metadata: ObjectMeta,
    #[serde(default)]
    pub spec: PodSpec,
}

/// Watch frame types emitted by the apiserver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum WatchEventType {
    Added,
    Modified,
    Deleted,
    Bookmark,
    Error,
}

/// One watch frame: `{"type": "<TYPE>", "object": {...}}`.
///
/// For non-ERROR frames `object` is the watched resource (e.g. [`Node`]);
/// ERROR frames carry a [`Status`] instead and are dispatched separately
/// (see `watch::parse_watch_line`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WatchEvent<T> {
    #[serde(rename = "type")]
    pub event_type: WatchEventType,
    pub object: T,
}

/// Apiserver error payload (kind: Status), subset we care about.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub code: u16,
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} (reason: {}, code: {})",
            self.message, self.reason, self.code
        )
    }
}

/// True when a watch ERROR status means "resource version too old": the
/// caller must relist (HTTP 410 Gone semantics).
pub fn is_expired(status: &Status) -> bool {
    status.code == 410 || status.reason == "Expired"
}
