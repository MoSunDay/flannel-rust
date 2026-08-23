//! Thin Kubernetes API client for flannel-rust.
//!
//! Minimal subset of the apiserver surface that flanneld's kube subnet
//! manager needs (mirrors `pkg/subnet/kube/kube.go` in flannel upstream
//! cdf76059): LIST/WATCH/PATCH nodes and GET pod (NODE_NAME discovery).
//! Works against a plain-HTTP apiserver (k3as/init-pro, no auth) as well
//! as real clusters (bearer token, optional CA).
//!
//! Layout: [`types`] holds wire types, [`config`] builds a [`KubeConfig`]
//! (api url / in-cluster / kubeconfig), [`client`] performs requests and
//! [`watch`] decodes chunked watch streams.

mod client;
mod config;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_config;
mod types;
mod watch;

pub use client::{KubeClient, KubeError, PatchType};
pub use config::{from_api_url, from_kubeconfig, in_cluster, resolve, KubeConfig};
pub use types::{
    is_expired, ListMeta, Node, NodeList, NodeSpec, ObjectMeta, Pod, PodSpec, Status, WatchEvent,
    WatchEventType,
};
pub use watch::{decode_watch_stream, parse_watch_line};
