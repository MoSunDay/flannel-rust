//! Shared helpers for the kube subnet manager integration tests:
//! env-var guarding (process-global, serialized via ENV_LOCK), net-conf
//! fixtures, lease attributes, and manager/watch startup.

use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use serde_json::value::RawValue;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::mock::MockApiserver;
use super::{new_subnet_manager, KubeSubnetManager};
use crate::ip::IP4Net;
use crate::kube::{from_api_url, KubeClient};
use crate::lease::{Event, Lease, LeaseAttrs, LeaseWatchResult};
use crate::subnet::manager::Manager;

pub(super) const PREFIX: &str = "flannel.alpha.coreos.com";
pub(super) const VXLAN_CONF: &str = r#"{"Network": "10.244.0.0/16", "Backend": {"Type": "vxlan"}}"#;

/// Env mutations are process-global: tests holding env state serialize.
pub(super) static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub(super) struct EnvGuard {
    key: &'static str,
    prev: Option<String>,
}

impl EnvGuard {
    pub(super) fn set(key: &'static str, value: &str) -> Self {
        let prev = std::env::var(key).ok();
        std::env::set_var(key, value);
        Self { key, prev }
    }

    pub(super) fn remove(key: &'static str) -> Self {
        let prev = std::env::var(key).ok();
        std::env::remove_var(key);
        Self { key, prev }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match &self.prev {
            Some(v) => std::env::set_var(self.key, v),
            None => std::env::remove_var(self.key),
        }
    }
}

pub(super) fn write_conf(content: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("net-conf.json");
    std::fs::write(&path, content).unwrap();
    (dir, path)
}

pub(super) fn vxlan_attrs() -> LeaseAttrs {
    LeaseAttrs {
        public_ip: "192.168.1.10".parse().unwrap(),
        public_ipv6: None,
        backend_type: "vxlan".to_string(),
        backend_data: Some(
            RawValue::from_string(r#"{"VNI":1,"VtepMAC":"12:c6:65:89:b4:e3"}"#.into()).unwrap(),
        ),
        backend_v6_data: None,
    }
}

pub(super) fn dummy_lease() -> Lease {
    Lease {
        enable_ipv4: false,
        enable_ipv6: false,
        subnet: Default::default(),
        ipv6_subnet: Default::default(),
        attrs: vxlan_attrs(),
        expiration: SystemTime::now() + Duration::from_secs(60),
        asof: 0,
    }
}

pub(super) fn managed_annotations(public_ip: &str) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    m.insert(format!("{PREFIX}/kube-subnet-manager"), "true".into());
    m.insert(format!("{PREFIX}/backend-type"), "vxlan".into());
    m.insert(
        format!("{PREFIX}/backend-data"),
        r#"{"VNI":1,"VtepMAC":"aa:bb:cc:dd:ee:ff"}"#.into(),
    );
    m.insert(format!("{PREFIX}/public-ip"), public_ip.into());
    m
}

pub(super) async fn start(
    url: &str,
    conf_path: &str,
    set_unavailable: bool,
) -> anyhow::Result<(Arc<KubeSubnetManager>, CancellationToken)> {
    let client = KubeClient::new(from_api_url(url).unwrap()).unwrap();
    let cancel = CancellationToken::new();
    let mgr = new_subnet_manager(&cancel, client, PREFIX, conf_path, set_unavailable).await?;
    Ok((mgr, cancel))
}

pub(super) fn spawn_watch_leases(
    mgr: Arc<KubeSubnetManager>,
    cancel: CancellationToken,
) -> mpsc::Receiver<Vec<LeaseWatchResult>> {
    let (tx, rx) = mpsc::channel(32);
    tokio::spawn(async move {
        let _ = mgr.watch_leases(&cancel, tx).await;
    });
    rx
}

pub(super) async fn recv_event(
    rx: &mut mpsc::Receiver<Vec<LeaseWatchResult>>,
    timeout: Duration,
) -> Event {
    let batch = tokio::time::timeout(timeout, rx.recv())
        .await
        .expect("timeout waiting for watch event")
        .expect("watch channel closed");
    batch
        .into_iter()
        .next()
        .unwrap()
        .events
        .into_iter()
        .next()
        .unwrap()
}

pub(super) fn ip4(s: &str) -> IP4Net {
    IP4Net::from_str(s).unwrap()
}

/// Node without flannel annotations (not managed yet).
pub(super) fn put_plain_node(api: &MockApiserver, name: &str, cidr: &str) {
    api.put_node(name, &[cidr], &BTreeMap::new());
}
