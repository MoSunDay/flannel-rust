//! Integration tests: KubeSubnetManager against the in-memory mock
//! apiserver (super::mock). Covers construction/sync, AcquireLease
//! (patching, podCIDR polling, errors), CompleteLease, pod-based node
//! name resolution, env/prefix validation, and stored annotation
//! readers. Watch-path tests live in watch_integration_tests.rs.

use std::collections::BTreeMap;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use super::mock::MockApiserver;
use super::new_subnet_manager;
use super::support::*;
use crate::kube::{from_api_url, KubeClient};
use crate::subnet::manager::Manager;

#[tokio::test]
async fn constructor_syncs_and_reports_name_and_config() {
    let _guard = ENV_LOCK.lock().await;
    let _node = EnvGuard::set("NODE_NAME", "node1");
    let (api_url, api) = MockApiserver::start().await;
    put_plain_node(&api, "node1", "10.244.1.0/24");
    let (_dir, conf) = write_conf(VXLAN_CONF);

    let (mgr, _cancel) = start(&api_url, conf.to_str().unwrap(), true).await.unwrap();
    assert_eq!(mgr.name(), "Kubernetes Subnet Manager - node1");
    let cfg = mgr
        .get_network_config(&CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(cfg.network, ip4("10.244.0.0/16"));
    assert_eq!(cfg.backend_type, "vxlan");
}

#[tokio::test]
async fn acquire_lease_patches_annotations_and_builds_lease() {
    let _guard = ENV_LOCK.lock().await;
    let _node = EnvGuard::set("NODE_NAME", "node1");
    let (api_url, api) = MockApiserver::start().await;
    put_plain_node(&api, "node1", "10.244.1.0/24");
    let (_dir, conf) = write_conf(VXLAN_CONF);
    let (mgr, cancel) = start(&api_url, conf.to_str().unwrap(), true).await.unwrap();

    let attrs = vxlan_attrs();
    let lease = mgr.acquire_lease(&cancel, &attrs).await.unwrap();
    assert_eq!(lease.subnet, ip4("10.244.1.0/24"));
    // Go: only non vxlan/host-gw/wireguard backends force EnableIPv4.
    assert!(!lease.enable_ipv4 && !lease.enable_ipv6);
    assert!(lease.expiration > std::time::SystemTime::now());

    let ann = api.node_annotations("node1");
    assert_eq!(
        ann.get(&format!("{PREFIX}/kube-subnet-manager"))
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        ann.get(&format!("{PREFIX}/backend-type"))
            .map(String::as_str),
        Some("vxlan")
    );
    assert_eq!(
        ann.get(&format!("{PREFIX}/backend-data"))
            .map(String::as_str),
        Some(r#"{"VNI":1,"VtepMAC":"12:c6:65:89:b4:e3"}"#)
    );
    assert_eq!(
        ann.get(&format!("{PREFIX}/public-ip")).map(String::as_str),
        Some("192.168.1.10")
    );

    // Strategic-merge patch containing exactly the changed annotations.
    let patches = api.patches();
    assert_eq!(patches.len(), 1);
    let (ct, node, body) = &patches[0];
    assert_eq!(ct, "application/strategic-merge-patch+json");
    assert_eq!(node, "node1");
    let changed = body
        .pointer("/metadata/annotations")
        .unwrap()
        .as_object()
        .unwrap();
    assert!(changed.contains_key(&format!("{PREFIX}/kube-subnet-manager")));
    assert!(changed.contains_key(&format!("{PREFIX}/backend-type")));

    // Second acquire with identical attrs: nothing needs patching.
    let _ = mgr.acquire_lease(&cancel, &attrs).await.unwrap();
    assert_eq!(api.patches().len(), 1);
}

#[tokio::test]
async fn acquire_lease_polls_until_pod_cidr_assigned() {
    let _guard = ENV_LOCK.lock().await;
    let _node = EnvGuard::set("NODE_NAME", "node1");
    let (api_url, api) = MockApiserver::start().await;
    api.put_node("node1", &[], &BTreeMap::new()); // no podCIDR yet
    let (_dir, conf) = write_conf(VXLAN_CONF);
    let (mgr, cancel) = start(&api_url, conf.to_str().unwrap(), true).await.unwrap();

    let attrs = vxlan_attrs();
    let acquire = mgr.acquire_lease(&cancel, &attrs);
    tokio::pin!(acquire);
    // The poll loop starts immediately; after 200ms the (mock) node
    // controller assigns the podCIDR -> the next poll succeeds.
    let lease = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::time::sleep(Duration::from_millis(200)).await;
        put_plain_node(&api, "node1", "10.244.7.0/24");
        acquire.await
    })
    .await
    .expect("acquire_lease timed out")
    .unwrap();
    assert_eq!(lease.subnet, ip4("10.244.7.0/24"));
}

#[tokio::test]
async fn acquire_lease_returns_cancel_error_for_missing_node() {
    let _guard = ENV_LOCK.lock().await;
    let _node = EnvGuard::set("NODE_NAME", "ghost");
    let (api_url, _api) = MockApiserver::start().await;
    let (_dir, conf) = write_conf(VXLAN_CONF);
    let (mgr, cancel) = start(&api_url, conf.to_str().unwrap(), true).await.unwrap();

    cancel.cancel();
    let err = mgr
        .acquire_lease(&cancel, &vxlan_attrs())
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("timeout contacting kube-api"),
        "unexpected: {err}"
    );
}

#[tokio::test]
async fn acquire_lease_rejects_podcidr_outside_configured_network() {
    let _guard = ENV_LOCK.lock().await;
    let _node = EnvGuard::set("NODE_NAME", "node1");
    let (api_url, api) = MockApiserver::start().await;
    put_plain_node(&api, "node1", "192.168.5.0/24");
    let (_dir, conf) = write_conf(VXLAN_CONF);
    let (mgr, cancel) = start(&api_url, conf.to_str().unwrap(), true).await.unwrap();

    let err = mgr
        .acquire_lease(&cancel, &vxlan_attrs())
        .await
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "subnet \"10.244.0.0/16\" specified in the flannel net config \
         doesn't contain \"192.168.5.0/24\" PodCIDR of the \"node1\" node"
    );
}

#[tokio::test]
async fn acquire_lease_rejects_more_than_two_pod_cidrs() {
    let _guard = ENV_LOCK.lock().await;
    let _node = EnvGuard::set("NODE_NAME", "node1");
    let (api_url, api) = MockApiserver::start().await;
    api.put_node(
        "node1",
        &["10.244.1.0/24", "10.244.2.0/24", "10.244.3.0/24"],
        &BTreeMap::new(),
    );
    let (_dir, conf) = write_conf(VXLAN_CONF);
    let (mgr, cancel) = start(&api_url, conf.to_str().unwrap(), true).await.unwrap();

    let err = mgr
        .acquire_lease(&cancel, &vxlan_attrs())
        .await
        .unwrap_err();
    assert!(err
        .to_string()
        .contains("pod cidrs should be IPv4/IPv6 only or dualstack"));
}

#[tokio::test]
async fn complete_lease_patches_node_status_condition() {
    let _guard = ENV_LOCK.lock().await;
    let _node = EnvGuard::set("NODE_NAME", "node1");
    let (api_url, api) = MockApiserver::start().await;
    put_plain_node(&api, "node1", "10.244.1.0/24");
    let (_dir, conf) = write_conf(VXLAN_CONF);
    let (mgr, cancel) = start(&api_url, conf.to_str().unwrap(), true).await.unwrap();

    mgr.complete_lease(&cancel, &dummy_lease()).await.unwrap();
    let status = api.node_status("node1").expect("status patch applied");
    let cond = &status["conditions"][0];
    assert_eq!(cond["type"], "NetworkUnavailable");
    assert_eq!(cond["status"], "False");
    assert_eq!(cond["reason"], "FlannelIsUp");
    assert_eq!(cond["message"], "Flannel is running on this node");
    let (ct, _, _) = &api.patches()[0];
    assert_eq!(ct, "application/strategic-merge-patch+json");
}

#[tokio::test]
async fn complete_lease_skips_when_flag_disabled() {
    let _guard = ENV_LOCK.lock().await;
    let _node = EnvGuard::set("NODE_NAME", "node1");
    let (api_url, api) = MockApiserver::start().await;
    put_plain_node(&api, "node1", "10.244.1.0/24");
    let (_dir, conf) = write_conf(VXLAN_CONF);
    let (mgr, cancel) = start(&api_url, conf.to_str().unwrap(), false)
        .await
        .unwrap();

    mgr.complete_lease(&cancel, &dummy_lease()).await.unwrap();
    assert!(api.patches().is_empty());
}

#[tokio::test]
async fn pod_name_and_namespace_resolve_node_name() {
    let _guard = ENV_LOCK.lock().await;
    let _node = EnvGuard::remove("NODE_NAME");
    let _pod = EnvGuard::set("POD_NAME", "kube-flannel-ds-x9");
    let _ns = EnvGuard::set("POD_NAMESPACE", "kube-system");
    let (api_url, api) = MockApiserver::start().await;
    api.set_pod("kube-system", "kube-flannel-ds-x9", "node1");
    put_plain_node(&api, "node1", "10.244.1.0/24");
    let (_dir, conf) = write_conf(VXLAN_CONF);

    let (mgr, _cancel) = start(&api_url, conf.to_str().unwrap(), true).await.unwrap();
    assert_eq!(mgr.name(), "Kubernetes Subnet Manager - node1");

    // Pod with empty nodeName -> dedicated error.
    api.set_pod("kube-system", "unscheduled", "");
    let _pod = EnvGuard::set("POD_NAME", "unscheduled");
    let err = start(&api_url, conf.to_str().unwrap(), true)
        .await
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "node name not present in pod spec 'kube-system/unscheduled'"
    );

    // Missing pod -> retrieval error.
    let _pod = EnvGuard::set("POD_NAME", "missing-pod");
    let err = start(&api_url, conf.to_str().unwrap(), true)
        .await
        .unwrap_err();
    assert!(err
        .to_string()
        .starts_with("error retrieving pod spec for 'kube-system/missing-pod':"));
}

#[tokio::test]
async fn constructor_env_and_prefix_validation_errors() {
    let _guard = ENV_LOCK.lock().await;
    let (api_url, api) = MockApiserver::start().await;
    put_plain_node(&api, "node1", "10.244.1.0/24");
    let (_dir, conf) = write_conf(VXLAN_CONF);
    let cancel = CancellationToken::new();
    let client = || KubeClient::new(from_api_url(&api_url).unwrap()).unwrap();

    // No NODE_NAME / POD_NAME / POD_NAMESPACE at all.
    let _node = EnvGuard::remove("NODE_NAME");
    let _pod = EnvGuard::remove("POD_NAME");
    let _ns = EnvGuard::remove("POD_NAMESPACE");
    let err = start(&api_url, conf.to_str().unwrap(), true)
        .await
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "env variables POD_NAME and POD_NAMESPACE must be set"
    );

    // Malformed EVENT_QUEUE_DEPTH.
    let _node = EnvGuard::set("NODE_NAME", "node1");
    let _depth = EnvGuard::set("EVENT_QUEUE_DEPTH", "abc");
    let err = start(&api_url, conf.to_str().unwrap(), true)
        .await
        .unwrap_err();
    assert!(err
        .to_string()
        .starts_with("env EVENT_QUEUE_DEPTH=abc format error"));
    drop(_depth);

    // Prefix with two slashes / not an fqdn.
    let err = new_subnet_manager(&cancel, client(), "a/b/c", conf.to_str().unwrap(), true)
        .await
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "subnet/kube: prefix can contain at most single slash"
    );
    let err = new_subnet_manager(&cancel, client(), "org", conf.to_str().unwrap(), true)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("prefix must be in a format"));

    // Missing net-conf file.
    let err = new_subnet_manager(
        &cancel,
        client(),
        PREFIX,
        "/nonexistent/net-conf.json",
        true,
    )
    .await
    .unwrap_err();
    assert!(err.to_string().starts_with("failed to read net conf"));
}

#[tokio::test]
async fn stored_mac_addresses_and_public_ips_are_read_back() {
    let _guard = ENV_LOCK.lock().await;
    let _node = EnvGuard::set("NODE_NAME", "node1");
    let (api_url, api) = MockApiserver::start().await;
    let mut ann = BTreeMap::new();
    ann.insert(
        format!("{PREFIX}/backend-data"),
        r#"{"VNI":1,"VtepMAC":"12:c6:65:89:b4:e3"}"#.into(),
    );
    ann.insert(
        format!("{PREFIX}/backend-v6-data"),
        r#"{"VNI":2,"VtepMAC":"22:aa:bb:cc:dd:ee"}"#.into(),
    );
    ann.insert(format!("{PREFIX}/node-public-ip"), "203.0.113.7".into());
    ann.insert(format!("{PREFIX}/node-public-ipv6"), "2001:db8::7".into());
    api.put_node("node1", &["10.244.1.0/24"], &ann);
    let (_dir, conf) = write_conf(VXLAN_CONF);
    let (mgr, cancel) = start(&api_url, conf.to_str().unwrap(), true).await.unwrap();

    let (macv4, macv6) = mgr.get_stored_mac_addresses(&cancel).await;
    assert_eq!(
        (macv4, macv6),
        (
            "12:c6:65:89:b4:e3".to_string(),
            "22:aa:bb:cc:dd:ee".to_string()
        )
    );
    let (ipv4, ipv6) = mgr.get_stored_public_ip(&cancel).await;
    assert_eq!(
        (ipv4, ipv6),
        ("203.0.113.7".to_string(), "2001:db8::7".to_string())
    );
}

#[tokio::test]
async fn alloc_backend_disables_informer_and_acquires_via_direct_get() {
    let _guard = ENV_LOCK.lock().await;
    let _node = EnvGuard::set("NODE_NAME", "node1");
    let (api_url, api) = MockApiserver::start().await;
    put_plain_node(&api, "node1", "10.244.1.0/24");
    let (_dir, conf) = write_conf(r#"{"Network": "10.244.0.0/16", "Backend": {"Type": "alloc"}}"#);
    let (mgr, cancel) = start(&api_url, conf.to_str().unwrap(), true).await.unwrap();
    assert!(mgr.disable_node_informer);

    let mut attrs = vxlan_attrs();
    attrs.backend_type = "alloc".to_string();
    let lease = mgr.acquire_lease(&cancel, &attrs).await.unwrap();
    assert_eq!(lease.subnet, ip4("10.244.1.0/24"));
    // alloc forces the enable flags (backend not vxlan/host-gw/wireguard).
    assert!(lease.enable_ipv4 && !lease.enable_ipv6);
}
