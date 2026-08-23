//! Watch-path integration tests: `WatchLeases`/`WatchLease` event flow
//! over the mock apiserver (super::mock), including hub backlog replay,
//! 410-Gone relist and dropped-connection recovery.

use std::time::Duration;

use tokio::sync::mpsc;

use super::mock::MockApiserver;
use super::support::*;
use crate::lease::EventType;
use crate::subnet::manager::Manager;

#[tokio::test]
async fn watch_leases_emits_events_for_managed_nodes() {
    let _guard = ENV_LOCK.lock().await;
    let _node = EnvGuard::set("NODE_NAME", "node1");
    let (api_url, api) = MockApiserver::start().await;
    put_plain_node(&api, "node1", "10.244.1.0/24");
    api.put_node(
        "node2",
        &["10.244.2.0/24"],
        &managed_annotations("192.168.1.20"),
    );
    let (_dir, conf) = write_conf(VXLAN_CONF);
    let (mgr, cancel) = start(&api_url, conf.to_str().unwrap(), true).await.unwrap();

    let mut rx = spawn_watch_leases(mgr.clone(), cancel.clone());
    // Initial LIST made node2 known; its Added event is replayed from
    // the hub backlog (Go: buffered events channel).
    let event = recv_event(&mut rx, Duration::from_secs(5)).await;
    assert_eq!(event.event_type, EventType::Added);
    assert_eq!(event.lease.subnet, ip4("10.244.2.0/24"));

    // Annotation change -> MODIFIED frame -> updated lease event.
    let mut ann = managed_annotations("192.168.1.20");
    ann.insert(
        format!("{PREFIX}/backend-data"),
        r#"{"VNI":1,"VtepMAC":"11:22:33:44:55:66"}"#.into(),
    );
    api.put_node("node2", &["10.244.2.0/24"], &ann);
    let event = recv_event(&mut rx, Duration::from_secs(5)).await;
    assert_eq!(event.event_type, EventType::Added); // Go: updates re-add
    assert_eq!(event.lease.subnet, ip4("10.244.2.0/24"));

    // Node deletion -> Removed event.
    api.delete_node("node2");
    let event = recv_event(&mut rx, Duration::from_secs(5)).await;
    assert_eq!(event.event_type, EventType::Removed);
}

#[tokio::test]
async fn watch_leases_survives_gone_and_watch_restart() {
    let _guard = ENV_LOCK.lock().await;
    let _node = EnvGuard::set("NODE_NAME", "node1");
    let (api_url, api) = MockApiserver::start().await;
    put_plain_node(&api, "node1", "10.244.1.0/24");
    // First watch attempt after the initial LIST gets 410 -> relist.
    api.expect_gone(1);
    let (_dir, conf) = write_conf(VXLAN_CONF);
    let (mgr, cancel) = start(&api_url, conf.to_str().unwrap(), true).await.unwrap();

    let mut rx = spawn_watch_leases(mgr.clone(), cancel.clone());
    // Mid-run: apiserver drops the watch connection -> relist again,
    // then the new event still arrives over the fresh watch.
    api.drop_watch();
    let mut ann = managed_annotations("192.168.1.30");
    ann.insert(format!("{PREFIX}/backend-data"), r#"{"VNI":2}"#.into());
    api.put_node("node3", &["10.244.3.0/24"], &ann);
    let event = recv_event(&mut rx, Duration::from_secs(10)).await;
    assert_eq!(event.event_type, EventType::Added);
    assert_eq!(event.lease.subnet, ip4("10.244.3.0/24"));
}

#[tokio::test]
async fn watch_lease_filters_by_subnet() {
    let _guard = ENV_LOCK.lock().await;
    let _node = EnvGuard::set("NODE_NAME", "node1");
    let (api_url, api) = MockApiserver::start().await;
    put_plain_node(&api, "node1", "10.244.1.0/24");
    api.put_node(
        "node2",
        &["10.244.2.0/24"],
        &managed_annotations("192.168.1.20"),
    );
    api.put_node(
        "node3",
        &["10.244.3.0/24"],
        &managed_annotations("192.168.1.30"),
    );
    let (_dir, conf) = write_conf(VXLAN_CONF);
    let (mgr, cancel) = start(&api_url, conf.to_str().unwrap(), true).await.unwrap();

    let (tx, mut rx) = mpsc::channel(32);
    let watched = mgr.clone();
    let cancel2 = cancel.clone();
    tokio::spawn(async move {
        let _ = watched
            .watch_lease(&cancel2, ip4("10.244.2.0/24"), Default::default(), tx)
            .await;
    });

    // node2 matches, node3 does not.
    let event = recv_event(&mut rx, Duration::from_secs(5)).await;
    assert_eq!(event.lease.subnet, ip4("10.244.2.0/24"));
    let mut ann = managed_annotations("192.168.1.30");
    ann.insert(format!("{PREFIX}/backend-data"), r#"{"VNI":9}"#.into());
    api.put_node("node3", &["10.244.3.0/24"], &ann);
    assert!(
        tokio::time::timeout(Duration::from_millis(500), rx.recv())
            .await
            .is_err(),
        "node3 event must not pass the subnet filter"
    );
}
