//! Tests for the free watch functions, mirroring pkg/subnet/subnet.go +
//! pkg/lease/lease.go semantics: snapshot reset vs. incremental update,
//! own-lease filtering (adds and removals), single-lease forwarding.

use super::*;
use crate::lease::LeaseAttrs;
use crate::subnet::config::Config;
use crate::subnet::manager::Ctx;
use futures::future::BoxFuture;
use std::collections::VecDeque;
use std::time::{Duration, UNIX_EPOCH};
use tokio::sync::Mutex;

fn lease(v4: bool, v6: bool, subnet: &str) -> Lease {
    Lease {
        enable_ipv4: v4,
        enable_ipv6: v6,
        subnet: subnet.parse().unwrap(),
        ipv6_subnet: IP6Net::default(),
        attrs: LeaseAttrs::default(),
        expiration: UNIX_EPOCH,
        asof: 0,
    }
}

fn added(l: Lease) -> Event {
    Event {
        event_type: EventType::Added,
        lease: l,
    }
}

fn removed(l: Lease) -> Event {
    Event {
        event_type: EventType::Removed,
        lease: l,
    }
}

fn snapshot(leases: Vec<Lease>) -> LeaseWatchResult {
    LeaseWatchResult {
        events: Vec::new(),
        snapshot: leases,
    }
}

fn updates(events: Vec<Event>) -> LeaseWatchResult {
    LeaseWatchResult {
        events,
        snapshot: Vec::new(),
    }
}

/// Manager stub for the watch functions: replays canned
/// [`LeaseWatchResult`] batches on the watch channel, then either returns
/// (Go channel close) or waits for cancellation.
struct FakeManager {
    batches: Mutex<VecDeque<Vec<LeaseWatchResult>>>,
    wait_cancel: bool,
    fail_with: Option<String>,
}

impl FakeManager {
    fn new(batches: Vec<Vec<LeaseWatchResult>>, wait_cancel: bool) -> Self {
        Self {
            batches: Mutex::new(batches.into()),
            wait_cancel,
            fail_with: None,
        }
    }

    fn failing(msg: &str) -> Self {
        Self {
            batches: Mutex::new(VecDeque::new()),
            wait_cancel: false,
            fail_with: Some(msg.to_string()),
        }
    }

    /// Shared body of watch_lease/watch_leases, like a manager that feeds
    /// one channel until ctx is done.
    fn run_watch<'a>(
        &'a self,
        ctx: Ctx<'a>,
        tx: mpsc::Sender<Vec<LeaseWatchResult>>,
    ) -> BoxFuture<'a, anyhow::Result<()>> {
        Box::pin(async move {
            if let Some(msg) = &self.fail_with {
                return Err(anyhow::anyhow!("{msg}"));
            }
            while let Some(batch) = self.batches.lock().await.pop_front() {
                if tx.send(batch).await.is_err() {
                    return Ok(());
                }
            }
            if self.wait_cancel {
                ctx.cancelled().await;
            }
            Ok(())
        })
    }
}

impl Manager for FakeManager {
    fn get_network_config<'a>(&'a self, _ctx: Ctx<'a>) -> BoxFuture<'a, anyhow::Result<Config>> {
        Box::pin(async { Ok(Config::default()) })
    }

    fn handle_subnet_file<'a>(
        &'a self,
        _path: &'a str,
        _config: &'a Config,
        _ip_masq: bool,
        _sn: IP4Net,
        _ipv6sn: IP6Net,
        _mtu: u32,
    ) -> BoxFuture<'a, anyhow::Result<()>> {
        unimplemented!("not used by watch tests")
    }

    fn acquire_lease<'a>(
        &'a self,
        _ctx: Ctx<'a>,
        _attrs: &'a LeaseAttrs,
    ) -> BoxFuture<'a, anyhow::Result<Lease>> {
        unimplemented!("not used by watch tests")
    }

    fn renew_lease<'a>(
        &'a self,
        _ctx: Ctx<'a>,
        _lease: &'a Lease,
    ) -> BoxFuture<'a, anyhow::Result<Lease>> {
        unimplemented!("not used by watch tests")
    }

    fn watch_lease<'a>(
        &'a self,
        ctx: Ctx<'a>,
        _sn: IP4Net,
        _sn6: IP6Net,
        tx: mpsc::Sender<Vec<LeaseWatchResult>>,
    ) -> BoxFuture<'a, anyhow::Result<()>> {
        self.run_watch(ctx, tx)
    }

    fn watch_leases<'a>(
        &'a self,
        ctx: Ctx<'a>,
        tx: mpsc::Sender<Vec<LeaseWatchResult>>,
    ) -> BoxFuture<'a, anyhow::Result<()>> {
        self.run_watch(ctx, tx)
    }

    fn complete_lease<'a>(
        &'a self,
        _ctx: Ctx<'a>,
        _lease: &'a Lease,
    ) -> BoxFuture<'a, anyhow::Result<()>> {
        unimplemented!("not used by watch tests")
    }

    fn get_stored_mac_addresses<'a>(&'a self, _ctx: Ctx<'a>) -> BoxFuture<'a, (String, String)> {
        Box::pin(async { (String::new(), String::new()) })
    }

    fn get_stored_public_ip<'a>(&'a self, _ctx: Ctx<'a>) -> BoxFuture<'a, (String, String)> {
        Box::pin(async { (String::new(), String::new()) })
    }

    fn name(&self) -> String {
        "fake".to_string()
    }
}

/// Runs `watch_leases` to completion and collects the forwarded batches.
/// The receiver stream ends when the function returns (its sender drops).
async fn collect_watch_leases(
    sm: FakeManager,
    own: Lease,
    token: CancellationToken,
) -> Vec<Vec<Event>> {
    let (tx_out, mut rx_out) = mpsc::channel(16);
    let handle = tokio::spawn(async move {
        watch_leases(&token, &sm, &own, tx_out).await;
    });
    let mut got = Vec::new();
    while let Some(batch) = rx_out.recv().await {
        got.push(batch);
    }
    handle.await.unwrap();
    got
}

#[tokio::test]
async fn watch_leases_snapshot_reset_skips_own_lease() {
    let own = lease(true, false, "10.1.2.0/24");
    let a = lease(true, false, "10.1.3.0/24");
    let b = lease(true, false, "10.1.4.0/24");
    // Empty events => Reset with the snapshot; own lease is filtered out.
    let sm = FakeManager::new(
        vec![vec![snapshot(vec![own.clone(), a.clone(), b.clone()])]],
        false,
    );
    let got = collect_watch_leases(sm, own, CancellationToken::new()).await;
    assert_eq!(got, vec![vec![added(a), added(b)]]);
}

#[tokio::test]
async fn watch_leases_events_update_filters_own_adds_and_removes() {
    let own = lease(true, false, "10.1.2.0/24");
    let a = lease(true, false, "10.1.3.0/24");
    let c = lease(true, false, "10.1.5.0/24");
    let sm = FakeManager::new(
        vec![
            vec![snapshot(vec![a.clone()])],
            vec![updates(vec![
                added(c.clone()),
                added(own.clone()), // own lease add: filtered
                removed(a.clone()),
                removed(own.clone()), // own lease removal: filtered
            ])],
        ],
        false,
    );
    let got = collect_watch_leases(sm, own, CancellationToken::new()).await;
    assert_eq!(
        got,
        vec![vec![added(a.clone())], vec![added(c), removed(a)]]
    );
}

#[tokio::test]
async fn watch_leases_empty_events_and_snapshot_removes_stored() {
    // Go: empty events always means Reset, even with an empty snapshot,
    // which emits Removed for every previously stored lease.
    let own = lease(true, false, "10.1.2.0/24");
    let a = lease(true, false, "10.1.3.0/24");
    let sm = FakeManager::new(
        vec![vec![snapshot(vec![a.clone()])], vec![snapshot(Vec::new())]],
        false,
    );
    let got = collect_watch_leases(sm, own, CancellationToken::new()).await;
    assert_eq!(got, vec![vec![added(a.clone())], vec![removed(a)]]);
}

#[tokio::test]
async fn watch_leases_manager_error_returns_without_events() {
    let own = lease(true, false, "10.1.2.0/24");
    let got =
        collect_watch_leases(FakeManager::failing("boom"), own, CancellationToken::new()).await;
    assert!(got.is_empty());
}

#[tokio::test]
async fn watch_leases_returns_on_cancel() {
    let own = lease(true, false, "10.1.2.0/24");
    let token = CancellationToken::new();
    let sm = FakeManager::new(Vec::new(), true);
    let (tx_out, mut rx_out) = mpsc::channel(16);
    let t2 = token.clone();
    let handle = tokio::spawn(async move {
        watch_leases(&t2, &sm, &own, tx_out).await;
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    token.cancel();
    handle.await.unwrap();
    assert!(rx_out.try_recv().is_err());
}

/// Runs `watch_lease` to completion and collects the forwarded events.
async fn collect_watch_lease(sm: FakeManager, token: CancellationToken) -> Vec<Event> {
    let (tx_out, mut rx_out) = mpsc::channel(16);
    let handle = tokio::spawn(async move {
        watch_lease(&token, &sm, IP4Net::default(), IP6Net::default(), tx_out).await;
    });
    let mut got = Vec::new();
    while let Some(event) = rx_out.recv().await {
        got.push(event);
    }
    handle.await.unwrap();
    got
}

#[tokio::test]
async fn watch_lease_snapshot_becomes_added_then_events_forwarded() {
    let x = lease(true, false, "10.1.3.0/24");
    let sm = FakeManager::new(
        vec![
            vec![snapshot(vec![x.clone()])],
            vec![updates(vec![removed(x.clone())])],
            // Empty result: logged and skipped, nothing forwarded.
            vec![LeaseWatchResult::default()],
        ],
        false,
    );
    let got = collect_watch_lease(sm, CancellationToken::new()).await;
    assert_eq!(got, vec![added(x.clone()), removed(x)]);
}

#[tokio::test]
async fn watch_lease_snapshot_wins_over_events() {
    // Go checks the snapshot first: when both are set, snapshot[0] is
    // forwarded as EventAdded and events are ignored.
    let x = lease(true, false, "10.1.3.0/24");
    let y = lease(true, false, "10.1.4.0/24");
    let wr = LeaseWatchResult {
        events: vec![removed(y)],
        snapshot: vec![x.clone()],
    };
    let sm = FakeManager::new(vec![vec![wr]], false);
    let got = collect_watch_lease(sm, CancellationToken::new()).await;
    assert_eq!(got, vec![added(x)]);
}
