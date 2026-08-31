//! Port of pkg/subnet/kube (upstream cdf76059): the Kubernetes subnet
//! manager. It watches node objects through a LIST/WATCH informer
//! (approximating client-go's SharedIndexInformer over the thin
//! [`crate::kube`] client), derives flannel leases from podCIDRs and
//! node annotations, and publishes node annotations (backend data,
//! public IPs, kube-subnet-manager marker) via strategic-merge patches.
//!
//! Module layout mirrors kube.go:
//! - `annotations`: annotation key construction (`newAnnotations`)
//! - `events`: node -> lease event handlers + enqueue backpressure
//! - `informer`: node store + LIST/WATCH/relist loop
//! - `acquire`: `AcquireLease`
//! - `watch_ops`: `WatchLeases`/`WatchLease`/stored-annotation readers
//! - `status`: `CompleteLease` (NetworkUnavailable)
//!
//! Top-level deviations from Go (all documented at the use site):
//! - Go's single-consumer `events` channel is kept internally but fanned
//!   out over an [`EventHub`] (bounded backlog + replay on subscribe,
//!   blocking backpressure per subscriber) so `watch_leases` and the
//!   here-implemented `watch_lease` can run independently.
//! - On informer sync failure Go returns the manager together with the
//!   error; this constructor returns only the error.

mod acquire;
mod annotations;
mod events;
mod informer;
mod status;
mod watch_ops;

#[cfg(test)]
#[path = "events_tests.rs"]
mod events_tests;
#[cfg(test)]
#[path = "hub_tests.rs"]
mod hub_tests;
#[cfg(test)]
#[path = "kube_integration_tests.rs"]
mod kube_integration_tests;
#[cfg(test)]
mod mock;
#[cfg(test)]
mod support;
#[cfg(test)]
#[path = "watch_integration_tests.rs"]
mod watch_integration_tests;

pub use annotations::{new_annotations, Annotations};

use std::sync::Arc;
use std::time::{Duration, Instant};

use std::collections::VecDeque;
use std::sync::Mutex;

use futures::future::BoxFuture;
use tokio::sync::{mpsc, Semaphore};
use tokio_util::sync::CancellationToken;

use crate::ip::{IP4Net, IP6Net};
use crate::kube::KubeClient;
use crate::lease::{Event, Lease, LeaseAttrs, LeaseWatchResult};
use crate::subnet::config::Config;
use crate::subnet::manager::{Ctx, Manager};
use crate::subnet::writefile::write_subnet_file;

use self::informer::{run_node_informer, sleep_cancellable, InformerCtx, NodeStore};

/// Go: `nodeControllerSyncTimeout = 10 * time.Minute`.
const NODE_CONTROLLER_SYNC_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// Go: default event channel capacity.
const DEFAULT_EVENT_QUEUE_DEPTH: usize = 5000;
/// Go: `semaphore.NewWeighted(100)` bounding async event retries.
const ASYNC_SEND_SLOTS: usize = 100;

/// Port of Go `kubeSubnetManager`.
pub struct KubeSubnetManager {
    pub(crate) client: KubeClient,
    pub(crate) config: Config,
    pub(crate) node_name: String,
    pub(crate) annotations: Annotations,
    pub(crate) annotation_prefix: String,
    pub(crate) enable_ipv4: bool,
    pub(crate) enable_ipv6: bool,
    pub(crate) store: Arc<NodeStore>,
    pub(crate) events_tx: mpsc::Sender<Event>,
    pub(crate) hub: EventHub,
    pub(crate) semaphore: Arc<Semaphore>,
    pub(crate) disable_node_informer: bool,
    pub(crate) set_node_network_unavailable: bool,
}

impl std::fmt::Debug for KubeSubnetManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KubeSubnetManager")
            .field("node_name", &self.node_name)
            .field("annotation_prefix", &self.annotation_prefix)
            .field("disable_node_informer", &self.disable_node_informer)
            .finish_non_exhaustive()
    }
}

/// Go: `NewSubnetManager(ctx, apiUrl, kubeconfig, prefix, netConfPath,
/// setNodeNetworkUnavailable)`. The caller already resolved the
/// [`KubeClient`] (Go: BuildConfigFromFlags + NewForConfig). Resolves
/// the node name from NODE_NAME or POD_NAME/POD_NAMESPACE, reads the
/// net-conf file, builds the informer and waits (up to 10min) for its
/// initial sync.
pub async fn new_subnet_manager(
    ctx: &CancellationToken,
    client: KubeClient,
    prefix: &str,
    net_conf_path: &str,
    set_node_network_unavailable: bool,
) -> anyhow::Result<Arc<KubeSubnetManager>> {
    // The kube subnet mgr needs to know the k8s node name it runs on so
    // it can annotate it: NODE_NAME, else POD_NAME+POD_NAMESPACE -> pod.
    let node_name = resolve_node_name(&client).await?;

    let net_conf = std::fs::read_to_string(net_conf_path)
        .map_err(|e| anyhow::anyhow!("failed to read net conf: {e}"))?;
    let config = crate::subnet::config::parse_config(&net_conf)
        .map_err(|e| anyhow::anyhow!("error parsing subnet config: {e}"))?;

    let (mut sm, events_rx) = new_kube_subnet_manager(client, config, node_name, prefix)?;
    sm.set_node_network_unavailable = set_node_network_unavailable;

    if sm.disable_node_informer {
        tracing::info!("Node controller skips sync");
        return Ok(Arc::new(sm));
    }

    let sm = Arc::new(sm);
    // Fan the Go single-consumer events channel out to all watchers.
    tokio::spawn(fan_out(events_rx, sm.hub.clone()));
    tokio::spawn(run_node_informer(InformerCtx {
        client: sm.client.clone(),
        store: sm.store.clone(),
        annotations: sm.annotations.clone(),
        enable_ipv4: sm.enable_ipv4,
        enable_ipv6: sm.enable_ipv6,
        events_tx: sm.events_tx.clone(),
        semaphore: sm.semaphore.clone(),
        cancel: ctx.clone(),
    }));

    tracing::info!(
        "Waiting {:?} for node controller to sync",
        NODE_CONTROLLER_SYNC_TIMEOUT
    );
    wait_synced(&sm.store, ctx)
        .await
        .map_err(|e| anyhow::anyhow!("error waiting for nodeController to sync state: {e}"))?;
    tracing::info!("Node controller sync successful");

    Ok(sm)
}

/// Go: NODE_NAME env, else POD_NAME/POD_NAMESPACE -> pod.Spec.NodeName.
/// Error strings identical to Go. Runs in the constructor, before any
/// context exists (Go uses context.TODO here) - a detached token matches
/// that: the request is bounded by the dial timeout, not cancellable.
async fn resolve_node_name(client: &KubeClient) -> anyhow::Result<String> {
    let todo = tokio_util::sync::CancellationToken::new();
    let node_name = std::env::var("NODE_NAME").unwrap_or_default();
    if !node_name.is_empty() {
        return Ok(node_name);
    }
    let pod_name = std::env::var("POD_NAME").unwrap_or_default();
    let pod_namespace = std::env::var("POD_NAMESPACE").unwrap_or_default();
    if pod_name.is_empty() || pod_namespace.is_empty() {
        anyhow::bail!("env variables POD_NAME and POD_NAMESPACE must be set");
    }
    let pod = client
        .get_pod(&todo, &pod_namespace, &pod_name)
        .await
        .map_err(|e| {
            anyhow::anyhow!("error retrieving pod spec for '{pod_namespace}/{pod_name}': {e}")
        })?;
    match pod.spec.node_name.filter(|n| !n.is_empty()) {
        Some(name) => Ok(name),
        None => anyhow::bail!("node name not present in pod spec '{pod_namespace}/{pod_name}'"),
    }
}

/// Go: EVENT_QUEUE_DEPTH env (default 5000, must parse as int).
fn event_queue_depth() -> anyhow::Result<usize> {
    let scale_str = std::env::var("EVENT_QUEUE_DEPTH").unwrap_or_default();
    if scale_str.is_empty() {
        return Ok(DEFAULT_EVENT_QUEUE_DEPTH);
    }
    let n: i64 = scale_str
        .parse()
        .map_err(|e| anyhow::anyhow!("env EVENT_QUEUE_DEPTH={scale_str} format error: {e}"))?;
    Ok(if n > 0 {
        n as usize
    } else {
        DEFAULT_EVENT_QUEUE_DEPTH
    })
}

/// Go: `newKubeSubnetManager`. Returns the manager plus the receive half
/// of the internal event channel for the fan-out task.
fn new_kube_subnet_manager(
    client: KubeClient,
    config: Config,
    node_name: String,
    prefix: &str,
) -> anyhow::Result<(KubeSubnetManager, mpsc::Receiver<Event>)> {
    let annotations = new_annotations(prefix)?;
    let enable_ipv4 = config.enable_ipv4;
    let enable_ipv6 = config.enable_ipv6;
    let scale = event_queue_depth()?;
    let (events_tx, events_rx) = mpsc::channel(scale);
    // when backend type is alloc, someone else (e.g. cloud-controller-
    // managers) is taking care of the routing, thus we do not need the
    // informer (https://github.com/flannel-io/flannel/issues/1617).
    let disable_node_informer = config.backend_type == "alloc";
    let sm = KubeSubnetManager {
        client,
        config,
        node_name,
        annotations,
        annotation_prefix: prefix.to_string(),
        enable_ipv4,
        enable_ipv6,
        store: Arc::new(NodeStore::new()),
        events_tx,
        hub: EventHub::new(scale),
        semaphore: Arc::new(Semaphore::new(ASYNC_SEND_SLOTS)),
        disable_node_informer,
        set_node_network_unavailable: false,
    };
    Ok((sm, events_rx))
}

/// Bridges the Go-style single event channel to the watcher fan-out.
/// `publish` awaits its subscribers: a slow watcher backpressures the
/// informer exactly like Go's single consumer does.
async fn fan_out(mut rx: mpsc::Receiver<Event>, hub: EventHub) {
    while let Some(event) = rx.recv().await {
        hub.publish(event).await;
    }
}

/// Fan-out with a bounded backlog: Go's buffered `events` channel keeps
/// early events until `WatchLeases` starts consuming; `subscribe` here
/// replays the backlog so late subscribers still see them.
#[derive(Clone)]
pub(crate) struct EventHub {
    inner: Arc<Mutex<HubInner>>,
}

struct HubInner {
    backlog: VecDeque<Event>,
    capacity: usize,
    subscribers: Vec<mpsc::Sender<Event>>,
}

impl EventHub {
    fn new(capacity: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HubInner {
                backlog: VecDeque::new(),
                capacity: capacity.max(1),
                subscribers: Vec::new(),
            })),
        }
    }

    /// Blocking backpressure, Go's single-consumer semantics spread over
    /// the subscribers: each subscriber is awaited (`send().await`) so a
    /// watcher that cannot keep up slows the informer instead of being
    /// silently evicted (the old `try_send` + `retain` dropped a stalled
    /// watcher's channel permanently and the watch chain stopped while
    /// the daemon kept running). Only `Closed` receivers — a watcher
    /// returned/dropped — retire their sender. Subscribers are served in
    /// registration order, so one stalled watcher delays the others
    /// (there is no per-subscriber buffer beyond the channel capacity).
    /// The lock is never held across `.await`.
    async fn publish(&self, event: Event) {
        let subscribers: Vec<mpsc::Sender<Event>> = {
            let mut inner = self.inner.lock().unwrap();
            inner.backlog.push_back(event.clone());
            while inner.backlog.len() > inner.capacity {
                inner.backlog.pop_front();
            }
            inner.subscribers.clone()
        };

        let mut retired: Vec<mpsc::Sender<Event>> = Vec::new();
        for tx in &subscribers {
            if tx.send(event.clone()).await.is_err() {
                retired.push(tx.clone());
            }
        }
        if !retired.is_empty() {
            let mut inner = self.inner.lock().unwrap();
            inner
                .subscribers
                .retain(|tx| !retired.iter().any(|r| r.same_channel(tx)));
        }
    }

    fn subscribe(&self) -> mpsc::Receiver<Event> {
        let inner = self.inner.lock().unwrap();
        let (tx, rx) = mpsc::channel(inner.capacity + inner.backlog.len());
        for event in &inner.backlog {
            let _ = tx.try_send(event.clone());
        }
        // Mutex guard held until tx is registered: no publish races in
        // between, so no event is lost or duplicated.
        let mut inner = inner;
        inner.subscribers.push(tx);
        rx
    }
}

/// Go's `wait.PollUntilContextTimeout(ctx, time.Second, 10min, ...)`
/// around `HasSynced`.
async fn wait_synced(store: &NodeStore, ctx: &CancellationToken) -> anyhow::Result<()> {
    let deadline = Instant::now() + NODE_CONTROLLER_SYNC_TIMEOUT;
    while !store.is_synced() {
        if ctx.is_cancelled() {
            anyhow::bail!("context canceled");
        }
        if Instant::now() >= deadline {
            anyhow::bail!("context deadline exceeded");
        }
        if !sleep_cancellable(Duration::from_secs(1), ctx).await {
            anyhow::bail!("context canceled");
        }
    }
    Ok(())
}

impl Manager for KubeSubnetManager {
    fn get_network_config<'a>(&'a self, _ctx: Ctx<'a>) -> BoxFuture<'a, anyhow::Result<Config>> {
        Box::pin(async move { Ok(self.config.clone()) })
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_subnet_file<'a>(
        &'a self,
        path: &'a str,
        config: &'a Config,
        ip_masq: bool,
        sn: IP4Net,
        ipv6sn: IP6Net,
        mtu: u32,
    ) -> BoxFuture<'a, anyhow::Result<()>> {
        Box::pin(async move { write_subnet_file(path, config, ip_masq, sn, ipv6sn, mtu) })
    }

    fn acquire_lease<'a>(
        &'a self,
        ctx: Ctx<'a>,
        attrs: &'a LeaseAttrs,
    ) -> BoxFuture<'a, anyhow::Result<Lease>> {
        Box::pin(acquire::acquire_lease(self, ctx, attrs))
    }

    fn renew_lease<'a>(
        &'a self,
        _ctx: Ctx<'a>,
        _lease: &'a Lease,
    ) -> BoxFuture<'a, anyhow::Result<Lease>> {
        // Go: `return ErrUnimplemented`.
        Box::pin(async move { Err(anyhow::anyhow!("unimplemented")) })
    }

    fn watch_lease<'a>(
        &'a self,
        ctx: Ctx<'a>,
        sn: IP4Net,
        sn6: IP6Net,
        tx: mpsc::Sender<Vec<LeaseWatchResult>>,
    ) -> BoxFuture<'a, anyhow::Result<()>> {
        Box::pin(watch_ops::watch_lease(self, ctx, sn, sn6, tx))
    }

    fn watch_leases<'a>(
        &'a self,
        ctx: Ctx<'a>,
        tx: mpsc::Sender<Vec<LeaseWatchResult>>,
    ) -> BoxFuture<'a, anyhow::Result<()>> {
        Box::pin(watch_ops::watch_leases(self, ctx, tx))
    }

    fn complete_lease<'a>(
        &'a self,
        ctx: Ctx<'a>,
        lease: &'a Lease,
    ) -> BoxFuture<'a, anyhow::Result<()>> {
        Box::pin(status::complete_lease(self, ctx, lease))
    }

    fn get_stored_mac_addresses<'a>(&'a self, ctx: Ctx<'a>) -> BoxFuture<'a, (String, String)> {
        Box::pin(watch_ops::get_stored_mac_addresses(self, ctx))
    }

    fn get_stored_public_ip<'a>(&'a self, ctx: Ctx<'a>) -> BoxFuture<'a, (String, String)> {
        Box::pin(watch_ops::get_stored_public_ip(self, ctx))
    }

    fn name(&self) -> String {
        format!("Kubernetes Subnet Manager - {}", self.node_name)
    }
}
