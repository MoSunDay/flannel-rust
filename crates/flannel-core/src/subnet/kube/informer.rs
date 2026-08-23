//! Node informer: approximation of Go client-go's SharedIndexInformer
//! (pkg/subnet/kube/kube.go `newKubeSubnetManager` + `Run`, upstream
//! cdf76059) over the thin [`crate::kube`] client.
//!
//! Semantics: initial LIST of ALL nodes (no fieldSelector, Go uses
//! `fields.Everything()`), then WATCH from the list's resourceVersion.
//! On `KubeError::Gone` (410) or any watch end the informer relists.
//! Every resync period (5min) all stored nodes are re-emitted as
//! MODIFIED, like the Go informer's ResyncPeriod. Store is keyed by node
//! name; `synced` mirrors client-go's `HasSynced` (set after the initial
//! list is processed).

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::StreamExt;
use tokio::sync::{mpsc, Semaphore};
use tokio_util::sync::CancellationToken;

use crate::kube::{KubeClient, KubeError, Node, WatchEvent, WatchEventType};
use crate::lease::{Event, EventType};

use super::annotations::Annotations;
use super::events::{handle_add_lease_event, handle_update_lease_event, EventEnv};

/// Go `resyncPeriod = 5 * time.Minute`.
pub(crate) const RESYNC_PERIOD: Duration = Duration::from_secs(5 * 60);
/// Backoff before retrying a failed LIST (Go reflector backs off too).
const LIST_RETRY_BACKOFF: Duration = Duration::from_secs(1);
/// Backoff before relisting after a watch ended/failed.
const RELIST_BACKOFF: Duration = Duration::from_millis(500);

/// Shared node cache plus the sync signal (Go `nodeStore` + HasSynced).
pub(crate) struct NodeStore {
    nodes: Mutex<HashMap<String, Node>>,
    synced: AtomicBool,
}

impl NodeStore {
    pub(crate) fn new() -> Self {
        Self {
            nodes: Mutex::new(HashMap::new()),
            synced: AtomicBool::new(false),
        }
    }

    pub(crate) fn get(&self, name: &str) -> Option<Node> {
        self.nodes.lock().unwrap().get(name).cloned()
    }

    pub(crate) fn snapshot(&self) -> Vec<Node> {
        self.nodes.lock().unwrap().values().cloned().collect()
    }

    /// Insert/replace; returns the previous object (Go store Add/Update).
    pub(crate) fn put(&self, node: Node) -> Option<Node> {
        self.nodes
            .lock()
            .unwrap()
            .insert(node.metadata.name.clone(), node)
    }

    pub(crate) fn remove(&self, name: &str) -> Option<Node> {
        self.nodes.lock().unwrap().remove(name)
    }

    /// Replace the whole store from a LIST; returns the previous content
    /// so the caller can compute add/update/delete deltas (Go DeltaFIFO
    /// Replace).
    pub(crate) fn replace_all(&self, items: Vec<Node>) -> HashMap<String, Node> {
        let mut new = HashMap::with_capacity(items.len());
        for node in items {
            new.insert(node.metadata.name.clone(), node);
        }
        std::mem::replace(&mut self.nodes.lock().unwrap(), new)
    }

    pub(crate) fn mark_synced(&self) {
        self.synced.store(true, Ordering::SeqCst);
    }

    pub(crate) fn is_synced(&self) -> bool {
        self.synced.load(Ordering::SeqCst)
    }
}

/// Sleep that returns early (false) when `cancel` fires.
pub(crate) async fn sleep_cancellable(d: Duration, cancel: &CancellationToken) -> bool {
    tokio::select! {
        biased;
        _ = cancel.cancelled() => false,
        _ = tokio::time::sleep(d) => true,
    }
}

/// Everything the informer loop needs (cheap clones only).
pub(crate) struct InformerCtx {
    pub(crate) client: KubeClient,
    pub(crate) store: Arc<NodeStore>,
    pub(crate) annotations: Annotations,
    pub(crate) enable_ipv4: bool,
    pub(crate) enable_ipv6: bool,
    pub(crate) events_tx: mpsc::Sender<Event>,
    pub(crate) semaphore: Arc<Semaphore>,
    pub(crate) cancel: CancellationToken,
}

impl InformerCtx {
    fn handler_ctx(&self) -> EventEnv<'_> {
        EventEnv {
            ctx: &self.cancel,
            tx: &self.events_tx,
            sem: &self.semaphore,
            annotations: &self.annotations,
            enable_ipv4: self.enable_ipv4,
            enable_ipv6: self.enable_ipv6,
        }
    }
}

/// Go `Run(ctx)` + the reflector's ListAndWatch loop. Runs until `cancel`.
pub(crate) async fn run_node_informer(ictx: InformerCtx) {
    tracing::info!("Starting kube subnet manager");
    loop {
        if ictx.cancel.is_cancelled() {
            return;
        }
        // LIST all nodes (Go: fields.Everything()).
        let list = match ictx.client.list_nodes(None).await {
            Ok(list) => list,
            Err(e) => {
                tracing::warn!("node list failed, retrying: {e}");
                if !sleep_cancellable(LIST_RETRY_BACKOFF, &ictx.cancel).await {
                    return;
                }
                continue;
            }
        };

        let items = list.items;
        let old = ictx.store.replace_all(items.clone());
        reconcile_relist(&ictx, &old, &items);
        ictx.store.mark_synced();

        // WATCH from the list's resourceVersion until it ends.
        let mut rv = list.metadata.resource_version;
        match run_watch(&ictx, &mut rv).await {
            WatchEnd::Cancelled => return,
            WatchEnd::Gone => {
                tracing::info!("watch resource version expired (410 Gone), relisting");
            }
            WatchEnd::Ended => {
                tracing::info!("watch stream ended, relisting");
            }
            WatchEnd::Failed(e) => {
                tracing::warn!("watch failed ({e}), relisting");
            }
        }
        if !sleep_cancellable(RELIST_BACKOFF, &ictx.cancel).await {
            return;
        }
    }
}

/// Deltas of a LIST replace (Go DeltaFIFO Replace): objects in the new
/// list are Added (new) or Updated (known); missing ones are Deleted.
fn reconcile_relist(ictx: &InformerCtx, old: &HashMap<String, Node>, items: &[Node]) {
    let h = ictx.handler_ctx();
    let mut seen: HashSet<&str> = HashSet::new();
    for node in items {
        seen.insert(node.metadata.name.as_str());
        match old.get(&node.metadata.name) {
            None => handle_add_lease_event(&h, EventType::Added, node),
            Some(prev) => handle_update_lease_event(&h, prev, node),
        }
    }
    for (name, node) in old {
        if !seen.contains(name.as_str()) {
            handle_add_lease_event(&h, EventType::Removed, node);
        }
    }
}

enum WatchEnd {
    Cancelled,
    Ended,
    Gone,
    Failed(KubeError),
}

/// One WATCH session: dispatch events into the store + lease handlers,
/// track the latest resourceVersion (bookmarks included), re-emit all
/// stored nodes as MODIFIED every resync period.
async fn run_watch(ictx: &InformerCtx, rv: &mut Option<String>) -> WatchEnd {
    let stream = match ictx
        .client
        .watch_nodes(None, rv.as_deref(), true, ictx.cancel.clone())
        .await
    {
        Ok(stream) => stream,
        Err(e) => return WatchEnd::Failed(e),
    };
    futures::pin_mut!(stream);

    let mut resync = tokio::time::interval(RESYNC_PERIOD);
    resync.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    resync.tick().await; // consume the immediate first tick

    loop {
        tokio::select! {
            biased;
            _ = ictx.cancel.cancelled() => return WatchEnd::Cancelled,
            item = stream.next() => {
                let Some(result) = item else { return WatchEnd::Ended };
                match result {
                    Ok(event) => {
                        if let Some(new_rv) = &event.object.metadata.resource_version {
                            *rv = Some(new_rv.clone());
                        }
                        dispatch(ictx, event);
                    }
                    Err(KubeError::Gone) => return WatchEnd::Gone,
                    Err(e) => return WatchEnd::Failed(e),
                }
            }
            _ = resync.tick() => {
                // Go ResyncPeriod: re-emit MODIFIED for all stored nodes.
                let h = ictx.handler_ctx();
                for node in ictx.store.snapshot() {
                    handle_update_lease_event(&h, &node.clone(), &node);
                }
            }
        }
    }
}

/// Route one watch frame to the store and the lease event handlers with
/// client-go informer semantics (ADDED of a known object is an update).
fn dispatch(ictx: &InformerCtx, event: WatchEvent<Node>) {
    let h = ictx.handler_ctx();
    match event.event_type {
        WatchEventType::Added => match ictx.store.put(event.object.clone()) {
            None => handle_add_lease_event(&h, EventType::Added, &event.object),
            Some(old) => handle_update_lease_event(&h, &old, &event.object),
        },
        WatchEventType::Modified | WatchEventType::Bookmark => {
            // Bookmark carries only a fresh resourceVersion (already
            // recorded by the caller).
            if event.event_type == WatchEventType::Bookmark {
                return;
            }
            let old = ictx
                .store
                .put(event.object.clone())
                .unwrap_or_else(|| event.object.clone());
            handle_update_lease_event(&h, &old, &event.object);
        }
        WatchEventType::Deleted => {
            // Go DeleteFunc: DeletedFinalStateUnknown handling collapses
            // to "always treat the payload as the deleted node" here.
            ictx.store.remove(&event.object.metadata.name);
            handle_add_lease_event(&h, EventType::Removed, &event.object);
        }
        WatchEventType::Error => {
            // Surfaced as Err by the watch decoder; ignore defensively.
            tracing::warn!("unexpected ERROR watch frame object");
        }
    }
}
