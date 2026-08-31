//! Port of extension_network.go (upstream cdf76059): the extension
//! `network` struct, its `Run` loop and `handleSubnetEvents`.
//!
//! Go's `Run` spawns a goroutine feeding the `evts` channel (owned by
//! `subnet.WatchLeases`) and returns when the channel closes; `defer
//! wg.Wait()` joins the goroutine. The Rust port mirrors that exactly:
//! the watch runs as its own task that owns the channel sender, so the
//! sender drops -- and `recv()` observes the close -- the moment the
//! watch ends.

use super::{run_cmd, split_command, ExtensionConfig, BACKEND_TYPE};
use crate::backend::traits::Network;
use crate::lease::{Event, EventType, Lease};
use crate::subnet::manager::{Ctx, Manager};
use crate::subnet::watch::watch_leases;
use futures::future::BoxFuture;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

/// Go: `network` (extension_network.go). Go's `extIface` field is
/// replaced by the `mtu` snapshotted at register time (see mod.rs).
pub struct ExtensionNetwork {
    sm: Arc<dyn Manager>,
    lease: Lease,
    mtu: u32,
    cfg: ExtensionConfig,
}

impl ExtensionNetwork {
    pub(crate) fn new(sm: Arc<dyn Manager>, lease: Lease, mtu: u32, cfg: ExtensionConfig) -> Self {
        Self {
            sm,
            lease,
            mtu,
            cfg,
        }
    }
}

impl Network for ExtensionNetwork {
    fn lease(&self) -> &Lease {
        &self.lease
    }

    /// Go: `MTU()` = n.extIface.Iface.MTU (snapshotted at register time).
    fn mtu(&self) -> u32 {
        self.mtu
    }

    /// Go: `Run`: watch for subnet lease events and handle each batch
    /// until the events channel closes (extension_network.go:48-68).
    fn run<'a>(&'a self, ctx: Ctx<'a>) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            info!("Watching for new subnet leases");
            let (ev_tx, mut ev_rx) = mpsc::channel::<Vec<Event>>(1);

            // Go: `go func() { subnet.WatchLeases(ctx, n.sm, n.lease, evts)
            // }()`. The spawned task owns the sender: when the watch ends
            // (ctx done or manager end) the channel closes.
            let watch_task = tokio::spawn({
                let sm = self.sm.clone();
                let own_lease = self.lease.clone();
                let token = ctx.clone();
                async move { watch_leases(&token, &*sm, &own_lease, ev_tx).await }
            });

            // Go: `evtBatch, ok := <-evts; if !ok { log; return }`.
            while let Some(batch) = ev_rx.recv().await {
                handle_subnet_events(&self.cfg, &batch);
            }
            info!("evts chan closed");

            // Go: `defer wg.Wait()`.
            let _ = watch_task.await;
        })
    }
}

/// Go: `handleSubnetEvents`.
fn handle_subnet_events(cfg: &ExtensionConfig, batch: &[Event]) {
    for evt in batch {
        match evt.event_type {
            EventType::Added => {
                info!(
                    "Subnet added: {} via {}",
                    evt.lease.subnet, evt.lease.attrs.public_ip
                );

                if evt.lease.attrs.backend_type != BACKEND_TYPE {
                    warn!(
                        "Ignoring non-extension subnet: type={}",
                        evt.lease.attrs.backend_type
                    );
                    continue;
                }

                let cmd = cfg.subnet_add_command.as_deref().unwrap_or_default();
                if !cmd.is_empty() {
                    run_event_command(cmd, &evt.lease);
                }
            }
            EventType::Removed => {
                info!("Subnet removed: {}", evt.lease.subnet);

                if evt.lease.attrs.backend_type != BACKEND_TYPE {
                    warn!(
                        "Ignoring non-extension subnet: type={}",
                        evt.lease.attrs.backend_type
                    );
                    continue;
                }

                let cmd = cfg.subnet_remove_command.as_deref().unwrap_or_default();
                if !cmd.is_empty() {
                    run_event_command(cmd, &evt.lease);
                }
            }
        }
    }
}

/// Shared command-running part of Go's EventAdded/EventRemoved cases:
/// unmarshal the event lease's BackendData (a JSON-encoded string) into
/// the command's stdin, export SUBNET/PUBLIC_IP, and run the command.
///
/// Go deviation: a BackendData of JSON `null` leaves Go's string empty
/// (unmarshal no-op); here it fails the decode and the event is skipped
/// with Go's error log -- the only practical difference.
fn run_event_command(cmd: &str, lease: &Lease) {
    // Go: json.Unmarshal(evt.Lease.Attrs.BackendData, &backendData).
    let backend_data = match lease.attrs.backend_data.as_deref() {
        Some(raw) => match serde_json::from_str::<String>(raw.get()) {
            Ok(s) => s,
            Err(e) => {
                error!("failed to unmarshal BackendData: {e}");
                return; // Go: continue (skip this event)
            }
        },
        None => String::new(),
    };

    // Whitespace-only command: Go would panic indexing Fields()[0]; the
    // port skips (see mod.rs module docs).
    let Some(args) = split_command(cmd) else {
        return;
    };

    let env = vec![
        format!("SUBNET={}", lease.subnet),
        format!("PUBLIC_IP={}", lease.attrs.public_ip),
    ];
    match run_cmd(&env, &backend_data, args[0], &args[1..]) {
        Ok(out) => info!("Ran command: {cmd}\n Output: {out}"),
        Err(e) => error!("failed to run command: {cmd} Err: {e}"),
    }
}
