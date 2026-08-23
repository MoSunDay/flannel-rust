//! Port of extension_network.go (upstream cdf76059): the extension
//! `network` struct, its `Run` loop and `handleSubnetEvents`.
//!
//! Go deviation: Go's `Run` drives `WatchLeases` from a goroutine and
//! `defer wg.Wait()`s it; the Rust port drives the watch future in the
//! same task via `tokio::select!` (same shape as the vxlan port).

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

    /// Go: `Run`: watch for subnet lease events and handle each batch.
    fn run<'a>(&'a self, ctx: Ctx<'a>) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            info!("Watching for new subnet leases");
            let (ev_tx, mut ev_rx) = mpsc::channel::<Vec<Event>>(1);
            let watch = watch_leases(ctx, &*self.sm, &self.lease, ev_tx);
            tokio::pin!(watch);
            let mut watch_done = false;

            loop {
                tokio::select! {
                    biased;
                    batch = ev_rx.recv() => match batch {
                        Some(b) => handle_subnet_events(&self.cfg, &b),
                        None => {
                            info!("evts chan closed");
                            return;
                        }
                    },
                    _ = &mut watch, if !watch_done => { watch_done = true; }
                }
            }
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
