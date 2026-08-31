//! Port of the free watch functions of pkg/subnet/subnet.go (upstream
//! cdf76059): `WatchLeases` and `WatchLease`.
//!
//! Go spawns a goroutine running the manager's watch and ranges over the
//! channel it feeds; Rust cannot spawn with borrowed data, so the manager
//! future is driven concurrently in the same task via `tokio::select!`.
//! When the manager future finishes, its sender is inert (it lives inside
//! the completed future), so any buffered batches are drained with
//! `try_recv` before returning -- the moral equivalent of Go's channel
//! close (`for range` end).
//!
//! Go deviation (failure semantics): a watch error never ends the watch.
//! Go's run loops treat the watch as eternal -- a dead watch goroutine
//! leaves the `for range` parked instead of tearing down routes -- and
//! upstream watch.go retries manager errors with backoff, returning only
//! when the context is done. `watch_leases` mirrors that: manager errors
//! are logged and the watch session is re-established after an exponential
//! backoff (1s doubling to 30s); the backoff sleep races `ctx`, so
//! shutdown is prompt. Only a clean manager end (Go's channel close) or
//! cancellation returns.

use crate::ip::{IP4Net, IP6Net};
use crate::lease::{Event, EventType, Lease, LeaseWatchResult, LeaseWatcher};
use crate::subnet::manager::Manager;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Capacity of the internal watch channel. Go uses an unbuffered channel;
/// capacity 1 gives the same one-batch backpressure.
const WATCH_CHAN_CAP: usize = 1;

/// First delay before re-establishing a failed watch session.
const WATCH_RETRY_DELAY: Duration = Duration::from_secs(1);
/// Cap of the exponential watch retry backoff.
const WATCH_RETRY_MAX: Duration = Duration::from_secs(30);

/// Reduces one [`LeaseWatchResult`] to a batch of events through the
/// [`LeaseWatcher`] (Go inline logic inside `WatchLeases`): non-empty
/// events mean an incremental update; empty events mean the cursor was out
/// of range and the snapshot is used for a reset (etcd semantics, see
/// `LeaseWatchResult`). Own-lease filtering (including removals of the
/// own subnet) happens inside `LeaseWatcher`.
fn reduce(lw: &mut LeaseWatcher, wr: &LeaseWatchResult) -> Vec<Event> {
    if !wr.events.is_empty() {
        lw.update(&wr.events)
    } else {
        lw.reset(&wr.snapshot)
    }
}

/// Feeds one channel item (a slice of watch results) through the watcher,
/// logging each emitted event (Go: `log.Infof("Batch elem [%d] ...")`) and
/// forwarding non-empty batches. Returns false when the receiver is gone.
async fn handle_batch_results(
    lw: &mut LeaseWatcher,
    watch_results: &[LeaseWatchResult],
    receiver: &mut mpsc::Sender<Vec<Event>>,
) -> bool {
    for wr in watch_results {
        let batch = reduce(lw, wr);
        for (i, e) in batch.iter().enumerate() {
            tracing::info!("Batch elem [{i}] is {{ {e:?} }}");
        }
        if !batch.is_empty() && receiver.send(batch).await.is_err() {
            return false;
        }
    }
    true
}

/// Port of Go `WatchLeases`: performs a long term watch of all subnet
/// leases, communicating addition/deletion event batches on `receiver`.
/// Handles the "fall-behind" logic (snapshot reset vs. incremental update)
/// via [`LeaseWatcher`], which also filters out every event whose subnet
/// matches `own_lease` (including `EventRemoved` of the own lease).
///
/// Watch errors are retried with backoff until `ctx` is cancelled (see the
/// module docs); the function returns when the manager's watch session
/// ends cleanly (`Ok(())`) or `receiver` is dropped. A session whose
/// channel closes without a terminal result is re-established like an
/// error (the session future owns its sender for its whole lifetime).
pub async fn watch_leases<M: Manager + ?Sized>(
    ctx: &CancellationToken,
    sm: &M,
    own_lease: &Lease,
    mut receiver: mpsc::Sender<Vec<Event>>,
) {
    // LeaseWatcher is initiated with the Lease of the local node.
    let mut lw = LeaseWatcher::new(own_lease.clone());
    let mut backoff = WATCH_RETRY_DELAY;
    loop {
        let (tx, mut rx) = mpsc::channel::<Vec<LeaseWatchResult>>(WATCH_CHAN_CAP);
        let mut watch = Box::pin(sm.watch_leases(ctx, tx));

        'session: loop {
            tokio::select! {
                biased;
                _ = ctx.cancelled() => return,
                res = rx.recv() => {
                    let Some(watch_results) = res else { break 'session };
                    if !handle_batch_results(&mut lw, &watch_results, &mut receiver).await {
                        return;
                    }
                }
                res = &mut watch => {
                    // Go: the goroutine logs any error and returns; the
                    // channel close then ends the `for range` loop. Drain
                    // whatever the manager buffered before ending.
                    while let Ok(watch_results) = rx.try_recv() {
                        if !handle_batch_results(&mut lw, &watch_results, &mut receiver).await {
                            return;
                        }
                    }
                    match res {
                        // Go: the manager closed the channel -- forward loop
                        // ends, `close(receiver)` follows.
                        Ok(()) => return,
                        Err(e) if ctx.is_cancelled() => {
                            tracing::info!("{e}, close receiver chan");
                            return;
                        }
                        // Go never tears the watch down on errors (upstream
                        // watch.go retries with backoff): log and retry.
                        Err(e) => tracing::error!("could not watch leases: {e}"),
                    }
                    break 'session;
                }
            }
        }

        // Re-establish the watch after the backoff; the sleep races ctx so
        // shutdown never waits out the exponential delay.
        tokio::select! {
            biased;
            _ = ctx.cancelled() => return,
            _ = tokio::time::sleep(backoff) => {}
        }
        backoff = (backoff * 2).min(WATCH_RETRY_MAX);
    }
}

/// Maps one single-lease watch result to the event Go forwards: the first
/// snapshot entry as `EventAdded`, else the first event, else nothing
/// (logged, Go `log.V(2)`).
fn single_event(wr: &LeaseWatchResult) -> Option<Event> {
    if !wr.snapshot.is_empty() {
        Some(Event {
            event_type: EventType::Added,
            lease: wr.snapshot[0].clone(),
        })
    } else if !wr.events.is_empty() {
        Some(wr.events[0].clone())
    } else {
        tracing::debug!("WatchLease: empty event received");
        None
    }
}

/// Forwards one channel item of single-lease watch results; returns false
/// when the receiver is gone.
async fn handle_single_results(
    watch_results: &[LeaseWatchResult],
    receiver: &mut mpsc::Sender<Event>,
) -> bool {
    for wr in watch_results {
        let Some(event) = single_event(wr) else {
            continue;
        };
        if receiver.send(event).await.is_err() {
            return false;
        }
    }
    true
}

/// Port of Go `WatchLease`: long term watch of the given network's subnet
/// lease (used by `CompleteLease` to observe the own lease), emitting one
/// [`Event`] per change on `receiver`. Returns when the manager's watch
/// finishes, when `receiver` is dropped, or when `ctx` is cancelled.
pub async fn watch_lease<M: Manager + ?Sized>(
    ctx: &CancellationToken,
    sm: &M,
    sn: IP4Net,
    sn6: IP6Net,
    mut receiver: mpsc::Sender<Event>,
) {
    let (tx, mut rx) = mpsc::channel::<Vec<LeaseWatchResult>>(WATCH_CHAN_CAP);
    let mut watch = Box::pin(sm.watch_lease(ctx, sn, sn6, tx));

    'outer: loop {
        tokio::select! {
            biased;
            _ = ctx.cancelled() => break,
            res = rx.recv() => {
                let Some(watch_results) = res else { break };
                if !handle_single_results(&watch_results, &mut receiver).await {
                    break 'outer;
                }
            }
            res = &mut watch => {
                if let Err(e) = res {
                    if ctx.is_cancelled() {
                        // Go: context.Canceled/DeadlineExceeded branch.
                        tracing::info!("{e}, close receiver chan");
                    } else {
                        tracing::error!("Subnet watch failed: {e}");
                    }
                }
                while let Ok(watch_results) = rx.try_recv() {
                    if !handle_single_results(&watch_results, &mut receiver).await {
                        break 'outer;
                    }
                }
                break;
            }
        }
    }
    tracing::info!("leaseWatchChan channel closed");
}

#[cfg(test)]
mod tests;
