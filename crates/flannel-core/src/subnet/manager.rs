//! Port of the `subnet.Manager` interface (pkg/subnet/subnet.go, upstream
//! cdf76059, lines ~94-105).
//!
//! Convention: native trait methods returning `BoxFuture` (no async-trait
//! macro) so the trait stays object-safe for `Arc<dyn Manager>`. The Go
//! `context.Context` parameter becomes [`Ctx`], a borrowed
//! [`CancellationToken`] that implementations can `select` on.

use crate::ip::{IP4Net, IP6Net};
use crate::lease::{Lease, LeaseAttrs, LeaseWatchResult};
use crate::subnet::config::Config;
use futures::future::BoxFuture;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Port of Go `context.Context` in manager calls: a borrowed cancellation
/// token that async functions can `select` on (Go: `<-ctx.Done()`).
pub type Ctx<'a> = &'a CancellationToken;

/// Port of Go `subnet.Manager`. Implementations: the Kubernetes subnet
/// manager (P1, `kube/`) and the etcd local manager (not ported).
///
/// Deviations from Go, all forced by the Rust type system and documented
/// at the method level:
/// - `RenewLease(ctx, *lease.Lease)` mutates the lease's expiration in
///   place; here the updated lease is returned instead.
/// - `CompleteLease` drops Go's `*sync.WaitGroup`: it existed only so the
///   etcd manager could account for a goroutine it spawned; Rust callers
///   await the returned future instead.
/// - `WatchLease`/`WatchLeases` take the send half of a tokio channel;
///   the etcd-only `Cursor` of `LeaseWatchResult` is not ported (no etcd
///   manager), so implementations never need cursor bookkeeping.
pub trait Manager: Send + Sync {
    /// Go: `GetNetworkConfig(ctx) (*Config, error)`.
    fn get_network_config<'a>(&'a self, ctx: Ctx<'a>) -> BoxFuture<'a, anyhow::Result<Config>>;

    /// Go: `HandleSubnetFile(path, config, ipMasq, sn, ipv6sn, mtu) error`.
    /// Writes the subnet.env file (Go delegates to `WriteSubnetFile`).
    #[allow(clippy::too_many_arguments)]
    fn handle_subnet_file<'a>(
        &'a self,
        path: &'a str,
        config: &'a Config,
        ip_masq: bool,
        sn: IP4Net,
        ipv6sn: IP6Net,
        mtu: u32,
    ) -> BoxFuture<'a, anyhow::Result<()>>;

    /// Go: `AcquireLease(ctx, attrs) (*lease.Lease, error)`. Acquires or
    /// reuses the lease for this node.
    fn acquire_lease<'a>(
        &'a self,
        ctx: Ctx<'a>,
        attrs: &'a LeaseAttrs,
    ) -> BoxFuture<'a, anyhow::Result<Lease>>;

    /// Go: `RenewLease(ctx, lease) error`, which updates
    /// `lease.Expiration` in place; the Rust port returns the lease with
    /// the refreshed expiration instead.
    fn renew_lease<'a>(
        &'a self,
        ctx: Ctx<'a>,
        lease: &'a Lease,
    ) -> BoxFuture<'a, anyhow::Result<Lease>>;

    /// Go: `WatchLease(ctx, sn, sn6, receiver) error`. Sends watch results
    /// for the single subnet `sn`/`sn6` on `tx` until `ctx` is cancelled,
    /// then returns (dropping `tx`, which ends the receiver's stream).
    fn watch_lease<'a>(
        &'a self,
        ctx: Ctx<'a>,
        sn: IP4Net,
        sn6: IP6Net,
        tx: mpsc::Sender<Vec<LeaseWatchResult>>,
    ) -> BoxFuture<'a, anyhow::Result<()>>;

    /// Go: `WatchLeases(ctx, receiver) error`. Sends watch results for all
    /// subnet leases on `tx` until `ctx` is cancelled, then returns.
    fn watch_leases<'a>(
        &'a self,
        ctx: Ctx<'a>,
        tx: mpsc::Sender<Vec<LeaseWatchResult>>,
    ) -> BoxFuture<'a, anyhow::Result<()>>;

    /// Go: `CompleteLease(ctx, lease, wg) error`. Called once the network
    /// is running; the kube manager clears NodeNetworkUnavailable, the etcd
    /// manager starts its renewal loop. Go's `wg` is dropped (see trait
    /// docs).
    fn complete_lease<'a>(
        &'a self,
        ctx: Ctx<'a>,
        lease: &'a Lease,
    ) -> BoxFuture<'a, anyhow::Result<()>>;

    /// Go: `GetStoredMacAddresses(ctx) (string, string)`: stored (macv4,
    /// macv6); failures are logged inside the implementation, empty
    /// strings on error, exactly like Go.
    fn get_stored_mac_addresses<'a>(&'a self, ctx: Ctx<'a>) -> BoxFuture<'a, (String, String)>;

    /// Go: `GetStoredPublicIP(ctx) (string, string)`: stored (publicIPv4,
    /// publicIPv6) annotations; empty strings on error, like Go.
    fn get_stored_public_ip<'a>(&'a self, ctx: Ctx<'a>) -> BoxFuture<'a, (String, String)>;

    /// Go: `Name() string`, e.g. "Kubernetes Subnet Manager - node1".
    fn name(&self) -> String;
}
