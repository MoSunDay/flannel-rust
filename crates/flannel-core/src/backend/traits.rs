//! Port of the `Backend`/`Network` interfaces and `BackendCtor` from
//! pkg/backend/common.go (upstream cdf76059). `ExternalInterface` itself
//! lives in `common.rs` (P0).
//!
//! Convention: native trait methods returning `BoxFuture` so the traits
//! stay object-safe for `Box<dyn Backend>` / `Box<dyn Network>`.
//!
//! Go deviations, forced by the Rust port:
//! - `RegisterNetwork` drops Go's `*sync.WaitGroup`: Go used it to let
//!   main wait for backend goroutines; here awaiting `Network::run` plays
//!   that role.
//! - `Run(ctx)` blocks until ctx is done in Go; `run` returns a future
//!   that completes when the token is cancelled.

use crate::backend::common::ExternalInterface;
use crate::lease::Lease;
use crate::subnet::config::Config;
use crate::subnet::manager::Ctx;
use crate::subnet::manager::Manager;
use futures::future::BoxFuture;
use std::sync::Arc;

/// Port of Go `backend.Backend`. Besides these entry points, a backend's
/// constructor receives static network interface information (like
/// internal and external IP addresses) which it should cache for later
/// use if needed.
pub trait Backend: Send + Sync {
    /// Go: `RegisterNetwork(ctx, wg, config) (Network, error)`. Called
    /// when the backend should create or begin managing a new network.
    fn register_network<'a>(
        &'a self,
        ctx: Ctx<'a>,
        config: &'a Config,
    ) -> BoxFuture<'a, anyhow::Result<Box<dyn Network>>>;
}

/// Port of Go `backend.Network`.
pub trait Network: Send + Sync {
    /// Go: `Lease() *lease.Lease`.
    fn lease(&self) -> &Lease;

    /// Go: `MTU() int`.
    fn mtu(&self) -> u32;

    /// Go: `Run(ctx)`, which blocks until ctx is done. The returned
    /// future completes when `ctx` is cancelled.
    fn run<'a>(&'a self, ctx: Ctx<'a>) -> BoxFuture<'a, ()>;
}

/// Port of Go `BackendCtor func(sm subnet.Manager, ei *ExternalInterface)
/// (Backend, error)`. Boxed so constructors can be stored in the registry
/// map; `Arc` shares the manager and interface with the daemon.
pub type BackendCtor = Box<
    dyn Fn(Arc<dyn Manager>, Arc<ExternalInterface>) -> anyhow::Result<Box<dyn Backend>>
        + Send
        + Sync,
>;
