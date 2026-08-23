//! TrafficManager seam. Port of the `trafficmngr.TrafficManager`
//! interface and main.go's `newTrafficManager` (upstream cdf76059).
//!
//! P1 ships a no-op implementation: iptables/nftables rule management
//! lands in P3. The daemon call sequence already matches Go exactly
//! (clean up the opposite manager, init, masquerade rules, forward
//! rules), so P3 only replaces the implementation returned by
//! [`new_traffic_manager`].
//!
//! Convention: `BoxFuture` trait methods like `crate::subnet::Manager`
//! (object-safe, no async-trait macro).

use flannel_core::ip::{IP4Net, IP6Net};
use flannel_core::lease::Lease;
use flannel_core::subnet::manager::Ctx;
use futures::future::BoxFuture;
use std::sync::Once;

/// Go: `trafficmngr.TrafficManager`.
pub trait TrafficManager: Send + Sync {
    /// Go: `CleanUp(ctx) error`: remove all rules this manager owns.
    fn clean_up<'a>(&'a self, ctx: Ctx<'a>) -> BoxFuture<'a, anyhow::Result<()>>;

    /// Go: `Init(ctx) error`.
    fn init<'a>(&'a self, ctx: Ctx<'a>) -> BoxFuture<'a, anyhow::Result<()>>;

    /// Go: `SetupAndEnsureMasqRules(ctx, net, prevSubnet, prevNetwork,
    /// v6Net, prevV6Subnet, prevV6Network, lease, resyncSeconds,
    /// randomFullyDisabled) error`.
    #[allow(clippy::too_many_arguments)]
    fn setup_and_ensure_masq_rules<'a>(
        &'a self,
        ctx: Ctx<'a>,
        network: IP4Net,
        prev_subnet: IP4Net,
        prev_network: IP4Net,
        v6_network: IP6Net,
        prev_v6_subnet: IP6Net,
        prev_v6_network: IP6Net,
        lease: &'a Lease,
        resync_seconds: i64,
        random_fully_disabled: bool,
    ) -> BoxFuture<'a, anyhow::Result<()>>;

    /// Go: `SetupAndEnsureForwardRules(ctx, net, v6Net, resyncSeconds)`
    /// (returns nothing in Go).
    fn setup_and_ensure_forward_rules<'a>(
        &'a self,
        ctx: Ctx<'a>,
        network: IP4Net,
        v6_network: IP6Net,
        resync_seconds: i64,
    ) -> BoxFuture<'a, ()>;
}

/// Placeholder until P3 implements real rule management. Logs one
/// process-wide warning so operators know no rules are being applied.
pub struct NoopTrafficManager {
    /// Would select iptables vs nftables once P3 lands (Go: the
    /// `useNftables` argument of `newTrafficManager`).
    pub use_nftables: bool,
}

/// Warn exactly once per process, however many managers get built
/// (Go constructs two per run: cleanup + active).
static P3_WARN: Once = Once::new();

fn warn_p3_once(use_nftables: bool) {
    P3_WARN.call_once(|| {
        let engine = if use_nftables { "nftables" } else { "iptables" };
        tracing::warn!(
            "traffic rules management lands in P3; {engine} rules are not \
             applied by this build"
        );
    });
}

impl TrafficManager for NoopTrafficManager {
    fn clean_up<'a>(&'a self, _ctx: Ctx<'a>) -> BoxFuture<'a, anyhow::Result<()>> {
        warn_p3_once(self.use_nftables);
        Box::pin(async move { Ok(()) })
    }

    fn init<'a>(&'a self, _ctx: Ctx<'a>) -> BoxFuture<'a, anyhow::Result<()>> {
        warn_p3_once(self.use_nftables);
        Box::pin(async move { Ok(()) })
    }

    #[allow(clippy::too_many_arguments)]
    fn setup_and_ensure_masq_rules<'a>(
        &'a self,
        _ctx: Ctx<'a>,
        _network: IP4Net,
        _prev_subnet: IP4Net,
        _prev_network: IP4Net,
        _v6_network: IP6Net,
        _prev_v6_subnet: IP6Net,
        _prev_v6_network: IP6Net,
        _lease: &'a Lease,
        _resync_seconds: i64,
        _random_fully_disabled: bool,
    ) -> BoxFuture<'a, anyhow::Result<()>> {
        warn_p3_once(self.use_nftables);
        Box::pin(async move { Ok(()) })
    }

    fn setup_and_ensure_forward_rules<'a>(
        &'a self,
        _ctx: Ctx<'a>,
        _network: IP4Net,
        _v6_network: IP6Net,
        _resync_seconds: i64,
    ) -> BoxFuture<'a, ()> {
        warn_p3_once(self.use_nftables);
        Box::pin(async move {})
    }
}

/// Go: `newTrafficManager(useNftables)` — picks nftables or iptables.
/// Until P3 both choices yield the no-op manager.
pub fn new_traffic_manager(use_nftables: bool) -> Box<dyn TrafficManager> {
    Box::new(NoopTrafficManager { use_nftables })
}
