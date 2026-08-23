//! Port of pkg/trafficmngr (upstream cdf76059): kernel traffic-rule
//! management for flannel. Two implementations, selected exactly like
//! Go's `newTrafficManager` in main.go:
//!
//! - [`iptables::IPTablesManager`]: shells out to `iptables`/
//!   `ip6tables` (+ `iptables-restore`), managing the `FLANNEL-POSTRTG`
//!   (masquerade) and `FLANNEL-FWD` (forward) chains.
//! - [`nftables::NFTablesManager`]: shells out to `nft` via
//!   knftables-style transactions, managing the `flannel-ipv4` /
//!   `flannel-ipv6` tables.
//!
//! Convention: `BoxFuture` trait methods like `crate::subnet::Manager`
//! (object-safe, no async-trait macro).

mod iptables;
mod iptables_restore;
mod nft;
mod nftables;

pub use iptables::IPTablesManager;
pub use nftables::NFTablesManager;

use crate::ip::{IP4Net, IP6Net};
use crate::lease::Lease;
use crate::subnet::manager::Ctx;
use futures::future::BoxFuture;

/// Go: `trafficmngr.KubeProxyMark`.
pub const KUBE_PROXY_MARK: &str = "0x4000/0x4000";

/// Go: `trafficmngr.IPTablesRule`. Rulespecs embed dynamic CIDR
/// strings, so all fields are owned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IPTablesRule {
    pub table: String,
    /// `-A` (all Go rules use `-A`).
    pub action: String,
    pub chain: String,
    pub rulespec: Vec<String>,
}

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

/// Go: `newTrafficManager(useNftables)` in main.go.
pub fn new_traffic_manager(use_nftables: bool) -> Box<dyn TrafficManager> {
    if use_nftables {
        Box::new(NFTablesManager::new())
    } else {
        Box::new(IPTablesManager::new())
    }
}
