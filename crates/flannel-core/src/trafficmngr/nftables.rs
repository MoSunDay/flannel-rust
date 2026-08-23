//! Port of pkg/trafficmngr/nftables (upstream cdf76059): the nftables
//! traffic manager (Go files nftables.go + utils.go). Manages the
//! `flannel-ipv4` / `flannel-ipv6` tables through knftables-style
//! transactions ([`super::nft`]). Go has no resync loops here: flush +
//! re-add is idempotent and the masq setup runs once.

#[path = "nftables_masq.rs"]
mod masq;

#[cfg(test)]
#[path = "nftables_tests.rs"]
mod tests;

use super::nft::{
    concat, ChainDef, Family, Nft, Transaction, FILTER_PRIORITY, FILTER_TYPE, FORWARD_HOOK,
    NAT_TYPE, POSTROUTING_HOOK, SNAT_PRIORITY,
};
use super::TrafficManager;
use crate::ip::{IP4Net, IP6Net};
use crate::lease::Lease;
use crate::subnet::manager::Ctx;
use anyhow::{anyhow, Result};
use futures::future::BoxFuture;
use masq::{masq_rule_texts, masquerade_test_tx, MASQ_FULLY_RANDOM, MASQ_PLAIN};
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

/// Go: `ipv4Table`, `ipv6Table`, `forwardChain`, `postrtgChain` and
/// utils.go's `masqueradeTestTable`.
pub const IPV4_TABLE: &str = "flannel-ipv4";
pub const IPV6_TABLE: &str = "flannel-ipv6";
pub const FORWARD_CHAIN: &str = "forward";
pub const POSTRTG_CHAIN: &str = "postrtg";
pub const MASQUERADE_TEST_CHAIN: &str = "masqueradeTest";

/// Go: `NFTablesManager`. Handles are created by [`TrafficManager::init`]
/// (Go's zero-value manager holds nil interfaces).
#[derive(Default)]
pub struct NFTablesManager {
    nft_v4: Mutex<Option<Nft>>,
    nft_v6: Mutex<Option<Nft>>,
}

/// Go: the `knftables.Chain` literals of the three flannel chains.
fn chain_def(
    name: &str,
    comment: &str,
    typ: &'static str,
    hook: &'static str,
    priority: &'static str,
) -> ChainDef {
    ChainDef {
        name: name.to_string(),
        comment: Some(comment.to_string()),
        typ: Some(typ),
        hook: Some(hook),
        priority: Some(priority),
    }
}

impl NFTablesManager {
    /// Go: zero-value `NFTablesManager{}`.
    pub fn new() -> Self {
        Self {
            nft_v4: Mutex::new(None),
            nft_v6: Mutex::new(None),
        }
    }

    /// Clones an initialised handle out of its slot. Go nil-derefs if
    /// `Init` never ran; the port errors (or returns false) instead.
    async fn handle(slot: &Mutex<Option<Nft>>, which: &str) -> Result<Nft> {
        slot.lock()
            .await
            .clone()
            .ok_or_else(|| anyhow!("nftables: {which} handle not initialised (Init not called)"))
    }

    /// Go: `checkRandomfully` (utils.go): validate a `masquerade
    /// fully-random` rule via the v4 handle; false if unsupported or the
    /// handle is missing (Init never ran).
    async fn check_random_fully(&self, ctx: Ctx<'_>) -> bool {
        let Ok(nft) = Self::handle(&self.nft_v4, "ipv4").await else {
            return false;
        };
        let tx = masquerade_test_tx(nft.is_modern());
        if nft.check(ctx, &tx).await.is_err() {
            warn!("nftables: random fully unsupported");
            return false;
        }
        true
    }

    /// Go: `addMasqRules` (returns nil upstream, so void here).
    async fn add_masq_rules(
        &self,
        ctx: Ctx<'_>,
        tx: &mut Transaction,
        cluster_cidr: &str,
        pod_cidr: &str,
        family: Family,
        random_fully_disabled: bool,
    ) {
        let fully_random = self.check_random_fully(ctx).await && !random_fully_disabled;
        let masquerade = if fully_random {
            MASQ_FULLY_RANDOM
        } else {
            MASQ_PLAIN
        };
        for rule in masq_rule_texts(cluster_cidr, pod_cidr, family.as_str(), masquerade) {
            tx.add_rule(POSTRTG_CHAIN, &rule);
        }
    }
}

fn table_name(family: Family) -> &'static str {
    match family {
        Family::Ip => IPV4_TABLE,
        Family::Ip6 => IPV6_TABLE,
    }
}

/// Go: `initTable` — create the table and return the handle to it.
async fn init_table(ctx: Ctx<'_>, family: Family, name: &str) -> Result<Nft> {
    let nft = Nft::new(family, name).await?;
    let mut tx = nft.new_transaction();
    tx.add_table(Some(&format!("rules for {name}")));
    if let Err(e) = nft.run(ctx, &tx).await {
        return Err(anyhow!("nftables: couldn't initialise table {name}: {e}"));
    }
    Ok(nft)
}

/// Go: the transaction built by each SetupAndEnsureForwardRules block.
fn forward_tx(family: Family, modern: bool, network: &str) -> Transaction {
    let f = family.as_str();
    let mut tx = Transaction::new(family, table_name(family), modern);
    tx.add_chain(&chain_def(
        FORWARD_CHAIN,
        "chain to accept flannel traffic",
        FILTER_TYPE,
        FORWARD_HOOK,
        FILTER_PRIORITY,
    ));
    tx.flush_chain(FORWARD_CHAIN);
    tx.add_rule(FORWARD_CHAIN, &concat(&[f, "saddr", network, "accept"]));
    tx.add_rule(FORWARD_CHAIN, &concat(&[f, "daddr", network, "accept"]));
    tx
}

/// Go: one family's CleanUp body. Go re-creates the handles; failures are
/// logged (Go log.V(2)) and never propagated.
async fn clean_up_table(ctx: Ctx<'_>, family: Family) {
    let name = table_name(family);
    let res = match Nft::new(family, name).await {
        Ok(nft) => {
            let mut tx = nft.new_transaction();
            tx.delete_table();
            nft.run(ctx, &tx).await
        }
        Err(e) => Err(e),
    };
    if let Err(e) = res {
        let prefix = if family == Family::Ip6 {
            "nftables (ipv6)"
        } else {
            "nftables"
        };
        debug!("{prefix}: couldn't delete table: {e}");
    }
}

/// Go: one family's forward block (errors logged, never returned).
async fn ensure_forward(
    ctx: Ctx<'_>,
    slot: &Mutex<Option<Nft>>,
    which: &str,
    suffix: &str,
    net: &str,
) {
    match NFTablesManager::handle(slot, which).await {
        Ok(nft) => {
            let tx = forward_tx(nft.family(), nft.is_modern(), net);
            if let Err(e) = nft.run(ctx, &tx).await {
                error!("nftables: couldn't setup forward rules{suffix}: {e}");
            }
        }
        Err(e) => error!("nftables: couldn't setup forward rules{suffix}: {e}"),
    }
}

impl TrafficManager for NFTablesManager {
    /// Go: `CleanUp`.
    fn clean_up<'a>(&'a self, ctx: Ctx<'a>) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            info!("Cleaning-up nftables rules...");
            clean_up_table(ctx, Family::Ip).await;
            clean_up_table(ctx, Family::Ip6).await;
            Ok(())
        })
    }

    /// Go: `Init`.
    fn init<'a>(&'a self, ctx: Ctx<'a>) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            info!("Starting flannel in nftables mode...");
            let v4 = init_table(ctx, Family::Ip, IPV4_TABLE).await?;
            *self.nft_v4.lock().await = Some(v4);
            let v6 = init_table(ctx, Family::Ip6, IPV6_TABLE).await?;
            *self.nft_v6.lock().await = Some(v6);
            Ok(())
        })
    }

    /// Go: `SetupAndEnsureMasqRules` (prev* and resyncPeriod are unused
    /// upstream: flush + re-add is idempotent and runs once).
    #[allow(clippy::too_many_arguments)]
    fn setup_and_ensure_masq_rules<'a>(
        &'a self,
        ctx: Ctx<'a>,
        network: IP4Net,
        _prev_subnet: IP4Net,
        _prev_network: IP4Net,
        v6_network: IP6Net,
        _prev_v6_subnet: IP6Net,
        _prev_v6_network: IP6Net,
        lease: &'a Lease,
        _resync_seconds: i64,
        random_fully_disabled: bool,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if !network.empty() {
                info!("nftables: setting up masking rules (ipv4)");
                setup_masq(
                    self,
                    ctx,
                    &self.nft_v4,
                    "ipv4",
                    &network.to_string(),
                    &lease.subnet.to_string(),
                    Family::Ip,
                    random_fully_disabled,
                )
                .await?;
            }
            if !v6_network.empty() {
                info!("nftables: setting up masking rules (ipv6)");
                setup_masq(
                    self,
                    ctx,
                    &self.nft_v6,
                    "ipv6",
                    &v6_network.to_string(),
                    &lease.ipv6_subnet.to_string(),
                    Family::Ip6,
                    random_fully_disabled,
                )
                .await?;
            }
            Ok(())
        })
    }

    /// Go: `SetupAndEnsureForwardRules` (returns nothing; errors logged).
    fn setup_and_ensure_forward_rules<'a>(
        &'a self,
        ctx: Ctx<'a>,
        network: IP4Net,
        v6_network: IP6Net,
        _resync_seconds: i64,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            if !network.empty() {
                info!("Changing default FORWARD chain policy to ACCEPT");
                ensure_forward(ctx, &self.nft_v4, "ipv4", "", &network.to_string()).await;
            }
            if !v6_network.empty() {
                info!("Changing default FORWARD chain policy to ACCEPT (ipv6)");
                ensure_forward(
                    ctx,
                    &self.nft_v6,
                    "ipv6",
                    " (ipv6)",
                    &v6_network.to_string(),
                )
                .await;
            }
        })
    }
}

/// Go: one family's masq block (chain + flush + addMasqRules + run).
#[allow(clippy::too_many_arguments)]
async fn setup_masq(
    mgr: &NFTablesManager,
    ctx: Ctx<'_>,
    slot: &Mutex<Option<Nft>>,
    which: &str,
    cluster_cidr: &str,
    pod_cidr: &str,
    family: Family,
    random_fully_disabled: bool,
) -> Result<()> {
    let nft = NFTablesManager::handle(slot, which).await?;
    let mut tx = nft.new_transaction();
    tx.add_chain(&chain_def(
        POSTRTG_CHAIN,
        "chain to manage traffic masquerading by flannel",
        NAT_TYPE,
        POSTROUTING_HOOK,
        SNAT_PRIORITY,
    ));
    // Go: flush first, so no check-and-recycle part like iptables.go.
    tx.flush_chain(POSTRTG_CHAIN);
    mgr.add_masq_rules(
        ctx,
        &mut tx,
        cluster_cidr,
        pod_cidr,
        family,
        random_fully_disabled,
    )
    .await;
    if let Err(e) = nft.run(ctx, &tx).await {
        return Err(anyhow!("nftables: couldn't setup masq rules: {e}"));
    }
    Ok(())
}
