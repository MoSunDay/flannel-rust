//! Port of pkg/trafficmngr/iptables/iptables.go (upstream cdf76059):
//! the iptables-based `TrafficManager` (`IPTablesManager`), managing
//! the `FLANNEL-POSTRTG` (masquerade) and `FLANNEL-FWD` (forward)
//! chains via `iptables`/`ip6tables` plus `iptables-restore`.

#[path = "ipt.rs"]
pub(crate) mod ipt;

#[path = "ip_tables.rs"]
mod ip_tables;

#[path = "iptables_rules.rs"]
mod iptables_rules;

#[cfg(test)]
#[path = "iptables_tests.rs"]
mod tests;

use crate::ip::{IP4Net, IP6Net};
use crate::lease::{Lease, LeaseAttrs};
use crate::subnet::manager::Ctx;
use crate::trafficmngr::{IPTablesRule, TrafficManager};
use futures::future::BoxFuture;
use ip_tables::{clean_up_chains, create_chain, delete_tables, setup_and_ensure};
use ipt::Protocol;
use iptables_rules::{forward_rules, masq_ip6_rules, masq_rules};
use std::time::UNIX_EPOCH;
use tokio::sync::Mutex;
use tracing::info;

/// Go: `IPTablesManager`.
#[derive(Default)]
pub struct IPTablesManager {
    ipv4_rules: Mutex<Vec<IPTablesRule>>,
    ipv6_rules: Mutex<Vec<IPTablesRule>>,
}

impl IPTablesManager {
    pub fn new() -> Self {
        Self::default()
    }
}

impl TrafficManager for IPTablesManager {
    /// Go: `Init`.
    fn init<'a>(&'a self, _ctx: Ctx<'a>) -> BoxFuture<'a, anyhow::Result<()>> {
        Box::pin(async move {
            info!("Starting flannel in iptables mode...");
            self.ipv4_rules.lock().await.clear();
            self.ipv6_rules.lock().await.clear();
            Ok(())
        })
    }

    /// Go: `CleanUp`.
    fn clean_up<'a>(&'a self, _ctx: Ctx<'a>) -> BoxFuture<'a, anyhow::Result<()>> {
        Box::pin(async move {
            info!("Cleaning-up iptables rules...");
            clean_up_chains(Protocol::IPv4).await?;
            clean_up_chains(Protocol::IPv6).await?;
            Ok(())
        })
    }

    /// Go: `SetupAndEnsureMasqRules`.
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
    ) -> BoxFuture<'a, anyhow::Result<()>> {
        Box::pin(async move {
            if !network.empty() {
                // recycle rules only when the configured network or the
                // leased subnet is not equal to the current one.
                if network != prev_network || prev_subnet != lease.subnet {
                    info!(
                        "Current network or subnet ({}, {}) is not equal to previous one ({}, {}), \
                        trying to recycle old iptables rules",
                        network, lease.subnet, prev_network, prev_subnet
                    );
                    let prev = prev_lease(prev_subnet, IP6Net::default());
                    let old = masq_rules(prev_network, &prev, random_fully_disabled).await;
                    delete_tables(Protocol::IPv4, old).await?;
                }
                info!("Setting up masking rules");
                create_chain(Protocol::IPv4, "nat", "FLANNEL-POSTRTG").await;
                let rules = masq_rules(network, lease, random_fully_disabled).await;
                setup_and_ensure(&self.ipv4_rules, ctx, Protocol::IPv4, rules, resync_seconds)
                    .await;
            }
            if !v6_network.empty() {
                if v6_network != prev_v6_network || prev_v6_subnet != lease.ipv6_subnet {
                    info!(
                        "Current network or subnet ({}, {}) is not equal to previous one ({}, {}), \
                        trying to recycle old iptables rules",
                        v6_network, lease.ipv6_subnet, prev_v6_network, prev_v6_subnet
                    );
                    let prev = prev_lease(IP4Net::default(), prev_v6_subnet);
                    let old = masq_ip6_rules(prev_v6_network, &prev, random_fully_disabled).await;
                    delete_tables(Protocol::IPv6, old).await?;
                }
                info!("Setting up masking rules for IPv6");
                create_chain(Protocol::IPv6, "nat", "FLANNEL-POSTRTG").await;
                let rules = masq_ip6_rules(v6_network, lease, random_fully_disabled).await;
                setup_and_ensure(&self.ipv6_rules, ctx, Protocol::IPv6, rules, resync_seconds)
                    .await;
            }
            Ok(())
        })
    }

    /// Go: `SetupAndEnsureForwardRules`.
    fn setup_and_ensure_forward_rules<'a>(
        &'a self,
        ctx: Ctx<'a>,
        network: IP4Net,
        v6_network: IP6Net,
        resync_seconds: i64,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            if !network.empty() {
                info!("Changing default FORWARD chain policy to ACCEPT");
                create_chain(Protocol::IPv4, "filter", "FLANNEL-FWD").await;
                let rules = forward_rules(&network.to_string());
                setup_and_ensure(&self.ipv4_rules, ctx, Protocol::IPv4, rules, resync_seconds)
                    .await;
            }
            if !v6_network.empty() {
                info!("IPv6: Changing default FORWARD chain policy to ACCEPT");
                create_chain(Protocol::IPv6, "filter", "FLANNEL-FWD").await;
                let rules = forward_rules(&v6_network.to_string());
                setup_and_ensure(&self.ipv6_rules, ctx, Protocol::IPv6, rules, resync_seconds)
                    .await;
            }
        })
    }
}

/// Go: `&lease.Lease{Subnet: ..., IPv6Subnet: ...}` (zero values
/// otherwise; UNIX_EPOCH stands in for Go's zero time).
fn prev_lease(subnet: IP4Net, ipv6_subnet: IP6Net) -> Lease {
    Lease {
        enable_ipv4: false,
        enable_ipv6: false,
        subnet,
        ipv6_subnet,
        attrs: LeaseAttrs::default(),
        expiration: UNIX_EPOCH,
        asof: 0,
    }
}
