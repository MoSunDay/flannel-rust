//! iptables kernel-state helpers split out of `iptables.rs`:
//! flannel chain/table creation, bootstrap/teardown and CleanUp
//! (parts of upstream pkg/trafficmngr/iptables/iptables.go).

use super::ipt::IPTables;
use super::ipt::Protocol;
use crate::subnet::manager::Ctx;
use crate::trafficmngr::iptables_restore::{IPTablesRestore, IPTablesRestoreRules};
use crate::trafficmngr::IPTablesRule;
use anyhow::{anyhow, Result};
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{debug, error, info, trace};

/// Go log family name for a protocol.
pub fn iptables_family(proto: Protocol) -> &'static str {
    match proto {
        Protocol::IPv4 => "IPTables",
        Protocol::IPv6 => "IP6Tables",
    }
}

/// Go's CleanUp body for one protocol family.
pub async fn clean_up_chains(proto: Protocol) -> Result<()> {
    let binary = if proto == Protocol::IPv4 {
        "iptables"
    } else {
        "ip6tables"
    };
    let ipt = IPTables::new(proto)
        .await
        .map_err(|e| anyhow!("failed to setup IPTables. {binary} binary was not found: {e}"))?;
    for chain in ["FLANNEL-POSTRTG", "FLANNEL-FWD"] {
        // Go uses the nat table for FLANNEL-FWD too (upstream quirk: the
        // chain lives in filter, so this normally fails and is logged).
        if let Err(e) = ipt.clear_and_delete_chain("nat", chain).await {
            debug!(
                "could not clean-up {chain} ({}): {e}",
                iptables_family(proto)
            );
        }
    }
    Ok(())
}

/// Go: `CreateIP4Chain` / `CreateIP6Chain` body.
pub async fn create_chain(proto: Protocol, table: &str, chain: &str) {
    let ipt = match IPTables::new(proto).await {
        Ok(ipt) => ipt,
        Err(e) => {
            // if we can't find iptables, give up and return
            let family = iptables_family(proto);
            error!("Failed to setup {family}. iptables binary was not found: {e}");
            return;
        }
    };
    if let Err(e) = ipt.clear_chain(table, chain).await {
        let family = iptables_family(proto);
        error!("Failed to setup {family}. Error on creating the chain: {e}");
    }
}

/// Go: `setupAndEnsureIP4Tables` / `setupAndEnsureIP6Tables` body.
pub async fn setup_and_ensure(
    mgr_rules: &Mutex<Vec<IPTablesRule>>,
    ctx: Ctx<'_>,
    proto: Protocol,
    rules: Vec<IPTablesRule>,
    resync_seconds: i64,
) {
    let family = iptables_family(proto);
    let ipt = match IPTables::new(proto).await {
        Ok(ipt) => ipt,
        Err(e) => {
            error!("Failed to setup {family}. iptables binary was not found: {e}");
            return;
        }
    };
    let iptr = match IPTablesRestore::new(proto).await {
        Ok(iptr) => iptr,
        Err(e) => {
            // Go's v6 message is just "Failed to setup iptables-restore"
            let msg = if proto == Protocol::IPv4 {
                "Failed to setup IPTables. iptables-restore binary was not found"
            } else {
                "Failed to setup iptables-restore"
            };
            error!("{msg}: {e}");
            return;
        }
    };
    if let Err(e) = ip_tables_bootstrap(&ipt, &iptr, &rules).await {
        error!("Failed to bootstrap IPTables: {e}");
    }
    mgr_rules.lock().await.extend(rules.iter().cloned());
    spawn_resync(ctx, ipt, iptr, rules, resync_seconds);
}

/// Go's resync goroutine from `setupAndEnsureIP4Tables` /
/// `setupAndEnsureIP6Tables`. Deviation from Go: `time.After` with a
/// non-positive resync period fires immediately and busy-loops, so the
/// period is clamped to at least one second.
pub fn spawn_resync(
    ctx: Ctx<'_>,
    ipt: IPTables,
    iptr: IPTablesRestore,
    rules: Vec<IPTablesRule>,
    resync_seconds: i64,
) {
    let token = ctx.clone();
    let period = Duration::from_secs(resync_seconds.max(1) as u64);
    tokio::spawn(async move {
        loop {
            tokio::select! {
                // clean-up is setup in Init
                _ = token.cancelled() => break,
                _ = tokio::time::sleep(period) => {
                    // Ensure that all the iptables rules exist periodically
                    if let Err(e) = ensure_iptables(&ipt, &iptr, &rules).await {
                        error!("Failed to ensure iptables rules: {e}");
                    }
                }
            }
        }
    });
}

/// Go: `deleteIP4Tables` / `deleteIP6Tables` body.
pub async fn delete_tables(proto: Protocol, rules: Vec<IPTablesRule>) -> Result<()> {
    let family = iptables_family(proto);
    let ipt = match IPTables::new(proto).await {
        Ok(ipt) => ipt,
        Err(e) => {
            error!("Failed to setup {family}. iptables binary was not found: {e}");
            return Err(e);
        }
    };
    let iptr = match IPTablesRestore::new(proto).await {
        Ok(iptr) => iptr,
        Err(e) => {
            error!("Failed to setup iptables-restore: {e}");
            return Err(e);
        }
    };
    if let Err(e) = teardown_ip_tables(&ipt, &iptr, &rules).await {
        error!("Failed to teardown iptables: {e}");
        return Err(e);
    }
    Ok(())
}

/// Go: `ensureIPTables`.
pub async fn ensure_iptables(
    ipt: &IPTables,
    ipt_restore: &IPTablesRestore,
    rules: &[IPTablesRule],
) -> Result<()> {
    let exists = ip_tables_rules_exist(ipt, rules)
        .await
        .map_err(|e| anyhow!("error checking rule existence: {e}"))?;
    if exists {
        // if all the rules already exist, no need to do anything
        return Ok(());
    }
    // Otherwise, teardown all the rules and set them up again.
    // We do this because the order of the rules is important.
    info!("Some iptables rules are missing; deleting and recreating rules");
    ip_tables_bootstrap(ipt, ipt_restore, rules)
        .await
        .map_err(|e| anyhow!("error setting up rules: {e}"))
}

/// Name of the flannel chain a rule belongs to or jumps to (Go repeats
/// the `Chain == X || Rulespec[last] == X` check inline).
pub fn flannel_chain(rule: &IPTablesRule) -> Option<&'static str> {
    let last = rule.rulespec.last().map(String::as_str);
    if rule.chain == "FLANNEL-FWD" || last == Some("FLANNEL-FWD") {
        Some("FLANNEL-FWD")
    } else if rule.chain == "FLANNEL-POSTRTG" || last == Some("FLANNEL-POSTRTG") {
        Some("FLANNEL-POSTRTG")
    } else {
        None
    }
}

/// Go's inline `ChainExists` guard: `Ok(true)` = chain exists (or rule
/// has no flannel chain), `Ok(false)` = missing, `Err` = probe failed.
pub async fn flannel_chain_exists(ipt: &IPTables, rule: &IPTablesRule) -> Result<bool> {
    match flannel_chain(rule) {
        Some(chain) => ipt
            .chain_exists(&rule.table, chain)
            .await
            .map_err(|e| anyhow!("failed to check rule existence: {e}")),
        None => Ok(true),
    }
}

/// Go: `ipTablesRulesExist`.
pub async fn ip_tables_rules_exist(ipt: &IPTables, rules: &[IPTablesRule]) -> Result<bool> {
    for rule in rules {
        if !flannel_chain_exists(ipt, rule).await? {
            return Ok(false);
        }
        match ipt.exists(&rule.table, &rule.chain, &rule.rulespec).await {
            Ok(true) => {}
            Ok(false) => return Ok(false),
            Err(e) => return Err(anyhow!("failed to check rule existence: {e}")),
        }
    }
    Ok(true)
}

/// Go: `ipTablesBootstrap`: init iptables rules using iptables-restore
/// (with some cleaning if some rules already exist).
pub async fn ip_tables_bootstrap(
    ipt: &IPTables,
    ipt_restore: &IPTablesRestore,
    rules: &[IPTablesRule],
) -> Result<()> {
    let tables_rules = ip_tables_clean_and_build(ipt, rules)
        .await
        .map_err(|e| anyhow!("failed to setup iptables-restore payload: {e}"))?;
    trace!("trying to run iptables-restore < {:?}", tables_rules); // Go log.V(6)
    ipt_restore
        .apply_without_flush(&tables_rules)
        .await
        .map_err(|e| anyhow!("failed to apply partial iptables-restore {e}"))?;
    info!("bootstrap done");
    Ok(())
}

/// Go: `ipTablesCleanAndBuild`: create from a list of iptables rules a
/// transaction for iptables-restore, ordering the rules effectively
/// running. An existing rule gets a `-D` entry first; the build entry
/// is always appended after it.
pub async fn ip_tables_clean_and_build(
    ipt: &IPTables,
    rules: &[IPTablesRule],
) -> Result<IPTablesRestoreRules> {
    let mut tables_rules = IPTablesRestoreRules::new();
    // Build append and delete rules
    for rule in rules {
        if let Some(chain) = flannel_chain(rule) {
            if !flannel_chain_exists(ipt, rule).await? {
                ipt.clear_chain(&rule.table, chain)
                    .await
                    .map_err(|e| anyhow!("failed to create rule chain: {e}"))?;
            }
        }
        let exists = ipt
            .exists(&rule.table, &rule.chain, &rule.rulespec)
            .await
            .map_err(|e| anyhow!("failed to check rule existence: {e}"))?;
        let entry = tables_rules.entry(rule.table.clone()).or_default();
        if exists {
            // if the rule exists it's safer to delete it and then create it
            entry.push(with_prefix(["-D", &rule.chain], &rule.rulespec));
        }
        // with iptables-restore we can ensure that all rules created are
        // in good order and have no external rule between them
        entry.push(with_prefix([&rule.action, &rule.chain], &rule.rulespec));
    }
    Ok(tables_rules)
}

/// Go: `teardownIPTables`.
pub async fn teardown_ip_tables(
    ipt: &IPTables,
    iptr: &IPTablesRestore,
    rules: &[IPTablesRule],
) -> Result<()> {
    let mut tables_rules = IPTablesRestoreRules::new();
    // Build delete rules to a transaction for iptables restore
    for rule in rules {
        // rules of a missing flannel chain are skipped (Go: continue)
        if !flannel_chain_exists(ipt, rule).await? {
            continue;
        }
        let exists = ipt
            .exists(&rule.table, &rule.chain, &rule.rulespec)
            .await
            .map_err(|e| anyhow!("failed to check rule existence: {e}"))?;
        if exists {
            tables_rules
                .entry(rule.table.clone())
                .or_default()
                .push(with_prefix(["-D", &rule.chain], &rule.rulespec));
        }
    }
    // ApplyWithoutFlush makes a diff, Apply makes a replace (desired state)
    iptr.apply_without_flush(&tables_rules)
        .await
        .map_err(|e| anyhow!("unable to teardown iptables: {e}"))
}

pub fn with_prefix(prefix: [&str; 2], rulespec: &[String]) -> Vec<String> {
    let mut v = vec![prefix[0].to_string(), prefix[1].to_string()];
    v.extend(rulespec.iter().cloned());
    v
}
