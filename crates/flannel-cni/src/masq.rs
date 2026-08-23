//! FLANNEL-POSTRTG-CHAIN-01 masquerade rule management.
//!
//! Port of upstream flannel-io/cni-plugin `masq.go`: when
//! `FLANNEL_IPMASQ=true`, flannel installs the masquerade rules itself
//! (the delegate's `ipMasq` is forced false). For each family with both
//! a network and a subnet this ensures, in the `nat` table:
//! - chain [`CHAIN`] exists (`-N`, tolerating "Chain already exists");
//! - POSTROUTING jumps to the chain (checked with `-C`, inserted with
//!   `-I POSTROUTING 1` when absent);
//! - two MASQUERADE rules are appended when absent (checked with `-C`).
//!
//! A family missing its network is skipped silently (upstream errors if
//! the rules are actually needed; flannel never derives the network from
//! the subnet — see `ip_masq_config` docs).

use anyhow::{bail, Context, Result};
use flannel_core::ip::{IP4Net, IP6Net};
use std::process::Command;

#[cfg(test)]
#[path = "masq_tests.rs"]
mod tests;

pub const CHAIN: &str = "FLANNEL-POSTRTG-CHAIN-01";
pub const COMMENT: &str = "flannel masq";

/// Ensure the masquerade rules for every family whose network *and*
/// subnet are present; families with either member `None` are skipped
/// silently (in particular, a missing FLANNEL_NETWORK is not derived
/// from the subnet — upstream treats that as "no masq config for the
/// family", so we do too).
pub fn ip_masq_config(
    v4_net: Option<&IP4Net>,
    v4_subnet: Option<&IP4Net>,
    v6_net: Option<&IP6Net>,
    v6_subnet: Option<&IP6Net>,
) -> Result<()> {
    if let (Some(net), Some(subnet)) = (v4_net, v4_subnet) {
        masq_family("iptables", &net.to_string(), &subnet.to_string())?;
    }
    if let (Some(net6), Some(subnet6)) = (v6_net, v6_subnet) {
        masq_family("ip6tables", &net6.to_string(), &subnet6.to_string())?;
    }
    Ok(())
}

/// Ensure chain + POSTROUTING jump + the two MASQUERADE rules for one
/// family via `binary` (`iptables` or `ip6tables`).
fn masq_family(binary: &str, network: &str, subnet: &str) -> Result<()> {
    ensure_chain(binary)?;
    // Jump rule: `-C` matches the rule regardless of its position, so it
    // is a correct presence check even though we insert at position 1.
    if exec(
        binary,
        &[
            "-t",
            "nat",
            "-C",
            "POSTROUTING",
            "-m",
            "comment",
            "--comment",
            COMMENT,
            "-j",
            CHAIN,
        ],
    )
    .is_err()
    {
        exec(
            binary,
            &[
                "-t",
                "nat",
                "-I",
                "POSTROUTING",
                "1",
                "-m",
                "comment",
                "--comment",
                COMMENT,
                "-j",
                CHAIN,
            ],
        )
        .with_context(|| format!("{binary}: failed to insert POSTROUTING jump to {CHAIN}"))?;
    }
    ensure_masq_rule(binary, &["-s", subnet, "!", "-d", network])?;
    ensure_masq_rule(binary, &["!", "-s", subnet, "-d", network])?;
    Ok(())
}

/// Append the `-j MASQUERADE` rule described by `match_spec` to [`CHAIN`]
/// unless `-C` reports it already present.
fn ensure_masq_rule(binary: &str, match_spec: &[&str]) -> Result<()> {
    let tail = ["-m", "comment", "--comment", COMMENT, "-j", "MASQUERADE"];
    let mut check = vec!["-t", "nat", "-C", CHAIN];
    check.extend(match_spec);
    check.extend(tail);
    if exec(binary, &check).is_ok() {
        return Ok(());
    }
    let mut append = vec!["-t", "nat", "-A", CHAIN];
    append.extend(match_spec);
    append.extend(tail);
    exec(binary, &append).with_context(|| format!("{binary}: failed to append rule to {CHAIN}"))
}

/// Create the chain, tolerating "Chain already exists".
fn ensure_chain(binary: &str) -> Result<()> {
    match exec(binary, &["-t", "nat", "-N", CHAIN]) {
        Ok(()) => Ok(()),
        Err(e) if e.to_string().contains("Chain already exists") => Ok(()),
        Err(e) => Err(e),
    }
}

/// Run one `iptables`/`ip6tables` invocation; on failure the error
/// includes the exit status, stdout and stderr.
fn exec(binary: &str, args: &[&str]) -> Result<()> {
    let out = Command::new(binary)
        .args(args)
        .output()
        .with_context(|| format!("failed to run {binary}"))?;
    if out.status.success() {
        return Ok(());
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    bail!(
        "{binary} {} failed ({}): stdout: {}; stderr: {}",
        args.join(" "),
        out.status,
        stdout.trim(),
        stderr.trim()
    )
}
