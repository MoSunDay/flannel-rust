//! Live iptables test for the FLANNEL-POSTRTG-CHAIN-01 rules. Requires
//! root + a usable `iptables`; skips itself otherwise. Cleanup runs even
//! on panic via the [`MasqCleanup`] guard.

use super::*;
use flannel_core::ip::IP4Net;
use std::process::Command;
use std::str::FromStr;

const NET: &str = "10.244.0.0/16";
const SUBNET: &str = "10.244.3.0/24";

/// Best-effort removal of the chain, its rules and the POSTROUTING jump
/// (also removes leftovers from crashed runs).
fn cleanup() {
    // The jump rule may be present more than once after crashes; -D
    // removes one occurrence per call, so loop until it fails.
    for _ in 0..4 {
        let out = Command::new("iptables")
            .args([
                "-t",
                "nat",
                "-D",
                "POSTROUTING",
                "-m",
                "comment",
                "--comment",
                COMMENT,
                "-j",
                CHAIN,
            ])
            .output();
        if !matches!(out, Ok(o) if o.status.success()) {
            break;
        }
    }
    let _ = Command::new("iptables")
        .args(["-t", "nat", "-F", CHAIN])
        .output();
    let _ = Command::new("iptables")
        .args(["-t", "nat", "-X", CHAIN])
        .output();
}

/// Restores the nat table state on drop (test end or panic).
struct MasqCleanup;

impl Drop for MasqCleanup {
    fn drop(&mut self) {
        cleanup();
    }
}

fn iptables_usable() -> bool {
    (unsafe { libc::geteuid() } == 0)
        && Command::new("iptables")
            .args(["-t", "nat", "-L", "-n"])
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false)
}

fn iptables_save() -> String {
    let out = Command::new("iptables-save")
        .arg("-t")
        .arg("nat")
        .output()
        .expect("iptables-save runs");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn masq_rules_live_idempotent() {
    if !iptables_usable() {
        eprintln!("skipping masq test: iptables not usable (needs root)");
        return;
    }
    cleanup();
    let _guard = MasqCleanup;

    let net = IP4Net::from_str(NET).unwrap();
    let subnet = IP4Net::from_str(SUBNET).unwrap();
    ip_masq_config(Some(&net), Some(&subnet), None, None).unwrap();
    // Second run must be idempotent (no duplicate rules).
    ip_masq_config(Some(&net), Some(&subnet), None, None).unwrap();

    let saved = iptables_save();
    let rule1 = format!(
        "-A {CHAIN} -s {SUBNET} ! -d {NET} -m comment --comment \"{COMMENT}\" -j MASQUERADE"
    );
    let rule2 = format!(
        "-A {CHAIN} ! -s {SUBNET} -d {NET} -m comment --comment \"{COMMENT}\" -j MASQUERADE"
    );
    let jump = format!("-A POSTROUTING -m comment --comment \"{COMMENT}\" -j {CHAIN}");
    assert_eq!(saved.matches(&rule1).count(), 1, "rule1 in:\n{saved}");
    assert_eq!(saved.matches(&rule2).count(), 1, "rule2 in:\n{saved}");
    assert_eq!(saved.matches(&jump).count(), 1, "jump in:\n{saved}");

    // A family with a missing member is skipped silently.
    ip_masq_config(Some(&net), None, None, None).unwrap();
    ip_masq_config(None, None, None, None).unwrap();
    let saved = iptables_save();
    assert_eq!(saved.matches(&rule1).count(), 1);
}
