//! Port of pkg/trafficmngr/iptables/iptables_restore.go (upstream
//! cdf76059): wrapper around `iptables-restore` used to apply ordered
//! rule batches without flushing existing chains.

use super::iptables::ipt::{look_path, parse_version, Protocol};
use anyhow::{anyhow, Context, Result};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::sync::Mutex;
use tracing::trace;

/// Go: `IPTablesRestoreRules`. A BTreeMap rather than Go's map: Go's
/// random map iteration order here was accidental; BTreeMap emits the
/// table blocks deterministically (sorted by table name).
pub type IPTablesRestoreRules = BTreeMap<String, Vec<Vec<String>>>;

/// Go: `ipTablesRestore`.
pub struct IPTablesRestore {
    path: PathBuf,
    has_wait: bool,
    // Go: mu sync.Mutex. Needed to avoid collisions between two
    // goroutines calling ApplyWithoutFlush in parallel: the second call
    // could otherwise accidentally restore a rule removed by the first.
    mu: Mutex<()>,
}

impl IPTablesRestore {
    /// Go: `NewIPTablesRestoreWithProtocol`.
    pub async fn new(proto: Protocol) -> Result<Self> {
        let cmd = restore_command(proto);
        let path = look_path(cmd).ok_or_else(|| anyhow!("{cmd} binary was not found"))?;
        // Go derives wait support from the version of the *iptables*
        // binary (not iptables-restore); ported verbatim.
        let ipt_cmd = proto.cmd();
        let ipt_path =
            look_path(ipt_cmd).ok_or_else(|| anyhow!("{ipt_cmd} binary was not found"))?;
        let version = version_string(&ipt_path).await?;
        let v = parse_version(&version)
            .map_err(|_| anyhow!("no iptables-restore version found in string: {version}"))?;
        Ok(IPTablesRestore {
            path,
            has_wait: ip_tables_has_wait_support(v),
            mu: Mutex::new(()),
        })
    }

    /// Go: `ApplyWithoutFlush`: apply rules without flushing chains.
    pub async fn apply_without_flush(&self, rules: &IPTablesRestoreRules) -> Result<()> {
        let _guard = self.mu.lock().await;
        let payload = build_payload(rules);
        trace!("trying to run with payload {}", payload); // Go log.V(6)
        let mut args = vec!["--noflush".to_string()];
        if self.has_wait {
            args.push("--wait".to_string());
        }
        let mut child = Command::new(&self.path)
            .args(&args)
            .stdin(Stdio::piped())
            .spawn()
            .with_context(|| format!("failed to run {}", self.path.display()))?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(payload.as_bytes()).await?;
        }
        let out = child.wait_with_output().await?;
        if !out.status.success() {
            return Err(anyhow!(
                "unable to run iptables-restore ({}, {}): exit status {}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr),
                out.status.code().unwrap_or(-1)
            ));
        }
        Ok(())
    }
}

/// Go: `getIptablesRestoreVersionString`.
async fn version_string(path: &Path) -> Result<String> {
    let out = Command::new(path)
        .arg("--version")
        .output()
        .await
        .map_err(|e| anyhow!("unable to find iptables-restore version: {e}"))?;
    if !out.status.success() {
        return Err(anyhow!(
            "unable to find iptables-restore version: exit status {}",
            out.status.code().unwrap_or(-1)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Go: `ipTablesHasWaitSupport` — `--wait` was added in 1.6.2.
fn ip_tables_has_wait_support(v: (u32, u32, u32)) -> bool {
    v >= (1, 6, 2)
}

/// Go: `getIptablesRestoreCommand`.
fn restore_command(proto: Protocol) -> &'static str {
    match proto {
        Protocol::IPv6 => "ip6tables-restore",
        Protocol::IPv4 => "iptables-restore",
    }
}

/// Go: `buildIPTablesRestorePayload`: build the `*<table>`/`COMMIT`
/// payload for iptables-restore.
fn build_payload(table_rules: &IPTablesRestoreRules) -> String {
    let mut payload = String::new();
    for (table, rules) in table_rules {
        payload.push('*');
        payload.push_str(table);
        payload.push('\n');
        for line_rule in rules {
            let size = line_rule.len();
            for (i, token) in line_rule.iter().enumerate() {
                // as iptables-restore uses stdin, protect "the comment"
                // following "--comment" with double quotes
                if i > 0 && line_rule[i - 1] == "--comment" {
                    payload.push('"');
                    payload.push_str(token);
                    payload.push('"');
                } else {
                    payload.push_str(token);
                }
                payload.push(if i < size - 1 { ' ' } else { '\n' });
            }
        }
        payload.push_str("COMMIT\n");
    }
    payload
}

#[cfg(test)]
mod tests {
    use super::*;

    fn svec(tokens: &[&str]) -> Vec<String> {
        tokens.iter().map(|s| s.to_string()).collect()
    }

    /// Go: `TestRules`.
    #[test]
    fn rules_payload_with_comment_quoting() {
        let specs = vec![
            svec(&[
                "-A",
                "INPUT",
                "-s",
                "127.0.0.1",
                "-d",
                "127.0.0.1",
                "-j",
                "RETURN",
            ]),
            svec(&[
                "-A",
                "INPUT",
                "-s",
                "127.0.0.1",
                "!",
                "-d",
                "224.0.0.0/4",
                "-m",
                "comment",
                "--comment",
                "flanneld masq",
                "-j",
                "MASQUERADE",
                "--random-fully",
            ]),
        ];
        let mut rules = IPTablesRestoreRules::new();
        rules.insert("filter".to_string(), specs.clone());
        rules.insert("nat".to_string(), specs);
        let expected_filter = "*filter\n\
            -A INPUT -s 127.0.0.1 -d 127.0.0.1 -j RETURN\n\
            -A INPUT -s 127.0.0.1 ! -d 224.0.0.0/4 -m comment --comment \"flanneld masq\" -j MASQUERADE --random-fully\n\
            COMMIT\n";
        let expected_nat = "*nat\n\
            -A INPUT -s 127.0.0.1 -d 127.0.0.1 -j RETURN\n\
            -A INPUT -s 127.0.0.1 ! -d 224.0.0.0/4 -m comment --comment \"flanneld masq\" -j MASQUERADE --random-fully\n\
            COMMIT\n";
        // Go accepted either table order (map iteration is randomized);
        // BTreeMap is deterministic and emits "filter" before "nat".
        assert_eq!(
            build_payload(&rules),
            format!("{expected_filter}{expected_nat}")
        );
    }

    #[test]
    fn empty_payload() {
        assert_eq!(build_payload(&IPTablesRestoreRules::new()), "");
    }

    #[test]
    fn wait_support_gate() {
        assert!(!ip_tables_has_wait_support((0, 9, 9)));
        assert!(!ip_tables_has_wait_support((1, 6, 1)));
        assert!(ip_tables_has_wait_support((1, 6, 2)));
        assert!(ip_tables_has_wait_support((1, 8, 7)));
        assert!(ip_tables_has_wait_support((2, 0, 0)));
    }

    #[tokio::test]
    async fn new_probes_installed_binary() {
        if look_path("iptables-restore").is_none() {
            return; // nothing to probe on this host
        }
        let iptr = IPTablesRestore::new(Protocol::IPv4).await.unwrap();
        // The container ships iptables v1.8.7 >= 1.6.2.
        assert!(iptr.has_wait);
    }
}
