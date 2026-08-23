//! Port of the parts of `github.com/coreos/go-iptables` v0.8.0 that
//! flannel uses: an async wrapper around the iptables/ip6tables
//! binaries. go-iptables sources are not vendored here; this is
//! implemented from its observable behavior (argument layout, exit
//! status handling, error strings).

use anyhow::{anyhow, Context, Result};
use regex::Regex;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tokio::process::Command;

/// Go: `iptables.Protocol`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Protocol {
    IPv4,
    IPv6,
}

impl Protocol {
    /// Go: `Protocol.cmd` (binary name for the protocol).
    pub fn cmd(self) -> &'static str {
        match self {
            Protocol::IPv4 => "iptables",
            Protocol::IPv6 => "ip6tables",
        }
    }
}

/// Error returned when iptables exits non-zero (Go: `iptables.Error`;
/// only the fields flannel relies on are ported). `msg` is the stderr
/// output.
#[derive(Debug)]
pub struct IPTablesError {
    pub msg: String,
}

impl std::fmt::Display for IPTablesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.msg.trim_end())
    }
}

impl std::error::Error for IPTablesError {}

impl IPTablesError {
    /// Go: `(*Error).IsNotExist`.
    pub fn is_not_exist(&self) -> bool {
        self.msg
            .contains("does a matching rule exist in that chain?")
            || self.msg.contains("No chain/target/match by that name")
    }

    /// Go: `(*Error).IsExist`.
    pub fn is_exist(&self) -> bool {
        self.msg.contains("Chain already exists")
    }
}

/// Async wrapper around one iptables binary (Go: roughly
/// `iptables.IPTables`).
#[derive(Clone, Debug)]
pub struct IPTables {
    path: PathBuf,
    has_wait: bool,
    has_random_fully: bool,
}

/// Go `exec.LookPath` analogue for a bare command name: searches PATH
/// for a file that exists and is executable.
pub fn look_path(cmd: &str) -> Option<PathBuf> {
    // Go also accepts explicit paths; flannel only passes bare names,
    // but mirror the behavior anyway.
    if cmd.contains('/') {
        let p = PathBuf::from(cmd);
        return is_executable(&p).then_some(p);
    }
    let path_var = std::env::var_os("PATH")?;
    std::env::split_paths(&path_var)
        .map(|dir| dir.join(cmd))
        .find(|candidate| is_executable(candidate))
}

fn is_executable(path: &Path) -> bool {
    match std::fs::metadata(path) {
        Ok(meta) => meta.is_file() && meta.permissions().mode() & 0o111 != 0,
        Err(_) => false,
    }
}

/// Go: `extractVersion` (regexp `v([0-9]+)\.([0-9]+)\.([0-9]+)`).
pub fn parse_version(s: &str) -> Result<(u32, u32, u32)> {
    let re = Regex::new(r"v([0-9]+)\.([0-9]+)\.([0-9]+)").expect("valid static regex");
    let caps = re
        .captures(s)
        .ok_or_else(|| anyhow!("no iptables version found in string: {s}"))?;
    Ok((caps[1].parse()?, caps[2].parse()?, caps[3].parse()?))
}

/// `-w` support landed in 1.6.0 (go-iptables' hasWait gate).
fn has_wait_support(v: (u32, u32, u32)) -> bool {
    v >= (1, 6, 0)
}

/// `--random-fully` support landed in 1.6.2. Note: go-iptables v0.8.0
/// may probe support live; the version-based check is the documented
/// approximation and matches when kernel support landed.
fn has_random_fully_support(v: (u32, u32, u32)) -> bool {
    v >= (1, 6, 2)
}

impl IPTables {
    /// Go: `iptables.New` / `NewWithProtocol`.
    pub async fn new(proto: Protocol) -> Result<Self> {
        let cmd = proto.cmd();
        let path = look_path(cmd).ok_or_else(|| anyhow!("iptables binary was not found: {cmd}"))?;
        let out = Command::new(&path)
            .arg("--version")
            .output()
            .await
            .with_context(|| format!("unable to find iptables version: {cmd}"))?;
        if !out.status.success() {
            return Err(anyhow!(
                "unable to find iptables version: {cmd} exited with {}",
                out.status
            ));
        }
        let version = String::from_utf8_lossy(&out.stdout);
        let v = parse_version(&version)?;
        Ok(IPTables {
            path,
            has_wait: has_wait_support(v),
            has_random_fully: has_random_fully_support(v),
        })
    }

    /// Go: `HasRandomFully`.
    pub fn has_random_fully(&self) -> bool {
        self.has_random_fully
    }

    /// Run the binary and return stdout; a non-zero exit becomes an
    /// [`IPTablesError`] carrying stderr. `-w` is passed as the first
    /// argument when supported.
    async fn run(&self, args: &[String]) -> Result<String> {
        let mut full: Vec<String> = Vec::with_capacity(args.len() + 1);
        if self.has_wait {
            full.push("-w".to_string());
        }
        full.extend_from_slice(args);
        let out = Command::new(&self.path)
            .args(&full)
            .output()
            .await
            .with_context(|| format!("failed to run {}", self.path.display()))?;
        if !out.status.success() {
            return Err(anyhow!(IPTablesError {
                msg: String::from_utf8_lossy(&out.stderr).into_owned(),
            }));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    fn table_chain(table: &str, flag: &str, chain: &str) -> Vec<String> {
        vec![
            "-t".to_string(),
            table.to_string(),
            flag.to_string(),
            chain.to_string(),
        ]
    }

    /// Go: `Exists` (`-t <table> -C <chain> <rulespec...>`).
    pub async fn exists(&self, table: &str, chain: &str, rulespec: &[String]) -> Result<bool> {
        let mut args = Self::table_chain(table, "-C", chain);
        args.extend_from_slice(rulespec);
        match self.run(&args).await {
            Ok(_) => Ok(true),
            Err(e) => match e.downcast_ref::<IPTablesError>() {
                Some(ipt_err) if ipt_err.is_not_exist() => Ok(false),
                _ => Err(e),
            },
        }
    }

    /// Go: `NewChain` (`-N`).
    pub async fn new_chain(&self, table: &str, chain: &str) -> Result<()> {
        self.run(&Self::table_chain(table, "-N", chain))
            .await
            .map(|_| ())
    }

    /// Go: `ClearChain`: NewChain; if the chain already exists, flush
    /// it (`-F`) instead.
    pub async fn clear_chain(&self, table: &str, chain: &str) -> Result<()> {
        match self.new_chain(table, chain).await {
            Ok(()) => Ok(()),
            Err(e) => {
                let exists = matches!(e.downcast_ref::<IPTablesError>(), Some(x) if x.is_exist());
                if !exists {
                    return Err(e);
                }
                self.run(&Self::table_chain(table, "-F", chain))
                    .await
                    .map(|_| ())
            }
        }
    }

    /// Go: `ChainExists` (`-t <table> -nL <chain>`). iptables-nft
    /// reports a missing chain as "is incompatible, use 'nft' tool"
    /// (go-iptables issue #96; handled upstream since v0.7.0, and
    /// flannel depends on v0.8.0).
    pub async fn chain_exists(&self, table: &str, chain: &str) -> Result<bool> {
        match self.run(&Self::table_chain(table, "-nL", chain)).await {
            Ok(_) => Ok(true),
            Err(e) => match e.downcast_ref::<IPTablesError>() {
                Some(ipt_err)
                    if ipt_err.is_not_exist()
                        || ipt_err.msg.contains("is incompatible, use 'nft' tool") =>
                {
                    Ok(false)
                }
                _ => Err(e),
            },
        }
    }

    /// Go: `Delete` (`-D`). Flannel itself does not call it; kept for
    /// go-iptables API parity and used by the integration tests to
    /// clean up kernel state.
    #[allow(dead_code)]
    pub async fn delete(&self, table: &str, chain: &str, rulespec: &[String]) -> Result<()> {
        let mut args = Self::table_chain(table, "-D", chain);
        args.extend_from_slice(rulespec);
        self.run(&args).await.map(|_| ())
    }

    /// Go: `ClearAndDeleteChain`: if the chain exists, `-F` then `-X`.
    pub async fn clear_and_delete_chain(&self, table: &str, chain: &str) -> Result<()> {
        if !self.chain_exists(table, chain).await? {
            return Ok(());
        }
        self.run(&Self::table_chain(table, "-F", chain)).await?;
        self.run(&Self::table_chain(table, "-X", chain)).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_version_matches_go_extractor() {
        assert_eq!(
            parse_version("iptables v1.8.7 (nf_tables)").unwrap(),
            (1, 8, 7)
        );
        assert_eq!(parse_version("iptables v1.6.1").unwrap(), (1, 6, 1));
        assert_eq!(
            parse_version("iptables-restore v1.3.66").unwrap(),
            (1, 3, 66)
        );
        assert!(parse_version("no version here").is_err());
    }

    #[test]
    fn support_gates() {
        assert!(!has_wait_support((1, 5, 9)));
        assert!(has_wait_support((1, 6, 0)));
        assert!(has_wait_support((1, 8, 7)));
        assert!(!has_random_fully_support((1, 6, 1)));
        assert!(has_random_fully_support((1, 6, 2)));
        assert!(has_random_fully_support((2, 0, 0)));
    }

    #[test]
    fn error_matching() {
        let bad_rule = IPTablesError {
            msg: "iptables: Bad rule (does a matching rule exist in that chain?).".into(),
        };
        assert!(bad_rule.is_not_exist());
        assert!(!bad_rule.is_exist());
        let no_chain = IPTablesError {
            msg: "ip6tables: No chain/target/match by that name.".into(),
        };
        assert!(no_chain.is_not_exist());
        let exists = IPTablesError {
            msg: "iptables: Chain already exists.".into(),
        };
        assert!(exists.is_exist());
        assert!(!exists.is_not_exist());
        let other = IPTablesError {
            msg: "some other failure".into(),
        };
        assert!(!other.is_exist());
        assert!(!other.is_not_exist());
    }

    #[test]
    fn look_path_finds_sh() {
        assert!(look_path("sh").is_some());
        assert!(look_path("no-such-binary-flannel-rust-test").is_none());
    }

    #[tokio::test]
    async fn new_probes_installed_binary() {
        if look_path("iptables").is_none() {
            return; // nothing to probe on this host
        }
        let ipt = IPTables::new(Protocol::IPv4).await.unwrap();
        // The gates must agree with the installed binary's version.
        let out = std::process::Command::new("iptables")
            .arg("--version")
            .output()
            .unwrap();
        let v = parse_version(&String::from_utf8_lossy(&out.stdout)).unwrap();
        assert_eq!(ipt.has_random_fully(), has_random_fully_support(v));
    }
}
