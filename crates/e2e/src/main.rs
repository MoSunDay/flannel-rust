//! `flannel-e2e`: full closed-loop e2e harness.
//!
//! Every scenario boots the *real* flanneld (in-process, inside a scratch
//! netns) against a mock kube apiserver with a working watch, and drives
//! the *real* `flannel` CNI binary with real bridge + host-local plugins.
//! Capabilities covered: all 9 backends (7 real closed loops, ipsec /
//! tencent-vpc deliberate skips with reasons), traffic manager (iptables
//! + nftables), healthz, --version, CNI edge cases, lease lifecycle.
//!
//! Exit code 0 = all scenarios pass (skips tolerated but reported).

mod apiserver;
mod cni;
mod daemonctl;
mod netutil;
mod scenarios;

use anyhow::{anyhow, Context, Result};
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::time::Instant;

/// Scenario verdict: hard failure or a deliberate skip (with reason).
#[derive(Debug)]
pub enum E2EError {
    Fail(anyhow::Error),
    Skip(String),
}

impl From<anyhow::Error> for E2EError {
    fn from(e: anyhow::Error) -> Self {
        Self::Fail(e)
    }
}

impl From<std::io::Error> for E2EError {
    fn from(e: std::io::Error) -> Self {
        Self::Fail(e.into())
    }
}

impl E2EError {
    pub fn skip(reason: impl Into<String>) -> Self {
        Self::Skip(reason.into())
    }
}

pub type ScenarioFn = fn() -> Pin<Box<dyn Future<Output = Result<(), E2EError>> + Send>>;

pub struct Scenario {
    pub name: &'static str,
    pub desc: &'static str,
    pub run: ScenarioFn,
}

/// Resolve the sibling workspace binaries (same target dir as this bin).
pub mod bins {
    use super::*;
    pub fn flannel() -> Result<PathBuf> {
        sibling("flannel")
    }
    pub fn flanneld() -> Result<PathBuf> {
        sibling("flanneld")
    }
    fn sibling(name: &str) -> Result<PathBuf> {
        let dir = std::env::current_exe()
            .context("current_exe")?
            .parent()
            .context("exe parent")?
            .to_path_buf();
        let bin = dir.join(name);
        if bin.exists() {
            Ok(bin)
        } else {
            Err(anyhow!(
                "binary {name} not found next to the harness at {} \
                 (run `cargo build --workspace` first)",
                dir.display()
            ))
        }
    }
}

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = std::env::var("RUST_LOG")
        .map(EnvFilter::new)
        .unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}

fn print_probes() {
    println!("== environment probes ==");
    let euid = unsafe { libc::geteuid() };
    println!("  euid: {euid} (root required)");
    let path =
        std::env::var("CNI_PLUGINS_TGZ").unwrap_or_else(|_| netutil::DEFAULT_PLUGIN_TGZ.into());
    println!(
        "  cni plugins tgz: {path} -> {}",
        std::path::Path::new(&path).exists()
    );
    for (name, cmd, args) in [
        ("ping", "ping", &["-c", "1", "-W", "1", "127.0.0.1"][..]),
        ("iptables", "iptables", &["--version"][..]),
        ("nft", "nft", &["--version"][..]),
        ("tar", "tar", &["--version"][..]),
    ] {
        let ok = std::process::Command::new(cmd)
            .args(args)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        println!("  {name}: {ok}");
    }
    println!();
}

#[tokio::main]
async fn main() {
    init_tracing();
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--list") {
        for s in scenarios::all() {
            println!("{:<28} {}", s.name, s.desc);
        }
        return;
    }
    print_probes();

    let all = scenarios::all();
    let selected: Vec<&Scenario> = if args.is_empty() {
        all.iter().collect()
    } else {
        args.iter()
            .map(|name| {
                all.iter()
                    .find(|s| s.name == name)
                    .unwrap_or_else(|| panic!("unknown scenario: {name} (see --list)"))
            })
            .collect()
    };

    let mut passed = 0;
    let mut failed = 0;
    let mut skipped = 0;
    for s in selected {
        // host-local IPAM state is host-mount-ns global; a failed
        // scenario skips DEL and leaks allocations that break the next
        // scenario's CNI ADD -- clean before every scenario.
        if let Err(e) = cni::clear_ipam_state() {
            eprintln!("  warn: ipam cleanup failed: {e:#}");
        }
        let t0 = Instant::now();
        println!("== scenario: {} ({}) ==", s.name, s.desc);
        let outcome = match tokio::spawn((s.run)()).await {
            Ok(Ok(())) => {
                passed += 1;
                "PASS".to_string()
            }
            Ok(Err(E2EError::Skip(reason))) => {
                skipped += 1;
                println!("  SKIP: {reason}");
                "SKIP".to_string()
            }
            Ok(Err(E2EError::Fail(e))) => {
                failed += 1;
                eprintln!("  FAIL: {e:#}");
                "FAIL".to_string()
            }
            Err(join) => {
                failed += 1;
                eprintln!("  PANIC: {join}");
                "FAIL".to_string()
            }
        };
        println!(
            "== {} {outcome} in {:.1}s ==",
            s.name,
            t0.elapsed().as_secs_f64()
        );
        println!();
    }

    println!("== summary: {passed} passed, {failed} failed, {skipped} skipped ==");
    std::process::exit(if failed == 0 { 0 } else { 1 });
}

/// Async helper: run a blocking closure off-runtime (daemon threads are
/// unaffected either way, but child processes must not stall the
/// apiserver task).
pub async fn blocking<T, F>(f: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .context("blocking task panicked")?
}
