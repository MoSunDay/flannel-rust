//! CNI skeleton protocol: env parsing, command dispatch, error reporting.
//!
//! Error-code mapping (documented deviation from the CNI spec's
//! per-error codes, kept simple like upstream skel): netconf parse
//! failure → code 1, unknown command → code 4, all other errors →
//! code 100 ("internal"). Errors are printed as CNI error JSON on
//! stdout and the process exits non-zero (1).

use anyhow::{anyhow, Result};
use serde_json::json;

#[cfg(test)]
#[path = "skel_tests.rs"]
mod tests;

/// Inputs collected from the CNI environment (see the CNI spec).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CniArgs {
    pub command: String,
    pub container_id: String,
    pub netns: String,
    pub if_name: String,
    pub args: String,
    pub path: String,
}

/// Collect [`CniArgs`] from the process environment.
pub fn args_from_env() -> Result<CniArgs> {
    args_from(|key| std::env::var(key).ok())
}

/// Testable core of [`args_from_env`]: `lookup` answers env var lookups.
/// CNI_COMMAND is mandatory; the remaining vars default to empty.
pub fn args_from(lookup: impl Fn(&str) -> Option<String>) -> Result<CniArgs> {
    let command = lookup("CNI_COMMAND")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("CNI_COMMAND env var missing"))?;
    Ok(CniArgs {
        command,
        container_id: lookup("CNI_CONTAINERID").unwrap_or_default(),
        netns: lookup("CNI_NETNS").unwrap_or_default(),
        if_name: lookup("CNI_IFNAME").unwrap_or_default(),
        args: lookup("CNI_ARGS").unwrap_or_default(),
        path: lookup("CNI_PATH").unwrap_or_default(),
    })
}

/// Render a CNI error object: `{"cniVersion", "code", "msg", "details"}`.
pub fn error_json(version: &str, code: i32, msg: &str) -> String {
    json!({
        "cniVersion": version,
        "code": code,
        "msg": msg,
        "details": "",
    })
    .to_string()
}

fn conf_version(conf_bytes: &[u8]) -> String {
    crate::netconf::load_flannel_net_conf(conf_bytes)
        .map(|conf| conf.cni_version)
        .unwrap_or_else(|_| "1.0.0".to_string())
}

/// Read the netconf from stdin. VERSION may be called with empty stdin;
/// empty input is treated as `{}`.
fn read_netconf() -> Result<String> {
    let mut buf = String::new();
    use std::io::Read;
    std::io::stdin()
        .read_to_string(&mut buf)
        .map_err(|e| anyhow!("failed to read netconf from stdin: {e}"))?;
    Ok(if buf.trim().is_empty() {
        "{}".to_string()
    } else {
        buf
    })
}

/// CNI entry point: collect env args + stdin netconf, dispatch, print
/// result/error JSON to stdout, return the process exit code.
pub fn run() -> i32 {
    let args = match args_from_env() {
        Ok(args) => args,
        Err(e) => {
            println!("{}", error_json("1.0.0", 1, &format!("{e:#}")));
            return 1;
        }
    };
    let conf = match read_netconf() {
        Ok(conf) => conf,
        Err(e) => {
            println!("{}", error_json("1.0.0", 1, &format!("{e:#}")));
            return 1;
        }
    };
    dispatch(&args, conf.as_bytes())
}

/// Dispatch one CNI command with an already-read netconf and print the
/// result (or CNI error JSON) to stdout; returns the exit code.
pub fn dispatch(args: &CniArgs, conf_bytes: &[u8]) -> i32 {
    // Netconf parse failure: code 1 (VERSION is lenient, see cmd_version).
    if args.command != "VERSION" {
        if let Err(e) = crate::netconf::load_flannel_net_conf(conf_bytes) {
            println!(
                "{}",
                error_json("1.0.0", 1, &format!("invalid flannel netconf: {e:#}"))
            );
            return 1;
        }
    }
    let version = conf_version(conf_bytes);
    let fail = |e: anyhow::Error| -> i32 {
        println!("{}", error_json(&version, 100, &format!("{e:#}")));
        1
    };
    match args.command.as_str() {
        "ADD" => match crate::cmd_add(args, conf_bytes) {
            Ok(result) => {
                println!("{result}");
                0
            }
            Err(e) => fail(e),
        },
        "DEL" => match crate::cmd_del(args, conf_bytes) {
            Ok(()) => 0,
            Err(e) => fail(e),
        },
        "CHECK" => match crate::cmd_check(args, conf_bytes) {
            Ok(()) => 0,
            Err(e) => fail(e),
        },
        "VERSION" => {
            println!("{}", crate::cmd_version(conf_bytes));
            0
        }
        other => {
            println!(
                "{}",
                error_json(&version, 4, &format!("unknown CNI_COMMAND {other}"))
            );
            1
        }
    }
}
