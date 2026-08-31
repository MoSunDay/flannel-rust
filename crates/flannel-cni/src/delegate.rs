//! Delegate plugin discovery and execution (exec-style CNI invocation).
//!
//! The flannel meta-plugin delegates ADD/DEL/CHECK to a real CNI plugin
//! (bridge by default): find the binary on `CNI_PATH`, run it with the
//! CNI env vars and the delegate config on stdin, parse its stdout.

use crate::skel::CniArgs;
use anyhow::{anyhow, bail, Context, Result};
use serde_json::Value;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

#[cfg(test)]
#[path = "delegate_tests.rs"]
mod tests;

/// Find the delegate plugin binary named `plugin_type` by searching the
/// `:`-separated dirs of CNI_PATH; returns the first existing regular
/// file (upstream libcni `invoke.FindInPath` behavior).
pub fn find_plugin(path: &str, plugin_type: &Value) -> Result<PathBuf> {
    let name = plugin_type
        .as_str()
        .ok_or_else(|| anyhow!("delegate config has no string 'type' field"))?;
    if name.is_empty() {
        bail!("delegate config has an empty 'type' field");
    }
    path.split(':')
        .filter(|dir| !dir.is_empty())
        .map(|dir| Path::new(dir).join(name))
        .find(|candidate| candidate.is_file())
        .ok_or_else(|| anyhow!("failed to find plugin {name} in CNI_PATH {path}"))
}

/// CNI ADD through the delegate plugin; returns the parsed result JSON.
pub fn delegate_add(conf: &Value, plugin: &Path, args: &CniArgs) -> Result<Value> {
    let out = exec_delegate(plugin, "ADD", args, conf)?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    if !out.status.success() {
        return Err(delegate_error("ADD", plugin, &out));
    }
    serde_json::from_str(&stdout)
        .with_context(|| format!("{}: unparseable ADD result: {stdout}", plugin.display()))
}

/// CNI DEL through the delegate plugin. DEL is idempotent; [`crate::cmd_del`]
/// swallows any error returned here.
pub fn delegate_del(conf: &Value, plugin: &Path, args: &CniArgs) -> Result<()> {
    let out = exec_delegate(plugin, "DEL", args, conf)?;
    if out.status.success() {
        return Ok(());
    }
    Err(delegate_error("DEL", plugin, &out))
}

/// CNI CHECK through the delegate plugin. A successful CHECK may print a
/// result JSON; it is ignored.
pub fn delegate_check(conf: &Value, plugin: &Path, args: &CniArgs) -> Result<()> {
    let out = exec_delegate(plugin, "CHECK", args, conf)?;
    if out.status.success() {
        return Ok(());
    }
    Err(delegate_error("CHECK", plugin, &out))
}

/// Run the plugin binary with the CNI env vars and `conf` on stdin.
///
/// The config is written from a helper thread while
/// [`Child::wait_with_output`] concurrently drains stdout/stderr: writing
/// stdin inline before waiting deadlocks against a delegate that fills
/// its output pipes first (its writes block, so it never reads our
/// stdin, so our write blocks too).
fn exec_delegate(plugin: &Path, command: &str, args: &CniArgs, conf: &Value) -> Result<Output> {
    let conf_bytes = serde_json::to_vec(conf).context("failed to serialize delegate config")?;
    let mut child = Command::new(plugin)
        .env("CNI_COMMAND", command)
        .env("CNI_CONTAINERID", &args.container_id)
        .env("CNI_NETNS", &args.netns)
        .env("CNI_IFNAME", &args.if_name)
        .env("CNI_ARGS", &args.args)
        .env("CNI_PATH", &args.path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to spawn delegate plugin {}", plugin.display()))?;
    // ChildStdin is Send; the thread owns it, so dropping it at the end
    // also closes the pipe (the plugin sees EOF, as with inline writing).
    let writer = child
        .stdin
        .take()
        .map(|mut stdin| std::thread::spawn(move || stdin.write_all(&conf_bytes)));
    let out = child
        .wait_with_output()
        .context("failed to wait for delegate plugin")?;
    if let Some(writer) = writer {
        match writer.join() {
            Ok(Ok(())) => {}
            // Same error an inline write would have produced (e.g. the
            // plugin exited before reading all of stdin).
            Ok(Err(e)) => return Err(e).context("failed to write delegate config to plugin stdin"),
            Err(_) => bail!("delegate stdin writer thread panicked"),
        }
    }
    Ok(out)
}

/// Build the error for a failed delegate run: when stdout parses as a CNI
/// error object `{code, msg}` report those, otherwise report status plus
/// stdout/stderr.
fn delegate_error(op: &str, plugin: &Path, out: &Output) -> anyhow::Error {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    if let Ok(value) = serde_json::from_str::<Value>(&stdout) {
        if let (Some(code), Some(msg)) = (
            value.get("code").and_then(Value::as_i64),
            value.get("msg").and_then(Value::as_str),
        ) {
            return anyhow!(
                "delegate {op} via {} failed: code {code}: {msg} (stderr: {})",
                plugin.display(),
                stderr.trim()
            );
        }
    }
    anyhow!(
        "delegate {op} via {} exited with {}: stdout: {}; stderr: {}",
        plugin.display(),
        out.status,
        stdout.trim(),
        stderr.trim()
    )
}
