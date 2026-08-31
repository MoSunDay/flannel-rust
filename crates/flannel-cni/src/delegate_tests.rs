//! Tests for plugin discovery and delegate execution. The delegate is a
//! throwaway shell script, so the exec machinery (pipe handling, error
//! capture) is exercised against a real child process without network
//! namespaces or real CNI plugins.

use super::*;
use crate::skel::CniArgs;
use serde_json::json;
use std::os::unix::fs::PermissionsExt;

/// Enough stdin to overflow the 64 KiB pipe buffer, so an inline
/// (write-then-wait) implementation would block.
const CONF_PAD_BYTES: usize = 512 * 1024;

/// Pipe-stdout payload bigger than the pipe buffer, so a plugin that
/// emits it before reading stdin blocks until the caller drains.
const PLUGIN_NOISE_BYTES: &str = "1048576";

fn args(command: &str) -> CniArgs {
    CniArgs {
        command: command.to_string(),
        container_id: "ctest".to_string(),
        netns: "/proc/self/ns/net".to_string(),
        if_name: "eth0".to_string(),
        args: String::new(),
        path: String::new(),
    }
}

/// Install `script` as an executable plugin named `name` in `dir`.
fn write_plugin(dir: &Path, name: &str, body: &str) -> PathBuf {
    let script = dir.join(name);
    std::fs::write(&script, body).unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    script
}

/// A delegate conf padded to `CONF_PAD_BYTES` (like a netconf carrying
/// large user delegate overrides).
fn padded_conf(name: &str) -> Value {
    json!({
        "cniVersion": "0.4.0",
        "name": name,
        "pad": "x".repeat(CONF_PAD_BYTES),
    })
}

#[test]
fn find_plugin_searches_path_in_order() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    // `vlan` exists only in the first dir, `bridge` only in the second.
    let bridge = write_plugin(second.path(), "bridge", "#!/bin/sh\nexit 0\n");
    write_plugin(first.path(), "vlan", "#!/bin/sh\nexit 0\n");
    let both = format!("{}:{}", first.path().display(), second.path().display());
    assert_eq!(find_plugin(&both, &json!("bridge")).unwrap(), bridge);
    // First hit wins when both dirs carry the plugin.
    write_plugin(first.path(), "bridge", "#!/bin/sh\nexit 0\n");
    assert_eq!(
        find_plugin(&both, &json!("bridge")).unwrap(),
        first.path().join("bridge")
    );
    // Missing, non-string, and empty names are errors.
    assert!(find_plugin(&both, &json!("vlan2")).is_err());
    assert!(find_plugin(&both, &json!(42)).is_err());
    assert!(find_plugin(&both, &json!("")).is_err());
}

/// Regression: the plugin writes 1 MiB to stderr *before* reading stdin,
/// and the delegate conf is larger than the pipe buffer. Writing stdin
/// inline before draining stdout/stderr deadlocks; the concurrent
/// writer + `wait_with_output` drain must complete both directions.
#[test]
fn exec_delegate_writes_stdin_while_draining_output() {
    let dir = tempfile::tempdir().unwrap();
    let plugin = write_plugin(
        dir.path(),
        "chatty",
        "#!/bin/sh\n\
         # Fill the output pipes before consuming stdin ...\n\
         head -c PLUGIN_NOISE /dev/zero >&2\n\
         cat > /dev/null\n\
         # ... then answer with a CNI ADD result.\n\
         echo '{\"cniVersion\":\"0.4.0\"}'\n\
         exit 0\n"
            .replace("PLUGIN_NOISE", PLUGIN_NOISE_BYTES)
            .as_str(),
    );
    let conf = padded_conf("chatty");
    let result = delegate_add(&conf, &plugin, &args("ADD")).unwrap();
    assert_eq!(result["cniVersion"], json!("0.4.0"));
}

/// Same shape on DEL, with the noise on stdout: DEL ignores stdout, so
/// the drain must still unblock the plugin (and the call must succeed).
#[test]
fn delegate_del_drains_stdout_while_writing_stdin() {
    let dir = tempfile::tempdir().unwrap();
    let plugin = write_plugin(
        dir.path(),
        "chatty",
        "#!/bin/sh\n\
         head -c PLUGIN_NOISE /dev/zero\n\
         cat > /dev/null\n\
         exit 0\n"
            .replace("PLUGIN_NOISE", PLUGIN_NOISE_BYTES)
            .as_str(),
    );
    delegate_del(&padded_conf("chatty"), &plugin, &args("DEL")).unwrap();
}

/// A plugin that consumes the delegate config and then fails (CNI error
/// JSON on stdout, nonzero exit) is an error naming the plugin and its
/// message -- the captured stdout/stderr drive the error text.
#[test]
fn delegate_failure_is_reported_with_plugin_message() {
    let dir = tempfile::tempdir().unwrap();
    let plugin = write_plugin(
        dir.path(),
        "failing",
        "#!/bin/sh\n\
         cat > /dev/null\n\
         echo '{\"code\":100,\"msg\":\"boom\"}'\n\
         echo 'teardown went wrong' >&2\n\
         exit 1\n",
    );
    let err = delegate_del(&padded_conf("failing"), &plugin, &args("DEL")).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("boom"), "unexpected error: {msg}");
    assert!(msg.contains("failing"), "unexpected error: {msg}");
    assert!(
        msg.contains("teardown went wrong"),
        "unexpected error: {msg}"
    );
}
