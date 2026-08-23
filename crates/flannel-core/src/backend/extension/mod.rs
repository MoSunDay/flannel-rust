//! Port of pkg/backend/extension (upstream cdf76059): the extension
//! backend runs user-supplied commands for subnet management. No netlink
//! is involved.
//!
//! - mod.rs: `ExtensionConfig`, env-map/expand helpers, `run_cmd`,
//!   `register_network` (extension.go).
//! - network.rs: network struct, `Run`, `handleSubnetEvents`
//!   (extension_network.go).
//!
//! Go deviations:
//! - Go's `ExtensionBackend` carries an unused `networks` map; dropped.
//! - Go's `MTU()` reads `n.extIface.Iface.MTU` on demand; the Rust
//!   `ExternalInterface` has no MTU field, so the MTU is fetched via
//!   netlink once at register time (same approach as the vxlan port) and
//!   stored on the network.
//! - `run_cmd` with an empty program name returns `Ok("")`; Go would
//!   return an `exec: no command` error, which its callers can never hit
//!   (they index `strings.Fields(cmd)[0]` and would panic first on a
//!   whitespace-only command). Whitespace-only commands are likewise
//!   skipped here instead of panicking.
//! - Go's `CombinedOutput` interleaves stdout/stderr in arrival order;
//!   this port concatenates stdout then stderr.
//! - Unset `PublicIPv6` prints as the literal `<nil>` (Go's nil net.IP
//!   formatting, kept for parity). Unset `PublicIP` prints `0.0.0.0`
//!   where Go would print `<nil>` (the Rust `IP4` is non-optional).

mod network;

#[cfg(test)]
#[path = "extension_tests.rs"]
mod extension_tests;

pub use network::ExtensionNetwork;

use crate::backend::common::ExternalInterface;
use crate::backend::traits::{Backend, Network};
use crate::ip::iface::{get_link_mtu, Netlink};
use crate::ip::{IP4, IP6};
use crate::lease::LeaseAttrs;
use crate::subnet::config::Config;
use crate::subnet::manager::{Ctx, Manager};
use anyhow::anyhow;
use futures::future::BoxFuture;
use serde::Deserialize;
use serde_json::value::RawValue;
use std::collections::HashMap;
use std::io::Write;
use std::net::IpAddr;
use std::process::{Command, Stdio};
use std::sync::Arc;
use tracing::info;

/// Go `backendType`.
pub const BACKEND_TYPE: &str = "extension";

/// The four optional commands of the extension backend (Go: the anonymous
/// struct in `RegisterNetwork`; Go JSON field names).
#[derive(Clone, Debug, Default, Deserialize)]
pub struct ExtensionConfig {
    #[serde(rename = "PreStartupCommand", default)]
    pub pre_startup_command: Option<String>,
    #[serde(rename = "PostStartupCommand", default)]
    pub post_startup_command: Option<String>,
    #[serde(rename = "SubnetAddCommand", default)]
    pub subnet_add_command: Option<String>,
    #[serde(rename = "SubnetRemoveCommand", default)]
    pub subnet_remove_command: Option<String>,
}

/// Go: `ExtensionBackend` (the unused `networks` map is dropped).
pub struct ExtensionBackend {
    sm: Arc<dyn Manager>,
    ei: Arc<ExternalInterface>,
}

/// Port of Go `New` + the `backend.Register("extension", New)` shape.
pub fn new_backend(
    sm: Arc<dyn Manager>,
    ei: Arc<ExternalInterface>,
) -> anyhow::Result<Box<dyn Backend>> {
    Ok(Box::new(ExtensionBackend { sm, ei }))
}

impl Backend for ExtensionBackend {
    /// Go: `RegisterNetwork`. Parses the config, runs the pre-startup
    /// command (its JSON-encoded output becomes the lease BackendData),
    /// acquires the lease, then runs the post-startup command.
    fn register_network<'a>(
        &'a self,
        ctx: Ctx<'a>,
        config: &'a Config,
    ) -> BoxFuture<'a, anyhow::Result<Box<dyn Network>>> {
        Box::pin(async move {
            // Go: `if len(config.Backend) > 0 { ... }`.
            let cfg = match config.backend.as_deref() {
                Some(raw) if raw.get().trim() == "null" => ExtensionConfig::default(),
                Some(raw) => serde_json::from_str(raw.get())
                    .map_err(|e| anyhow!("error decoding backend config: {e}"))?,
                None => ExtensionConfig::default(),
            };

            // Go's MTU() reads extIface.Iface.MTU on demand; snapshot it
            // here instead (see module docs).
            let nl = Netlink::new().await?;
            let ext_mtu = get_link_mtu(&nl, self.ei.iface_index).await?;

            let mut backend_data: Option<Box<RawValue>> = None;
            let pre_cmd = cfg.pre_startup_command.as_deref().unwrap_or_default();
            match split_command(pre_cmd) {
                Some(parts) => {
                    // Go: runCmd([]string{}, "", ...) -- no extra env.
                    let out = run_cmd(&[], "", parts[0], &parts[1..])
                        .map_err(|e| anyhow!("failed to run command: {pre_cmd} Err: {e}"))?;
                    info!("Ran command: {pre_cmd}\n Output: {out}");
                    // Go: data = json.Marshal(cmd_output) -- the OUTPUT
                    // string is JSON-encoded and stored as BackendData.
                    backend_data = Some(RawValue::from_string(serde_json::to_string(&out)?)?);
                }
                None => info!("No pre startup command configured - skipping"),
            }

            let mut attrs = LeaseAttrs {
                backend_type: BACKEND_TYPE.to_string(),
                backend_data,
                ..Default::default()
            };
            // Go: ip.FromIP / ip.FromIP6 (v4/v6 only, respectively).
            if let Some(IpAddr::V4(ip)) = self.ei.iface_addr {
                attrs.public_ip = IP4::from_bytes(ip.octets());
            }
            if let Some(IpAddr::V6(ip)) = self.ei.iface_v6_addr {
                attrs.public_ipv6 = Some(IP6::from_std(ip));
            }

            let lease = match self.sm.acquire_lease(ctx, &attrs).await {
                Ok(l) => l,
                // Go: context.Canceled / DeadlineExceeded pass through.
                Err(e) if ctx.is_cancelled() => return Err(e),
                Err(e) => return Err(anyhow!("failed to acquire lease: {e}")),
            };

            match cfg.post_startup_command.as_deref().and_then(split_command) {
                Some(parts) => {
                    let public_ipv6 = attrs
                        .public_ipv6
                        .map(|ip| ip.to_string())
                        .unwrap_or_else(|| "<nil>".to_string());
                    let env = vec![
                        format!("NETWORK={}", config.network),
                        format!("SUBNET={}", lease.subnet),
                        format!("IPV6SUBNET={}", lease.ipv6_subnet),
                        format!("PUBLIC_IP={}", attrs.public_ip),
                        format!("PUBLIC_IPV6={public_ipv6}"),
                    ];
                    let out = run_cmd(&env, "", parts[0], &parts[1..]).map_err(|e| {
                        anyhow!("failed to run command: {} Err: {e}", parts.join(" "))
                    })?;
                    info!("Ran command: {}\n Output: {out}", parts.join(" "));
                }
                None => info!("No post startup command configured - skipping"),
            }

            Ok(
                Box::new(ExtensionNetwork::new(self.sm.clone(), lease, ext_mtu, cfg))
                    as Box<dyn Network>,
            )
        })
    }
}

/// Go `strings.Fields` split; `None` when there is nothing to run. Go
/// panics on a whitespace-only command (empty `Fields` result indexed at
/// 0); the port skips it instead (see module docs).
fn split_command(cmd: &str) -> Option<Vec<&str>> {
    let mut fields = cmd.split_whitespace();
    let first = fields.next()?;
    Some(std::iter::once(first).chain(fields).collect())
}

/// Go: `buildEnvMap` -- os.Environ() with the given "K=V" pairs overlaid
/// (later wins; a pair without '=' maps to the empty string).
fn build_env_map(env: &[String]) -> HashMap<String, String> {
    let mut m: HashMap<String, String> = std::env::vars().collect();
    for e in env {
        let (k, v) = e.split_once('=').unwrap_or((e.as_str(), ""));
        m.insert(k.to_string(), v.to_string());
    }
    m
}

/// Go: `isShellSpecialVar` (os/env.go).
fn is_shell_special_var(c: u8) -> bool {
    matches!(
        c,
        b'*' | b'#' | b'$' | b'@' | b'!' | b'?' | b'-' | b'0'..=b'9'
    )
}

/// Go: `isAlphaNum` (os/env.go).
fn is_alpha_num(c: u8) -> bool {
    c == b'_' || c.is_ascii_alphanumeric()
}

/// Go: `getShellName` (os/env.go); returns (name, consumed bytes).
/// Caller guarantees `s` is non-empty.
fn get_shell_name(s: &[u8]) -> (&[u8], usize) {
    match s[0] {
        b'{' => {
            if s.len() > 2 && is_shell_special_var(s[1]) && s[2] == b'}' {
                return (&s[1..2], 3);
            }
            for (i, &c) in s.iter().enumerate().skip(1) {
                if c == b'}' {
                    return if i == 1 {
                        (&[], 2) // bad syntax; Go eats "${}"
                    } else {
                        (&s[1..i], i + 1)
                    };
                }
            }
            (&[], 1) // bad syntax; Go eats "${"
        }
        c if is_shell_special_var(c) => (&s[..1], 1),
        c if is_alpha_num(c) => {
            let mut i = 0;
            while i < s.len() && is_alpha_num(s[i]) {
                i += 1;
            }
            (&s[..i], i)
        }
        _ => (&[], 0),
    }
}

/// Port of Go `os.Expand` with the mapping `map.get(name).unwrap_or("")`:
/// `$VAR` and `${VAR}` are substituted from `map`, missing keys become "".
/// Go's exact syntax rules are kept:
/// - `$` + shell special char (`*#$@!?-`, digits) expands that one-char
///   name, so `$$` expands name "$" and becomes "" (flannel's env maps
///   missing keys to "");
/// - `$name` is the longest run of `[A-Za-z0-9_]`;
/// - `${name}` runs to the closing brace; `${}` and an unclosed `${` are
///   eaten as invalid syntax;
/// - a `$` followed by anything else stays untouched (`$.`, trailing `$`).
fn expand(s: &str, map: &HashMap<String, String>) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    let mut j = 0;
    while j < b.len() {
        if b[j] == b'$' && j + 1 < b.len() {
            out.extend_from_slice(&b[i..j]);
            let (name, w) = get_shell_name(&b[j + 1..]);
            if !name.is_empty() {
                let key = String::from_utf8_lossy(name);
                let val = map.get(key.as_ref()).map(String::as_str).unwrap_or("");
                out.extend_from_slice(val.as_bytes());
            } else if w == 0 {
                // Valid syntax, but $ was not followed by a name: Go
                // leaves the dollar character untouched.
                out.push(b[j]);
            }
            // else: invalid syntax; Go eats the characters.
            j += w;
            i = j + 1;
        }
        j += 1;
    }
    out.extend_from_slice(&b[i..]);
    // `s` is valid UTF-8 and only ASCII-boundary slices plus map values
    // (valid UTF-8) are spliced in; lossy for safety.
    String::from_utf8_lossy(&out).into_owned()
}

/// Go: `expandVars`.
fn expand_vars<'a>(
    map: &HashMap<String, String>,
    args: impl IntoIterator<Item = &'a str>,
) -> Vec<String> {
    args.into_iter().map(|a| expand(a, map)).collect()
}

/// Go: `runCmd` -- runs `program args...` with `env` ("K=V" pairs)
/// overlaid on the process environment, feeds it `stdin` + "\n" on stdin
/// and returns the combined stdout+stderr, whitespace-trimmed.
///
/// `$VAR`/`${VAR}` in the program name and args are expanded from the
/// merged env before exec (Go: `expandVars`; exec has no shell, so
/// expanded values are passed as literal arguments). An empty program
/// name returns `Ok("")` (see module docs for the Go difference).
///
/// On a non-zero exit the error carries Go's final message shape once
/// callers wrap it with "failed to run command: <cmd> Err: ...":
/// "exit status N Output: <trimmed output>".
fn run_cmd(env: &[String], stdin: &str, program: &str, args: &[&str]) -> anyhow::Result<String> {
    let env_map = build_env_map(env);
    let expanded = expand_vars(
        &env_map,
        std::iter::once(program).chain(args.iter().copied()),
    );
    let name = expanded[0].as_str();

    if name.is_empty() {
        return Ok(String::new());
    }

    let mut cmd = Command::new(name);
    cmd.args(expanded[1..].iter().map(String::as_str));
    // Go: cmd.Env = append(os.Environ(), env...) with last-wins dedupe;
    // the merged map is exactly that.
    cmd.env_clear();
    for (k, v) in &env_map {
        cmd.env(k, v);
    }
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = cmd.spawn().map_err(|e| spawn_err(name, e))?;
    if let Some(mut si) = child.stdin.take() {
        // Go: io.WriteString(pipe, stdin), io.WriteString(pipe, "\n"),
        // then Close.
        si.write_all(stdin.as_bytes())?;
        si.write_all(b"\n")?;
    }
    let out = child.wait_with_output()?;

    // Go's CombinedOutput interleaves the two streams; this port
    // concatenates stdout then stderr (see module docs).
    let mut combined = out.stdout;
    combined.extend_from_slice(&out.stderr);
    let combined = String::from_utf8_lossy(&combined).trim().to_string();

    match out.status.code() {
        Some(0) => Ok(combined),
        Some(code) => Err(anyhow!("exit status {code} Output: {combined}")),
        None => Err(anyhow!("process terminated by signal Output: {combined}")),
    }
}

/// Go shapes a missing-executable failure as
/// `exec: "name": executable file not found in $PATH`.
fn spawn_err(name: &str, e: std::io::Error) -> anyhow::Error {
    if e.kind() == std::io::ErrorKind::NotFound {
        anyhow!("exec: \"{name}\": executable file not found in $PATH")
    } else {
        anyhow!("{e}")
    }
}
