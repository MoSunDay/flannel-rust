//! Tests for the extension backend: expand/build_env_map/run_cmd unit
//! tests plus a full register_network + run flow against an in-memory
//! Manager. Hermetic: unique tempfile paths everywhere.
//!
//! Note: run_cmd expands `$VAR`/`${VAR}` in program name AND args from
//! the merged env (Go does the same -- no shell), so `sh -c` scripts
//! passed as args cannot use their own shell variables; the full-flow
//! test uses script files instead.
use super::*;
use crate::backend::common::ExternalInterface;

use crate::ip::{IP4Net, IP6Net, IP4};
use crate::lease::{Event, EventType, Lease, LeaseAttrs, LeaseWatchResult};
use crate::subnet::config::Config;
use crate::subnet::manager::{Ctx, Manager};
use futures::future::BoxFuture;
use serde_json::value::RawValue;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
fn env_map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}
#[test]
fn expand_var_forms() {
    let m = env_map(&[("SUBNET", "10.1.2.3/24"), ("GW", "10.1.2.1")]);
    assert_eq!(expand("$SUBNET", &m), "10.1.2.3/24");
    assert_eq!(expand("${SUBNET}", &m), "10.1.2.3/24");
    assert_eq!(
        expand("add $SUBNET via ${GW} done", &m),
        "add 10.1.2.3/24 via 10.1.2.1 done"
    );
    // Longest alphanumeric run is the name: SUBNETx is missing -> "".
    assert_eq!(expand("$SUBNETx", &m), "");
    assert_eq!(
        expand_vars(&m, ["$A", "x${SUBNET}y"]),
        vec!["", "x10.1.2.3/24y"]
    );
}
#[test]
fn expand_missing_and_dollar_rules() {
    let m = env_map(&[]);
    assert_eq!(expand("$NOPE", &m), ""); // missing var -> ""
    assert_eq!(expand("$$", &m), ""); // name "$" missing -> ""
    assert_eq!(expand("a$$b", &m), "ab");
    assert_eq!(expand("$", &m), "$"); // trailing $ left untouched
    assert_eq!(expand("$.", &m), "$."); // $ + non-name char untouched
    assert_eq!(expand("${}", &m), ""); // bad syntax eaten
    assert_eq!(expand("${unclosed", &m), "unclosed"); // bad syntax eaten
    assert_eq!(expand("${NOPE}", &m), "");
    assert_eq!(expand("$1x", &m), "x"); // $1 is a one-char special name
    assert_eq!(expand("$_", &m), ""); // "_" starts a name, missing -> ""
}
#[test]
fn build_env_map_overlay_and_defaults() {
    std::env::set_var("FLANNEL_EXT_TEST_KEY", "base");
    let m = build_env_map(&[
        "FLANNEL_EXT_TEST_KEY=override".to_string(),
        "FLANNEL_EXT_TEST_KEY2".to_string(), // no '=' -> value ""
    ]);
    assert_eq!(m["FLANNEL_EXT_TEST_KEY"], "override"); // later wins
    assert_eq!(m["FLANNEL_EXT_TEST_KEY2"], ""); // no '=' -> ""
    assert!(m.contains_key("PATH")); // process env is included
}
#[test]
fn run_cmd_behavior() {
    // stdout capture.
    assert_eq!(run_cmd(&[], "", "/bin/echo", &["hello"]).unwrap(), "hello");
    // combined stdout+stderr.
    let out = run_cmd(&[], "", "/bin/sh", &["-c", "echo out; echo err 1>&2"]).unwrap();
    assert!(out.contains("out") && out.contains("err"), "got: {out:?}");
    // stdin delivery ("abc\n" echoed by cat; trim leaves "abc") and the
    // appended newline (wc -l counts one line).
    assert_eq!(run_cmd(&[], "abc", "/bin/cat", &[]).unwrap(), "abc");
    assert_eq!(
        run_cmd(&[], "abc", "/bin/sh", &["-c", "wc -l"]).unwrap(),
        "1"
    );
    // env var delivery and arg expansion before exec (/bin/echo prints
    // its args verbatim -- no shell involved).
    let env = ["SUBNET=10.1.2.3/24".to_string()];
    let out = run_cmd(&env, "", "/bin/sh", &["-c", "echo $SUBNET"]).unwrap();
    assert_eq!(out, "10.1.2.3/24");
    let out = run_cmd(&env, "", "/bin/echo", &["$SUBNET", "tail"]).unwrap();
    assert_eq!(out, "10.1.2.3/24 tail");
    // non-zero exit errors carry the output; empty program skips.
    let err = run_cmd(&[], "", "/bin/sh", &["-c", "echo oops 1>&2; exit 3"]).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("exit status 3") && msg.contains("oops"),
        "got: {msg}"
    );
    assert_eq!(run_cmd(&[], "", "", &[]).unwrap(), "");
    assert_eq!(run_cmd(&[], "stdin", "", &["arg"]).unwrap(), "");
}
static COUNTER: AtomicU32 = AtomicU32::new(0);
fn tmp_path(tag: &str) -> std::path::PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    std::env::temp_dir().join(format!("flannel-ext-test-{}-{tag}-{n}", std::process::id()))
}

/// Write an executable shell script to a unique path (script files let
/// the test use `$VAR` without colliding with run_cmd's own expansion).
fn write_exec_script(body: &str) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = tmp_path("script");
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

/// Polls `run` (it drives the watch loop) until `path` contains
/// `needle`; returns the file contents.
async fn wait_with_run<F: std::future::Future<Output = ()>>(
    mut run: std::pin::Pin<&mut F>,
    path: &std::path::Path,
    needle: &str,
) -> String {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let c = std::fs::read_to_string(path).unwrap_or_default();
        if c.contains(needle) {
            return c;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {needle:?}"
        );
        tokio::select! {
            () = &mut run => panic!("run() ended before {needle:?} appeared"),
            () = tokio::time::sleep(Duration::from_millis(25)) => {}
        }
    }
}

/// In-memory Manager: fixed lease, records acquire attrs, replays batches.
struct MockManager {
    config: Config,
    lease: Lease,
    attrs_seen: Mutex<Option<LeaseAttrs>>,
    batches: Vec<Vec<LeaseWatchResult>>,
}
impl Manager for MockManager {
    fn get_network_config<'a>(&'a self, _ctx: Ctx<'a>) -> BoxFuture<'a, anyhow::Result<Config>> {
        Box::pin(async move { Ok(self.config.clone()) })
    }

    fn handle_subnet_file<'a>(
        &'a self,
        _path: &'a str,
        _config: &'a Config,
        _ip_masq: bool,
        _sn: IP4Net,
        _ipv6sn: IP6Net,
        _mtu: u32,
    ) -> BoxFuture<'a, anyhow::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn acquire_lease<'a>(
        &'a self,
        _ctx: Ctx<'a>,
        attrs: &'a LeaseAttrs,
    ) -> BoxFuture<'a, anyhow::Result<Lease>> {
        Box::pin(async move {
            *self.attrs_seen.lock().unwrap() = Some(attrs.clone());
            Ok(self.lease.clone())
        })
    }

    fn renew_lease<'a>(
        &'a self,
        _ctx: Ctx<'a>,
        lease: &'a Lease,
    ) -> BoxFuture<'a, anyhow::Result<Lease>> {
        Box::pin(async move { Ok(lease.clone()) })
    }

    fn watch_lease<'a>(
        &'a self,
        ctx: Ctx<'a>,
        _sn: IP4Net,
        _sn6: IP6Net,
        _tx: mpsc::Sender<Vec<LeaseWatchResult>>,
    ) -> BoxFuture<'a, anyhow::Result<()>> {
        Box::pin(async move {
            ctx.cancelled().await;
            Ok(())
        })
    }

    fn watch_leases<'a>(
        &'a self,
        ctx: Ctx<'a>,
        tx: mpsc::Sender<Vec<LeaseWatchResult>>,
    ) -> BoxFuture<'a, anyhow::Result<()>> {
        let batches = self.batches.clone();
        Box::pin(async move {
            for b in batches {
                if tx.send(b).await.is_err() {
                    break;
                }
            }
            ctx.cancelled().await;
            Ok(())
        })
    }

    fn complete_lease<'a>(
        &'a self,
        _ctx: Ctx<'a>,
        _lease: &'a Lease,
    ) -> BoxFuture<'a, anyhow::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn get_stored_mac_addresses<'a>(&'a self, _ctx: Ctx<'a>) -> BoxFuture<'a, (String, String)> {
        Box::pin(async { (String::new(), String::new()) })
    }

    fn get_stored_public_ip<'a>(&'a self, _ctx: Ctx<'a>) -> BoxFuture<'a, (String, String)> {
        Box::pin(async { (String::new(), String::new()) })
    }

    fn name(&self) -> String {
        "Mock Subnet Manager".to_string()
    }
}
fn test_lease(octet_b: u8) -> Lease {
    Lease {
        enable_ipv4: true,
        enable_ipv6: false,
        subnet: IP4Net {
            ip: IP4::from_bytes([10, 1, octet_b, 0]),
            prefix_len: 24,
        },
        ipv6_subnet: IP6Net::default(),
        attrs: LeaseAttrs::default(),
        expiration: SystemTime::now() + Duration::from_secs(3600),
        asof: 0,
    }
}
fn event_lease(octet_b: u8, backend_type: &str, data: &str, public_ip: [u8; 4]) -> Lease {
    let mut l = test_lease(octet_b);
    l.attrs = LeaseAttrs {
        public_ip: IP4::from_bytes(public_ip),
        backend_type: backend_type.to_string(),
        backend_data: Some(RawValue::from_string(data.to_string()).unwrap()),
        ..Default::default()
    };
    l
}
fn mock_and_ei(batches: Vec<Vec<LeaseWatchResult>>, config: Config) -> Arc<MockManager> {
    Arc::new(MockManager {
        config,
        lease: test_lease(2),
        attrs_seen: Mutex::new(None),
        batches,
    })
}
/// Loopback iface: always present, so the register-time MTU fetch works
/// without a netns.
fn loopback_ei(addr: Option<&str>) -> Arc<ExternalInterface> {
    Arc::new(ExternalInterface {
        iface_index: 1,
        iface_name: "lo".to_string(),
        iface_addr: addr.map(|a| a.parse().unwrap()),
        ..Default::default()
    })
}
#[tokio::test]
async fn register_and_run_full_flow() {
    let post_file = tmp_path("post");
    let add_file = tmp_path("add");
    let rm_file = tmp_path("rm");
    let post_script = write_exec_script(&format!(
        "echo NET=$NETWORK SUBNET=$SUBNET IPV6SUBNET=$IPV6SUBNET PUBLIC_IP=$PUBLIC_IP PUBLIC_IPV6=$PUBLIC_IPV6 > {}",
        post_file.display()
    ));
    let add_script = write_exec_script(&format!(
        "echo SUBNET=$SUBNET PUBLIC_IP=$PUBLIC_IP > {f}\ncat >> {f}",
        f = add_file.display()
    ));
    let rm_script = write_exec_script(&format!("cat > {}", rm_file.display()));

    let backend_json = format!(
        "{{\"PreStartupCommand\":\"echo hello\",\"PostStartupCommand\":\"{}\",\"SubnetAddCommand\":\"{}\",\"SubnetRemoveCommand\":\"{}\"}}",
        post_script.display(), add_script.display(), rm_script.display()
    );
    let config = Config {
        enable_ipv4: true,
        network: IP4Net {
            ip: IP4::from_bytes([10, 1, 0, 0]),
            prefix_len: 16,
        },
        subnet_len: 24,
        backend: Some(RawValue::from_string(backend_json).unwrap()),
        ..Default::default()
    };

    // Event BackendData is a JSON-encoded string, as register stores it.
    let added = event_lease(3, "extension", "\"payload-add\"", [192, 168, 7, 7]);
    let removed = event_lease(4, "extension", "\"payload-rm\"", [192, 168, 7, 8]);
    let foreign = event_lease(5, "vxlan", "\"ignored\"", [192, 168, 7, 9]);
    let batch = vec![LeaseWatchResult {
        events: vec![
            Event {
                event_type: EventType::Added,
                lease: added,
            },
            Event {
                event_type: EventType::Removed,
                lease: removed,
            },
            Event {
                event_type: EventType::Added,
                lease: foreign,
            },
        ],
        snapshot: vec![],
    }];

    let mock = mock_and_ei(vec![batch], config.clone());
    let be = new_backend(mock.clone(), loopback_ei(Some("192.168.1.10"))).unwrap();
    let ctx = CancellationToken::new();
    let net = be.register_network(&ctx, &config).await.unwrap();

    // PreStartup "echo hello" -> JSON-encoded "hello" as BackendData.
    let attrs = mock.attrs_seen.lock().unwrap().clone().unwrap();
    assert_eq!(attrs.backend_type, "extension");
    assert_eq!(attrs.backend_data.as_deref().unwrap().get(), "\"hello\"");
    assert_eq!(attrs.public_ip, IP4::from_bytes([192, 168, 1, 10]));
    assert_eq!(net.lease().subnet, test_lease(2).subnet);
    assert!(net.mtu() > 0, "loopback MTU snapshot should be positive");

    // PostStartupCommand ran during register with Go's env.
    let post = std::fs::read_to_string(&post_file).unwrap();
    assert_eq!(post, "NET=10.1.0.0/16 SUBNET=10.1.2.0/24 IPV6SUBNET=::/0 PUBLIC_IP=192.168.1.10 PUBLIC_IPV6=<nil>\n");

    // Run loop: drive run() while waiting for the event-command output.
    let run = net.run(&ctx);
    tokio::pin!(run);
    let add = wait_with_run(run.as_mut(), &add_file, "payload-add").await;
    assert_eq!(
        add,
        "SUBNET=10.1.3.0/24 PUBLIC_IP=192.168.7.7\npayload-add\n"
    );
    let rm = wait_with_run(run.as_mut(), &rm_file, "payload-rm").await;
    assert_eq!(rm, "payload-rm\n");

    ctx.cancel();
    tokio::time::timeout(Duration::from_secs(5), run)
        .await
        .expect("run() should return after cancellation");
    for p in [&post_file, &add_file, &rm_file] {
        let _ = std::fs::remove_file(p);
    }
}
#[tokio::test]
async fn register_error_paths() {
    // Failing pre-startup aborts registration with Go's error shape.
    // (script file: split_command keeps quotes literal, no spaces)
    let bad_script = write_exec_script("echo boom 1>&2; exit 7");
    let bad_json =
        serde_json::json!({ "PreStartupCommand": bad_script.display().to_string() }).to_string();
    let config = Config {
        enable_ipv4: true,
        backend: Some(RawValue::from_string(bad_json).unwrap()),
        ..Default::default()
    };
    let mock = mock_and_ei(vec![], config.clone());
    let be = new_backend(mock, loopback_ei(None)).unwrap();
    let ctx = CancellationToken::new();
    let res = be.register_network(&ctx, &config).await;
    let err = res.err().expect("should fail");
    let msg = err.to_string();
    assert!(msg.contains("failed to run command"), "got: {msg}");
    assert!(msg.contains("exit status 7"), "got: {msg}");
    assert!(msg.contains("boom"), "got: {msg}");

    // A malformed backend config is reported like Go's decode error.
    let config = Config {
        enable_ipv4: true,
        backend: Some(RawValue::from_string("{\"PreStartupCommand\": 3}".to_string()).unwrap()),
        ..Default::default()
    };
    let mock = mock_and_ei(vec![], config.clone());
    let be = new_backend(mock, Arc::new(ExternalInterface::default())).unwrap();
    let res = be.register_network(&ctx, &config).await;
    let err = res.err().expect("should fail");
    assert!(
        err.to_string().contains("error decoding backend config"),
        "got: {err}"
    );
}
