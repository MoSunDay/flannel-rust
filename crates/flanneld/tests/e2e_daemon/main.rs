//! P1 end-to-end test: `flanneld::run` against an in-memory mock kube
//! apiserver. The daemon must reach READY (subnet.env written from the
//! node's podCIDR via the alloc backend), patch the node annotations,
//! clear NodeNetworkUnavailable, and exit 0 on cancel.
//!
//! Requires: root/netlink (interface selection) and a default route —
//! both present in this repo's CI container.

mod mock_apiserver;

use flanneld::flags_defs::{build_flag_set, options_from_flag_set};
use mock_apiserver::MockApiserver;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

/// Install a subscriber once so the daemon's tracing output is visible
/// in test logs (the lib entry point, unlike main.rs, does not init
/// one). Filter via RUST_LOG; defaults to info.
fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

/// NODE_NAME is process-global env; serialize tests that set it.
/// Async-aware: the guard is held across awaits in the e2e test.
static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct EnvGuard {
    prev: Option<String>,
}

impl EnvGuard {
    fn set_node_name(value: &str) -> Self {
        let prev = std::env::var("NODE_NAME").ok();
        std::env::set_var("NODE_NAME", value);
        Self { prev }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match &self.prev {
            Some(v) => std::env::set_var("NODE_NAME", v),
            None => std::env::remove_var("NODE_NAME"),
        }
    }
}

/// Async so the single-threaded test runtime keeps driving the daemon.
async fn wait_for_file(path: &std::path::Path, timeout: Duration) -> Option<String> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(content) = std::fs::read_to_string(path) {
            if !content.is_empty() {
                return Some(content);
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    None
}

#[tokio::test]
async fn daemon_runs_writes_subnet_file_and_exits_cleanly_on_cancel() {
    init_tracing();
    let _guard = ENV_LOCK.lock().await;
    let _node = EnvGuard::set_node_name("e2e-node");

    let api = MockApiserver::start().await;
    api.put_node("e2e-node", "10.244.1.0/24");

    let dir = tempfile::tempdir().unwrap();
    let conf_path = dir.path().join("net-conf.json");
    std::fs::write(
        &conf_path,
        r#"{"Network": "10.244.0.0/16", "Backend": {"Type": "alloc"}}"#,
    )
    .unwrap();
    let subnet_file = dir.path().join("subnet.env");

    // Build opts through the real flag set (Go-equivalent defaults),
    // overriding only what points at the mock and temp paths.
    let mut fs = build_flag_set();
    let args: Vec<String> = vec![
        "--kube-subnet-mgr".into(),
        format!("--kube-api-url={}", api.url()),
        format!("--net-config-path={}", conf_path.display()),
        format!("--subnet-file={}", subnet_file.display()),
        "--healthz-port=0".into(),
    ];
    fs.parse(&args).unwrap();
    let opts = options_from_flag_set(&fs);

    let cancel = CancellationToken::new();
    let run_task = tokio::spawn(flanneld::run(opts, cancel.clone()));

    // The daemon reaches READY: subnet.env written from the lease.
    let content = wait_for_file(&subnet_file, Duration::from_secs(30))
        .await
        .expect("daemon wrote subnet.env within 30s");
    assert!(
        content.contains("FLANNEL_NETWORK=10.244.0.0/16\n"),
        "{content}"
    );
    // write_subnet_file increments the lease IP by one (first usable).
    assert!(
        content.contains("FLANNEL_SUBNET=10.244.1.1/24\n"),
        "{content}"
    );
    assert!(content.contains("FLANNEL_MTU="), "{content}");
    assert!(content.contains("FLANNEL_IPMASQ=false\n"), "{content}");

    // Cancel -> clean exit 0 (Go signal-handler equivalent).
    cancel.cancel();
    let code = tokio::time::timeout(Duration::from_secs(15), run_task)
        .await
        .expect("daemon exited after cancel")
        .unwrap()
        .unwrap();
    assert_eq!(code, 0);

    // Node annotations were patched by acquire_lease. For the alloc
    // backend the type/data attrs are empty ("")/null — flannel-core
    // still writes the keys, like upstream.
    let ann = api.node_annotations("e2e-node");
    let prefix = "flannel.alpha.coreos.com";
    assert_eq!(
        ann.get(&format!("{prefix}/kube-subnet-manager"))
            .map(String::as_str),
        Some("true"),
        "{ann:?}"
    );
    assert!(
        ann.contains_key(&format!("{prefix}/backend-type")),
        "{ann:?}"
    );
    let public_ip = ann
        .get(&format!("{prefix}/public-ip"))
        .expect("public-ip annotation set from the selected interface");
    assert!(
        public_ip.parse::<std::net::Ipv4Addr>().is_ok(),
        "{public_ip:?}"
    );

    // complete_lease cleared NodeNetworkUnavailable via a status patch.
    let status_patch = api
        .patches()
        .into_iter()
        .find(|(_, _, body)| body.get("status").is_some())
        .expect("a status patch was sent");
    let cond = status_patch
        .2
        .pointer("/status/conditions/0/type")
        .and_then(|v| v.as_str());
    assert_eq!(cond, Some("NetworkUnavailable"));
}

/// Daemon without `--kube-subnet-mgr` exits 1 (etcd not ported).
#[tokio::test]
async fn daemon_rejects_etcd_mode() {
    let mut fs = build_flag_set();
    fs.parse(&["--subnet-lease-renew-margin=60".to_string()])
        .unwrap();
    let opts = options_from_flag_set(&fs);
    let code = flanneld::run(opts, CancellationToken::new()).await.unwrap();
    assert_eq!(code, 1);
}

/// Common setup for the scenario tests: mock apiserver with a node, a
/// temp net-conf.json + subnet.env, and parsed `Options` pointing at
/// them. `backend_type` lands in the net-conf Backend.Type.
async fn scenario_opts(
    api: &MockApiserver,
    dir: &tempfile::TempDir,
    backend_type: &str,
    extra: &[String],
) -> (std::path::PathBuf, flanneld::Options) {
    let conf_path = dir.path().join("net-conf.json");
    std::fs::write(
        &conf_path,
        format!(r#"{{"Network": "10.244.0.0/16", "Backend": {{"Type": "{backend_type}"}}}}"#),
    )
    .unwrap();
    let subnet_file = dir.path().join("subnet.env");

    // Build opts through the real flag set (Go-equivalent defaults),
    // overriding only what points at the mock and temp paths.
    let mut fs = build_flag_set();
    let mut args: Vec<String> = vec![
        "--kube-subnet-mgr".into(),
        format!("--kube-api-url={}", api.url()),
        format!("--net-config-path={}", conf_path.display()),
        format!("--subnet-file={}", subnet_file.display()),
        "--healthz-port=0".into(),
    ];
    args.extend_from_slice(extra);
    fs.parse(&args).unwrap();
    let opts = options_from_flag_set(&fs);
    (subnet_file, opts)
}

/// Wait (bounded) until `f` turns true; keeps the single-threaded test
/// runtime polling while the daemon task runs.
async fn wait_until(timeout: Duration, mut f: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if f() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    f()
}

/// Go main.go:502-513 CompleteLease parity: when CompleteLease fails
/// (here: the /status patch is rejected, the only kube-mode error path,
/// pkg/subnet/kube/kube.go:639-675) Go only logs it and does NOT cancel
/// — the kube manager can never produce errInterrupted — so the daemon
/// keeps running, and still exits 0 when shutdown arrives.
#[tokio::test]
async fn complete_lease_failure_keeps_daemon_running_then_exits_zero() {
    init_tracing();
    let _guard = ENV_LOCK.lock().await;
    let _node = EnvGuard::set_node_name("e2e-node");

    let api = MockApiserver::start().await;
    api.put_node("e2e-node", "10.244.1.0/24");
    api.fail_status_patches();

    let dir = tempfile::tempdir().unwrap();
    let (subnet_file, opts) = scenario_opts(&api, &dir, "alloc", &[]).await;

    let cancel = CancellationToken::new();
    let run_task = tokio::spawn(flanneld::run(opts, cancel.clone()));

    // The daemon gets all the way to READY before complete_lease runs.
    wait_for_file(&subnet_file, Duration::from_secs(30))
        .await
        .expect("daemon wrote subnet.env within 30s");
    assert!(
        wait_until(Duration::from_secs(30), || {
            api.status_patch_failures() > 0
        })
        .await,
        "complete_lease's status patch attempted"
    );

    // A failed CompleteLease must NOT stop the daemon (no cancel, no
    // early exit): it is still running after the failure.
    assert!(
        !run_task.is_finished(),
        "daemon died on CompleteLease error"
    );

    // Shutdown arrives -> clean exit 0 (main.go:509-513).
    cancel.cancel();
    let code = tokio::time::timeout(Duration::from_secs(15), run_task)
        .await
        .expect("daemon exited after cancel")
        .unwrap()
        .unwrap();
    assert_eq!(code, 0);
}

/// Go main.go:553 + 587-591: the raw --healthz-port int goes to
/// net.JoinHostPort; 70000 fails ListenAndServe ("invalid port") and Go
/// aborts. The port maps that to the startup-failure path: exit 1 — NOT
/// a silent `as u16` wrap to 4464 — with the token cancelled and the
/// spawned tasks drained.
#[tokio::test]
async fn healthz_port_out_of_range_exits_one() {
    init_tracing();
    let _guard = ENV_LOCK.lock().await;
    let _node = EnvGuard::set_node_name("e2e-node");

    let api = MockApiserver::start().await;
    api.put_node("e2e-node", "10.244.1.0/24");

    let dir = tempfile::tempdir().unwrap();
    let (_, opts) = scenario_opts(&api, &dir, "alloc", &["--healthz-port=70000".to_string()]).await;

    let cancel = CancellationToken::new();
    let code = tokio::time::timeout(Duration::from_secs(60), flanneld::run(opts, cancel.clone()))
        .await
        .expect("startup failure surfaces within 60s")
        .unwrap();
    assert_eq!(code, 1);
    assert!(cancel.is_cancelled(), "exit path cancels the token");
}

/// Embedder mode (`install_signal_handlers == false`) with a startup
/// failure (unknown backend type, Go main.go:367-372: cancel();
/// wg.Wait(); os.Exit(1)): run must return 1, cancel the token and
/// drain every spawned task — observable by the healthz port becoming
/// rebindable — with NO signal-handler task ever spawned.
#[tokio::test]
async fn embedder_startup_failure_cancels_token_and_drains_tasks() {
    init_tracing();
    let _guard = ENV_LOCK.lock().await;
    let _node = EnvGuard::set_node_name("e2e-node");

    let api = MockApiserver::start().await;
    api.put_node("e2e-node", "10.244.1.0/24");

    // Reserve a free port for the healthz listener, then release it.
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let healthz_port = probe.local_addr().unwrap().port();
    drop(probe);

    let dir = tempfile::tempdir().unwrap();
    let (_, mut opts) = scenario_opts(
        &api,
        &dir,
        "no-such-backend",
        &[format!("--healthz-port={healthz_port}")],
    )
    .await;
    opts.install_signal_handlers = false;

    let cancel = CancellationToken::new();
    let code = tokio::time::timeout(Duration::from_secs(60), flanneld::run(opts, cancel.clone()))
        .await
        .expect("startup failure surfaces within 60s")
        .unwrap();
    assert_eq!(code, 1, "unknown backend type exits 1");
    assert!(cancel.is_cancelled(), "exit path cancels the token");

    // Tasks drained: the healthz listener was released (the server task
    // ends only on cancellation, so a successful rebind proves both).
    let rebindable = wait_until(Duration::from_secs(5), || {
        std::net::TcpListener::bind(("127.0.0.1", healthz_port)).is_ok()
    })
    .await;
    assert!(rebindable, "healthz listener drained (port rebindable)");
}
