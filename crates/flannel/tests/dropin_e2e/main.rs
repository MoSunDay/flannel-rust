//! Drop-in end-to-end test for the full flannel chain: the `flanneld`
//! daemon (alloc backend, in-memory mock apiserver) writes `subnet.env`,
//! the `flannel` CNI meta-plugin binary consumes it (via
//! FLANNEL_SUBNET_FILE), and the real `bridge` + `host-local` plugins
//! create a pod veth (eth0) inside a fresh network namespace.
//!
//! Requires: root/netlink, a default route (daemon iface selection), the
//! CNI plugins tarball and netns support — all present in this repo's CI
//! container (the flannel-cni e2e exercises the same prerequisites).

mod mock_apiserver;

use flannel_core::ip::{IP4Net, IP4};
use flanneld::flags_defs::{build_flag_set, options_from_flag_set};
use mock_apiserver::MockApiserver;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::str::FromStr;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

/// Real CNI plugin binaries (bridge + host-local live at the tar root).
const PLUGIN_TGZ: &str = "/root/k3as/vendor/cache/cni-plugins-linux-amd64-v1.5.1.tgz";

/// Netconf handed to the flannel binary on stdin (CNI exec protocol).
const NETCONF: &str = r#"{"cniVersion":"0.4.0","name":"dropin","type":"flannel"}"#;

const CONTAINER_ID: &str = "dropin-test";

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

/// Namespace cleanup on drop (also on panic): no leaked netns regardless
/// of where an assertion fails. `remove()` consumes, hence the Option.
struct NsGuard(Option<netns_rs::NetNs>);

impl NsGuard {
    fn create(name: &str) -> Self {
        if let Ok(old) = netns_rs::NetNs::get(name) {
            let _ = old.remove();
        }
        let ns = netns_rs::NetNs::new(name)
            .unwrap_or_else(|e| panic!("failed to create network namespace {name:?}: {e}"));
        Self(Some(ns))
    }

    fn path(&self) -> String {
        self.0
            .as_ref()
            .expect("ns present")
            .path()
            .to_str()
            .unwrap()
            .to_string()
    }
}

impl Drop for NsGuard {
    fn drop(&mut self) {
        if let Some(ns) = self.0.take() {
            let _ = ns.remove();
        }
    }
}

/// Async so the single-threaded test runtime keeps driving the daemon.
async fn wait_for_file(path: &Path, timeout: Duration) -> Option<String> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(content) = std::fs::read_to_string(path) {
            if content.contains("FLANNEL_SUBNET=") {
                return Some(content);
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    None
}

/// Unique-ish suffix (pid + nanos) so parallel/rerun tests don't collide.
fn unique_suffix() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{:x}{:x}", std::process::id(), nanos)
}

/// Extract `bridge` + `host-local` from the CNI plugins tarball. This
/// environment is expected to provide it: fail loudly, never skip.
fn extract_plugins(dir: &Path) {
    let out = std::process::Command::new("tar")
        .args([
            "xzf",
            PLUGIN_TGZ,
            "-C",
            dir.to_str().unwrap(),
            "./bridge",
            "./host-local",
        ])
        .output()
        .unwrap_or_else(|e| panic!("failed to run tar on {PLUGIN_TGZ}: {e}"));
    assert!(
        out.status.success(),
        "tar extraction of CNI plugins from {PLUGIN_TGZ} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    for name in ["bridge", "host-local"] {
        let plugin = dir.join(name);
        assert!(
            plugin.is_file(),
            "plugin {name} missing after extracting {PLUGIN_TGZ}"
        );
        // tar preserves modes, but be safe.
        std::fs::set_permissions(&plugin, std::fs::Permissions::from_mode(0o755))
            .unwrap_or_else(|e| panic!("chmod +x for {name}: {e}"));
    }
}

/// Value of a `KEY=value` line in subnet.env (panics with the content
/// when the line is absent).
fn env_line_value(content: &str, key: &str) -> String {
    let prefix = format!("{key}=");
    content
        .lines()
        .find_map(|line| line.strip_prefix(&prefix).map(str::trim))
        .map(str::to_string)
        .unwrap_or_else(|| panic!("no {prefix} line in subnet.env:\n{content}"))
}

/// FLANNEL_SUBNET as written by flanneld (host address, e.g.
/// 10.244.9.1/24), masked to its network (10.244.9.0/24) for assertions.
fn parse_pod_subnet(content: &str) -> IP4Net {
    let raw = env_line_value(content, "FLANNEL_SUBNET");
    // IP4Net::from_str clears host bits (net.ParseCIDR semantics).
    IP4Net::from_str(&raw).unwrap_or_else(|e| panic!("unparseable FLANNEL_SUBNET {raw:?}: {e}"))
}

/// Run the `flannel` CNI binary as a child process per the CNI exec
/// protocol: env vars + netconf on stdin. FLANNEL_SUBNET_FILE is set for
/// the child only — never mutated in the test process.
fn run_cni(
    command: &str,
    flannel_bin: &str,
    netns: &str,
    cni_path: &Path,
    subnet_file: &Path,
) -> anyhow::Result<std::process::Output> {
    use std::io::Write;
    let mut child = std::process::Command::new(flannel_bin)
        .env("CNI_COMMAND", command)
        .env("CNI_CONTAINERID", CONTAINER_ID)
        .env("CNI_NETNS", netns)
        .env("CNI_IFNAME", "eth0")
        .env("CNI_ARGS", "IgnoreUnknown=1")
        .env("CNI_PATH", cni_path)
        .env("FLANNEL_SUBNET_FILE", subnet_file)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| anyhow::anyhow!("spawning flannel binary for {command}: {e}"))?;
    child
        .stdin
        .take()
        .expect("stdin piped")
        .write_all(NETCONF.as_bytes())?;
    Ok(child.wait_with_output()?)
}

/// CNI 0.4.0 result check: some interface is named eth0 and an ips[]
/// entry bound to that interface holds an address inside `subnet`.
fn eth0_ip_in(result: &serde_json::Value, subnet: IP4Net) -> bool {
    let Some(interfaces) = result["interfaces"].as_array() else {
        return false;
    };
    let Some(eth0_index) = interfaces.iter().position(|iface| iface["name"] == "eth0") else {
        return false;
    };
    result["ips"]
        .as_array()
        .map(|ips| {
            ips.iter().any(|ip| {
                let address = ip["address"].as_str().unwrap_or("");
                let Some((addr, _)) = address.split_once('/') else {
                    return false;
                };
                ip["interface"].as_u64() == Some(eth0_index as u64)
                    && addr
                        .parse::<IP4>()
                        .map(|v4| subnet.contains(v4))
                        .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

#[tokio::test]
async fn dropin_daemon_subnet_env_cni_pod_veth() {
    init_tracing();
    let _guard = ENV_LOCK.lock().await;
    let _node = EnvGuard::set_node_name("dropin-node");

    // 1. Mock apiserver with the node's podCIDR (controller-manager role).
    let api = MockApiserver::start().await;
    api.put_node("dropin-node", "10.244.9.0/24");

    let dir = tempfile::tempdir().unwrap();
    let conf_path = dir.path().join("net-conf.json");
    std::fs::write(
        &conf_path,
        r#"{"Network": "10.244.0.0/16", "Backend": {"Type": "alloc"}}"#,
    )
    .unwrap();
    let subnet_file = dir.path().join("subnet.env");

    // 2. Daemon options through the real flag set (Go-equivalent
    //    defaults), mirroring the flanneld e2e_daemon harness.
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

    // 3. Daemon as an in-process task; wait for the READY signal
    //    (subnet.env written from the alloc lease).
    let cancel = CancellationToken::new();
    let run_task = tokio::spawn(flanneld::run(opts, cancel.clone()));
    let content = wait_for_file(&subnet_file, Duration::from_secs(30))
        .await
        .expect("daemon wrote subnet.env within 30s");
    assert!(
        content.contains("FLANNEL_NETWORK=10.244.0.0/16\n"),
        "{content}"
    );

    // 4. Pod subnet: flanneld writes the first usable host address
    //    (10.244.9.1/24); mask to the network for the range assertion.
    let pod_subnet = parse_pod_subnet(&content);
    assert_eq!(
        pod_subnet,
        IP4Net::from_str("10.244.9.0/24").unwrap(),
        "unexpected pod subnet in {content}"
    );

    // 5. Real bridge + host-local plugin binaries.
    let plugins_dir = tempfile::tempdir().unwrap();
    extract_plugins(plugins_dir.path());

    // 6. Fresh netns for the "pod", plus a scratch netns standing in for
    //    the container runtime's (host) side: the delegated bridge plugin
    //    creates cni0 in its *caller's* namespace, so executing the CNI
    //    chain inside the scratch netns keeps it off the real host (which
    //    may already have a cni0, e.g. under k3s) and it dies with the ns.
    let ns_name = format!("dropin-e2e-{}", unique_suffix());
    let ns = NsGuard::create(&ns_name);
    let ns_path = ns.path();
    let host_ns_name = format!("dropin-e2e-host-{}", unique_suffix());
    // Bound as `_`-prefixed: never read by name, but must stay alive
    // until test end so the scratch netns exists for the children and is
    // removed on Drop.
    let _host_ns = NsGuard::create(&host_ns_name);

    // 7+9. CNI ADD then DEL through the real flannel binary. Blocking
    //      child I/O runs off-runtime so the daemon task stays polled;
    //      the children spawn inside the scratch host netns.
    let flannel_bin = env!("CARGO_BIN_EXE_flannel").to_string();
    let plugins_path = plugins_dir.path().to_path_buf();
    let subnet_path = subnet_file.clone();
    let (add_out, del_out) = {
        let host_ns_name = host_ns_name.clone();
        tokio::task::spawn_blocking(move || {
            let host_ns = netns_rs::NetNs::get(&host_ns_name)
                .map_err(|e| anyhow::anyhow!("opening scratch host netns {host_ns_name:?}: {e}"))?;
            host_ns
                .run(|_| {
                    let add = run_cni("ADD", &flannel_bin, &ns_path, &plugins_path, &subnet_path)?;
                    let del = run_cni("DEL", &flannel_bin, &ns_path, &plugins_path, &subnet_path)?;
                    anyhow::Ok((add, del))
                })
                .map_err(|e| anyhow::anyhow!("entering scratch host netns: {e}"))
                .and_then(|r| r)
        })
        .await
        .expect("CNI child runs joined")
        .unwrap_or_else(|e| panic!("CNI child run failed: {e:#}"))
    };

    // 8. ADD: exit 0 and a result with an eth0 IP in 10.244.9.0/24.
    assert!(
        add_out.status.success(),
        "flannel ADD exited {:?}: stdout={} stderr={}",
        add_out.status.code(),
        String::from_utf8_lossy(&add_out.stdout),
        String::from_utf8_lossy(&add_out.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&add_out.stdout).unwrap_or_else(|e| {
        panic!(
            "CNI ADD stdout is not JSON ({e}): {}",
            String::from_utf8_lossy(&add_out.stdout)
        )
    });
    assert!(
        eth0_ip_in(&result, pod_subnet),
        "no eth0 IP in {pod_subnet}: {result}"
    );

    // DEL: exit 0 (DEL must be idempotent).
    assert!(
        del_out.status.success(),
        "flannel DEL exited {:?}: stdout={} stderr={}",
        del_out.status.code(),
        String::from_utf8_lossy(&del_out.stdout),
        String::from_utf8_lossy(&del_out.stderr)
    );

    // 10. Cancel -> clean exit 0, like the Go signal-handler path.
    cancel.cancel();
    let code = tokio::time::timeout(Duration::from_secs(15), run_task)
        .await
        .expect("daemon exited after cancel")
        .unwrap()
        .unwrap();
    assert_eq!(code, 0);

    // The daemon also patched the node (acquire_lease/complete_lease),
    // like in the flanneld e2e.
    let ann = api.node_annotations("dropin-node");
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
