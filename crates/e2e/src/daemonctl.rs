//! Boot/shutdown real `flanneld` in-process. The daemon runs on a
//! dedicated OS thread (optionally after entering a netns) with its own
//! current-thread tokio runtime — the same pattern the live-kernel tests
//! use: netlink sockets must be created inside the target netns.
//!
//! `NODE_NAME` is read from the process environment during subnet-manager
//! creation, so daemons must be spawned sequentially: wait for one
//! daemon's readiness before spawning the next (the harness does this).

use anyhow::{bail, Context, Result};
use flanneld::flags_defs::{build_flag_set, options_from_flag_set};
use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

/// Hook run on the daemon thread *after* `flanneld::run` returns, still
/// inside the netns (e.g. traffic-manager `clean_up` for the masq tests).
pub type PostHook = Box<dyn FnOnce() -> Pin<Box<dyn Future<Output = ()> + Send>> + Send>;

pub struct DaemonSpec {
    pub node_name: String,
    pub api_url: String,
    pub net_conf: serde_json::Value,
    pub iface: Option<String>,
    pub extra_args: Vec<String>,
    pub healthz_port: u16,
    pub netns_path: Option<PathBuf>,
    pub post_hook: Option<PostHook>,
    /// Extra process env vars applied (sequentially, like NODE_NAME)
    /// before the daemon thread starts; consumed during daemon startup,
    /// so the wait_ready barrier keeps concurrent daemons from racing.
    pub env: Vec<(String, String)>,
}

impl DaemonSpec {
    pub fn new(node_name: &str, api_url: &str, net_conf: serde_json::Value) -> Self {
        Self {
            node_name: node_name.to_string(),
            api_url: api_url.to_string(),
            net_conf,
            iface: None,
            extra_args: Vec::new(),
            healthz_port: 0,
            netns_path: None,
            post_hook: None,
            env: Vec::new(),
        }
    }

    /// Extra env var for the daemon (see `DaemonSpec::env`).
    pub fn env(mut self, key: &str, value: &str) -> Self {
        self.env.push((key.to_string(), value.to_string()));
        self
    }

    pub fn in_netns(mut self, path: &std::path::Path) -> Self {
        self.netns_path = Some(path.to_path_buf());
        self
    }

    pub fn iface(mut self, name: &str) -> Self {
        self.iface = Some(name.to_string());
        self
    }

    pub fn extra(mut self, args: &[&str]) -> Self {
        self.extra_args.extend(args.iter().map(|s| s.to_string()));
        self
    }

    pub fn healthz(mut self, port: u16) -> Self {
        self.healthz_port = port;
        self
    }

    pub fn after_shutdown(mut self, hook: PostHook) -> Self {
        self.post_hook = Some(hook);
        self
    }
}

pub struct DaemonHandle {
    pub node_name: String,
    pub subnet_file: PathBuf,
    _tmp: tempfile::TempDir,
    cancel: CancellationToken,
    code_rx: Arc<Mutex<mpsc::Receiver<anyhow::Result<i32>>>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl DaemonHandle {
    pub fn spawn(spec: DaemonSpec) -> Result<Self> {
        std::env::set_var("NODE_NAME", &spec.node_name);
        for (key, value) in &spec.env {
            std::env::set_var(key, value);
        }
        let tmp = tempfile::tempdir().context("daemon tempdir")?;
        let net_conf_path = tmp.path().join("net-conf.json");
        std::fs::write(&net_conf_path, spec.net_conf.to_string())
            .context("writing net-conf.json")?;
        let subnet_file = tmp.path().join("subnet.env");

        let mut args: Vec<String> = vec![
            "--kube-subnet-mgr".into(),
            format!("--kube-api-url={}", spec.api_url),
            format!("--net-config-path={}", net_conf_path.display()),
            format!("--subnet-file={}", subnet_file.display()),
            format!("--healthz-port={}", spec.healthz_port),
        ];
        if let Some(iface) = &spec.iface {
            args.push(format!("--iface={iface}"));
        }
        args.extend(spec.extra_args.clone());

        let mut fs = build_flag_set();
        fs.parse(&args).context("daemon flag parse")?;
        let opts = options_from_flag_set(&fs);

        let cancel = CancellationToken::new();
        let (tx, rx) = mpsc::channel();
        let run_cancel = cancel.clone();
        let ns_path = spec.netns_path.clone();
        let hook = spec.post_hook;
        let thread_name = format!("flanneld-{}", spec.node_name);
        let thread = std::thread::Builder::new()
            .name(thread_name.clone())
            .spawn(move || {
                let result = (|| -> anyhow::Result<i32> {
                    if let Some(p) = &ns_path {
                        let ns = netns_rs::get_from_path(p).context("opening netns")?;
                        ns.enter().context("entering netns")?;
                    }
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .context("daemon runtime")?;
                    let code = rt.block_on(flanneld::run(opts, run_cancel))?;
                    if let Some(hook) = hook {
                        rt.block_on(hook());
                    }
                    Ok(code)
                })();
                let _ = tx.send(result);
            })
            .with_context(|| format!("spawning daemon thread {thread_name}"))?;

        Ok(Self {
            node_name: spec.node_name,
            subnet_file,
            _tmp: tmp,
            cancel,
            code_rx: Arc::new(Mutex::new(rx)),
            thread: Some(thread),
        })
    }

    /// Poll the subnet.env file until `FLANNEL_SUBNET=` appears.
    pub async fn wait_ready(&self, timeout: Duration) -> Result<String> {
        let path = self.subnet_file.clone();
        let deadline = Instant::now() + timeout;
        loop {
            if let Ok(content) = std::fs::read_to_string(&path) {
                if content.contains("FLANNEL_SUBNET=") {
                    return Ok(content);
                }
            }
            if Instant::now() >= deadline {
                bail!(
                    "timed out after {timeout:?} waiting for daemon {} subnet.env",
                    self.node_name
                );
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Parse subnet.env into a key/value map.
    pub fn subnet_env(&self) -> Result<HashMap<String, String>> {
        let content = std::fs::read_to_string(&self.subnet_file)
            .with_context(|| format!("reading {}", self.subnet_file.display()))?;
        content
            .lines()
            .filter(|l| l.contains('='))
            .map(|l| {
                let (k, v) = l.split_once('=').expect("split");
                Ok((k.trim().to_string(), v.trim().to_string()))
            })
            .collect()
    }

    /// Cancel the daemon, join the thread, return the exit code.
    pub fn shutdown(&mut self, timeout: Duration) -> Result<i32> {
        self.cancel.cancel();
        let rx = self.code_rx.clone();
        let guard = rx.lock().expect("code rx");
        match guard.recv_timeout(timeout) {
            Ok(result) => {
                let code = result.context("daemon run error")?;
                if let Some(th) = self.thread.take() {
                    let _ = th.join();
                }
                Ok(code)
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                bail!("daemon {} did not exit within {timeout:?}", self.node_name)
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                bail!("daemon {} thread panicked/disconnected", self.node_name)
            }
        }
    }
}

impl Drop for DaemonHandle {
    fn drop(&mut self) {
        if self.thread.is_some() {
            self.cancel.cancel();
            let rx = self.code_rx.clone();
            let guard = rx.lock().expect("code rx");
            let _ = guard.recv_timeout(Duration::from_secs(10));
        }
    }
}
