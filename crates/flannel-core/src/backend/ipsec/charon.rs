//! Port of handle_charon.go: locating and spawning the strongSwan
//! "charon" IKE daemon, plus the CharonIKEDaemon operations (load the
//! PSK, load/unload connections) which drive charon over VICI.
//!
//! Go deviations:
//! - Go's daemon struct stores the `context.Context` for `getClient`
//!   retries; here every function takes `ctx` explicitly.
//! - Go's `LoadSharedKey` retries `LoadShared` forever; this port also
//!   aborts the retry wait when `ctx` is cancelled (otherwise flannel
//!   shutdown could hang on a dead charon).
//! - Client connections are closed by dropping/closing after each call
//!   like Go's deferred `client.Close()`.

use crate::backend::ipsec::vici::{ChildConf, IkeConf, ViciConn};
use crate::lease::Lease;
use crate::subnet::manager::Ctx;
use anyhow::anyhow;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::time::Duration;
use tracing::{error, info, warn};

#[cfg(test)]
#[path = "charon_tests.rs"]
mod charon_tests;

/// Go: the fixed `unix:///var/run/charon.vici` URI (network "unix").
const VICI_SOCKET_PATH: &str = "/var/run/charon.vici";

/// Port of Go `CharonIKEDaemon` (the `ctx`/`viciUri` fields are gone:
/// ctx is passed per call and the socket path is fixed).
pub struct Charon {
    pub esp_proposal: String,
}

/// Go: `NewCharonIKEDaemon(ctx, wg, espProposal)`: finds the binary,
/// starts it and registers a ctx-cancellation watcher that sends
/// SIGTERM and waits (here done inside [`spawn_charon`]). The Go
/// `*sync.WaitGroup` is dropped per the backend traits convention.
pub fn new_charon(ctx: Ctx<'_>, esp_proposal: String) -> anyhow::Result<Charon> {
    let exec_path = find_exec_path().map_err(|e| {
        error!("Charon daemon not found: {e}");
        e
    })?;
    spawn_charon(ctx, &exec_path).map_err(|e| {
        error!("Error starting charon daemon: {e}");
        e
    })?;
    info!("Charon daemon started");
    Ok(Charon { esp_proposal })
}

/// Go: `findExecPath` — try well-known charon paths in order.
pub fn find_exec_path() -> anyhow::Result<String> {
    find_exec_path_in(std::env::var_os("PATH").as_deref())
}

/// [`find_exec_path`] with an explicit PATH value (testability; see
/// [`look_path_in`]).
pub(crate) fn find_exec_path_in(path_var: Option<&std::ffi::OsStr>) -> anyhow::Result<String> {
    const CANDIDATES: &[&str] = &[
        "charon",                         // PATH
        "/usr/lib/strongswan/charon",     // alpine, arch, flannel container
        "/usr/lib/ipsec/charon",          // debian/ubuntu
        "/usr/libexec/strongswan/charon", // centos/rhel
        "/usr/libexec/ipsec/charon",      // opensuse/sles
    ];
    for candidate in CANDIDATES {
        if let Some(p) = look_path_in(candidate, path_var) {
            return Ok(p);
        }
        warn!("no valid charon executable found at path {candidate}");
    }
    anyhow::bail!("no valid charon executable found at paths {CANDIDATES:?}")
}

/// Go `exec.LookPath` equivalent: bare names are searched through
/// $PATH, paths with a separator are checked directly.
/// Go `exec.LookPath` for one candidate. `path_var` is the PATH value to
/// search; taking it as a parameter keeps PATH out of the process env so
/// tests can exercise it without global mutation.
pub(crate) fn look_path_in(candidate: &str, path_var: Option<&std::ffi::OsStr>) -> Option<String> {
    if candidate.contains('/') {
        return is_executable(Path::new(candidate)).then(|| candidate.to_string());
    }
    let path = path_var?;
    for dir in path.to_string_lossy().split(':') {
        let full = if dir.is_empty() {
            candidate.to_string() // Go LookPath: empty element = current dir
        } else {
            format!("{}/{}", dir.trim_end_matches('/'), candidate)
        };
        if is_executable(Path::new(&full)) {
            return Some(full);
        }
    }
    None
}

fn is_executable(path: &Path) -> bool {
    match std::fs::metadata(path) {
        Ok(m) => m.is_file() && m.permissions().mode() & 0o111 != 0,
        Err(_) => false,
    }
}

/// Go: `charon.run(execPath)` plus the ctx-watcher goroutine. The child
/// inherits stdout/stderr and gets `Pdeathsig: SIGTERM` (prctl). On ctx
/// cancellation a task sends SIGTERM and waits (Go's watcher goroutine).
pub(crate) fn spawn_charon(ctx: Ctx<'_>, exec_path: &str) -> anyhow::Result<()> {
    let mut cmd = std::process::Command::new(exec_path);
    unsafe {
        cmd.pre_exec(|| {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn()?;
    let token = ctx.clone();
    tokio::spawn(async move {
        token.cancelled().await;
        let pid = child.id() as i32;
        tokio::task::spawn_blocking(move || {
            if unsafe { libc::kill(pid, libc::SIGTERM) } != 0 {
                error!(
                    "Error while processing the signal: {}",
                    std::io::Error::last_os_error()
                );
            }
            match child.wait() {
                Ok(_) => info!("Stopped charon daemon"),
                Err(e) => error!("Error while waiting for process to exit: {e}"),
            }
        });
    });
    Ok(())
}

/// Go: `charon.getClient(wait)` — dial the VICI socket, retrying every
/// second until `ctx` is cancelled when `wait` is true.
async fn get_client(ctx: Ctx<'_>, wait: bool) -> std::io::Result<ViciConn> {
    loop {
        let res = tokio::task::spawn_blocking(|| ViciConn::connect(VICI_SOCKET_PATH))
            .await
            .unwrap_or_else(|e| Err(std::io::Error::other(e.to_string())));
        match res {
            Ok(conn) => return Ok(conn),
            Err(e) => {
                if !wait {
                    return Err(e);
                }
                tokio::select! {
                    _ = ctx.cancelled() => {
                        error!("Cancel waiting for charon");
                        return Err(e);
                    }
                    _ = tokio::time::sleep(Duration::from_secs(1)) => {
                        error!("ClientConnection failed: {e}");
                        info!("Retrying in a second ...");
                    }
                }
            }
        }
    }
}

/// Runs `op` on a blocking thread, handing the client back out.
async fn with_client<T>(
    mut client: ViciConn,
    op: impl FnOnce(&mut ViciConn) -> std::io::Result<T> + Send + 'static,
) -> anyhow::Result<(ViciConn, std::io::Result<T>)>
where
    T: Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let r = op(&mut client);
        (client, r)
    })
    .await
    .map_err(|e| anyhow!("VICI blocking task failed: {e}"))
}

/// Go: `LoadSharedKey(remotePublicIP, password)` — retry `load-shared`
/// every second until it succeeds (plus the ctx-abort deviation above).
pub async fn load_shared_key(
    ctx: Ctx<'_>,
    remote_public_ip: &str,
    password: &str,
) -> anyhow::Result<()> {
    let mut client = get_client(ctx, true)
        .await
        .map_err(|e| anyhow!("Failed to acquire Vici client: {e}"))?;
    let owner = remote_public_ip.to_string();
    let pw = password.to_string();
    loop {
        let pw_c = pw.clone();
        let owner_c = owner.clone();
        let (conn, res) = with_client(client, move |c| {
            c.load_shared("IKE", pw_c.as_bytes(), &[owner_c])
        })
        .await?;
        client = conn;
        if res.is_ok() {
            break;
        }
        error!("Failed to load my key. Retrying. {}", res.unwrap_err());
        tokio::select! {
            _ = ctx.cancelled() => anyhow::bail!("cancelled while loading shared key"),
            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
        }
    }
    let _ = client.close();
    info!("Loaded shared key for: {remote_public_ip}");
    Ok(())
}

/// Go: `LoadConnection(localLease, remoteLease, reqID, encap)` with all
/// the goStrongswanVici defaults (proposals aes256-sha256-modp4096,
/// version 2, keying_tries 0, psk auth, child start/trap/restart/1h...).
pub async fn load_connection(
    ctx: Ctx<'_>,
    charon: &Charon,
    local_lease: &Lease,
    remote_lease: &Lease,
    req_id: &str,
    encap: bool,
) -> anyhow::Result<()> {
    let mut client = get_client(ctx, true)
        .await
        .map_err(|e| anyhow!("Failed to acquire Vici client: {e}"))?;
    let ike = IkeConf {
        local_addrs: vec![local_lease.attrs.public_ip.to_string()],
        remote_addrs: vec![remote_lease.attrs.public_ip.to_string()],
        proposals: vec!["aes256-sha256-modp4096".to_string()],
        version: "2".to_string(),
        keying_tries: "0".to_string(),
        encap: encap.to_string(),
        child_name: format_child_sa_conf_name(local_lease, remote_lease),
        child: ChildConf {
            local_ts: vec![local_lease.subnet.to_string()],
            remote_ts: vec![remote_lease.subnet.to_string()],
            esp_proposals: vec![charon.esp_proposal.clone()],
            start_action: "start".to_string(),
            close_action: "trap".to_string(),
            dpd_action: "restart".to_string(),
            mode: "tunnel".to_string(),
            reqid: req_id.to_string(),
            rekey_time: "1h".to_string(),
            install_policy: "no".to_string(),
        },
    };
    let name = format_connection_name(local_lease, remote_lease);
    let (conn, res) = with_client(client, {
        let name = name.clone();
        move |c| c.load_conn(&name, &ike)
    })
    .await?;
    client = conn;
    res.map_err(|e| anyhow!("error loading connection: {e}"))?;
    let _ = client.close();
    info!("Loaded connection: {name}");
    Ok(())
}

/// Go: `UnloadCharonConnection(localLease, remoteLease)` (no wait).
pub async fn unload_charon_connection(
    ctx: Ctx<'_>,
    local_lease: &Lease,
    remote_lease: &Lease,
) -> anyhow::Result<()> {
    let mut client = get_client(ctx, false)
        .await
        .map_err(|e| anyhow!("Failed to acquire Vici client: {e}"))?;
    let name = format_connection_name(local_lease, remote_lease);
    tokio::task::spawn_blocking({
        let name = name.clone();
        move || client.unload_conn(&name)
    })
    .await
    .map_err(|e| anyhow!("VICI blocking task failed: {e}"))?
    .map_err(|e| anyhow!("error unloading connection: {e}"))?;
    info!("Unloaded connection: {name}");
    Ok(())
}

/// Go: `formatConnectionName`.
pub fn format_connection_name(local_lease: &Lease, remote_lease: &Lease) -> String {
    format!(
        "{}-{}-{}-{}",
        local_lease.attrs.public_ip,
        local_lease.subnet,
        remote_lease.subnet,
        remote_lease.attrs.public_ip
    )
}

/// Go: `formatChildSAConfName`.
pub fn format_child_sa_conf_name(local_lease: &Lease, remote_lease: &Lease) -> String {
    format!("{}-{}", local_lease.subnet, remote_lease.subnet)
}
