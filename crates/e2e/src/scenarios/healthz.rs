//! Daemon binary edge cases through the *real* binaries: `--version`,
//! etcd-mode rejection, and the healthz/readyz HTTP endpoints of a live
//! daemon (reached via the solo-link veth IP).

use crate::daemonctl::{DaemonHandle, DaemonSpec};
use crate::netutil;
use crate::{bins, E2EError, Scenario};
use serde_json::json;
use std::io::{Read, Write};
use std::time::Duration;

pub fn scenarios() -> Vec<Scenario> {
    vec![
        Scenario {
            name: "daemon-version-flag",
            desc: "flanneld --version prints the version and exits 0",
            run: || Box::pin(run_version()),
        },
        Scenario {
            name: "daemon-rejects-etcd-mode",
            desc: "flanneld without --kube-subnet-mgr exits 1 (etcd unsupported)",
            run: || Box::pin(run_etcd_reject()),
        },
        Scenario {
            name: "healthz-readyz",
            desc: "/healthz 200 and /readyz 200 on a live daemon",
            run: || Box::pin(run_healthz()),
        },
    ]
}

async fn run_version() -> Result<(), E2EError> {
    let bin = bins::flanneld()?;
    let out = std::process::Command::new(&bin).arg("--version").output()?;
    assert!(
        out.status.success(),
        "--version must exit 0: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // flanneld --version prints to stderr (like upstream flanneld).
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("flannel-rust v0.1.0"),
        "--version output mismatch: {stderr}"
    );
    Ok(())
}

async fn run_etcd_reject() -> Result<(), E2EError> {
    let bin = bins::flanneld()?;
    let out = std::process::Command::new(&bin)
        .args(["--etcd-endpoints=http://127.0.0.1:4001"])
        .output()?;
    assert_eq!(out.status.code(), Some(1), "etcd mode must exit 1");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("kube-subnet-mgr"),
        "etcd rejection must mention --kube-subnet-mgr: {stderr}"
    );
    Ok(())
}

/// Free port on the host loopback for the daemon's healthz server.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port()
}

fn http_get(addr: &str, path: &str) -> anyhow::Result<(u16, String)> {
    let mut stream = std::net::TcpStream::connect(addr).map_err(anyhow::Error::from)?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: e2e\r\nConnection: close\r\n\r\n"
    )
    .map_err(anyhow::Error::from)?;
    let mut buf = String::new();
    stream
        .read_to_string(&mut buf)
        .map_err(anyhow::Error::from)?;
    let status: u16 = buf
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow::anyhow!("bad HTTP response: {buf}"))?;
    Ok((status, buf))
}

async fn run_healthz() -> Result<(), E2EError> {
    let link = netutil::build_solo_link("hz")?;
    let api = crate::apiserver::MockApiserver::start().await?;
    api.put_node("e2e-hz", "10.244.3.0/24").await;

    let port = free_port();
    let net_conf = json!({"Network": "10.244.0.0/16", "Backend": {"Type": "alloc"}});
    let mut daemon = DaemonHandle::spawn(
        DaemonSpec::new("e2e-hz", &api.url_on(&link.host_ip), net_conf)
            .in_netns(&link.ns.path())
            .iface(&link.ns_iface)
            .healthz(port),
    )?;

    let addr = format!("{}:{port}", link.ns_ip);
    // /healthz answers as soon as the server is up (before readiness).
    let addr_health = addr.clone();
    netutil::wait_until("healthz endpoint", Duration::from_secs(20), move || {
        Ok(http_get(&addr_health, "/healthz")
            .map(|(s, _)| s == 200)
            .unwrap_or(false))
    })
    .await?;
    let (status, _) = http_get(&addr, "/healthz")?;
    assert_eq!(status, 200, "/healthz must be 200");

    // /readyz flips to 200 once subnet.env is written.
    daemon.wait_ready(Duration::from_secs(30)).await?;
    netutil::wait_until("readyz endpoint", Duration::from_secs(20), || {
        let (s, _) = http_get(&addr, "/readyz")?;
        Ok(s == 200)
    })
    .await?;
    assert_eq!(daemon.shutdown(Duration::from_secs(15))?, 0);
    Ok(())
}
