//! `extension` backend closed loop: the daemon runs the configured shell
//! hooks (PreStartupCommand stdout becomes BackendData; PostStartup and
//! SubnetAdd/SubnetRemove receive NETWORK/SUBNET env), and the harness
//! asserts the hook side effects plus a correct subnet.env.
//!
//! The backend execs hook commands directly (Go `strings.Fields` +
//! `exec.Command`, no shell), so hooks here are executable script files;
//! env values arrive via `$NETWORK`/`$SUBNET`/`$PUBLIC_IP` inherited
//! from the daemon process. Like upstream, the own-subnet watch event is
//! filtered by the LeaseWatcher, so SubnetAdd fires for a *peer* lease:
//! the harness simulates a second node acquiring its lease (and later
//! being deleted) via the mock apiserver.

use crate::daemonctl::{DaemonHandle, DaemonSpec};
use crate::netutil;
use crate::{E2EError, Scenario};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

pub fn scenario() -> Scenario {
    Scenario {
        name: "extension-hooks",
        desc: "extension: pre/post-startup + subnet-add/remove hooks run with correct env",
        run: || Box::pin(run()),
    }
}

const PREFIX: &str = "flannel.alpha.coreos.com";

async fn run() -> Result<(), E2EError> {
    let link = netutil::build_solo_link("ext")?;
    let api = crate::apiserver::MockApiserver::start().await?;
    api.put_node("e2e-ext", "10.244.5.0/24").await;
    api.put_node("e2e-peer", "10.244.6.0/24").await;

    let dir = tempfile::tempdir()?;
    let post_log = dir.path().join("post.log");
    let add_log = dir.path().join("add.log");
    let add_stdin = dir.path().join("add.stdin");
    let del_log = dir.path().join("del.log");

    // Hook scripts: the backend passes no shell, so the scripts do their
    // own expansion/redirection; args carry the log paths ($1).
    let script = |name: &str, body: String| -> std::io::Result<std::path::PathBuf> {
        let p = dir.path().join(name);
        fs::write(&p, body)?;
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755))?;
        Ok(p)
    };
    let post_sh = script(
        "post.sh",
        "#!/bin/sh\nprintf 'NET=%s SUB=%s\\n' \"$NETWORK\" \"$SUBNET\" >> \"$1\"\n".to_string(),
    )?;
    let add_sh = script(
        "add.sh",
        "#!/bin/sh\ncat > \"$2\"\nprintf 'SUB=%s IP=%s\\n' \"$SUBNET\" \"$PUBLIC_IP\" >> \"$1\"\n"
            .to_string(),
    )?;
    let del_sh = script(
        "del.sh",
        "#!/bin/sh\nprintf '%s\\n' \"$SUBNET\" >> \"$1\"\n".to_string(),
    )?;

    let backend = json!({
        "Type": "extension",
        "PreStartupCommand": "printf 'pre-marker'",
        "PostStartupCommand": format!("{} {}", post_sh.display(), post_log.display()),
        "SubnetAddCommand": format!("{} {} {}", add_sh.display(), add_log.display(), add_stdin.display()),
        "SubnetRemoveCommand": format!("{} {}", del_sh.display(), del_log.display()),
    });
    let net_conf = json!({"Network": "10.244.0.0/16", "Backend": backend});

    let mut daemon = DaemonHandle::spawn(
        DaemonSpec::new("e2e-ext", &api.url_on(&link.host_ip), net_conf)
            .in_netns(&link.ns.path())
            .iface(&link.ns_iface),
    )?;
    let env = daemon.wait_ready(Duration::from_secs(30)).await?;
    assert!(
        env.contains("FLANNEL_SUBNET=10.244.5.1/24"),
        "subnet.env mismatch: {env}"
    );

    // PostStartup ran during register with the network/subnet env vars
    // (Go: SUBNET is the lease's network address, 10.244.5.0/24).
    netutil::wait_until("post-startup hook log", Duration::from_secs(15), || {
        let content = fs::read_to_string(&post_log).unwrap_or_default();
        Ok(content.contains("NET=10.244.0.0/16 SUB=10.244.5.0/24"))
    })
    .await?;

    // Simulate the peer node acquiring its lease: exactly the annotation
    // set the real kube-subnet-mgr writes (backend type/data/public IP
    // + kube-subnet-manager marker; backend-data is a JSON-encoded
    // string, i.e. the peer's PreStartupCommand stdout).
    let peer_annotations: BTreeMap<String, Value> = BTreeMap::from([
        (format!("{PREFIX}/backend-type"), json!("extension")),
        (
            format!("{PREFIX}/backend-data"),
            json!("\"peer-marker\""),
        ),
        (format!("{PREFIX}/public-ip"), json!("10.99.0.3")),
        (
            format!("{PREFIX}/kube-subnet-manager"),
            json!("true"),
        ),
    ]);
    api.patch_node_annotations("e2e-peer", &peer_annotations)
        .await?;

    // SubnetAdd fired for the peer lease; BackendData (the peer's
    // PreStartupCommand stdout, JSON-decoded) arrived on its stdin.
    netutil::wait_until("subnet-add hook log", Duration::from_secs(20), || {
        let log = fs::read_to_string(&add_log).unwrap_or_default();
        let stdin = fs::read_to_string(&add_stdin).unwrap_or_default();
        Ok(log.contains("SUB=10.244.6.0/24") && stdin.contains("peer-marker"))
    })
    .await?;

    // Peer node goes away -> SubnetRemove fires with the peer subnet.
    api.delete_node("e2e-peer").await?;
    netutil::wait_until("subnet-remove hook log", Duration::from_secs(15), || {
        let log = fs::read_to_string(&del_log).unwrap_or_default();
        Ok(log.contains("10.244.6.0/24"))
    })
    .await?;

    assert_eq!(daemon.shutdown(Duration::from_secs(15))?, 0);
    Ok(())
}
