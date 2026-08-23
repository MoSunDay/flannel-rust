//! Tests for charon.rs: look_path/find_exec_path, connection-name
//! formatting, and a spawn/TERM lifecycle test with a scripted charon.

use super::{
    find_exec_path, find_exec_path_in, format_child_sa_conf_name, format_connection_name,
    look_path_in, spawn_charon,
};
use crate::ip::IP4Net;
use crate::lease::{Lease, LeaseAttrs};
use std::ffi::OsStr;
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, UNIX_EPOCH};
use tokio_util::sync::CancellationToken;

fn make_executable(path: &str) {
    std::fs::write(path, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn look_path_absolute_and_path_search() {
    let dir = std::env::temp_dir().join(format!("charon-lookpath-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let exe = dir.join("fakecharon");
    make_executable(exe.to_str().unwrap());
    // absolute candidate resolves when executable
    assert_eq!(
        look_path_in(exe.to_str().unwrap(), None).as_deref(),
        Some(exe.to_str().unwrap())
    );
    // missing or non-executable absolute candidates fail
    assert_eq!(look_path_in(dir.join("nope").to_str().unwrap(), None), None);
    let plain = dir.join("notexec");
    std::fs::write(&plain, "x").unwrap();
    assert_eq!(look_path_in(plain.to_str().unwrap(), None), None);
    // bare name found via an explicit PATH (no process-env mutation, so
    // this cannot race with concurrently spawned child processes)
    assert_eq!(
        look_path_in("fakecharon", Some(dir.as_os_str())).as_deref(),
        Some(exe.to_str().unwrap())
    );
    assert_eq!(
        look_path_in("definitely-missing-binary", Some(dir.as_os_str())),
        None
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn find_exec_path_matches_candidate_scan() {
    // Self-consistent check: find_exec_path must pick exactly the first
    // candidate look_path resolves (the container has no charon, so the
    // empty-PATH case below yields an error).
    let path = std::env::var_os("PATH");
    let expected = ["charon"]
        .into_iter()
        .chain([
            "/usr/lib/strongswan/charon",
            "/usr/lib/ipsec/charon",
            "/usr/libexec/strongswan/charon",
            "/usr/libexec/ipsec/charon",
        ])
        .find_map(|c| look_path_in(c, path.as_deref()));
    match expected {
        Some(p) => assert_eq!(find_exec_path().unwrap(), p),
        None => assert!(find_exec_path().is_err()),
    }
    // with an empty PATH and no installed charon the fixed paths alone
    // must fail (true in the CI container)
    if [
        "/usr/lib/strongswan/charon",
        "/usr/lib/ipsec/charon",
        "/usr/libexec/strongswan/charon",
        "/usr/libexec/ipsec/charon",
    ]
    .iter()
    .all(|p| look_path_in(p, Some(OsStr::new(""))).is_none())
    {
        assert!(find_exec_path_in(Some(OsStr::new(""))).is_err());
    }
}

fn lease(public_ip: &str, subnet: &str) -> Lease {
    Lease {
        enable_ipv4: true,
        enable_ipv6: false,
        subnet: subnet.parse::<IP4Net>().unwrap(),
        ipv6_subnet: Default::default(),
        attrs: LeaseAttrs {
            public_ip: public_ip.parse().unwrap(),
            ..Default::default()
        },
        expiration: UNIX_EPOCH,
        asof: 0,
    }
}

#[test]
fn connection_names_match_go_format() {
    let local = lease("10.0.0.1", "10.1.0.0/24");
    let remote = lease("10.0.0.2", "10.2.0.0/24");
    assert_eq!(
        format_connection_name(&local, &remote),
        "10.0.0.1-10.1.0.0/24-10.2.0.0/24-10.0.0.2"
    );
    assert_eq!(
        format_child_sa_conf_name(&local, &remote),
        "10.1.0.0/24-10.2.0.0/24"
    );
}

/// Scripted "charon" that writes a marker when it receives SIGTERM, so
/// the ctx-cancellation watcher of spawn_charon can be verified.
#[tokio::test]
async fn spawn_charon_terminates_on_cancel() {
    let dir = std::env::temp_dir().join(format!("charon-spawn-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let marker = dir.join("terminated");
    let ready = dir.join("ready");
    let script = dir.join("charon");
    let _ = std::fs::remove_file(&marker);
    let _ = std::fs::remove_file(&ready);
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\ntrap 'kill $B 2>/dev/null; echo done > {m}; exit 0' TERM\necho ready > {r}\nsleep 1000 &\nB=$!\nwait $B\n",
            m = marker.display(),
            r = ready.display()
        ),
    )
    .unwrap();
    let mut perms = std::fs::metadata(&script).unwrap().permissions();
    perms.set_mode(0o755); // chmod without clobbering the script body
    std::fs::set_permissions(&script, perms).unwrap();
    let ctx = CancellationToken::new();
    spawn_charon(&ctx, script.to_str().unwrap()).expect("spawn scripted charon");
    // Wait until the trap is actually installed; a SIGTERM before that hits
    // the default action and the marker never appears (load-dependent race).
    for _ in 0..50 {
        if ready.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(ready.exists(), "scripted charon never became ready");
    ctx.cancel();
    // wait for the TERM trap to fire
    for _ in 0..50 {
        if marker.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(marker.exists(), "charon did not receive SIGTERM");
    assert_eq!(std::fs::read_to_string(&marker).unwrap().trim(), "done");
    let _ = std::fs::remove_dir_all(&dir);
}
