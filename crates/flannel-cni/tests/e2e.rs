//! End-to-end tests: skel dispatch against a fake bridge plugin, and a
//! real ADD/DEL through the actual bridge + host-local plugins inside a
//! network namespace.
//!
//! The tests here point FLANNEL_SUBNET_FILE at a temp file (the only
//! process-env mutation in the suite) and serialize on `ENV_LOCK`.
//! Live requirements are checked and the tests skip gracefully when
//! missing (no plugin tarball, no netns support).

use flannel_cni::skel::{dispatch, CniArgs};
use flannel_core::ip::{IP4Net, IP4};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use std::str::FromStr;
use std::sync::Mutex;

const PLUGIN_TGZ: &str = "/root/k3as/vendor/cache/cni-plugins-linux-amd64-v1.5.1.tgz";

/// Guards FLANNEL_SUBNET_FILE mutations: the tests below mutate the
/// process env, so they must not overlap.
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Restores FLANNEL_SUBNET_FILE on drop (also on panic).
struct SubnetEnvVarGuard;

impl Drop for SubnetEnvVarGuard {
    fn drop(&mut self) {
        std::env::remove_var("FLANNEL_SUBNET_FILE");
    }
}

fn random_container_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{:x}{:x}", std::process::id(), nanos)
}

/// Extract `bridge` + `host-local` from the CNI plugins tarball (via
/// `tar`, no extra deps). Returns false (skip) when unavailable.
fn extract_plugins(dir: &Path) -> bool {
    let out = Command::new("tar")
        .args([
            "xzf",
            PLUGIN_TGZ,
            "-C",
            dir.to_str().unwrap(),
            "./bridge",
            "./host-local",
        ])
        .output();
    match out {
        Ok(o) if o.status.success() => true,
        _ => {
            eprintln!("skipping e2e: CNI plugin tarball {PLUGIN_TGZ} unavailable");
            false
        }
    }
}

fn write_fake_bridge(dir: &Path) {
    let script = dir.join("bridge");
    std::fs::write(
        &script,
        "#!/bin/sh\ncat > /dev/null\n\
         case \"$CNI_COMMAND\" in\n\
         \x20 ADD) echo '{\"cniVersion\":\"0.4.0\",\"interfaces\":[{\"name\":\"eth0\"}],\"ips\":[]}' ;;\n\
         esac\nexit 0\n",
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// Skel dispatch (ADD/DEL/VERSION/unknown) against a fake bridge
/// plugin, with subnet.env supplied through FLANNEL_SUBNET_FILE.
#[test]
fn dispatch_add_del_with_fake_bridge() {
    let _lock = ENV_LOCK.lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    write_fake_bridge(dir.path());
    let env_file = dir.path().join("subnet.env");
    std::fs::write(
        &env_file,
        "FLANNEL_NETWORK=10.244.0.0/16\nFLANNEL_SUBNET=10.244.9.1/24\n",
    )
    .unwrap();
    std::env::set_var("FLANNEL_SUBNET_FILE", &env_file);
    let _guard = SubnetEnvVarGuard;

    let conf = br#"{"cniVersion":"0.4.0","name":"fd","type":"flannel"}"#;
    let mut args = CniArgs {
        command: "ADD".into(),
        container_id: random_container_id(),
        netns: "/proc/1/ns/net".into(),
        if_name: "eth0".into(),
        args: String::new(),
        path: dir.path().to_str().unwrap().to_string(),
    };
    assert_eq!(dispatch(&args, conf), 0);
    args.command = "DEL".into();
    assert_eq!(dispatch(&args, conf), 0);
    args.command = "VERSION".into();
    assert_eq!(dispatch(&args, conf), 0);
    args.command = "FROB".into();
    assert_eq!(dispatch(&args, conf), 1);
}

/// Full ADD + DEL through the real bridge/host-local plugins in a fresh
/// netns: the whole chain runs *inside* the netns (like `ip netns exec`),
/// so the bridge that cni-plugins >= 1.2 creates in the caller's
/// namespace lands in the scratch netns and dies with it. The result
/// must carry an eth0 IP inside the leased subnet.
#[test]
fn e2e_add_del_real_bridge_in_netns() {
    let _lock = ENV_LOCK.lock().unwrap();
    let dir = match tempfile::tempdir() {
        Ok(dir) => dir,
        Err(e) => {
            eprintln!("skipping e2e: tempdir: {e}");
            return;
        }
    };
    if !extract_plugins(dir.path()) {
        return;
    }
    let env_file = dir.path().join("subnet.env");
    std::fs::write(
        &env_file,
        "FLANNEL_NETWORK=10.244.0.0/16\n\
         FLANNEL_SUBNET=10.244.7.1/24\n\
         FLANNEL_MTU=1450\n\
         FLANNEL_IPMASQ=false\n",
    )
    .unwrap();
    std::env::set_var("FLANNEL_SUBNET_FILE", &env_file);
    let _guard = SubnetEnvVarGuard;

    let ns_name = format!("fcni-e2e-{}", random_container_id());
    if let Ok(old) = netns_rs::NetNs::get(&ns_name) {
        let _ = old.remove();
    }
    let ns = match netns_rs::NetNs::new(&ns_name) {
        Ok(ns) => ns,
        Err(e) => {
            eprintln!("skipping e2e: netns creation failed ({e})");
            return;
        }
    };
    let ns_path = ns.path().to_str().unwrap().to_string();

    let args = CniArgs {
        command: "ADD".into(),
        container_id: random_container_id(),
        netns: ns_path,
        if_name: "eth0".into(),
        args: String::new(),
        path: dir.path().to_str().unwrap().to_string(),
    };
    let conf = br#"{"cniVersion":"0.4.0","name":"ftest","type":"flannel"}"#;

    let result = match ns.run(|_| flannel_cni::cmd_add(&args, conf)) {
        Ok(Ok(value)) => value,
        Ok(Err(e)) => {
            let _ = ns.remove();
            panic!("cmd_add failed: {e:#}");
        }
        Err(e) => {
            let _ = ns.remove();
            panic!("entering netns for cmd_add failed: {e:#}");
        }
    };

    // The result must list an eth0 interface with an IP in 10.244.7.0/24.
    let subnet = IP4Net::from_str("10.244.7.0/24").unwrap();
    let interfaces = result["interfaces"].as_array().expect("interfaces array");
    let eth0_index = interfaces
        .iter()
        .position(|iface| iface["name"] == "eth0")
        .unwrap_or_else(|| panic!("no eth0 interface in result: {result}"));
    let has_ip = result["ips"]
        .as_array()
        .expect("ips array")
        .iter()
        .any(|ip| {
            let address = ip["address"].as_str().unwrap_or("");
            let Some((addr, _)) = address.split_once('/') else {
                return false;
            };
            ip["interface"].as_u64() == Some(eth0_index as u64)
                && addr
                    .parse::<IP4>()
                    .map(|v4| subnet.contains(v4))
                    .unwrap_or(false)
        });
    assert!(has_ip, "no eth0 IP in {subnet}: {result}");

    match ns.run(|_| flannel_cni::cmd_del(&args, conf)) {
        Ok(Ok(())) => {}
        Ok(Err(e)) => panic!("cmd_del failed: {e:#}"),
        Err(e) => panic!("entering netns for cmd_del failed: {e:#}"),
    }
    let _ = ns.remove();
}
