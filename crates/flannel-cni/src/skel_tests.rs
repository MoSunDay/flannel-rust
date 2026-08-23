//! Tests for the CNI skeleton: error JSON shape, env arg collection
//! (via a lookup closure, no process-env mutation) and dispatch with a
//! fake `bridge` delegate plugin.

use super::*;
use std::os::unix::fs::PermissionsExt;

#[test]
fn error_json_shape() {
    let value: serde_json::Value = serde_json::from_str(&error_json("0.4.0", 100, "boom")).unwrap();
    assert_eq!(value["cniVersion"], serde_json::json!("0.4.0"));
    assert_eq!(value["code"], serde_json::json!(100));
    assert_eq!(value["msg"], serde_json::json!("boom"));
    assert_eq!(value["details"], serde_json::json!(""));
    assert_eq!(value.as_object().unwrap().len(), 4);
}

fn lookup_from<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
    move |key| {
        pairs
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.to_string())
    }
}

#[test]
fn args_from_requires_command() {
    let err = args_from(lookup_from(&[("CNI_NETNS", "/ns")])).unwrap_err();
    assert!(format!("{err:#}").contains("CNI_COMMAND"));
    // Empty CNI_COMMAND also counts as missing.
    let err = args_from(lookup_from(&[("CNI_COMMAND", "")])).unwrap_err();
    assert!(format!("{err:#}").contains("CNI_COMMAND"));
}

#[test]
fn args_from_collects_all_vars() {
    let args = args_from(lookup_from(&[
        ("CNI_COMMAND", "ADD"),
        ("CNI_CONTAINERID", "cid123"),
        ("CNI_NETNS", "/var/run/netns/x"),
        ("CNI_IFNAME", "eth0"),
        ("CNI_ARGS", "K8S_POD_NAME=p"),
        ("CNI_PATH", "/opt/bin:/opt/bin2"),
    ]))
    .unwrap();
    assert_eq!(
        args,
        CniArgs {
            command: "ADD".into(),
            container_id: "cid123".into(),
            netns: "/var/run/netns/x".into(),
            if_name: "eth0".into(),
            args: "K8S_POD_NAME=p".into(),
            path: "/opt/bin:/opt/bin2".into(),
        }
    );
    // Missing optional vars default to empty strings.
    let args = args_from(lookup_from(&[("CNI_COMMAND", "VERSION")])).unwrap();
    assert_eq!(args.container_id, "");
    assert_eq!(args.path, "");
}

/// Write an executable fake `bridge` plugin: ADD echoes a fixed result
/// JSON, everything else exits 0.
fn write_fake_bridge(dir: &std::path::Path) -> std::path::PathBuf {
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
    script
}

#[test]
fn dispatch_del_via_fake_bridge() {
    // DEL with no subnet.env (default path absent for tests) exercises
    // the minimal_delegate_conf fallback and needs no env mutation: the
    // fake plugin is found through CniArgs.path.
    let dir = tempfile::tempdir().unwrap();
    write_fake_bridge(dir.path());
    let args = CniArgs {
        command: "DEL".into(),
        container_id: "cid".into(),
        netns: "/proc/1/ns/net".into(),
        if_name: "eth0".into(),
        args: String::new(),
        path: dir.path().to_str().unwrap().to_string(),
    };
    let conf = br#"{"cniVersion":"0.4.0","name":"f","type":"flannel"}"#;
    if std::path::Path::new("/run/flannel/subnet.env").exists() {
        eprintln!("skipping: real subnet.env present, DEL path differs");
        return;
    }
    assert_eq!(dispatch(&args, conf), 0);
}

#[test]
fn dispatch_version_and_unknown_command() {
    let conf = br#"{"cniVersion":"0.4.0","name":"f","type":"flannel"}"#;
    let args = |command: &str| CniArgs {
        command: command.to_string(),
        ..Default::default()
    };
    assert_eq!(dispatch(&args("VERSION"), conf), 0);
    // VERSION tolerates empty netconf.
    assert_eq!(dispatch(&args("VERSION"), b""), 0);

    assert_eq!(dispatch(&args("FROBNICATE"), conf), 1);

    // Bad netconf on a real command -> exit 1 with code 1 JSON.
    assert_eq!(dispatch(&args("ADD"), b"{not json"), 1);
}
