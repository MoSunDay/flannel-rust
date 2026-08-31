//! Tests for netconf parsing, subnet.env parsing, delegate config
//! building and CNI version comparison. Pure; no env/iptables needed.

use super::*;
use serde_json::json;

fn netconf(cni_version: &str, delegate: Value) -> NetConf {
    let mut map = Map::new();
    if let Value::Object(delegate) = delegate {
        map = delegate;
    }
    NetConf {
        cni_version: cni_version.to_string(),
        name: "ftest".to_string(),
        plugin_type: "flannel".to_string(),
        delegate: map,
    }
}

fn v4_env() -> FlannelSubnetEnv {
    FlannelSubnetEnv {
        network: Some("10.244.0.0/16".parse().unwrap()),
        subnet: Some("10.244.7.0/24".parse().unwrap()),
        ..Default::default()
    }
}

#[test]
fn netconf_parses_with_and_without_delegate() {
    let bare =
        load_flannel_net_conf(br#"{"cniVersion":"0.4.0","name":"f","type":"flannel"}"#).unwrap();
    assert_eq!(bare.cni_version, "0.4.0");
    assert_eq!(bare.name, "f");
    assert_eq!(bare.plugin_type, "flannel");
    assert!(bare.delegate.is_empty());

    let with = load_flannel_net_conf(
        br#"{"cniVersion":"1.0.0","name":"f","type":"flannel",
             "delegate":{"isDefaultGateway":true,"hairpinMode":true}}"#,
    )
    .unwrap();
    assert_eq!(with.delegate.len(), 2);
    assert_eq!(with.delegate["hairpinMode"], json!(true));

    // cniVersion missing defaults to 1.0.0; unknown fields are ignored.
    let minimal = load_flannel_net_conf(br#"{"name":"f","bogus":1}"#).unwrap();
    assert_eq!(minimal.cni_version, "1.0.0");

    assert!(load_flannel_net_conf(b"not json").is_err());
}

#[test]
fn subnet_env_full_v4_v6_mtu_ipmasq() {
    let env = parse_subnet_env(
        "FLANNEL_NETWORK=10.244.0.0/16\n\
         FLANNEL_SUBNET=10.244.7.1/24\n\
         FLANNEL_IPV6_NETWORK=fc00::/48\n\
         FLANNEL_IPV6_SUBNET=fc00:0:0:1::1/64\n\
         FLANNEL_MTU=1450\n\
         FLANNEL_IPMASQ=true\n",
    )
    .unwrap();
    assert_eq!(env.network, Some("10.244.0.0/16".parse().unwrap()));
    // Host bits of the lease address are masked (upstream net.ParseCIDR).
    assert_eq!(env.subnet, Some("10.244.7.0/24".parse().unwrap()));
    assert_eq!(env.ipv6_network, Some("fc00::/48".parse().unwrap()));
    assert_eq!(env.ipv6_subnet, Some("fc00:0:0:1::/64".parse().unwrap()));
    assert_eq!(env.mtu, Some(1450));
    assert!(env.ipmasq);
}

#[test]
fn subnet_env_defaults_and_missing_keys() {
    let env = parse_subnet_env("FLANNEL_SUBNET=10.244.7.1/24\n").unwrap();
    assert!(env.network.is_none());
    assert_eq!(env.mtu, None);
    assert!(!env.ipmasq);
    // Empty lines and lines without '=' are ignored.
    let env = parse_subnet_env("\nno equals sign here\nFLANNEL_IPMASQ=false\n").unwrap();
    assert!(!env.ipmasq);
}

#[test]
fn subnet_env_unknown_key_ignored() {
    let env = parse_subnet_env("FLANNEL_FUTURE=whatever\nFLANNEL_SUBNET=10.244.9.1/24\n").unwrap();
    assert_eq!(env.subnet, Some("10.244.9.0/24".parse().unwrap()));
}

#[test]
fn subnet_env_malformed_values_error() {
    assert!(parse_subnet_env("FLANNEL_NETWORK=garbage\n").is_err());
    assert!(parse_subnet_env("FLANNEL_SUBNET=10.244.7.0\n").is_err());
    assert!(parse_subnet_env("FLANNEL_IPV6_SUBNET=10.244.0.0/16\n").is_err());
    assert!(parse_subnet_env("FLANNEL_MTU=abc\n").is_err());
    assert!(parse_subnet_env("FLANNEL_MTU=-1\n").is_err());
    assert!(parse_subnet_env("FLANNEL_IPMASQ=maybe\n").is_err());
}

#[test]
fn subnet_env_missing_file_errors() {
    let err = load_flannel_subnet_env(Path::new("/nonexistent/subnet.env")).unwrap_err();
    assert!(format!("{err:#}").contains("failed to read subnet.env"));
}

#[test]
fn subnet_env_load_reads_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("subnet.env");
    std::fs::write(&path, "FLANNEL_NETWORK=10.244.0.0/16\nFLANNEL_MTU=1400\n").unwrap();
    let env = load_flannel_subnet_env(&path).unwrap();
    assert_eq!(env.mtu, Some(1400));
}

#[test]
fn default_subnet_env_path_respects_override() {
    // No env mutation: only the default branch is checked here (the
    // FLANNEL_SUBNET_FILE branch is exercised by the e2e tests).
    if std::env::var_os("FLANNEL_SUBNET_FILE").is_none() {
        assert_eq!(default_subnet_env_path(), PathBuf::from(DEFAULT_SUBNET_ENV));
    }
}

#[test]
fn delegate_conf_ranges_v4() {
    let conf = netconf("0.4.0", Value::Null);
    let value = build_delegate_conf(&conf, &v4_env()).unwrap();
    assert_eq!(value["cniVersion"], json!("0.4.0"));
    assert_eq!(value["name"], json!("ftest"));
    assert_eq!(value["type"], json!("bridge"));
    assert_eq!(value["ipMasq"], json!(false));
    assert_eq!(value["isGateway"], json!(true)); // bridge default (upstream)
    assert!(value.get("mtu").is_none()); // FLANNEL_MTU absent -> no mtu
    assert_eq!(
        value["ipam"]["ranges"],
        json!([[{"subnet": "10.244.7.0/24"}]])
    );
    assert_eq!(value["ipam"]["type"], json!("host-local"));
    assert_eq!(value["ipam"]["routes"], json!([{"dst": "0.0.0.0/0"}]));
    assert!(value["ipam"].get("subnet").is_none());
}

#[test]
fn delegate_conf_dual_stack_with_mtu() {
    let conf = netconf("1.0.0", Value::Null);
    let env = FlannelSubnetEnv {
        network: Some("10.244.0.0/16".parse().unwrap()),
        subnet: Some("10.244.7.0/24".parse().unwrap()),
        ipv6_network: Some("fc00::/48".parse().unwrap()),
        ipv6_subnet: Some("fc00:0:0:1::/64".parse().unwrap()),
        mtu: Some(1450),
        ipmasq: true,
    };
    let value = build_delegate_conf(&conf, &env).unwrap();
    assert_eq!(value["mtu"], json!(1450));
    assert_eq!(
        value["ipam"]["ranges"],
        json!([[{"subnet": "10.244.7.0/24"}], [{"subnet": "fc00:0:0:1::/64"}]])
    );
    assert_eq!(
        value["ipam"]["routes"],
        json!([{"dst": "0.0.0.0/0"}, {"dst": "::/0"}])
    );
}

#[test]
fn delegate_conf_v6_only() {
    let conf = netconf("1.0.0", Value::Null);
    let env = FlannelSubnetEnv {
        ipv6_network: Some("fc00::/48".parse().unwrap()),
        ipv6_subnet: Some("fc00:0:0:1::/64".parse().unwrap()),
        ..Default::default()
    };
    let value = build_delegate_conf(&conf, &env).unwrap();
    assert_eq!(
        value["ipam"]["ranges"],
        json!([[{"subnet": "fc00:0:0:1::/64"}]])
    );
    assert_eq!(value["ipam"]["routes"], json!([{"dst": "::/0"}]));
}

#[test]
fn delegate_conf_legacy_flat_subnet() {
    let conf = netconf("0.2.0", Value::Null);
    let value = build_delegate_conf(&conf, &v4_env()).unwrap();
    assert_eq!(value["ipam"]["subnet"], json!("10.244.7.0/24"));
    assert!(value["ipam"].get("ranges").is_none());
}

#[test]
fn delegate_conf_legacy_v6_only_errors() {
    let conf = netconf("0.2.0", Value::Null);
    let env = FlannelSubnetEnv {
        ipv6_subnet: Some("fc00:0:0:1::/64".parse().unwrap()),
        ..Default::default()
    };
    let err = build_delegate_conf(&conf, &env).unwrap_err();
    assert!(format!("{err:#}").contains("IPv6 subnets are not supported"));
}

#[test]
fn delegate_conf_no_subnet_errors() {
    let conf = netconf("1.0.0", Value::Null);
    let err = build_delegate_conf(&conf, &FlannelSubnetEnv::default()).unwrap_err();
    assert!(format!("{err:#}").contains("no subnet found"));
}

#[test]
fn delegate_conf_user_overrides_preserved_but_ipmasq_mtu_forced() {
    let conf = netconf(
        "0.4.0",
        json!({"hairpinMode": true, "ipMasq": true, "mtu": 9999,
              "isDefaultGateway": true, "isGateway": false}),
    );
    let env = FlannelSubnetEnv {
        mtu: Some(1450),
        ..v4_env()
    };
    let value = build_delegate_conf(&conf, &env).unwrap();
    assert_eq!(value["hairpinMode"], json!(true));
    assert_eq!(value["isDefaultGateway"], json!(true));
    assert_eq!(value["isGateway"], json!(false)); // user value survives
    assert_eq!(value["ipMasq"], json!(false)); // forced false
    assert_eq!(value["mtu"], json!(1450)); // forced from subnet.env
                                           // Without FLANNEL_MTU the user mtu override survives (upstream only
                                           // overrides mtu when the env value is present), while ipMasq is
                                           // forced regardless.
    let value = build_delegate_conf(&conf, &v4_env()).unwrap();
    assert_eq!(value["mtu"], json!(9999));
    assert_eq!(value["ipMasq"], json!(false));
}

#[test]
fn delegate_conf_user_ipam_merged() {
    let conf = netconf(
        "1.0.0",
        json!({"ipam": {"dataDir": "/tmp/ipam", "resolvConf": "/dev/null"}}),
    );
    let value = build_delegate_conf(&conf, &v4_env()).unwrap();
    assert_eq!(value["ipam"]["type"], json!("host-local")); // injected
    assert_eq!(value["ipam"]["dataDir"], json!("/tmp/ipam")); // user kept
    assert_eq!(value["ipam"]["resolvConf"], json!("/dev/null"));
}

#[test]
fn delegate_conf_user_routes_preserved() {
    let conf = netconf("1.0.0", json!({"routes": [{"dst": "192.168.0.0/16"}]}));
    let value = build_delegate_conf(&conf, &v4_env()).unwrap();
    // User routes in the delegate win; flannel adds no default routes.
    assert_eq!(value["routes"], json!([{"dst": "192.168.0.0/16"}]));
    assert!(value["ipam"].get("routes").is_none());
}

/// `delegate.ipam.routes` is spec-standard user ipam config: it must
/// survive the merge instead of being clobbered by flannel's default
/// routes (which are only injected when the user supplied none).
#[test]
fn delegate_conf_user_ipam_routes_preserved() {
    let user_routes = json!([
        {"dst": "192.168.0.0/16"},
        {"dst": "10.1.0.0/16", "gw": "10.1.0.1"}
    ]);
    let conf = netconf(
        "1.0.0",
        json!({"ipam": {"routes": user_routes.clone(), "dataDir": "/tmp/ipam"}}),
    );
    let value = build_delegate_conf(&conf, &v4_env()).unwrap();
    // User ipam routes survive verbatim; no 0.0.0.0/0 default injected.
    assert_eq!(value["ipam"]["routes"], user_routes);
    // Other user ipam keys and flannel's range injection still apply.
    assert_eq!(value["ipam"]["dataDir"], json!("/tmp/ipam"));
    assert_eq!(
        value["ipam"]["ranges"],
        json!([[{"subnet": "10.244.7.0/24"}]])
    );
    // Nothing is duplicated at the delegate top level either.
    assert!(value.get("routes").is_none());

    // Dual stack: user routes also suppress the ::/0 default (and vice
    // versa: delegate-level routes suppress ipam routes injection).
    let env = FlannelSubnetEnv {
        ipv6_subnet: Some("fc00:0:0:1::/64".parse().unwrap()),
        ..v4_env()
    };
    let value = build_delegate_conf(&conf, &env).unwrap();
    assert_eq!(value["ipam"]["routes"], user_routes);

    let conf = netconf(
        "1.0.0",
        json!({"routes": [{"dst": "192.168.0.0/16"}],
               "ipam": {"routes": [{"dst": "10.2.0.0/16"}]}}),
    );
    let value = build_delegate_conf(&conf, &env).unwrap();
    assert_eq!(value["ipam"]["routes"], json!([{"dst": "10.2.0.0/16"}]));
    assert_eq!(value["routes"], json!([{"dst": "192.168.0.0/16"}]));
}

#[test]
fn minimal_delegate_conf_keeps_user_overrides_only() {
    let conf = netconf(
        "0.4.0",
        json!({"ipam": {"type": "host-local", "dataDir": "/x"}, "mtu": 1200}),
    );
    let value = minimal_delegate_conf(&conf).unwrap();
    assert_eq!(value["cniVersion"], json!("0.4.0"));
    assert_eq!(value["name"], json!("ftest"));
    assert_eq!(value["type"], json!("bridge"));
    assert_eq!(value["mtu"], json!(1200));
    assert_eq!(
        value["ipam"],
        json!({"type": "host-local", "dataDir": "/x"})
    );
    // No flannel injection of ranges/subnet/routes.
    assert!(value["ipam"].get("ranges").is_none());
    assert!(value.get("ipMasq").is_none());
}

#[test]
fn version_at_least_orders_cni_versions() {
    assert!(version_at_least("1.0.0", "0.3.0"));
    assert!(version_at_least("0.3.0", "0.3.0"));
    assert!(version_at_least("0.3.1", "0.3.0"));
    assert!(version_at_least("0.4.0", "0.3.0"));
    assert!(!version_at_least("0.2.0", "0.3.0"));
    assert!(!version_at_least("0.2.9", "0.3.0"));
    // Missing/non-numeric components.
    assert!(version_at_least("0.3", "0.3.0"));
    assert!(version_at_least("1.0", "0.3.0"));
    assert!(version_at_least("10.0.0", "9.9.9")); // numeric, not lexical
    assert!(!version_at_least("0.x.0", "0.3.0"));
}
