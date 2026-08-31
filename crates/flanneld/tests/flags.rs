//! Flag-set and early-exit tests: defaults, `--version`,
//! `--kube-subnet-mgr`, env overlay (`FLANNELD_*`), help/unknown-flag
//! handling, tolerated klog flags, and the margin validation plus
//! etcd-rejection branches of `flanneld::run`.

use flannel_core::flags::FlagError;
use flanneld::flags_defs::{build_flag_set, options_from_flag_set};
use flanneld::Options;

fn parse(args: &[&str]) -> flannel_core::flags::FlagSet {
    let mut fs = build_flag_set();
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    fs.parse(&args).unwrap();
    fs
}

#[test]
fn defaults_match_go() {
    let fs = build_flag_set();
    assert_eq!(fs.get_int("subnet-lease-renew-margin"), 60);
    assert_eq!(fs.get_string("subnet-file"), "/run/flannel/subnet.env");
    assert_eq!(
        fs.get_string("net-config-path"),
        "/etc/kube-flannel/net-conf.json"
    );
    assert_eq!(
        fs.get_string("kube-annotation-prefix"),
        "flannel.alpha.coreos.com"
    );
    assert_eq!(fs.get_string("healthz-ip"), "0.0.0.0");
    assert_eq!(fs.get_int("healthz-port"), 0);
    assert_eq!(fs.get_int("iptables-resync"), 5);
    assert!(!fs.get_bool("kube-subnet-mgr"));
    assert!(!fs.get_bool("version"));
    assert!(!fs.get_bool("ip-masq"));
    assert!(fs.get_bool("iptables-forward-rules"));
    assert!(fs.get_bool("set-node-network-unavailable"));
    assert!(fs.get_slice("iface").is_empty());
}

#[test]
fn version_and_kube_subnet_mgr_parse() {
    let fs = parse(&["--version"]);
    assert!(options_from_flag_set(&fs).version);

    let fs = parse(&["--kube-subnet-mgr", "--kube-api-url=http://1.2.3.4:8080"]);
    let opts = options_from_flag_set(&fs);
    assert!(opts.kube_subnet_mgr);
    assert_eq!(opts.kube_api_url, "http://1.2.3.4:8080");
}

#[test]
fn iface_slice_accumulates() {
    let fs = parse(&["--iface=eth0", "--iface=eth1", "--iface-regex=^en.*"]);
    let opts = options_from_flag_set(&fs);
    assert_eq!(opts.iface, vec!["eth0".to_string(), "eth1".to_string()]);
    assert_eq!(opts.iface_regex, vec!["^en.*".to_string()]);
}

#[test]
fn env_overlay_sets_flags() {
    // Env mutation is process-global; keep the mutation scoped.
    std::env::set_var("FLANNELD_SUBNET_LEASE_RENEW_MARGIN", "120");
    std::env::set_var("FLANNELD_IFACE", "eth7");
    let mut fs = build_flag_set();
    let errs = fs.set_flags_from_env("FLANNELD");
    std::env::remove_var("FLANNELD_SUBNET_LEASE_RENEW_MARGIN");
    std::env::remove_var("FLANNELD_IFACE");
    assert!(errs.is_empty(), "{errs:?}");
    let opts = options_from_flag_set(&fs);
    assert_eq!(opts.subnet_lease_renew_margin, 120);
    assert_eq!(opts.iface, vec!["eth7".to_string()]);
}

#[test]
fn help_and_unknown_flags() {
    let mut fs = build_flag_set();
    assert!(matches!(
        fs.parse(&["--help".to_string()]),
        Err(FlagError::Help)
    ));

    let mut fs = build_flag_set();
    let err = fs.parse(&["--no-such-flag".to_string()]).unwrap_err();
    assert!(!matches!(err, FlagError::Help));

    // klog flags are tolerated (registered unknowns), with and w/o value.
    let fs = parse(&["--v=2", "--logtostderr"]);
    let _ = options_from_flag_set(&fs);
}

#[test]
fn parsed_options_install_signal_handlers() {
    // Go parity: the standalone binary installs its SIGINT/SIGTERM
    // handlers. Not a CLI flag (upstream has none): always `true` from
    // the flag set; embedders flip the `Options` field in code.
    let opts = options_from_flag_set(&parse(&[]));
    assert!(opts.install_signal_handlers);

    let fs = parse(&["--kube-subnet-mgr", "--ip-masq"]);
    assert!(options_from_flag_set(&fs).install_signal_handlers);
}

#[test]
fn default_options_carry_registry_defaults() {
    // Options::default() must share ONE source of truth with the CLI
    // flag registry (Go main.go init()): a hand-mirrored Default once
    // zeroed margin/resync, which insta-exits at the daemon's
    // `margin <= 0` check and busy-loops the iptables resync.
    let parsed = options_from_flag_set(&parse(&[]));
    assert_eq!(Options::default(), parsed);

    let d = Options::default();
    assert_eq!(d.subnet_lease_renew_margin, 60, "Go main.go:127 default");
    assert!(d.subnet_lease_renew_margin > 0);
    assert_eq!(d.iptables_resync_seconds, 5, "Go main.go:137 default");
    assert!(d.iptables_resync_seconds > 0);
    assert_eq!(d.subnet_file, "/run/flannel/subnet.env");
    assert_eq!(d.net_config_path, "/etc/kube-flannel/net-conf.json");
    assert_eq!(d.healthz_ip, "0.0.0.0");
    assert_eq!(d.healthz_port, 0);
    assert_eq!(
        d.etcd_endpoints,
        "http://127.0.0.1:4001,http://127.0.0.1:2379"
    );
    assert!(d.iptables_forward_rules);
    assert!(d.set_node_network_unavailable);
    assert!(d.install_signal_handlers, "Go parity, not a CLI flag");
}

#[tokio::test]
async fn run_prints_version_and_exits_zero() {
    let opts = Options {
        version: true,
        ..Default::default()
    };
    let code = flanneld::run(opts, tokio_util::sync::CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(code, 0);
}

#[tokio::test]
async fn run_rejects_out_of_range_margin() {
    let cancel = tokio_util::sync::CancellationToken::new();
    // Go: margin >= 24*60 or <= 0 -> os.Exit(1).
    for margin in [0i64, -5, 24 * 60, 24 * 60 + 1] {
        let opts = Options {
            subnet_lease_renew_margin: margin,
            ..Default::default()
        };
        let code = flanneld::run(opts, cancel.clone()).await.unwrap();
        assert_eq!(code, 1, "margin {margin} must exit 1");
    }
}

#[tokio::test]
async fn run_accepts_boundary_margins_but_rejects_etcd() {
    // 1 and 1439 pass validation; with kube-subnet-mgr unset the etcd
    // branch is rejected by the port -> also exit 1, but only AFTER the
    // margin check (a bad margin would fail first, tested above).
    for margin in [1i64, 1439] {
        let opts = Options {
            subnet_lease_renew_margin: margin,
            ..Default::default()
        };
        let code = flanneld::run(opts, tokio_util::sync::CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(code, 1, "margin {margin}: etcd unsupported, exit 1");
    }
}
