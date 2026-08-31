//! CLI flag registration and `Options` collection. Port of the flag
//! block in flannel `main.go` `init()` (upstream cdf76059): same flag
//! names, defaults and help texts. etcd flags are still registered for
//! CLI compatibility but flannel-rust only supports the kube subnet
//! manager (using them is rejected at runtime, see `daemon::run`).
//!
//! Go's klog flags are accepted but ignored: they are registered as
//! tolerated unknowns on the flag set (Go registers them on the default
//! flag set via `log.InitFlags` and copies `v`/`vmodule` over).

use flannel_core::flags::FlagSet;

/// klog flags flanneld tolerates on the command line without effect
/// (tracing replaces klog; `v` etc. have no Rust equivalent wired up).
pub const KLOG_TOLERATED_FLAGS: &[&str] = &[
    "v",
    "vmodule",
    "logtostderr",
    "alsologtostderr",
    "stderrthreshold",
    "log_dir",
    "log_file",
    "log_file_max_size",
    "add_dir_header",
    "skip_headers",
    "skip_log_headers",
    "one_output",
];

/// Go: the `flannelFlags` registrations in `init()`, in Go order with
/// exact Go defaults and usage strings.
pub fn build_flag_set() -> FlagSet {
    let mut fs = FlagSet::new("flannel");
    fs.register_string(
        "etcd-endpoints",
        "http://127.0.0.1:4001,http://127.0.0.1:2379",
        "a comma-delimited list of etcd endpoints",
    );
    fs.register_string("etcd-prefix", "/coreos.com/network", "etcd prefix");
    fs.register_string(
        "etcd-keyfile",
        "",
        "SSL key file used to secure etcd communication",
    );
    fs.register_string(
        "etcd-certfile",
        "",
        "SSL certification file used to secure etcd communication",
    );
    fs.register_string(
        "etcd-cafile",
        "",
        "SSL Certificate Authority file used to secure etcd communication",
    );
    fs.register_string("etcd-username", "", "username for BasicAuth to etcd");
    fs.register_string("etcd-password", "", "password for BasicAuth to etcd");
    fs.register_slice(
        "iface",
        "interface to use (IP or name) for inter-host communication. Can be \
         specified multiple times to check each option in order. Returns the \
         first match found.",
    );
    fs.register_slice(
        "iface-regex",
        "regex expression to match the first interface to use (IP or name) for \
         inter-host communication. Can be specified multiple times to check each \
         regex in order. Returns the first match found. Regexes are checked after \
         specific interfaces specified by the iface option have already been checked.",
    );
    fs.register_string(
        "iface-can-reach",
        "",
        "detect interface to use (IP or name) for inter-host communication based \
         on which will be used for provided IP. This is exactly the interface to \
         use of command 'ip route get <ip-address>'",
    );
    fs.register_string(
        "subnet-file",
        "/run/flannel/subnet.env",
        "filename where env variables (subnet, MTU, ... ) will be written to",
    );
    fs.register_string(
        "public-ip",
        "",
        "IP accessible by other nodes for inter-host communication",
    );
    fs.register_string(
        "public-ipv6",
        "",
        "IPv6 accessible by other nodes for inter-host communication",
    );
    fs.register_int(
        "subnet-lease-renew-margin",
        60,
        "subnet lease renewal margin, in minutes, ranging from 1 to 1439",
    );
    fs.register_bool(
        "ip-masq",
        false,
        "setup IP masquerade rule for traffic destined outside of overlay network",
    );
    fs.register_bool(
        "ip-masq-fully-random-disable",
        false,
        "disable fully-random mode for MASQUERADE",
    );
    fs.register_bool(
        "kube-subnet-mgr",
        false,
        "contact the Kubernetes API for subnet assignment instead of etcd.",
    );
    fs.register_string(
        "kube-api-url",
        "",
        "Kubernetes API server URL. Does not need to be specified if flannel is \
         running in a pod.",
    );
    fs.register_string(
        "kube-annotation-prefix",
        "flannel.alpha.coreos.com",
        "Kubernetes annotation prefix. Can contain single slash \"/\", otherwise \
         it will be appended at the end.",
    );
    fs.register_string(
        "kubeconfig-file",
        "",
        "kubeconfig file location. Does not need to be specified if flannel is \
         running in a pod.",
    );
    fs.register_bool("version", false, "print version and exit");
    fs.register_string(
        "healthz-ip",
        "0.0.0.0",
        "the IP address for healthz server to listen",
    );
    fs.register_int(
        "healthz-port",
        0,
        "the port for healthz server to listen(0 to disable)",
    );
    fs.register_int(
        "iptables-resync",
        5,
        "resync period for iptables rules, in seconds",
    );
    fs.register_bool(
        "iptables-forward-rules",
        true,
        "add default accept rules to FORWARD chain in iptables",
    );
    fs.register_bool(
        "ip-blackhole-route",
        false,
        "add blackroute route ont the node for the local podCIDR",
    );
    fs.register_string(
        "net-config-path",
        "/etc/kube-flannel/net-conf.json",
        "path to the network configuration file",
    );
    fs.register_bool(
        "set-node-network-unavailable",
        true,
        "set NodeNetworkUnavailable after ready",
    );
    fs.with_tolerated_unknown(KLOG_TOLERATED_FLAGS)
}

/// Parsed command line configuration (Go `CmdLineOpts`). Plain data.
///
/// Deviation from Go (no upstream counterpart): `install_signal_handlers`
/// lets an embedding process own SIGINT/SIGTERM. Every other field keeps
/// its Go zero value; this one defaults to `true` so the default path is
/// exactly Go's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Options {
    pub etcd_endpoints: String,
    pub etcd_prefix: String,
    pub etcd_keyfile: String,
    pub etcd_certfile: String,
    pub etcd_cafile: String,
    pub etcd_username: String,
    pub etcd_password: String,
    pub version: bool,
    pub kube_subnet_mgr: bool,
    pub kube_api_url: String,
    pub kube_annotation_prefix: String,
    pub kubeconfig_file: String,
    pub iface: Vec<String>,
    pub iface_regex: Vec<String>,
    pub iface_can_reach: String,
    pub ip_masq: bool,
    pub ip_masq_random_fully_disable: bool,
    pub subnet_file: String,
    pub public_ip: String,
    pub public_ipv6: String,
    pub subnet_lease_renew_margin: i64,
    pub healthz_ip: String,
    pub healthz_port: i64,
    pub iptables_resync_seconds: i64,
    pub iptables_forward_rules: bool,
    pub blackhole_route: bool,
    pub net_config_path: String,
    pub set_node_network_unavailable: bool,
    /// Port extension, NOT a CLI flag (upstream flanneld has no such
    /// flag and its CLI surface must not change): when `false`, flanneld
    /// installs no SIGINT/SIGTERM handlers and the embedder (e.g.
    /// init-pro, driving a `CancellationToken` from `tokio::signal`)
    /// cancels `run` itself. Defaults to `true` (Go parity).
    pub install_signal_handlers: bool,
}

/// `Default` delegates to the CLI flag registry so there is ONE source
/// of Go's flag defaults (main.go `init()`): a hand-mirrored `Default`
/// silently drifts, and a derived one would zero
/// `subnet_lease_renew_margin` / `iptables_resync_seconds` — tripping
/// the daemon's `margin <= 0` startup check (Go main.go:232-235) and
/// busy-looping the resync period. The embedder-only
/// `install_signal_handlers: true` comes from `options_from_flag_set`
/// (Go parity; upstream has no such flag).
impl Default for Options {
    fn default() -> Self {
        options_from_flag_set(&build_flag_set())
    }
}

/// Collect the parsed flag values into [`Options`] (Go binds the flags
/// directly into `opts`; the Rust port reads them back after parsing).
pub fn options_from_flag_set(fs: &FlagSet) -> Options {
    Options {
        etcd_endpoints: fs.get_string("etcd-endpoints"),
        etcd_prefix: fs.get_string("etcd-prefix"),
        etcd_keyfile: fs.get_string("etcd-keyfile"),
        etcd_certfile: fs.get_string("etcd-certfile"),
        etcd_cafile: fs.get_string("etcd-cafile"),
        etcd_username: fs.get_string("etcd-username"),
        etcd_password: fs.get_string("etcd-password"),
        version: fs.get_bool("version"),
        kube_subnet_mgr: fs.get_bool("kube-subnet-mgr"),
        kube_api_url: fs.get_string("kube-api-url"),
        kube_annotation_prefix: fs.get_string("kube-annotation-prefix"),
        kubeconfig_file: fs.get_string("kubeconfig-file"),
        iface: fs.get_slice("iface"),
        iface_regex: fs.get_slice("iface-regex"),
        iface_can_reach: fs.get_string("iface-can-reach"),
        ip_masq: fs.get_bool("ip-masq"),
        ip_masq_random_fully_disable: fs.get_bool("ip-masq-fully-random-disable"),
        subnet_file: fs.get_string("subnet-file"),
        public_ip: fs.get_string("public-ip"),
        public_ipv6: fs.get_string("public-ipv6"),
        subnet_lease_renew_margin: fs.get_int("subnet-lease-renew-margin"),
        healthz_ip: fs.get_string("healthz-ip"),
        healthz_port: fs.get_int("healthz-port"),
        iptables_resync_seconds: fs.get_int("iptables-resync"),
        iptables_forward_rules: fs.get_bool("iptables-forward-rules"),
        blackhole_route: fs.get_bool("ip-blackhole-route"),
        net_config_path: fs.get_string("net-config-path"),
        set_node_network_unavailable: fs.get_bool("set-node-network-unavailable"),
        // Go parity default; deliberately not a CLI flag (upstream has
        // no such flag). Embedders flip this field directly in code.
        install_signal_handlers: true,
    }
}
