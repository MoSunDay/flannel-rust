//! Host-side helpers: unique names, netns guards, veth/bridge topologies,
//! `ip`/`ping` command wrappers, polling, CNI plugin extraction.
//!
//! All daemons in this harness run inside scratch netns so host network
//! state (iptables chains, routes) is never mutated; the only host-visible
//! objects are transient veth/bridge links, removed by the guards on Drop.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Unique-ish suffix (pid + nanoseconds hex) so parallel/rerun runs don't
/// collide (mirrors the dropin_e2e convention).
pub fn unique_suffix() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{:x}{:x}", std::process::id(), nanos)
}

/// Short suffix for interface names (IFNAMSIZ is 15 chars).
pub fn short_suffix() -> String {
    let s = unique_suffix();
    s.chars().rev().take(8).collect()
}

/// Run a host command; returns stdout, bails with stderr on failure.
pub fn run_cmd(cmd: &str, args: &[&str]) -> Result<String> {
    let out = std::process::Command::new(cmd)
        .args(args)
        .output()
        .with_context(|| format!("spawning {cmd}"))?;
    if !out.status.success() {
        bail!(
            "{cmd} {args:?} failed (exit {:?}): {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Run a command inside a named netns via `ip netns exec`.
pub fn run_in_ns(ns: &str, cmd: &str, args: &[&str]) -> Result<String> {
    let mut full: Vec<String> = vec!["netns".into(), "exec".into(), ns.into(), cmd.into()];
    full.extend(args.iter().map(|s| s.to_string()));
    let refs: Vec<&str> = full.iter().map(String::as_str).collect();
    run_cmd("ip", &refs)
}

/// RAII netns: created on `create`, removed on Drop (even on panic).
pub struct NsGuard {
    inner: Option<netns_rs::NetNs>,
    pub name: String,
}

impl NsGuard {
    pub fn create(prefix: &str) -> Result<Self> {
        let name = format!("{prefix}-{}", unique_suffix());
        // Remove a stale namespace of the same name from a crashed run.
        if let Ok(stale) = netns_rs::NetNs::get(&name) {
            let _ = stale.remove();
        }
        let ns = netns_rs::NetNs::new(&name).with_context(|| format!("creating netns {name}"))?;
        Ok(Self {
            inner: Some(ns),
            name,
        })
    }

    pub fn path(&self) -> PathBuf {
        self.inner
            .as_ref()
            .expect("NsGuard alive")
            .path()
            .to_path_buf()
    }
}

impl Drop for NsGuard {
    fn drop(&mut self) {
        if let Some(ns) = self.inner.take() {
            let _ = ns.remove();
        }
    }
}

/// One node of the two-node topology: a netns for the daemon, a fresh
/// empty netns for the pod (CNI ADD target), and the external veth iface.
pub struct Node {
    pub name: String,
    pub ns: NsGuard,
    pub pod_ns: NsGuard,
    pub ext_iface: String,
    pub pod_cidr: String,
}

/// Shared-bridge topology: two nodes are L2-adjacent on a host bridge
/// (`10.99.0.0/24`, host side `.254`), so the apiserver bound on the
/// bridge IP is reachable from both netns and the peers see each other's
/// external IPs on-link (required by host-gw).
pub struct BridgeTopology {
    pub bridge: String,
    pub bridge_ip: String,
    pub nodes: Vec<Node>,
}

impl Drop for BridgeTopology {
    fn drop(&mut self) {
        // veths die with their netns; the bridge removes host-side peers
        // plus its FORWARD accepts (see build_bridge_topology).
        let _ = run_cmd(
            "iptables",
            &["-D", "FORWARD", "-i", &self.bridge, "-j", "ACCEPT"],
        );
        let _ = run_cmd(
            "iptables",
            &["-D", "FORWARD", "-o", &self.bridge, "-j", "ACCEPT"],
        );
        let _ = run_cmd("ip", &["link", "del", &self.bridge]);
    }
}

/// Delete every link still holding `ip` (except `lo`). Both topology
/// builders use fixed subnet constants; a SIGKILLed run can leak its
/// bridge/veth with that address, and `ip addr add` on the new run then
/// creates a duplicate-IP routing blackhole. Reclaiming the address
/// first makes the harness self-healing after killed runs.
fn reclaim_addr(ip: &str) {
    let Ok(out) = run_cmd("ip", &["-o", "-4", "addr", "show", "scope", "global"]) else {
        return;
    };
    for line in out.lines() {
        // `ip -o -4 addr` line: `<ifindex>: <name> ... inet <ip>/<len> ...`
        let Some((_, rest)) = line.split_once(':') else {
            continue;
        };
        let Some(iface) = rest.split_whitespace().next() else {
            continue;
        };
        if iface == "lo" || !rest.contains(&format!("{ip}/")) {
            continue;
        }
        eprintln!("reclaim: deleting stale link {iface} holding {ip}");
        let _ = run_cmd("ip", &["link", "del", iface]);
    }
}

/// Build the two-node topology (stale-clean, panic-safe via guards).
pub fn build_bridge_topology(prefix: &str) -> Result<BridgeTopology> {
    let sfx = short_suffix();
    let bridge = format!("e2ebr{sfx}");
    let bridge_ip = "10.99.0.254";
    reclaim_addr(bridge_ip);
    run_cmd("ip", &["link", "add", &bridge, "type", "bridge"])
        .with_context(|| format!("creating bridge {bridge}"))?;
    // With br_netfilter active (net.bridge.bridge-nf-call-iptables=1),
    // frames forwarded by the bridge traverse the HOST iptables FORWARD
    // chain; on shared hosts that chain often drops unknown traffic
    // (e.g. policy DROP under k3s), silently blackholing the underlay
    // exchanges between the two node netns (vxlan/ipip/wireguard/udp
    // outer packets). Accept forwarding through our scratch bridge
    // explicitly; Drop removes the rules again.
    run_cmd(
        "iptables",
        &["-I", "FORWARD", "1", "-i", &bridge, "-j", "ACCEPT"],
    )
    .with_context(|| format!("accepting FORWARD in {bridge}"))?;
    run_cmd(
        "iptables",
        &["-I", "FORWARD", "1", "-o", &bridge, "-j", "ACCEPT"],
    )
    .with_context(|| format!("accepting FORWARD out {bridge}"))?;
    run_cmd("ip", &["addr", "add", "10.99.0.254/24", "dev", &bridge])?;
    run_cmd("ip", &["link", "set", &bridge, "up"])?;

    let mut nodes = Vec::new();
    for (i, (suffix_ip, cidr)) in [("1", "10.244.0.0/24"), ("2", "10.244.1.0/24")]
        .iter()
        .enumerate()
    {
        let node_name = format!("e2e-{prefix}-{}", i + 1);
        let ns = NsGuard::create(&format!("{prefix}-n{}", i + 1))?;
        let pod_ns = NsGuard::create(&format!("{prefix}-p{}", i + 1))?;
        let host_veth = format!("vh{sfx}{i}");
        let ns_iface = format!("e2e{i}{sfx}");
        let ext_ip = format!("10.99.0.{suffix_ip}");
        run_cmd(
            "ip",
            &[
                "link", "add", &host_veth, "type", "veth", "peer", "name", &ns_iface,
            ],
        )?;
        run_cmd("ip", &["link", "set", &host_veth, "master", &bridge])?;
        run_cmd("ip", &["link", "set", &host_veth, "up"])?;
        run_cmd(
            "ip",
            &[
                "link",
                "set",
                &ns_iface,
                "netns",
                ns.path().to_str().unwrap(),
            ],
        )?;
        run_in_ns(&ns.name, "ip", &["link", "set", "lo", "up"])?;
        run_in_ns(
            &ns.name,
            "ip",
            &["addr", "add", &format!("{ext_ip}/24"), "dev", &ns_iface],
        )?;
        run_in_ns(&ns.name, "ip", &["link", "set", &ns_iface, "up"])?;
        nodes.push(Node {
            name: node_name,
            ns,
            pod_ns,
            ext_iface: ns_iface,
            pod_cidr: cidr.to_string(),
        });
    }
    Ok(BridgeTopology {
        bridge,
        bridge_ip: bridge_ip.to_string(),
        nodes,
    })
}

/// Single-node topology: one veth to the host (`172.31.200.0/24`, host
/// `.1`, node `.2`); the apiserver is reachable via the host-side IP.
pub struct SoloLink {
    pub ns: NsGuard,
    pub pod_ns: NsGuard,
    pub host_ip: String,
    pub ns_ip: String,
    pub ns_iface: String,
}

pub fn build_solo_link(prefix: &str) -> Result<SoloLink> {
    let sfx = short_suffix();
    let ns = NsGuard::create(&format!("{prefix}-n"))?;
    let pod_ns = NsGuard::create(&format!("{prefix}-p"))?;
    let host_veth = format!("sh{sfx}");
    let ns_iface = format!("se{sfx}");
    reclaim_addr("172.31.200.1");
    run_cmd(
        "ip",
        &[
            "link", "add", &host_veth, "type", "veth", "peer", "name", &ns_iface,
        ],
    )?;
    run_cmd("ip", &["addr", "add", "172.31.200.1/24", "dev", &host_veth])?;
    run_cmd("ip", &["link", "set", &host_veth, "up"])?;
    run_cmd(
        "ip",
        &[
            "link",
            "set",
            &ns_iface,
            "netns",
            ns.path().to_str().unwrap(),
        ],
    )?;
    run_in_ns(&ns.name, "ip", &["link", "set", "lo", "up"])?;
    run_in_ns(
        &ns.name,
        "ip",
        &["addr", "add", "172.31.200.2/24", "dev", &ns_iface],
    )?;
    run_in_ns(&ns.name, "ip", &["link", "set", &ns_iface, "up"])?;
    Ok(SoloLink {
        ns,
        pod_ns,
        host_ip: "172.31.200.1".into(),
        ns_ip: "172.31.200.2".into(),
        ns_iface,
    })
}

/// Poll a probe closure every 150 ms until it returns `Ok(true)` or the
/// timeout elapses (used for subnet.env / routes / annotations).
pub async fn wait_until<F>(desc: &str, timeout: Duration, mut probe: F) -> Result<()>
where
    F: FnMut() -> Result<bool>,
{
    let deadline = Instant::now() + timeout;
    loop {
        match probe() {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(_) => {}
        }
        if Instant::now() >= deadline {
            bail!("timed out after {timeout:?} waiting for {desc}");
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}

/// `ping` a target from inside a netns (2 probes, 3 s each).
pub fn ping_from_ns(ns: &str, target: &str) -> Result<String> {
    run_in_ns(ns, "ping", &["-c", "2", "-W", "3", target])
}

/// Tx packet counter of a device inside a netns (via sysfs).
pub fn link_tx_packets(ns: &str, dev: &str) -> Result<u64> {
    let path = format!("/sys/class/net/{dev}/statistics/tx_packets");
    let out = run_in_ns(ns, "cat", &[&path])?;
    out.trim().parse::<u64>().context("parsing tx_packets")
}

/// Print the routes of a netns (for diagnostics).
pub fn dump_routes(ns: &str) -> String {
    run_in_ns(ns, "ip", &["-o", "route"]).unwrap_or_else(|e| format!("(route dump failed: {e})"))
}

/// CNI plugin tarball: the real bridge + host-local binaries. Path is
/// overridable via `CNI_PLUGINS_TGZ` (default matches the dropin e2e).
pub const DEFAULT_PLUGIN_TGZ: &str = "/root/k3as/vendor/cache/cni-plugins-linux-amd64-v1.5.1.tgz";

pub fn extract_cni_plugins(dir: &Path) -> Result<()> {
    let tgz = std::env::var("CNI_PLUGINS_TGZ").unwrap_or_else(|_| DEFAULT_PLUGIN_TGZ.into());
    if !Path::new(&tgz).exists() {
        bail!("CNI plugins tarball not found: {tgz} (set CNI_PLUGINS_TGZ)");
    }
    run_cmd(
        "tar",
        &[
            "xzf",
            &tgz,
            "-C",
            dir.to_str().unwrap(),
            "./bridge",
            "./host-local",
        ],
    )?;
    for p in ["bridge", "host-local"] {
        let f = dir.join(p);
        std::fs::set_permissions(&f, std::os::unix::fs::PermissionsExt::from_mode(0o755))?;
    }
    Ok(())
}
