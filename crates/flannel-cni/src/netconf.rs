//! Netconf parsing, subnet.env parsing and delegate config construction.
//!
//! Mirrors upstream flannel-io/cni-plugin behavior: the flannel netconf
//! (JSON from stdin) plus flanneld's `subnet.env` become a `bridge` +
//! `host-local` delegate configuration.

use anyhow::{bail, Context, Result};
use flannel_core::ip::{IP4Net, IP6Net};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::path::{Path, PathBuf};
use std::str::FromStr;

#[cfg(test)]
#[path = "netconf_tests.rs"]
mod tests;

/// Default location of the file flanneld writes (`WriteSubnetFile`).
pub const DEFAULT_SUBNET_ENV: &str = "/run/flannel/subnet.env";

/// Masquerade chain managed by [`crate::masq`] (kept here for
/// discoverability; the rule management lives in `masq.rs`).
pub const MASQ_CHAIN_PLACEHOLDER: &str = "FLANNEL-POSTRTG-CHAIN-01";

/// Default delegate plugin type (upstream `DefaultDelegateType`).
pub const DEFAULT_DELEGATE_TYPE: &str = "bridge";

/// Default delegate IPAM type (upstream `DefaultDelegateIPAMType`).
pub const DEFAULT_DELEGATE_IPAM_TYPE: &str = "host-local";

/// Flannel netconf: the JSON the CNI runtime passes on stdin.
///
/// Only the fields flannel itself consumes are typed; user delegate
/// overrides are kept as raw JSON so they can be merged verbatim into
/// the delegate (bridge) config.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct NetConf {
    #[serde(rename = "cniVersion", default = "default_cni_version")]
    pub cni_version: String,
    #[serde(default)]
    pub name: String,
    #[serde(rename = "type", default)]
    pub plugin_type: String,
    /// User-provided delegate overrides (bridge plugin keys).
    #[serde(default)]
    pub delegate: Map<String, Value>,
}

fn default_cni_version() -> String {
    "1.0.0".to_string()
}

/// Parse the flannel netconf from the bytes the runtime passed on stdin.
pub fn load_flannel_net_conf(bytes: &[u8]) -> Result<NetConf> {
    serde_json::from_slice(bytes).context("failed to parse flannel netconf")
}

/// Path of subnet.env: `$FLANNEL_SUBNET_FILE` if set, else
/// `/run/flannel/subnet.env`.
pub fn default_subnet_env_path() -> PathBuf {
    std::env::var_os("FLANNEL_SUBNET_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SUBNET_ENV))
}

/// Parsed contents of flanneld's subnet.env
/// (`flannel-core::subnet::writefile` writes it).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct FlannelSubnetEnv {
    /// FLANNEL_NETWORK (IPv4 pod CIDR).
    pub network: Option<IP4Net>,
    /// FLANNEL_SUBNET (IPv4 lease of this node; host bits are masked).
    pub subnet: Option<IP4Net>,
    /// FLANNEL_IPV6_NETWORK.
    pub ipv6_network: Option<IP6Net>,
    /// FLANNEL_IPV6_SUBNET.
    pub ipv6_subnet: Option<IP6Net>,
    /// FLANNEL_MTU; absent means the delegate mtu stays unset.
    pub mtu: Option<u32>,
    /// FLANNEL_IPMASQ, defaults to false. When true flannel installs the
    /// masquerade rules itself and the delegate's `ipMasq` is forced to
    /// false regardless.
    pub ipmasq: bool,
}

/// Read and parse a subnet.env file.
pub fn load_flannel_subnet_env(path: &Path) -> Result<FlannelSubnetEnv> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read subnet.env file {}", path.display()))?;
    parse_subnet_env(&contents)
}

/// Parse KEY=VALUE lines of a subnet.env. Unknown keys and lines without
/// `=` are ignored; malformed CIDR/integer/boolean values are errors.
pub fn parse_subnet_env(contents: &str) -> Result<FlannelSubnetEnv> {
    let mut env = FlannelSubnetEnv::default();
    for raw_line in contents.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((key, val)) = line.split_once('=') else {
            continue;
        };
        let val = val.trim();
        match key.trim() {
            "FLANNEL_NETWORK" => env.network = Some(parse_v4_net(val, key)?),
            "FLANNEL_SUBNET" => env.subnet = Some(parse_v4_net(val, key)?),
            "FLANNEL_IPV6_NETWORK" => env.ipv6_network = Some(parse_v6_net(val, key)?),
            "FLANNEL_IPV6_SUBNET" => env.ipv6_subnet = Some(parse_v6_net(val, key)?),
            "FLANNEL_MTU" => {
                env.mtu = Some(
                    val.parse::<u32>()
                        .with_context(|| format!("invalid FLANNEL_MTU value: {val}"))?,
                )
            }
            "FLANNEL_IPMASQ" => {
                env.ipmasq = parse_bool(val)
                    .ok_or_else(|| anyhow::anyhow!("invalid FLANNEL_IPMASQ value: {val}"))?
            }
            _ => {} // unknown keys are ignored
        }
    }
    Ok(env)
}

fn parse_v4_net(val: &str, key: &str) -> Result<IP4Net> {
    IP4Net::from_str(val).with_context(|| format!("invalid {key} value: {val}"))
}

fn parse_v6_net(val: &str, key: &str) -> Result<IP6Net> {
    IP6Net::from_str(val).with_context(|| format!("invalid {key} value: {val}"))
}

fn parse_bool(val: &str) -> Option<bool> {
    match val.to_ascii_lowercase().as_str() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

/// Numeric CNI version comparison: `"0.3.0"` vs `"1.0.0"` compares
/// component-wise as integers. Missing components count as 0 and
/// non-numeric components parse as 0. Returns `a >= b`.
pub fn version_at_least(a: &str, b: &str) -> bool {
    let components = |s: &str| {
        s.split('.')
            .map(|c| c.parse::<u64>().unwrap_or(0))
            .collect::<Vec<_>>()
    };
    let (va, vb) = (components(a), components(b));
    for i in 0..va.len().max(vb.len()) {
        let x = va.get(i).copied().unwrap_or(0);
        let y = vb.get(i).copied().unwrap_or(0);
        if x != y {
            return x > y;
        }
    }
    true
}

/// Build the full delegate (bridge + host-local) config from the flannel
/// netconf and the parsed subnet.env, mirroring upstream
/// `buildDelegateConfig`:
/// - base `{cniVersion, name, type: "bridge"}` with user delegate
///   overrides on top, except `ipMasq` (forced false — flannel does the
///   masquerading itself) and `mtu` (forced to FLANNEL_MTU when present);
/// - `ipam`: `{type: "host-local"}` + user delegate.ipam overrides, then
///   flannel injects `ranges` (cniVersion >= 0.3.0) or a flat `subnet`
///   (legacy; IPv6 unsupported there) and default routes when the user
///   supplied none;
/// - at least one of FLANNEL_SUBNET / FLANNEL_IPV6_SUBNET is required.
pub fn build_delegate_conf(conf: &NetConf, env: &FlannelSubnetEnv) -> Result<Value> {
    if env.subnet.is_none() && env.ipv6_subnet.is_none() {
        bail!("no subnet found in subnet.env (need FLANNEL_SUBNET or FLANNEL_IPV6_SUBNET)");
    }
    let mut delegate = Map::new();
    delegate.insert("cniVersion".into(), json!(conf.cni_version));
    delegate.insert("name".into(), json!(conf.name));
    delegate.insert("type".into(), json!(DEFAULT_DELEGATE_TYPE));
    for (key, val) in &conf.delegate {
        delegate.insert(key.clone(), val.clone());
    }
    // Upstream (flannel_linux.go): bridge delegates default isGateway to
    // true unless the user supplied the key themselves.
    if delegate.get("type").and_then(Value::as_str) == Some(DEFAULT_DELEGATE_TYPE)
        && !delegate.contains_key("isGateway")
    {
        delegate.insert("isGateway".into(), json!(true));
    }
    // Flannel always forces these two keys.
    delegate.insert("ipMasq".into(), json!(false));
    if let Some(mtu) = env.mtu {
        delegate.insert("mtu".into(), json!(mtu));
    }
    delegate.insert("ipam".into(), build_ipam(conf, env)?);
    Ok(Value::Object(delegate))
}

/// Minimal bridge config for DEL when subnet.env is unavailable: base
/// config + user delegate overrides only, no flannel ipam injection
/// (a user-supplied delegate.ipam is kept verbatim).
pub fn minimal_delegate_conf(conf: &NetConf) -> Result<Value> {
    let mut delegate = Map::new();
    delegate.insert("cniVersion".into(), json!(conf.cni_version));
    delegate.insert("name".into(), json!(conf.name));
    delegate.insert("type".into(), json!(DEFAULT_DELEGATE_TYPE));
    for (key, val) in &conf.delegate {
        delegate.insert(key.clone(), val.clone());
    }
    Ok(Value::Object(delegate))
}

fn build_ipam(conf: &NetConf, env: &FlannelSubnetEnv) -> Result<Value> {
    let mut ipam = Map::new();
    ipam.insert("type".into(), json!(DEFAULT_DELEGATE_IPAM_TYPE));
    if let Some(Value::Object(user_ipam)) = conf.delegate.get("ipam") {
        for (key, val) in user_ipam {
            ipam.insert(key.clone(), val.clone());
        }
    }
    if version_at_least(&conf.cni_version, "0.3.0") {
        // One inner range per family present: [[{subnet: v4}], [{subnet: v6}]].
        let mut ranges = Vec::new();
        if let Some(subnet) = env.subnet {
            ranges.push(json!([{"subnet": subnet.to_string()}]));
        }
        if let Some(subnet6) = env.ipv6_subnet {
            ranges.push(json!([{"subnet": subnet6.to_string()}]));
        }
        ipam.insert("ranges".into(), Value::Array(ranges));
    } else {
        match env.subnet {
            Some(subnet) => {
                ipam.insert("subnet".into(), json!(subnet.to_string()));
            }
            None => bail!(
                "IPv6 subnets are not supported for cniVersion {}",
                conf.cni_version
            ),
        }
    }
    if !conf.delegate.contains_key("routes") {
        let mut routes = Vec::new();
        if env.subnet.is_some() {
            routes.push(json!({"dst": "0.0.0.0/0"}));
        }
        if env.ipv6_subnet.is_some() {
            routes.push(json!({"dst": "::/0"}));
        }
        ipam.insert("routes".into(), Value::Array(routes));
    }
    Ok(Value::Object(ipam))
}
