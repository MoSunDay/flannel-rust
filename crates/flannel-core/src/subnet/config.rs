//! Port of pkg/subnet/config.go (upstream cdf76059): net-conf.json parsing
//! and validation.
//!
//! Go's `encoding/json` matches struct field names case-insensitively (an
//! exact match takes precedence over a folded one), which serde does not do;
//! `Config` therefore has a hand-written `Deserialize` that reproduces the Go
//! behavior (the upstream test suite parses e.g. `{ "network": ... }`).
//!
//! As in Go, `backend_type` is `json:"-"` (never (de)serialized; it is
//! computed by `parse_config`), and `backend` is `json:",omitempty"` (a
//! missing/None Backend is omitted on serialize).

use crate::ip::ip6net::{
    check_ipv6_subnet, get_ipv6_subnet_max, get_ipv6_subnet_min, is_empty, mask6,
};
use crate::ip::ipnet::{check_subnet, get_subnet_max, get_subnet_min, mask};
use crate::ip::{IP4Net, IP6Net, IP4, IP6};
use serde::de::{IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::value::RawValue;
use std::fmt;
use thiserror::Error;

/// Errors from `parse_config` / `check_network_config`. The Display strings
/// are byte-identical to the Go `errors.New` / `fmt.Errorf` messages.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ConfigError {
    /// JSON syntax / type error while decoding net-conf.json (serde text).
    #[error("{0}")]
    Json(String),
    /// Go: `error decoding Backend property of config: %v`.
    #[error("error decoding Backend property of config: {0}")]
    Backend(String),
    #[error("please define a correct Network parameter in the flannel config")]
    MissingNetwork,
    #[error("please define a correct IPv6Network parameter in the flannel config")]
    MissingIpv6Network,
    #[error("SubnetLen must be less than /31")]
    SubnetLenTooBigV4,
    #[error("SubnetLen must be less than /127")]
    SubnetLenTooBigV6,
    #[error("network must be able to accommodate at least four subnets")]
    TooFewSubnets,
    #[error("network is too small. Minimum useful network prefix is /28")]
    NetworkTooSmallV4,
    #[error("IPv6Network is too small. Minimum useful network prefix is /124")]
    NetworkTooSmallV6,
    #[error("SubnetMin is not in the range of the Network")]
    SubnetMinOutOfRange,
    #[error("SubnetMax is not in the range of the Network")]
    SubnetMaxOutOfRange,
    #[error("IPv6SubnetMin is not in the range of the IPv6Network")]
    Ipv6SubnetMinOutOfRange,
    #[error("IPv6SubnetMax is not in the range of the IPv6Network")]
    Ipv6SubnetMaxOutOfRange,
    #[error("SubnetMin is not on a SubnetLen boundary: {0}")]
    SubnetMinUnaligned(IP4),
    #[error("SubnetMax is not on a SubnetLen boundary: {0}")]
    SubnetMaxUnaligned(IP4),
    #[error("IPv6SubnetMin is not on a SubnetLen boundary: {0}")]
    Ipv6SubnetMinUnaligned(IP6),
    #[error("IPv6SubnetMax is not on a SubnetLen boundary: {0}")]
    Ipv6SubnetMaxUnaligned(IP6),
}

/// Parsed net-conf.json (Go: `subnet.Config`). Field order and JSON names
/// match the Go struct; missing fields keep Go's zero values.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Config {
    #[serde(rename = "EnableIPv4")]
    pub enable_ipv4: bool,
    #[serde(rename = "EnableIPv6")]
    pub enable_ipv6: bool,
    #[serde(rename = "EnableNFTables")]
    pub enable_nftables: bool,
    #[serde(rename = "Network")]
    pub network: IP4Net,
    #[serde(rename = "IPv6Network")]
    pub ipv6_network: IP6Net,
    #[serde(rename = "SubnetMin")]
    pub subnet_min: IP4,
    #[serde(rename = "SubnetMax")]
    pub subnet_max: IP4,
    /// Go `*ip.IP6`: None when absent or JSON null.
    #[serde(rename = "IPv6SubnetMin")]
    pub ipv6_subnet_min: Option<IP6>,
    #[serde(rename = "IPv6SubnetMax")]
    pub ipv6_subnet_max: Option<IP6>,
    #[serde(rename = "SubnetLen")]
    pub subnet_len: u32,
    #[serde(rename = "IPv6SubnetLen")]
    pub ipv6_subnet_len: u32,
    /// Go `json:"-"`: computed from `backend`, never (de)serialized.
    #[serde(skip)]
    pub backend_type: String,
    /// Go `json.RawMessage json:",omitempty"`: raw Backend JSON, verbatim.
    #[serde(rename = "Backend", skip_serializing_if = "Option::is_none")]
    pub backend: Option<Box<RawValue>>,
}

/// Go field names in declaration order (BackendType is `json:"-"`).
const CONFIG_FIELDS: &[&str] = &[
    "EnableIPv4",
    "EnableIPv6",
    "EnableNFTables",
    "Network",
    "IPv6Network",
    "SubnetMin",
    "SubnetMax",
    "IPv6SubnetMin",
    "IPv6SubnetMax",
    "SubnetLen",
    "IPv6SubnetLen",
    "Backend",
];

/// Go `encoding/json` field lookup: an exact match wins, then the first
/// case-insensitive match.
fn match_config_field(key: &str) -> Option<&'static str> {
    CONFIG_FIELDS
        .iter()
        .copied()
        .find(|name| *name == key)
        .or_else(|| {
            CONFIG_FIELDS
                .iter()
                .copied()
                .find(|name| name.eq_ignore_ascii_case(key))
        })
}

struct ConfigVisitor;

impl<'de> Visitor<'de> for ConfigVisitor {
    type Value = Config;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON object (flannel net-conf.json)")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Config, A::Error> {
        // Go: cfg.EnableIPv4 = true before json.Unmarshal (a present key
        // still overrides it below).
        let mut cfg = Config {
            enable_ipv4: true,
            ..Default::default()
        };
        // Like Go, duplicate keys are applied in order (last one wins) and
        // unknown keys are ignored.
        while let Some(key) = map.next_key::<String>()? {
            match match_config_field(&key) {
                Some("EnableIPv4") => cfg.enable_ipv4 = map.next_value()?,
                Some("EnableIPv6") => cfg.enable_ipv6 = map.next_value()?,
                Some("EnableNFTables") => cfg.enable_nftables = map.next_value()?,
                Some("Network") => cfg.network = map.next_value()?,
                Some("IPv6Network") => cfg.ipv6_network = map.next_value()?,
                Some("SubnetMin") => cfg.subnet_min = map.next_value()?,
                Some("SubnetMax") => cfg.subnet_max = map.next_value()?,
                Some("IPv6SubnetMin") => cfg.ipv6_subnet_min = map.next_value()?,
                Some("IPv6SubnetMax") => cfg.ipv6_subnet_max = map.next_value()?,
                Some("SubnetLen") => cfg.subnet_len = map.next_value()?,
                Some("IPv6SubnetLen") => cfg.ipv6_subnet_len = map.next_value()?,
                Some("Backend") => cfg.backend = Some(map.next_value()?),
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(cfg)
    }
}

impl<'de> Deserialize<'de> for Config {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        de.deserialize_map(ConfigVisitor)
    }
}

/// Go: `ParseConfig`.
pub fn parse_config(s: &str) -> Result<Config, ConfigError> {
    let mut cfg: Config = serde_json::from_str(s).map_err(|e| ConfigError::Json(e.to_string()))?;
    cfg.backend_type = parse_backend_type(cfg.backend.as_deref())?;
    Ok(cfg)
}

/// Go: `parseBackendType`. An absent or empty Backend means "udp"; otherwise
/// the Backend object's `Type` field (Go matches the key case-insensitively).
fn parse_backend_type(backend: Option<&RawValue>) -> Result<String, ConfigError> {
    let Some(raw) = backend else {
        return Ok("udp".to_string());
    };
    if raw.get().is_empty() {
        return Ok("udp".to_string());
    }
    let value: serde_json::Value =
        serde_json::from_str(raw.get()).map_err(|e| ConfigError::Backend(e.to_string()))?;
    let fields = match &value {
        // Go: json.Unmarshal of `null` into struct{Type string} is a no-op.
        serde_json::Value::Null => return Ok(String::new()),
        serde_json::Value::Object(fields) => fields,
        other => {
            return Err(ConfigError::Backend(format!(
                "cannot unmarshal {} into Go value of type struct {{ Type string }}",
                json_type_name(other)
            )));
        }
    };
    // Go: var bt struct{ Type string } with case-insensitive key matching.
    match fold_lookup(fields, "Type") {
        None => Ok(String::new()),
        Some(serde_json::Value::String(ty)) => Ok(ty.clone()),
        Some(other) => Err(ConfigError::Backend(format!(
            "cannot unmarshal {} into Go struct field .Type of type string",
            json_type_name(other)
        ))),
    }
}

/// First map entry whose key equals `name`, else whose key case-folds to it
/// (Go `encoding/json` field matching).
fn fold_lookup<'a>(
    fields: &'a serde_json::Map<String, serde_json::Value>,
    name: &str,
) -> Option<&'a serde_json::Value> {
    fields.get(name).or_else(|| {
        fields
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v)
    })
}

fn json_type_name(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

/// Go: `CheckNetworkConfig`. Checks the coherence of the flannel
/// configuration and fills in the SubnetMin/SubnetMax/SubnetLen defaults.
/// Used only with the local network manager, not the kubernetes-based one.
pub fn check_network_config(config: &mut Config) -> Result<(), ConfigError> {
    if config.enable_ipv4 {
        if config.network.empty() {
            return Err(ConfigError::MissingNetwork);
        }
        if config.subnet_len > 0 {
            // SubnetLen needs to allow for a tunnel and bridge device on
            // each host.
            if config.subnet_len > 30 {
                return Err(ConfigError::SubnetLenTooBigV4);
            }
            // SubnetLen needs to fit _more_ than twice into the Network;
            // the first subnet isn't used, so splitting into two would only
            // provide one usable host.
            if config.subnet_len < config.network.prefix_len + 2 {
                return Err(ConfigError::TooFewSubnets);
            }
        } else if config.network.prefix_len > 28 {
            // Each subnet needs at least four addresses (/30) and the
            // network needs to accommodate at least four since the first
            // subnet isn't used, so splitting into two would only provide
            // one usable host. So the min useful PrefixLen is /28.
            return Err(ConfigError::NetworkTooSmallV4);
        } else if config.network.prefix_len <= 22 {
            // Network is big enough to give each host a /24.
            config.subnet_len = 24;
        } else {
            // Use +2 to provide four hosts per subnet.
            config.subnet_len = config.network.prefix_len + 2;
        }

        let subnet_size = 1u32 << (32 - config.subnet_len);

        if config.subnet_min == IP4(0) {
            // Skip over the first subnet otherwise it causes problems. e.g.
            // if Network is 10.100.0.0/16, having an interface with
            // 10.100.0.0 conflicts with the network address.
            config.subnet_min = get_subnet_min(config.network.ip, subnet_size);
        } else if !config.network.contains(config.subnet_min) {
            return Err(ConfigError::SubnetMinOutOfRange);
        }

        if config.subnet_max == IP4(0) {
            config.subnet_max = get_subnet_max(config.network.next().ip, subnet_size);
        } else if !config.network.contains(config.subnet_max) {
            return Err(ConfigError::SubnetMaxOutOfRange);
        }

        // The SubnetMin and SubnetMax need to be aligned to a SubnetLen
        // boundary.
        let boundary = mask(config.subnet_len);
        if !check_subnet(config.subnet_min, boundary) {
            return Err(ConfigError::SubnetMinUnaligned(config.subnet_min));
        }
        if !check_subnet(config.subnet_max, boundary) {
            return Err(ConfigError::SubnetMaxUnaligned(config.subnet_max));
        }
    }
    if config.enable_ipv6 {
        if config.ipv6_network.empty() {
            return Err(ConfigError::MissingIpv6Network);
        }
        if config.ipv6_subnet_len > 0 {
            if config.ipv6_subnet_len > 126 {
                return Err(ConfigError::SubnetLenTooBigV6);
            }
            if config.ipv6_subnet_len < config.ipv6_network.prefix_len + 2 {
                return Err(ConfigError::TooFewSubnets);
            }
        } else if config.ipv6_network.prefix_len > 124 {
            return Err(ConfigError::NetworkTooSmallV6);
        } else if config.ipv6_network.prefix_len <= 62 {
            // Network is big enough to give each host a /64.
            config.ipv6_subnet_len = 64;
        } else {
            // Use +2 to provide four hosts per subnet.
            config.ipv6_subnet_len = config.ipv6_network.prefix_len + 2;
        }

        // Go: big.NewInt(0).Lsh(big.NewInt(1), 128-config.IPv6SubnetLen).
        let ipv6_subnet_size = 1u128 << (128 - config.ipv6_subnet_len);

        let v6_min = match config.ipv6_subnet_min {
            Some(min) if !is_empty(min) => {
                if !config.ipv6_network.contains(min) {
                    return Err(ConfigError::Ipv6SubnetMinOutOfRange);
                }
                min
            }
            // Skip over the first subnet otherwise it causes problems. e.g.
            // if Network is fc00::/48, having an interface with fc00::
            // conflicts with the broadcast address.
            _ => {
                let min = get_ipv6_subnet_min(config.ipv6_network.ip, ipv6_subnet_size);
                config.ipv6_subnet_min = Some(min);
                min
            }
        };

        let v6_max = match config.ipv6_subnet_max {
            Some(max) if !is_empty(max) => {
                if !config.ipv6_network.contains(max) {
                    return Err(ConfigError::Ipv6SubnetMaxOutOfRange);
                }
                max
            }
            _ => {
                let max = get_ipv6_subnet_max(config.ipv6_network.next().ip, ipv6_subnet_size);
                config.ipv6_subnet_max = Some(max);
                max
            }
        };

        // The SubnetMin and SubnetMax need to be aligned to a SubnetLen
        // boundary.
        let boundary = mask6(config.ipv6_subnet_len);
        if !check_ipv6_subnet(v6_min, boundary) {
            return Err(ConfigError::Ipv6SubnetMinUnaligned(v6_min));
        }
        if !check_ipv6_subnet(v6_max, boundary) {
            return Err(ConfigError::Ipv6SubnetMaxUnaligned(v6_max));
        }
    }
    Ok(())
}
