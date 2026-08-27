//! Previous-CIDR readers for the subnet.env file. Port of
//! `ReadCIDRFromSubnetFile` / `ReadCIDRsFromSubnetFile` and their IPv6
//! twins from flannel `main.go` (upstream cdf76059).
//!
//! Go reads the file with `godotenv.Read` (KEY=VALUE lines; no quoting
//! occurs in subnet.env files this port writes or reads). The Rust port
//! parses lines directly with godotenv-equivalent semantics: blank lines
//! and `#` comments are skipped, `KEY=VALUE` pairs are trimmed, and
//! malformed lines are logged and skipped (Go would fail the whole file
//! read; per-line tolerance is the practical equivalent here).
//!
//! Multi-value entries ("a,b,c") are comma-split exactly like Go.
//!
//! CIDR parsing uses Go `net.ParseCIDR` + `ip.FromIPNet` semantics
//! (main.go `ReadCIDRsFromSubnetFile` / `ReadIP6CIDRsFromSubnetFile`):
//! host bits are MASKED, so a `FLANNEL_SUBNET=10.244.1.1/24` line (the
//! lease address the daemon writes, first usable IP) reads back as the
//! network `10.244.1.0/24`. That is what the prev-subnet comparisons
//! and the masq-rule recycle in main.go expect (network-to-network).
//! `IP4Net`/`IP6Net`'s `FromStr` masks the same way, but the local
//! helpers keep the tolerant log-and-skip handling of the Go readers
//! instead of failing the entry.

use flannel_core::ip::{IP4Net, IP6Net, IP4, IP6};
use std::collections::BTreeMap;
use std::io::ErrorKind;

/// Go `net.ParseCIDR` + `ip.FromIPNet`: `a.b.c.d/len` -> [`IP4Net`],
/// host bits masked to the network address.
fn parse_ip4net(s: &str) -> Option<IP4Net> {
    let (addr, prefix) = s.split_once('/')?;
    let prefix_len: u32 = prefix.parse().ok()?;
    if prefix_len > 32 {
        return None;
    }
    let ip: IP4 = addr.parse().ok()?;
    Some(IP4Net { ip, prefix_len }.network())
}

/// Go `net.ParseCIDR` + `ip.FromIP6Net`: `addr/len` -> [`IP6Net`],
/// host bits masked to the network address.
fn parse_ip6net(s: &str) -> Option<IP6Net> {
    let (addr, prefix) = s.rsplit_once('/')?;
    let prefix_len: u32 = prefix.parse().ok()?;
    if prefix_len > 128 {
        return None;
    }
    let ip: IP6 = addr.parse().ok()?;
    Some(IP6Net { ip, prefix_len }.network())
}

/// godotenv-equivalent file read. `Ok(None)` means the file does not
/// exist (Go: `os.IsNotExist` skip), `Ok(Some(map))` the parsed pairs.
fn read_env_file(path: &str) -> Result<Option<BTreeMap<String, String>>, std::io::Error> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut values = BTreeMap::new();
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            // Go's godotenv fails the whole file here; this port logs
            // and skips the line (documented deviation, see module docs).
            tracing::warn!("skipping malformed subnet file line: {raw_line}");
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            tracing::warn!("skipping malformed subnet file line: {raw_line}");
            continue;
        }
        values.insert(key.to_string(), value.trim().to_string());
    }
    Ok(Some(values))
}

/// Go: `ReadCIDRsFromSubnetFile(path, CIDRKey) []ip.IP4Net`.
pub fn read_cidrs_from_subnet_file(path: &str, cidr_key: &str) -> Vec<IP4Net> {
    let values = match read_env_file(path) {
        Ok(Some(v)) => v,
        Ok(None) => return Vec::new(),
        Err(e) => {
            tracing::error!("Couldn't fetch previous {cidr_key} from subnet file at {path}: {e}");
            return Vec::new();
        }
    };
    let Some(raw) = values.get(cidr_key) else {
        return Vec::new();
    };
    let mut cidrs = Vec::new();
    for part in raw.split(',') {
        match parse_ip4net(part) {
            Some(net) => cidrs.push(net),
            None => {
                tracing::error!(
                    "Couldn't parse previous {cidr_key} from subnet file at {path}: {part}"
                );
            }
        }
    }
    cidrs
}

/// Go: `ReadCIDRFromSubnetFile(path, CIDRKey) ip.IP4Net`.
pub fn read_cidr_from_subnet_file(path: &str, cidr_key: &str) -> IP4Net {
    let cidrs = read_cidrs_from_subnet_file(path, cidr_key);
    if cidrs.is_empty() {
        tracing::warn!("no subnet found for key: {cidr_key} in file: {path}");
        IP4Net::default()
    } else if cidrs.len() > 1 {
        tracing::error!(
            "error reading subnet: more than 1 entry found for key: {cidr_key} \
             in file {path}: "
        );
        IP4Net::default()
    } else {
        cidrs[0]
    }
}

/// Go: `ReadIP6CIDRsFromSubnetFile(path, CIDRKey) []ip.IP6Net`.
pub fn read_ip6_cidrs_from_subnet_file(path: &str, cidr_key: &str) -> Vec<IP6Net> {
    let values = match read_env_file(path) {
        Ok(Some(v)) => v,
        Ok(None) => return Vec::new(),
        Err(e) => {
            tracing::error!("Couldn't fetch previous {cidr_key} from subnet file at {path}: {e}");
            return Vec::new();
        }
    };
    let Some(raw) = values.get(cidr_key) else {
        return Vec::new();
    };
    let mut cidrs = Vec::new();
    for part in raw.split(',') {
        match parse_ip6net(part) {
            Some(net) => cidrs.push(net),
            None => {
                tracing::error!(
                    "Couldn't parse previous {cidr_key} from subnet file at {path}: {part}"
                );
            }
        }
    }
    cidrs
}

/// Go: `ReadIP6CIDRFromSubnetFile(path, CIDRKey) ip.IP6Net`.
pub fn read_ip6_cidr_from_subnet_file(path: &str, cidr_key: &str) -> IP6Net {
    let cidrs = read_ip6_cidrs_from_subnet_file(path, cidr_key);
    if cidrs.is_empty() {
        tracing::warn!("no subnet found for key: {cidr_key} in file: {path}");
        IP6Net::default()
    } else if cidrs.len() > 1 {
        tracing::error!(
            "error reading subnet: more than 1 entry found for key: {cidr_key} \
             in file {path}: "
        );
        IP6Net::default()
    } else {
        cidrs[0]
    }
}
