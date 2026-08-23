//! Port of pkg/subnet/config.go. CONTRACT STUB: completed in P0.

use crate::ip::{IP4Net, IP6Net};
use serde_json::value::RawValue;

/// Parsed network backend spec (Go: embedded Backend json.RawMessage).
#[derive(Clone, Debug)]
pub struct NetworkBackend {
    /// Raw JSON of the "Backend" object from net-conf.json.
    pub raw: Box<RawValue>,
}

/// Parsed net-conf.json (Go: subnet.Config).
#[derive(Clone, Debug)]
pub struct Config {
    pub network: Option<IP4Net>,
    pub ipv6_network: Option<IP6Net>,
    pub enable_ipv4: bool,
    pub enable_ipv6: bool,
    pub enable_nftables: bool,
    pub backend_type: String,
    pub backend: Option<NetworkBackend>,
}
