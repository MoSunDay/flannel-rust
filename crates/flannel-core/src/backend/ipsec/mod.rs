//! Port of pkg/backend/ipsec (upstream cdf76059): flannel's approach to
//! IPSec uses strongSwan for the key exchange (IKEv2) and the kernel for
//! the actual encryption. Flannel runs strongSwan's "charon" as a child
//! process and talks to it over VICI.
//!
//! - vici.rs: the VICI protocol client (Go: goStrongswanVici).
//! - charon.rs: charon daemon management (handle_charon.go).
//! - xfrm.rs: raw NETLINK_XFRM policy client (the netlink ops of
//!   handle_xfrm.go; the policy orchestration lives in network.rs).
//! - network.rs: the `Network` run loop (ipsec_network.go).
//!
//! Go deviation: Go reads the external MTU via `ExtIface.Iface.MTU` in
//! `MTU()`; the Rust `ExternalInterface` carries no MTU, so it is
//! resolved once in `register_network` (see network.rs).

mod charon;
mod network;
mod vici;
mod xfrm;

#[cfg(test)]
#[path = "mod_tests.rs"]
mod mod_tests;

pub use network::IPsecNetwork;

use crate::backend::common::ExternalInterface;
use crate::backend::traits::{Backend, Network};
use crate::ip::iface::{get_link_mtu, Netlink};
use crate::lease::LeaseAttrs;
use crate::subnet::config::Config;
use crate::subnet::manager::{Ctx, Manager};
use anyhow::{anyhow, bail};
use futures::future::BoxFuture;
use serde_json::value::RawValue;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::info;

/// Go `backendType`.
pub const BACKEND_TYPE: &str = "ipsec";
/// Go `defaultESPProposal`.
const DEFAULT_ESP_PROPOSAL: &str = "aes128gcm16-sha256-prfsha256-ecp256";
/// Go `minPasswordLength`.
const MIN_PASSWORD_LENGTH: usize = 96;

/// Go: `IPSECBackend`.
pub struct IPSECBackend {
    sm: Arc<dyn Manager>,
    ei: Arc<ExternalInterface>,
}

/// Go: `New` (+ `backend.Register("ipsec", New)` registration shape).
pub fn new_backend(
    sm: Arc<dyn Manager>,
    ei: Arc<ExternalInterface>,
) -> anyhow::Result<Box<dyn Backend>> {
    Ok(Box::new(IPSECBackend { sm, ei }))
}

/// Go's inline config struct inside `RegisterNetwork`.
#[derive(Debug)]
struct IPsecCfg {
    udp_encap: bool,
    esp_proposal: String,
    psk: String,
}

#[derive(serde::Deserialize)]
struct IPsecCfgJson {
    #[serde(rename = "UDPEncap", default)]
    udp_encap: bool,
    #[serde(rename = "ESPProposal", default = "default_esp_proposal")]
    esp_proposal: String,
    #[serde(rename = "PSK", default)]
    psk: String,
}

fn default_esp_proposal() -> String {
    DEFAULT_ESP_PROPOSAL.to_string()
}

/// Go: the inline `json.Unmarshal(config.Backend, &cfg)` on the
/// pre-initialized defaults, plus the PSK length check.
fn parse_ipsec_config(backend: Option<&RawValue>) -> anyhow::Result<IPsecCfg> {
    let mut cfg = IPsecCfg {
        udp_encap: false,
        esp_proposal: DEFAULT_ESP_PROPOSAL.to_string(),
        psk: String::new(),
    };
    if let Some(raw) = backend {
        let text = raw.get();
        if !text.is_empty() && text != "null" {
            let json: IPsecCfgJson = serde_json::from_str(text)
                .map_err(|e| anyhow!("error decoding IPSEC backend config: {e}"))?;
            cfg.udp_encap = json.udp_encap;
            cfg.esp_proposal = json.esp_proposal;
            cfg.psk = json.psk;
        }
    }
    if cfg.psk.len() < MIN_PASSWORD_LENGTH {
        bail!("config error, password is too short");
    }
    Ok(cfg)
}

impl Backend for IPSECBackend {
    /// Go: `RegisterNetwork`.
    fn register_network<'a>(
        &'a self,
        ctx: Ctx<'a>,
        config: &'a Config,
    ) -> BoxFuture<'a, anyhow::Result<Box<dyn Network>>> {
        Box::pin(async move {
            let cfg = parse_ipsec_config(config.backend.as_deref())?;
            info!(
                "IPSec config: UDPEncap={} ESPProposal={}",
                cfg.udp_encap, cfg.esp_proposal
            );

            let mut attrs = LeaseAttrs {
                backend_type: BACKEND_TYPE.to_string(),
                ..Default::default()
            };
            // Go: PublicIP = ip.FromIP(ExtAddr); only v4 applies here
            // (same convention as the vxlan port's new_subnet_attrs).
            if let Some(IpAddr::V4(ip)) = self.ei.ext_addr {
                attrs.public_ip = crate::ip::IP4::from_bytes(ip.octets());
            }

            let lease = match self.sm.acquire_lease(ctx, &attrs).await {
                Ok(l) => l,
                // Go: context.Canceled / DeadlineExceeded pass through.
                Err(e) if ctx.is_cancelled() => return Err(e),
                Err(e) => return Err(anyhow!("failed to acquire lease: {e}")),
            };

            let iked = charon::new_charon(ctx, cfg.esp_proposal.clone())
                .map_err(|e| anyhow!("error creating CharonIKEDaemon struct: {e}"))?;

            // Go reads ExtIface.Iface.MTU inside MTU(); resolve it once.
            let nl = Netlink::new().await?;
            let ext_mtu = get_link_mtu(&nl, self.ei.iface_index).await?;

            Ok(Box::new(network::new_network(
                self.sm.clone(),
                ext_mtu,
                cfg.udp_encap,
                cfg.psk,
                iked,
                lease,
            )) as Box<dyn Network>)
        })
    }
}
