//! Port of pkg/backend/udp (upstream cdf76059): the userspace UDP
//! encap proxy backend.
//!
//! - mod.rs: `UdpBackend` + `RegisterNetwork` (udp.go, udp_amd64.go).
//! - network.rs: network struct, tun/iface setup, run loop and the ctl
//!   command writers (udp_network_amd64.go, cproxy_amd64.go).
//! - proxy.rs / proxy_packet.rs: the blocking packet proxy
//!   (proxy_amd64.c + proxy_amd64.h) re-implemented in Rust.
//!
//! Go deviations:
//! - Like upstream the backend is IPv4-only; `config.enable_ipv6` is
//!   never consulted, exactly like Go.
//! - Go `ip.FromIP` panics when `ExtAddr` is not a 4-byte address; the
//!   Rust port returns an error instead.

mod network;
mod proxy;
mod proxy_packet;

#[cfg(test)]
#[path = "proxy_tests.rs"]
mod proxy_tests;

pub use network::UdpNetwork;

use crate::backend::common::ExternalInterface;
use crate::backend::traits::{Backend, Network};
use crate::ip::{IP4Net, IP4};
use crate::lease::LeaseAttrs;
use crate::subnet::config::Config;
use crate::subnet::manager::{Ctx, Manager};
use anyhow::anyhow;
use futures::future::BoxFuture;
use serde::Deserialize;
use std::net::IpAddr;
use std::sync::Arc;

/// Go `backendType`.
pub const BACKEND_TYPE: &str = "udp";
/// Go `defaultPort`.
pub const DEFAULT_PORT: i32 = 8285;

/// Go: `struct { Port int }` inline config (JSON `{"Port": N}`).
#[derive(Deserialize)]
struct UdpBackendConfig {
    #[serde(rename = "Port", default = "default_port")]
    port: i32,
}

const fn default_port() -> i32 {
    DEFAULT_PORT
}

/// Go `UdpBackend`.
pub struct UdpBackend {
    sm: Arc<dyn Manager>,
    ei: Arc<ExternalInterface>,
}

/// Port of Go `New` + `backend.Register("udp", New)` constructor shape.
pub fn new_backend(
    sm: Arc<dyn Manager>,
    ei: Arc<ExternalInterface>,
) -> anyhow::Result<Box<dyn Backend>> {
    Ok(Box::new(UdpBackend { sm, ei }))
}

/// Go `ip.FromIP(extIface.ExtAddr)` -- an error instead of a panic when
/// the external address is not IPv4.
fn ext_addr_ip4(ei: &ExternalInterface) -> anyhow::Result<IP4> {
    match ei.ext_addr {
        Some(IpAddr::V4(v4)) => Ok(IP4::from_bytes(v4.octets())),
        _ => Err(anyhow!("Address is not an IPv4 address")),
    }
}

impl Backend for UdpBackend {
    /// Go: `RegisterNetwork` (udp_amd64.go): parse the config, acquire
    /// the lease, then build the network (tun, UDP socket, ctl pair).
    fn register_network<'a>(
        &'a self,
        ctx: Ctx<'a>,
        config: &'a Config,
    ) -> BoxFuture<'a, anyhow::Result<Box<dyn Network>>> {
        Box::pin(async move {
            // Go: optional backend config JSON, default port 8285.
            let cfg = match &config.backend {
                Some(raw) => serde_json::from_str::<UdpBackendConfig>(raw.get())
                    .map_err(|e| anyhow!("error decoding UDP backend config: {e}"))?,
                None => UdpBackendConfig { port: DEFAULT_PORT },
            };

            // Go: LeaseAttrs{PublicIP: FromIP(ExtAddr)}; the udp backend
            // sets no BackendData.
            let attrs = LeaseAttrs {
                public_ip: ext_addr_ip4(&self.ei)?,
                ..Default::default()
            };

            let lease = match self.sm.acquire_lease(ctx, &attrs).await {
                Ok(l) => l,
                // Go: context.Canceled / DeadlineExceeded pass through.
                Err(e) if ctx.is_cancelled() => return Err(e),
                Err(e) => return Err(anyhow!("failed to acquire lease: {e}")),
            };

            // Tunnel's subnet is that of the whole overlay network (e.g.
            // /16) and not that of the individual host (e.g. /24).
            let tun_net = IP4Net::new(lease.subnet.ip, config.network.prefix_len);

            let nw =
                network::new_network(self.sm.clone(), self.ei.clone(), cfg.port, tun_net, lease)
                    .await?;
            Ok(Box::new(nw) as Box<dyn Network>)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_config_default_port() {
        let cfg: UdpBackendConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(cfg.port, 8285);
    }

    #[test]
    fn udp_config_custom_port() {
        let cfg: UdpBackendConfig = serde_json::from_str("{\"Port\": 9999}").unwrap();
        assert_eq!(cfg.port, 9999);
    }

    #[test]
    fn udp_config_bad_json() {
        assert!(serde_json::from_str::<UdpBackendConfig>("{\"Port\": \"x\"}").is_err());
    }
}
