//! Port of pkg/backend/vxlan (upstream cdf76059): the VXLAN backend.
//!
//! - config.rs: `VXLANConfig` parsing (Go: parseVXLANConfig).
//! - device.rs: vxlan device creation/reuse + ARP/FDB ops (device.go).
//! - link_info.rs: netlink LinkMessage inspection helpers.
//! - network.rs: `Network` impl, run loop, device watcher, recreation
//!   (vxlan_network.go).
//! - events.rs: subnet lease event handling (handleSubnetEvents).
//!
//! Go deviation: Go's `New` constructor does no validation of the external
//! address; neither does this port.

mod config;
mod device;
mod events;
mod link_info;
mod network;

#[cfg(test)]
mod fake;
#[cfg(test)]
#[path = "network_tests.rs"]
mod network_tests;

pub use config::{parse_vxlan_config, VXLANConfig};
pub use device::{
    add_arp, add_fdb, configure_device_v4, configure_device_v6, del_arp, del_fdb, new_vxlan_device,
    VXLANAttrs, VXLANDevice,
};
pub use network::VXLANNetwork;

use crate::backend::common::ExternalInterface;
use crate::backend::traits::{Backend, Network};
use crate::ip::iface::{get_link_mtu, Netlink};
use crate::ip::{IP4Net, IP6Net, IP4, IP6};
use crate::lease::{Lease, LeaseAttrs};
use crate::mac::{mac_to_string, MacAddr};
use crate::subnet::config::Config;
use crate::subnet::manager::{Ctx, Manager};
use anyhow::{anyhow, bail};
use futures::future::BoxFuture;
use serde::Serialize;
use serde_json::value::RawValue;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::{error, info};

/// Go: `VXLANBackend`.
pub struct VXLANBackend {
    sm: Arc<dyn Manager>,
    ei: Arc<ExternalInterface>,
}

/// Port of Go `New` + `backend.Register("vxlan", New)` constructor shape.
pub fn new_backend(
    sm: Arc<dyn Manager>,
    ei: Arc<ExternalInterface>,
) -> anyhow::Result<Box<dyn Backend>> {
    Ok(Box::new(VXLANBackend { sm, ei }))
}

impl Backend for VXLANBackend {
    /// Go: `RegisterNetwork`. Parses the VXLAN config, creates (or reuses)
    /// the vxlan device(s), acquires the lease, configures the device IP.
    fn register_network<'a>(
        &'a self,
        ctx: Ctx<'a>,
        config: &'a Config,
    ) -> BoxFuture<'a, anyhow::Result<Box<dyn Network>>> {
        Box::pin(async move {
            let nl = Netlink::new().await?;
            // Go reads be.extIface.Iface.MTU; the Rust ExternalInterface
            // has no MTU, so fetch it from the link.
            let ext_mtu = get_link_mtu(&nl, self.ei.iface_index).await?;
            let cfg = parse_vxlan_config(config.backend.as_deref(), ext_mtu)
                .map_err(|e| anyhow!("error decoding VXLAN backend config: {e}"))?;
            info!(
                "VXLAN config: VNI={} Port={} GBP={} Learning={} DirectRouting={}",
                cfg.vni, cfg.port, cfg.gbp, cfg.learning, cfg.direct_routing
            );

            let (dev, v6_dev) = create_vxlan_device(
                ctx,
                &nl,
                DeviceParams {
                    config,
                    cfg: &cfg,
                    sm: &*self.sm,
                    ext_iface_index: self.ei.iface_index,
                    ext_addr: self.ei.ext_addr,
                    ext_v6_addr: self.ei.ext_v6_addr,
                },
            )
            .await
            .map_err(|e| anyhow!("failed to create vxlan device: {e}"))?;

            let subnet_attrs = new_subnet_attrs(
                self.ei.ext_addr,
                self.ei.ext_v6_addr,
                cfg.vni,
                dev.as_ref(),
                v6_dev.as_ref(),
            )?;

            let lease = match self.sm.acquire_lease(ctx, &subnet_attrs).await {
                Ok(l) => l,
                // Go: context.Canceled / DeadlineExceeded pass through.
                Err(e) if ctx.is_cancelled() => return Err(e),
                Err(e) => return Err(anyhow!("failed to acquire lease: {e}")),
            };

            // Give the device a /32 address so no broadcast routes are
            // created (Go comment).
            configure_device_ipv4_ipv6(&nl, dev.as_ref(), v6_dev.as_ref(), &lease, config).await?;

            Ok(Box::new(VXLANNetwork::new(
                self.sm.clone(),
                self.ei.clone(),
                lease,
                dev,
                v6_dev,
                cfg.mtu,
            )) as Box<dyn Network>)
        })
    }
}

/// Aggregated arguments for [`create_vxlan_device`] (keeps the call
/// signature within clippy's `too_many_arguments` bound).
pub(crate) struct DeviceParams<'a> {
    pub(crate) config: &'a Config,
    pub(crate) cfg: &'a VXLANConfig,
    pub(crate) sm: &'a dyn Manager,
    pub(crate) ext_iface_index: u32,
    pub(crate) ext_addr: Option<IpAddr>,
    pub(crate) ext_v6_addr: Option<IpAddr>,
}

/// Go: `createVXLANDevice`. Stored MAC annotations are restored onto the
/// devices (flannel restart stability); unparsable ones fall back to a
/// random MAC (with the Go log lines, in Go's exact order).
pub(crate) async fn create_vxlan_device(
    ctx: Ctx<'_>,
    nl: &Netlink,
    params: DeviceParams<'_>,
) -> anyhow::Result<(Option<VXLANDevice>, Option<VXLANDevice>)> {
    let DeviceParams {
        config,
        cfg,
        sm,
        ext_iface_index,
        ext_addr,
        ext_v6_addr,
    } = params;
    let (mac_str, mac_str_v6) = sm.get_stored_mac_addresses(ctx).await;

    let mut hw_addr = None;
    if !mac_str.is_empty() {
        match parse_mac(&mac_str) {
            Ok(m) => hw_addr = Some(m),
            Err(e) => error!("Failed to parse mac addr({mac_str}): {e}"),
        }
        info!(
            "Interface flannel.{} mac address set to: {mac_str}",
            cfg.vni
        );
    }

    let mut dev = None;
    if config.enable_ipv4 {
        let attrs = VXLANAttrs {
            name: format!("flannel.{}", cfg.vni),
            vni: cfg.vni,
            mtu: cfg.mtu,
            vtep_index: ext_iface_index,
            vtep_addr: ext_addr,
            port: cfg.port,
            gbp: cfg.gbp,
            learning: cfg.learning,
            hw_addr,
        };
        let mut d = new_vxlan_device(nl, &attrs).await?;
        d.direct_routing = cfg.direct_routing;
        dev = Some(d);
    }

    let mut hw_addr_v6 = None;
    if !mac_str_v6.is_empty() {
        match parse_mac(&mac_str_v6) {
            Ok(m) => hw_addr_v6 = Some(m),
            Err(e) => error!("Failed to parse mac addr({mac_str_v6}): {e}"),
        }
        info!(
            "Interface flannel-v6.{} mac address set to: {mac_str_v6}",
            cfg.vni
        );
    }

    let mut v6_dev = None;
    if config.enable_ipv6 {
        let attrs = VXLANAttrs {
            name: format!("flannel-v6.{}", cfg.vni),
            vni: cfg.vni,
            mtu: cfg.mtu,
            vtep_index: ext_iface_index,
            vtep_addr: ext_v6_addr,
            port: cfg.port,
            gbp: cfg.gbp,
            learning: cfg.learning,
            hw_addr: hw_addr_v6,
        };
        let mut d = new_vxlan_device(nl, &attrs).await?;
        d.direct_routing = cfg.direct_routing;
        v6_dev = Some(d);
    }

    Ok((dev, v6_dev))
}

/// Go: `configureDeviceIPv4IPv6`.
pub(crate) async fn configure_device_ipv4_ipv6(
    nl: &Netlink,
    dev: Option<&VXLANDevice>,
    v6_dev: Option<&VXLANDevice>,
    lease: &Lease,
    config: &Config,
) -> anyhow::Result<()> {
    if config.enable_ipv4 {
        // Go dereferences dev (panics on nil); bail instead with the same
        // message shape.
        let Some(dev) = dev else {
            bail!("failed to configure interface: IPv4 is enabled but no vxlan device");
        };
        if lease.subnet.empty() {
            bail!(
                "failed to configure interface {}: IPv4 is enabled but the lease has no IPv4",
                dev.name
            );
        }
        let ipa = IP4Net {
            ip: lease.subnet.ip,
            prefix_len: 32,
        };
        configure_device_v4(dev, nl, ipa, config.network)
            .await
            .map_err(|e| anyhow!("failed to configure interface {}: {e}", dev.name))?;
    }

    if config.enable_ipv6 {
        let Some(v6_dev) = v6_dev else {
            bail!("failed to configure interface: IPv6 is enabled but no vxlan device");
        };
        if lease.ipv6_subnet.empty() {
            bail!(
                "failed to configure interface {}: IPv6 is enabled but the lease has no IPv6",
                v6_dev.name
            );
        }
        let ipn = IP6Net {
            ip: lease.ipv6_subnet.ip,
            prefix_len: 128,
        };
        configure_device_v6(v6_dev, nl, ipn, config.ipv6_network)
            .await
            .map_err(|e| anyhow!("failed to configure interface {}: {e}", v6_dev.name))?;
    }

    Ok(())
}

/// Go: `vxlanLeaseAttrs` (BackendData / BackendV6Data payload).
#[derive(Serialize)]
struct VXLANLeaseAttrs {
    #[serde(rename = "VNI")]
    vni: u32,
    #[serde(rename = "VtepMAC")]
    vtep_mac: String,
}

/// Go: `newSubnetAttrs`.
fn new_subnet_attrs(
    public_ip: Option<IpAddr>,
    public_ipv6: Option<IpAddr>,
    vni: u32,
    dev: Option<&VXLANDevice>,
    v6_dev: Option<&VXLANDevice>,
) -> anyhow::Result<LeaseAttrs> {
    let mut attrs = LeaseAttrs {
        backend_type: "vxlan".to_string(),
        ..Default::default()
    };

    // Go only sets PublicIP when ExtAddr is an IPv4 (FromIP is v4-only).
    if let (Some(IpAddr::V4(ip)), Some(dev)) = (public_ip, dev) {
        let data = serde_json::to_string(&VXLANLeaseAttrs {
            vni,
            vtep_mac: mac_to_string(&dev.mac),
        })?;
        attrs.public_ip = IP4::from_bytes(ip.octets());
        attrs.backend_data = Some(RawValue::from_string(data)?);
    }

    if let (Some(IpAddr::V6(ip)), Some(v6_dev)) = (public_ipv6, v6_dev) {
        let data = serde_json::to_string(&VXLANLeaseAttrs {
            vni,
            vtep_mac: mac_to_string(&v6_dev.mac),
        })?;
        attrs.public_ipv6 = Some(IP6::from_std(ip));
        attrs.backend_v6_data = Some(RawValue::from_string(data)?);
    }

    Ok(attrs)
}

/// Port of `net.ParseMAC` for the 6-octet colon form flannel stores
/// (hyphen separators accepted too, like Go).
pub fn parse_mac(s: &str) -> anyhow::Result<MacAddr> {
    let parts: Vec<&str> = s.split([':', '-']).collect();
    if parts.len() != 6 {
        bail!("address {s}: invalid MAC address");
    }
    let mut out = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        if p.len() != 2 {
            bail!("address {s}: invalid MAC address");
        }
        out[i] = u8::from_str_radix(p, 16)
            .map_err(|_| anyhow!("address {s}: invalid hex digit in MAC address"))?;
    }
    Ok(out)
}
