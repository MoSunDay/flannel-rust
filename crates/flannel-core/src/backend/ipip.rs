//! Port of pkg/backend/ipip/ipip.go (upstream cdf76059): the "ipip"
//! backend. Creates the `flannel.ipip` IPIP tunnel device and routes
//! peer subnets through it (optionally direct-routed for L2-adjacent
//! peers). IPv4 only, like Go.
//!
//! Go deviation: Go keeps reusing the locally built `netlink.Iptun`
//! object after `LinkAdd` (vishvananda refetches the index there); the
//! Rust port re-fetches the link by name after create/validate, which is
//! equivalent and also correct on the "device already existed" path.

use crate::backend::common::ExternalInterface;
use crate::backend::route_network::spec::RouteSpec;
use crate::backend::route_network::{GetRouteFn, RouteNetwork};
use crate::backend::traits::{Backend, Network};
use crate::ip::iface::{direct_routing, ensure_v4_address_on_link, Netlink};
use crate::ip::{IP4Net, IP4};
use crate::lease::{Lease, LeaseAttrs};
use crate::subnet::config::Config;
use crate::subnet::manager::{Ctx, Manager};
use futures::future::BoxFuture;
use futures::stream::TryStreamExt;
use netlink_packet_route::link::{
    InfoData, InfoIpTunnel, InfoKind, LinkAttribute, LinkInfo, LinkMessage,
};
use netlink_packet_route::AddressFamily;
use rtnetlink::{LinkIpIp, LinkUnspec};
use serde::Deserialize;
use std::net::IpAddr;
use std::sync::Arc;

/// Go `backendType`.
pub const BACKEND_TYPE: &str = "ipip";
/// Go `tunnelName`.
pub const TUNNEL_NAME: &str = "flannel.ipip";

/// Port of Go `HostgwBackend`-style holder: `IPIPBackend{sm, extIface}`.
pub struct IPIPBackend {
    pub sm: Arc<dyn Manager>,
    pub ei: Arc<ExternalInterface>,
}

/// Port of Go `ipip.New`, registered as `"ipip"` (Go `init()`).
pub fn new_backend(
    sm: Arc<dyn Manager>,
    ei: Arc<ExternalInterface>,
) -> anyhow::Result<Box<dyn Backend>> {
    Ok(Box::new(IPIPBackend { sm, ei }))
}

/// Go backend config struct: `struct { DirectRouting bool }`.
#[derive(Clone, Copy, Debug, Default, Deserialize)]
struct IPIPBackendConfig {
    #[serde(rename = "DirectRouting", default)]
    direct_routing: bool,
}

/// Port of Go `ip.FromIP` (same panic message, as an error here).
fn ext_addr_ip4(ei: &ExternalInterface) -> anyhow::Result<IP4> {
    match ei.ext_addr {
        Some(IpAddr::V4(v4)) => Ok(IP4::from_bytes(v4.octets())),
        _ => anyhow::bail!("Address is not an IPv4 address"),
    }
}

/// Go `expectMTU := extIface.Iface.MTU - 20` with the too-small check.
pub fn expected_tunnel_mtu(ext_mtu: u32, iface_name: &str) -> anyhow::Result<u32> {
    if ext_mtu <= 20 {
        anyhow::bail!("MTU {ext_mtu} of iface {iface_name} is too small for ipip mode to work");
    }
    Ok(ext_mtu - 20)
}

/// Port of the Go `GetRoute` closure: route via the tunnel device with
/// FLAG_ONLINK (no gateway resolution needed on a point-to-point-style
/// tunnel); with DirectRouting enabled, L2-adjacent peers are routed
/// directly on the external interface instead.
pub fn ipip_get_route(
    nl: Netlink,
    is_direct_routing: bool,
    tunnel_index: u32,
    ext_index: u32,
) -> GetRouteFn {
    Arc::new(move |lease: &Lease| {
        let mut spec = RouteSpec {
            dst: IpAddr::V4(lease.subnet.ip.to_std()),
            prefix_len: lease.subnet.prefix_len as u8,
            gateway: IpAddr::V4(lease.attrs.public_ip.to_std()),
            link_index: tunnel_index,
            family: AddressFamily::Inet,
            onlink: true,
        };
        if !is_direct_routing {
            return Box::pin(async move { spec });
        }
        let gw = spec.gateway;
        let nl = nl.clone();
        Box::pin(async move {
            match direct_routing(&nl, gw).await {
                Ok(true) => {
                    tracing::debug!("configure route to {gw} via direct routing");
                    spec.link_index = ext_index;
                }
                Ok(false) => {}
                Err(e) => tracing::error!("{e}"),
            }
            spec
        })
    })
}

impl Backend for IPIPBackend {
    /// Port of Go `(*IPIPBackend).RegisterNetwork`: parse the optional
    /// backend JSON, acquire the lease, create/validate the tunnel
    /// device, then wire the RouteNetwork.
    fn register_network<'a>(
        &'a self,
        ctx: Ctx<'a>,
        config: &'a Config,
    ) -> BoxFuture<'a, anyhow::Result<Box<dyn Network>>> {
        Box::pin(async move {
            let cfg = match &config.backend {
                Some(raw) => serde_json::from_str::<IPIPBackendConfig>(raw.get())
                    .map_err(|e| anyhow::anyhow!("error decoding IPIP backend config: {e}"))?,
                None => IPIPBackendConfig::default(),
            };
            tracing::info!("IPIP config: DirectRouting={}", cfg.direct_routing);

            let nl = Netlink::new().await?;
            let attrs = LeaseAttrs {
                public_ip: ext_addr_ip4(&self.ei)?,
                backend_type: BACKEND_TYPE.to_string(),
                ..Default::default()
            };

            let lease = match self.sm.acquire_lease(ctx, &attrs).await {
                Ok(lease) => lease,
                // Go: case context.Canceled, context.DeadlineExceeded.
                Err(e) if ctx.is_cancelled() => return Err(e),
                Err(e) => return Err(anyhow::anyhow!("failed to acquire lease: {e}")),
            };

            let (link_index, mtu) =
                configure_ipip_device(&nl, &self.ei, &lease, config.network).await?;

            let get_route = ipip_get_route(
                nl.clone(),
                cfg.direct_routing,
                link_index,
                self.ei.iface_index,
            );

            Ok(Box::new(RouteNetwork {
                lease,
                backend_type: BACKEND_TYPE.to_string(),
                sm: self.sm.clone(),
                mtu,
                link_index,
                get_route: Some(get_route),
                get_v6_route: None,
            }) as Box<dyn Network>)
        })
    }
}

/// True when a LinkAdd failed because the device already exists.
fn is_eexist(e: &rtnetlink::Error) -> bool {
    matches!(e, rtnetlink::Error::NetlinkError(msg)
        if msg.code.is_some_and(|c| c.get() == -libc::EEXIST))
}

/// InfoKind of a link, if the kernel reported one.
fn link_kind(msg: &LinkMessage) -> Option<InfoKind> {
    msg.attributes.iter().find_map(|a| match a {
        LinkAttribute::LinkInfo(infos) => infos.iter().find_map(|i| match i {
            LinkInfo::Kind(k) => Some(k.clone()),
            _ => None,
        }),
        _ => None,
    })
}

/// Local/Remote tunnel endpoints reported by the kernel, if any.
fn iptun_local_remote(msg: &LinkMessage) -> (Option<IpAddr>, Option<IpAddr>) {
    let infos = msg.attributes.iter().find_map(|a| match a {
        LinkAttribute::LinkInfo(infos) => Some(infos),
        _ => None,
    });
    let mut local = None;
    let mut remote = None;
    if let Some(infos) = infos {
        for info in infos {
            if let LinkInfo::Data(InfoData::IpTunnel(attrs)) = info {
                for attr in attrs {
                    match attr {
                        InfoIpTunnel::Local(ip) => local = Some(*ip),
                        InfoIpTunnel::Remote(ip) => remote = Some(*ip),
                        _ => {}
                    }
                }
            }
        }
    }
    (local, remote)
}

async fn link_by_name(nl: &Netlink, name: &str) -> anyhow::Result<LinkMessage> {
    let mut links = nl.handle.link().get().match_name(name).execute();
    match links.try_next().await.map_err(|e| anyhow::anyhow!("{e}"))? {
        Some(link) => Ok(link),
        // Go netlink.LinkByName error text.
        None => anyhow::bail!("Link not found"),
    }
}

/// Port of Go `configureIPIPDevice`: ensure `flannel.ipip` exists with
/// local == ext iface address (recreate when incompatible), size the MTU
/// to ext MTU - 20, assign the lease subnet's first IP as a /32, set UP.
/// Returns `(link index, final MTU)`.
async fn configure_ipip_device(
    nl: &Netlink,
    ei: &ExternalInterface,
    lease: &Lease,
    flannelnet: IP4Net,
) -> anyhow::Result<(u32, u32)> {
    // When modprobe ipip module, a tunl0 ipip device is created
    // automatically per network namespace by ipip kernel module. It is
    // the namespace default IPIP device with attributes local=any and
    // remote=any. [...] Considering tunl0 might be used by users, we
    // create a new ipip device and set its local attribute to
    // distinguish the two (comments abridged from upstream).
    let local = match ei.iface_addr {
        Some(IpAddr::V4(v4)) => v4,
        _ => anyhow::bail!("Address is not an IPv4 address"),
    };
    let link_msg = LinkIpIp::new(TUNNEL_NAME).local(local).build();

    if let Err(e) = nl.handle.link().add(link_msg).execute().await {
        if !is_eexist(&e) {
            return Err(anyhow::anyhow!("{e}"));
        }

        // The link already exists, so check existing link attributes.
        let existing = link_by_name(nl, TUNNEL_NAME).await?;

        // Go checks `existing.Type() != "ipip"` and the *Iptun cast;
        // both collapse to the InfoKind check with this crate stack.
        if link_kind(&existing) != Some(InfoKind::IpIp) {
            anyhow::bail!(
                "{TUNNEL_NAME} isn't an ipip mode device, please remove device and try again"
            );
        }

        // local should be equal to extIface.IfaceAddr and remote should
        // be nil (or 0.0.0.0); otherwise recreate the device.
        let (tun_local, tun_remote) = iptun_local_remote(&existing);
        let bad_local = tun_local != Some(IpAddr::V4(local));
        let bad_remote = tun_remote.is_some_and(|r| !r.is_unspecified());
        if bad_local || bad_remote {
            let disp = |ip: Option<IpAddr>| {
                ip.map(|i| i.to_string())
                    .unwrap_or_else(|| "<nil>".to_string())
            };
            tracing::warn!(
                "\"{TUNNEL_NAME}\" already exists with incompatible attributes: local={} remote={}; recreating device",
                disp(tun_local),
                disp(tun_remote)
            );

            if let Err(e) = nl.handle.link().del(existing.header.index).execute().await {
                anyhow::bail!("failed to delete interface: {e}");
            }
            let redo = LinkIpIp::new(TUNNEL_NAME).local(local).build();
            if let Err(e) = nl.handle.link().add(redo).execute().await {
                anyhow::bail!("failed to create ipip interface: {e}");
            }
        }
    }

    let link = link_by_name(nl, TUNNEL_NAME).await?;
    let link_index = link.header.index;
    let old_mtu = crate::ip::iface::link_mtu(&link);

    // Due to the extra 20 byte IP header that the tunnel will add to
    // each packet, MTU size for both the workload and tunnel interfaces
    // should be 20 bytes less than the selected iface.
    let expect_mtu = expected_tunnel_mtu(
        crate::ip::iface::get_link_mtu(nl, ei.iface_index).await?,
        &ei.iface_name,
    )?;
    let mut mtu = old_mtu;
    if old_mtu > expect_mtu || old_mtu == 0 {
        tracing::info!("current MTU of {TUNNEL_NAME} is {old_mtu}, setting it to {expect_mtu}");
        let set = LinkUnspec::new_with_index(link_index)
            .mtu(expect_mtu)
            .build();
        if let Err(e) = nl.handle.link().set(set).execute().await {
            anyhow::bail!("failed to set {TUNNEL_NAME} MTU to {expect_mtu}: {e}");
        }
        mtu = expect_mtu;
    }

    // Ensure the device has a /32 address so no broadcast routes are
    // created; it is the source address for host-to-workload traffic.
    let ipa = IP4Net::new(lease.subnet.ip, 32);
    if let Err(e) = ensure_v4_address_on_link(nl, ipa, flannelnet, link_index).await {
        anyhow::bail!("failed to ensure address of interface {TUNNEL_NAME}: {e}");
    }

    let up = LinkUnspec::new_with_index(link_index).up().build();
    if let Err(e) = nl.handle.link().set(up).execute().await {
        anyhow::bail!("failed to set {TUNNEL_NAME} UP: {e}");
    }

    Ok((link_index, mtu))
}

#[cfg(test)]
#[path = "ipip/tests.rs"]
mod tests;
