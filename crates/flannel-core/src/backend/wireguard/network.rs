//! Port of pkg/backend/wireguard/wireguard_network.go (upstream
//! cdf76059): the wireguard `network` struct, its `Run` loop and
//! `handleSubnetEvents`.
//!
//! Go's `Run` spawns a goroutine feeding the `events` channel, selects on
//! `events` and `ctx.Done()`, and `defer wg.Wait()`s the goroutine. The
//! Rust port mirrors that: the watch runs as its own task that owns the
//! channel sender, so the sender drops -- and `recv()` observes the close
//! -- the moment the watch ends.
//!
//! Go deviation: on `GetNetworkConfig` error Go still adds routes for
//! the zero-valued config; the Rust port logs and skips the routes.

use super::genl::WgAllowedIp;
use super::{device, Mode, WireguardLeaseAttrs, BACKEND_TYPE, OVERHEAD};
use crate::backend::common::ExternalInterface;
use crate::backend::traits::Network;
use crate::ip::iface::Netlink;
use crate::ip::{IP4, IP6};
use crate::lease::{Event, EventType, Lease};
use crate::subnet::manager::{Ctx, Manager};
use crate::subnet::watch::watch_leases;
use futures::future::BoxFuture;
use netlink_packet_route::route::RouteScope;
use rtnetlink::RouteMessageBuilder;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

#[cfg(test)]
#[path = "network_tests.rs"]
mod network_tests;

/// Port of the Go `network` struct.
pub(crate) struct WireguardNetwork {
    sm: Arc<dyn Manager>,
    ei: Arc<ExternalInterface>,
    dev: Option<device::WGDevice>,
    v6_dev: Option<device::WGDevice>,
    mode: Mode,
    lease: Lease,
    mtu: u32,
}

/// Port of Go `newNetwork`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn new_wireguard_network(
    sm: Arc<dyn Manager>,
    ei: Arc<ExternalInterface>,
    dev: Option<device::WGDevice>,
    v6_dev: Option<device::WGDevice>,
    mode: Mode,
    lease: Lease,
    mtu: u32,
) -> WireguardNetwork {
    WireguardNetwork {
        sm,
        ei,
        dev,
        v6_dev,
        mode,
        lease,
        mtu,
    }
}

impl Network for WireguardNetwork {
    fn lease(&self) -> &Lease {
        &self.lease
    }

    /// Go: `MTU()` = n.mtu - overhead.
    fn mtu(&self) -> u32 {
        self.mtu.saturating_sub(OVERHEAD)
    }

    /// Go: `Run` (wireguard_network.go:78-100): spawn the lease watch,
    /// select over events and ctx.Done until either ends.
    fn run<'a>(&'a self, ctx: Ctx<'a>) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            info!("Watching for new subnet leases");
            let (ev_tx, mut ev_rx) = mpsc::channel::<Vec<Event>>(1);

            // Go: `go func() { subnet.WatchLeases(ctx, n.sm, n.lease,
            // events) }()`. The spawned task owns the sender: when the
            // watch ends (ctx done or manager end) the channel closes.
            let watch_task = tokio::spawn({
                let sm = self.sm.clone();
                let own_lease = self.lease.clone();
                let token = ctx.clone();
                async move { watch_leases(&token, &*sm, &own_lease, ev_tx).await }
            });

            loop {
                tokio::select! {
                    biased;
                    // Go: `case <-ctx.Done(): return`.
                    _ = ctx.cancelled() => break,
                    // Go: `case evtBatch := <-events:` (a closed channel
                    // would deliver the zero value in Go; here the close
                    // ends the loop like in the other backends).
                    batch = ev_rx.recv() => match batch {
                        Some(b) => self.handle_subnet_events(ctx, &b).await,
                        None => {
                            info!("evts chan closed");
                            break;
                        }
                    },
                }
            }

            // Go: `defer wg.Wait()`.
            let _ = watch_task.await;
        })
    }
}

/// Port of Go `selectMode`: pick the address family most likely to
/// allow a successful connection to the remote endpoint.
fn select_mode(ei: &ExternalInterface, ip4: IP4, ip6: Option<IP6>) -> Mode {
    let Some(ip6) = ip6 else {
        return Mode::Ipv4;
    };
    if !ip4.is_private() && ei.ext_addr.is_some() {
        return Mode::Ipv4;
    }
    if !ip6.is_private()
        && ei
            .ext_v6_addr
            .is_some_and(|a| matches!(a, IpAddr::V6(v6) if !IP6::from_std(v6).is_private()))
    {
        return Mode::Ipv6;
    }
    Mode::Ipv4
}
impl WireguardNetwork {
    /// Port of Go `handleSubnetEvents` (the Go `default` arm logging
    /// "Internal error: unknown event type" cannot occur: the Rust
    /// `EventType` enum is exhaustive).
    async fn handle_subnet_events(&self, ctx: Ctx<'_>, batch: &[Event]) {
        for event in batch {
            match event.event_type {
                EventType::Added => self.handle_added(ctx, event).await,
                EventType::Removed => self.handle_removed(event).await,
            }
        }
    }

    /// Port of the Go `lease.EventAdded` arm of `handleSubnetEvents`.
    async fn handle_added(&self, ctx: Ctx<'_>, event: &Event) {
        if event.lease.attrs.backend_type != BACKEND_TYPE {
            warn!(
                "Ignoring non-wireguard subnet: type={}",
                event.lease.attrs.backend_type
            );
            return;
        }

        let v4_allowed = WgAllowedIp {
            ip: IpAddr::V4(event.lease.subnet.ip.to_std()),
            cidr: event.lease.subnet.prefix_len as u8,
        };
        let v6_allowed = WgAllowedIp {
            ip: IpAddr::V6(event.lease.ipv6_subnet.ip.to_std()),
            cidr: event.lease.ipv6_subnet.prefix_len as u8,
        };
        let mut v4_attrs = WireguardLeaseAttrs::default();
        let mut v6_attrs = WireguardLeaseAttrs::default();
        // Go: `wireguardAttrs`, the attrs used in the non-Separate arm.
        let mut attrs = WireguardLeaseAttrs::default();
        // Only used if mode != Separate (Go comment).
        let mut subnet_strs: Vec<String> = Vec::new();
        if event.lease.enable_ipv4 {
            if let Some(raw) = &event.lease.attrs.backend_data {
                match serde_json::from_str::<WireguardLeaseAttrs>(raw.get()) {
                    Ok(a) => v4_attrs = a,
                    Err(e) => {
                        error!("failed to unmarshal BackendData: {e}");
                        return;
                    }
                }
            }
            attrs = v4_attrs.clone();
            subnet_strs.push(event.lease.subnet.to_string());
        }
        if event.lease.enable_ipv6 {
            if let Some(raw) = &event.lease.attrs.backend_v6_data {
                match serde_json::from_str::<WireguardLeaseAttrs>(raw.get()) {
                    Ok(a) => v6_attrs = a,
                    Err(e) => {
                        error!("failed to unmarshal BackendData: {e}");
                        return;
                    }
                }
            }
            attrs = v6_attrs.clone();
            subnet_strs.push(event.lease.ipv6_subnet.to_string());
        }

        // Default to the port in the attrs, but use the device's listen
        // port if it's not set, for backwards compatibility with older
        // flannel versions.
        let mut v4_port = v4_attrs.port;
        if v4_port == 0 {
            if let Some(dev) = &self.dev {
                v4_port = dev.attrs.listen_port;
            }
        }
        let mut v6_port = v6_attrs.port;
        if v6_port == 0 {
            if let Some(dev) = &self.v6_dev {
                v6_port = dev.attrs.listen_port;
            }
        }
        let v4_endpoint = format!("{}:{v4_port}", event.lease.attrs.public_ip);
        let v6_endpoint = event
            .lease
            .attrs
            .public_ipv6
            .map(|ip| format!("[{ip}]:{v6_port}"))
            .unwrap_or_default();

        if self.mode == Mode::Separate {
            if event.lease.enable_ipv4 {
                info!("Subnet added: {} via {v4_endpoint}", event.lease.subnet);
                if let Some(dev) = &self.dev {
                    if let Err(e) =
                        device::add_peer(dev, &v4_endpoint, &v4_attrs.public_key, vec![v4_allowed])
                            .await
                    {
                        error!("failed to setup ipv4 peer ({}): {e}", v4_attrs.public_key);
                    }
                }
                self.add_config_route(ctx, &self.dev, true).await;
            }
            if event.lease.enable_ipv6 {
                info!(
                    "Subnet added: {} via {v6_endpoint}",
                    event.lease.ipv6_subnet
                );
                if let Some(dev) = &self.v6_dev {
                    if let Err(e) =
                        device::add_peer(dev, &v6_endpoint, &v6_attrs.public_key, vec![v6_allowed])
                            .await
                    {
                        error!("failed to setup ipv6 peer ({}): {e}", v6_attrs.public_key);
                    }
                }
                self.add_config_route(ctx, &self.v6_dev, false).await;
            }
            return;
        }

        // Auto / Ipv4 / Ipv6: one device carries all subnets.
        let mut mode = self.mode;
        if mode == Mode::Auto {
            mode = select_mode(
                &self.ei,
                event.lease.attrs.public_ip,
                event.lease.attrs.public_ipv6,
            );
        }
        let endpoint = if mode == Mode::Ipv6 {
            v6_endpoint
        } else {
            v4_endpoint
        };
        info!(
            "Subnet(s) added: [{}] via {endpoint}",
            subnet_strs.join(" ")
        );
        let mut peers = Vec::new();
        if event.lease.enable_ipv4 {
            peers.push(v4_allowed);
        }
        if event.lease.enable_ipv6 {
            peers.push(v6_allowed);
        }
        if let Some(dev) = &self.dev {
            if let Err(e) = device::add_peer(dev, &endpoint, &attrs.public_key, peers).await {
                // Go quirk: the error prints the *v4* attrs public key.
                error!("failed to setup peer ({}): {e}", v4_attrs.public_key);
            }
        }
        match self.sm.get_network_config(ctx).await {
            Ok(netconf) => {
                if let Some(dev) = &self.dev {
                    let dst = IpAddr::V4(netconf.network.ip.to_std());
                    let disp = netconf.network.to_string();
                    if let Err(e) =
                        add_net_route(dev, dst, netconf.network.prefix_len as u8, &disp).await
                    {
                        error!("failed to add ipv4 route to ({}): {e}", netconf.network);
                    }
                    let dst = IpAddr::V6(netconf.ipv6_network.ip.to_std());
                    let disp = netconf.ipv6_network.to_string();
                    if let Err(e) =
                        add_net_route(dev, dst, netconf.ipv6_network.prefix_len as u8, &disp).await
                    {
                        error!(
                            "failed to add ipv6 route to ({}): {e}",
                            netconf.ipv6_network
                        );
                    }
                }
            }
            Err(e) => error!("could not read network config: {e}"),
        }
    }

    /// Port of the Go Separate-mode route step: `GetNetworkConfig` then
    /// `addRoute(Network)` (v4, on dev) or `addRoute(IPv6Network)`
    /// (v6, on v6Dev).
    async fn add_config_route(&self, ctx: Ctx<'_>, dev: &Option<device::WGDevice>, v4: bool) {
        let Some(dev) = dev else { return };
        match self.sm.get_network_config(ctx).await {
            Ok(netconf) => {
                let (dst, plen, disp) = if v4 {
                    (
                        IpAddr::V4(netconf.network.ip.to_std()),
                        netconf.network.prefix_len as u8,
                        netconf.network.to_string(),
                    )
                } else {
                    (
                        IpAddr::V6(netconf.ipv6_network.ip.to_std()),
                        netconf.ipv6_network.prefix_len as u8,
                        netconf.ipv6_network.to_string(),
                    )
                };
                if let Err(e) = add_net_route(dev, dst, plen, &disp).await {
                    if v4 {
                        error!("failed to add ipv4 route to ({disp}): {e}");
                    } else {
                        error!("failed to add ipv6 route to ({disp}): {e}");
                    }
                }
            }
            Err(e) => error!("could not read network config: {e}"),
        }
    }

    /// Port of the Go `lease.EventRemoved` arm of `handleSubnetEvents`.
    async fn handle_removed(&self, event: &Event) {
        if event.lease.attrs.backend_type != BACKEND_TYPE {
            warn!(
                "Ignoring non-wireguard subnet: type={}",
                event.lease.attrs.backend_type
            );
            return;
        }
        let mut attrs = WireguardLeaseAttrs::default();
        if event.lease.enable_ipv4 {
            if let Some(dev) = &self.dev {
                info!("Subnet removed: {}", event.lease.subnet);
                if let Some(raw) = &event.lease.attrs.backend_data {
                    match serde_json::from_str::<WireguardLeaseAttrs>(raw.get()) {
                        Ok(a) => attrs = a,
                        Err(e) => {
                            error!("failed to unmarshal BackendData: {e}");
                            return;
                        }
                    }
                }
                if let Err(e) = device::remove_peer(dev, &attrs.public_key).await {
                    error!("failed to remove ipv4 peer ({}): {e}", attrs.public_key);
                }
            }
        }
        if event.lease.enable_ipv6 {
            info!("Subnet removed: {}", event.lease.ipv6_subnet);
            if let Some(raw) = &event.lease.attrs.backend_v6_data {
                match serde_json::from_str::<WireguardLeaseAttrs>(raw.get()) {
                    Ok(a) => attrs = a,
                    Err(e) => {
                        error!("failed to unmarshal BackendData: {e}");
                        return;
                    }
                }
            }
            let target = if self.mode == Mode::Separate && self.v6_dev.is_some() {
                self.v6_dev.as_ref()
            } else {
                self.dev.as_ref()
            };
            if let Some(dev) = target {
                if let Err(e) = device::remove_peer(dev, &attrs.public_key).await {
                    error!("failed to remove ipv6 peer ({}): {e}", attrs.public_key);
                }
            }
        }
    }
}

/// Port of Go `(*wgDevice).addRoute(route.ToIPNet())` as used by the
/// event loop: SCOPE_LINK route via the wireguard device, double-wrapped
/// error message like Go's `upAndAddRoute`.
async fn add_net_route(
    dev: &device::WGDevice,
    dst: IpAddr,
    prefix_len: u8,
    disp: &str,
) -> anyhow::Result<()> {
    let nl = Netlink::new().await?;
    let msg = match dst {
        IpAddr::V4(v4) => RouteMessageBuilder::<Ipv4Addr>::new()
            .destination_prefix(v4, prefix_len)
            .output_interface(dev.ifindex)
            .scope(RouteScope::Link)
            .build(),
        IpAddr::V6(v6) => RouteMessageBuilder::<Ipv6Addr>::new()
            .destination_prefix(v6, prefix_len)
            .output_interface(dev.ifindex)
            .scope(RouteScope::Link)
            .build(),
    };
    device::up_and_add_route(&nl, dev, msg, disp).await
}
