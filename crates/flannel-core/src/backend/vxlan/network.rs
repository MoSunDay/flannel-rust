//! Port of vxlan_network.go's network plumbing (upstream cdf76059):
//! `newNetwork`, `MTU`, `Run`, `watchVXLANDevice`, `reCreateVxlan`.

use super::config::parse_vxlan_config;
use super::device::{VXLANDevice, ENCAP_OVERHEAD};
use super::events::handle_subnet_events;
use super::{configure_device_ipv4_ipv6, create_vxlan_device, DeviceParams};
use crate::backend::common::ExternalInterface;
use crate::backend::traits::Network;
use crate::ip::iface::{
    get_iface_ip4_addrs, get_iface_ip6_addrs, get_interface_by_name, get_link_mtu, Netlink,
};
use crate::lease::{Event, Lease};
use crate::subnet::manager::{Ctx, Manager};
use crate::subnet::watch::watch_leases;
use anyhow::anyhow;
use futures::future::BoxFuture;
use futures::StreamExt;
use netlink_packet_route::RouteNetlinkMessage;
use rtnetlink::packet_core::NetlinkPayload;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

/// Mutable network state shared by the run loop, the device watcher and
/// recreate (Go: the nw.dev / nw.v6Dev / nw.mtu fields).
#[derive(Clone, Debug, Default)]
pub(crate) struct NetState {
    pub(crate) dev: Option<VXLANDevice>,
    pub(crate) v6_dev: Option<VXLANDevice>,
    pub(crate) mtu: u32,
}

/// Go: `network` (vxlan_network.go) with SimpleNetwork's fields inlined.
pub struct VXLANNetwork {
    sm: Arc<dyn Manager>,
    ei: Arc<ExternalInterface>,
    lease: Lease,
    state: Arc<Mutex<NetState>>,
}

impl VXLANNetwork {
    /// Go: `newNetwork` (its `ip.IP4Net` parameter is unused upstream).
    pub(crate) fn new(
        sm: Arc<dyn Manager>,
        ei: Arc<ExternalInterface>,
        lease: Lease,
        dev: Option<VXLANDevice>,
        v6_dev: Option<VXLANDevice>,
        mtu: u32,
    ) -> Self {
        Self {
            sm,
            ei,
            lease,
            state: Arc::new(Mutex::new(NetState { dev, v6_dev, mtu })),
        }
    }
}

impl Network for VXLANNetwork {
    fn lease(&self) -> &Lease {
        &self.lease
    }

    /// Go: `MTU() int` = nw.mtu - encapOverhead. After a recreation Go
    /// stores the link MTU (already reduced) back into nw.mtu and
    /// subtracts again -- a quirk reproduced here.
    fn mtu(&self) -> u32 {
        self.state
            .lock()
            .unwrap()
            .mtu
            .saturating_sub(ENCAP_OVERHEAD)
    }

    /// Go: `Run`. Deviation: Go's `defer wg.Wait()` waits for the two
    /// goroutines; the Rust port drops the pinned futures instead.
    fn run<'a>(&'a self, ctx: Ctx<'a>) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            info!("watching for new subnet leases");
            let (ev_tx, mut ev_rx) = mpsc::channel::<Vec<Event>>(1);
            let (miss_tx, mut miss_rx) = mpsc::channel::<bool>(1);

            let watch = watch_leases(ctx, &*self.sm, &self.lease, ev_tx);
            tokio::pin!(watch);
            let dev_watch = self.watch_vxlan_device(ctx, miss_tx);
            tokio::pin!(dev_watch);
            let (mut watch_done, mut dev_watch_done) = (false, false);

            loop {
                tokio::select! {
                    biased;
                    ev = ev_rx.recv() => match ev {
                        Some(batch) => {
                            let Ok(nl) = Netlink::new().await else { continue };
                            handle_subnet_events(&nl, &self.state, &batch).await;
                        }
                        None => { info!("leaseEvents chan closed"); return; }
                    },
                    m = miss_rx.recv() => match m {
                        Some(_) => {
                            info!("vxlan device missing, attempting to recreate...");
                            let ctx = ctx.clone();
                            let (sm, ei, lease, state) = (
                                self.sm.clone(),
                                self.ei.clone(),
                                self.lease.clone(),
                                self.state.clone(),
                            );
                            tokio::spawn(async move {
                                if let Err(e) = recreate_vxlan(ctx, sm, ei, lease, state).await {
                                    error!("failed to recreate vxlan: {e}");
                                }
                            });
                        }
                        None => { info!("vxlanMissingChan closed"); return; }
                    },
                    _ = &mut watch, if !watch_done => {
                        watch_done = true;
                        debug!("WatchLeases exited");
                    }
                    _ = &mut dev_watch, if !dev_watch_done => {
                        dev_watch_done = true;
                        debug!("WatchVXLANDevice exited");
                    }
                }
            }
        })
    }
}

impl VXLANNetwork {
    /// Go: `watchVXLANDevice`. Deviation: Go `log.Fatalf`s on subscribe
    /// failure; the Rust port logs an error and returns (the run loop then
    /// observes the closed channel).
    async fn watch_vxlan_device(&self, ctx: Ctx<'_>, miss_tx: mpsc::Sender<bool>) {
        info!("starting vxlan device watcher");
        let name = {
            let st = self.state.lock().unwrap();
            match &st.dev {
                Some(d) => d.name.clone(),
                None => String::new(),
            }
        };
        if name.is_empty() {
            error!("vxlan device is nil, cannot watch for events");
            return;
        }

        let groups = [rtnetlink::MulticastGroup::Link];
        let (conn, _handle, mut messages) = match rtnetlink::new_multicast_connection(&groups) {
            Ok(c) => c,
            Err(e) => {
                error!("failed to subscribe to netlink: {e}");
                return;
            }
        };
        tokio::spawn(conn);

        loop {
            tokio::select! {
                biased;
                _ = ctx.cancelled() => {
                    info!("stopping vxlan device watcher");
                    return;
                }
                msg = messages.next() => {
                    let Some((msg, _addr)) = msg else { return };
                    if let NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelLink(link)) =
                        msg.payload
                    {
                        if super::link_info::link_name(&link) == name {
                            info!("Interface {name} deleted");
                            // Go's buffered channel: skip if already queued.
                            let _ = miss_tx.try_send(true);
                        }
                    }
                }
            }
        }
    }
}

/// Go: `reCreateVxlan` -- rebuilds the vxlan device(s) after a deletion,
/// retrying each step with a doubling backoff (1s, capped at 30s) until it
/// succeeds or the context is cancelled.
async fn recreate_vxlan(
    ctx: CancellationToken,
    sm: Arc<dyn Manager>,
    ei: Arc<ExternalInterface>,
    lease: Lease,
    state: Arc<Mutex<NetState>>,
) -> anyhow::Result<()> {
    const MAX_BACKOFF: Duration = Duration::from_secs(30);
    let mut backoff = Duration::from_secs(1);
    let name = ei.iface_name.clone();

    loop {
        if ctx.is_cancelled() {
            return Err(anyhow!("context canceled, stopping vxlan recreate"));
        }

        let Ok(nl) = Netlink::new().await else {
            retry_after_backoff(&mut backoff, MAX_BACKOFF).await;
            continue;
        };
        let iface = match get_interface_by_name(&nl, &name).await {
            Ok(i) => i,
            Err(_) => {
                info!(
                    "external interface {name} not found, retrying in {}",
                    go_duration(backoff)
                );
                retry_after_backoff(&mut backoff, MAX_BACKOFF).await;
                continue;
            }
        };
        let config = match sm.get_network_config(&ctx).await {
            Ok(c) => c,
            Err(e) => {
                error!("failed to get network config: {e}");
                retry_after_backoff(&mut backoff, MAX_BACKOFF).await;
                continue;
            }
        };
        let ext_mtu = get_link_mtu(&nl, iface.index).await.unwrap_or(0);
        let cfg = match parse_vxlan_config(config.backend.as_deref(), ext_mtu) {
            Ok(c) => c,
            Err(e) => {
                error!("failed to parse vxlan config: {e}");
                retry_after_backoff(&mut backoff, MAX_BACKOFF).await;
                continue;
            }
        };

        let mut iface_addr = None;
        if config.enable_ipv4 {
            match get_iface_ip4_addrs(&nl, &iface).await {
                Ok(addrs) if !addrs.is_empty() => iface_addr = Some(addrs[0]),
                Ok(_) => {
                    warn!("no IPv4 addresses found for interface {name}, retrying");
                    retry_after_backoff(&mut backoff, MAX_BACKOFF).await;
                    continue;
                }
                Err(e) => {
                    error!("error getting IPv4 addresses for {name}: {e}");
                    retry_after_backoff(&mut backoff, MAX_BACKOFF).await;
                    continue;
                }
            }
        }
        let mut iface_v6_addr = None;
        if config.enable_ipv6 {
            match get_iface_ip6_addrs(&nl, &iface).await {
                Ok(addrs) if !addrs.is_empty() => iface_v6_addr = Some(addrs[0]),
                Ok(_) => {
                    warn!("no IPv6 addresses found for interface {name}, retrying");
                    retry_after_backoff(&mut backoff, MAX_BACKOFF).await;
                    continue;
                }
                Err(e) => {
                    error!("error getting IPv6 addresses for {name}: {e}");
                    retry_after_backoff(&mut backoff, MAX_BACKOFF).await;
                    continue;
                }
            }
        }

        let (dev, v6_dev) = match create_vxlan_device(
            &ctx,
            &nl,
            DeviceParams {
                config: &config,
                cfg: &cfg,
                sm: &*sm,
                ext_iface_index: iface.index,
                ext_addr: iface_addr,
                ext_v6_addr: iface_v6_addr,
            },
        )
        .await
        {
            Ok(d) => d,
            Err(e) => {
                error!("failed to create vxlan device: {e}");
                retry_after_backoff(&mut backoff, MAX_BACKOFF).await;
                continue;
            }
        };

        if let Err(e) =
            configure_device_ipv4_ipv6(&nl, dev.as_ref(), v6_dev.as_ref(), &lease, &config).await
        {
            error!("failed to configure vxlan device: {e}");
            retry_after_backoff(&mut backoff, MAX_BACKOFF).await;
            continue;
        }

        let mut st = state.lock().unwrap();
        if let Some(dev) = dev {
            // Go: nw.dev / nw.mtu = dev.link.Attrs().MTU (the raw link MTU,
            // which MTU() then reduces a second time -- Go quirk kept).
            info!("VXLAN device {} recreated successfully", dev.name);
            st.mtu = dev.mtu;
            st.dev = Some(dev);
        }
        st.v6_dev = v6_dev;
        return Ok(());
    }
}

/// Go: `retryAfterBackoff` -- sleep the current backoff, then double it
/// (capped at max).
async fn retry_after_backoff(backoff: &mut Duration, max: Duration) {
    tokio::time::sleep(*backoff).await;
    *backoff = (*backoff * 2).min(max);
}

/// Go `time.Duration.String()` for whole-second backoffs ("1s", "30s").
fn go_duration(d: Duration) -> String {
    format!("{}s", d.as_secs())
}
