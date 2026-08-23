//! Port of ipsec_network.go (plus the xfrm policy orchestration of
//! handle_xfrm.go): the ipsec `Network`, its PSK-load + lease-watch run
//! loop, subnet event handling and kernel policy add/delete.

use super::charon::{self, Charon};
use super::xfrm::{self, XfrmPolicySpec, DIR_FWD, DIR_IN, DIR_OUT};
use crate::backend::traits::Network;
use crate::lease::{Event, EventType, Lease};
use crate::subnet::manager::{Ctx, Manager};
use crate::subnet::watch::watch_leases;
use anyhow::anyhow;
use futures::future::BoxFuture;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

#[cfg(test)]
#[path = "network_tests.rs"]
mod network_tests;

/// Go `ipsecOverhead` (bytes): new IP header 20, SPI 4, sequence 4,
/// ESP-AES IV 16, pad 0-15, pad length 1, next header 1, SHA-256 ICV 16.
const IPSEC_OVERHEAD: u32 = 77;
/// Go `udpEncapOverhead` (extra UDP encapsulation header).
const UDP_ENCAP_OVERHEAD: u32 = 8;
/// Go `defaultReqID`.
pub(crate) const DEFAULT_REQ_ID: u32 = 11;

/// Port of Go `network` (embeds `SimpleNetwork`). Go deviation: Go's
/// `MTU()` reads `ExtIface.Iface.MTU` on every call; the Rust
/// `ExternalInterface` has no MTU, so `register_network` resolves it and
/// `new_network` applies the overhead once (same result).
pub struct IPsecNetwork {
    lease: Lease,
    mtu: u32,
    password: String,
    udp_encap: bool,
    sm: Arc<dyn Manager>,
    iked: Charon,
}

/// Go: `newNetwork` (the `ext_mtu` replaces Go's `ExtIface.Iface.MTU`).
pub fn new_network(
    sm: Arc<dyn Manager>,
    ext_mtu: u32,
    udp_encap: bool,
    password: String,
    iked: Charon,
    lease: Lease,
) -> IPsecNetwork {
    let mut mtu = ext_mtu.saturating_sub(IPSEC_OVERHEAD);
    if udp_encap {
        mtu = mtu.saturating_sub(UDP_ENCAP_OVERHEAD);
    }
    IPsecNetwork {
        lease,
        mtu,
        password,
        udp_encap,
        sm,
        iked,
    }
}

impl Network for IPsecNetwork {
    fn lease(&self) -> &Lease {
        &self.lease
    }

    fn mtu(&self) -> u32 {
        self.mtu
    }

    /// Go: `Run`: load the own PSK, then watch lease events and process
    /// them until the watch ends.
    fn run<'a>(&'a self, ctx: Ctx<'a>) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let own_ip = self.lease.attrs.public_ip.to_string();
            if let Err(e) = charon::load_shared_key(ctx, &own_ip, &self.password).await {
                error!("Failed to load PSK: {e}");
                return;
            }

            info!("Watching for new subnet leases");
            let (ev_tx, mut ev_rx) = mpsc::channel::<Vec<Event>>(1);
            let watch = watch_leases(ctx, &*self.sm, &self.lease, ev_tx);
            tokio::pin!(watch);
            let mut watch_done = false;

            loop {
                tokio::select! {
                    biased;
                    batch = ev_rx.recv() => match batch {
                        Some(events) => {
                            info!("Handling event");
                            handle_subnet_events(ctx, self, &events).await;
                        }
                        None => {
                            info!("evts chan closed");
                            return;
                        }
                    },
                    _ = &mut watch, if !watch_done => {
                        watch_done = true;
                        info!("WatchLeases exited");
                    }
                }
            }
        })
    }
}

/// Go: `handleSubnetEvents`.
async fn handle_subnet_events(ctx: Ctx<'_>, net: &IPsecNetwork, batch: &[Event]) {
    for evt in batch {
        match evt.event_type {
            EventType::Added => {
                info!("Subnet added: {}", evt.lease.subnet);
                if evt.lease.attrs.backend_type != super::BACKEND_TYPE {
                    warn!(
                        "Ignoring non-ipsec event: type: {}",
                        evt.lease.attrs.backend_type
                    );
                    continue;
                }
                if evt.lease.subnet == net.lease.subnet {
                    warn!("Ignoring own lease add event: {:?}", evt.lease);
                    continue;
                }
                if let Err(e) = add_ipsec_policies(&net.lease, &evt.lease, DEFAULT_REQ_ID).await {
                    error!("error adding ipsec policy: {e}");
                }
                let remote_ip = evt.lease.attrs.public_ip.to_string();
                if let Err(e) = charon::load_shared_key(ctx, &remote_ip, &net.password).await {
                    error!("error loading shared key into IKE daemon: {e}");
                }
                let req_id = DEFAULT_REQ_ID.to_string();
                if let Err(e) = charon::load_connection(
                    ctx,
                    &net.iked,
                    &net.lease,
                    &evt.lease,
                    &req_id,
                    net.udp_encap,
                )
                .await
                {
                    error!("error loading connection into IKE daemon: {e}");
                }
            }
            EventType::Removed => {
                info!("Subnet removed: {}", evt.lease.subnet);
                if evt.lease.attrs.backend_type != super::BACKEND_TYPE {
                    warn!(
                        "Ignoring non-ipsec event: type: {}",
                        evt.lease.attrs.backend_type
                    );
                    continue;
                }
                if evt.lease.subnet == net.lease.subnet {
                    warn!("Ignoring own lease remove event: {:?}", evt.lease);
                    continue;
                }
                if let Err(e) = charon::unload_charon_connection(ctx, &net.lease, &evt.lease).await
                {
                    error!("error unloading charon connections: {e}");
                }
                if let Err(e) = delete_ipsec_policies(&net.lease, &evt.lease, DEFAULT_REQ_ID).await
                {
                    error!("error deleting ipsec policies: {e}");
                }
            }
        }
    }
}

/// Go: `AddIPSECPolicies(remoteLease, reqID)` — OUT, IN and FWD.
async fn add_ipsec_policies(
    local_lease: &Lease,
    remote_lease: &Lease,
    req_id: u32,
) -> anyhow::Result<()> {
    add_xfrm_policy(local_lease, remote_lease, DIR_OUT, req_id)
        .await
        .map_err(|e| anyhow!("error adding ipsec out policy: {e}"))?;
    add_xfrm_policy(remote_lease, local_lease, DIR_IN, req_id)
        .await
        .map_err(|e| anyhow!("error adding ipsec in policy: {e}"))?;
    add_xfrm_policy(remote_lease, local_lease, DIR_FWD, req_id)
        .await
        .map_err(|e| anyhow!("error adding ipsec fwd policy: {e}"))
}

/// Go: `DeleteIPSECPolicies(localSubnet, remoteSubnet, localPublicIP,
/// remotePublicIP, reqID)` — OUT, IN and FWD (same argument data, taken
/// from the leases).
async fn delete_ipsec_policies(
    local_lease: &Lease,
    remote_lease: &Lease,
    req_id: u32,
) -> anyhow::Result<()> {
    del_xfrm_policy(local_lease, remote_lease, DIR_OUT, req_id)
        .await
        .map_err(|e| anyhow!("error deleting ipsec out policy: {e}"))?;
    del_xfrm_policy(remote_lease, local_lease, DIR_IN, req_id)
        .await
        .map_err(|e| anyhow!("error deleting ipsec in policy: {e}"))?;
    del_xfrm_policy(remote_lease, local_lease, DIR_FWD, req_id)
        .await
        .map_err(|e| anyhow!("error deleting ipsec fwd policy: {e}"))
}

/// One policy spec in the shape handle_xfrm.go builds (selector = the
/// two subnets, template = the two public IPs, ESP tunnel).
fn policy_spec(src_lease: &Lease, dst_lease: &Lease, dir: u8, req_id: u32) -> XfrmPolicySpec {
    XfrmPolicySpec {
        src: src_lease.subnet.ip.to_std().into(),
        src_prefix: src_lease.subnet.prefix_len as u8,
        dst: dst_lease.subnet.ip.to_std().into(),
        dst_prefix: dst_lease.subnet.prefix_len as u8,
        dir,
        tunnel_src: src_lease.attrs.public_ip.to_std().into(),
        tunnel_dst: dst_lease.attrs.public_ip.to_std().into(),
        reqid: req_id,
    }
}

/// Go: `AddXFRMPolicy(myLease, remoteLease, dir, reqID)` — GET first:
/// absent (ENOENT) -> Add, present -> Update.
async fn add_xfrm_policy(
    my_lease: &Lease,
    remote_lease: &Lease,
    dir: u8,
    req_id: u32,
) -> anyhow::Result<()> {
    let spec = policy_spec(my_lease, remote_lease, dir, req_id);
    tokio::task::spawn_blocking(move || {
        match xfrm::get_policy(&spec)? {
            None => {
                info!(
                    "Adding ipsec policy: src={} dst={} dir={dir} reqid={}",
                    spec.tunnel_src, spec.tunnel_dst, spec.reqid
                );
                xfrm::add_policy(&spec).map_err(|e| anyhow!("error adding policy: {e}"))?;
            }
            Some(existing) => {
                info!(
                    "Updating ipsec policy index={} dir={dir} reqid={}",
                    existing.index, spec.reqid
                );
                xfrm::update_policy(&spec).map_err(|e| anyhow!("error updating policy: {e}"))?;
            }
        }
        Ok(())
    })
    .await?
}

/// Go: `DeleteXFRMPolicy(localSubnet, remoteSubnet, localPublicIP,
/// remotePublicIP, dir, reqID)`.
async fn del_xfrm_policy(
    src_lease: &Lease,
    dst_lease: &Lease,
    dir: u8,
    req_id: u32,
) -> anyhow::Result<()> {
    let spec = policy_spec(src_lease, dst_lease, dir, req_id);
    tokio::task::spawn_blocking(move || {
        info!(
            "Deleting ipsec policy: src={} dst={} dir={dir} reqid={}",
            spec.tunnel_src, spec.tunnel_dst, spec.reqid
        );
        xfrm::del_policy(&spec).map_err(|e| anyhow!("error deleting policy: {e}"))
    })
    .await?
}
