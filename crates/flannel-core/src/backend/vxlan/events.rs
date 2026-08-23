//! Port of `handleSubnetEvents` (vxlan_network.go, upstream cdf76059):
//! turns subnet lease events into ARP/FDB/route programming on the vxlan
//! device, plus the local `retry.Do` helper (avast/retry-go defaults).
//!
//! Go deviation: Go nil-derefs `nw.dev` when IPv4 is enabled on the event
//! but the local node has no vxlan device; the Rust port skips that part.

use super::device::{add_arp, add_fdb, del_arp, del_fdb};
use super::network::NetState;
use crate::ip::iface::{direct_routing, Netlink};
use crate::ip::{IP4Net, IP6Net};
use crate::lease::Event;
use crate::mac::{mac_to_string, MacAddr};
use anyhow::anyhow;
use netlink_packet_route::route::RouteMessage;
use rtnetlink::RouteMessageBuilder;
use serde::Deserialize;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// Go: `vxlanLeaseAttrs` as parsed from a remote lease's BackendData.
#[derive(Deserialize)]
struct VXLANLeaseAttrs {
    /// Parsed for parity with Go, which reads the whole struct but only
    /// uses VtepMAC in handleSubnetEvents.
    #[allow(dead_code)]
    #[serde(rename = "VNI")]
    vni: u32,
    #[serde(rename = "VtepMAC")]
    vtep_mac: MacJson,
}

/// VtepMAC with Go's `hardwareAddr.UnmarshalJSON` semantics: a quoted
/// string is required ("error parsing hardware addr" otherwise), then the
/// 6-octet MAC form.
struct MacJson(MacAddr);

impl<'de> Deserialize<'de> for MacJson {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v: serde_json::Value = Deserialize::deserialize(d)?;
        let Some(s) = v.as_str() else {
            return Err(serde::de::Error::custom("error parsing hardware addr"));
        };
        super::parse_mac(s)
            .map(MacJson)
            .map_err(serde::de::Error::custom)
    }
}

/// Go: `handleSubnetEvents`.
pub(super) async fn handle_subnet_events(nl: &Netlink, state: &Mutex<NetState>, batch: &[Event]) {
    for event in batch {
        let sn = event.lease.subnet;
        let v6_sn = event.lease.ipv6_subnet;
        let attrs = &event.lease.attrs;
        info!("Received Subnet Event with VxLan: {attrs}");
        if attrs.backend_type != "vxlan" {
            warn!(
                "ignoring non-vxlan v4Subnet({sn}) v6Subnet({v6_sn}): type={}",
                attrs.backend_type
            );
            continue;
        }

        // Go reads nw.dev / nw.v6Dev at event time; snapshot them.
        let (dev, v6_dev) = {
            let st = state.lock().unwrap();
            (st.dev.clone(), st.v6_dev.clone())
        };

        let mut vxlan_attrs = None;
        let mut v6_vxlan_attrs = None;
        let mut direct_ok = false;
        let mut v6_direct_ok = false;
        let mut vxlan_route = None;
        let mut direct_route = None;
        let mut v6_vxlan_rt = None;
        let mut v6_direct_rt = None;

        if let (true, Some(d)) = (event.lease.enable_ipv4, dev.as_ref()) {
            match parse_backend_data(attrs.backend_data.as_deref().map(|r| r.get())) {
                Ok(a) => vxlan_attrs = Some(a),
                Err(e) => {
                    error!("error decoding subnet lease JSON: {e}");
                    continue;
                }
            }
            // Route used when traffic should be vxlan-encapsulated.
            vxlan_route = Some(v4_vxlan_route(d.ifindex, sn));
            direct_route = Some(v4_direct_route(sn, attrs.public_ip.to_std()));
            if d.direct_routing {
                match direct_routing(nl, IpAddr::V4(attrs.public_ip.to_std())).await {
                    Ok(dr) => direct_ok = dr,
                    Err(e) => error!("{e}"),
                }
            }
        }

        let pub6 = attrs.public_ipv6.unwrap_or_default();
        if let (true, Some(d)) = (event.lease.enable_ipv6, v6_dev.as_ref()) {
            match parse_backend_data(attrs.backend_v6_data.as_deref().map(|r| r.get())) {
                Ok(a) => v6_vxlan_attrs = Some(a),
                Err(e) => {
                    error!("error decoding v6 subnet lease JSON: {e}");
                    continue;
                }
            }
            // Go: `if v6Sn.IP != nil` -- Rust uses the empty subnet instead.
            if !v6_sn.empty() {
                v6_vxlan_rt = Some(v6_vxlan_route(d.ifindex, v6_sn));
                v6_direct_rt = Some(v6_direct_route(v6_sn, pub6.to_std()));
                if d.direct_routing {
                    match direct_routing(nl, IpAddr::V6(pub6.to_std())).await {
                        Ok(dr) => v6_direct_ok = dr,
                        Err(e) => error!("{e}"),
                    }
                }
            }
        }

        // Go matches the raw int event type (default arm logs unknown).
        match event.event_type as i32 {
            0 => {
                // ---------- lease.EventAdded ----------
                if event.lease.enable_ipv4 {
                    if let (Some(dev), Some(vxa), Some(vxr), Some(dr)) = (
                        dev.as_ref(),
                        vxlan_attrs.as_ref(),
                        &vxlan_route,
                        &direct_route,
                    ) {
                        let mac = &vxa.vtep_mac.0;
                        let gw = IpAddr::V4(sn.ip.to_std());
                        let vtep = IpAddr::V4(attrs.public_ip.to_std());
                        if direct_ok {
                            debug!(
                                "Adding direct route to subnet: {sn} PublicIP: {}",
                                attrs.public_ip
                            );
                            if let Err(e) = retry_do(|| route_replace(nl, dr)).await {
                                error!("Error adding route to {sn} via {}: {e}", attrs.public_ip);
                                continue;
                            }
                        } else {
                            debug!(
                                "adding subnet: {sn} PublicIP: {} VtepMAC: {}",
                                attrs.public_ip,
                                mac_to_string(mac)
                            );
                            if let Err(e) = retry_do(|| add_arp(nl, dev, mac, gw)).await {
                                error!("AddARP failed: {e}");
                                continue;
                            }
                            if let Err(e) = retry_do(|| add_fdb(nl, dev, mac, vtep)).await {
                                error!("AddFDB failed: {e}");
                                // Clean up the ARP entry then continue.
                                if let Err(e) = retry_do(|| del_arp(nl, dev, mac, gw)).await {
                                    error!("DelARP failed: {e}");
                                }
                                continue;
                            }
                            // Set the route last: the kernel would ARP for
                            // Gw if it were not already set above.
                            if let Err(e) = retry_do(|| route_replace(nl, vxr)).await {
                                error!("failed to add vxlanRoute ({sn} -> {}): {e}", sn.ip);
                                // Go: cleanup without retry on this path.
                                if let Err(e) = del_arp(nl, dev, mac, gw).await {
                                    error!("DelARP failed: {e}");
                                }
                                if let Err(e) = del_fdb(nl, dev, mac, vtep).await {
                                    error!("DelFDB failed: {e}");
                                }
                                continue;
                            }
                        }
                    }
                }
                if event.lease.enable_ipv6 {
                    if let (Some(dev), Some(vxa), Some(vxr), Some(dr)) = (
                        v6_dev.as_ref(),
                        v6_vxlan_attrs.as_ref(),
                        &v6_vxlan_rt,
                        &v6_direct_rt,
                    ) {
                        let mac = &vxa.vtep_mac.0;
                        let gw = IpAddr::V6(v6_sn.ip.to_std());
                        let vtep = IpAddr::V6(pub6.to_std());
                        if v6_direct_ok {
                            debug!(
                                "Adding v6 direct route to v6 subnet: {v6_sn} PublicIPv6: {pub6}"
                            );
                            if let Err(e) = retry_do(|| route_replace(nl, dr)).await {
                                error!("Error adding v6 route to {v6_sn} via {pub6}: {e}");
                                continue;
                            }
                        } else {
                            debug!(
                                "adding v6 subnet: {v6_sn} PublicIPv6: {pub6} VtepMAC: {}",
                                mac_to_string(mac)
                            );
                            if let Err(e) = retry_do(|| add_arp(nl, dev, mac, gw)).await {
                                error!("AddV6ARP failed: {e}");
                                continue;
                            }
                            if let Err(e) = retry_do(|| add_fdb(nl, dev, mac, vtep)).await {
                                error!("AddV6FDB failed: {e}");
                                if let Err(e) = retry_do(|| del_arp(nl, dev, mac, gw)).await {
                                    error!("DelV6ARP failed: {e}");
                                }
                                continue;
                            }
                            if let Err(e) = retry_do(|| route_replace(nl, vxr)).await {
                                error!(
                                    "failed to add v6 vxlanRoute ({v6_sn} -> {}): {e}",
                                    v6_sn.ip
                                );
                                if let Err(e) = retry_do(|| del_arp(nl, dev, mac, gw)).await {
                                    error!("DelV6ARP failed: {e}");
                                }
                                if let Err(e) = retry_do(|| del_fdb(nl, dev, mac, vtep)).await {
                                    error!("DelV6FDB failed: {e}");
                                }
                                continue;
                            }
                        }
                    }
                }
            }
            1 => {
                // ---------- lease.EventRemoved ----------
                if event.lease.enable_ipv4 {
                    if let (Some(dev), Some(vxa), Some(vxr), Some(dr)) = (
                        dev.as_ref(),
                        vxlan_attrs.as_ref(),
                        &vxlan_route,
                        &direct_route,
                    ) {
                        let mac = &vxa.vtep_mac.0;
                        let gw = IpAddr::V4(sn.ip.to_std());
                        let vtep = IpAddr::V4(attrs.public_ip.to_std());
                        if direct_ok {
                            debug!(
                                "Removing direct route to subnet: {sn} PublicIP: {}",
                                attrs.public_ip
                            );
                            if let Err(e) = retry_do(|| route_del(nl, dr)).await {
                                error!("Error deleting route to {sn} via {}: {e}", attrs.public_ip);
                            }
                        } else {
                            debug!(
                                "removing subnet: {sn} PublicIP: {} VtepMAC: {}",
                                attrs.public_ip,
                                mac_to_string(mac)
                            );
                            // Remove all entries; do not bail on one failure.
                            if let Err(e) = retry_do(|| del_arp(nl, dev, mac, gw)).await {
                                error!("DelARP failed: {e}");
                            }
                            if let Err(e) = retry_do(|| del_fdb(nl, dev, mac, vtep)).await {
                                error!("DelFDB failed: {e}");
                            }
                            if let Err(e) = retry_do(|| route_del(nl, vxr)).await {
                                error!("failed to delete vxlanRoute ({sn} -> {}): {e}", sn.ip);
                            }
                        }
                    }
                }
                if event.lease.enable_ipv6 {
                    if let (Some(dev), Some(vxa), Some(vxr), Some(dr)) = (
                        v6_dev.as_ref(),
                        v6_vxlan_attrs.as_ref(),
                        &v6_vxlan_rt,
                        &v6_direct_rt,
                    ) {
                        let mac = &vxa.vtep_mac.0;
                        let gw = IpAddr::V6(v6_sn.ip.to_std());
                        let vtep = IpAddr::V6(pub6.to_std());
                        if v6_direct_ok {
                            // Go logs `sn` here and labels it "PublicIP" --
                            // an upstream bug, reproduced faithfully.
                            debug!(
                                "Removing v6 direct route to subnet: {} PublicIP: {pub6}",
                                event.lease.subnet
                            );
                            if let Err(e) = retry_do(|| route_del(nl, dr)).await {
                                error!("Error deleting v6 route to {v6_sn} via {pub6}: {e}");
                            }
                        } else {
                            debug!(
                                "removing v6subnet: {v6_sn} PublicIPv6: {pub6} VtepMAC: {}",
                                mac_to_string(mac)
                            );
                            if let Err(e) = retry_do(|| del_arp(nl, dev, mac, gw)).await {
                                error!("DelV6ARP failed: {e}");
                            }
                            if let Err(e) = retry_do(|| del_fdb(nl, dev, mac, vtep)).await {
                                error!("DelV6FDB failed: {e}");
                            }
                            if let Err(e) = retry_do(|| route_del(nl, vxr)).await {
                                error!(
                                    "failed to delete v6 vxlanRoute ({v6_sn} -> {}): {e}",
                                    v6_sn.ip
                                );
                            }
                        }
                    }
                }
            }
            t => error!("internal error: unknown event type: {t}"),
        }
    }
}

fn parse_backend_data(raw: Option<&str>) -> Result<VXLANLeaseAttrs, serde_json::Error> {
    serde_json::from_str(raw.unwrap_or("null"))
}

// ---------- route builders (Go netlink.Route literals) ----------

/// Go: `vxlanRoute` (LinkIndex, Scope universe, Dst sn, Gw sn.IP, ONLINK).
fn v4_vxlan_route(ifindex: u32, sn: IP4Net) -> RouteMessage {
    RouteMessageBuilder::<Ipv4Addr>::new()
        .destination_prefix(sn.ip.to_std(), sn.prefix_len as u8)
        .gateway(sn.ip.to_std())
        .output_interface(ifindex)
        .onlink()
        .build()
}

/// Go: `directRoute` (Dst sn, Gw publicIP).
fn v4_direct_route(sn: IP4Net, public_ip: Ipv4Addr) -> RouteMessage {
    RouteMessageBuilder::<Ipv4Addr>::new()
        .destination_prefix(sn.ip.to_std(), sn.prefix_len as u8)
        .gateway(public_ip)
        .build()
}

fn v6_vxlan_route(ifindex: u32, sn: IP6Net) -> RouteMessage {
    RouteMessageBuilder::<Ipv6Addr>::new()
        .destination_prefix(sn.ip.to_std(), sn.prefix_len as u8)
        .gateway(sn.ip.to_std())
        .output_interface(ifindex)
        .onlink()
        .build()
}

fn v6_direct_route(sn: IP6Net, public_ip: Ipv6Addr) -> RouteMessage {
    RouteMessageBuilder::<Ipv6Addr>::new()
        .destination_prefix(sn.ip.to_std(), sn.prefix_len as u8)
        .gateway(public_ip)
        .build()
}

async fn route_replace(nl: &Netlink, msg: &RouteMessage) -> anyhow::Result<()> {
    nl.handle
        .route()
        .add(msg.clone())
        .replace()
        .execute()
        .await
        .map_err(|e| anyhow!("{e}"))
}

async fn route_del(nl: &Netlink, msg: &RouteMessage) -> anyhow::Result<()> {
    nl.handle
        .route()
        .del(msg.clone())
        .execute()
        .await
        .map_err(|e| anyhow!("{e}"))
}

/// Port of flannel's `retry.Do` (avast/retry-go/v4 defaults): 10 attempts,
/// exponential delay starting at 100ms, logging each retry like Go's
/// OnRetry hook ("#%d: %s\n").
async fn retry_do<F, Fut>(mut f: F) -> anyhow::Result<()>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<()>>,
{
    const ATTEMPTS: u32 = 10;
    let mut delay = Duration::from_millis(100);
    for attempt in 0..ATTEMPTS {
        match f().await {
            Ok(()) => return Ok(()),
            Err(e) if attempt + 1 == ATTEMPTS => return Err(e),
            Err(e) => {
                error!("#{attempt}: {e}\n");
                tokio::time::sleep(delay).await;
                delay *= 2;
            }
        }
    }
    unreachable!("loop above always returns")
}
