//! Port of pkg/backend/vxlan/device.go (upstream cdf76059): creation,
//! compatibility checking and configuration of the flannel VXLAN device,
//! plus the static ARP/FDB entries the event loop programs on it.
//!
//! Go deviation: `ensureLink` re-looks-up the created device by *name*
//! instead of the index vishvananda parses from the RTM_NEWLINK echo
//! (rtnetlink does not expose it); the name is the unique key Go used.

use super::link_info::{get_link_by_name, link_kind, link_mac, link_mtu, vxlan_info};
use crate::ip::iface::{ensure_v4_address_on_link, ensure_v6_address_on_link, Netlink};
use crate::ip::{IP4Net, IP6Net};
use crate::mac::{mac_to_string, new_hardware_addr, MacAddr};
use anyhow::{anyhow, bail};
use netlink_packet_route::link::LinkMessage;
use netlink_packet_route::neighbour::{
    NeighbourAddress, NeighbourAttribute, NeighbourFlags, NeighbourMessage, NeighbourState,
};
use netlink_packet_route::route::RouteType;
use netlink_packet_route::AddressFamily;
use rtnetlink::{Error as RtError, LinkUnspec, LinkVxlan};
use std::net::IpAddr;
use tracing::{debug, trace, warn};

/// VXLAN encapsulation overhead (Go: `encapOverhead = 50`).
pub(crate) const ENCAP_OVERHEAD: u32 = 50;

/// Device creation attributes (Go: `vxlanDeviceAttrs`).
#[derive(Clone, Debug, PartialEq)]
pub struct VXLANAttrs {
    pub name: String,
    pub vni: u32,
    pub mtu: u32,
    pub vtep_index: u32,
    pub vtep_addr: Option<IpAddr>,
    pub port: u32,
    pub gbp: bool,
    pub learning: bool,
    pub hw_addr: Option<MacAddr>,
}

/// The created VXLAN device (Go: `vxlanDevice`).
#[derive(Clone, Debug, PartialEq)]
pub struct VXLANDevice {
    pub name: String,
    pub ifindex: u32,
    /// Link MTU (`attrs.mtu - 50` at creation time).
    pub mtu: u32,
    pub mac: MacAddr,
    pub direct_routing: bool,
}

/// Go: `newVXLANDevice` -- create (or reuse) the device, then best-effort
/// disable IPv6 router solicits on it.
pub async fn new_vxlan_device(nl: &Netlink, attrs: &VXLANAttrs) -> anyhow::Result<VXLANDevice> {
    let hw_addr = match attrs.hw_addr {
        Some(m) => m,
        None => {
            new_hardware_addr().map_err(|e| anyhow!("failed to generate hardware addr: {e}"))?
        }
    };

    let link = ensure_link(nl, attrs, &hw_addr).await?;

    // Go: sysctl net/ipv6/conf/<name>/accept_ra = 0, errors ignored.
    let _ = std::fs::write(
        format!("/proc/sys/net/ipv6/conf/{}/accept_ra", attrs.name),
        "0",
    );

    Ok(VXLANDevice {
        name: attrs.name.clone(),
        ifindex: link.header.index,
        mtu: link_mtu(&link),
        mac: link_mac(&link).unwrap_or(hw_addr),
        direct_routing: false,
    })
}

/// Go: `ensureLink` -- add the device; on EEXIST reuse it when compatible,
/// otherwise delete and re-create it. Returns the resulting link message.
async fn ensure_link(
    nl: &Netlink,
    attrs: &VXLANAttrs,
    hw_addr: &MacAddr,
) -> anyhow::Result<LinkMessage> {
    let msg = build_vxlan_link(attrs, hw_addr);

    match nl.handle.link().add(msg.clone()).execute().await {
        Ok(()) => {}
        Err(e) if is_eexist(&e) => {
            debug!("VXLAN device already exists");
            let existing = get_link_by_name(nl, &attrs.name).await?;

            match vxlan_links_incompat(attrs, &existing) {
                Ok(()) => {
                    debug!("Returning existing device");
                    return Ok(existing);
                }
                Err(incompat) => {
                    warn!(
                        "\"{}\" already exists with incompatible configuration: {incompat}; \
                         recreating device",
                        attrs.name
                    );
                    nl.handle
                        .link()
                        .del(existing.header.index)
                        .execute()
                        .await
                        .map_err(|e| anyhow!("failed to delete interface: {e}"))?;
                    nl.handle
                        .link()
                        .add(msg)
                        .execute()
                        .await
                        .map_err(|e| anyhow!("failed to create vxlan interface: {e}"))?;
                }
            }
        }
        Err(e) => return Err(anyhow!("{e}")),
    }

    let link = get_link_by_name(nl, &attrs.name).await.map_err(|e| {
        // Go reports the index parsed from the RTM_NEWLINK echo; rtnetlink
        // does not expose it, so 0 stands in when the device is gone.
        anyhow!("can't locate created vxlan device with index 0: {e}")
    })?;
    if vxlan_info(&link).is_none() {
        bail!(
            "created vxlan device with index {} is not vxlan",
            link.header.index
        );
    }
    Ok(link)
}

/// Build the netlink message for the VXLAN device. Zero-valued fields
/// are omitted like Go does (port, src address, vtep index, MTU <= 0).
fn build_vxlan_link(attrs: &VXLANAttrs, hw_addr: &MacAddr) -> LinkMessage {
    let mut b = LinkVxlan::new(&attrs.name, attrs.vni).learning(attrs.learning);
    if attrs.vtep_index > 0 {
        b = b.dev(attrs.vtep_index);
    }
    match attrs.vtep_addr {
        Some(IpAddr::V4(ip)) => b = b.local(ip),
        Some(IpAddr::V6(ip)) => b = b.local6(ip),
        None => {}
    }
    if attrs.port > 0 {
        b = b.port(attrs.port as u16);
    }
    if attrs.gbp {
        b = b.gbp();
    }
    let mut b = b.address(hw_addr.to_vec());
    let mtu = attrs.mtu as i64 - ENCAP_OVERHEAD as i64;
    if mtu > 0 {
        b = b.mtu(mtu as u32);
    }
    b.build()
}

/// True when a netlink request was rejected with EEXIST ("file exists").
fn is_eexist(err: &RtError) -> bool {
    matches!(err,
        RtError::NetlinkError(msg)
            if msg.code.is_some_and(|c| c.get() == -libc::EEXIST))
}

/// Go: `vxlanLinksIncompat` -- Ok when `existing` matches `attrs`,
/// otherwise the first mismatch as the error string. (Go also compares
/// the multicast Group on both sides, but the desired device never sets
/// one, so that check can never trigger.)
fn vxlan_links_incompat(attrs: &VXLANAttrs, existing: &LinkMessage) -> Result<(), String> {
    let Some(v2) = vxlan_info(existing) else {
        let kind = link_kind(existing)
            .map(|k| k.to_string())
            .unwrap_or_else(|| "unknown".into());
        return Err(format!("link type: vxlan vs {kind}"));
    };
    if attrs.vni != v2.vni {
        return Err(format!("vni: {} vs {}", attrs.vni, v2.vni));
    }
    if attrs.vtep_index > 0 && v2.vtep_index > 0 && attrs.vtep_index != v2.vtep_index {
        return Err(format!(
            "vtep (external) interface: {} vs {}",
            attrs.vtep_index, v2.vtep_index
        ));
    }
    if let (Some(a), Some(b)) = (attrs.vtep_addr, v2.vtep_addr) {
        if a != b {
            return Err(format!("vtep (external) IP: {a} vs {b}"));
        }
    }
    if v2.l2miss {
        return Err(format!("l2miss: false vs {}", v2.l2miss));
    }
    if attrs.port > 0 && v2.port > 0 && attrs.port != v2.port {
        return Err(format!("port: {} vs {}", attrs.port, v2.port));
    }
    if attrs.gbp != v2.gbp {
        return Err(format!("gbp: {} vs {}", attrs.gbp, v2.gbp));
    }
    Ok(())
}

/// Go: `Configure` -- ensure the /32 address, bring the link up, verify
/// the hardware address (flannel issue #1795).
pub async fn configure_device_v4(
    dev: &VXLANDevice,
    nl: &Netlink,
    ipa: IP4Net,
    flannelnet: IP4Net,
) -> anyhow::Result<()> {
    ensure_v4_address_on_link(nl, ipa, flannelnet, dev.ifindex)
        .await
        .map_err(|e| anyhow!("failed to ensure address of interface {}: {e}", dev.name))?;
    set_link_up(nl, dev).await?;
    check_mac(dev, nl, "").await
}

/// Go: `ConfigureIPv6` -- v6 counterpart of [`configure_device_v4`].
pub async fn configure_device_v6(
    dev: &VXLANDevice,
    nl: &Netlink,
    ipn: IP6Net,
    flannelnet: IP6Net,
) -> anyhow::Result<()> {
    ensure_v6_address_on_link(nl, ipn, flannelnet, dev.ifindex)
        .await
        .map_err(|e| anyhow!("failed to ensure v6 address of interface {}: {e}", dev.name))?;
    set_link_up(nl, dev)
        .await
        .map_err(|e| anyhow!("failed to set v6 interface {} to UP state: {e}", dev.name))?;
    check_mac(dev, nl, "v6 ").await
}

async fn set_link_up(nl: &Netlink, dev: &VXLANDevice) -> anyhow::Result<()> {
    nl.handle
        .link()
        .set(LinkUnspec::new_with_index(dev.ifindex).up().build())
        .execute()
        .await
        .map_err(|e| anyhow!("failed to set interface {} to UP state: {e}", dev.name))
}

/// Go's post-up MAC check. Fetch errors and non-vxlan links are ignored
/// like Go does; `label` is "v6 " for the v6 variant.
async fn check_mac(dev: &VXLANDevice, nl: &Netlink, label: &str) -> anyhow::Result<()> {
    if let Ok(link) = get_link_by_name(nl, &dev.name).await {
        if vxlan_info(&link).is_some() {
            if let Some(mac) = link_mac(&link) {
                if mac != dev.mac {
                    bail!(
                        "{}'s {label}mac address wanted: {}, but got: {}",
                        dev.name,
                        mac_to_string(&dev.mac),
                        mac_to_string(&mac)
                    );
                }
            }
        }
    }
    Ok(())
}

/// Go: `AddARP`/`AddV6ARP` -- NUD_PERMANENT + RTN_UNICAST (NeighSet).
pub async fn add_arp(
    nl: &Netlink,
    dev: &VXLANDevice,
    mac: &MacAddr,
    ip: IpAddr,
) -> anyhow::Result<()> {
    trace!("calling AddARP: {ip}, {}", mac_to_string(mac));
    nl.handle
        .neighbours()
        .add(dev.ifindex, ip)
        .link_layer_address(mac)
        .kind(RouteType::Unicast)
        .replace()
        .execute()
        .await
        .map_err(|e| anyhow!("{e}"))
}

/// Go: `DelARP`/`DelV6ARP`.
pub async fn del_arp(
    nl: &Netlink,
    dev: &VXLANDevice,
    mac: &MacAddr,
    ip: IpAddr,
) -> anyhow::Result<()> {
    trace!("calling DelARP: {ip}, {}", mac_to_string(mac));
    let msg = neigh_message(dev.ifindex, mac, ip, NeighbourState::Permanent);
    nl.handle
        .neighbours()
        .del(msg)
        .execute()
        .await
        .map_err(|e| anyhow!("{e}"))
}

/// Go: `AddFDB`/`AddV6FDB` -- AF_BRIDGE, NTF_SELF, NUD_PERMANENT.
pub async fn add_fdb(
    nl: &Netlink,
    dev: &VXLANDevice,
    mac: &MacAddr,
    dst: IpAddr,
) -> anyhow::Result<()> {
    trace!("calling AddFDB: {dst}, {}", mac_to_string(mac));
    nl.handle
        .neighbours()
        .add_bridge(dev.ifindex, mac)
        .flags(NeighbourFlags::Own)
        .destination(dst)
        .replace()
        .execute()
        .await
        .map_err(|e| anyhow!("{e}"))
}

/// Go: `DelFDB`/`DelV6FDB` -- no NUD state, unlike DelARP.
pub async fn del_fdb(
    nl: &Netlink,
    dev: &VXLANDevice,
    mac: &MacAddr,
    dst: IpAddr,
) -> anyhow::Result<()> {
    trace!("calling DelFDB: {dst}, {}", mac_to_string(mac));
    let mut msg = neigh_message(dev.ifindex, mac, dst, NeighbourState::None);
    msg.header.family = AddressFamily::Bridge;
    msg.header.flags = NeighbourFlags::Own;
    nl.handle
        .neighbours()
        .del(msg)
        .execute()
        .await
        .map_err(|e| anyhow!("{e}"))
}

fn neigh_message(
    ifindex: u32,
    mac: &MacAddr,
    dst: IpAddr,
    state: NeighbourState,
) -> NeighbourMessage {
    let mut msg = NeighbourMessage::default();
    msg.header.family = match dst {
        IpAddr::V4(_) => AddressFamily::Inet,
        IpAddr::V6(_) => AddressFamily::Inet6,
    };
    msg.header.ifindex = ifindex;
    msg.header.state = state;
    msg.header.kind = RouteType::Unicast;
    msg.attributes
        .push(NeighbourAttribute::Destination(match dst {
            IpAddr::V4(ip) => NeighbourAddress::Inet(ip),
            IpAddr::V6(ip) => NeighbourAddress::Inet6(ip),
        }));
    msg.attributes
        .push(NeighbourAttribute::LinkLayerAddress(mac.to_vec()));
    msg
}

#[cfg(test)]
#[path = "device_tests.rs"]
mod device_tests;
