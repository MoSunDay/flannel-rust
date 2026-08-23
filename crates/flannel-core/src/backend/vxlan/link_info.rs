//! Link message inspection helpers shared by the vxlan backend (parsing
//! names/MTU/MAC/kind and the vxlan-specific info block). Used by
//! device.rs for creation/reuse decisions and by network.rs's watcher.

use crate::ip::iface::{list_links, Netlink};
use crate::mac::MacAddr;
use anyhow::bail;
use netlink_packet_route::link::{
    InfoData, InfoKind, InfoVxlan, LinkAttribute, LinkInfo, LinkMessage,
};
use std::net::IpAddr;

/// Find a link by name via a dump (Go: `LinkByName`).
pub(crate) async fn get_link_by_name(nl: &Netlink, name: &str) -> anyhow::Result<LinkMessage> {
    for link in list_links(nl).await? {
        if link_name(&link) == name {
            return Ok(link);
        }
    }
    bail!("no such network interface with name {name}")
}

/// Link name attribute ("" when absent).
pub(crate) fn link_name(link: &LinkMessage) -> String {
    link.attributes
        .iter()
        .find_map(|a| match a {
            LinkAttribute::IfName(n) => Some(n.clone()),
            _ => None,
        })
        .unwrap_or_default()
}

/// Link MTU attribute (0 when absent).
pub(crate) fn link_mtu(link: &LinkMessage) -> u32 {
    link.attributes
        .iter()
        .find_map(|a| match a {
            LinkAttribute::Mtu(m) => Some(*m),
            _ => None,
        })
        .unwrap_or(0)
}

/// Link hardware address (6-byte address attribute).
pub(crate) fn link_mac(link: &LinkMessage) -> Option<MacAddr> {
    link.attributes.iter().find_map(|a| match a {
        LinkAttribute::Address(b) if b.len() == 6 => Some(b.as_slice().try_into().unwrap()),
        _ => None,
    })
}

/// Link kind (e.g. vxlan, dummy) from the link-info attributes.
pub(crate) fn link_kind(link: &LinkMessage) -> Option<InfoKind> {
    link.attributes.iter().find_map(|a| match a {
        LinkAttribute::LinkInfo(infos) => infos.iter().find_map(|i| match i {
            LinkInfo::Kind(k) => Some(k.clone()),
            _ => None,
        }),
        _ => None,
    })
}

/// Parsed VXLAN parameters of a dumped link (`None` when not a vxlan).
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct VxlanInfo {
    pub vni: u32,
    pub vtep_index: u32,
    pub vtep_addr: Option<IpAddr>,
    pub group: Option<IpAddr>,
    pub l2miss: bool,
    pub port: u32,
    pub gbp: bool,
}

pub(crate) fn vxlan_info(link: &LinkMessage) -> Option<VxlanInfo> {
    let infos = link.attributes.iter().find_map(|a| match a {
        LinkAttribute::LinkInfo(infos) => Some(infos),
        _ => None,
    })?;
    let mut is_vxlan = false;
    let mut data = None;
    for info in infos {
        match info {
            LinkInfo::Kind(InfoKind::Vxlan) => is_vxlan = true,
            LinkInfo::Data(d) => data = Some(d),
            _ => {}
        }
    }
    if !is_vxlan {
        return None;
    }
    let mut v = VxlanInfo::default();
    if let Some(InfoData::Vxlan(items)) = data {
        for item in items {
            match item {
                InfoVxlan::Id(n) => v.vni = *n,
                InfoVxlan::Link(i) => v.vtep_index = *i,
                InfoVxlan::Local(ip) => v.vtep_addr = Some(IpAddr::V4(*ip)),
                InfoVxlan::Local6(ip) => v.vtep_addr = Some(IpAddr::V6(*ip)),
                InfoVxlan::Group(ip) => v.group = Some(IpAddr::V4(*ip)),
                InfoVxlan::Group6(ip) => v.group = Some(IpAddr::V6(*ip)),
                InfoVxlan::L2Miss(b) => v.l2miss = *b,
                InfoVxlan::Port(p) => v.port = *p as u32,
                InfoVxlan::Gbp => v.gbp = true,
                _ => {}
            }
        }
    }
    Some(v)
}
