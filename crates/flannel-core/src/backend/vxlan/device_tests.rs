//! netns tests for device.rs: vxlan link lifecycle (create / reuse /
//! recreate on incompat / GBP) and the ARP/FDB netlink helpers.

use super::{add_arp, add_fdb, del_arp, del_fdb, new_vxlan_device, VXLANAttrs};
use crate::backend::vxlan::fake::{netns_block_on, setup_ext_iface};
use crate::backend::vxlan::link_info::{get_link_by_name, link_kind, vxlan_info};
use crate::ip::iface::Netlink;
use crate::mac::MacAddr;
use anyhow::anyhow;
use futures::stream::TryStreamExt;
use netlink_packet_route::link::InfoKind;
use netlink_packet_route::neighbour::{NeighbourAddress, NeighbourAttribute, NeighbourState};
use netlink_packet_route::route::RouteType;
use netlink_packet_route::AddressFamily;
use std::net::{IpAddr, Ipv4Addr};

const MAC: MacAddr = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
const VTEP: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 99, 0, 1));

fn test_attrs(vni: u32, mtu: u32) -> VXLANAttrs {
    VXLANAttrs {
        name: format!("flannel.{vni}"),
        vni,
        mtu,
        vtep_index: 0, // fixed up to the dummy iface index by the caller
        vtep_addr: Some(VTEP),
        port: 0,
        gbp: false,
        learning: false,
        hw_addr: Some(MAC),
    }
}

/// Dump all neighbour entries of `family`.
async fn dump_neigh(
    nl: &Netlink,
    family: AddressFamily,
) -> anyhow::Result<Vec<netlink_packet_route::neighbour::NeighbourMessage>> {
    nl.handle
        .neighbours()
        .get()
        .set_address_family(family)
        .execute()
        .try_collect()
        .await
        .map_err(|e| anyhow!("{e}"))
}

/// Does a neighbour entry matching (ifindex, dst, mac) with `state` exist?
fn has_neigh(
    entries: &[netlink_packet_route::neighbour::NeighbourMessage],
    ifindex: u32,
    dst: IpAddr,
    mac: &MacAddr,
    state: NeighbourState,
) -> bool {
    entries.iter().any(|m| {
        let want_dst = NeighbourAddress::from(dst);
        m.header.ifindex == ifindex
            && m.header.state == state
            && m.attributes
                .iter()
                .any(|a| matches!(a, NeighbourAttribute::Destination(d) if *d == want_dst))
            && m.attributes
                .iter()
                .any(|a| matches!(a, NeighbourAttribute::LinkLayerAddress(b) if b == mac))
    })
}

/// NeighbourAddress -> IpAddr; bridge FDB destinations dump as raw
/// `Other(bytes)` rather than `Inet`/`Inet6`.
fn neigh_addr_ip(a: &NeighbourAddress) -> Option<IpAddr> {
    match a {
        NeighbourAddress::Inet(ip) => Some(IpAddr::V4(*ip)),
        NeighbourAddress::Inet6(ip) => Some(IpAddr::V6(*ip)),
        NeighbourAddress::Other(b) if b.len() == 4 => {
            Some(IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3])))
        }
        _ => None,
    }
}

#[test]
fn creates_vxlan_link_with_expected_attrs() {
    netns_block_on("flnl_vx_dev_create", async {
        let nl = Netlink::new().await?;
        let ext = setup_ext_iface(&nl, "ext0", Some((VTEP, 24)), None).await?;
        let mut attrs = test_attrs(1, 1500);
        attrs.vtep_index = ext;

        let dev = new_vxlan_device(&nl, &attrs).await?;
        assert_eq!(dev.name, "flannel.1");
        assert_eq!(dev.mac, MAC);
        assert!(!dev.direct_routing);
        // Go sets attrs.MTU - encapOverhead on the link.
        assert_eq!(dev.mtu, 1450);

        let link = get_link_by_name(&nl, "flannel.1").await?;
        assert_eq!(link_kind(&link), Some(InfoKind::Vxlan));
        let info = vxlan_info(&link).expect("link is vxlan");
        assert_eq!(info.vni, 1);
        assert_eq!(info.vtep_index, ext);
        assert_eq!(info.vtep_addr, Some(VTEP));
        Ok(())
    })
    .unwrap();
}

#[test]
fn reuses_compatible_existing_device() {
    netns_block_on("flnl_vx_dev_reuse", async {
        let nl = Netlink::new().await?;
        let ext = setup_ext_iface(&nl, "ext0", Some((VTEP, 24)), None).await?;
        let mut attrs = test_attrs(1, 1500);
        attrs.vtep_index = ext;

        let first = new_vxlan_device(&nl, &attrs).await?;
        let second = new_vxlan_device(&nl, &attrs).await?;
        // Same device reused: same index and MAC, no recreation.
        assert_eq!(first.ifindex, second.ifindex);
        assert_eq!(first.mac, second.mac);
        assert_eq!(second.mac, MAC);
        Ok(())
    })
    .unwrap();
}

#[test]
fn recreates_device_on_incompatible_vni() {
    netns_block_on("flnl_vx_dev_incompat", async {
        let nl = Netlink::new().await?;
        let ext = setup_ext_iface(&nl, "ext0", Some((VTEP, 24)), None).await?;
        let mut attrs = test_attrs(1, 1500);
        attrs.vtep_index = ext;
        new_vxlan_device(&nl, &attrs).await?;

        // Same name, different VNI: incompatible -> delete + recreate.
        attrs.vni = 2;
        attrs.hw_addr = Some([0x10, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let dev = new_vxlan_device(&nl, &attrs).await?;
        assert_eq!(dev.mac, [0x10, 0x22, 0x33, 0x44, 0x55, 0x66]);
        assert_eq!(dev.name, "flannel.1");

        let link = get_link_by_name(&nl, "flannel.1").await?;
        let info = vxlan_info(&link).expect("link is vxlan");
        assert_eq!(info.vni, 2);
        Ok(())
    })
    .unwrap();
}

#[test]
fn gbp_device_reports_gbp() {
    netns_block_on("flnl_vx_dev_gbp", async {
        let nl = Netlink::new().await?;
        let ext = setup_ext_iface(&nl, "ext0", Some((VTEP, 24)), None).await?;
        let mut attrs = test_attrs(1, 1500);
        attrs.vtep_index = ext;
        attrs.gbp = true;
        new_vxlan_device(&nl, &attrs).await?;

        let link = get_link_by_name(&nl, "flannel.1").await?;
        let info = vxlan_info(&link).expect("link is vxlan");
        assert!(info.gbp);
        Ok(())
    })
    .unwrap();
}

#[test]
fn arp_and_fdb_roundtrip() {
    netns_block_on("flnl_vx_dev_arp_fdb", async {
        let nl = Netlink::new().await?;
        let ext = setup_ext_iface(&nl, "ext0", Some((VTEP, 24)), None).await?;
        let mut attrs = test_attrs(1, 1500);
        attrs.vtep_index = ext;
        let dev = new_vxlan_device(&nl, &attrs).await?;

        let peer_mac: MacAddr = [0x0a, 0x11, 0x22, 0x33, 0x44, 0x55];
        let peer_gw = IpAddr::V4(Ipv4Addr::new(10, 42, 1, 1));
        let peer_vtep = IpAddr::V4(Ipv4Addr::new(192, 168, 77, 10));

        // ARP: NUD_PERMANENT + RTN_UNICAST entry keyed by the gateway IP.
        add_arp(&nl, &dev, &peer_mac, peer_gw).await?;
        let entries = dump_neigh(&nl, AddressFamily::Inet).await?;
        assert!(has_neigh(&entries, dev.ifindex, peer_gw, &peer_mac, NeighbourState::Permanent));

        del_arp(&nl, &dev, &peer_mac, peer_gw).await?;
        let entries = dump_neigh(&nl, AddressFamily::Inet).await?;
        assert!(!has_neigh(&entries, dev.ifindex, peer_gw, &peer_mac, NeighbourState::Permanent));

        // FDB: AF_BRIDGE entry with NDA_DST = the peer VTEP.
        add_fdb(&nl, &dev, &peer_mac, peer_vtep).await?;
        let entries = dump_neigh(&nl, AddressFamily::Bridge).await?;
        let found = entries.iter().any(|m| {
            m.header.ifindex == dev.ifindex
                && m.attributes.iter().any(|a| matches!(a, NeighbourAttribute::LinkLayerAddress(b) if b == &peer_mac))
                && m.attributes.iter().any(|a| matches!(a, NeighbourAttribute::Destination(d) if neigh_addr_ip(d) == Some(peer_vtep)))
        });
        assert!(found, "FDB entry present");

        del_fdb(&nl, &dev, &peer_mac, peer_vtep).await?;
        let entries = dump_neigh(&nl, AddressFamily::Bridge).await?;
        let found = entries.iter().any(|m| {
            m.header.ifindex == dev.ifindex
                && m.attributes.iter().any(|a| matches!(a, NeighbourAttribute::LinkLayerAddress(b) if b == &peer_mac))
        });
        assert!(!found, "FDB entry removed");
        Ok(())
    })
    .unwrap();
}

/// RouteType on ARP entries: Go sets RTN_UNICAST on the neigh message.
#[test]
fn arp_entry_kind_is_unicast() {
    netns_block_on("flnl_vx_dev_arp_kind", async {
        let nl = Netlink::new().await?;
        let ext = setup_ext_iface(&nl, "ext0", Some((VTEP, 24)), None).await?;
        let mut attrs = test_attrs(1, 1500);
        attrs.vtep_index = ext;
        let dev = new_vxlan_device(&nl, &attrs).await?;

        let peer_mac: MacAddr = [0x0a, 0x11, 0x22, 0x33, 0x44, 0x55];
        let peer_gw = IpAddr::V4(Ipv4Addr::new(10, 42, 1, 1));
        add_arp(&nl, &dev, &peer_mac, peer_gw).await?;

        let entries = dump_neigh(&nl, AddressFamily::Inet).await?;
        let kind_ok = entries
            .iter()
            .any(|m| m.header.ifindex == dev.ifindex && m.header.kind == RouteType::Unicast);
        assert!(kind_ok);
        Ok(())
    })
    .unwrap();
}

/// The kernel rejects ONLINK routes on a down vxlan link with ENETDOWN;
/// the register flow brings the link up in configure_device_v4/v6.
#[test]
fn vxlan_route_add_requires_link_up() {
    use rtnetlink::{LinkUnspec, RouteMessageBuilder};
    netns_block_on("flnl_vx_route_up", async {
        let nl = Netlink::new().await?;
        let ext = setup_ext_iface(&nl, "ext0", Some((VTEP, 24)), None).await?;
        let mut attrs = test_attrs(1, 1500);
        attrs.vtep_index = ext;
        let dev = new_vxlan_device(&nl, &attrs).await?;

        let msg = RouteMessageBuilder::<Ipv4Addr>::new()
            .destination_prefix(Ipv4Addr::new(10, 1, 2, 0), 24)
            .gateway(Ipv4Addr::new(10, 1, 2, 0))
            .output_interface(dev.ifindex)
            .onlink()
            .build();
        assert!(nl
            .handle
            .route()
            .add(msg.clone())
            .replace()
            .execute()
            .await
            .is_err());
        nl.handle
            .link()
            .set(LinkUnspec::new_with_index(dev.ifindex).up().build())
            .execute()
            .await?;
        nl.handle.route().add(msg).replace().execute().await?;
        Ok(())
    })
    .unwrap();
}
