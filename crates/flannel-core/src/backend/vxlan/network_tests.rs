//! netns tests: `register_network` end-to-end and `handle_subnet_events`
//! (Added/Removed, encapsulated and direct-routing paths).

use super::device::{new_vxlan_device, VXLANAttrs, VXLANDevice};
use super::events::handle_subnet_events;
use super::fake::{netns_block_on, setup_ext_iface, test_config, vxlan_backend_data, FakeManager};
use super::link_info::{get_link_by_name, link_kind, vxlan_info};
use super::network::NetState;
use super::new_backend;
use crate::backend::common::ExternalInterface;
use crate::ip::iface::Netlink;
use crate::ip::{IP4Net, IP6Net, IP4};
use crate::lease::{Event, EventType, Lease};
use crate::mac::{mac_to_string, MacAddr};
use anyhow::anyhow;
use futures::stream::TryStreamExt;
use netlink_packet_route::link::InfoKind;
use netlink_packet_route::neighbour::{NeighbourAddress, NeighbourAttribute};
use netlink_packet_route::route::RouteAttribute;
use netlink_packet_route::AddressFamily;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tokio_util::sync::CancellationToken;

const VTEP: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 99, 0, 1));
const REMOTE_VTEP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 77, 10));
const PEER_MAC: MacAddr = [0x0a, 0x11, 0x22, 0x33, 0x44, 0x55];

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

/// Is there a kernel route with (dst, prefix, gw, oif)? `oif == 0`
/// matches any output interface (direct routes carry no oif filter in Go).
async fn has_route(
    nl: &Netlink,
    family: AddressFamily,
    dst: IpAddr,
    prefix: u8,
    gw: Option<IpAddr>,
    oif: u32,
) -> anyhow::Result<bool> {
    use crate::ip::iface::route_addr_to_ip;
    let routes = crate::backend::route_network::dump_routes(nl, family).await?;
    Ok(routes.iter().any(|m| {
        let mut d = None;
        let mut g = None;
        let mut o = None;
        for a in &m.attributes {
            match a {
                RouteAttribute::Destination(x) => d = route_addr_to_ip(x),
                RouteAttribute::Gateway(x) => g = route_addr_to_ip(x),
                RouteAttribute::Oif(i) => o = Some(*i),
                _ => {}
            }
        }
        m.header.destination_prefix_length == prefix
            && d == Some(dst)
            && g == gw
            && (oif == 0 || o == Some(oif))
    }))
}

/// A remote-subnet Added/Removed event (v4 only, backend "vxlan").
fn peer_event(kind: EventType, direct: bool) -> Event {
    let _ = direct; // direct routing is a property of the local device
    Event {
        event_type: kind,
        lease: Lease {
            enable_ipv4: true,
            enable_ipv6: false,
            subnet: IP4Net {
                ip: IP4::from_bytes([10, 1, 2, 0]),
                prefix_len: 24,
            },
            ipv6_subnet: IP6Net::default(),
            attrs: crate::lease::LeaseAttrs {
                public_ip: IP4::from_bytes([192, 168, 77, 10]),
                public_ipv6: None,
                backend_type: "vxlan".to_string(),
                backend_data: Some(vxlan_backend_data(42, &mac_to_string(&PEER_MAC))),
                backend_v6_data: None,
            },
            expiration: SystemTime::now() + Duration::from_secs(3600),
            asof: 0,
        },
    }
}

/// Create the local vxlan device used by the event tests.
async fn local_dev(
    nl: &Netlink,
    ext_index: u32,
    direct_routing: bool,
) -> anyhow::Result<VXLANDevice> {
    let attrs = VXLANAttrs {
        name: "flannel.42".to_string(),
        vni: 42,
        mtu: 1500,
        vtep_index: ext_index,
        vtep_addr: Some(VTEP),
        port: 0,
        gbp: false,
        learning: false,
        hw_addr: Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
    };
    let mut dev = new_vxlan_device(nl, &attrs).await?;
    dev.direct_routing = direct_routing;
    // The register flow brings the link up in configure_device_v4/v6;
    // routes added by the event handler require the link to be up.
    use rtnetlink::LinkUnspec;
    nl.handle
        .link()
        .set(LinkUnspec::new_with_index(dev.ifindex).up().build())
        .execute()
        .await?;
    Ok(dev)
}

#[test]
fn register_network_creates_devices_and_lease() {
    netns_block_on("flnl_vx_register", async {
        let nl = Netlink::new().await?;
        let ext_index = setup_ext_iface(
            &nl,
            "ext0",
            Some((VTEP, 24)),
            Some((IpAddr::V6("fd00:99::1".parse().unwrap()), 64)),
        )
        .await?;

        let ei = Arc::new(ExternalInterface {
            iface_index: ext_index,
            iface_name: "ext0".to_string(),
            iface_addr: Some(VTEP),
            iface_v6_addr: Some(IpAddr::V6("fd00:99::1".parse().unwrap())),
            ext_addr: Some(VTEP),
            ext_v6_addr: Some(IpAddr::V6("fd00:99::1".parse().unwrap())),
        });
        let config = test_config(true, true, Some("{\"vni\":42}"));
        let sm = FakeManager::new(config.clone());
        let backend = new_backend(sm.clone(), ei)?;

        let ctx = CancellationToken::new();
        let network = backend.register_network(&ctx, &config).await?;

        // Both devices exist with the configured VNI.
        for name in ["flannel.42", "flannel-v6.42"] {
            let link = get_link_by_name(&nl, name).await?;
            assert_eq!(link_kind(&link), Some(InfoKind::Vxlan));
            assert_eq!(vxlan_info(&link).unwrap().vni, 42);
        }
        // Lease attrs carry the backend data (VNI + VtepMAC).
        let data = network.lease().attrs.backend_data.as_ref().unwrap().get();
        let v: serde_json::Value = serde_json::from_str(data)?;
        assert_eq!(v["VNI"], 42);
        assert!(v["VtepMAC"].as_str().unwrap().contains(':'));
        // MTU = cfg.mtu(ext MTU) - encapOverhead.
        assert_eq!(network.mtu(), 1450);
        assert_eq!(network.lease().subnet.prefix_len, 24);
        Ok(())
    })
    .unwrap();
}

#[test]
fn events_add_and_remove_encapsulated_route() {
    netns_block_on("flnl_vx_events_encap", async {
        let nl = Netlink::new().await?;
        let ext_index = setup_ext_iface(&nl, "ext0", Some((VTEP, 24)), None).await?;
        let dev = local_dev(&nl, ext_index, false).await?;
        let state = Mutex::new(NetState { dev: Some(dev.clone()), v6_dev: None, mtu: 1450 });

        handle_subnet_events(&nl, &state, &[peer_event(EventType::Added, false)]).await;

        // ARP entry for the remote subnet IP, FDB for the remote VTEP.
        let neigh: Vec<_> = nl.handle.neighbours().get().set_address_family(AddressFamily::Inet).execute().try_collect().await.map_err(|e| anyhow!("{e}"))?;
        assert!(neigh.iter().any(|m| m.header.ifindex == dev.ifindex
            && m.attributes.iter().any(|a| matches!(a, NeighbourAttribute::Destination(NeighbourAddress::Inet(ip)) if *ip == Ipv4Addr::new(10, 1, 2, 0)))
            && m.attributes.iter().any(|a| matches!(a, NeighbourAttribute::LinkLayerAddress(b) if b == &PEER_MAC))));
        let fdb: Vec<_> = nl.handle.neighbours().get().set_address_family(AddressFamily::Bridge).execute().try_collect().await.map_err(|e| anyhow!("{e}"))?;
        assert!(fdb.iter().any(|m| m.header.ifindex == dev.ifindex
            && m.attributes.iter().any(|a| matches!(a, NeighbourAttribute::Destination(d) if neigh_addr_ip(d) == Some(REMOTE_VTEP)))));
        // vxlanRoute: dst 10.1.2.0/24 via 10.1.2.0 dev flannel.42 ONLINK.
        assert!(has_route(&nl, AddressFamily::Inet, IpAddr::V4(Ipv4Addr::new(10, 1, 2, 0)), 24,
            Some(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 0))), dev.ifindex).await?);

        handle_subnet_events(&nl, &state, &[peer_event(EventType::Removed, false)]).await;

        assert!(!has_route(&nl, AddressFamily::Inet, IpAddr::V4(Ipv4Addr::new(10, 1, 2, 0)), 24,
            Some(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 0))), dev.ifindex).await?);
        let neigh: Vec<_> = nl.handle.neighbours().get().set_address_family(AddressFamily::Inet).execute().try_collect().await.map_err(|e| anyhow!("{e}"))?;
        assert!(!neigh.iter().any(|m| m.header.ifindex == dev.ifindex
            && m.attributes.iter().any(|a| matches!(a, NeighbourAttribute::Destination(NeighbourAddress::Inet(ip)) if *ip == Ipv4Addr::new(10, 1, 2, 0)))));
        Ok(())
    })
    .unwrap();
}

#[test]
fn events_add_and_remove_direct_route() {
    netns_block_on("flnl_vx_events_direct", async {
        let nl = Netlink::new().await?;
        let ext_index = setup_ext_iface(&nl, "ext0", Some((VTEP, 24)), None).await?;
        // Peer VTEP must be directly reachable: give the ns a matching
        // interface (Go's direct_routing() = route lookup has no gateway).
        setup_ext_iface(
            &nl,
            "peerlan",
            Some((IpAddr::V4(Ipv4Addr::new(192, 168, 77, 1)), 24)),
            None,
        )
        .await?;
        let dev = local_dev(&nl, ext_index, true).await?;
        let state = Mutex::new(NetState {
            dev: Some(dev.clone()),
            v6_dev: None,
            mtu: 1450,
        });

        handle_subnet_events(&nl, &state, &[peer_event(EventType::Added, true)]).await;

        // directRoute: dst 10.1.2.0/24 via the peer's public IP.
        assert!(
            has_route(
                &nl,
                AddressFamily::Inet,
                IpAddr::V4(Ipv4Addr::new(10, 1, 2, 0)),
                24,
                Some(REMOTE_VTEP),
                0
            )
            .await?
        );
        // No vxlan route / ARP entry on the direct path.
        assert!(
            !has_route(
                &nl,
                AddressFamily::Inet,
                IpAddr::V4(Ipv4Addr::new(10, 1, 2, 0)),
                24,
                Some(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 0))),
                dev.ifindex
            )
            .await?
        );

        handle_subnet_events(&nl, &state, &[peer_event(EventType::Removed, true)]).await;
        assert!(
            !has_route(
                &nl,
                AddressFamily::Inet,
                IpAddr::V4(Ipv4Addr::new(10, 1, 2, 0)),
                24,
                Some(REMOTE_VTEP),
                0
            )
            .await?
        );
        Ok(())
    })
    .unwrap();
}
