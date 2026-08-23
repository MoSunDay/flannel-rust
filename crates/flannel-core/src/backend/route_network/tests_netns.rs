//! netns tests for the route_network port. `test_route_cache` and
//! `test_v6_route_cache` are 1:1 ports of the Go suite
//! (route_network_test.go); the rest cover Rust-only code paths.
//! Requires root/CAP_NET_ADMIN; netns-rs cleans itself up per test.

use super::spec::{route_msg_matches, RouteSpec};
use super::{dump_routes, handle_subnet_events, GetRouteFn, RouteList};
use crate::ip::iface::Netlink;
use crate::ip::{IP4Net, IP6Net, IP4, IP6};
use crate::lease::{Event, EventType, Lease, LeaseAttrs};
use futures::stream::TryStreamExt;
use netlink_packet_route::AddressFamily;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::UNIX_EPOCH;
use tokio::sync::Mutex;

/// Run a netns-scoped future with a single-threaded runtime, mirroring
/// examples/netlink_spike.rs.
pub(crate) fn netns_block_on<F: std::future::Future<Output = anyhow::Result<()>>>(
    name: &str,
    fut: F,
) -> anyhow::Result<()> {
    // Best-effort cleanup of a stale ns from a crashed previous run
    // (mirrors examples/netlink_spike.rs).
    if let Ok(old) = netns_rs::NetNs::get(name) {
        let _ = old.remove();
    }
    let ns = netns_rs::NetNs::new(name)?;
    ns.enter()?;
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(fut);
    ns.remove()?;
    result
}

pub(crate) fn lo_route(dst: &str, prefix_len: u8, gw: &str) -> RouteSpec {
    RouteSpec {
        dst: dst.parse().unwrap(),
        prefix_len,
        gateway: gw.parse().unwrap(),
        link_index: 1, // loopback always exists
        family: AddressFamily::Inet,
        onlink: false,
    }
}

/// Kernel routes of `family` matching `spec` (dst, prefix, gw, oif).
pub(crate) async fn kernel_routes_matching(
    nl: &Netlink,
    family: AddressFamily,
    spec: &RouteSpec,
) -> anyhow::Result<Vec<bool>> {
    Ok(dump_routes(nl, family)
        .await?
        .iter()
        .map(|m| route_msg_matches(m, spec))
        .collect())
}

/// Port of Go TestRouteCache: a re-added event with the same Dst but a
/// new gateway replaces the tracked and the kernel route.
#[test]
fn test_route_cache() {
    netns_block_on("flnl_rt_cache_v4", async {
        let nl = Netlink::new().await?;
        // Go: AddrAdd(lo, 127.0.0.1/32) then LinkSetUp(lo).
        nl.handle
            .address()
            .add(1, IpAddr::V4("127.0.0.1".parse().unwrap()), 32)
            .execute()
            .await?;
        nl.handle
            .link()
            .set(rtnetlink::LinkUnspec::new_with_index(1).up().build())
            .execute()
            .await?;

        let routes: RouteList = Arc::new(Mutex::new(Vec::new()));
        let v6_routes: RouteList = Arc::new(Mutex::new(Vec::new()));
        let get_route: GetRouteFn = Arc::new(move |lease: &Lease| {
            let spec = RouteSpec {
                dst: IpAddr::V4(lease.subnet.ip.to_std()),
                prefix_len: lease.subnet.prefix_len as u8,
                gateway: IpAddr::V4(lease.attrs.public_ip.to_std()),
                link_index: 1,
                family: AddressFamily::Inet,
                onlink: false,
            };
            Box::pin(async move { spec })
        });

        let subnet1 = IP4Net::new(IP4::from_octets(192, 168, 0, 0), 24);
        let evt = |gw: Ipv4Addr| Event {
            event_type: EventType::Added,
            lease: Lease {
                enable_ipv4: true,
                enable_ipv6: false,
                subnet: subnet1,
                ipv6_subnet: IP6Net::default(),
                attrs: LeaseAttrs {
                    public_ip: IP4::from_bytes(gw.octets()),
                    backend_type: "host-gw".to_string(),
                    ..Default::default()
                },
                expiration: UNIX_EPOCH,
                asof: 0,
            },
        };

        handle_subnet_events(
            &nl,
            "host-gw",
            Some(&get_route),
            None,
            &[evt("127.0.0.1".parse().unwrap())],
            &routes,
            &v6_routes,
        )
        .await;
        {
            let l = routes.lock().await;
            assert_eq!(l.len(), 1);
            assert!(route_msg_matches_matches_spec(
                &l[0],
                subnet1,
                "127.0.0.1",
                1
            ));
        }

        // Change the gateway of the previous route.
        handle_subnet_events(
            &nl,
            "host-gw",
            Some(&get_route),
            None,
            &[evt("127.0.0.2".parse().unwrap())],
            &routes,
            &v6_routes,
        )
        .await;
        {
            let l = routes.lock().await;
            assert_eq!(l.len(), 1);
            assert!(route_msg_matches_matches_spec(
                &l[0],
                subnet1,
                "127.0.0.2",
                1
            ));
        }

        // The kernel route now points at the new gateway.
        let spec2 = lo_route("192.168.0.0", 24, "127.0.0.2");
        let matches = kernel_routes_matching(&nl, AddressFamily::Inet, &spec2).await?;
        assert!(matches.iter().any(|m| *m));
        let spec1 = lo_route("192.168.0.0", 24, "127.0.0.1");
        let matches = kernel_routes_matching(&nl, AddressFamily::Inet, &spec1).await?;
        assert!(!matches.iter().any(|m| *m));
        Ok(())
    })
    .unwrap();
}

/// routeEqual-style check on a tracked spec (Go compares Dst/Gw/LinkIndex).
fn route_msg_matches_matches_spec(
    spec: &RouteSpec,
    dst: IP4Net,
    gw: &str,
    link_index: u32,
) -> bool {
    use super::spec::route_spec_equal;
    let want = RouteSpec {
        dst: IpAddr::V4(dst.ip.to_std()),
        prefix_len: dst.prefix_len as u8,
        gateway: gw.parse().unwrap(),
        link_index,
        family: spec.family,
        onlink: false,
    };
    route_spec_equal(spec, &want)
}

/// Port of Go TestV6RouteCache: bridge "br" with 2001:db8:1::1/64, v6
/// subnet routes swapped from gw ::2 to ::10.
#[test]
fn test_v6_route_cache() {
    netns_block_on("flnl_rt_cache_v6", async {
        let nl = Netlink::new().await?;
        nl.handle
            .link()
            .add(rtnetlink::LinkBridge::new("br").build())
            .execute()
            .await?;
        let idx = {
            let mut links = nl.handle.link().get().match_name("br").execute();
            links
                .try_next()
                .await?
                .ok_or(anyhow::anyhow!("no br link"))?
                .header
                .index
        };
        nl.handle
            .address()
            .add(idx, IpAddr::V6("2001:db8:1::1".parse().unwrap()), 64)
            .execute()
            .await?;
        nl.handle
            .link()
            .set(rtnetlink::LinkUnspec::new_with_index(idx).up().build())
            .execute()
            .await?;

        let routes: RouteList = Arc::new(Mutex::new(Vec::new()));
        let v6_routes: RouteList = Arc::new(Mutex::new(Vec::new()));
        let link = idx;
        let get_v6_route: GetRouteFn = Arc::new(move |lease: &Lease| {
            let spec = RouteSpec {
                dst: IpAddr::V6(lease.ipv6_subnet.ip.to_std()),
                prefix_len: lease.ipv6_subnet.prefix_len as u8,
                gateway: IpAddr::V6(lease.attrs.public_ipv6.unwrap_or_default().to_std()),
                link_index: link,
                family: AddressFamily::Inet6,
                onlink: false,
            };
            Box::pin(async move { spec })
        });

        let subnet1 = IP6Net {
            ip: IP6::from_std("2001:db8:ffff::".parse().unwrap()),
            prefix_len: 64,
        };
        let evt = |gw: &str| Event {
            event_type: EventType::Added,
            lease: Lease {
                enable_ipv4: false,
                enable_ipv6: true,
                subnet: IP4Net::default(),
                ipv6_subnet: subnet1,
                attrs: LeaseAttrs {
                    public_ipv6: Some(IP6::from_std(gw.parse().unwrap())),
                    backend_type: "host-gw".to_string(),
                    ..Default::default()
                },
                expiration: UNIX_EPOCH,
                asof: 0,
            },
        };

        handle_subnet_events(
            &nl,
            "host-gw",
            None,
            Some(&get_v6_route),
            &[evt("2001:db8:1::2")],
            &routes,
            &v6_routes,
        )
        .await;
        {
            let l = v6_routes.lock().await;
            assert_eq!(l.len(), 1);
            assert_eq!(l[0].gateway, "2001:db8:1::2".parse::<IpAddr>().unwrap());
            assert_eq!(l[0].link_index, idx);
        }

        handle_subnet_events(
            &nl,
            "host-gw",
            None,
            Some(&get_v6_route),
            &[evt("2001:db8:1::10")],
            &routes,
            &v6_routes,
        )
        .await;
        {
            let l = v6_routes.lock().await;
            assert_eq!(l.len(), 1);
            assert_eq!(l[0].gateway, "2001:db8:1::10".parse::<IpAddr>().unwrap());
            assert_eq!(l[0].link_index, idx);
        }

        // Go checks RouteList(br, FAMILY_V6) for the gateway; the kernel
        // route must now be via ::10 on br.
        let spec = RouteSpec {
            dst: IpAddr::V6("2001:db8:ffff::".parse().unwrap()),
            prefix_len: 64,
            gateway: "2001:db8:1::10".parse().unwrap(),
            link_index: idx,
            family: AddressFamily::Inet6,
            onlink: false,
        };
        let matches = kernel_routes_matching(&nl, AddressFamily::Inet6, &spec).await?;
        assert!(matches.iter().any(|m| *m));
        Ok(())
    })
    .unwrap();
}

/// Events for other backend types must be ignored (Go logs
/// "Ignoring non-ipip subnet: type=host-gw").
#[test]
fn test_route_cache_events_ignored() {
    netns_block_on("flnl_rt_cache_ignore", async {
        let nl = Netlink::new().await?;
        let routes: RouteList = Arc::new(Mutex::new(Vec::new()));
        let v6_routes: RouteList = Arc::new(Mutex::new(Vec::new()));
        let batch = vec![Event {
            event_type: EventType::Added,
            lease: Lease {
                enable_ipv4: true,
                enable_ipv6: false,
                subnet: IP4Net::new(IP4::from_octets(192, 168, 122, 0), 24),
                ipv6_subnet: IP6Net::default(),
                attrs: LeaseAttrs {
                    public_ip: IP4::from_octets(127, 0, 0, 1),
                    backend_type: "host-gw".to_string(),
                    ..Default::default()
                },
                expiration: UNIX_EPOCH,
                asof: 0,
            },
        }];
        handle_subnet_events(&nl, "ipip", None, None, &batch, &routes, &v6_routes).await;
        assert!(routes.lock().await.is_empty());
        assert!(v6_routes.lock().await.is_empty());
        Ok(())
    })
    .unwrap();
}
