//! Additional netns tests for Rust-only route_network code paths
//! (event removal, recovery, end-to-end Run, route_add replacement).
//! Requires root/CAP_NET_ADMIN.

use super::spec::RouteSpec;
use super::tests_netns::{kernel_routes_matching, lo_route, netns_block_on};
use super::{
    check_subnet_exist_in_routes, handle_subnet_events, route_add, GetRouteFn, RouteList,
    RouteNetwork,
};
use crate::backend::traits::Network;
use crate::ip::iface::Netlink;
use crate::ip::{IP4Net, IP6Net, IP4};
use crate::lease::{Event, EventType, Lease, LeaseAttrs, LeaseWatchResult};
use crate::subnet::manager::{Ctx, Manager};
use futures::future::BoxFuture;
use netlink_packet_route::AddressFamily;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};
use tokio::sync::{mpsc, Mutex};
use tokio_util::sync::CancellationToken;

/// Removed events delete the tracked and kernel route.
#[test]
fn test_route_cache_event_removed() {
    netns_block_on("flnl_rt_cache_remove", async {
        let nl = Netlink::new().await?;
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
        let lease = Lease {
            enable_ipv4: true,
            enable_ipv6: false,
            subnet: IP4Net::new(IP4::from_octets(192, 168, 7, 0), 24),
            ipv6_subnet: IP6Net::default(),
            attrs: LeaseAttrs {
                public_ip: IP4::from_octets(127, 0, 0, 1),
                backend_type: "host-gw".to_string(),
                ..Default::default()
            },
            expiration: UNIX_EPOCH,
            asof: 0,
        };

        handle_subnet_events(
            &nl,
            "host-gw",
            Some(&get_route),
            None,
            &[Event {
                event_type: EventType::Added,
                lease: lease.clone(),
            }],
            &routes,
            &v6_routes,
        )
        .await;
        assert_eq!(routes.lock().await.len(), 1);

        handle_subnet_events(
            &nl,
            "host-gw",
            Some(&get_route),
            None,
            &[Event {
                event_type: EventType::Removed,
                lease: lease.clone(),
            }],
            &routes,
            &v6_routes,
        )
        .await;
        assert!(routes.lock().await.is_empty());
        let spec = lo_route("192.168.7.0", 24, "127.0.0.1");
        let matches = kernel_routes_matching(&nl, AddressFamily::Inet, &spec).await?;
        assert!(!matches.iter().any(|m| *m));
        Ok(())
    })
    .unwrap();
}

/// checkSubnetExistInRoutes re-adds tracked routes missing in the kernel.
#[test]
fn test_check_subnet_exist_in_routes() {
    netns_block_on("flnl_rt_check_exist", async {
        let nl = Netlink::new().await?;
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

        let spec = lo_route("192.168.122.0", 24, "127.0.0.1");
        let list: RouteList = Arc::new(Mutex::new(vec![spec.clone()]));
        check_subnet_exist_in_routes(&nl, &list, AddressFamily::Inet).await;
        let matches = kernel_routes_matching(&nl, AddressFamily::Inet, &spec).await?;
        assert!(matches.iter().any(|m| *m), "route was not recovered");
        Ok(())
    })
    .unwrap();
}

/// Manager double for the Run test: forwards injected LeaseWatchResults
/// and blocks until cancellation.
struct EventManager {
    tx: Arc<Mutex<Option<mpsc::Sender<Vec<LeaseWatchResult>>>>>,
}

impl Manager for EventManager {
    fn get_network_config<'a>(
        &'a self,
        _c: Ctx<'a>,
    ) -> BoxFuture<'a, anyhow::Result<crate::subnet::config::Config>> {
        unimplemented!()
    }
    fn handle_subnet_file<'a>(
        &'a self,
        _p: &'a str,
        _c: &'a crate::subnet::config::Config,
        _m: bool,
        _s: IP4Net,
        _s6: IP6Net,
        _mtu: u32,
    ) -> BoxFuture<'a, anyhow::Result<()>> {
        unimplemented!()
    }
    fn acquire_lease<'a>(
        &'a self,
        _c: Ctx<'a>,
        _a: &'a LeaseAttrs,
    ) -> BoxFuture<'a, anyhow::Result<Lease>> {
        unimplemented!()
    }
    fn renew_lease<'a>(
        &'a self,
        _c: Ctx<'a>,
        _l: &'a Lease,
    ) -> BoxFuture<'a, anyhow::Result<Lease>> {
        unimplemented!()
    }
    fn watch_lease<'a>(
        &'a self,
        _c: Ctx<'a>,
        _s: IP4Net,
        _s6: IP6Net,
        _t: mpsc::Sender<Vec<LeaseWatchResult>>,
    ) -> BoxFuture<'a, anyhow::Result<()>> {
        unimplemented!()
    }
    fn watch_leases<'a>(
        &'a self,
        ctx: Ctx<'a>,
        tx: mpsc::Sender<Vec<LeaseWatchResult>>,
    ) -> BoxFuture<'a, anyhow::Result<()>> {
        let slot = self.tx.clone();
        Box::pin(async move {
            *slot.lock().await = Some(tx);
            ctx.cancelled().await;
            Ok(())
        })
    }
    fn complete_lease<'a>(
        &'a self,
        _c: Ctx<'a>,
        _l: &'a Lease,
    ) -> BoxFuture<'a, anyhow::Result<()>> {
        unimplemented!()
    }
    fn get_stored_mac_addresses<'a>(&'a self, _c: Ctx<'a>) -> BoxFuture<'a, (String, String)> {
        unimplemented!()
    }
    fn get_stored_public_ip<'a>(&'a self, _c: Ctx<'a>) -> BoxFuture<'a, (String, String)> {
        unimplemented!()
    }
    fn name(&self) -> String {
        "events".to_string()
    }
}

/// End-to-end Run: inject an Added event through the manager watch and
/// expect the route in the kernel; cancellation joins both tasks.
#[test]
fn test_route_network_run() {
    netns_block_on("flnl_rt_run", async {
        let nl = Netlink::new().await?;
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

        let evt_tx: Arc<Mutex<Option<mpsc::Sender<Vec<LeaseWatchResult>>>>> =
            Arc::new(Mutex::new(None));
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
        let rt_net = Arc::new(RouteNetwork {
            lease: Lease {
                enable_ipv4: true,
                enable_ipv6: false,
                subnet: IP4Net::new(IP4::from_octets(192, 168, 122, 0), 24),
                ipv6_subnet: IP6Net::default(),
                attrs: LeaseAttrs::default(),
                expiration: UNIX_EPOCH,
                asof: 0,
            },
            backend_type: "host-gw".to_string(),
            sm: Arc::new(EventManager { tx: evt_tx.clone() }),
            mtu: 1500,
            link_index: 1,
            get_route: Some(get_route),
            get_v6_route: None,
        });

        let token = CancellationToken::new();
        let net = rt_net.clone();
        let tok = token.clone();
        let handle = tokio::spawn(async move { net.run(&tok).await });

        // Wait for the manager watch to register its sender, then inject
        // an Added event for another node's subnet.
        let tx = loop {
            tokio::time::sleep(Duration::from_millis(20)).await;
            if let Some(tx) = evt_tx.lock().await.clone() {
                break tx;
            }
        };
        let new_lease = Lease {
            enable_ipv4: true,
            enable_ipv6: false,
            subnet: IP4Net::new(IP4::from_octets(192, 168, 123, 0), 24),
            ipv6_subnet: IP6Net::default(),
            attrs: LeaseAttrs {
                public_ip: IP4::from_octets(127, 0, 0, 1),
                backend_type: "host-gw".to_string(),
                ..Default::default()
            },
            expiration: UNIX_EPOCH,
            asof: 0,
        };
        tx.send(vec![LeaseWatchResult {
            events: vec![Event {
                event_type: EventType::Added,
                lease: new_lease,
            }],
            snapshot: Vec::new(),
        }])
        .await?;

        let spec = lo_route("192.168.123.0", 24, "127.0.0.1");
        let mut found = false;
        for _ in 0..200 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            if kernel_routes_matching(&nl, AddressFamily::Inet, &spec)
                .await?
                .iter()
                .any(|m| *m)
            {
                found = true;
                break;
            }
        }
        assert!(found, "route to 192.168.123.0/24 was not installed");

        token.cancel();
        handle.await?;
        Ok(())
    })
    .unwrap();
}

/// route_add tracks first and dedups kernel installs for equal routes.
#[test]
fn test_route_add_replaces_existing() {
    netns_block_on("flnl_rt_add_replace", async {
        let nl = Netlink::new().await?;
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

        let list: RouteList = Arc::new(Mutex::new(Vec::new()));
        let r1 = lo_route("192.168.55.0", 24, "127.0.0.1");
        route_add(&nl, &r1, AddressFamily::Inet, &list).await;
        assert_eq!(list.lock().await.len(), 1);

        // Same route again: tracked list stays at one entry.
        route_add(&nl, &r1, AddressFamily::Inet, &list).await;
        assert_eq!(list.lock().await.len(), 1);

        // New gateway for the same Dst replaces the kernel route.
        let r2 = lo_route("192.168.55.0", 24, "127.0.0.2");
        route_add(&nl, &r2, AddressFamily::Inet, &list).await;
        let l = list.lock().await;
        assert_eq!(l.len(), 1);
        assert_eq!(l[0].gateway, "127.0.0.2".parse::<IpAddr>().unwrap());
        drop(l);
        let matches = kernel_routes_matching(&nl, AddressFamily::Inet, &r2).await?;
        assert!(matches.iter().any(|m| *m));
        let matches = kernel_routes_matching(&nl, AddressFamily::Inet, &r1).await?;
        assert!(!matches.iter().any(|m| *m));
        Ok(())
    })
    .unwrap();
}
