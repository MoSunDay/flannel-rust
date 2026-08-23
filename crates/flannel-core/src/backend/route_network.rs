//! Port of pkg/backend/route_network.go (upstream cdf76059): the shared
//! `RouteNetwork` used by the route-based backends (host-gw, ipip). It
//! watches subnet leases and maintains one static route per peer subnet.
//!
//! Go deviations (documented where relevant):
//! - Go's `netlink.Route` is reduced to [`RouteSpec`] (dst/gw/oif/family
//!   plus the onlink flag; see `spec.rs`), convertible to an rtnetlink
//!   RouteMessage.
//! - Go's pointer-receiver mutations of `routes`/`v6Routes` become two
//!   tokio `Mutex` lists shared by the event loop and the route-check
//!   task; both Go goroutines map 1:1 to tokio tasks.
//! - Kernel route dumps default to the main table, mirroring Go's
//!   `RouteList`/`RouteListFiltered` defaults.

pub mod spec;

use crate::ip::iface::{route_dst, Netlink};
use crate::lease::{Event, EventType, Lease};
use crate::subnet::manager::{Ctx, Manager};
use crate::subnet::watch::watch_leases;
use futures::future::BoxFuture;
use futures::stream::TryStreamExt;
use netlink_packet_route::route::RouteMessage;
use netlink_packet_route::AddressFamily;
use spec::{add_to_route_list, remove_from_route_list, remove_msg_from_route_list};
use spec::{route_msg_matches, spec_of, RouteSpec};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};
use tokio_util::sync::CancellationToken;

pub use spec::{route_spec_equal as spec_equal, RouteSpec as Spec};

/// Go `routeCheckRetries = 10`: route reconciliation period in seconds.
pub const ROUTE_CHECK_RETRIES: u64 = 10;

/// Capacity of the event channel. Go uses an unbuffered channel.
const EVENT_CHAN_CAP: usize = 1;

/// Port of Go `GetRoute func(*lease.Lease) *netlink.Route` (and
/// `GetV6Route`). Async because ipip's `DirectRouting` variant needs a
/// netlink lookup; simple backends return a ready future.
pub type GetRouteFn = Arc<dyn Fn(&Lease) -> BoxFuture<'static, RouteSpec> + Send + Sync>;

/// Route list shared between the event loop and the route-check task
/// (Go: `routes`/`v6Routes` fields mutated through the pointer receiver).
pub type RouteList = Arc<Mutex<Vec<RouteSpec>>>;

/// Port of Go `RouteNetwork` (embeds `SimpleNetwork`: lease + MTU).
pub struct RouteNetwork {
    /// Go `SimpleNetwork.SubnetLease`.
    pub lease: Lease,
    /// Go `BackendType`.
    pub backend_type: String,
    /// Go `SM subnet.Manager`.
    pub sm: Arc<dyn Manager>,
    /// Go `Mtu` (`MTU()` returns it).
    pub mtu: u32,
    /// Go `LinkIndex`.
    pub link_index: u32,
    /// Go `GetRoute`; `None` when the backend disabled the family.
    pub get_route: Option<GetRouteFn>,
    /// Go `GetV6Route`.
    pub get_v6_route: Option<GetRouteFn>,
}

impl crate::backend::traits::Network for RouteNetwork {
    fn lease(&self) -> &Lease {
        &self.lease
    }

    fn mtu(&self) -> u32 {
        self.mtu
    }

    fn run<'a>(&'a self, ctx: Ctx<'a>) -> BoxFuture<'a, ()> {
        Box::pin(run_route_network(self, ctx))
    }
}

/// Port of Go `(*RouteNetwork).Run`: watch leases, run the periodic
/// route check, process subnet events until the channel closes, then
/// wait for cancellation (Go: `defer wg.Wait()`; the route-check
/// goroutine only exits on `ctx.Done()`).
async fn run_route_network(nw: &RouteNetwork, ctx: Ctx<'_>) {
    tracing::info!("Watching for new subnet leases");
    let (tx, mut rx) = mpsc::channel::<Vec<Event>>(EVENT_CHAN_CAP);

    let watch_task = tokio::spawn({
        let sm = nw.sm.clone();
        let own_lease = nw.lease.clone();
        let token = ctx.clone();
        async move { watch_leases(&token, &*sm, &own_lease, tx).await }
    });

    // Go: `n.routes = make([]netlink.Route, 0, 10)` (v6 list untouched).
    let routes: RouteList = Arc::new(Mutex::new(Vec::with_capacity(10)));
    let v6_routes: RouteList = Arc::new(Mutex::new(Vec::new()));

    let nl = match Netlink::new().await {
        Ok(nl) => nl,
        Err(e) => {
            tracing::error!("failed to open netlink connection: {e}");
            return;
        }
    };

    let check_task = tokio::spawn(route_check(
        ctx.clone(),
        nl.clone(),
        routes.clone(),
        v6_routes.clone(),
    ));

    // Go: `for { evtBatch, ok := <-evts; if !ok { log; return }; ... }`
    // -- the loop has no ctx case; it ends when the evts channel closes,
    // which happens when `WatchLeases` returns (it does so on ctx
    // cancellation).
    while let Some(batch) = rx.recv().await {
        handle_subnet_events(
            &nl,
            &nw.backend_type,
            nw.get_route.as_ref(),
            nw.get_v6_route.as_ref(),
            &batch,
            &routes,
            &v6_routes,
        )
        .await;
    }
    tracing::info!("evts chan closed");

    // Go: `defer wg.Wait()` -- Run returns only after both goroutines
    // end; routeCheck ends solely on ctx.Done().
    let _ = (watch_task.await, check_task.await);
}

/// Port of Go `(*RouteNetwork).handleSubnetEvents`.
pub(crate) async fn handle_subnet_events(
    nl: &Netlink,
    backend_type: &str,
    get_route: Option<&GetRouteFn>,
    get_v6_route: Option<&GetRouteFn>,
    batch: &[Event],
    routes: &RouteList,
    v6_routes: &RouteList,
) {
    for evt in batch {
        match evt.event_type {
            EventType::Added => {
                if evt.lease.attrs.backend_type != backend_type {
                    tracing::warn!(
                        "Ignoring non-{backend_type} subnet: type={}",
                        evt.lease.attrs.backend_type
                    );
                    continue;
                }

                if evt.lease.enable_ipv4 {
                    tracing::info!(
                        "Subnet added: {} via {}",
                        evt.lease.subnet,
                        evt.lease.attrs.public_ip
                    );
                    let Some(gr) = get_route else {
                        tracing::warn!("no v4 GetRoute configured; skipping");
                        continue;
                    };
                    let route = gr(&evt.lease).await;
                    route_add(nl, &route, AddressFamily::Inet, routes).await;
                }

                if evt.lease.enable_ipv6 {
                    let pv6 = evt
                        .lease
                        .attrs
                        .public_ipv6
                        .map(|ip| ip.to_string())
                        .unwrap_or_else(|| "<nil>".to_string());
                    tracing::info!("Subnet added: {} via {}", evt.lease.ipv6_subnet, pv6);
                    let Some(gr6) = get_v6_route else {
                        tracing::warn!("no v6 GetRoute configured; skipping");
                        continue;
                    };
                    let route = gr6(&evt.lease).await;
                    route_add(nl, &route, AddressFamily::Inet6, v6_routes).await;
                }
            }
            EventType::Removed => {
                if evt.lease.attrs.backend_type != backend_type {
                    tracing::warn!(
                        "Ignoring non-{backend_type} subnet: type={}",
                        evt.lease.attrs.backend_type
                    );
                    continue;
                }

                if evt.lease.enable_ipv4 {
                    tracing::info!("Subnet removed: {}", evt.lease.subnet);
                    let Some(gr) = get_route else { continue };
                    let route = gr(&evt.lease).await;
                    // Go: always remove from the route list first.
                    remove_from_route_list(&mut *routes.lock().await, &route);
                    if let Err(e) = nl.handle.route().del(route.to_message()).execute().await {
                        tracing::error!("Error deleting route to {}: {}", evt.lease.subnet, e);
                    }
                }

                if evt.lease.enable_ipv6 {
                    tracing::info!("Subnet removed: {}", evt.lease.ipv6_subnet);
                    let Some(gr6) = get_v6_route else { continue };
                    let route = gr6(&evt.lease).await;
                    remove_from_route_list(&mut *v6_routes.lock().await, &route);
                    if let Err(e) = nl.handle.route().del(route.to_message()).execute().await {
                        tracing::error!("Error deleting route to {}: {}", evt.lease.ipv6_subnet, e);
                    }
                }
            } // EventType is exhaustive; Go's `default` branch is unreachable.
        }
    }
}

/// Port of Go `routeAdd`: track the route, replace any kernel route with
/// the same Dst but different Gw/LinkIndex, then add unless an equal
/// route already exists. The final `RouteListFiltered` (result unused in
/// Go) is kept for parity.
pub(crate) async fn route_add(
    nl: &Netlink,
    route: &RouteSpec,
    family: AddressFamily,
    list: &RouteList,
) {
    add_to_route_list(&mut *list.lock().await, route);

    // Check if route exists before attempting to add it.
    let mut route_list = match list_routes_by_dst(nl, family, route).await {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!("Unable to list routes: {e}");
            Vec::new()
        }
    };

    if let Some(first) = route_list.first() {
        if !route_msg_matches(first, route) {
            // Same Dst different Gw or different link index. Remove it,
            // correct route will be added below.
            tracing::warn!(
                "Replacing existing route to {} with {}",
                spec_of(first),
                route
            );
            if let Err(e) = nl.handle.route().del(first.clone()).execute().await {
                // Go typo ("Effor deleteing") kept verbatim from upstream.
                tracing::error!(
                    "Effor deleteing route to {}: {}",
                    spec_of(first).dst_net(),
                    e
                );
                return;
            }
            remove_msg_from_route_list(&mut *list.lock().await, first);
        }
    }

    route_list = match list_routes_by_dst(nl, family, route).await {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!("Unable to list routes: {e}");
            Vec::new()
        }
    };

    if matches!(route_list.first(), Some(first) if route_msg_matches(first, route)) {
        // Same Dst and same Gw, keep it and do not attempt to add it.
        tracing::info!("Route to {route} already exists, skipping.");
    } else if let Err(e) = nl.handle.route().add(route.to_message()).execute().await {
        tracing::error!("Error adding route to {route}: {e}");
        return;
    }

    if let Err(e) = list_routes_by_dst(nl, family, route).await {
        tracing::warn!("Unable to list routes: {e}");
    }
}

/// Port of Go `routeCheck`: re-add missing routes every
/// `routeCheckRetries` seconds until cancelled.
async fn route_check(ctx: CancellationToken, nl: Netlink, routes: RouteList, v6_routes: RouteList) {
    loop {
        tokio::select! {
            biased;
            _ = ctx.cancelled() => return,
            _ = tokio::time::sleep(Duration::from_secs(ROUTE_CHECK_RETRIES)) => {
                check_subnet_exist_in_routes(&nl, &routes, AddressFamily::Inet).await;
                check_subnet_exist_in_routes(&nl, &v6_routes, AddressFamily::Inet6).await;
            }
        }
    }
}

/// Port of Go `checkSubnetExistInRoutes`: re-add every tracked route
/// missing from the kernel table.
pub(crate) async fn check_subnet_exist_in_routes(
    nl: &Netlink,
    list: &RouteList,
    family: AddressFamily,
) {
    let routes = list.lock().await.clone();
    let route_list = match dump_routes(nl, family).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("Error fetching route list. Will automatically retry: {e}");
            return;
        }
    };

    for route in &routes {
        let exist = route_list
            .iter()
            .any(|r| route_dst(r).is_some() && route_msg_matches(r, route));
        if exist {
            continue;
        }
        match nl.handle.route().add(route.to_message()).execute().await {
            // Go logs only non-`net.Error` failures; Go's syscall-based
            // netlink errors implement net.Error, so kernel rejections
            // are skipped silently. `NetlinkError` (errno-carrying) is
            // the Rust equivalent class.
            Err(e) => {
                if !matches!(e, rtnetlink::Error::NetlinkError(_)) {
                    tracing::error!(
                        "Error recovering route to {}: {}, {}",
                        route.dst_net(),
                        route.gateway,
                        e
                    );
                }
            }
            Ok(()) => tracing::info!("Route recovered {} : {}", route.dst_net(), route.gateway),
        }
    }
}

/// Dump routes of one family (kernel dumps default to the main table,
/// matching Go's `RouteList` defaults).
pub(crate) async fn dump_routes(
    nl: &Netlink,
    family: AddressFamily,
) -> anyhow::Result<Vec<RouteMessage>> {
    let mut routes = nl.handle.route().get(RouteMessage::default()).execute();
    let mut out = Vec::new();
    while let Some(route) = routes
        .try_next()
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?
    {
        if route.header.address_family == family {
            out.push(route);
        }
    }
    Ok(out)
}

/// Port of Go `RouteListFiltered(family, &Route{Dst: dst}, RT_FILTER_DST)`.
pub(crate) async fn list_routes_by_dst(
    nl: &Netlink,
    family: AddressFamily,
    route: &RouteSpec,
) -> anyhow::Result<Vec<RouteMessage>> {
    Ok(dump_routes(nl, family)
        .await?
        .into_iter()
        .filter(|r| {
            route_dst(r) == Some(route.dst)
                && r.header.destination_prefix_length == route.prefix_len
        })
        .collect())
}

#[cfg(test)]
#[path = "route_network/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "route_network/tests_netns.rs"]
mod tests_netns;

#[cfg(test)]
#[path = "route_network/tests_run.rs"]
mod tests_run;
