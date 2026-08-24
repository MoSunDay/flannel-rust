// Read-only netlink survey (split out of the netlink spike): link /
// address / route dumps (async, tokio). Works without NET_ADMIN.

use std::net::IpAddr;

use futures::stream::TryStreamExt;
use netlink_packet_route::{
    address::AddressAttribute,
    link::{LinkAttribute, LinkMessage},
    route::{RouteAddress, RouteAttribute, RouteMessage},
    AddressFamily,
};
use rtnetlink::Handle;

use crate::rterr;

// ---------- read-only survey: links, addresses, routes ----------

pub fn link_summary(msg: &LinkMessage) -> (String, u32) {
    let mut name = String::from("?");
    let mut mtu = 0;
    for attr in &msg.attributes {
        match attr {
            LinkAttribute::IfName(n) => name = n.clone(),
            LinkAttribute::Mtu(m) => mtu = *m,
            _ => {}
        }
    }
    (name, mtu)
}

pub async fn survey(handle: &Handle) -> anyhow::Result<()> {
    println!("=== read-only survey (works without NET_ADMIN) ===");

    let mut links = handle.link().get().execute();
    let mut total = 0usize;
    while let Some(link) = links.try_next().await.map_err(rterr)? {
        total += 1;
        if total <= 8 {
            let (name, mtu) = link_summary(&link);
            println!(
                "  link  idx={:<3} name={:<16} mtu={}",
                link.header.index, name, mtu
            );
        }
    }
    println!("  links: {total} total");

    let mut addrs = handle.address().get().execute();
    let mut shown = 0usize;
    while let Some(addr) = addrs.try_next().await.map_err(rterr)? {
        if addr.header.family != AddressFamily::Inet {
            continue;
        }
        if shown < 8 {
            let ip = addr.attributes.iter().find_map(|a| match a {
                AddressAttribute::Address(ip) => Some(ip.to_string()),
                _ => None,
            });
            println!(
                "  addr  ifindex={:<3} {}/{}",
                addr.header.index,
                ip.unwrap_or_default(),
                addr.header.prefix_len
            );
        }
        shown += 1;
    }
    println!("  addrs: {shown} ipv4 total");

    // RouteMessage::default() has no Destination attribute, so
    // RouteGetRequest performs a full dump (NLM_F_DUMP).
    let mut routes = handle.route().get(RouteMessage::default()).execute();
    let mut shown_routes = 0usize;
    while let Some(route) = routes.try_next().await.map_err(rterr)? {
        if shown_routes < 8 {
            println!("  route {}", fmt_route(&route));
        }
        shown_routes += 1;
    }
    println!("  routes: {shown_routes} total");
    Ok(())
}

fn route_attr_ip(attrs: &[RouteAttribute], want_dst: bool) -> Option<IpAddr> {
    attrs.iter().find_map(|a| {
        let route_addr = match a {
            RouteAttribute::Destination(r) if want_dst => Some(r),
            RouteAttribute::Gateway(r) if !want_dst => Some(r),
            _ => None,
        }?;
        match route_addr {
            RouteAddress::Inet(v4) => Some(IpAddr::V4(*v4)),
            RouteAddress::Inet6(v6) => Some(IpAddr::V6(*v6)),
            _ => None,
        }
    })
}

pub fn fmt_route(route: &RouteMessage) -> String {
    let dst = route_attr_ip(&route.attributes, true)
        .map(|i| i.to_string())
        .unwrap_or_else(|| "default".into());
    let gw = route_attr_ip(&route.attributes, false)
        .map(|i| format!(" via {i}"))
        .unwrap_or_default();
    let oif = route
        .attributes
        .iter()
        .find_map(|a| match a {
            RouteAttribute::Oif(i) => Some(*i),
            _ => None,
        })
        .map(|i| format!(" dev#{i}"))
        .unwrap_or_default();
    format!(
        "{}/{}{}{} table={}",
        dst, route.header.destination_prefix_length, gw, oif, route.header.table
    )
}
