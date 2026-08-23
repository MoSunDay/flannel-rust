//! Port of pkg/ipmatch/match.go: interface matching for `--iface`,
//! `--iface-regex` and `--iface-canreach`. Error strings kept
//! byte-identical to Go.

use std::net::IpAddr;

use anyhow::{anyhow, bail, Context, Result};
use regex::Regex;
use tracing::info;

use crate::backend::common::ExternalInterface;
use crate::ip::iface::{
    get_default_gateway_interface, get_default_v6_gateway_interface, get_iface_ip4_addrs,
    get_iface_ip6_addrs, get_interface_by_ip, get_interface_by_ip6, get_interface_by_name,
    get_interface_by_specific_ip_routing, get_link_mtu, list_links, net_iface_of, NetIface,
    Netlink,
};

/// Mirror of Go match.go's unexported IP-family stack constants.
pub const IPV4_STACK: i32 = 0;
pub const IPV6_STACK: i32 = 1;
pub const DUAL_STACK: i32 = 2;
pub const NONE_STACK: i32 = 3;

/// PublicIPOpts mirrors match.go's PublicIPOpts.
#[derive(Default)]
pub struct PublicIPOpts {
    pub public_ip: String,
    pub public_ip_v6: String,
}

/// Go GetIPFamily: stack derived from the enabled address families.
pub fn get_ip_family(auto_detect_ipv4: bool, auto_detect_ipv6: bool) -> Result<i32> {
    if auto_detect_ipv4 && !auto_detect_ipv6 {
        Ok(IPV4_STACK)
    } else if !auto_detect_ipv4 && auto_detect_ipv6 {
        Ok(IPV6_STACK)
    } else if auto_detect_ipv4 && auto_detect_ipv6 {
        Ok(DUAL_STACK)
    } else {
        Err(anyhow!("none defined stack"))
    }
}

/// Go `%s` on a possibly-nil net.IP: "<nil>" when absent.
fn show_ip(ip: Option<IpAddr>) -> String {
    ip.map_or_else(|| "<nil>".to_string(), |a| a.to_string())
}

/// Wraps err Go-style: "prefix: cause".
fn ctx(prefix: impl std::fmt::Display, err: anyhow::Error) -> anyhow::Error {
    err.context(format!("{prefix}"))
}

fn lookup_err(ifname: &str, e: anyhow::Error) -> anyhow::Error {
    ctx(format!("error looking up interface {ifname}"), e)
}

fn lookup_v6_err(name: &str, e: anyhow::Error) -> anyhow::Error {
    ctx(format!("error looking up v6 interface {name}"), e)
}

fn default_iface_err(e: anyhow::Error) -> anyhow::Error {
    ctx("failed to get default interface", e)
}

fn default_v6_iface_err(e: anyhow::Error) -> anyhow::Error {
    ctx("failed to get default v6 interface", e)
}

/// Go GetInterfaceByIP: v4 address match over all interfaces.
async fn iface_by_ip(nl: &Netlink, ip: IpAddr) -> Result<NetIface> {
    match ip {
        IpAddr::V4(v4) => get_interface_by_ip(nl, v4).await,
        IpAddr::V6(_) => Err(anyhow!("no interface with given IP found")),
    }
}

/// Go GetInterfaceByIP6: v6 address match over all interfaces.
async fn iface_by_ip6(nl: &Netlink, ip: IpAddr) -> Result<NetIface> {
    match ip {
        IpAddr::V6(v6) => get_interface_by_ip6(nl, v6).await,
        IpAddr::V4(_) => Err(anyhow!("no interface with given IPv6 found")),
    }
}

/// Go matchIP: first interface address whose string matches the regex.
fn match_ip(re: &Regex, ips: &[IpAddr]) -> Option<IpAddr> {
    ips.iter().copied().find(|ip| re.is_match(&ip.to_string()))
}

/// Go's `%s:%v` rendering of "name:[ip1 ip2 ...]" for the
/// available-interfaces error message.
fn face_desc(name: &str, ips: &[IpAddr]) -> String {
    let ips: Vec<String> = ips.iter().map(|ip| ip.to_string()).collect();
    format!("{name}:[{}]", ips.join(" "))
}

/// LookupExtIface mirrors match.go's LookupExtIface. `ip_stack` comes
/// from get_ip_family, like Go's main passes it in.
pub async fn lookup_ext_iface(
    nl: &Netlink,
    ifname: &str,
    ifregex: &str,
    ifcanreach: &str,
    ip_stack: i32,
    opts: &PublicIPOpts,
) -> Result<ExternalInterface> {
    let mut iface: Option<NetIface> = None;
    let mut iface_addr: Option<IpAddr> = None;
    let mut iface_v6_addr: Option<IpAddr> = None;
    let mut compiled: Option<Regex> = None;

    if !ifregex.is_empty() {
        match Regex::new(ifregex) {
            Ok(re) => compiled = Some(re),
            Err(e) => {
                bail!("could not compile the IP address regex '{ifregex}': {e}")
            }
        }
    }

    if ip_stack == NONE_STACK {
        bail!("none matched ip stack");
    }

    if !ifname.is_empty() {
        if let Ok(ip) = ifname.parse::<IpAddr>() {
            info!("Searching for interface using {ip}");
            // Go assigns ifaceAddr = net.ParseIP(ifname) before the switch.
            iface_addr = Some(ip);
            match ip_stack {
                IPV4_STACK => {
                    let f = iface_by_ip(nl, ip).await;
                    iface = Some(f.map_err(|e| lookup_err(ifname, e))?);
                }
                IPV6_STACK => {
                    let f = iface_by_ip6(nl, ip).await;
                    iface = Some(f.map_err(|e| lookup_v6_err(ifname, e))?);
                    iface_v6_addr = Some(ip);
                }
                DUAL_STACK => {
                    if ip.is_ipv4() {
                        let f = iface_by_ip(nl, ip).await;
                        iface = Some(f.map_err(|e| lookup_err(ifname, e))?);
                    }
                    if !opts.public_ip_v6.is_empty() {
                        if let Ok(v6) = opts.public_ip_v6.parse::<IpAddr>() {
                            iface_v6_addr = Some(v6);
                            let p = opts.public_ip_v6.as_str();
                            let f = iface_by_ip6(nl, v6).await;
                            let v6_iface = f.map_err(|e| lookup_v6_err(p, e))?;
                            if ip.is_ipv6() {
                                iface = Some(v6_iface);
                                iface_addr = None;
                            } else if iface.as_ref().unwrap().name != v6_iface.name {
                                bail!(
                                    "v6 interface {} must be the same with v4 interface {}",
                                    v6_iface.name,
                                    iface.as_ref().unwrap().name
                                );
                            }
                        }
                    }
                }
                _ => {}
            }
        } else {
            let f = get_interface_by_name(nl, ifname).await;
            iface = Some(f.map_err(|e| lookup_err(ifname, e))?);
        }
    } else if let Some(re) = &compiled {
        // Use the regex if specified and the iface option for matching a
        // specific ip or name is not used.
        let links = list_links(nl).await;
        let links = links.map_err(|e| ctx("error listing all interfaces", e))?;
        let faces: Vec<NetIface> = links.iter().map(net_iface_of).collect();

        // Check IP (Go's labelled `ifaceLoop` loop, ported with `matched`).
        for face in &faces {
            let mut matched = false;
            match ip_stack {
                IPV4_STACK => {
                    if let Ok(ips) = get_iface_ip4_addrs(nl, face).await {
                        if let Some(m) = match_ip(re, &ips) {
                            iface_addr = Some(m);
                            iface = Some(face.clone());
                            matched = true;
                        }
                    }
                }
                IPV6_STACK => {
                    if let Ok(ips) = get_iface_ip6_addrs(nl, face).await {
                        if let Some(m) = match_ip(re, &ips) {
                            iface_v6_addr = Some(m);
                            iface = Some(face.clone());
                            matched = true;
                        }
                    }
                }
                DUAL_STACK => {
                    let v4s = match get_iface_ip4_addrs(nl, face).await {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    let v6s = match get_iface_ip6_addrs(nl, face).await {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    if let Some(m) = match_ip(re, &v4s) {
                        iface_addr = Some(m);
                    } else {
                        continue;
                    }
                    if let Some(m) = match_ip(re, &v6s) {
                        iface_v6_addr = Some(m);
                        iface = Some(face.clone());
                        matched = true;
                    }
                }
                _ => {}
            }
            if matched {
                break;
            }
        }

        // Check Name.
        if iface.is_none() && (iface_addr.is_none() || iface_v6_addr.is_none()) {
            for face in &faces {
                if re.is_match(&face.name) {
                    iface = Some(face.clone());
                    break;
                }
            }
        }

        // Check that nothing was matched.
        if iface.is_none() {
            let mut avail = Vec::new();
            for face in &faces {
                let ips = if ip_stack == IPV6_STACK {
                    get_iface_ip6_addrs(nl, face).await.unwrap_or_default()
                } else {
                    get_iface_ip4_addrs(nl, face).await.unwrap_or_default()
                };
                avail.push(face_desc(&face.name, &ips));
            }
            bail!(
                "could not match pattern {ifregex} to any of the available \
                 network interfaces ({})",
                avail.join(", ")
            );
        }
    } else if !ifcanreach.is_empty() {
        info!("Determining interface to use based on given ifcanreach: {ifcanreach}");
        let ip: IpAddr = ifcanreach
            .parse()
            .context("failed to get ifcanreach based interface")?;
        let f = get_interface_by_specific_ip_routing(nl, ip).await;
        let (i, addr) = f.map_err(|e| ctx("failed to get ifcanreach based interface", e))?;
        iface = Some(i);
        iface_addr = addr;
    } else {
        info!("Determining IP address of default interface");
        match ip_stack {
            IPV4_STACK => {
                let f = get_default_gateway_interface(nl).await;
                let (i, _) = f.map_err(default_iface_err)?;
                iface = Some(i);
            }
            IPV6_STACK => {
                let f = get_default_v6_gateway_interface(nl).await;
                let (i, _) = f.map_err(default_v6_iface_err)?;
                iface = Some(i);
            }
            DUAL_STACK => {
                let f = get_default_gateway_interface(nl).await;
                let (i, _) = f.map_err(default_iface_err)?;
                let f6 = get_default_v6_gateway_interface(nl).await;
                let (v6_iface, _) = f6.map_err(default_v6_iface_err)?;
                if i.name != v6_iface.name {
                    bail!(
                        "v6 default route interface {} must be the same with \
                         v4 default route interface {}",
                        v6_iface.name,
                        i.name
                    );
                }
                iface = Some(i);
            }
            _ => {}
        }
    }

    let i = iface.ok_or_else(|| anyhow!("couldn't find interface to use"))?;

    // Fill in the interface addresses not fixed by the matching above.
    if (ip_stack == IPV4_STACK && iface_addr.is_none())
        || (ip_stack == DUAL_STACK && iface_addr.is_none())
    {
        match get_iface_ip4_addrs(nl, &i).await {
            Ok(a) if !a.is_empty() => iface_addr = Some(a[0]),
            _ => bail!("failed to find IPv4 address for interface {}", i.name),
        }
    }
    if (ip_stack == IPV6_STACK && iface_v6_addr.is_none())
        || (ip_stack == DUAL_STACK && iface_v6_addr.is_none())
    {
        match get_iface_ip6_addrs(nl, &i).await {
            Ok(a) if !a.is_empty() => iface_v6_addr = Some(a[0]),
            _ => bail!("failed to find IPv6 address for interface {}", i.name),
        }
    }

    if let Some(addr) = iface_addr {
        info!("Using interface with name {} and address {addr}", i.name);
    }
    if let Some(addr) = iface_v6_addr {
        info!("Using interface with name {} and v6 address {addr}", i.name);
    }

    let mtu = get_link_mtu(nl, i.index).await.unwrap_or(0);
    if mtu == 0 {
        bail!(
            "failed to determine MTU for {} interface",
            show_ip(iface_addr)
        );
    }

    let mut ext_addr: Option<IpAddr> = None;
    let mut ext_v6_addr: Option<IpAddr> = None;

    if !opts.public_ip.is_empty() {
        match opts.public_ip.parse::<IpAddr>() {
            Ok(ip) => {
                ext_addr = Some(ip);
                info!("Using {ip} as external address");
            }
            Err(_) => bail!("invalid public IP address: {}", opts.public_ip),
        }
    }
    if ext_addr.is_none() && ip_stack != IPV6_STACK {
        info!(
            "Defaulting external address to interface address ({})",
            show_ip(iface_addr)
        );
        ext_addr = iface_addr;
    }

    if !opts.public_ip_v6.is_empty() {
        match opts.public_ip_v6.parse::<IpAddr>() {
            Ok(ip) => {
                ext_v6_addr = Some(ip);
                info!("Using {ip} as external address");
            }
            Err(_) => bail!("invalid public IPv6 address: {}", opts.public_ip_v6),
        }
    }
    if ext_v6_addr.is_none() && ip_stack != IPV4_STACK {
        info!(
            "Defaulting external v6 address to interface address ({})",
            show_ip(iface_v6_addr)
        );
        ext_v6_addr = iface_v6_addr;
    }

    Ok(ExternalInterface {
        iface_index: i.index,
        iface_name: i.name.clone(),
        iface_addr,
        iface_v6_addr,
        ext_addr,
        ext_v6_addr,
    })
}

#[cfg(test)]
mod tests;
