//! Port of pkg/backend/wireguard/device.go (upstream cdf76059):
//! wireguard device creation/configuration, keys, routes and peers,
//! plus the wgctrl read path (`Client.Device` -> [`get_device`]) over
//! `genl::dump_device`. Go deviation: `ensureLink` re-looks-up the
//! created device by *name* (rtnetlink has no RTM_NEWLINK echo index).

use super::genl::{
    configure_device, dump_device, parse_endpoint, parse_nlas, u16_of, u32_of, WgAllowedIp,
    WgDeviceConfig, WgPeerConfig, WGALLOWEDIP_A_CIDR_MASK, WGALLOWEDIP_A_FAMILY,
    WGALLOWEDIP_A_IPADDR, WGDEVICE_A_IFINDEX, WGDEVICE_A_LISTEN_PORT, WGDEVICE_A_PEERS,
    WGDEVICE_F_REPLACE_PEERS, WGPEER_A_ALLOWEDIPS, WGPEER_A_ENDPOINT,
    WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL, WGPEER_A_PUBLIC_KEY, WGPEER_F_REMOVE_ME,
    WGPEER_F_REPLACE_ALLOWEDIPS,
};
use super::keys::{self, Key};
use crate::ip::iface::{
    ensure_v4_address_on_link, ensure_v6_address_on_link, get_interface_by_name, Netlink,
};
use crate::ip::{IP4Net, IP6Net, IP4, IP6};
use crate::subnet::Ctx;
use anyhow::anyhow;
use netlink_packet_route::route::{RouteMessage, RouteScope};
use rtnetlink::{Error as RtError, LinkUnspec, LinkWireguard, RouteMessageBuilder};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::time::Duration;
use tokio::task;
use tracing::{error, info, warn};

/// Peer state read back from the kernel (Go: `wgtypes.Peer`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WgPeerInfo {
    pub public_key: [u8; 32],
    pub endpoint: Option<SocketAddr>,
    pub persistent_keepalive_interval: u16,
    pub allowed_ips: Vec<WgAllowedIp>,
}
/// Device state read back from the kernel (subset the backend needs).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WgDeviceInfo {
    pub ifindex: u32,
    pub listen_port: u16,
    pub peers: Vec<WgPeerInfo>,
}
/// Go: `wgctrl.Client.Device` over [`dump_device`].
#[allow(dead_code)] // read path, exercised by genl_tests
pub fn get_device(ifname: &str) -> std::io::Result<WgDeviceInfo> {
    // Go's wgctrl translates ENODEV to os.ErrNotExist; surface it as an
    // empty dump so the caller reports NotFound (like Go).
    let msgs = match dump_device(ifname) {
        Err(e) if e.raw_os_error() == Some(libc::ENODEV) => Vec::new(),
        other => other?,
    };
    let Some(msg) = msgs.first() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("no wireguard device {ifname}"),
        ));
    };
    let mut info = WgDeviceInfo::default();
    for (t, v) in parse_nlas(&msg[4..]) {
        match t {
            WGDEVICE_A_IFINDEX => info.ifindex = u32_of(&v).unwrap_or(0),
            WGDEVICE_A_LISTEN_PORT => info.listen_port = u16_of(&v).unwrap_or(0),
            // every nested entry (its type is just an index) is one peer
            WGDEVICE_A_PEERS => info
                .peers
                .extend(parse_nlas(&v).iter().map(|(_, pv)| parse_peer(pv))),
            _ => {}
        }
    }
    Ok(info)
}
fn parse_peer(body: &[u8]) -> WgPeerInfo {
    let mut peer = WgPeerInfo::default();
    for (t, v) in parse_nlas(body) {
        match t {
            WGPEER_A_PUBLIC_KEY if v.len() >= 32 => peer.public_key.copy_from_slice(&v[0..32]),
            WGPEER_A_ENDPOINT => peer.endpoint = parse_endpoint(&v),
            WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL => {
                peer.persistent_keepalive_interval = u16_of(&v).unwrap_or(0);
            }
            WGPEER_A_ALLOWEDIPS => {
                let nlas = parse_nlas(&v);
                peer.allowed_ips
                    .extend(nlas.iter().filter_map(|(_, av)| parse_allowed_ip(av)));
            }
            _ => {}
        }
    }
    peer
}
fn parse_allowed_ip(body: &[u8]) -> Option<WgAllowedIp> {
    let (mut family, mut addr, mut cidr) = (0u16, None, 0u8);
    for (t, v) in parse_nlas(body) {
        match t {
            WGALLOWEDIP_A_FAMILY => family = u16_of(&v).unwrap_or(0),
            WGALLOWEDIP_A_IPADDR => addr = Some(v),
            WGALLOWEDIP_A_CIDR_MASK if !v.is_empty() => cidr = v[0],
            _ => {}
        }
    }
    let addr = addr?;
    let ip = if family == libc::AF_INET as u16 && addr.len() >= 4 {
        IpAddr::V4(Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]))
    } else if family == libc::AF_INET6 as u16 && addr.len() >= 16 {
        IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&addr[0..16]).ok()?))
    } else {
        return None;
    };
    Some(WgAllowedIp { ip, cidr })
}
/// Device creation attributes (Go: `wgDeviceAttrs`).
#[derive(Clone, Debug)]
pub struct WGDeviceAttrs {
    pub listen_port: u16,
    pub private_key: Option<Key>,
    pub public_key: Option<Key>,
    pub psk: Option<Key>,
    pub keepalive: Option<Duration>,
    pub name: String,
    pub mtu: u32,
}
/// The created wireguard device (Go: `wgDevice`; the link identity is
/// `ifindex`/`ifname` instead of Go's `*netlink.GenericLink`).
#[derive(Clone, Debug)]
pub struct WGDevice {
    pub attrs: WGDeviceAttrs,
    pub ifindex: u32,
    pub ifname: String,
}

/// Go: `writePrivateKey` (MkdirAll dir 0755, chmod the file 0400).
fn write_private_key(path: &str, content: &str) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::path::Path::new(path)
        .parent()
        .unwrap_or(std::path::Path::new(""));
    if !dir.as_os_str().is_empty() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(path, content)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400))?;
    Ok(())
}
/// Go: `(*wgDeviceAttrs).setupKeys`: load or generate the node key
/// pair (file: $WIREGUARD_KEY_FILE or /run/flannel/wgkey) and parse
/// the optional preshared key.
pub fn setup_keys(attrs: &mut WGDeviceAttrs, psk: &str) -> anyhow::Result<()> {
    let key_file =
        std::env::var("WIREGUARD_KEY_FILE").unwrap_or_else(|_| "/run/flannel/wgkey".to_string());
    if !std::path::Path::new(&key_file).exists() {
        let private_key = keys::Key::generate_private_key()
            .map_err(|e| anyhow!("could not generate private key: {e}"))?;
        let public_key = private_key.public_key();
        write_private_key(&key_file, &private_key.to_string())
            .map_err(|e| anyhow!("could not write key file: {e}"))?;
        attrs.private_key = Some(private_key);
        attrs.public_key = Some(public_key);
    } else {
        let data = std::fs::read_to_string(&key_file)?;
        let private_key = keys::Key::parse(&data)
            .map_err(|e| anyhow!("could not parse private key from file: {e}"))?;
        attrs.public_key = Some(private_key.public_key());
        attrs.private_key = Some(private_key);
    }
    if !psk.is_empty() {
        let psk = keys::Key::parse(psk).map_err(|e| anyhow!("could not parse psk: {e}"))?;
        attrs.psk = Some(psk);
    }
    Ok(())
}
/// Go: `newWGDevice`: create (or recreate) the wireguard link, apply
/// the initial device configuration and spawn the removal task that
/// runs on context cancellation.
pub async fn new_wg_device(
    nl: &Netlink,
    attrs: &WGDeviceAttrs,
    ctx: Ctx<'_>,
) -> anyhow::Result<WGDevice> {
    let ifindex = ensure_link(nl, attrs).await?;
    let dev = WGDevice {
        attrs: attrs.clone(),
        ifindex,
        ifname: attrs.name.clone(),
    };
    // Go: wgtypes.Config{PrivateKey, ListenPort, ReplacePeers: true}.
    let cfg = WgDeviceConfig {
        ifname: attrs.name.clone(),
        private_key: attrs.private_key.as_ref().map(|k| k.0),
        listen_port: Some(attrs.listen_port),
        flags: WGDEVICE_F_REPLACE_PEERS,
        peers: Vec::new(),
    };
    task::spawn_blocking(move || configure_device(&cfg))
        .await
        .map_err(|e| anyhow!("failed to configure device: {e}"))?
        .map_err(|e| anyhow!("failed to configure device {e}"))?;
    // Go: remove the device when the context is cancelled, undoing any
    // change made to the system. Runs until flannel terminates.
    let token = ctx.clone();
    let cleanup_nl = nl.clone();
    let name = attrs.name.clone();
    tokio::spawn(async move {
        token.cancelled().await;
        if let Err(e) = cleanup_nl.handle.link().del(ifindex).execute().await {
            error!("Error while removing device: {e}");
        }
        info!("Removed wireguard device {name}");
    });
    Ok(dev)
}
/// Go: `ensureLink` -- add the link; on EEXIST delete the existing one
/// and recreate it. Returns the ifindex of the resulting device.
async fn ensure_link(nl: &Netlink, attrs: &WGDeviceAttrs) -> anyhow::Result<u32> {
    let msg = build_link(attrs);
    match nl.handle.link().add(msg.clone()).execute().await {
        Ok(()) => {}
        Err(e) if is_eexist(&e) => {
            let existing = get_interface_by_name(nl, &attrs.name).await?;
            warn!("\"{}\" already exists; recreating device", attrs.name);
            nl.handle
                .link()
                .del(existing.index)
                .execute()
                .await
                .map_err(|e| anyhow!("{e}"))?;
            if let Err(e) = nl.handle.link().add(msg).execute().await {
                return Err(anyhow!("could not create wireguard interface: {e}"));
            }
        }
        Err(e) => return Err(anyhow!("could not create wireguard interface: {e}")),
    }
    // Go verifies with LinkByIndex(echo index); rtnetlink has no echo
    // index, so the name lookup doubles as the verification.
    get_interface_by_name(nl, &attrs.name)
        .await
        .map_err(|e| {
            anyhow!(
                "can't locate created wireguard device with index ({}): {e}",
                attrs.name
            )
        })
        .map(|iface| iface.index)
}
fn build_link(attrs: &WGDeviceAttrs) -> netlink_packet_route::link::LinkMessage {
    let mut b = LinkWireguard::new(&attrs.name);
    // Go: LinkAttrs.MTU = MTU - overhead.
    let mtu = attrs.mtu as i64 - super::OVERHEAD as i64;
    if mtu > 0 {
        b = b.mtu(mtu as u32);
    }
    b.build()
}
/// True when a netlink request was rejected with EEXIST.
fn is_eexist(err: &RtError) -> bool {
    matches!(err,
        RtError::NetlinkError(msg)
            if msg.code.is_some_and(|c| c.get() == -libc::EEXIST))
}
/// Go: `Configure`: ensure the v4 address, set the link UP and add the
/// route for the whole flannel network.
pub async fn configure(
    nl: &Netlink,
    dev: &WGDevice,
    dev_ip: IP4,
    flannelnet: IP4Net,
) -> anyhow::Result<()> {
    let ipa = IP4Net {
        ip: dev_ip,
        prefix_len: 32,
    };
    ensure_v4_address_on_link(nl, ipa, flannelnet, dev.ifindex)
        .await
        .map_err(|e| anyhow!("failed to ensure address of interface {}: {e}", dev.ifname))?;
    let msg = RouteMessageBuilder::<Ipv4Addr>::new()
        .destination_prefix(flannelnet.ip.to_std(), flannelnet.prefix_len as u8)
        .output_interface(dev.ifindex)
        .scope(RouteScope::Link)
        .build();
    up_and_add_route(nl, dev, msg, flannelnet)
        .await
        .map_err(|e| anyhow!("failed to set up the route: {e}"))
}
/// Go: `ConfigureV6`.
pub async fn configure_v6(
    nl: &Netlink,
    dev: &WGDevice,
    dev_ip: IP6,
    flannelnet: IP6Net,
) -> anyhow::Result<()> {
    let ipn = IP6Net {
        ip: dev_ip,
        prefix_len: 128,
    };
    ensure_v6_address_on_link(nl, ipn, flannelnet, dev.ifindex)
        .await
        .map_err(|e| anyhow!("failed to ensure address of interface {}: {e}", dev.ifname))?;
    let msg = RouteMessageBuilder::<Ipv6Addr>::new()
        .destination_prefix(flannelnet.ip.to_std(), flannelnet.prefix_len as u8)
        .output_interface(dev.ifindex)
        .scope(RouteScope::Link)
        .build();
    up_and_add_route(nl, dev, msg, flannelnet)
        .await
        .map_err(|e| anyhow!("failed to set up the route: {e}"))
}
/// Go: `upAndAddRoute` (double-wrapped error, like Go).
pub(crate) async fn up_and_add_route(
    nl: &Netlink,
    dev: &WGDevice,
    msg: RouteMessage,
    dst: impl std::fmt::Display,
) -> anyhow::Result<()> {
    set_link_up(nl, dev).await?;
    let name = &dev.ifname;
    add_route(nl, dev, msg).await.map_err(|e| {
        anyhow!("failed to add route to destination ({dst}) to interface ({name}): {e}")
    })
}
/// Go: `addRoute` (SCOPE_LINK, RouteReplace; Go's error message prints
/// the device *name*, not the destination).
async fn add_route(nl: &Netlink, dev: &WGDevice, msg: RouteMessage) -> anyhow::Result<()> {
    nl.handle
        .route()
        .add(msg)
        .replace()
        .execute()
        .await
        .map_err(|e| anyhow!("failed to add route {}: {e}", dev.ifname))
}
async fn set_link_up(nl: &Netlink, dev: &WGDevice) -> anyhow::Result<()> {
    nl.handle
        .link()
        .set(LinkUnspec::new_with_index(dev.ifindex).up().build())
        .execute()
        .await
        .map_err(|e| anyhow!("failed to set interface {} to UP state: {e}", dev.ifname))
}
/// Go: `addPeer`: resolve the UDP endpoint, parse the peer key and
/// push one peer (ReplaceAllowedIPs) with the device's PSK/keepalive.
pub async fn add_peer(
    dev: &WGDevice,
    public_endpoint: &str,
    peer_public_key_raw: &str,
    peer_subnets: Vec<WgAllowedIp>,
) -> anyhow::Result<()> {
    let endpoint = resolve_udp_addr(public_endpoint)?;
    let peer_public_key = keys::Key::parse(peer_public_key_raw)
        .map_err(|e| anyhow!("failed to parse publicKey: {e}"))?;
    let cfg = WgDeviceConfig {
        ifname: dev.ifname.clone(),
        private_key: dev.attrs.private_key.as_ref().map(|k| k.0),
        listen_port: Some(dev.attrs.listen_port),
        flags: 0,
        peers: vec![WgPeerConfig {
            public_key: peer_public_key.0,
            preshared_key: dev.attrs.psk.as_ref().map(|k| k.0),
            flags: WGPEER_F_REPLACE_ALLOWEDIPS,
            endpoint: Some(endpoint),
            persistent_keepalive_interval: dev.attrs.keepalive.map(|d| d.as_secs() as u16),
            allowed_ips: peer_subnets,
        }],
    };
    task::spawn_blocking(move || configure_device(&cfg))
        .await
        .map_err(|e| anyhow!("failed to configure device: {e}"))?
        .map_err(|e| anyhow!("failed to configure device {e}"))
}
/// Go: `net.ResolveUDPAddr("udp", ...)` (requires host:port form).
fn resolve_udp_addr(s: &str) -> anyhow::Result<SocketAddr> {
    let mut addrs = s
        .to_socket_addrs()
        .map_err(|e| anyhow!("failed to resolve UDP address: {e}"))?;
    addrs
        .next()
        .ok_or_else(|| anyhow!("failed to resolve UDP address"))
}
/// Go: `removePeer` (WGPEER_F_REMOVE_ME).
pub async fn remove_peer(dev: &WGDevice, peer_public_key_raw: &str) -> anyhow::Result<()> {
    let peer_public_key = keys::Key::parse(peer_public_key_raw)
        .map_err(|e| anyhow!("failed to parse publicKey: {e}"))?;
    let cfg = WgDeviceConfig {
        ifname: dev.ifname.clone(),
        private_key: None,
        listen_port: None,
        flags: 0,
        peers: vec![WgPeerConfig {
            public_key: peer_public_key.0,
            preshared_key: None,
            flags: WGPEER_F_REMOVE_ME,
            endpoint: None,
            persistent_keepalive_interval: None,
            allowed_ips: Vec::new(),
        }],
    };
    task::spawn_blocking(move || configure_device(&cfg))
        .await
        .map_err(|e| anyhow!("failed to remove peer: {e}"))?
        .map_err(|e| anyhow!("failed to remove peer {e}"))
}
