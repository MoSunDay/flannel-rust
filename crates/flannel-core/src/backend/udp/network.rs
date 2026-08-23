//! Port of udp_network_amd64.go + cproxy_amd64.go (upstream cdf76059):
//! the udp backend's network struct (`newNetwork`, `initTun`,
//! `configureIface`, `Run`, `processSubnetEvents`) and the ctl command
//! writers (`setRoute`, `removeRoute`, `stopProxy`).

use super::proxy::{run_proxy, Command, CMD_DEL_ROUTE, CMD_SET_ROUTE, CMD_STOP};
use crate::backend::common::ExternalInterface;
use crate::backend::traits::Network;
use crate::ip::iface::{get_interface_by_name, get_link_mtu, Netlink};
use crate::ip::tun::open_tun;
use crate::ip::{IP4Net, IP4};
use crate::lease::{Event, EventType, Lease};
use crate::subnet::manager::{Ctx, Manager};
use crate::subnet::watch::watch_leases;
use anyhow::{anyhow, bail};
use futures::future::BoxFuture;
use netlink_packet_route::route::RouteScope;
use rtnetlink::{LinkUnspec, RouteMessageBuilder};
use std::net::{IpAddr, Ipv4Addr};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tracing::{error, info};

/// Go `encapOverhead`: 20 bytes IP hdr + 8 bytes UDP hdr.
const ENCAP_OVERHEAD: u32 = 28;
/// Go `initTun` opens the tun with this name pattern.
const TUN_DEVICE_PATTERN: &str = "flannel%d";

/// Go `network` (SimpleNetwork fields inlined).
pub struct UdpNetwork {
    sm: Arc<dyn Manager>,
    #[allow(dead_code)] // Go keeps ExtIface on SimpleNetwork; kept for parity.
    ei: Arc<ExternalInterface>,
    lease: Lease,
    port: i32,
    tun_net: IP4Net,
    mtu: u32,
    tun: OwnedFd,
    conn: std::net::UdpSocket,
    ctl: OwnedFd,
    /// Moved into the proxy thread by `run` (Go passes n.ctl2 to the
    /// goroutine). Mutex because `Network::run` only has `&self`.
    ctl2: Mutex<Option<OwnedFd>>,
}

impl Network for UdpNetwork {
    fn lease(&self) -> &Lease {
        &self.lease
    }

    /// Go: `SimpleNetwork.MTU() = ExtIface.Iface.MTU - encapOverhead`,
    /// resolved against the external link MTU at construction time.
    fn mtu(&self) -> u32 {
        self.mtu
    }

    /// Go: `Run`. Spawns the blocking C proxy on an OS thread, then
    /// processes subnet lease events until the watch ends, at which
    /// point CMD_STOP is sent to the proxy.
    fn run<'a>(&'a self, ctx: Ctx<'a>) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            // Go: conn.File() dup()s the socket; do the same for tun and
            // the UDP socket so the originals stay owned by the network
            // and are closed only when Run returns (Go defers).
            let Some(ctl2) = self.ctl2.lock().unwrap().take() else {
                error!("udp network already ran, proxy control socket gone");
                return;
            };
            let Ok(tun2) = dup_fd(&self.tun) else {
                error!("Converting tun to File failed");
                return;
            };
            let Ok(sock2) = dup_fd(&self.conn) else {
                error!("Converting UDPConn to File failed");
                return;
            };

            let tun_ip = self.tun_net.ip.network_order();
            let tun_mtu = self.mtu as usize;

            std::thread::spawn(move || {
                run_proxy(tun2, sock2, ctl2, tun_ip, tun_mtu);
            });

            info!("Watching for new subnet leases");
            let (ev_tx, mut ev_rx) = mpsc::channel::<Vec<Event>>(1);
            let watch = watch_leases(ctx, &*self.sm, &self.lease, ev_tx);
            tokio::pin!(watch);

            loop {
                tokio::select! {
                    biased;
                    batch = ev_rx.recv() => match batch {
                        Some(batch) => self.process_subnet_events(&batch),
                        // Go: evts chan closed -> stopProxy(n.ctl) + defers.
                        None => {
                            info!("evts chan closed");
                            self.stop_proxy();
                            return;
                        }
                    },
                    _ = &mut watch => {
                        // Go's WatchLeases returns only on ctx cancel; the
                        // evts channel then closes and the branch above
                        // fires. Stop the proxy in either case.
                        self.stop_proxy();
                        return;
                    }
                }
            }
        })
    }
}

impl UdpNetwork {
    /// Go: `processSubnetEvents`.
    fn process_subnet_events(&self, batch: &[Event]) {
        for evt in batch {
            match evt.event_type {
                EventType::Added => {
                    info!("Subnet added: {}", evt.lease.subnet);
                    self.set_route(evt.lease.subnet, evt.lease.attrs.public_ip);
                }
                EventType::Removed => {
                    info!("Subnet removed: {}", evt.lease.subnet);
                    self.remove_route(evt.lease.subnet);
                } // Go logs "unknown event type"; Rust's enum is exhaustive.
            }
        }
    }

    /// Go `setRoute`: next hop is the lease's public IP plus our own
    /// UDP port (the peer listens on the same port we do).
    fn set_route(&self, dst: IP4Net, next_hop_ip: IP4) {
        let cmd = Command {
            cmd: CMD_SET_ROUTE,
            dest_net: dst.ip.network_order(),
            dest_net_len: dst.prefix_len as i32,
            next_hop_ip: next_hop_ip.network_order(),
            next_hop_port: self.port as i16,
        };
        self.write_command(&cmd);
    }

    /// Go `removeRoute`.
    fn remove_route(&self, dst: IP4Net) {
        let cmd = Command {
            cmd: CMD_DEL_ROUTE,
            dest_net: dst.ip.network_order(),
            dest_net_len: dst.prefix_len as i32,
            next_hop_ip: 0,
            next_hop_port: 0,
        };
        self.write_command(&cmd);
    }

    /// Go `stopProxy`.
    fn stop_proxy(&self) {
        self.write_command(&Command {
            cmd: CMD_STOP,
            dest_net: 0,
            dest_net_len: 0,
            next_hop_ip: 0,
            next_hop_port: 0,
        });
    }

    /// Go `writeCommand`: SEQPACKET keeps the 20-byte command atomic.
    fn write_command(&self, cmd: &Command) {
        let bytes = cmd.to_bytes();
        let n = unsafe { libc::write(self.ctl.as_raw_fd(), bytes.as_ptr().cast(), bytes.len()) };
        if n < 0 || n as usize != bytes.len() {
            error!(
                "Error while writing the command {cmd:?}. Error: {}",
                std::io::Error::last_os_error()
            );
        }
    }
}

/// Port of Go `newNetwork`: open + configure the tun, bind the UDP
/// socket to the external interface address, create the ctl socketpair.
pub(super) async fn new_network(
    sm: Arc<dyn Manager>,
    ei: Arc<ExternalInterface>,
    port: i32,
    tun_net: IP4Net,
    lease: Lease,
) -> anyhow::Result<UdpNetwork> {
    let nl = Netlink::new().await?;

    // Go reads ExtIface.Iface.MTU (captured at startup); the Rust port
    // resolves the external link MTU here instead.
    let mtu = get_link_mtu(&nl, ei.iface_index)
        .await?
        .saturating_sub(ENCAP_OVERHEAD);

    // Go: n.initTun() -- OpenTun then configureIface(name, tunNet, MTU()).
    let (tun, tun_name) =
        open_tun(TUN_DEVICE_PATTERN).map_err(|e| anyhow!("failed to open TUN device: {e}"))?;
    configure_iface(&nl, &tun_name, tun_net, mtu).await?;

    // Go: net.ListenUDP("udp4", &net.UDPAddr{IP: extIface.IfaceAddr, Port: port}).
    let bind_ip = match ei.iface_addr {
        Some(IpAddr::V4(v4)) => v4,
        _ => bail!("failed to start listening on UDP socket: no IPv4 interface address"),
    };
    let conn = std::net::UdpSocket::bind((bind_ip, port as u16))
        .map_err(|e| anyhow!("failed to start listening on UDP socket: {e}"))?;

    // Go: newCtlSockets() = socketpair(AF_UNIX, SOCK_SEQPACKET, 0).
    let (ctl, ctl2) = nix::sys::socket::socketpair(
        nix::sys::socket::AddressFamily::Unix,
        nix::sys::socket::SockType::SeqPacket,
        None,
        nix::sys::socket::SockFlag::empty(),
    )
    .map_err(|e| anyhow!("failed to create control socket: {e}"))?;

    Ok(UdpNetwork {
        sm,
        ei,
        lease,
        port,
        tun_net,
        mtu,
        tun,
        conn,
        ctl,
        ctl2: Mutex::new(Some(ctl2)),
    })
}

/// Go `configureIface`: /32 address on the tun (so no broadcast routes
/// are created), MTU, UP, and an explicit universe-scope route for the
/// whole flannel network (Docker may already hold the subnet route, so
/// EEXIST is tolerated).
async fn configure_iface(nl: &Netlink, ifname: &str, ipn: IP4Net, mtu: u32) -> anyhow::Result<()> {
    let iface = get_interface_by_name(nl, ifname)
        .await
        .map_err(|_| anyhow!("failed to lookup interface {ifname}"))?;

    let ipn_local = IP4Net::new(ipn.ip, 32);
    if let Err(e) = nl
        .handle
        .address()
        .add(iface.index, IpAddr::V4(ipn_local.ip.to_std()), 32)
        .execute()
        .await
    {
        bail!("failed to add IP address {ipn_local} to {ifname}: {e}");
    }

    let set = LinkUnspec::new_with_index(iface.index).mtu(mtu).build();
    if let Err(e) = nl.handle.link().set(set).execute().await {
        bail!("failed to set MTU for {ifname}: {e}");
    }

    let up = LinkUnspec::new_with_index(iface.index).up().build();
    if let Err(e) = nl.handle.link().set(up).execute().await {
        bail!("failed to set interface {ifname} to UP state: {e}");
    }

    // Explicitly add the route since one for the subnet may already be
    // installed by Docker and then it won't get auto added.
    let net = ipn.network();
    let route = RouteMessageBuilder::<Ipv4Addr>::new()
        .destination_prefix(net.ip.to_std(), net.prefix_len as u8)
        .output_interface(iface.index)
        .scope(RouteScope::Universe)
        .build();
    if let Err(e) = nl.handle.route().add(route).execute().await {
        if !is_eexist(&e) {
            bail!("failed to add route ({net} -> {ifname}): {e}");
        }
    }
    Ok(())
}

/// True when a netlink op failed because the object already exists.
fn is_eexist(e: &rtnetlink::Error) -> bool {
    matches!(e, rtnetlink::Error::NetlinkError(msg)
        if msg.code.is_some_and(|c| c.get() == -libc::EEXIST))
}

/// Go's `conn.File()` / passing `n.tun` dup()s the fd; replicate that.
fn dup_fd<F: AsFd>(fd: &F) -> anyhow::Result<OwnedFd> {
    let raw = unsafe { libc::dup(fd.as_fd().as_raw_fd()) };
    if raw < 0 {
        bail!("dup failed: {}", std::io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}
