//! Port of proxy_amd64.c + proxy_amd64.h (upstream cdf76059): the
//! blocking userspace packet proxy (`run_proxy`) with its route table
//! and ctl commands.
//!
//! Go/C deviations:
//! - C keeps routes, tun_addr, exit_flag and log_enabled in file-scope
//!   globals; the Rust port keeps them in locals passed around, so one
//!   proxy instance per thread instead of per process.
//! - C `exit(1)` on poll failure becomes a logged return.
//! - C gates its logging on `log_errors` (klog V(1)); the Rust port
//!   uses tracing levels (error/warn/debug) unconditionally.
//! - C `recv(ctl)` returning 0 (peer closed) would leave poll() firing
//!   forever; the Rust port treats a zero-length read as CMD_STOP.

use super::proxy_packet::{decrement_ttl, inaddr_str, send_net_unreachable, IPHDR_LEN};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use tracing::{debug, error, warn};

/// Go/C `CMD_SET_ROUTE` (proxy_amd64.h).
pub const CMD_SET_ROUTE: i32 = 1;
/// Go/C `CMD_DEL_ROUTE`.
pub const CMD_DEL_ROUTE: i32 = 2;
/// Go/C `CMD_STOP`.
pub const CMD_STOP: i32 = 3;

/// Size of the C `command` struct on amd64 (18 bytes of fields plus 2
/// bytes of trailing padding).
pub const COMMAND_SIZE: usize = 20;

/// Go `command` (proxy_amd64.h). All addresses are network-order, like
/// C `in_addr_t`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Command {
    pub cmd: i32,
    pub dest_net: u32,
    pub dest_net_len: i32,
    pub next_hop_ip: u32,
    pub next_hop_port: i16,
}

impl Command {
    /// Bytes exactly as the C struct is laid out on amd64 (little
    /// endian, 2 padding bytes at the end).
    pub fn to_bytes(self) -> [u8; COMMAND_SIZE] {
        let mut b = [0u8; COMMAND_SIZE];
        b[0..4].copy_from_slice(&self.cmd.to_le_bytes());
        b[4..8].copy_from_slice(&self.dest_net.to_le_bytes());
        b[8..12].copy_from_slice(&self.dest_net_len.to_le_bytes());
        b[12..16].copy_from_slice(&self.next_hop_ip.to_le_bytes());
        b[16..18].copy_from_slice(&self.next_hop_port.to_le_bytes());
        b // b[18..20] stays zero (struct padding)
    }

    pub fn from_bytes(b: &[u8; COMMAND_SIZE]) -> Self {
        Self {
            cmd: i32::from_le_bytes(b[0..4].try_into().unwrap()),
            dest_net: u32::from_le_bytes(b[4..8].try_into().unwrap()),
            dest_net_len: i32::from_le_bytes(b[8..12].try_into().unwrap()),
            next_hop_ip: u32::from_le_bytes(b[12..16].try_into().unwrap()),
            next_hop_port: i16::from_le_bytes(b[16..18].try_into().unwrap()),
        }
    }
}

/// Go `struct ip_net`: a destination network as network-order address
/// plus network-order mask.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(super) struct IpNet {
    pub(super) ip: u32,
    pub(super) mask: u32,
}

/// Go `struct route_entry` (sockaddr_in flattened to ip + host-order
/// port).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(super) struct RouteEntry {
    pub(super) dst: IpNet,
    pub(super) next_hop_ip: u32,
    pub(super) next_hop_port: u16,
}

/// Go: the file-scope `routes` array with `set_route` / `del_route` /
/// `find_route`. `find_route` swaps a hit to the front because packets
/// for the same destination tend to come in bursts.
#[derive(Default)]
pub(super) struct RouteTable {
    pub(super) entries: Vec<RouteEntry>,
}

impl RouteTable {
    pub(super) fn set_route(&mut self, dst: IpNet, next_hop_ip: u32, next_hop_port: u16) {
        if let Some(e) = self.entries.iter_mut().find(|e| e.dst == dst) {
            e.next_hop_ip = next_hop_ip;
            e.next_hop_port = next_hop_port;
            return;
        }
        self.entries.push(RouteEntry {
            dst,
            next_hop_ip,
            next_hop_port,
        });
    }

    /// Go `del_route` swaps the last entry into the deleted slot; the
    /// Rust port keeps order via swap_remove, which does the same.
    pub(super) fn del_route(&mut self, dst: IpNet) -> bool {
        match self.entries.iter().position(|e| e.dst == dst) {
            Some(i) => {
                self.entries.swap_remove(i);
                true
            }
            None => false,
        }
    }

    pub(super) fn find_route(&mut self, dst_ip: u32) -> Option<(u32, u16)> {
        let i = self
            .entries
            .iter()
            .position(|e| e.dst.ip == (dst_ip & e.dst.mask))?;
        if i != 0 {
            self.entries.swap(0, i);
        }
        let e = &self.entries[0];
        Some((e.next_hop_ip, e.next_hop_port))
    }
}

/// Go `netmask`: `htonl(~0 << (32 - prefix_len))`, clamped to /0../32
/// (Go only ever sends real prefix lengths).
pub(super) fn netmask(prefix_len: i32) -> u32 {
    let bits = prefix_len.clamp(0, 32) as u32;
    if bits == 0 {
        0
    } else {
        (u32::MAX << (32 - bits)).to_be()
    }
}

/// Go `tun_recv_packet`: read one packet from the tun. None on error
/// or short reads (logged like C, except EAGAIN/EWOULDBLOCK).
fn tun_recv_packet(tun: RawFd, buf: &mut [u8]) -> Option<usize> {
    let nread = unsafe { libc::read(tun, buf.as_mut_ptr().cast(), buf.len()) };
    if nread < 0 {
        let e = std::io::Error::last_os_error();
        if !matches!(e.raw_os_error(), Some(libc::EAGAIN)) {
            // (C also checks EWOULDBLOCK, which equals EAGAIN on Linux.)
            error!("TUN recv failed: {e}");
        }
        return None;
    }
    let nread = nread as usize;
    if nread < IPHDR_LEN {
        error!("TUN recv packet too small: {nread} bytes");
        return None;
    }
    Some(nread)
}

/// Go `sock_recv_packet`: non-blocking recv on the UDP socket.
fn sock_recv_packet(sock: RawFd, buf: &mut [u8]) -> Option<usize> {
    let nread = unsafe { libc::recv(sock, buf.as_mut_ptr().cast(), buf.len(), libc::MSG_DONTWAIT) };
    if nread < 0 {
        let e = std::io::Error::last_os_error();
        if !matches!(e.raw_os_error(), Some(libc::EAGAIN)) {
            // (C also checks EWOULDBLOCK, which equals EAGAIN on Linux.)
            error!("UDP recv failed: {e}");
        }
        return None;
    }
    let nread = nread as usize;
    if nread < IPHDR_LEN {
        error!("UDP recv packet too small: {nread} bytes");
        return None;
    }
    Some(nread)
}

/// Go `sock_send_packet`: sendto the next hop.
fn sock_send_packet(sock: RawFd, pkt: &[u8], dst_ip: u32, dst_port: u16) {
    let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    sa.sin_family = libc::AF_INET as libc::sa_family_t;
    sa.sin_port = dst_port.to_be();
    sa.sin_addr.s_addr = dst_ip; // already network order
    let nsent = unsafe {
        libc::sendto(
            sock,
            pkt.as_ptr().cast(),
            pkt.len(),
            0,
            std::ptr::addr_of!(sa).cast(),
            std::mem::size_of::<libc::sockaddr_in>() as u32,
        )
    };
    if nsent != pkt.len() as isize {
        let dst = format!("{}:{dst_port}", inaddr_str(dst_ip));
        if nsent < 0 {
            error!(
                "UDP send to {dst} failed: {}",
                std::io::Error::last_os_error()
            );
        } else {
            error!(
                "Was only able to send {nsent} out of {} bytes to {dst}",
                pkt.len()
            );
        }
    }
}

/// Go `tun_send_packet`: write to the tun, retrying on EAGAIN.
fn tun_send_packet(tun: RawFd, pkt: &[u8]) {
    loop {
        let nsent = unsafe { libc::write(tun, pkt.as_ptr().cast(), pkt.len()) };
        if nsent == pkt.len() as isize {
            return;
        }
        if nsent < 0 {
            let e = std::io::Error::last_os_error();
            if matches!(e.raw_os_error(), Some(libc::EAGAIN)) {
                // (C also checks EWOULDBLOCK, which equals EAGAIN on Linux.)
                continue; // C: goto _retry
            }
            error!("TUN send failed: {e}");
        } else {
            error!(
                "Was only able to send {nsent} out of {} bytes to TUN",
                pkt.len()
            );
        }
        return;
    }
}

/// Go `tun_to_udp`: one tun->UDP forwarding step. True when work was
/// done (C returns "activity" so the loop can bypass poll()).
fn tun_to_udp(
    tun: RawFd,
    sock: RawFd,
    buf: &mut [u8],
    tun_ip: u32,
    routes: &mut RouteTable,
) -> bool {
    let Some(pktlen) = tun_recv_packet(tun, buf) else {
        return false;
    };
    let daddr = u32::from_ne_bytes(buf[16..20].try_into().unwrap());
    match routes.find_route(daddr) {
        None => send_net_unreachable(tun, &buf[..pktlen], tun_ip),
        Some((hop_ip, hop_port)) => {
            if !decrement_ttl(&mut buf[..pktlen]) {
                // TTL went to 0, discard. TODO: send back ICMP Time
                // Exceeded (upstream TODO).
                return true;
            }
            sock_send_packet(sock, &buf[..pktlen], hop_ip, hop_port);
        }
    }
    true
}

/// Go `udp_to_tun`: one UDP->tun forwarding step.
fn udp_to_tun(sock: RawFd, tun: RawFd, buf: &mut [u8]) -> bool {
    let Some(pktlen) = sock_recv_packet(sock, buf) else {
        return false;
    };
    if !decrement_ttl(&mut buf[..pktlen]) {
        return true; // TTL went to 0, discard (upstream TODO as above).
    }
    tun_send_packet(tun, &buf[..pktlen]);
    true
}

/// Go `process_cmd`: read one command from the ctl socket and apply it
/// to the route table (or set the exit flag).
pub(super) fn process_cmd(ctl: RawFd, routes: &mut RouteTable, exit_flag: &mut bool) {
    let mut bytes = [0u8; COMMAND_SIZE];
    let nrecv = unsafe { libc::recv(ctl, bytes.as_mut_ptr().cast(), bytes.len(), 0) };
    if nrecv < 0 {
        error!("CTL recv failed: {}", std::io::Error::last_os_error());
        return;
    }
    if nrecv == 0 {
        // Peer closed; C would busy-poll here. Treat as CMD_STOP.
        *exit_flag = true;
        return;
    }
    if (nrecv as usize) < COMMAND_SIZE {
        warn!("CTL recv short command: {nrecv} bytes");
        return;
    }
    let cmd = Command::from_bytes(&bytes);
    match cmd.cmd {
        CMD_SET_ROUTE => {
            let mask = netmask(cmd.dest_net_len);
            routes.set_route(
                IpNet {
                    ip: cmd.dest_net & mask,
                    mask,
                },
                cmd.next_hop_ip,
                cmd.next_hop_port as u16,
            );
        }
        CMD_DEL_ROUTE => {
            let mask = netmask(cmd.dest_net_len);
            routes.del_route(IpNet {
                ip: cmd.dest_net & mask,
                mask,
            });
        }
        CMD_STOP => *exit_flag = true,
        other => warn!("CTL unknown command: {other}"),
    }
}

/// Go/C poll() slots.
const PFD_TUN: usize = 0;
const PFD_SOCK: usize = 1;
const PFD_CTL: usize = 2;

/// Go `run_proxy` (proxy_amd64.c): blocking poll() loop over the tun,
/// the UDP socket and the ctl socket. Runs until CMD_STOP (or ctl EOF).
/// The fds are owned by this function and closed on return.
pub fn run_proxy(tun: OwnedFd, sock: OwnedFd, ctl: OwnedFd, tun_ip: u32, tun_mtu: usize) {
    let (tun_fd, sock_fd, ctl_fd) = (tun.as_raw_fd(), sock.as_raw_fd(), ctl.as_raw_fd());

    if tun_mtu == 0 {
        error!("Failed to allocate 0 byte buffer"); // C: exit(1)
        return;
    }
    let mut buf = vec![0u8; tun_mtu];
    let mut routes = RouteTable::default();
    let mut exit_flag = false;

    let mut fds = [
        libc::pollfd {
            fd: tun_fd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: sock_fd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: ctl_fd,
            events: libc::POLLIN,
            revents: 0,
        },
    ];

    // C: fcntl(tun, F_SETFL, O_NONBLOCK).
    unsafe { libc::fcntl(tun_fd, libc::F_SETFL, libc::O_NONBLOCK) };

    while !exit_flag {
        let nfds = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
        if nfds < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            error!("Poll failed: {e}"); // C: exit(1)
            return;
        }

        if (fds[PFD_CTL].revents & libc::POLLIN) != 0 {
            process_cmd(ctl_fd, &mut routes, &mut exit_flag);
        }

        if (fds[PFD_TUN].revents & libc::POLLIN) != 0 || (fds[PFD_SOCK].revents & libc::POLLIN) != 0
        {
            // As long as tun or udp is readable, bypass poll(): an
            // occasional EAGAIN on an unreadable fd is cheaper than the
            // poll() call (upstream comment; the ctl socket may wait).
            loop {
                let mut activity = false;
                activity |= tun_to_udp(tun_fd, sock_fd, &mut buf, tun_ip, &mut routes);
                activity |= udp_to_tun(sock_fd, tun_fd, &mut buf);
                if !activity {
                    break;
                }
            }
        }
    }
    debug!("udp proxy exiting");
}
