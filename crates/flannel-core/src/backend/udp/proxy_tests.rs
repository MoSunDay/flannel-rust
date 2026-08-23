//! Tests for the udp proxy: command wire format, route table, ctl
//! command processing and a netns end-to-end tun->UDP forwarding test.

use super::proxy::{
    netmask, process_cmd, run_proxy, Command, IpNet, RouteTable, CMD_DEL_ROUTE, CMD_SET_ROUTE,
    CMD_STOP, COMMAND_SIZE,
};
use super::proxy_packet::cksum;
use crate::ip::iface::{get_interface_by_name, Netlink};
use crate::ip::tun::open_tun;
use crate::ip::IP4;
use anyhow::anyhow;
use std::net::{Ipv4Addr, UdpSocket};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::time::Duration;

fn ip_net(a: u8, b: u8, c: u8, d: u8) -> u32 {
    IP4::from_octets(a, b, c, d).network_order()
}

#[test]
fn command_bytes_match_c_layout() {
    let c = Command {
        cmd: CMD_SET_ROUTE,
        dest_net: 0x0102_0304,
        dest_net_len: 24,
        next_hop_ip: 0x0506_0708,
        next_hop_port: -12345,
    };
    let b = c.to_bytes();
    // Layout of the C struct on amd64, including the trailing pad.
    assert_eq!(&b[0..4], &1i32.to_le_bytes());
    assert_eq!(&b[4..8], &0x0102_0304u32.to_le_bytes());
    assert_eq!(&b[8..12], &24i32.to_le_bytes());
    assert_eq!(&b[12..16], &0x0506_0708u32.to_le_bytes());
    assert_eq!(&b[16..18], &(-12345i16).to_le_bytes());
    assert_eq!(&b[18..COMMAND_SIZE], &[0, 0]);
    assert_eq!(Command::from_bytes(&b), c);
}

#[test]
fn netmask_values() {
    assert_eq!(netmask(0), 0);
    // Values follow the C htonl convention: the logical mask converted
    // to network byte order (byte-swapped on amd64).
    assert_eq!(netmask(8), 0xFF00_0000u32.to_be());
    assert_eq!(netmask(24), 0xFFFF_FF00u32.to_be());
    assert_eq!(netmask(32), 0xFFFF_FFFFu32.to_be());
}

#[test]
fn route_table_set_find_delete() {
    let mut t = RouteTable::default();
    let a = IpNet {
        ip: ip_net(10, 1, 0, 0),
        mask: netmask(24),
    };
    let b = IpNet {
        ip: ip_net(10, 2, 0, 0),
        mask: netmask(24),
    };
    t.set_route(a, ip_net(127, 0, 0, 1), 1000);
    t.set_route(b, ip_net(127, 0, 0, 2), 2000);

    // A hit moves the entry to the front.
    assert_eq!(
        t.find_route(ip_net(10, 2, 0, 9)),
        Some((ip_net(127, 0, 0, 2), 2000))
    );
    assert_eq!(t.entries[0].dst, b);

    // Replacing an existing route keeps the entry count.
    t.set_route(a, ip_net(127, 0, 0, 3), 3000);
    assert_eq!(t.entries.len(), 2);
    assert_eq!(
        t.find_route(ip_net(10, 1, 0, 7)),
        Some((ip_net(127, 0, 0, 3), 3000))
    );

    // Miss.
    assert_eq!(t.find_route(ip_net(192, 168, 0, 1)), None);

    // Delete uses swap_remove (C swaps the last entry into the slot).
    assert!(t.del_route(b));
    assert_eq!(t.entries.len(), 1);
    assert_eq!(t.entries[0].dst, a);
    assert!(!t.del_route(b));
}

#[test]
fn process_cmd_set_del_stop() {
    let (w, r) = nix::sys::socket::socketpair(
        nix::sys::socket::AddressFamily::Unix,
        nix::sys::socket::SockType::SeqPacket,
        None,
        nix::sys::socket::SockFlag::empty(),
    )
    .unwrap();
    let mut routes = RouteTable::default();
    let mut stop = false;

    let send = |cmd: Command| {
        let b = cmd.to_bytes();
        let n = unsafe { libc::write(w.as_raw_fd(), b.as_ptr().cast(), b.len()) };
        assert_eq!(n, b.len() as isize);
    };

    send(Command {
        cmd: CMD_SET_ROUTE,
        dest_net: ip_net(10, 9, 0, 1), // unmasked, like Go's setRoute
        dest_net_len: 16,
        next_hop_ip: ip_net(127, 0, 0, 1),
        next_hop_port: 8285,
    });
    process_cmd(r.as_raw_fd(), &mut routes, &mut stop);
    assert!(!stop);
    // process_cmd masks dest_net to the /16 before storing.
    assert_eq!(
        routes.find_route(ip_net(10, 9, 1, 2)),
        Some((ip_net(127, 0, 0, 1), 8285))
    );

    send(Command {
        cmd: CMD_DEL_ROUTE,
        dest_net: ip_net(10, 9, 0, 0),
        dest_net_len: 16,
        next_hop_ip: 0,
        next_hop_port: 0,
    });
    process_cmd(r.as_raw_fd(), &mut routes, &mut stop);
    assert!(!stop);
    assert!(routes.find_route(ip_net(10, 9, 1, 2)).is_none());

    send(Command {
        cmd: CMD_STOP,
        dest_net: 0,
        dest_net_len: 0,
        next_hop_ip: 0,
        next_hop_port: 0,
    });
    process_cmd(r.as_raw_fd(), &mut routes, &mut stop);
    assert!(stop);

    // A closed peer reads as stop (deviation from C, see proxy.rs docs).
    drop(w);
    let mut stop2 = false;
    process_cmd(r.as_raw_fd(), &mut routes, &mut stop2);
    assert!(stop2);
}

/// End-to-end: open a tun in a scratch netns, run the proxy, install a
/// route over the ctl socket, feed an IP packet into the tun and check
/// it arrives at the next-hop UDP socket with its TTL decremented.
/// Needs root + /dev/net/tun; skips itself elsewhere.
#[test]
fn proxy_tun_to_udp_end_to_end() {
    let can = unsafe { libc::geteuid() } == 0 && std::path::Path::new("/dev/net/tun").exists();
    if !can {
        eprintln!("skipping udp proxy e2e test: needs root and /dev/net/tun");
        return;
    }
    if let Err(e) = netns_block_on("flnl_udp_proxy", proxy_e2e()) {
        panic!("proxy e2e failed: {e:#}");
    }
}

/// Scratch-netns runner mirroring crate::backend::vxlan::fake (the
/// module is private to vxlan, so keep a local copy).
fn netns_block_on<F: std::future::Future<Output = anyhow::Result<()>>>(
    name: &str,
    fut: F,
) -> anyhow::Result<()> {
    if let Ok(old) = netns_rs::NetNs::get(name) {
        let _ = old.remove();
    }
    let ns = netns_rs::NetNs::new(name)?;
    ns.enter()?;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(fut)
    }));
    let removed = ns.remove();
    match result {
        Ok(inner) => {
            removed.map_err(|e| anyhow!("netns remove: {e}"))?;
            inner
        }
        Err(panic) => {
            let _ = removed;
            std::panic::resume_unwind(panic);
        }
    }
}

fn dup_fd<F: AsFd>(fd: &F) -> anyhow::Result<OwnedFd> {
    let raw = unsafe { libc::dup(fd.as_fd().as_raw_fd()) };
    anyhow::ensure!(raw >= 0, "dup failed: {}", std::io::Error::last_os_error());
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

async fn proxy_e2e() -> anyhow::Result<()> {
    let nl = Netlink::new().await?;

    // lo must be up for the 127.0.0.1 next hop to work in the new ns.
    nl.handle
        .link()
        .set(rtnetlink::LinkUnspec::new_with_index(1).up().build())
        .execute()
        .await?;

    let (tun, tun_name) = open_tun("flannel%d")?;
    let iface = get_interface_by_name(&nl, &tun_name).await?;
    // Local address on the tun so the kernel can pick a src when it
    // routes overlay-bound packets out fln0.
    nl.handle
        .address()
        .add(
            iface.index,
            std::net::IpAddr::V4(Ipv4Addr::new(10, 99, 0, 1)),
            32,
        )
        .execute()
        .await?;
    // Bring the tun up first: route add over a down link fails with
    // ENETDOWN.
    nl.handle
        .link()
        .set(
            rtnetlink::LinkUnspec::new_with_index(iface.index)
                .up()
                .build(),
        )
        .execute()
        .await?;
    // Kernel route so overlay-bound packets are written out the tun,
    // where the proxy picks them up.
    let route = rtnetlink::RouteMessageBuilder::<Ipv4Addr>::new()
        .destination_prefix(Ipv4Addr::new(10, 99, 0, 0), 16)
        .output_interface(iface.index)
        .build();
    nl.handle.route().add(route).execute().await?;

    let proxy_sock = UdpSocket::bind("127.0.0.1:0")?;
    let recv_sock = UdpSocket::bind("127.0.0.1:0")?;
    let recv_port = recv_sock.local_addr()?.port();
    recv_sock.set_read_timeout(Some(Duration::from_secs(5)))?;

    let (ctl, ctl2) = nix::sys::socket::socketpair(
        nix::sys::socket::AddressFamily::Unix,
        nix::sys::socket::SockType::SeqPacket,
        None,
        nix::sys::socket::SockFlag::empty(),
    )?;

    // The OS thread inherits this thread's netns.
    let tun2 = dup_fd(&tun)?;
    let sock2 = dup_fd(&proxy_sock)?;
    std::thread::spawn(move || {
        run_proxy(tun2, sock2, ctl2, ip_net(10, 99, 0, 1), 1500);
    });

    // Set route 10.99.0.0/16 -> 127.0.0.1:recv_port over the ctl socket.
    let b = Command {
        cmd: CMD_SET_ROUTE,
        dest_net: ip_net(10, 99, 0, 0),
        dest_net_len: 16,
        next_hop_ip: ip_net(127, 0, 0, 1),
        next_hop_port: recv_port as i16,
    }
    .to_bytes();
    let n = unsafe { libc::write(ctl.as_raw_fd(), b.as_ptr().cast(), b.len()) };
    anyhow::ensure!(n == b.len() as isize, "ctl write failed");
    std::thread::sleep(Duration::from_millis(200));

    // Generate overlay traffic the way a real container would: send a
    // UDP datagram to a destination inside the routed subnet. The
    // kernel routes it out fln0, so it appears on the tun fd for the
    // proxy, which forwards it to the next hop with the TTL
    // decremented exactly once.
    let sender = UdpSocket::bind("0.0.0.0:0")?;
    let payload = b"flannel-udp-proxy-e2e";
    sender.send_to(payload, (Ipv4Addr::new(10, 99, 1, 2), 12345))?;

    let mut buf = [0u8; 2048];
    let (n, _from) = recv_sock.recv_from(&mut buf)?;
    let ip = &buf[..n];
    // IPv4, IHL 5, UDP.
    assert_eq!(ip[0], 0x45);
    assert_eq!(ip[9], 17);
    // Kernel started at TTL 64; the proxy decremented it exactly once.
    assert_eq!(ip[8], 63);
    assert_eq!(&ip[12..16], &[10, 99, 0, 1]); // src = tun address
    assert_eq!(&ip[16..20], &[10, 99, 1, 2]); // dst
    assert_eq!(cksum(&ip[..20]), 0); // header checksum valid
                                     // The UDP payload survived intact.
    assert_eq!(&ip[n - payload.len()..n], payload);
    Ok(())
}
