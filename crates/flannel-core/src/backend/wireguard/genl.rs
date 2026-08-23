//! WireGuard generic-netlink client: a raw libc AF_NETLINK socket
//! (protocol 16 / NETLINK_GENERIC) exposing the wgctrl-go style API
//! ([`configure_device`] / [`dump_device`]) and the wire helpers.
//! Blocking std I/O: async callers must use `spawn_blocking`.
//! GETFAMILY needs NLM_F_ACK or recv blocks forever; wg command ids
//! come from CTRL_ATTR_OPS (dump-capable op = GET_DEVICE, do-capable =
//! SET_DEVICE, fallback 1/2; some kernels use 0/1 not mainline 1/2).

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[cfg(test)]
#[path = "genl_tests.rs"]
mod genl_tests;
const GENL_ID_CTRL: u16 = 0x10;
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;
const CTRL_ATTR_OPS: u16 = 6;
const CTRL_ATTR_OP_ID: u16 = 1;
const CTRL_ATTR_OP_FLAGS: u16 = 2;
const GENL_CMD_CAP_DO: u32 = 0x02;
const GENL_CMD_CAP_DUMP: u32 = 0x04;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_ACK: u16 = 4;
const NLM_F_DUMP: u16 = 0x300;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;

pub const WG_GENL_NAME: &str = "wireguard";
const WG_GENL_VERSION: u8 = 1;
pub(crate) const WGDEVICE_A_IFINDEX: u16 = 1;
pub(crate) const WGDEVICE_A_IFNAME: u16 = 2;
const WGDEVICE_A_PRIVATE_KEY: u16 = 3;
const WGDEVICE_A_FLAGS: u16 = 5;
pub(crate) const WGDEVICE_A_LISTEN_PORT: u16 = 6;
pub(crate) const WGDEVICE_A_PEERS: u16 = 8;
pub const WGDEVICE_F_REPLACE_PEERS: u32 = 1 << 0;
pub(crate) const WGPEER_A_PUBLIC_KEY: u16 = 1;
const WGPEER_A_PRESHARED_KEY: u16 = 2;
const WGPEER_A_FLAGS: u16 = 3;
pub(crate) const WGPEER_A_ENDPOINT: u16 = 4;
pub(crate) const WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL: u16 = 5;
pub(crate) const WGPEER_A_ALLOWEDIPS: u16 = 9;
pub const WGPEER_F_REMOVE_ME: u32 = 1 << 0;
pub const WGPEER_F_REPLACE_ALLOWEDIPS: u32 = 1 << 1;
pub(crate) const WGALLOWEDIP_A_FAMILY: u16 = 1;
pub(crate) const WGALLOWEDIP_A_IPADDR: u16 = 2;
pub(crate) const WGALLOWEDIP_A_CIDR_MASK: u16 = 3;
/// One allowed IP of a peer (Go: `wgtypes.AllowedIP`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WgAllowedIp {
    pub ip: IpAddr,
    pub cidr: u8,
}
/// Peer configuration (Go: `wgtypes.PeerConfig`).
#[derive(Clone, Debug)]
pub struct WgPeerConfig {
    pub public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    pub flags: u32, // combination of WGPEER_F_*
    pub endpoint: Option<SocketAddr>,
    pub persistent_keepalive_interval: Option<u16>,
    pub allowed_ips: Vec<WgAllowedIp>,
}
/// Device configuration (Go: `wgtypes.Config`).
#[derive(Clone, Debug)]
pub struct WgDeviceConfig {
    pub ifname: String,
    pub private_key: Option<[u8; 32]>,
    pub listen_port: Option<u16>,
    pub flags: u32, // combination of WGDEVICE_F_*
    pub peers: Vec<WgPeerConfig>,
}

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// One attribute: u16 length, u16 type, payload, padded to 4 bytes.
fn nla(attr_type: u16, payload: &[u8]) -> Vec<u8> {
    let len = (4 + payload.len()) as u16;
    let mut v = Vec::with_capacity(align4(len as usize));
    v.extend_from_slice(&len.to_ne_bytes());
    v.extend_from_slice(&attr_type.to_ne_bytes());
    v.extend_from_slice(payload);
    v.resize(align4(v.len()), 0);
    v
}
fn nla_u8(t: u16, v: u8) -> Vec<u8> {
    nla(t, &[v])
}
fn nla_u16(t: u16, v: u16) -> Vec<u8> {
    nla(t, &v.to_ne_bytes())
}
fn nla_u32(t: u16, v: u32) -> Vec<u8> {
    nla(t, &v.to_ne_bytes())
}
fn nla_str(t: u16, s: &str) -> Vec<u8> {
    let mut b = s.as_bytes().to_vec();
    b.push(0);
    nla(t, &b)
}
/// Nested attribute (NLA_F_NEST set) wrapping encoded children.
fn nla_nest(t: u16, children: &[Vec<u8>]) -> Vec<u8> {
    nla(t | 0x8000, &children.concat())
}

/// Parse a stream of attributes; NLA_F_NEST is masked off the type.
pub(crate) fn parse_nlas(mut b: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let mut out = Vec::new();
    while b.len() >= 4 {
        let len = u16::from_ne_bytes(b[0..2].try_into().unwrap()) as usize;
        let t = u16::from_ne_bytes(b[2..4].try_into().unwrap());
        if len < 4 || len > b.len() {
            break;
        }
        out.push((t & 0x7fff, b[4..len].to_vec()));
        b = &b[align4(len)..];
    }
    out
}
pub(crate) fn u16_of(v: &[u8]) -> Option<u16> {
    v.get(0..2)
        .map(|b| u16::from_ne_bytes(b.try_into().unwrap()))
}
pub(crate) fn u32_of(v: &[u8]) -> Option<u32> {
    v.get(0..4)
        .map(|b| u32::from_ne_bytes(b.try_into().unwrap()))
}

/// sockaddr_in / sockaddr_in6 bytes: u16 family (native byte order),
/// u16 port (big endian), address, zero padded to the struct size.
fn sockaddr_bytes(addr: SocketAddr) -> Vec<u8> {
    match addr {
        SocketAddr::V4(v4) => {
            let mut v = Vec::with_capacity(16);
            v.extend_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
            v.extend_from_slice(&v4.port().to_be_bytes());
            v.extend_from_slice(&v4.ip().octets());
            v.resize(16, 0);
            v
        }
        SocketAddr::V6(v6) => {
            let mut v = Vec::with_capacity(28);
            v.extend_from_slice(&(libc::AF_INET6 as u16).to_ne_bytes());
            v.extend_from_slice(&v6.port().to_be_bytes());
            v.extend_from_slice(&0u32.to_ne_bytes()); // sin6_flowinfo
            v.extend_from_slice(&v6.ip().octets());
            v.extend_from_slice(&v6.scope_id().to_ne_bytes());
            v
        }
    }
}

/// Decode a kernel endpoint sockaddr (v4 or v6).
#[allow(dead_code)] // read path, exercised by genl_tests
pub(crate) fn parse_endpoint(b: &[u8]) -> Option<SocketAddr> {
    let family = u16_of(b)?;
    let port = u16::from_be_bytes(b.get(2..4)?.try_into().unwrap());
    let ip = if family == libc::AF_INET as u16 {
        let o = b.get(4..8)?;
        IpAddr::V4(Ipv4Addr::new(o[0], o[1], o[2], o[3]))
    } else if family == libc::AF_INET6 as u16 {
        IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(b.get(8..24)?).ok()?))
    } else {
        return None;
    };
    Some(SocketAddr::new(ip, port))
}

struct GenlSocket {
    fd: i32,
    seq: u32,
    port: u32,
}

impl GenlSocket {
    fn new() -> io::Result<Self> {
        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, 16) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        let r = unsafe {
            libc::bind(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as u32,
            )
        };
        if r < 0 {
            unsafe { libc::close(fd) };
            return Err(io::Error::last_os_error());
        }
        let mut out: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::sockaddr_nl>() as u32;
        unsafe { libc::getsockname(fd, &mut out as *mut _ as *mut libc::sockaddr, &mut len) };
        Ok(GenlSocket {
            fd,
            seq: 0,
            port: out.nl_pid,
        })
    }

    /// Send one request, collect reply bodies until NLMSG_DONE or the
    /// ACK; a nonzero NLMSG_ERROR becomes an OS error.
    fn request(
        &mut self,
        family: u16,
        cmd: u8,
        flags: u16,
        attrs: &[u8],
    ) -> io::Result<Vec<Vec<u8>>> {
        self.seq += 1;
        let mut payload = vec![cmd, WG_GENL_VERSION];
        payload.extend_from_slice(&0u16.to_ne_bytes());
        payload.extend_from_slice(attrs);
        let mut msg = Vec::with_capacity(16 + payload.len());
        msg.extend_from_slice(&((16 + payload.len()) as u32).to_ne_bytes());
        msg.extend_from_slice(&family.to_ne_bytes());
        msg.extend_from_slice(&flags.to_ne_bytes());
        msg.extend_from_slice(&self.seq.to_ne_bytes());
        msg.extend_from_slice(&self.port.to_ne_bytes());
        msg.extend_from_slice(&payload);
        // send() on AF_NETLINK targets pid 0, i.e. the kernel.
        let sent =
            unsafe { libc::send(self.fd, msg.as_ptr() as *const libc::c_void, msg.len(), 0) };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut results = Vec::new();
        let mut buf = vec![0u8; 65536];
        loop {
            let n =
                unsafe { libc::recv(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            let buf = &buf[..n as usize];
            let (mut off, mut done) = (0usize, false);
            while off + 16 <= buf.len() {
                let mlen = u32_of(&buf[off..]).unwrap_or(0) as usize;
                let mtype = u16_of(&buf[off + 4..]).unwrap_or(0);
                if mlen < 16 || off + mlen > buf.len() {
                    break;
                }
                let body = &buf[off + 16..off + mlen];
                if mtype == NLMSG_ERROR {
                    let code = i32::from_ne_bytes(body[0..4].try_into().unwrap());
                    if code != 0 {
                        return Err(io::Error::from_raw_os_error(-code));
                    }
                    done = true; // ACK
                } else if mtype == NLMSG_DONE {
                    done = true;
                } else {
                    results.push(body.to_vec());
                }
                off += align4(mlen);
            }
            if done {
                break;
            }
        }
        Ok(results)
    }

    /// Family id + GET (dump op) / SET (do op) ids from CTRL_ATTR_OPS.
    fn resolve_family_ops(&mut self, name: &str) -> io::Result<(u16, u8, u8)> {
        // NLM_F_ACK is critical here: without it recv blocks forever.
        let msgs = self.request(
            GENL_ID_CTRL,
            CTRL_CMD_GETFAMILY,
            NLM_F_REQUEST | NLM_F_ACK,
            &nla_str(CTRL_ATTR_FAMILY_NAME, name),
        )?;
        for m in msgs {
            let (mut fam, mut get_cmd, mut set_cmd) = (None, None, None);
            for (t, v) in parse_nlas(&m[4..]) {
                match t {
                    CTRL_ATTR_FAMILY_ID => fam = u16_of(&v),
                    CTRL_ATTR_OPS => {
                        for (_, op) in parse_nlas(&v) {
                            let (mut id, mut flags) = (None, 0u32);
                            for (ot, ov) in parse_nlas(&op) {
                                if ot == CTRL_ATTR_OP_ID && !ov.is_empty() {
                                    id = Some(ov[0]);
                                }
                                if ot == CTRL_ATTR_OP_FLAGS {
                                    flags = u32_of(&ov).unwrap_or(0);
                                }
                            }
                            let Some(id) = id else { continue };
                            if flags & GENL_CMD_CAP_DUMP != 0 && get_cmd.is_none() {
                                get_cmd = Some(id);
                            }
                            if flags & GENL_CMD_CAP_DO != 0 && set_cmd.is_none() {
                                set_cmd = Some(id);
                            }
                        }
                    }
                    _ => {}
                }
            }
            if let Some(fam) = fam {
                return Ok((fam, get_cmd.unwrap_or(1), set_cmd.unwrap_or(2)));
            }
        }
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("generic netlink family {name} not found"),
        ))
    }
}

impl Drop for GenlSocket {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

/// Go: `wgctrl.Client.ConfigureDevice` (SET_DEVICE, waits for the ACK).
pub fn configure_device(cfg: &WgDeviceConfig) -> io::Result<()> {
    let mut sock = GenlSocket::new()?;
    let (fam, _get_cmd, set_cmd) = sock.resolve_family_ops(WG_GENL_NAME)?;
    let mut attrs = nla_str(WGDEVICE_A_IFNAME, &cfg.ifname);
    if let Some(k) = &cfg.private_key {
        attrs.extend_from_slice(&nla(WGDEVICE_A_PRIVATE_KEY, k));
    }
    if let Some(p) = cfg.listen_port {
        attrs.extend_from_slice(&nla_u16(WGDEVICE_A_LISTEN_PORT, p));
    }
    if cfg.flags != 0 {
        attrs.extend_from_slice(&nla_u32(WGDEVICE_A_FLAGS, cfg.flags));
    }
    if !cfg.peers.is_empty() {
        let peers: Vec<Vec<u8>> = cfg
            .peers
            .iter()
            .enumerate()
            .map(|(i, p)| nla_nest((i + 1) as u16, &peer_attrs(p)))
            .collect();
        attrs.extend_from_slice(&nla_nest(WGDEVICE_A_PEERS, &peers));
    }
    sock.request(fam, set_cmd, NLM_F_REQUEST | NLM_F_ACK, &attrs)?;
    Ok(())
}

fn peer_attrs(p: &WgPeerConfig) -> Vec<Vec<u8>> {
    let mut a = vec![nla(WGPEER_A_PUBLIC_KEY, &p.public_key)];
    if let Some(psk) = &p.preshared_key {
        a.push(nla(WGPEER_A_PRESHARED_KEY, psk));
    }
    if p.flags != 0 {
        a.push(nla_u32(WGPEER_A_FLAGS, p.flags));
    }
    if let Some(ep) = p.endpoint {
        a.push(nla(WGPEER_A_ENDPOINT, &sockaddr_bytes(ep)));
    }
    if let Some(k) = p.persistent_keepalive_interval {
        a.push(nla_u16(WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL, k));
    }
    if !p.allowed_ips.is_empty() {
        let ips: Vec<Vec<u8>> = p
            .allowed_ips
            .iter()
            .enumerate()
            .map(|(i, ip)| nla_nest((i + 1) as u16, &allowed_ip_attrs(ip)))
            .collect();
        a.push(nla_nest(WGPEER_A_ALLOWEDIPS, &ips));
    }
    a
}

fn allowed_ip_attrs(ip: &WgAllowedIp) -> Vec<Vec<u8>> {
    let (family, addr): (u16, Vec<u8>) = match ip.ip {
        IpAddr::V4(v4) => (libc::AF_INET as u16, v4.octets().to_vec()),
        IpAddr::V6(v6) => (libc::AF_INET6 as u16, v6.octets().to_vec()),
    };
    vec![
        nla_u16(WGALLOWEDIP_A_FAMILY, family),
        nla(WGALLOWEDIP_A_IPADDR, &addr),
        nla_u8(WGALLOWEDIP_A_CIDR_MASK, ip.cidr),
    ]
}

/// Raw GET_DEVICE dump by name (Go: `wgctrl.Client.Device`); the caller parses the bodies (see `device.rs`).
#[allow(dead_code)] // read path, exercised by genl_tests
pub(crate) fn dump_device(ifname: &str) -> io::Result<Vec<Vec<u8>>> {
    let mut sock = GenlSocket::new()?;
    let (fam, get_cmd, _set_cmd) = sock.resolve_family_ops(WG_GENL_NAME)?;
    sock.request(
        fam,
        get_cmd,
        NLM_F_REQUEST | NLM_F_DUMP | NLM_F_ACK,
        &nla_str(WGDEVICE_A_IFNAME, ifname),
    )
}
