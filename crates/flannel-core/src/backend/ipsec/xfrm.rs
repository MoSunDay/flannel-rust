//! Raw NETLINK_XFRM policy client (hand-rolled like wireguard/genl.rs;
//! replaces vishvananda/netlink's XfrmPolicy{Add,Get,Update,Del} used by
//! handle_xfrm.go). Blocking libc I/O: async callers use `spawn_blocking`.
//! Structs mirror linux/xfrm.h (sizes pinned below); flannel policies are
//! IPv4 ESP/tunnel with Go zero-value defaults (lifetimes/priority/action
//! POLICY_ALLOW/flags SHARE_ANY/zero tmpl algos, Go XfrmPolicyTmpl zero);
//! only selector, dir and tmpl Src/Dst/Proto ESP/Mode TUNNEL/Reqid set.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[cfg(test)]
#[path = "xfrm_tests.rs"]
mod xfrm_tests;

const NETLINK_XFRM: i32 = 6;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_ACK: u16 = 4;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const XFRM_MSG_NEWPOLICY: u16 = 19;
const XFRM_MSG_DELPOLICY: u16 = 20;
const XFRM_MSG_GETPOLICY: u16 = 21;
const XFRM_MSG_UPDPOLICY: u16 = 25;
const XFRMA_TMPL: u16 = 5; // rtattr type of the xfrm_user_tmpl array
const PROTO_ESP: u8 = 50; // flannel only programs ESP tunnel templates
const MODE_TUNNEL: u8 = 1;

/// Policy direction (linux/xfrm.h `XFRM_POLICY_IN/OUT/FWD`).
pub const DIR_IN: u8 = 0;
pub const DIR_OUT: u8 = 1;
pub const DIR_FWD: u8 = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XfrmPolicySpec {
    pub src: IpAddr,
    pub src_prefix: u8,
    pub dst: IpAddr,
    pub dst_prefix: u8,
    /// DIR_IN / DIR_OUT / DIR_FWD.
    pub dir: u8,
    pub tunnel_src: IpAddr,
    pub tunnel_dst: IpAddr,
    pub reqid: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XfrmPolicy {
    pub src: IpAddr,
    pub src_prefix: u8,
    pub dst: IpAddr,
    pub dst_prefix: u8,
    pub dir: u8,
    pub index: u32,
    pub priority: u32,
    pub tmpls: Vec<XfrmTmpl>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XfrmTmpl {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub proto: u8,
    pub mode: u8,
    pub reqid: u32,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct XfrmAddress([u8; 16]);
#[derive(Clone, Copy)]
#[repr(C)]
struct XfrmSelector {
    daddr: XfrmAddress,
    saddr: XfrmAddress,
    dport: u16,
    dport_mask: u16,
    sport: u16,
    sport_mask: u16,
    family: u16,
    prefixlen_d: u8,
    prefixlen_s: u8,
    proto: u8,
    ifindex: i32,
    user: u32,
}
#[derive(Clone, Copy)]
#[repr(C)]
struct XfrmLifetimeCfg {
    soft_byte_limit: u64,
    hard_byte_limit: u64,
    soft_packet_limit: u64,
    hard_packet_limit: u64,
    soft_add_expires_seconds: u64,
    hard_add_expires_seconds: u64,
    soft_use_expires_seconds: u64,
    hard_use_expires_seconds: u64,
}
#[derive(Clone, Copy)]
#[repr(C)]
struct XfrmLifetimeCur {
    bytes: u64,
    packets: u64,
    add_time: u64,
    use_time: u64,
}
#[derive(Clone, Copy)]
#[repr(C)]
struct XfrmUserpolicyInfo {
    sel: XfrmSelector,
    lft: XfrmLifetimeCfg,
    curlft: XfrmLifetimeCur,
    priority: u32,
    index: u32,
    dir: u8,
    action: u8,
    flags: u8,
    share: u8,
}
#[derive(Clone, Copy)]
#[repr(C)]
struct XfrmId {
    daddr: XfrmAddress,
    spi: u32,
    proto: u8,
}
#[derive(Clone, Copy)]
#[repr(C)]
struct XfrmUserTmpl {
    id: XfrmId,
    family: u16,
    saddr: XfrmAddress,
    reqid: u32,
    mode: u8,
    share: u8,
    optional: u8,
    aalgos: u32,
    ealgos: u32,
    calgos: u32,
}
#[derive(Clone, Copy)]
#[repr(C)]
struct XfrmUserpolicyId {
    sel: XfrmSelector,
    index: u32,
    dir: u8,
}

const _: () = assert!(std::mem::size_of::<XfrmSelector>() == 56);
const _: () = assert!(std::mem::size_of::<XfrmUserpolicyInfo>() == 168);
const _: () = assert!(std::mem::size_of::<XfrmUserTmpl>() == 64);
const _: () = assert!(std::mem::size_of::<XfrmUserpolicyId>() == 64);

fn addr(ip: IpAddr) -> XfrmAddress {
    let mut a = XfrmAddress([0u8; 16]);
    match ip {
        IpAddr::V4(v4) => a.0[..4].copy_from_slice(&v4.octets()),
        IpAddr::V6(v6) => a.0.copy_from_slice(&v6.octets()),
    }
    a
}
fn family_of(ip: IpAddr) -> u16 {
    match ip {
        IpAddr::V4(_) => libc::AF_INET as u16,
        IpAddr::V6(_) => libc::AF_INET6 as u16,
    }
}
fn ip_of(a: &XfrmAddress, family: u16) -> IpAddr {
    if family == libc::AF_INET6 as u16 {
        IpAddr::V6(Ipv6Addr::from(a.0))
    } else {
        IpAddr::V4(Ipv4Addr::new(a.0[0], a.0[1], a.0[2], a.0[3]))
    }
}
fn fill_selector(sel: &mut XfrmSelector, spec: &XfrmPolicySpec) {
    sel.family = family_of(spec.src);
    sel.saddr = addr(spec.src);
    sel.prefixlen_s = spec.src_prefix;
    sel.daddr = addr(spec.dst);
    sel.prefixlen_d = spec.dst_prefix;
}
fn policy_info(spec: &XfrmPolicySpec) -> XfrmUserpolicyInfo {
    let mut info: XfrmUserpolicyInfo = unsafe { std::mem::zeroed() };
    fill_selector(&mut info.sel, spec);
    info.dir = spec.dir;
    info
}
fn user_tmpl(spec: &XfrmPolicySpec) -> XfrmUserTmpl {
    let mut t: XfrmUserTmpl = unsafe { std::mem::zeroed() };
    t.id.daddr = addr(spec.tunnel_dst);
    t.id.proto = PROTO_ESP;
    t.family = family_of(spec.tunnel_src);
    t.saddr = addr(spec.tunnel_src);
    t.reqid = spec.reqid;
    t.mode = MODE_TUNNEL;
    t
}
fn bytes_of<T: Sized>(v: &T) -> Vec<u8> {
    unsafe { std::slice::from_raw_parts(v as *const T as *const u8, std::mem::size_of::<T>()) }
        .to_vec()
}
fn read_struct<T: Copy + Sized>(b: &[u8], off: usize) -> Option<T> {
    let size = std::mem::size_of::<T>();
    let chunk = b.get(off..off + size)?;
    let mut out = std::mem::MaybeUninit::<T>::zeroed();
    unsafe { std::ptr::copy_nonoverlapping(chunk.as_ptr(), out.as_mut_ptr() as *mut u8, size) };
    Some(unsafe { out.assume_init() })
}
fn align4(n: usize) -> usize {
    (n + 3) & !3
}
fn rtattr(attr_type: u16, payload: &[u8]) -> Vec<u8> {
    let len = (4 + payload.len()) as u16;
    let mut v = Vec::with_capacity(align4(len as usize));
    v.extend_from_slice(&len.to_ne_bytes());
    v.extend_from_slice(&attr_type.to_ne_bytes());
    v.extend_from_slice(payload);
    v.resize(align4(v.len()), 0);
    v
}
fn parse_rtattrs(mut b: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let mut out = Vec::new();
    while b.len() >= 4 {
        let len = u16::from_ne_bytes(b[0..2].try_into().unwrap()) as usize;
        let t = u16::from_ne_bytes(b[2..4].try_into().unwrap());
        if len < 4 || len > b.len() {
            break;
        }
        out.push((t, b[4..len].to_vec()));
        b = &b[align4(len)..];
    }
    out
}
struct XfrmSocket {
    fd: i32,
    seq: u32,
    port: u32,
}

impl XfrmSocket {
    fn new() -> io::Result<Self> {
        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_XFRM) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        let len = std::mem::size_of::<libc::sockaddr_nl>() as u32;
        if unsafe { libc::bind(fd, &addr as *const _ as *const libc::sockaddr, len) } < 0 {
            unsafe { libc::close(fd) };
            return Err(io::Error::last_os_error());
        }
        let mut out: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::sockaddr_nl>() as u32;
        unsafe { libc::getsockname(fd, &mut out as *mut _ as *mut libc::sockaddr, &mut len) };
        Ok(Self {
            fd,
            seq: 0,
            port: out.nl_pid,
        })
    }

    // Send one request; collect reply bodies until the ACK (a nonzero
    // NLMSG_ERROR becomes the OS error) or NLMSG_DONE.
    fn request(&mut self, msg_type: u16, payload: &[u8]) -> io::Result<Vec<Vec<u8>>> {
        self.seq += 1;
        let mut msg = Vec::with_capacity(16 + payload.len());
        msg.extend_from_slice(&((16 + payload.len()) as u32).to_ne_bytes());
        msg.extend_from_slice(&msg_type.to_ne_bytes());
        msg.extend_from_slice(&(NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
        msg.extend_from_slice(&self.seq.to_ne_bytes());
        msg.extend_from_slice(&self.port.to_ne_bytes());
        msg.extend_from_slice(payload);
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
                let mlen = u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
                if mlen < 16 || off + mlen > buf.len() {
                    break;
                }
                let mtype = u16::from_ne_bytes(buf[off + 4..off + 6].try_into().unwrap());
                match mtype {
                    NLMSG_ERROR if mlen >= 20 => {
                        let code = i32::from_ne_bytes(buf[off + 16..off + 20].try_into().unwrap());
                        if code != 0 {
                            return Err(io::Error::from_raw_os_error(-code));
                        }
                        done = true; // ACK
                    }
                    NLMSG_DONE => done = true,
                    _ => results.push(buf[off + 16..off + mlen].to_vec()),
                }
                off += align4(mlen);
            }
            if done {
                return Ok(results);
            }
        }
    }
}

impl Drop for XfrmSocket {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}
fn xfrm_req(msg_type: u16, payload: &[u8]) -> io::Result<()> {
    XfrmSocket::new()?.request(msg_type, payload).map(|_| ())
}
fn policy_info_msg(spec: &XfrmPolicySpec) -> Vec<u8> {
    let mut payload = bytes_of(&policy_info(spec));
    payload.extend_from_slice(&rtattr(XFRMA_TMPL, &bytes_of(&user_tmpl(spec))));
    payload
}
fn policy_id_msg(spec: &XfrmPolicySpec) -> Vec<u8> {
    let mut pid: XfrmUserpolicyId = unsafe { std::mem::zeroed() };
    fill_selector(&mut pid.sel, spec);
    pid.dir = spec.dir;
    bytes_of(&pid)
}
fn parse_policy(body: &[u8]) -> io::Result<XfrmPolicy> {
    let Some(info) = read_struct::<XfrmUserpolicyInfo>(body, 0) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "short GETPOLICY reply",
        ));
    };
    let family = info.sel.family;
    let mut tmpls = Vec::new();
    for (t, payload) in parse_rtattrs(&body[std::mem::size_of::<XfrmUserpolicyInfo>()..]) {
        if t != XFRMA_TMPL {
            continue;
        }
        for chunk in payload.chunks_exact(std::mem::size_of::<XfrmUserTmpl>()) {
            let Some(ut) = read_struct::<XfrmUserTmpl>(chunk, 0) else {
                continue;
            };
            tmpls.push(XfrmTmpl {
                src: ip_of(&ut.saddr, ut.family),
                dst: ip_of(&ut.id.daddr, ut.family),
                proto: ut.id.proto,
                mode: ut.mode,
                reqid: ut.reqid,
            });
        }
    }
    Ok(XfrmPolicy {
        src: ip_of(&info.sel.saddr, family),
        src_prefix: info.sel.prefixlen_s,
        dst: ip_of(&info.sel.daddr, family),
        dst_prefix: info.sel.prefixlen_d,
        dir: info.dir,
        index: info.index,
        priority: info.priority,
        tmpls,
    })
}

/// Go: `netlink.XfrmPolicyAdd`.
pub fn add_policy(spec: &XfrmPolicySpec) -> io::Result<()> {
    xfrm_req(XFRM_MSG_NEWPOLICY, &policy_info_msg(spec))
}

/// Go: `netlink.XfrmPolicyUpdate`.
pub fn update_policy(spec: &XfrmPolicySpec) -> io::Result<()> {
    xfrm_req(XFRM_MSG_UPDPOLICY, &policy_info_msg(spec))
}

/// Go: `netlink.XfrmPolicyDel`.
pub fn del_policy(spec: &XfrmPolicySpec) -> io::Result<()> {
    xfrm_req(XFRM_MSG_DELPOLICY, &policy_id_msg(spec))
}

/// Go: `netlink.XfrmPolicyGet`: single filtered GETPOLICY (not a dump);
/// -ENOENT/-ENODATA nlmsgerrs mean "does not exist" -> None.
pub fn get_policy(spec: &XfrmPolicySpec) -> io::Result<Option<XfrmPolicy>> {
    let bodies = XfrmSocket::new()?
        .request(XFRM_MSG_GETPOLICY, &policy_id_msg(spec))
        .or_else(|e| {
            if matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ENODATA)) {
                Ok(Vec::new())
            } else {
                Err(e)
            }
        })?;
    bodies.first().map(|b| parse_policy(b)).transpose()
}
