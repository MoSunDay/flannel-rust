//! Port of the checksum / TTL / ICMP helpers of proxy_amd64.c (upstream
//! cdf76059): `cksum`, `decrement_ttl`, `send_net_unreachable` and
//! `inaddr_str`.
//!
//! Go/C deviations:
//! - C reads/writes IP header fields through packed struct pointers;
//!   the Rust port indexes the packet bytes directly (offsets of
//!   `struct iphdr`: ihl/version 0, tot_len 2, frag_off 6, ttl 8,
//!   protocol 9, check 10, saddr 12, daddr 16).
//! - C `memcpy`s the offender's header + 8 payload bytes even when the
//!   received packet is shorter than that (reading stale buffer data);
//!   the Rust port skips the ICMP reply in that case.
//! - C logs gated on `log_errors` (klog V(1)); the Rust port uses
//!   tracing unconditionally.

use std::os::fd::RawFd;
use tracing::{debug, error};

/// Go/C `sizeof(struct iphdr)`: the fixed IPv4 header size.
pub const IPHDR_LEN: usize = 20;
/// Go/C `MAX_IPOPTLEN`.
pub const MAX_IPOPTLEN: usize = 40;
/// Go/C `ICMP_DEST_UNREACH`.
const ICMP_DEST_UNREACH: u8 = 3;
/// Go/C `ICMP_NET_UNREACH`.
const ICMP_NET_UNREACH: u8 = 0;
/// Go/C `IPPROTO_ICMP` byte in the iphdr protocol field.
const PROTO_ICMP: u8 = 1;

/// Go `inaddr_str`: dotted quad of a network-order in_addr_t value.
pub fn inaddr_str(a: u32) -> String {
    let b = a.to_ne_bytes();
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

/// Go `cksum`: one's complement sum over the 4-byte words of `data`
/// with end-around carry, folded to 16 bits and complemented. Like C
/// this is only valid for lengths that are multiples of 4 (all callers
/// pass IP headers, ICMP header + IP header + 8 bytes, which are).
/// The accumulator is 64-bit (C `long` on amd64), so even an all-0xFF
/// 64 KiB packet cannot overflow; the carry fold loops until the sum
/// fits in 16 bits (C folds twice, which suffices for realistic sums).
pub fn cksum(data: &[u8]) -> u16 {
    let mut sum: u64 = 0;
    for chunk in data.chunks_exact(4) {
        sum += u32::from_ne_bytes(chunk.try_into().unwrap()) as u64;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Go `decrement_ttl`: decrement the TTL, discard (false) when it
/// reaches zero, otherwise patch the header checksum per RFC 1624 and
/// keep the packet (true). The checksum arithmetic mirrors the C code
/// byte-for-byte (it operates on the two check bytes as loaded by the
/// machine, i.e. little-endian on amd64).
pub fn decrement_ttl(pkt: &mut [u8]) -> bool {
    let ttl = pkt[8].wrapping_sub(1);
    pkt[8] = ttl;
    if ttl == 0 {
        debug!(
            "Discarding IP fragment {} -> {} due to zero TTL",
            inaddr_str(u32::from_ne_bytes(pkt[12..16].try_into().unwrap())),
            inaddr_str(u32::from_ne_bytes(pkt[16..20].try_into().unwrap()))
        );
        return false;
    }

    // C: if (check >= htons(0xFFFF - 0x100)) check += htons(0x100) + 1
    //    else check += htons(0x100).
    let check = u16::from_ne_bytes([pkt[10], pkt[11]]);
    let threshold = (0xFFFFu16 - 0x100).to_be(); // htons(0xFFFF - 0x100)
    let inc = 0x100u16.to_be(); // htons(0x100)
    let patched = if check >= threshold {
        check.wrapping_add(inc).wrapping_add(1)
    } else {
        check.wrapping_add(inc)
    };
    pkt[10..12].copy_from_slice(&patched.to_ne_bytes());
    true
}

/// Go `send_net_unreachable`: build the ICMP net-unreachable reply for
/// `offender` and write it back to the tun.
pub fn send_net_unreachable(tun: RawFd, offender: &[u8], tun_addr: u32) {
    let Some(pkt) = build_net_unreachable(offender, tun_addr) else {
        return;
    };
    let nsent = unsafe { libc::write(tun, pkt.as_ptr().cast(), pkt.len()) };
    if nsent < 0 {
        error!(
            "failed to send ICMP net unreachable: {}",
            std::io::Error::last_os_error()
        );
    } else if nsent as usize != pkt.len() {
        error!(
            "failed to send ICMP net unreachable: only {nsent} out of {} byte sent",
            pkt.len()
        );
    }
}

/// Packet-building half of Go `send_net_unreachable`. None when no ICMP
/// should go out: malformed ihl, ICMP-about-ICMP (RFC 792), non-first
/// fragment, or offender shorter than header + 8 payload bytes (see
/// module docs).
pub fn build_net_unreachable(offender: &[u8], tun_addr: u32) -> Option<Vec<u8>> {
    if offender.len() < IPHDR_LEN {
        return None;
    }
    let off_iph_len = (offender[0] & 0x0F) as usize * 4;
    if off_iph_len >= IPHDR_LEN + MAX_IPOPTLEN {
        debug!("not sending net unreachable: mulformed ip pkt: iph={off_iph_len}");
        return None;
    }
    if offender[9] == PROTO_ICMP {
        // RFC 792: never send ICMPs about ICMPs.
        return None;
    }
    // Low 13 bits of frag_off are the offset; ICMP only for the first
    // fragment. (C compares the natively loaded u16 against htons(0x1FFF),
    // which is the same as comparing the big-endian value to 0x1FFF.)
    let frag_off = u16::from_be_bytes([offender[6], offender[7]]);
    if frag_off & 0x1FFF != 0 {
        return None;
    }
    if offender.len() < off_iph_len + 8 {
        debug!("not sending net unreachable: offender shorter than iph + 8");
        return None;
    }

    // iphdr + icmphdr + offender's iph + first 8 payload bytes.
    let pktlen = IPHDR_LEN + 8 + off_iph_len + 8;
    let mut pkt = vec![0u8; pktlen];

    // Reply IP header (C: memset pkt then fill).
    pkt[0] = 0x45; // IPVERSION=4, ihl=5
    pkt[2..4].copy_from_slice(&(pktlen as u16).to_be_bytes()); // tot_len
    pkt[8] = 8; // C: ttl = 8
    pkt[9] = PROTO_ICMP;
    pkt[12..16].copy_from_slice(&tun_addr.to_ne_bytes()); // saddr
    pkt[16..20].copy_from_slice(&offender[12..16]); // daddr = offender saddr
    let ip_check = cksum(&pkt[..IPHDR_LEN]);
    pkt[10..12].copy_from_slice(&ip_check.to_ne_bytes());

    // ICMP header: type 3 (dest unreachable), code 0 (net unreachable).
    pkt[20] = ICMP_DEST_UNREACH;
    pkt[21] = ICMP_NET_UNREACH;

    // Copy the offender's IP hdr + first 8 bytes of IP payload.
    pkt[28..28 + off_iph_len + 8].copy_from_slice(&offender[..off_iph_len + 8]);
    let icmp_check = cksum(&pkt[20..]);
    pkt[22..24].copy_from_slice(&icmp_check.to_ne_bytes());

    Some(pkt)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Classic sample header (zeroed check):
    /// 45 00 00 3c 1c 46 40 00 40 06 00 00 ac 10 0a 63 ac 10 0a 0c.
    /// The on-wire checksum is b1 e6.
    const SAMPLE_HDR: [u8; 20] = [
        0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xac, 0x10, 0x0a,
        0x63, 0xac, 0x10, 0x0a, 0x0c,
    ];

    #[test]
    fn cksum_known_vector() {
        assert_eq!(cksum(&SAMPLE_HDR).to_ne_bytes(), [0xb1, 0xe6]);
    }

    #[test]
    fn decrement_ttl_patches_checksum() {
        let mut buf = SAMPLE_HDR.to_vec();
        buf[10..12].copy_from_slice(&[0xb1, 0xe6]); // valid checksum
        assert!(decrement_ttl(&mut buf));
        assert_eq!(buf[8], 63); // ttl 64 -> 63
        assert_eq!(&buf[10..12], &[0xb2, 0xe6]);
        // A valid header checksums to zero when the check field is
        // included in the sum.
        assert_eq!(cksum(&buf), 0);
    }

    #[test]
    fn decrement_ttl_zero_ttl_discards() {
        let mut buf = SAMPLE_HDR.to_vec();
        buf[10..12].copy_from_slice(&[0xb1, 0xe6]);
        buf[8] = 1;
        assert!(!decrement_ttl(&mut buf));
        assert_eq!(buf[8], 0);
    }

    #[test]
    fn decrement_ttl_wraps_zero_ttl_like_c() {
        // C decrements before the zero check, so ttl 0 wraps to 255 and
        // the packet is kept.
        let mut buf = SAMPLE_HDR.to_vec();
        buf[10..12].copy_from_slice(&[0xb1, 0xe6]);
        buf[8] = 0;
        assert!(decrement_ttl(&mut buf));
        assert_eq!(buf[8], 255);
    }

    /// Offender 10.1.1.1 -> 10.99.1.2, ttl 64, UDP, 8 payload bytes.
    fn offender() -> Vec<u8> {
        let mut off = vec![0u8; 28];
        off[0] = 0x45;
        off[2..4].copy_from_slice(&28u16.to_be_bytes());
        off[8] = 64;
        off[9] = 17;
        off[12..16].copy_from_slice(&[10, 1, 1, 1]);
        off[16..20].copy_from_slice(&[10, 99, 1, 2]);
        let c = cksum(&off[..20]);
        off[10..12].copy_from_slice(&c.to_ne_bytes());
        off[20..].copy_from_slice(&[9, 9, 9, 9, 8, 8, 8, 8]);
        off
    }

    #[test]
    fn build_net_unreachable_packet() {
        let tun_addr = u32::from_ne_bytes([10, 99, 0, 1]);
        let pkt = build_net_unreachable(&offender(), tun_addr).expect("icmp built");
        assert_eq!(pkt.len(), 20 + 8 + 28);
        // Reply IP header.
        assert_eq!(pkt[0], 0x45);
        assert_eq!(&pkt[2..4], &56u16.to_be_bytes());
        assert_eq!(pkt[8], 8); // C: ttl = 8
        assert_eq!(pkt[9], 1); // ICMP
        assert_eq!(&pkt[12..16], &[10, 99, 0, 1]);
        assert_eq!(&pkt[16..20], &[10, 1, 1, 1]);
        assert_eq!(cksum(&pkt[..20]), 0);
        // ICMP net unreachable + offender iph and first 8 payload bytes.
        assert_eq!(pkt[20], 3);
        assert_eq!(pkt[21], 0);
        assert_eq!(&pkt[28..56], &offender()[..28]);
        assert_eq!(cksum(&pkt[20..]), 0);
    }

    #[test]
    fn build_net_unreachable_skip_cases() {
        let tun_addr = u32::from_ne_bytes([10, 99, 0, 1]);
        // ICMP about ICMP is never sent.
        let mut off = offender();
        off[9] = 1;
        assert!(build_net_unreachable(&off, tun_addr).is_none());
        // Non-first fragment (offset != 0) is skipped.
        let mut off = offender();
        off[6..8].copy_from_slice(&[0x20, 0x01]);
        assert!(build_net_unreachable(&off, tun_addr).is_none());
        // MF flag alone (offset zero) still gets a reply.
        let mut off = offender();
        off[6] = 0x20;
        assert!(build_net_unreachable(&off, tun_addr).is_some());
        // Malformed ihl.
        let mut off = offender();
        off[0] = 0x4F; // ihl 15 -> 60 bytes >= 20 + MAX_IPOPTLEN
        assert!(build_net_unreachable(&off, tun_addr).is_none());
        // Shorter than header + 8 payload bytes.
        let off = offender();
        assert!(build_net_unreachable(&off[..24], tun_addr).is_none());
    }
}
