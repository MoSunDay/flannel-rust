//! IPv6 address/network arithmetic. Port of flannel `pkg/ip/ip6net.go`
//! (upstream cdf76059).
//!
//! Go uses `math/big.Int` for the 128-bit values; this port uses `u128`.
//! Operations whose Go result exceeds 128 bits wrap modulo 2^128 here
//! (e.g. `next()` of a /0 adds 2^128, `get_ipv6_subnet_max` below zero),
//! where Go's big.Int would keep growing or go negative. All realistic
//! prefixes (/1 through /128) behave identically.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

/// IPv6 address as 16 big-endian bytes, mirroring Go's `type IP6 big.Int`
/// (which always holds the canonical big-endian value of the address).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IP6(pub [u8; 16]);

/// IPv6 network: address + prefix length, mirroring Go's `ip.IP6Net`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct IP6Net {
    pub ip: IP6,
    pub prefix_len: u32,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IP6ParseError {
    #[error("invalid IPv6 address: {0}")]
    InvalidAddr(String),
    #[error("invalid IPv6 network: {0}")]
    InvalidNet(String),
}

const fn ip6_value(ip: IP6) -> u128 {
    u128::from_be_bytes(ip.0)
}

const fn ip6_from_value(v: u128) -> IP6 {
    IP6(v.to_be_bytes())
}

impl IP6 {
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Go: `FromIP16Bytes` / `FromIP6`.
    pub const fn from_std(ip: std::net::Ipv6Addr) -> Self {
        Self(ip.octets())
    }

    /// Go: `ToIP`. Note: Go renders values <= 0xFFFF_FFFF as dotted IPv4
    /// (a big.Int quirk); Rust always renders canonical IPv6 form.
    pub fn to_std(self) -> std::net::Ipv6Addr {
        std::net::Ipv6Addr::from(self.0)
    }

    /// Go: `IsPrivate` (RFC 4193 ULA, fc00::/7). Go inspects the most
    /// significant non-zero big.Int byte; on the fixed 16-byte representation
    /// this is simply the first byte.
    pub fn is_private(self) -> bool {
        self.0[0] & 0xfe == 0xfc
    }
}

impl fmt::Display for IP6 {
    /// Go: `String` — canonical RFC 5952 form, same as Rust's Ipv6Addr.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_std())
    }
}

impl FromStr for IP6 {
    type Err = IP6ParseError;

    /// Go: `ParseIP6`. (Go additionally accepts dotted-IPv4 strings, which
    /// it maps to ::ffff:a.b.c.d; Rust is stricter.)
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let std_ip: std::net::Ipv6Addr = s
            .parse()
            .map_err(|_| IP6ParseError::InvalidAddr(s.to_string()))?;
        Ok(Self(std_ip.octets()))
    }
}

// Go `MarshalJSON`: `"fc00::1"`; Go `UnmarshalJSON` accepts only a quoted
// string, matching the string-based impl. Go's `Cmp` is the derived Ord.
impl Serialize for IP6 {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for IP6 {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        String::deserialize(de)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// Go: `IsEmpty` (nil or zero in Go; Rust has no nil, so zero only).
pub fn is_empty(subnet: IP6) -> bool {
    subnet.0 == [0u8; 16]
}

/// Go: `GetIPv6SubnetMin` (big.Int Add; wraps mod 2^128 in u128).
pub fn get_ipv6_subnet_min(network_ip: IP6, subnet_size: u128) -> IP6 {
    ip6_from_value(ip6_value(network_ip).wrapping_add(subnet_size))
}

/// Go: `GetIPv6SubnetMax` (big.Int Sub; wraps mod 2^128 in u128).
pub fn get_ipv6_subnet_max(network_ip: IP6, subnet_size: u128) -> IP6 {
    ip6_from_value(ip6_value(network_ip).wrapping_sub(subnet_size))
}

/// Go: `CheckIPv6Subnet` — true when `subnet_ip` lies on the `mask`
/// boundary, i.e. `subnet_ip == subnet_ip & mask`.
pub fn check_ipv6_subnet(subnet_ip: IP6, mask: IP6) -> bool {
    let subnet = ip6_value(subnet_ip);
    subnet & ip6_value(mask) == subnet
}

/// Go: free `Mask(prefixLen int)` (net.CIDRMask over 128 bits). Like Go,
/// out-of-range prefix lengths (> 128) yield the zero mask; /0 masks to 0.
pub const fn mask6(bits: u32) -> IP6 {
    if bits == 0 || bits > 128 {
        IP6([0u8; 16])
    } else {
        IP6((u128::MAX << (128 - bits)).to_be_bytes())
    }
}

/// Go: `1 << (128 - PrefixLen)`. A /0 network would shift by 128 bits,
/// which cannot fit in u128 (Go's big.Int grows past 128 bits there);
/// this returns 0 so /0 arithmetic wraps as documented above.
const fn subnet_size6(prefix_len: u32) -> u128 {
    if prefix_len == 0 || prefix_len > 128 {
        0
    } else {
        1u128 << (128 - prefix_len)
    }
}

impl IP6Net {
    pub const fn new(ip: IP6, prefix_len: u32) -> Self {
        Self { ip, prefix_len }
    }

    /// Go: `func (n IP6Net) Mask() *big.Int`.
    pub const fn mask(self) -> IP6 {
        mask6(self.prefix_len)
    }

    /// Go: `StringSep` (Go ignores the hex separator for IPv6).
    pub fn string_sep(self, _hex_sep: &str, prefix_sep: &str) -> String {
        format!("{}{}{}", self.ip, prefix_sep, self.prefix_len)
    }

    /// Go: `Network`.
    pub fn network(self) -> IP6Net {
        IP6Net {
            ip: ip6_from_value(ip6_value(self.ip) & ip6_value(self.mask())),
            prefix_len: self.prefix_len,
        }
    }

    /// Port of Go (upstream master) `ClearHostBits` for IPv4 — same
    /// arithmetic as `Network`.
    pub fn clear_host_bits(self) -> IP6Net {
        self.network()
    }

    /// Go: `Next` — the sibling network of the same size (u128 wraps).
    pub fn next(self) -> IP6Net {
        IP6Net {
            ip: ip6_from_value(ip6_value(self.ip).wrapping_add(subnet_size6(self.prefix_len))),
            prefix_len: self.prefix_len,
        }
    }

    /// Increment the address in place (Go: `func (n *IP6Net) IncrementIP()`).
    pub fn increment_ip(&mut self) {
        self.ip = ip6_from_value(ip6_value(self.ip).wrapping_add(1));
    }

    /// Go: `ToIPNet`. Host bits of `ip` are kept, as Go keeps `n.IP`.
    pub fn to_std_cidr(self) -> Result<ipnet::Ipv6Net, IP6ParseError> {
        let err = || IP6ParseError::InvalidNet(self.to_string());
        let plen = u8::try_from(self.prefix_len).map_err(|_| err())?;
        ipnet::Ipv6Net::new(self.ip.to_std(), plen).map_err(|_| err())
    }

    /// Go: `Overlaps`.
    pub fn overlaps(self, other: IP6Net) -> bool {
        let m = if self.prefix_len < other.prefix_len {
            ip6_value(self.mask())
        } else {
            ip6_value(other.mask())
        };
        (ip6_value(self.ip) & m) == (ip6_value(other.ip) & m)
    }

    /// Go: `Contains`.
    pub fn contains(self, ip: IP6) -> bool {
        let m = ip6_value(self.mask());
        (ip6_value(self.ip) & m) == (ip6_value(ip) & m)
    }

    /// Go: `ContainsCIDR`.
    pub fn contains_cidr(self, other: IP6Net) -> bool {
        ip6_value(self.mask()) <= ip6_value(other.mask()) && self.contains(other.ip)
    }

    /// Go: `Empty`.
    pub fn empty(self) -> bool {
        is_empty(self.ip) && self.prefix_len == 0
    }
}

impl fmt::Display for IP6Net {
    /// Go: `String` (a nil IP prints as "::"; the Default IP6 does the same).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.ip, self.prefix_len)
    }
}

impl FromStr for IP6Net {
    type Err = IP6ParseError;

    /// Mirrors Go `UnmarshalJSON` (`net.ParseCIDR` + `FromIP6Net`): the
    /// prefix must be <= 128 and the address is masked to the network
    /// address (host bits cleared), exactly like `net.ParseCIDR`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr, prefix) = s
            .split_once('/')
            .ok_or_else(|| IP6ParseError::InvalidNet(s.to_string()))?;
        let prefix_len: u32 = prefix
            .parse()
            .map_err(|_| IP6ParseError::InvalidNet(s.to_string()))?;
        if prefix_len > 128 {
            return Err(IP6ParseError::InvalidNet(s.to_string()));
        }
        let ip: IP6 = addr.parse()?;
        Ok(IP6Net { ip, prefix_len }.network())
    }
}

impl Serialize for IP6Net {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for IP6Net {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        String::deserialize(de)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// Go: `MapIP6ToString`.
pub fn map_ip6_to_string(nws: &[IP6Net]) -> Vec<String> {
    nws.iter().map(|n| n.to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_ip6(s: &str) -> IP6 {
        s.parse().unwrap() // Go: MustParseIP6
    }

    fn mk_ip6_net(s: &str, plen: u32) -> IP6Net {
        IP6Net::new(mk_ip6(s), plen) // Go: mkIP6Net
    }

    #[test]
    fn test_ip6() {
        assert_eq!(
            IP6::from_std("fc00::1".parse().unwrap()).to_string(),
            "fc00::1"
        );
        let zero = IP6::from_std("::".parse().unwrap());
        assert_eq!(zero.to_string(), "::");
        assert!(is_empty(zero));

        let ip = mk_ip6("fc00::1");
        assert_eq!(ip.to_string(), "fc00::1");
        assert_eq!(ip.to_std().to_string(), "fc00::1");
        assert_eq!(serde_json::to_string(&ip).unwrap(), "\"fc00::1\"");

        for (addr, private) in [
            ("fc00::1", true),
            ("fcff::1", true),
            ("fd00::1", true),
            ("fdff::1", true),
            ("2001::", false),
            ("fe00::", false),
        ] {
            assert_eq!(mk_ip6(addr).is_private(), private, "{addr}");
        }
    }

    #[test]
    fn test_ip6_net() {
        let empty = IP6Net::default(); // Go: var n IP6Net
        assert!(empty.empty());
        assert!(mk_ip6_net("::", 0).empty());
        assert!(!mk_ip6_net("::", 64).empty());

        let mut n1 = mk_ip6_net("fc00:1::", 64);
        assert!(!n1.empty());
        assert_eq!(n1.to_std_cidr().unwrap().to_string(), "fc00:1::/64"); // ToIPNet

        assert!(n1.overlaps(n1));
        assert!(n1.overlaps(mk_ip6_net("fc00::", 16)));
        assert!(!n1.overlaps(mk_ip6_net("fc00:2::", 64)));
        assert!(!n1.overlaps(mk_ip6_net("fb00:2::", 48)));

        assert!(n1.contains(mk_ip6("fc00:1::")));
        assert!(n1.contains(mk_ip6("fc00:1::1")));
        assert!(!n1.contains(mk_ip6("fc00:2::")));

        assert_eq!(serde_json::to_string(&n1).unwrap(), "\"fc00:1::/64\"");

        n1.increment_ip();
        assert_eq!(n1.to_string(), "fc00:1::1/64");
    }

    #[test]
    fn test_ip6_net_arithmetic() {
        // Mask.
        assert_eq!(mask6(0), IP6([0u8; 16]));
        assert_eq!(mask6(64).0[..8], [0xff; 8]);
        assert_eq!(mask6(64).0[8..], [0u8; 8]);
        assert_eq!(mask6(128), IP6([0xff; 16]));
        assert_eq!(mask6(129), IP6([0u8; 16])); // Go CIDRMask -> nil -> 0
        assert_eq!(mk_ip6_net("fc00::", 16).mask(), mask6(16));

        // Network / ClearHostBits / Next.
        assert_eq!(
            mk_ip6_net("fc00:1::1", 64).network(),
            mk_ip6_net("fc00:1::", 64)
        );
        assert_eq!(
            mk_ip6_net("fc00:1::1", 64).clear_host_bits(),
            mk_ip6_net("fc00:1::", 64)
        );
        assert_eq!(
            mk_ip6_net("fc00:1::", 64).next(),
            mk_ip6_net("fc00:1:0:1::", 64)
        );
        assert_eq!(
            mk_ip6_net("fc00::", 48).next(),
            mk_ip6_net("fc00:0:1::", 48)
        );

        // Subnet min/max/boundary check (subnet/config.go, fc00::/48 + /64s).
        let net = mk_ip6_net("fc00::", 48);
        let size = 1u128 << (128 - 64);
        let min = get_ipv6_subnet_min(net.ip, size);
        let max = get_ipv6_subnet_max(net.next().ip, size);
        assert_eq!(min, mk_ip6("fc00:0:0:1::"));
        assert_eq!(max, mk_ip6("fc00:0:0:ffff::")); // fc00:0:1:: - 2^64
        assert!(check_ipv6_subnet(min, mask6(64)));
        assert!(!check_ipv6_subnet(
            ip6_from_value(ip6_value(min) + 1),
            mask6(64)
        ));

        // Serde: Go UnmarshalJSON masks host bits; empty string is an error.
        let parsed: IP6Net = serde_json::from_str("\"fc00:1::1/64\"").unwrap();
        assert_eq!(parsed, mk_ip6_net("fc00:1::", 64));
        assert!(serde_json::from_str::<IP6Net>("\"\"").is_err());
        assert!("fc00::/129".parse::<IP6Net>().is_err());
        // Zero value round-trips (Go zero IP6Net from net-conf.json).
        assert_eq!(IP6Net::default().to_string(), "::/0");
        assert_eq!(
            map_ip6_to_string(&[mk_ip6_net("fc00::", 48)]),
            vec!["fc00::/48".to_string()]
        );
    }
}
