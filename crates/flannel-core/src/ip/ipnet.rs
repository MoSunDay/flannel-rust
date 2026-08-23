//! IPv4 address/network arithmetic. Port of flannel `pkg/ip/ipnet.go`
//! (upstream cdf76059), plus the subnet helpers `subnet/config.go` computes
//! inline (upstream master: GetSubnetMin/GetSubnetMax/CheckSubnet/Broadcast).
//!
//! Endianness (`pkg/ip/endianess.go`): Go's `Htonl`/`Ntohl`/`NetworkOrder`
//! are exactly `u32::to_be`/`u32::from_be` (`Htons`/`Ntohs` the `u16`
//! variants), so no separate helpers are needed.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

/// IPv4 address stored host-order with the first octet most significant
/// (10.0.0.1 == 0x0A00_0001), mirroring Go's `type IP4 uint32`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IP4(pub u32);

/// IPv4 network: address + prefix length, mirroring Go's `ip.IP4Net`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct IP4Net {
    pub ip: IP4,
    pub prefix_len: u32,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IP4ParseError {
    #[error("invalid IPv4 address: {0}")]
    InvalidAddr(String),
    #[error("invalid IPv4 network: {0}")]
    InvalidNet(String),
}

impl IP4 {
    pub const fn new(v: u32) -> Self {
        Self(v)
    }

    /// Build from four octets: `from_octets(10, 0, 0, 1)` == 10.0.0.1.
    pub const fn from_octets(a: u8, b: u8, c: u8, d: u8) -> Self {
        Self(((a as u32) << 24) | ((b as u32) << 16) | ((c as u32) << 8) | d as u32)
    }

    /// Go: `FromBytes` (big-endian bytes).
    pub const fn from_bytes(bytes: [u8; 4]) -> Self {
        Self(u32::from_be_bytes(bytes))
    }

    /// Go: `Octets`.
    pub const fn octets(self) -> [u8; 4] {
        self.0.to_be_bytes()
    }

    /// Go: `ToIP`.
    pub const fn to_std(self) -> std::net::Ipv4Addr {
        let [a, b, c, d] = self.octets();
        std::net::Ipv4Addr::new(a, b, c, d)
    }

    /// Go: `NetworkOrder`. Identical to `u32::to_be` on every platform.
    pub const fn network_order(self) -> u32 {
        self.0.to_be()
    }

    /// Go: `StringSep`.
    pub fn string_sep(self, sep: &str) -> String {
        let [a, b, c, d] = self.octets();
        format!("{a}{sep}{b}{sep}{c}{sep}{d}")
    }

    /// Go: `IsPrivate` (RFC 1918).
    pub fn is_private(self) -> bool {
        let [a, b, ..] = self.octets();
        a == 10 || (a == 172 && b & 0xf0 == 16) || (a == 192 && b == 168)
    }
}

impl fmt::Display for IP4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d] = self.octets();
        write!(f, "{a}.{b}.{c}.{d}")
    }
}

impl FromStr for IP4 {
    type Err = IP4ParseError;

    /// Go: `ParseIP4`. Rejects IPv6 strings, as Go does via `To4() == nil`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let std_ip: std::net::Ipv4Addr = s
            .parse()
            .map_err(|_| IP4ParseError::InvalidAddr(s.to_string()))?;
        Ok(Self(u32::from(std_ip)))
    }
}

// Go `MarshalJSON`: `"10.0.0.1"`; Go `UnmarshalJSON` accepts only a quoted
// string (a JSON number fails `ParseIP4`), matching the string-based impl.
impl Serialize for IP4 {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for IP4 {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        String::deserialize(de)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// Go: `1 << (32 - PrefixLen)`. A /0 (or invalid > /32) network shifts by
/// >= 32 bits, which Go's uint32 evaluates to 0 (2^32 does not fit).
const fn subnet_size(prefix_len: u32) -> u32 {
    if prefix_len == 0 || prefix_len > 32 {
        0
    } else {
        1u32 << (32 - prefix_len)
    }
}

/// Go: `0xFFFFFFFF << (32 - prefixLen)`. /0 and > /32 mask to 0, matching
/// Go's uint32 shift semantics.
const fn mask_value(bits: u32) -> u32 {
    if bits == 0 || bits > 32 {
        0
    } else {
        u32::MAX << (32 - bits)
    }
}

impl IP4Net {
    pub const fn new(ip: IP4, prefix_len: u32) -> Self {
        Self { ip, prefix_len }
    }

    /// Go: `func (n IP4Net) Mask() uint32`.
    pub const fn mask(self) -> u32 {
        mask_value(self.prefix_len)
    }

    /// Go: `StringSep`.
    pub fn string_sep(self, octet_sep: &str, prefix_sep: &str) -> String {
        let ip = self.ip.string_sep(octet_sep);
        format!("{ip}{prefix_sep}{}", self.prefix_len)
    }

    /// Go: `Network`.
    pub fn network(self) -> IP4Net {
        IP4Net {
            ip: IP4(self.ip.0 & self.mask()),
            prefix_len: self.prefix_len,
        }
    }

    /// Go (upstream master): `ClearHostBits` — same arithmetic as `Network`.
    pub fn clear_host_bits(self) -> IP4Net {
        self.network()
    }

    /// Go: `Next` — the sibling network of the same size (uint32 wraps).
    pub fn next(self) -> IP4Net {
        IP4Net {
            ip: IP4(self.ip.0.wrapping_add(subnet_size(self.prefix_len))),
            prefix_len: self.prefix_len,
        }
    }

    /// Increment the address in place (Go: `func (n *IP4Net) IncrementIP()`).
    pub fn increment_ip(&mut self) {
        self.ip.0 += 1;
    }

    /// Go: `ToIPNet`. Host bits of `ip` are kept, as Go keeps `n.IP`.
    pub fn to_std_cidr(self) -> Result<ipnet::Ipv4Net, IP4ParseError> {
        let err = || IP4ParseError::InvalidNet(self.to_string());
        let plen = u8::try_from(self.prefix_len).map_err(|_| err())?;
        ipnet::Ipv4Net::new(self.ip.to_std(), plen).map_err(|_| err())
    }

    /// Go: `Overlaps`.
    pub fn overlaps(self, other: IP4Net) -> bool {
        let m = if self.prefix_len < other.prefix_len {
            self.mask()
        } else {
            other.mask()
        };
        (self.ip.0 & m) == (other.ip.0 & m)
    }

    /// Go: `Contains`.
    pub fn contains(self, ip: IP4) -> bool {
        (self.ip.0 & self.mask()) == (ip.0 & self.mask())
    }

    /// Go: `ContainsCIDR`.
    pub fn contains_cidr(self, other: IP4Net) -> bool {
        self.mask() <= other.mask() && self.contains(other.ip)
    }

    /// Go: `Empty`.
    pub fn empty(self) -> bool {
        self.ip.0 == 0 && self.prefix_len == 0
    }

    /// Go (upstream master): `Broadcast` — `n.IP | ^n.Mask()`.
    pub fn broadcast(self) -> IP4 {
        IP4(self.ip.0 | !self.mask())
    }
}

impl fmt::Display for IP4Net {
    /// Go: `String`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.ip, self.prefix_len)
    }
}

impl FromStr for IP4Net {
    type Err = IP4ParseError;

    /// Mirrors Go `UnmarshalJSON` (`net.ParseCIDR` + `FromIPNet`): the
    /// prefix must be <= 32 and the address is masked to the network
    /// address (host bits cleared), exactly like `net.ParseCIDR`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr, prefix) = s
            .split_once('/')
            .ok_or_else(|| IP4ParseError::InvalidNet(s.to_string()))?;
        let prefix_len: u32 = prefix
            .parse()
            .map_err(|_| IP4ParseError::InvalidNet(s.to_string()))?;
        if prefix_len > 32 {
            return Err(IP4ParseError::InvalidNet(s.to_string()));
        }
        let ip: IP4 = addr.parse()?;
        Ok(IP4Net { ip, prefix_len }.network())
    }
}

impl Serialize for IP4Net {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for IP4Net {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        String::deserialize(de)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// Go: `MapIP4ToString`.
pub fn map_ip4_to_string(nws: &[IP4Net]) -> Vec<String> {
    nws.iter().map(|n| n.to_string()).collect()
}

/// Go (`subnet/config.go`: `SubnetMin = Network.IP + subnetSize`; upstream
/// master `GetSubnetMin`). Wraps mod 2^32 like Go's uint32.
pub fn get_subnet_min(network: IP4, subnet_size: u32) -> IP4 {
    IP4(network.0.wrapping_add(subnet_size))
}

/// Go (`subnet/config.go`: `SubnetMax = Network.Next().IP - subnetSize`;
/// upstream master `GetSubnetMax`). Wraps mod 2^32 like Go's uint32.
pub fn get_subnet_max(network: IP4, subnet_size: u32) -> IP4 {
    IP4(network.0.wrapping_sub(subnet_size))
}

/// IPv4 network mask for a prefix length (Go: `0xFFFFFFFF << (32 - bits)`
/// as used in `subnet/config.go`; the IPv6 counterpart is `mask6`).
pub const fn mask(bits: u32) -> IP4 {
    IP4(mask_value(bits))
}

/// Go (`subnet/config.go`: `SubnetMin == SubnetMin & mask`; upstream master
/// `CheckSubnet`): true when `subnet` lies on a `mask` boundary.
pub fn check_subnet(subnet: IP4, mask: IP4) -> bool {
    IP4(subnet.0 & mask.0) == subnet
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_ip4(s: &str) -> IP4 {
        s.parse().unwrap() // Go: MustParseIP4
    }

    fn mk_ip4_net(s: &str, plen: u32) -> IP4Net {
        IP4Net::new(mk_ip4(s), plen) // Go: mkIP4Net
    }

    #[test]
    fn test_ip4() {
        let ip = mk_ip4("1.2.3.4");
        assert_eq!(ip.octets(), [1, 2, 3, 4]); // FromIP/Octets
        assert_eq!(ip.to_std().to_string(), "1.2.3.4"); // ToIP
        assert_eq!(ip.to_string(), "1.2.3.4"); // String
        assert_eq!(ip.string_sep("*"), "1*2*3*4"); // StringSep
        assert!("2001:db8::1".parse::<IP4>().is_err()); // rejects IPv6
        assert_eq!(serde_json::to_string(&ip).unwrap(), "\"1.2.3.4\"");

        for (addr, private) in [
            ("192.168.0.1", true),
            ("172.16.0.1", true),
            ("172.31.0.1", true),
            ("10.1.2.3", true),
            ("8.8.8.8", false),
            ("172.32.0.1", false),
            ("192.167.0.1", false),
            ("192.169.0.1", false),
        ] {
            assert_eq!(mk_ip4(addr).is_private(), private, "{addr}");
        }
    }

    #[test]
    fn test_ip4_net() {
        let mut n1 = mk_ip4_net("1.2.3.0", 24);
        assert_eq!(n1.to_std_cidr().unwrap().to_string(), "1.2.3.0/24"); // ToIPNet

        assert!(n1.overlaps(n1));
        assert!(n1.overlaps(mk_ip4_net("1.2.0.0", 16)));
        assert!(!n1.overlaps(mk_ip4_net("1.2.4.0", 24)));
        assert!(!n1.overlaps(mk_ip4_net("7.2.4.0", 22)));

        assert!(n1.contains(mk_ip4("1.2.3.0")));
        assert!(n1.contains(mk_ip4("1.2.3.4")));
        assert!(!n1.contains(mk_ip4("1.2.4.0")));

        assert_eq!(serde_json::to_string(&n1).unwrap(), "\"1.2.3.0/24\"");
        // Go: UnmarshalJSON rejects IPv6 CIDRs for IP4Net.
        assert!(serde_json::from_str::<IP4Net>("\"2001:db8::/64\"").is_err());

        n1.increment_ip();
        assert_eq!(n1.to_string(), "1.2.3.1/24");
    }

    #[test]
    fn test_ip4_net_arithmetic() {
        // Empty (Go: zero value of IP4Net).
        assert!(IP4Net::default().empty());
        assert!(mk_ip4_net("0.0.0.0", 0).empty());
        assert!(!mk_ip4_net("0.0.0.0", 24).empty());
        assert!(!mk_ip4_net("1.2.3.0", 24).empty());

        // Mask.
        assert_eq!(mask(0), IP4(0));
        assert_eq!(mask(8), IP4(0xFF00_0000));
        assert_eq!(mask(24), IP4(0xFFFF_FF00));
        assert_eq!(mask(32), IP4(0xFFFF_FFFF));
        assert_eq!(mk_ip4_net("1.2.3.0", 24).mask(), 0xFFFF_FF00);

        // Network / ClearHostBits / Broadcast.
        assert_eq!(
            mk_ip4_net("1.2.3.5", 24).network(),
            mk_ip4_net("1.2.3.0", 24)
        );
        assert_eq!(
            mk_ip4_net("1.2.3.5", 24).clear_host_bits(),
            mk_ip4_net("1.2.3.0", 24)
        );
        assert_eq!(mk_ip4_net("1.2.3.0", 24).broadcast(), mk_ip4("1.2.3.255"));

        // Next.
        assert_eq!(mk_ip4_net("1.2.3.0", 24).next(), mk_ip4_net("1.2.4.0", 24));
        assert_eq!(mk_ip4_net("10.0.0.0", 8).next(), mk_ip4_net("11.0.0.0", 8));

        // Subnet min/max/boundary check (subnet/config.go, 10.100.0.0/16 + /24s).
        let net = mk_ip4_net("10.100.0.0", 16);
        let size = 1u32 << (32 - 24);
        let min = get_subnet_min(net.ip, size);
        let max = get_subnet_max(net.next().ip, size);
        assert_eq!(min, mk_ip4("10.100.1.0"));
        assert_eq!(max, mk_ip4("10.100.255.0")); // 10.101.0.0 - 256
        assert!(check_subnet(min, mask(24)));
        assert!(!check_subnet(IP4(min.0 + 1), mask(24)));

        // Serde: Go UnmarshalJSON masks host bits; empty string is an error.
        let parsed: IP4Net = serde_json::from_str("\"1.2.3.5/24\"").unwrap();
        assert_eq!(parsed, mk_ip4_net("1.2.3.0", 24));
        assert!(serde_json::from_str::<IP4Net>("\"\"").is_err());
        assert!("1.2.3.0/33".parse::<IP4Net>().is_err());
        // Zero value round-trips (Go zero IP4Net from net-conf.json).
        assert_eq!(IP4Net::default().to_string(), "0.0.0.0/0");
        let nets = [mk_ip4_net("10.0.0.0", 8), mk_ip4_net("10.1.0.0", 16)];
        let strs = vec!["10.0.0.0/8".to_string(), "10.1.0.0/16".to_string()];
        assert_eq!(map_ip4_to_string(&nets), strs);
    }
}
