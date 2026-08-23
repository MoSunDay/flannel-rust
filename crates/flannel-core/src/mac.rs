//! Port of pkg/mac/mac.go: random locally-administered unicast MAC addresses.

use std::io;

/// 6-byte hardware (MAC) address (Go: net.HardwareAddr).
pub type MacAddr = [u8; 6];

/// Generate a new random hardware (MAC) address, local and unicast
/// (Go: `mac.NewHardwareAddr`).
///
/// Go fills 6 bytes from crypto/rand; here the first 6 bytes of a random
/// v4 UUID provide the randomness (bytes 0..6 of a v4 UUID are fully
/// random), after which the same bit handling is applied.
pub fn new_hardware_addr() -> io::Result<MacAddr> {
    let random = uuid::Uuid::new_v4().into_bytes();
    let mut hardware_addr = [0u8; 6];
    hardware_addr.copy_from_slice(&random[..6]);

    // Ensure that address is locally administered and unicast.
    hardware_addr[0] = (hardware_addr[0] & 0xfe) | 0x02;

    Ok(hardware_addr)
}

/// Format a MAC address exactly like Go's `net.HardwareAddr.String()`
/// (`aa:bb:cc:dd:ee:ff`, lowercase hex, colon-separated).
pub fn mac_to_string(addr: &MacAddr) -> String {
    addr.iter()
        .map(|octet| format!("{octet:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;

    // Faithful port of TestNewHardwareAddr: ignore the actual address, since
    // it's random. But an error should never be returned.
    #[test]
    fn test_new_hardware_addr() {
        if let Err(err) = new_hardware_addr() {
            panic!("err: {err}");
        }
    }

    #[test]
    fn test_new_hardware_addr_bits() {
        // Randomness sanity: addresses differ and always carry the
        // locally-administered bit set and the unicast (multicast) bit clear.
        let first = new_hardware_addr().unwrap();
        let mut saw_different = false;
        for _ in 0..16 {
            let addr = new_hardware_addr().unwrap();
            assert_eq!(addr[0] & 0x02, 0x02, "locally administered bit set");
            assert_eq!(addr[0] & 0x01, 0x00, "unicast bit clear");
            if addr != first {
                saw_different = true;
            }
        }
        assert!(saw_different, "expected random addresses to differ");
    }

    #[test]
    fn test_mac_to_string() {
        assert_eq!(
            mac_to_string(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            "aa:bb:cc:dd:ee:ff"
        );
        assert_eq!(
            mac_to_string(&[0x00, 0x01, 0x02, 0x03, 0x04, 0x05]),
            "00:01:02:03:04:05"
        );
    }

    #[test]
    fn test_new_hardware_addr_roundtrip_format() {
        let addr = new_hardware_addr().unwrap();
        let s = mac_to_string(&addr);
        let parts: Vec<&str> = s.split(':').collect();
        assert_eq!(parts.len(), 6);
        for (octet, part) in addr.iter().zip(parts.iter()) {
            assert_eq!(u8::from_str_radix(part, 16).unwrap(), *octet);
        }
    }
}
