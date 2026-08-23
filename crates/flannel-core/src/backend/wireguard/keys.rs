//! Port of `wgtypes.Key` semantics from wgctrl-go/wgtypes as used by
//! pkg/backend/wireguard/device.go (upstream cdf76059): RFC 7748-clamped
//! private key generation, X25519 public key derivation and the padded
//! standard base64 text form (`Key.String()` / `wgtypes.ParseKey`).

use anyhow::anyhow;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use curve25519_dalek::montgomery::MontgomeryPoint;
use std::fmt;

/// A 32-byte WireGuard key (Go: `wgtypes.Key`). Used for private keys,
/// public keys and preshared keys alike.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Key(pub [u8; 32]);

impl Key {
    /// Go: `wgtypes.GeneratePrivateKey` -- fill 32 bytes from the OS
    /// RNG, then clamp per RFC 7748 section 5.
    pub fn generate_private_key() -> anyhow::Result<Key> {
        let mut b = [0u8; 32];
        getrandom::getrandom(&mut b).map_err(|e| anyhow!("getrandom: {e}"))?;
        b[0] &= 248;
        b[31] &= 127;
        b[31] |= 64;
        Ok(Key(b))
    }

    /// Go: `Key.PublicKey()` -- X25519 scalar-base multiplication of the
    /// already-clamped private key.
    pub fn public_key(&self) -> Key {
        Key(MontgomeryPoint::mul_base_clamped(self.0).to_bytes())
    }

    /// Go: `wgtypes.ParseKey` -- standard base64, exactly 32 bytes.
    pub fn parse(s: &str) -> anyhow::Result<Key> {
        let b = STANDARD
            .decode(s)
            .map_err(|e| anyhow!("failed to parse base64 key: {e}"))?;
        let bytes: [u8; 32] = b
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("key must be 32 bytes: {}", b.len()))?;
        Ok(Key(bytes))
    }
}

/// Go: `Key.String()` -- padded standard base64 encoding.
impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", STANDARD.encode(self.0))
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print key material; the base64 form is public-key safe
        // only for public keys, so stay opaque for all key kinds.
        f.debug_tuple("Key").finish()
    }
}

#[cfg(test)]
mod tests {
    use super::Key;
    use base64::Engine;

    /// RFC 7748 section 6.1 Alice private key.
    const ALICE_PRIV_HEX: &str = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    /// RFC 7748 section 6.1 Alice public key.
    const ALICE_PUB_HEX: &str = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn to_hex(b: &[u8; 32]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn public_key_matches_rfc7748_alice_vector() {
        let mut priv_bytes = [0u8; 32];
        priv_bytes.copy_from_slice(&hex(ALICE_PRIV_HEX));
        let priv_key = Key(priv_bytes);
        assert_eq!(to_hex(&priv_key.public_key().0), ALICE_PUB_HEX);
    }

    #[test]
    fn parse_display_roundtrip() {
        let b64 = base64::engine::general_purpose::STANDARD.encode(hex(ALICE_PRIV_HEX));
        let parsed = Key::parse(&b64).unwrap();
        assert_eq!(to_hex(&parsed.0), ALICE_PRIV_HEX);
        assert_eq!(parsed.to_string(), b64);
    }

    #[test]
    fn generated_private_key_is_clamped() {
        for _ in 0..16 {
            let k = Key::generate_private_key().unwrap();
            assert_eq!(k.0[0] & 0b111, 0, "low three bits cleared");
            assert_eq!(k.0[31] & 0b1000_0000, 0, "high bit cleared");
            assert_eq!(k.0[31] & 0b0100_0000, 0b0100_0000, "bit 254 set");
        }
    }

    #[test]
    fn parse_rejects_bad_input() {
        // Wrong length (valid base64, 4 bytes).
        assert!(Key::parse("AQIDBA==").is_err());
        // Invalid base64.
        assert!(Key::parse("not base64 !!!").is_err());
        // Empty.
        assert!(Key::parse("").is_err());
    }

    #[test]
    fn generated_key_roundtrips_through_base64() {
        let k = Key::generate_private_key().unwrap();
        assert_eq!(Key::parse(&k.to_string()).unwrap(), k);
    }
}
