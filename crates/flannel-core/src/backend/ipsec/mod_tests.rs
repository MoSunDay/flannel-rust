//! Tests for mod.rs: ipsec backend config parsing.

use super::{parse_ipsec_config, DEFAULT_ESP_PROPOSAL, MIN_PASSWORD_LENGTH};
use serde_json::value::RawValue;

fn raw(s: &str) -> Box<RawValue> {
    RawValue::from_string(s.to_string()).unwrap()
}

#[test]
fn absent_or_null_backend_uses_defaults_but_psk_is_required() {
    // defaults are applied ...
    for input in [None, Some(raw("null"))] {
        // ... but the PSK check still fails (empty password)
        let err = parse_ipsec_config(input.as_deref()).unwrap_err();
        assert_eq!(err.to_string(), "config error, password is too short");
    }
}

#[test]
fn psk_length_validation_matches_go() {
    let short = "x".repeat(MIN_PASSWORD_LENGTH - 1);
    let long = "x".repeat(MIN_PASSWORD_LENGTH);
    let err = parse_ipsec_config(Some(&raw(&format!(r#"{{"PSK":"{short}"}}"#)))).unwrap_err();
    assert_eq!(err.to_string(), "config error, password is too short");
    let cfg = parse_ipsec_config(Some(&raw(&format!(r#"{{"PSK":"{long}"}}"#)))).unwrap();
    assert!(!cfg.udp_encap);
    assert_eq!(cfg.esp_proposal, DEFAULT_ESP_PROPOSAL);
}

#[test]
fn explicit_fields_override_defaults() {
    let psk = "y".repeat(96);
    let json = format!(
        r#"{{"UDPEncap":true,"ESPProposal":"aes256gcm16-sha384-prfsha384-ecp384","PSK":"{psk}"}}"#
    );
    let cfg = parse_ipsec_config(Some(&raw(&json))).unwrap();
    assert!(cfg.udp_encap);
    assert_eq!(cfg.esp_proposal, "aes256gcm16-sha384-prfsha384-ecp384");
    assert_eq!(cfg.psk, psk);
    // explicit empty ESPProposal overrides the default (Go semantics)
    let cfg = parse_ipsec_config(Some(&raw(&format!(
        r#"{{"ESPProposal":"","PSK":"{psk}"}}"#
    ))))
    .unwrap();
    assert_eq!(cfg.esp_proposal, "");
}

#[test]
fn invalid_json_surfaces_decode_error() {
    let err = parse_ipsec_config(Some(&raw(r#"{"PSK": 5}"#))).unwrap_err();
    assert!(err
        .to_string()
        .starts_with("error decoding IPSEC backend config:"));
}
