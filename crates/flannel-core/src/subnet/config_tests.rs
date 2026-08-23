//! Tests for subnet/config.rs: faithful ports of pkg/subnet/config_test.go
//! plus error-string table tests for check_network_config.

use super::config::{check_network_config, parse_config, ConfigError};

/// Go test helper: ParseConfig + CheckNetworkConfig, fatal on error.
fn parse_and_check(s: &str) -> super::config::Config {
    let mut cfg = parse_config(s).unwrap_or_else(|e| panic!("ParseConfig failed: {e}"));
    check_network_config(&mut cfg).unwrap_or_else(|e| panic!("CheckNetworkConfig failed: {e}"));
    cfg
}

// Go: TestConfigDefaults (note the lowercase "network" key: Go's
// encoding/json matches struct fields case-insensitively).
#[test]
fn config_defaults() {
    let cfg = parse_and_check(r#"{ "network": "10.3.0.0/16" }"#);
    assert_eq!(cfg.network.to_string(), "10.3.0.0/16");
    assert_eq!(cfg.subnet_min.to_string(), "10.3.1.0");
    assert_eq!(cfg.subnet_max.to_string(), "10.3.255.0");
    assert_eq!(cfg.subnet_len, 24);
}

// Go: TestIPv6ConfigDefaults.
#[test]
fn ipv6_config_defaults() {
    let s = r#"{ "enableIPv6": true, "ipv6Network": "fc00::/48", "enableIPv4": false }"#;
    let cfg = parse_and_check(s);
    assert_eq!(cfg.ipv6_network.to_string(), "fc00::/48");
    assert_eq!(cfg.ipv6_subnet_min.unwrap().to_string(), "fc00:0:0:1::");
    assert_eq!(cfg.ipv6_subnet_max.unwrap().to_string(), "fc00:0:0:ffff::");
    assert_eq!(cfg.ipv6_subnet_len, 64);
}

// Go: TestConfigOverrides (ParseConfig only, no CheckNetworkConfig).
#[test]
fn config_overrides() {
    let s = r#"{ "Network": "10.3.0.0/16", "SubnetMin": "10.3.5.0", "SubnetMax": "10.3.8.0", "SubnetLen": 28 }"#;
    let cfg = parse_config(s).unwrap_or_else(|e| panic!("ParseConfig failed: {e}"));
    assert_eq!(cfg.network.to_string(), "10.3.0.0/16");
    assert_eq!(cfg.subnet_min.to_string(), "10.3.5.0");
    assert_eq!(cfg.subnet_max.to_string(), "10.3.8.0");
    assert_eq!(cfg.subnet_len, 28);
}

// Go: TestIPv6ConfigOverrides.
#[test]
fn ipv6_config_overrides() {
    let s = r#"{ "EnableIPv6": true, "IPv6Network": "fc00::/48", "IPv6SubnetMin": "fc00:0:0:1::", "IPv6SubnetMax": "fc00:0:0:f::", "IPv6SubnetLen": 124, "enableIPv4": false }"#;
    let cfg = parse_config(s).unwrap_or_else(|e| panic!("ParseConfig failed: {e}"));
    assert_eq!(cfg.ipv6_network.to_string(), "fc00::/48");
    assert_eq!(cfg.ipv6_subnet_min.unwrap().to_string(), "fc00:0:0:1::");
    assert_eq!(cfg.ipv6_subnet_max.unwrap().to_string(), "fc00:0:0:f::");
    assert_eq!(cfg.ipv6_subnet_len, 124);
}

#[test]
fn parse_config_enable_ipv4_default_and_backend_defaults() {
    // Go: cfg.EnableIPv4 = true before unmarshal; absent Backend -> "udp".
    let cfg = parse_config("{}").unwrap();
    assert!(cfg.enable_ipv4);
    assert!(!cfg.enable_ipv6);
    assert_eq!(cfg.backend_type, "udp");
    assert!(cfg.backend.is_none());
    assert!(cfg.network.empty());
}

#[test]
fn parse_config_backend_type() {
    let cfg =
        parse_config(r#"{ "Network": "10.3.0.0/16", "Backend": { "Type": "vxlan" } }"#).unwrap();
    assert_eq!(cfg.backend_type, "vxlan");
    // Go json.RawMessage: original bytes preserved verbatim.
    assert_eq!(
        cfg.backend.as_ref().unwrap().get(),
        r#"{ "Type": "vxlan" }"#
    );

    // Go encoding/json folds key case for struct{ Type string }.
    let cfg = parse_config(r#"{ "Backend": { "type": "host-gw" } }"#).unwrap();
    assert_eq!(cfg.backend_type, "host-gw");

    // Backend present without a Type field -> Go zero value "".
    let cfg = parse_config(r#"{ "Backend": { "VNI": 1 } }"#).unwrap();
    assert_eq!(cfg.backend_type, "");

    // Go: json.Unmarshal("null", &bt) is a no-op -> "".
    let cfg = parse_config(r#"{ "Backend": null }"#).unwrap();
    assert_eq!(cfg.backend_type, "");
    assert_eq!(cfg.backend.as_ref().unwrap().get(), "null");

    let cfg = parse_config(r#"{ "Backend": {} }"#).unwrap();
    assert_eq!(cfg.backend_type, "");
}

#[test]
fn parse_config_backend_decode_errors() {
    for s in [
        r#"{ "Backend": 123 }"#,
        r#"{ "Backend": ["vxlan"] }"#,
        r#"{ "Backend": { "Type": 123 } }"#,
        r#"{ "Backend": "vxlan" }"#,
    ] {
        let err = match parse_config(s) {
            Err(e) => e,
            Ok(_) => panic!("{s} should fail"),
        };
        assert!(
            err.to_string()
                .starts_with("error decoding Backend property of config: "),
            "input {s}: got {err}"
        );
    }
}

#[test]
fn parse_config_json_and_field_errors() {
    // Malformed JSON.
    assert!(matches!(
        parse_config("{").unwrap_err(),
        ConfigError::Json(_)
    ));
    // Wrong value types error like Go json.Unmarshal.
    assert!(parse_config(r#"{ "Network": 5 }"#).is_err());
    assert!(parse_config(r#"{ "SubnetLen": "24" }"#).is_err());
    assert!(parse_config(r#"{ "Network": "bogus" }"#).is_err());
    // Unknown fields are ignored like Go.
    let cfg = parse_config(r#"{ "Network": "10.3.0.0/16", "SomeFutureField": {"x": 1} }"#).unwrap();
    assert_eq!(cfg.network.to_string(), "10.3.0.0/16");
    // Go: duplicate keys are applied in order; last wins.
    let cfg = parse_config(r#"{ "SubnetLen": 24, "SubnetLen": 28 }"#).unwrap();
    assert_eq!(cfg.subnet_len, 28);
}

// Every check_network_config error string, verified byte-for-byte.
#[test]
fn check_network_config_error_strings() {
    let cases = [
        (
            "{}",
            "please define a correct Network parameter in the flannel config",
        ),
        (
            r#"{ "Network": "10.3.0.0/16", "SubnetLen": 31 }"#,
            "SubnetLen must be less than /31",
        ),
        (
            r#"{ "Network": "10.3.0.0/16", "SubnetLen": 17 }"#,
            "network must be able to accommodate at least four subnets",
        ),
        (
            r#"{ "Network": "10.3.0.0/29" }"#,
            "network is too small. Minimum useful network prefix is /28",
        ),
        (
            r#"{ "Network": "10.3.0.0/16", "SubnetMin": "192.168.1.0" }"#,
            "SubnetMin is not in the range of the Network",
        ),
        (
            r#"{ "Network": "10.3.0.0/16", "SubnetMax": "192.168.1.0" }"#,
            "SubnetMax is not in the range of the Network",
        ),
        (
            r#"{ "Network": "10.3.0.0/16", "SubnetMin": "10.3.5.5" }"#,
            "SubnetMin is not on a SubnetLen boundary: 10.3.5.5",
        ),
        (
            r#"{ "Network": "10.3.0.0/16", "SubnetMax": "10.3.5.5" }"#,
            "SubnetMax is not on a SubnetLen boundary: 10.3.5.5",
        ),
        (
            r#"{ "EnableIPv6": true, "enableIPv4": false }"#,
            "please define a correct IPv6Network parameter in the flannel config",
        ),
        (
            r#"{ "EnableIPv6": true, "enableIPv4": false, "IPv6Network": "fc00::/48", "IPv6SubnetLen": 127 }"#,
            "SubnetLen must be less than /127",
        ),
        (
            r#"{ "EnableIPv6": true, "enableIPv4": false, "IPv6Network": "fc00::/48", "IPv6SubnetLen": 49 }"#,
            "network must be able to accommodate at least four subnets",
        ),
        (
            r#"{ "EnableIPv6": true, "enableIPv4": false, "IPv6Network": "fc00::/125" }"#,
            "IPv6Network is too small. Minimum useful network prefix is /124",
        ),
        (
            r#"{ "EnableIPv6": true, "enableIPv4": false, "IPv6Network": "fc00::/48", "IPv6SubnetMin": "fd00::1:0:0:0" }"#,
            "IPv6SubnetMin is not in the range of the IPv6Network",
        ),
        (
            r#"{ "EnableIPv6": true, "enableIPv4": false, "IPv6Network": "fc00::/48", "IPv6SubnetMax": "fd00::1:0:0:0" }"#,
            "IPv6SubnetMax is not in the range of the IPv6Network",
        ),
        (
            r#"{ "EnableIPv6": true, "enableIPv4": false, "IPv6Network": "fc00::/48", "IPv6SubnetMin": "fc00:0:0:1::1" }"#,
            "IPv6SubnetMin is not on a SubnetLen boundary: fc00:0:0:1::1",
        ),
        (
            r#"{ "EnableIPv6": true, "enableIPv4": false, "IPv6Network": "fc00::/48", "IPv6SubnetMax": "fc00:0:0:1::1" }"#,
            "IPv6SubnetMax is not on a SubnetLen boundary: fc00:0:0:1::1",
        ),
    ];
    for (input, want) in cases {
        let mut cfg = parse_config(input).unwrap_or_else(|e| panic!("{input}: {e}"));
        assert_eq!(
            check_network_config(&mut cfg).unwrap_err().to_string(),
            want,
            "input: {input}"
        );
    }
}

#[test]
fn check_network_config_subnet_len_defaults() {
    // Go: prefix <= 22 -> /24; otherwise prefix + 2 (up to /28 max).
    for (network, want) in [
        ("10.0.0.0/8", 24),
        ("10.0.0.0/22", 24),
        ("10.0.0.0/23", 25),
        ("10.0.0.0/28", 30),
    ] {
        let mut cfg = parse_config(&format!(r#"{{ "Network": "{network}" }}"#)).unwrap();
        check_network_config(&mut cfg).unwrap();
        assert_eq!(cfg.subnet_len, want, "network: {network}");
    }
    // Go: prefix <= 62 -> /64; otherwise prefix + 2 (up to /124 max).
    for (network, want) in [
        ("fc00::/16", 64),
        ("fc00::/62", 64),
        ("fc00::/63", 65),
        ("fc00::/124", 126),
    ] {
        let s =
            format!(r#"{{ "EnableIPv6": true, "enableIPv4": false, "IPv6Network": "{network}" }}"#);
        let mut cfg = parse_config(&s).unwrap();
        check_network_config(&mut cfg).unwrap();
        assert_eq!(cfg.ipv6_subnet_len, want, "network: {network}");
    }
}

#[test]
fn check_network_config_explicit_subnet_len() {
    let mut cfg = parse_config(r#"{ "Network": "10.0.0.0/8", "SubnetLen": 16 }"#).unwrap();
    check_network_config(&mut cfg).unwrap();
    assert_eq!(cfg.subnet_len, 16);
    assert_eq!(cfg.subnet_min.to_string(), "10.1.0.0");
    assert_eq!(cfg.subnet_max.to_string(), "10.255.0.0");

    let s = r#"{ "EnableIPv6": true, "enableIPv4": false, "IPv6Network": "fc00::/64", "IPv6SubnetLen": 66 }"#;
    let mut cfg = parse_config(s).unwrap();
    check_network_config(&mut cfg).unwrap();
    assert_eq!(cfg.ipv6_subnet_len, 66);
    // subnet size = 2^(128-66) = 2^62: skip the first /66 subnet, and max
    // is the end of fc00::/64 minus one subnet.
    assert_eq!(cfg.ipv6_subnet_min.unwrap().to_string(), "fc00::4000:0:0:0");
    assert_eq!(cfg.ipv6_subnet_max.unwrap().to_string(), "fc00::c000:0:0:0");
}

#[test]
fn serialize_uses_go_field_names() {
    let cfg =
        parse_config(r#"{ "Network": "10.3.0.0/16", "Backend": { "Type": "vxlan" } }"#).unwrap();
    let obj = serde_json::to_value(&cfg).unwrap();
    let obj = obj.as_object().unwrap();
    for key in [
        "EnableIPv4",
        "EnableIPv6",
        "EnableNFTables",
        "Network",
        "IPv6Network",
        "SubnetMin",
        "SubnetMax",
        "IPv6SubnetMin",
        "IPv6SubnetMax",
        "SubnetLen",
        "IPv6SubnetLen",
        "Backend",
    ] {
        assert!(obj.contains_key(key), "missing {key}");
    }
    // Go: BackendType is json:"-"; Backend is omitempty.
    assert!(!obj.contains_key("BackendType"));

    // Serialization uses the Go field names and splices the Backend raw
    // JSON verbatim (json.RawMessage behavior).
    let s = serde_json::to_string(&cfg).unwrap();
    assert!(s.contains(r#""EnableIPv4":true"#));
    assert!(s.contains(r#""Network":"10.3.0.0/16""#));
    assert!(s.contains(r#"{ "Type": "vxlan" }"#));
    assert!(!s.contains("BackendType"));

    let cfg = parse_config(r#"{ "Network": "10.3.0.0/16" }"#).unwrap();
    // Go omitempty: absent Backend is not marshaled.
    assert!(!serde_json::to_string(&cfg).unwrap().contains("Backend"));
}
