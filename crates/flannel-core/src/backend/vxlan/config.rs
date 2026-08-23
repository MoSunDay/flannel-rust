//! Port of `VXLANConfig` parsing in pkg/backend/vxlan/vxlan.go (upstream
//! cdf76059). Go uses lowercase json tags (`vni`, `port`, `mtu`, `gbp`,
//! `learning`, `directRouting`) and Go's encoding/json matches keys
//! case-insensitively, so `"vni"` and `"VNI"` both work. Unknown keys are
//! ignored. `MTU` defaults to the external interface MTU, which Go reads
//! from `extIface.Iface.MTU`; the caller supplies it as `default_mtu`.

use serde_json::Value;

/// Backend config (Go: `VXLANConfig`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VXLANConfig {
    /// VXLAN identifier (Go: `VNI`, default 1).
    pub vni: u32,
    /// UDP destination port (Go: `Port`; 0 means kernel default 8472).
    pub port: u32,
    /// Link MTU (Go: `MTU`; default = external interface MTU).
    pub mtu: u32,
    /// Group-based policy (Go: `GBP`).
    pub gbp: bool,
    /// VXLAN learning (Go: `Learning`).
    pub learning: bool,
    /// Route to same-L2 remote hosts without encapsulation (Go:
    /// `DirectRouting`).
    pub direct_routing: bool,
}

/// Go json tag names, in Go struct field order.
const FIELDS: &[&str] = &["mtu", "vni", "port", "gbp", "learning", "directRouting"];

/// Port of `parseVXLANConfig(config json.RawMessage, defaultMTU int)`.
/// `backend` is `Config.backend` (raw Backend JSON); absent or `null`
/// means "use defaults", like Go's empty `RawMessage`.
pub fn parse_vxlan_config(
    backend: Option<&serde_json::value::RawValue>,
    default_mtu: u32,
) -> anyhow::Result<VXLANConfig> {
    let mut cfg = VXLANConfig {
        vni: 1,
        port: 0,
        mtu: default_mtu,
        gbp: false,
        learning: false,
        direct_routing: false,
    };

    let Some(raw) = backend else {
        return Ok(cfg);
    };
    let text = raw.get();
    if text == "null" {
        return Ok(cfg);
    }
    let value: Value = serde_json::from_str(text)?;
    let Value::Object(map) = value else {
        anyhow::bail!(
            "json: cannot unmarshal {} into Go value of type vxlan.VXLANConfig",
            json_type(&value)
        );
    };

    // Go decodes keys in document order; each key overwrites earlier
    // values of the same field.
    for (key, val) in map {
        let Some(tag) = match_field(&key) else {
            continue; // unknown fields are ignored
        };
        match tag {
            "mtu" => cfg.mtu = int_field(tag, &val)?,
            "vni" => cfg.vni = int_field(tag, &val)?,
            "port" => cfg.port = int_field(tag, &val)?,
            "gbp" => cfg.gbp = bool_field(tag, &val)?,
            "learning" => cfg.learning = bool_field(tag, &val)?,
            "directRouting" => cfg.direct_routing = bool_field(tag, &val)?,
            _ => unreachable!("match_field only returns known tags"),
        }
    }
    Ok(cfg)
}

/// Go encoding/json field matching: exact tag match first, then
/// case-insensitive fallback (so `VNI`, `Mtu`, `DirectROUTING` all work).
fn match_field(key: &str) -> Option<&'static str> {
    for tag in FIELDS {
        if key == *tag {
            return Some(*tag);
        }
    }
    for tag in FIELDS {
        if key.eq_ignore_ascii_case(tag) {
            return Some(*tag);
        }
    }
    None
}

fn int_field(tag: &str, val: &Value) -> anyhow::Result<u32> {
    let Some(n) = val.as_i64() else {
        anyhow::bail!(
            "json: cannot unmarshal {} into Go struct field VXLANConfig.{tag} of type int",
            json_type(val)
        );
    };
    // Go casts int -> uint32 (wrapping); negatives come through as large
    // values exactly like Go's uint32(cfg.VNI).
    Ok(n as u32)
}

fn bool_field(tag: &str, val: &Value) -> anyhow::Result<bool> {
    let Some(b) = val.as_bool() else {
        anyhow::bail!(
            "json: cannot unmarshal {} into Go struct field VXLANConfig.{tag} of type bool",
            json_type(val)
        );
    };
    Ok(b)
}

/// Go encoding/json type names used in its error messages.
fn json_type(val: &Value) -> &'static str {
    match val {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::value::RawValue;

    fn raw(s: &str) -> Box<RawValue> {
        RawValue::from_string(s.to_string()).unwrap()
    }

    fn parse(s: &str) -> VXLANConfig {
        parse_vxlan_config(Some(&raw(s)), 1500).unwrap()
    }

    #[test]
    fn absent_backend_uses_defaults() {
        let cfg = parse_vxlan_config(None, 1500).unwrap();
        assert_eq!(
            cfg,
            VXLANConfig {
                vni: 1,
                port: 0,
                mtu: 1500,
                gbp: false,
                learning: false,
                direct_routing: false,
            }
        );
    }

    #[test]
    fn null_backend_uses_defaults() {
        let cfg = parse_vxlan_config(Some(&raw("null")), 8996).unwrap();
        assert_eq!(cfg.vni, 1);
        assert_eq!(cfg.mtu, 8996);
    }

    #[test]
    fn empty_object_uses_defaults() {
        let cfg = parse("{}");
        assert_eq!(cfg.vni, 1);
        assert_eq!(cfg.port, 0);
        assert_eq!(cfg.mtu, 1500);
    }

    #[test]
    fn all_fields_lower_case_tags() {
        let cfg = parse(
            r#"{"vni":7,"port":4789,"mtu":1400,"gbp":true,"learning":true,"directRouting":true}"#,
        );
        assert_eq!(cfg.vni, 7);
        assert_eq!(cfg.port, 4789);
        assert_eq!(cfg.mtu, 1400);
        assert!(cfg.gbp);
        assert!(cfg.learning);
        assert!(cfg.direct_routing);
    }

    #[test]
    fn case_insensitive_keys_like_go() {
        // Go encoding/json falls back to case-insensitive matching.
        let cfg = parse(r#"{"VNI":5,"Port":8472,"MTU":1300,"GBP":true,"DirectROUTING":true}"#);
        assert_eq!(cfg.vni, 5);
        assert_eq!(cfg.port, 8472);
        assert_eq!(cfg.mtu, 1300);
        assert!(cfg.gbp);
        assert!(cfg.direct_routing);
    }

    #[test]
    fn exact_key_beats_case_insensitive_dup() {
        // Go applies keys in document order: exact-match "vni" comes
        // second, so it wins.
        let cfg = parse(r#"{"VNI":5,"vni":7}"#);
        assert_eq!(cfg.vni, 7);
    }

    #[test]
    fn unknown_fields_ignored() {
        let cfg = parse(r#"{"vni":3,"Name":"other","Bogus":[1,2]}"#);
        assert_eq!(cfg.vni, 3);
        assert_eq!(cfg.mtu, 1500);
    }

    #[test]
    fn type_errors_match_go_shape() {
        let err = parse_vxlan_config(Some(&raw(r#"{"vni":"five"}"#)), 1500).unwrap_err();
        assert!(
            err.to_string().contains(
                "json: cannot unmarshal string into Go struct field VXLANConfig.vni of type int"
            ),
            "got: {err}"
        );

        let err = parse_vxlan_config(Some(&raw(r#"{"gbp":"yes"}"#)), 1500).unwrap_err();
        assert!(
            err.to_string().contains(
                "json: cannot unmarshal string into Go struct field VXLANConfig.gbp of type bool"
            ),
            "got: {err}"
        );

        // Case-insensitive matched keys keep the matched tag in the error.
        let err = parse_vxlan_config(Some(&raw(r#"{"PORT":[1]}"#)), 1500).unwrap_err();
        assert!(
            err.to_string().contains("VXLANConfig.port of type int"),
            "got: {err}"
        );
    }

    #[test]
    fn non_object_backend_is_an_error() {
        assert!(parse_vxlan_config(Some(&raw(r#""vxlan""#)), 1500).is_err());
        assert!(parse_vxlan_config(Some(&raw("[1,2]")), 1500).is_err());
    }
}
