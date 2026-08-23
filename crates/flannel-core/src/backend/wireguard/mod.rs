//! Port of pkg/backend/wireguard (upstream cdf76059): `Mode`, backend
//! config parsing, `RegisterNetwork` and the lease attributes. Device
//! handling lives in device.rs, the generic-netlink wgctrl layer in
//! genl.rs, key material in keys.rs, the event loop in network.rs.

mod device;
mod genl;
mod keys;
mod network;

use crate::backend::common::ExternalInterface;
use crate::backend::traits::{Backend, Network};
use crate::ip::iface::{get_link_mtu, Netlink};
use crate::ip::{IP4, IP6};
use crate::lease::LeaseAttrs;
use crate::subnet::config::Config;
use crate::subnet::manager::{Ctx, Manager};
use anyhow::{anyhow, bail};
use futures::future::BoxFuture;
use network::new_wireguard_network;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use serde_json::Value;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

/// Go `backendType`.
pub const BACKEND_TYPE: &str = "wireguard";
/// Go `overhead`: IPv4/IPv6 header, UDP header, type, key index, nonce
/// and authentication tag (see wireguard_network.go).
pub(crate) const OVERHEAD: u32 = 80;

/// Port of Go `Mode` (a string type; JSON values are matched exactly,
/// like Go's decoding into a string-typed field).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mode {
    Separate,
    Auto,
    Ipv4,
    Ipv6,
}

impl Mode {
    fn parse(s: &str) -> Option<Mode> {
        match s {
            "separate" => Some(Mode::Separate),
            "auto" => Some(Mode::Auto),
            "ipv4" => Some(Mode::Ipv4),
            "ipv6" => Some(Mode::Ipv6),
            _ => None,
        }
    }
}
/// Port of Go `wireguardLeaseAttrs`, serialized into the lease's
/// BackendData / BackendV6Data.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct WireguardLeaseAttrs {
    #[serde(rename = "PublicKey")]
    pub(crate) public_key: String,
    #[serde(rename = "Port")]
    pub(crate) port: u16,
}

/// Backend config (Go: the anonymous `cfg` struct in `RegisterNetwork`).
struct WgConfig {
    listen_port: u32,
    listen_port_v6: u32,
    mtu: u32,
    psk: String,
    keepalive_secs: u64,
    /// None when the Mode string is invalid (Go: "no valid Mode configured").
    mode: Option<Mode>,
}

/// Go field names of the anonymous cfg struct, in declaration order.
const FIELDS: &[&str] = &[
    "ListenPort",
    "ListenPortV6",
    "MTU",
    "PSK",
    "PersistentKeepaliveInterval",
    "Mode",
];

/// Port of the Go config decoding in `RegisterNetwork` (defaults:
/// ListenPort 51820, ListenPortV6 51821, MTU = external interface MTU,
/// PSK "", PersistentKeepaliveInterval 0, Mode Separate).
fn parse_wg_config(backend: Option<&RawValue>, default_mtu: u32) -> anyhow::Result<WgConfig> {
    let mut cfg = WgConfig {
        listen_port: 51820,
        listen_port_v6: 51821,
        mtu: default_mtu,
        psk: String::new(),
        keepalive_secs: 0,
        mode: Some(Mode::Separate),
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
            "json: cannot unmarshal {} into Go value of type struct {{ ListenPort int; \
             ListenPortV6 int; MTU int; PSK string; PersistentKeepaliveInterval \
             time.Duration; Mode wireguard.Mode }}",
            json_type(&value)
        );
    };
    for (key, val) in map {
        let Some(tag) = match_field(&key) else {
            continue; // unknown fields are ignored
        };
        match tag {
            "ListenPort" => cfg.listen_port = int_field(tag, &val)?,
            "ListenPortV6" => cfg.listen_port_v6 = int_field(tag, &val)?,
            "MTU" => cfg.mtu = int_field(tag, &val)?,
            "PSK" => cfg.psk = string_field(tag, &val)?,
            "PersistentKeepaliveInterval" => {
                let Some(n) = val.as_i64() else {
                    anyhow::bail!(
                        "json: cannot unmarshal {} into Go struct field .{tag} of type \
                         time.Duration",
                        json_type(&val)
                    );
                };
                // Go: ns-value * time.Second = N seconds; negatives
                // are clamped (the kernel rejects negative keepalives).
                cfg.keepalive_secs = n.max(0) as u64;
            }
            "Mode" => cfg.mode = Mode::parse(&string_field(tag, &val)?),
            _ => unreachable!("match_field only returns known tags"),
        }
    }
    Ok(cfg)
}

/// Go encoding/json field matching: exact tag match first, then
/// case-insensitive fallback.
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
            "json: cannot unmarshal {} into Go struct field .{tag} of type int",
            json_type(val)
        );
    };
    // Go casts int -> uint16 in newSubnetAttrs (wrapping); negatives
    // come through exactly like Go's uint16(cfg.ListenPort).
    Ok(n as u32)
}
fn string_field(tag: &str, val: &Value) -> anyhow::Result<String> {
    let Some(s) = val.as_str() else {
        anyhow::bail!(
            "json: cannot unmarshal {} into Go struct field .{tag} of type string",
            json_type(val)
        );
    };
    Ok(s.to_string())
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
/// The wireguard backend (Go `WireguardBackend`).
pub struct WireguardBackend {
    sm: Arc<dyn Manager>,
    ei: Arc<ExternalInterface>,
}

/// Go: `New` + `backend.Register("wireguard", New)`.
pub fn new_backend(
    sm: Arc<dyn Manager>,
    ei: Arc<ExternalInterface>,
) -> anyhow::Result<Box<dyn Backend>> {
    Ok(Box::new(WireguardBackend { sm, ei }))
}
/// Port of Go `createWGDev`.
async fn create_wg_dev(
    ctx: Ctx<'_>,
    nl: &Netlink,
    name: &str,
    psk: &str,
    keepalive: Duration,
    listen_port: u32,
    mtu: u32,
) -> anyhow::Result<device::WGDevice> {
    let mut attrs = device::WGDeviceAttrs {
        listen_port: listen_port as u16,
        private_key: None,
        public_key: None,
        psk: None,
        keepalive: Some(keepalive),
        name: name.to_string(),
        mtu,
    };
    device::setup_keys(&mut attrs, psk)?;
    device::new_wg_device(nl, &attrs, ctx).await
}

/// Go: `dev.attrs.publicKey.String()`.
fn public_key_of(dev: &device::WGDevice) -> String {
    dev.attrs
        .public_key
        .as_ref()
        .map(ToString::to_string)
        .unwrap_or_default()
}
/// Port of Go `newSubnetAttrs`.
fn new_subnet_attrs(
    public_ip: Option<IpAddr>,
    public_ipv6: Option<IpAddr>,
    enable_ipv4: bool,
    enable_ipv6: bool,
    public_key: &str,
    v4_port: u32,
    v6_port: u32,
) -> anyhow::Result<LeaseAttrs> {
    let v4_data = serde_json::to_string(&WireguardLeaseAttrs {
        public_key: public_key.to_string(),
        port: v4_port as u16,
    })?;
    let v6_data = serde_json::to_string(&WireguardLeaseAttrs {
        public_key: public_key.to_string(),
        port: v6_port as u16,
    })?;
    let mut attrs = LeaseAttrs {
        backend_type: BACKEND_TYPE.to_string(),
        ..Default::default()
    };
    // Go: ip.FromIP / ip.FromIP6 only set the field for matching family.
    if let Some(IpAddr::V4(ip)) = public_ip {
        attrs.public_ip = IP4::from_bytes(ip.octets());
    }
    if enable_ipv4 {
        attrs.backend_data = Some(RawValue::from_string(v4_data)?);
    }
    if let Some(IpAddr::V6(ip)) = public_ipv6 {
        attrs.public_ipv6 = Some(IP6::from_std(ip));
    }
    if enable_ipv6 {
        attrs.backend_v6_data = Some(RawValue::from_string(v6_data)?);
    }
    Ok(attrs)
}

impl Backend for WireguardBackend {
    /// Go: `RegisterNetwork`.
    fn register_network<'a>(
        &'a self,
        ctx: Ctx<'a>,
        config: &'a Config,
    ) -> BoxFuture<'a, anyhow::Result<Box<dyn Network>>> {
        Box::pin(async move {
            let nl = Netlink::new().await?;
            // Go reads be.extIface.Iface.MTU for the MTU default; the
            // Rust ExternalInterface has no MTU, so fetch it from the
            // link.
            let ext_mtu = get_link_mtu(&nl, self.ei.iface_index).await?;
            let cfg = parse_wg_config(config.backend.as_deref(), ext_mtu)
                .map_err(|e| anyhow!("error decoding backend config: {e}"))?;
            let Some(mode) = cfg.mode else {
                bail!("no valid Mode configured");
            };
            let keepalive = Duration::from_secs(cfg.keepalive_secs);

            let mut dev = None;
            let mut v6_dev = None;
            let mut public_key = String::new();
            match mode {
                Mode::Separate => {
                    if config.enable_ipv4 {
                        let d = create_wg_dev(
                            ctx,
                            &nl,
                            "flannel-wg",
                            &cfg.psk,
                            keepalive,
                            cfg.listen_port,
                            cfg.mtu,
                        )
                        .await?;
                        public_key = public_key_of(&d);
                        dev = Some(d);
                    }
                    if config.enable_ipv6 {
                        let d = create_wg_dev(
                            ctx,
                            &nl,
                            "flannel-wg-v6",
                            &cfg.psk,
                            keepalive,
                            cfg.listen_port_v6,
                            cfg.mtu,
                        )
                        .await?;
                        public_key = public_key_of(&d);
                        v6_dev = Some(d);
                    }
                }
                Mode::Auto | Mode::Ipv4 | Mode::Ipv6 => {
                    let d = create_wg_dev(
                        ctx,
                        &nl,
                        "flannel-wg",
                        &cfg.psk,
                        keepalive,
                        cfg.listen_port,
                        cfg.mtu,
                    )
                    .await?;
                    public_key = public_key_of(&d);
                    dev = Some(d);
                }
            }

            let subnet_attrs = new_subnet_attrs(
                self.ei.ext_addr,
                self.ei.ext_v6_addr,
                config.enable_ipv4,
                config.enable_ipv6,
                &public_key,
                cfg.listen_port,
                cfg.listen_port_v6,
            )?;

            let lease = match self.sm.acquire_lease(ctx, &subnet_attrs).await {
                Ok(l) => l,
                // Go: context.Canceled / DeadlineExceeded pass through.
                Err(e) if ctx.is_cancelled() => return Err(e),
                Err(e) => return Err(anyhow!("failed to acquire lease: {e}")),
            };

            if config.enable_ipv4 {
                if lease.subnet.empty() {
                    bail!(
                        "failed to configure wg interface: IPv4 is enabled but the lease \
                         has no IPv4"
                    );
                }
                // Go: dev.Configure(lease.Subnet.IP, config.Network).
                let d = dev.as_ref().expect("dev is created when IPv4 is enabled");
                device::configure(&nl, d, lease.subnet.ip, config.network).await?;
            }

            if config.enable_ipv6 {
                if lease.ipv6_subnet.empty() {
                    bail!(
                        "failed to configure wg interface: IPv6 is enabled but the lease \
                         has no IPv6"
                    );
                }
                // Go: Separate mode uses the dedicated v6 device, all
                // other modes the shared flannel-wg device.
                let d = if mode == Mode::Separate {
                    v6_dev
                        .as_ref()
                        .expect("v6Dev is created when IPv6 is enabled")
                } else {
                    dev.as_ref().expect("dev is created when IPv6 is enabled")
                };
                device::configure_v6(&nl, d, lease.ipv6_subnet.ip, config.ipv6_network).await?;
            }

            let net = new_wireguard_network(
                self.sm.clone(),
                self.ei.clone(),
                dev,
                v6_dev,
                mode,
                lease,
                cfg.mtu,
            );
            Ok(Box::new(net) as Box<dyn Network>)
        })
    }
}
