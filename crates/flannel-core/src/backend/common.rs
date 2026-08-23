//! Common backend types. Port of flannel `pkg/backend/common.go`
//! (upstream cdf76059). Only the `ExternalInterface` data struct is
//! ported in P0; the `Backend`/`Network` traits, `BackendCtor` and the
//! backend registry land in P2 together with the first backend ports.
//!
//! Functional style: plain data structs only, no methods with hidden
//! state.

use std::net::IpAddr;

/// Static information about the external (physical) interface flannel
/// uses to reach peers. Port of Go `backend.ExternalInterface`.
///
/// Where Go carries the full `*net.Interface`, the Rust port carries the
/// interface index plus name; anything richer (MTU, flags, ...) is
/// re-fetched through netlink by the code that needs it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExternalInterface {
    /// Index of the external interface (Go: `Iface.Index`).
    pub iface_index: u32,
    /// Name of the external interface (Go: `IfaceName`).
    pub iface_name: String,
    /// IPv4 address of the interface, if any (Go: `IfaceAddr`).
    pub iface_addr: Option<IpAddr>,
    /// IPv6 address of the interface, if any (Go: `IfaceV6Addr`).
    pub iface_v6_addr: Option<IpAddr>,
    /// Externally reachable IPv4 address (Go: `ExtAddr`).
    pub ext_addr: Option<IpAddr>,
    /// Externally reachable IPv6 address (Go: `ExtV6Addr`).
    pub ext_v6_addr: Option<IpAddr>,
}
