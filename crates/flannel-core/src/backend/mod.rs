//! Backend package. Port of flannel `pkg/backend`.
//!
//! P0 scope: the shared data types (`common`). The `Backend`/`Network`
//! traits, `BackendCtor` and the backend registry (Go `RegisterBackend`)
//! land in P2 when the first backends (vxlan, host-gw) are ported.

pub mod common;

pub use common::ExternalInterface;
