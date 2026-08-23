//! flannel-core: core library for the Rust rewrite of flannel.
//!
//! Ported from flannel (Go) upstream commit cdf76059. Functional style:
//! plain structs for data, free functions for logic, traits only for
//! backend/manager polymorphism.

pub mod endian;
pub mod flags;
pub mod ip;
pub mod ipmatch;
pub mod lease;
pub mod mac;
pub mod subnet;
pub mod utils;
