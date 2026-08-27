//! Port of pkg/subnet: net-conf.json parsing, subnet.env writing, managers.

pub mod config;
pub mod kube;
pub mod manager;
pub mod watch;
pub mod writefile;

#[cfg(test)]
#[path = "config_tests.rs"]
mod config_tests;

/// Go main.go `errInterrupted` ("interrupted"; the etcd local manager
/// returns it when the node's lease is revoked). Typed instead of a
/// string sentinel so callers downcast (`err.is::<Interrupted>()`)
/// rather than compare error text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("interrupted")]
pub struct Interrupted;

pub use config::{check_network_config, parse_config, Config, ConfigError};
pub use kube::{new_subnet_manager, KubeSubnetManager};
pub use manager::{Ctx, Manager};
pub use watch::{watch_lease, watch_leases};
pub use writefile::write_subnet_file;
