//! Port of pkg/subnet: net-conf.json parsing, subnet.env writing, managers.

pub mod config;
pub mod kube;
pub mod manager;
pub mod watch;
pub mod writefile;

#[cfg(test)]
#[path = "config_tests.rs"]
mod config_tests;

pub use config::{check_network_config, parse_config, Config, ConfigError};
pub use kube::{new_subnet_manager, KubeSubnetManager};
pub use manager::{Ctx, Manager};
pub use watch::{watch_lease, watch_leases};
pub use writefile::write_subnet_file;
