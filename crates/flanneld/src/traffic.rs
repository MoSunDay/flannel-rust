//! TrafficManager selection. Port of main.go's `newTrafficManager`
//! (upstream cdf76059). The trait and the iptables/nftables
//! implementations live in `flannel_core::trafficmngr`; the daemon
//! keeps this module as the stable call site.

pub use flannel_core::trafficmngr::{IPTablesManager, NFTablesManager, TrafficManager};

/// Go: `newTrafficManager(useNftables)`.
pub fn new_traffic_manager(use_nftables: bool) -> Box<dyn TrafficManager> {
    flannel_core::trafficmngr::new_traffic_manager(use_nftables)
}
