//! Backend package. Port of flannel `pkg/backend`.
//!
//! Ported so far: the backend framework skeleton (`common`, `traits`,
//! `manager`, `simple_network`), the `alloc` backend, and the two
//! route-based backends (`hostgw`, `ipip`) built on the shared
//! [`route_network`] port. The remaining upstream backends land in
//! later phases; each is a new module plus a one-liner in
//! [`default_registry`].

pub mod alloc;
pub mod common;
pub mod extension;
pub mod hostgw;
pub mod ipip;
pub mod ipsec;
pub mod manager;
pub mod route_network;
pub mod simple_network;
pub mod tencentvpc;
pub mod traits;
pub mod udp;
pub mod vxlan;
pub mod wireguard;

pub use common::ExternalInterface;
pub use manager::BackendManager;
pub use simple_network::SimpleNetwork;
pub use traits::{Backend, BackendCtor, Network};

/// Registers every upstream backend type by name on `mgr` (Go: the
/// `init()` `backend.Register` calls scattered over the backend packages).
pub fn default_registry(mgr: &mut BackendManager) {
    mgr.register("alloc", Box::new(alloc::new_backend));
    // Go: hostgw.init() and ipip.init() register these names.
    mgr.register("host-gw", Box::new(hostgw::new_backend));
    mgr.register("ipip", Box::new(ipip::new_backend));
    // Go: vxlan.init() registers this name.
    mgr.register("vxlan", Box::new(vxlan::new_backend));
    // Go: wireguard.init(), udp.init(), extension.init() register these.
    mgr.register("wireguard", Box::new(wireguard::new_backend));
    mgr.register("udp", Box::new(udp::new_backend));
    mgr.register("extension", Box::new(extension::new_backend));
    // Go: ipsec.init() and tencentvpc.init() register these names.
    mgr.register("ipsec", Box::new(ipsec::new_backend));
    mgr.register("tencent-vpc", Box::new(tencentvpc::new_backend));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ip::{IP4Net, IP6Net};
    use crate::lease::{Lease, LeaseAttrs, LeaseWatchResult};
    use crate::subnet::config::Config;
    use crate::subnet::manager::{Ctx, Manager};
    use futures::future::BoxFuture;
    use std::sync::Arc;
    use tokio::sync::mpsc;

    /// No-op manager: `default_registry` only constructs backends, which
    /// needs nothing from the subnet manager.
    struct NoopManager;

    impl Manager for NoopManager {
        fn get_network_config<'a>(
            &'a self,
            _ctx: Ctx<'a>,
        ) -> BoxFuture<'a, anyhow::Result<Config>> {
            unimplemented!("not used by registry tests")
        }

        fn handle_subnet_file<'a>(
            &'a self,
            _path: &'a str,
            _config: &'a Config,
            _ip_masq: bool,
            _sn: IP4Net,
            _ipv6sn: IP6Net,
            _mtu: u32,
        ) -> BoxFuture<'a, anyhow::Result<()>> {
            unimplemented!("not used by registry tests")
        }

        fn acquire_lease<'a>(
            &'a self,
            _ctx: Ctx<'a>,
            _attrs: &'a LeaseAttrs,
        ) -> BoxFuture<'a, anyhow::Result<Lease>> {
            unimplemented!("not used by registry tests")
        }

        fn renew_lease<'a>(
            &'a self,
            _ctx: Ctx<'a>,
            _lease: &'a Lease,
        ) -> BoxFuture<'a, anyhow::Result<Lease>> {
            unimplemented!("not used by registry tests")
        }

        fn watch_lease<'a>(
            &'a self,
            _ctx: Ctx<'a>,
            _sn: IP4Net,
            _sn6: IP6Net,
            _tx: mpsc::Sender<Vec<LeaseWatchResult>>,
        ) -> BoxFuture<'a, anyhow::Result<()>> {
            unimplemented!("not used by registry tests")
        }

        fn watch_leases<'a>(
            &'a self,
            _ctx: Ctx<'a>,
            _tx: mpsc::Sender<Vec<LeaseWatchResult>>,
        ) -> BoxFuture<'a, anyhow::Result<()>> {
            unimplemented!("not used by registry tests")
        }

        fn complete_lease<'a>(
            &'a self,
            _ctx: Ctx<'a>,
            _lease: &'a Lease,
        ) -> BoxFuture<'a, anyhow::Result<()>> {
            unimplemented!("not used by registry tests")
        }

        fn get_stored_mac_addresses<'a>(
            &'a self,
            _ctx: Ctx<'a>,
        ) -> BoxFuture<'a, (String, String)> {
            Box::pin(async { (String::new(), String::new()) })
        }

        fn get_stored_public_ip<'a>(&'a self, _ctx: Ctx<'a>) -> BoxFuture<'a, (String, String)> {
            Box::pin(async { (String::new(), String::new()) })
        }

        fn name(&self) -> String {
            "noop".to_string()
        }
    }

    #[test]
    fn default_registry_registers_alloc() {
        let mut mgr = BackendManager::new(Arc::new(NoopManager));
        default_registry(&mut mgr);
        let be = mgr.create("alloc", Arc::new(ExternalInterface::default()));
        assert!(be.is_ok());
    }

    #[test]
    fn default_registry_registers_host_gw_and_ipip() {
        let mut mgr = BackendManager::new(Arc::new(NoopManager));
        default_registry(&mut mgr);
        // Default ExternalInterface has ExtAddr == IfaceAddr (both None),
        // so host-gw's NAT check passes; ipip has no constructor checks.
        for name in [
            "host-gw",
            "ipip",
            "vxlan",
            "wireguard",
            "udp",
            "extension",
            "ipsec",
            "tencent-vpc",
        ] {
            let be = mgr.create(name, Arc::new(ExternalInterface::default()));
            assert!(be.is_ok(), "{name} should be registered");
        }
    }
}
