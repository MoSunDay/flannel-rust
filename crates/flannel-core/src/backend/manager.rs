//! Backend registry + factory. Port of the constructor map and lookup of
//! pkg/backend/manager.go (upstream cdf76059).
//!
//! Go's `manager` additionally caches active backends, runs them in
//! goroutines and joins them via a WaitGroup; the Rust daemon instead
//! awaits `Network::run`, so this port keeps only the registry part:
//! `register` (Go `Register`) and `create` (the constructor lookup of Go
//! `GetBackend`).

use crate::backend::common::ExternalInterface;
use crate::backend::traits::{Backend, BackendCtor};
use crate::subnet::manager::Manager;
use std::collections::HashMap;
use std::sync::Arc;

/// Registry of backend constructors keyed by (lowercase) backend type
/// name, plus the subnet manager handed to every constructed backend.
pub struct BackendManager {
    backends: HashMap<String, BackendCtor>,
    sm: Arc<dyn Manager>,
}

impl BackendManager {
    /// Go: `NewManager` (the registry half; the active-backend cache is
    /// not ported, see module docs).
    pub fn new(sm: Arc<dyn Manager>) -> Self {
        Self {
            backends: HashMap::new(),
            sm,
        }
    }

    /// Go: `Register(name, ctor)`. Names are stored verbatim; lookups
    /// lowercase, so registering lowercase names (as Go does) is expected.
    pub fn register(&mut self, name: &str, ctor: BackendCtor) {
        self.backends.insert(name.to_string(), ctor);
    }

    /// Constructor lookup of Go `GetBackend`: lowercase the type, find the
    /// constructor, build the backend. Error string matches Go:
    /// `unknown backend type: %v` with the lowercased name.
    pub fn create(
        &self,
        name: &str,
        ei: Arc<ExternalInterface>,
    ) -> anyhow::Result<Box<dyn Backend>> {
        let betype = name.to_lowercase();
        let ctor = self
            .backends
            .get(&betype)
            .ok_or_else(|| anyhow::anyhow!("unknown backend type: {betype}"))?;
        ctor(self.sm.clone(), ei)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::traits::Network;
    use crate::ip::{IP4Net, IP6Net};
    use crate::lease::{Lease, LeaseAttrs};
    use crate::subnet::config::Config;
    use crate::subnet::manager::Ctx;
    use futures::future::BoxFuture;
    use tokio::sync::mpsc;

    /// Minimal manager stub: only `name` matters for registry tests.
    struct StubManager;

    impl Manager for StubManager {
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
            _tx: mpsc::Sender<Vec<crate::lease::LeaseWatchResult>>,
        ) -> BoxFuture<'a, anyhow::Result<()>> {
            unimplemented!("not used by registry tests")
        }

        fn watch_leases<'a>(
            &'a self,
            _ctx: Ctx<'a>,
            _tx: mpsc::Sender<Vec<crate::lease::LeaseWatchResult>>,
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
            "stub".to_string()
        }
    }

    struct DummyBackend;

    impl Backend for DummyBackend {
        fn register_network<'a>(
            &'a self,
            _ctx: Ctx<'a>,
            _config: &'a Config,
        ) -> BoxFuture<'a, anyhow::Result<Box<dyn Network>>> {
            Box::pin(async { Err(anyhow::anyhow!("dummy")) })
        }
    }

    fn ext_iface() -> Arc<ExternalInterface> {
        Arc::new(ExternalInterface::default())
    }

    #[test]
    fn create_unknown_backend_type_error_string() {
        let mgr = BackendManager::new(Arc::new(StubManager));
        // Go: fmt.Errorf("unknown backend type: %v", betype) with
        // betype = strings.ToLower(backendType).
        let err = mgr.create("VXLAN", ext_iface()).err().unwrap();
        assert_eq!(err.to_string(), "unknown backend type: vxlan");
    }

    #[test]
    fn create_registered_backend_case_insensitive() {
        let mut mgr = BackendManager::new(Arc::new(StubManager));
        mgr.register(
            "dummy",
            Box::new(|_sm, _ei| Ok(Box::new(DummyBackend) as Box<dyn Backend>)),
        );
        assert!(mgr.create("Dummy", ext_iface()).is_ok());
    }

    #[test]
    fn create_passes_constructor_error_through() {
        let mut mgr = BackendManager::new(Arc::new(StubManager));
        mgr.register(
            "bad",
            Box::new(|_sm, _ei| Err(anyhow::anyhow!("ctor failed"))),
        );
        let err = mgr.create("bad", ext_iface()).err().unwrap();
        assert_eq!(err.to_string(), "ctor failed");
    }
}
