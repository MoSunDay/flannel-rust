//! Port of pkg/backend/alloc/alloc.go (upstream cdf76059): the "alloc"
//! backend, which only allocates a subnet lease and does no datapath
//! setup.
//!
//! Like Go, `register_network` ignores the parsed `Config` entirely: the
//! lease (and its subnet) comes from the subnet manager, and upstream
//! alloc performs no containment check against the configured network.

use crate::backend::common::ExternalInterface;
use crate::backend::simple_network::SimpleNetwork;
use crate::backend::traits::{Backend, Network};
use crate::ip::iface::{get_link_mtu, Netlink};
use crate::ip::IP4;
use crate::lease::LeaseAttrs;
use crate::subnet::config::Config;
use crate::subnet::manager::{Ctx, Manager};
use futures::future::BoxFuture;
use std::net::IpAddr;
use std::sync::Arc;

/// Port of Go `AllocBackend{sm, extIface}`.
pub struct AllocBackend {
    pub sm: Arc<dyn Manager>,
    pub ei: Arc<ExternalInterface>,
}

/// Port of Go `alloc.New`, the registered `BackendCtor` of this backend
/// (Go: `backend.Register("alloc", New)` in `init()`).
pub fn new_backend(
    sm: Arc<dyn Manager>,
    ei: Arc<ExternalInterface>,
) -> anyhow::Result<Box<dyn Backend>> {
    Ok(Box::new(AllocBackend { sm, ei }))
}

/// Port of Go `ip.FromIP(extIface.ExtAddr)`: Go panics when the address
/// is missing or not IPv4; the Rust port fails with the same message.
fn ext_addr_ip4(ei: &ExternalInterface) -> anyhow::Result<IP4> {
    match ei.ext_addr {
        Some(IpAddr::V4(v4)) => Ok(IP4::from_bytes(v4.octets())),
        _ => anyhow::bail!("Address is not an IPv4 address"),
    }
}

impl Backend for AllocBackend {
    /// Port of Go `(*AllocBackend).RegisterNetwork`:
    /// acquire the lease with `LeaseAttrs{PublicIP: ExtAddr}` and wrap it
    /// in a `SimpleNetwork`. Cancellation errors are returned unwrapped;
    /// any other acquire failure becomes `failed to acquire lease: %v`.
    fn register_network<'a>(
        &'a self,
        ctx: Ctx<'a>,
        _config: &'a Config,
    ) -> BoxFuture<'a, anyhow::Result<Box<dyn Network>>> {
        Box::pin(async move {
            let attrs = LeaseAttrs {
                public_ip: ext_addr_ip4(&self.ei)?,
                ..Default::default()
            };

            match self.sm.acquire_lease(ctx, &attrs).await {
                Ok(lease) => {
                    // Go reads the MTU lazily via ExtIface.Iface.MTU; the
                    // Rust ExternalInterface carries no MTU, so re-fetch
                    // it via netlink (see backend/common.rs docs).
                    let nl = Netlink::new().await?;
                    let mtu = get_link_mtu(&nl, self.ei.iface_index).await?;
                    Ok(Box::new(SimpleNetwork::new(lease, mtu)) as Box<dyn Network>)
                }
                // Go: case context.Canceled, context.DeadlineExceeded.
                Err(e) if ctx.is_cancelled() => Err(e),
                Err(e) => Err(anyhow::anyhow!("failed to acquire lease: {e}")),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ip::{IP4Net, IP6Net};
    use crate::lease::{Lease, LeaseWatchResult};
    use std::time::UNIX_EPOCH;
    use tokio::sync::{mpsc, Mutex};
    use tokio_util::sync::CancellationToken;

    /// Manager stub returning a canned lease; records the `LeaseAttrs`
    /// passed to `acquire_lease`. Doubles as a `Manager` usage example.
    struct MockManager {
        lease: Lease,
        acquire_err: Option<String>,
        recorded_attrs: Mutex<Option<LeaseAttrs>>,
    }

    impl MockManager {
        fn new(lease: Lease) -> Self {
            Self {
                lease,
                acquire_err: None,
                recorded_attrs: Mutex::new(None),
            }
        }
    }

    impl Manager for MockManager {
        fn get_network_config<'a>(
            &'a self,
            _ctx: Ctx<'a>,
        ) -> BoxFuture<'a, anyhow::Result<Config>> {
            Box::pin(async { Ok(Config::default()) })
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
            unimplemented!("not used by alloc tests")
        }

        fn acquire_lease<'a>(
            &'a self,
            ctx: Ctx<'a>,
            attrs: &'a LeaseAttrs,
        ) -> BoxFuture<'a, anyhow::Result<Lease>> {
            Box::pin(async move {
                *self.recorded_attrs.lock().await = Some(attrs.clone());
                if ctx.is_cancelled() {
                    return Err(anyhow::anyhow!("context canceled"));
                }
                if let Some(msg) = &self.acquire_err {
                    return Err(anyhow::anyhow!("{msg}"));
                }
                Ok(self.lease.clone())
            })
        }

        fn renew_lease<'a>(
            &'a self,
            _ctx: Ctx<'a>,
            _lease: &'a Lease,
        ) -> BoxFuture<'a, anyhow::Result<Lease>> {
            unimplemented!("not used by alloc tests")
        }

        fn watch_lease<'a>(
            &'a self,
            _ctx: Ctx<'a>,
            _sn: IP4Net,
            _sn6: IP6Net,
            _tx: mpsc::Sender<Vec<LeaseWatchResult>>,
        ) -> BoxFuture<'a, anyhow::Result<()>> {
            unimplemented!("not used by alloc tests")
        }

        fn watch_leases<'a>(
            &'a self,
            _ctx: Ctx<'a>,
            _tx: mpsc::Sender<Vec<LeaseWatchResult>>,
        ) -> BoxFuture<'a, anyhow::Result<()>> {
            unimplemented!("not used by alloc tests")
        }

        fn complete_lease<'a>(
            &'a self,
            _ctx: Ctx<'a>,
            _lease: &'a Lease,
        ) -> BoxFuture<'a, anyhow::Result<()>> {
            unimplemented!("not used by alloc tests")
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
            "mock".to_string()
        }
    }

    fn canned_lease() -> Lease {
        Lease {
            enable_ipv4: true,
            enable_ipv6: false,
            subnet: "10.1.2.0/24".parse().unwrap(),
            ipv6_subnet: IP6Net::default(),
            attrs: LeaseAttrs::default(),
            expiration: UNIX_EPOCH,
            asof: 0,
        }
    }

    /// Loopback-backed external interface: index 1 always exists on Linux
    /// and carries a real MTU for the netlink lookup.
    fn loopback_ext_iface(ext_addr: Option<IpAddr>) -> Arc<ExternalInterface> {
        Arc::new(ExternalInterface {
            iface_index: 1,
            iface_name: "lo".to_string(),
            iface_addr: Some("127.0.0.1".parse().unwrap()),
            iface_v6_addr: None,
            ext_addr,
            ext_v6_addr: None,
        })
    }

    #[tokio::test]
    async fn register_network_acquires_lease_and_returns_simple_network() {
        let lease = canned_lease();
        let mock = Arc::new(MockManager::new(lease.clone()));
        let be = AllocBackend {
            sm: mock.clone(),
            ei: loopback_ext_iface(Some("192.168.100.5".parse().unwrap())),
        };

        let token = CancellationToken::new();
        let net = be
            .register_network(&token, &Config::default())
            .await
            .expect("register_network succeeds");

        assert_eq!(net.lease(), &lease);
        assert!(net.mtu() > 0, "loopback MTU resolved via netlink");

        // Go: attrs := lease.LeaseAttrs{PublicIP: ip.FromIP(ExtAddr)}.
        let attrs = mock.recorded_attrs.lock().await.clone().unwrap();
        assert_eq!(attrs.public_ip, IP4::from_octets(192, 168, 100, 5));
        assert!(attrs.backend_type.is_empty());
        assert!(attrs.backend_data.is_none());
    }

    #[tokio::test]
    async fn register_network_wraps_acquire_error() {
        let mut mock = MockManager::new(canned_lease());
        mock.acquire_err = Some("no subnets left".to_string());
        let be = AllocBackend {
            sm: Arc::new(mock),
            ei: loopback_ext_iface(Some("192.168.100.5".parse().unwrap())),
        };

        let token = CancellationToken::new();
        let err = be
            .register_network(&token, &Config::default())
            .await
            .err()
            .unwrap();
        assert_eq!(err.to_string(), "failed to acquire lease: no subnets left");
    }

    #[tokio::test]
    async fn register_network_passes_cancellation_error_unwrapped() {
        // Go returns context.Canceled/DeadlineExceeded without wrapping.
        let be = AllocBackend {
            sm: Arc::new(MockManager::new(canned_lease())),
            ei: loopback_ext_iface(Some("192.168.100.5".parse().unwrap())),
        };

        let token = CancellationToken::new();
        token.cancel();
        let err = be
            .register_network(&token, &Config::default())
            .await
            .err()
            .unwrap();
        assert_eq!(err.to_string(), "context canceled");
    }

    #[tokio::test]
    async fn register_network_requires_ipv4_ext_addr() {
        // Go: ip.FromIP panics with "Address is not an IPv4 address".
        let be = AllocBackend {
            sm: Arc::new(MockManager::new(canned_lease())),
            ei: loopback_ext_iface(None),
        };

        let token = CancellationToken::new();
        let err = be
            .register_network(&token, &Config::default())
            .await
            .err()
            .unwrap();
        assert_eq!(err.to_string(), "Address is not an IPv4 address");
    }

    #[test]
    fn new_backend_ctor_returns_alloc_backend() {
        let be = new_backend(
            Arc::new(MockManager::new(canned_lease())),
            loopback_ext_iface(None),
        );
        assert!(be.is_ok());
    }
}
