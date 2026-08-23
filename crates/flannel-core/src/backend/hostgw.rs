//! Port of pkg/backend/hostgw/hostgw.go (upstream cdf76059): the
//! "host-gw" backend. Pure static routing: one route per peer subnet
//! with the peer node's public IP as gateway on the external interface.
//! Requires L2 adjacency between nodes (no NAT support).

use crate::backend::common::ExternalInterface;
use crate::backend::route_network::spec::RouteSpec;
use crate::backend::route_network::{GetRouteFn, RouteNetwork};
use crate::backend::traits::{Backend, Network};
use crate::ip::iface::{get_link_mtu, Netlink};
use crate::ip::{IP4, IP6};
use crate::lease::{Lease, LeaseAttrs};
use crate::subnet::config::Config;
use crate::subnet::manager::{Ctx, Manager};
use futures::future::BoxFuture;
use netlink_packet_route::AddressFamily;
use std::net::IpAddr;
use std::sync::Arc;

/// Port of Go `HostgwBackend{sm, extIface}`.
pub struct HostgwBackend {
    pub sm: Arc<dyn Manager>,
    pub ei: Arc<ExternalInterface>,
}

/// Port of Go `hostgw.New`, registered as `"host-gw"` (Go `init()`).
/// host-gw programs routes with the peer's public IP as gateway, which
/// is only reachable when it equals the interface address (no NAT).
pub fn new_backend(
    sm: Arc<dyn Manager>,
    ei: Arc<ExternalInterface>,
) -> anyhow::Result<Box<dyn Backend>> {
    if ei.ext_addr != ei.iface_addr {
        anyhow::bail!(
            "your PublicIP differs from interface IP, meaning that probably you're on a NAT, which is not supported by host-gw backend"
        );
    }
    Ok(Box::new(HostgwBackend { sm, ei }))
}

/// Port of Go `ip.FromIP(extIface.ExtAddr)`: Go panics when the address
/// is missing or not IPv4; the Rust port fails with the same message.
fn ext_addr_ip4(ei: &ExternalInterface) -> anyhow::Result<IP4> {
    match ei.ext_addr {
        Some(IpAddr::V4(v4)) => Ok(IP4::from_bytes(v4.octets())),
        _ => anyhow::bail!("Address is not an IPv4 address"),
    }
}

/// Port of Go `ip.FromIP6(extIface.ExtV6Addr)` (same panic message).
fn ext_addr_ip6(ei: &ExternalInterface) -> anyhow::Result<IP6> {
    match ei.ext_v6_addr {
        Some(IpAddr::V6(v6)) => Ok(IP6::from_std(v6)),
        _ => anyhow::bail!("Address is not an IPv6 address"),
    }
}

/// Port of the Go `GetRoute` closure: route to the lease subnet via the
/// peer's public IP on the external link.
pub fn hostgw_get_route(link_index: u32) -> GetRouteFn {
    Arc::new(move |lease: &Lease| {
        let spec = RouteSpec {
            dst: IpAddr::V4(lease.subnet.ip.to_std()),
            prefix_len: lease.subnet.prefix_len as u8,
            gateway: IpAddr::V4(lease.attrs.public_ip.to_std()),
            link_index,
            family: AddressFamily::Inet,
            onlink: false,
        };
        Box::pin(async move { spec })
    })
}

/// Port of the Go `GetV6Route` closure.
pub fn hostgw_get_v6_route(link_index: u32) -> GetRouteFn {
    Arc::new(move |lease: &Lease| {
        let gw = lease.attrs.public_ipv6.unwrap_or_default();
        let spec = RouteSpec {
            dst: IpAddr::V6(lease.ipv6_subnet.ip.to_std()),
            prefix_len: lease.ipv6_subnet.prefix_len as u8,
            gateway: IpAddr::V6(gw.to_std()),
            link_index,
            family: AddressFamily::Inet6,
            onlink: false,
        };
        Box::pin(async move { spec })
    })
}

impl Backend for HostgwBackend {
    /// Port of Go `(*HostgwBackend).RegisterNetwork`: build the
    /// RouteNetwork with MTU/LinkIndex of the external interface, wire
    /// the per-family GetRoute closures, then acquire the lease.
    fn register_network<'a>(
        &'a self,
        ctx: Ctx<'a>,
        config: &'a Config,
    ) -> BoxFuture<'a, anyhow::Result<Box<dyn Network>>> {
        Box::pin(async move {
            let nl = Netlink::new().await?;
            // Go: Mtu/LinkIndex come from extIface.Iface; the Rust
            // ExternalInterface carries no MTU, so re-fetch via netlink.
            let mtu = get_link_mtu(&nl, self.ei.iface_index).await?;

            let mut attrs = LeaseAttrs {
                backend_type: "host-gw".to_string(),
                ..Default::default()
            };
            let mut get_route = None;
            let mut get_v6_route = None;

            if config.enable_ipv4 {
                attrs.public_ip = ext_addr_ip4(&self.ei)?;
                get_route = Some(hostgw_get_route(self.ei.iface_index));
            }

            if config.enable_ipv6 {
                attrs.public_ipv6 = Some(ext_addr_ip6(&self.ei)?);
                get_v6_route = Some(hostgw_get_v6_route(self.ei.iface_index));
            }

            let lease = match self.sm.acquire_lease(ctx, &attrs).await {
                Ok(lease) => lease,
                // Go: case context.Canceled, context.DeadlineExceeded.
                Err(e) if ctx.is_cancelled() => return Err(e),
                Err(e) => return Err(anyhow::anyhow!("failed to acquire lease: {e}")),
            };

            Ok(Box::new(RouteNetwork {
                lease,
                backend_type: "host-gw".to_string(),
                sm: self.sm.clone(),
                mtu,
                link_index: self.ei.iface_index,
                get_route,
                get_v6_route,
            }) as Box<dyn Network>)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ip::{IP4Net, IP6Net};
    use crate::lease::LeaseWatchResult;
    use crate::subnet::manager::{Ctx, Manager};
    use std::sync::Arc;
    use std::time::UNIX_EPOCH;
    use tokio::sync::{mpsc, Mutex};
    use tokio_util::sync::CancellationToken;

    fn canned_lease() -> Lease {
        Lease {
            enable_ipv4: true,
            enable_ipv6: false,
            subnet: IP4Net::new(IP4::from_octets(10, 244, 0, 0), 24),
            ipv6_subnet: IP6Net::default(),
            attrs: LeaseAttrs::default(),
            expiration: UNIX_EPOCH,
            asof: 0,
        }
    }

    /// Records `acquire_lease` attrs; optional canned error.
    struct FakeManager {
        lease: Lease,
        acquire_err: Option<String>,
        recorded_attrs: Mutex<Option<LeaseAttrs>>,
    }

    impl Manager for FakeManager {
        fn get_network_config<'a>(
            &'a self,
            _ctx: Ctx<'a>,
        ) -> BoxFuture<'a, anyhow::Result<Config>> {
            unimplemented!()
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
            unimplemented!()
        }
        fn acquire_lease<'a>(
            &'a self,
            ctx: Ctx<'a>,
            attrs: &'a LeaseAttrs,
        ) -> BoxFuture<'a, anyhow::Result<Lease>> {
            let err = self.acquire_err.clone();
            *self.recorded_attrs.try_lock().unwrap() = Some(attrs.clone());
            let lease = self.lease.clone();
            Box::pin(async move {
                if ctx.is_cancelled() {
                    return Err(anyhow::anyhow!("context canceled"));
                }
                match err {
                    Some(e) => Err(anyhow::anyhow!("{e}")),
                    None => Ok(lease),
                }
            })
        }
        fn renew_lease<'a>(
            &'a self,
            _ctx: Ctx<'a>,
            _lease: &'a Lease,
        ) -> BoxFuture<'a, anyhow::Result<Lease>> {
            unimplemented!()
        }
        fn watch_lease<'a>(
            &'a self,
            _ctx: Ctx<'a>,
            _sn: IP4Net,
            _sn6: IP6Net,
            _tx: mpsc::Sender<Vec<LeaseWatchResult>>,
        ) -> BoxFuture<'a, anyhow::Result<()>> {
            unimplemented!()
        }
        fn watch_leases<'a>(
            &'a self,
            _ctx: Ctx<'a>,
            _tx: mpsc::Sender<Vec<LeaseWatchResult>>,
        ) -> BoxFuture<'a, anyhow::Result<()>> {
            unimplemented!()
        }
        fn complete_lease<'a>(
            &'a self,
            _ctx: Ctx<'a>,
            _lease: &'a Lease,
        ) -> BoxFuture<'a, anyhow::Result<()>> {
            unimplemented!()
        }
        fn get_stored_mac_addresses<'a>(
            &'a self,
            _ctx: Ctx<'a>,
        ) -> BoxFuture<'a, (String, String)> {
            unimplemented!()
        }
        fn get_stored_public_ip<'a>(&'a self, _ctx: Ctx<'a>) -> BoxFuture<'a, (String, String)> {
            unimplemented!()
        }
        fn name(&self) -> String {
            "fake".to_string()
        }
    }

    fn fake_manager(acquire_err: Option<String>) -> FakeManager {
        FakeManager {
            lease: canned_lease(),
            acquire_err,
            recorded_attrs: Mutex::new(None),
        }
    }

    /// Loopback external interface (index 1 exists on every Linux host;
    /// register_network only reads its MTU, so no NET_ADMIN is needed).
    fn loopback_ei(ext_addr: Option<IpAddr>) -> Arc<ExternalInterface> {
        Arc::new(ExternalInterface {
            iface_index: 1,
            iface_name: "lo".to_string(),
            iface_addr: Some("127.0.0.1".parse().unwrap()),
            iface_v6_addr: Some("::1".parse().unwrap()),
            ext_addr,
            ext_v6_addr: Some("::1".parse().unwrap()),
        })
    }

    #[test]
    fn new_backend_rejects_nat() {
        // Go: ExtAddr != IfaceAddr means NAT, which host-gw cannot do.
        let ei = loopback_ei(Some("192.0.2.99".parse().unwrap()));
        let err = new_backend(Arc::new(fake_manager(None)), ei).err().unwrap();
        assert_eq!(
            err.to_string(),
            "your PublicIP differs from interface IP, meaning that probably you're on a NAT, which is not supported by host-gw backend"
        );
    }

    #[test]
    fn new_backend_ok_when_ext_addr_matches_iface() {
        let be = new_backend(
            Arc::new(fake_manager(None)),
            loopback_ei(Some("127.0.0.1".parse().unwrap())),
        );
        assert!(be.is_ok());
    }

    #[tokio::test]
    async fn get_route_builds_route_to_lease_subnet_via_public_ip() {
        let lease = Lease {
            attrs: LeaseAttrs {
                public_ip: IP4::from_octets(192, 168, 77, 10),
                ..Default::default()
            },
            subnet: IP4Net::new(IP4::from_octets(10, 244, 1, 0), 24),
            ..canned_lease()
        };
        let spec = hostgw_get_route(7)(&lease).await;
        assert_eq!(spec.dst, "10.244.1.0".parse::<IpAddr>().unwrap());
        assert_eq!(spec.prefix_len, 24);
        assert_eq!(spec.gateway, "192.168.77.10".parse::<IpAddr>().unwrap());
        assert_eq!(spec.link_index, 7);
        assert_eq!(spec.family, AddressFamily::Inet);
        assert!(!spec.onlink);
    }

    #[tokio::test]
    async fn get_v6_route_builds_route_to_lease_v6_subnet() {
        let lease = Lease {
            attrs: LeaseAttrs {
                public_ipv6: Some(IP6::from_std("2001:db8::10".parse().unwrap())),
                ..Default::default()
            },
            ipv6_subnet: IP6Net {
                ip: IP6::from_std("2001:db8:ffff::".parse().unwrap()),
                prefix_len: 64,
            },
            ..canned_lease()
        };
        let spec = hostgw_get_v6_route(9)(&lease).await;
        assert_eq!(spec.dst, "2001:db8:ffff::".parse::<IpAddr>().unwrap());
        assert_eq!(spec.prefix_len, 64);
        assert_eq!(spec.gateway, "2001:db8::10".parse::<IpAddr>().unwrap());
        assert_eq!(spec.link_index, 9);
        assert_eq!(spec.family, AddressFamily::Inet6);
    }

    #[tokio::test]
    async fn register_network_wraps_acquire_error() {
        let be = HostgwBackend {
            sm: Arc::new(FakeManager {
                lease: canned_lease(),
                acquire_err: Some("no subnets left".to_string()),
                recorded_attrs: Mutex::new(None),
            }),
            ei: loopback_ei(Some("127.0.0.1".parse().unwrap())),
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
        let be = HostgwBackend {
            sm: Arc::new(fake_manager(None)),
            ei: loopback_ei(Some("127.0.0.1".parse().unwrap())),
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
    async fn register_network_builds_route_network() {
        // Read-only netlink (lo MTU lookup); no NET_ADMIN required.
        let fake = Arc::new(FakeManager {
            lease: canned_lease(),
            acquire_err: None,
            recorded_attrs: Mutex::new(None),
        });
        let be = HostgwBackend {
            sm: fake.clone(),
            ei: loopback_ei(Some("127.0.0.1".parse().unwrap())),
        };
        let config = Config {
            enable_ipv4: true,
            ..Default::default()
        };

        let token = CancellationToken::new();
        let net = be.register_network(&token, &config).await.unwrap();
        assert_eq!(net.lease().subnet, canned_lease().subnet);
        assert_eq!(net.mtu(), 65536); // lo MTU on Linux

        let attrs = fake.recorded_attrs.try_lock().unwrap().clone().unwrap();
        assert_eq!(attrs.backend_type, "host-gw");
        assert_eq!(attrs.public_ip, IP4::from_octets(127, 0, 0, 1));
    }
}
