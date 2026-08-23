//! Test-only doubles and helpers for the vxlan backend tests: a
//! [`FakeManager`] implementing [`Manager`], a netns-scoped async runner
//! (mirroring examples/netlink_spike.rs) and small fixture builders.

use crate::ip::iface::Netlink;
use crate::ip::{IP4Net, IP6Net, IP4, IP6};
use crate::lease::{Lease, LeaseAttrs, LeaseWatchResult};
use crate::subnet::config::Config;
use crate::subnet::manager::{Ctx, Manager};
use anyhow::anyhow;
use futures::future::BoxFuture;
use serde_json::value::RawValue;
use std::net::IpAddr;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::mpsc;

/// In-memory Manager for tests.
pub(crate) struct FakeManager {
    pub config: Config,
    /// GetStoredMacAddresses answer: (macv4, macv6).
    pub macs: (String, String),
    /// When Some, acquire_lease fails with this message.
    pub fail_acquire: Option<String>,
    /// Lease handed out by acquire_lease (subnet fields below).
    pub lease_subnet: IP4Net,
    pub lease_v6_subnet: IP6Net,
}

impl FakeManager {
    pub fn new(config: Config) -> Arc<Self> {
        let lease_subnet = IP4Net {
            ip: IP4(config.network.ip.0 + 0x100),
            prefix_len: config.subnet_len,
        };
        let lease_v6_subnet = IP6Net {
            ip: IP6((u128::from_be_bytes(config.ipv6_network.ip.0) + 0x100).to_be_bytes()),
            prefix_len: config.ipv6_subnet_len,
        };
        Arc::new(Self {
            config,
            macs: (String::new(), String::new()),
            fail_acquire: None,
            lease_subnet,
            lease_v6_subnet,
        })
    }
}

impl Manager for FakeManager {
    fn get_network_config<'a>(&'a self, _ctx: Ctx<'a>) -> BoxFuture<'a, anyhow::Result<Config>> {
        Box::pin(async move { Ok(self.config.clone()) })
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
        Box::pin(async { Ok(()) })
    }

    fn acquire_lease<'a>(
        &'a self,
        _ctx: Ctx<'a>,
        attrs: &'a LeaseAttrs,
    ) -> BoxFuture<'a, anyhow::Result<Lease>> {
        Box::pin(async move {
            if let Some(msg) = &self.fail_acquire {
                return Err(anyhow!("{msg}"));
            }
            Ok(Lease {
                enable_ipv4: self.config.enable_ipv4,
                enable_ipv6: self.config.enable_ipv6,
                subnet: self.lease_subnet,
                ipv6_subnet: self.lease_v6_subnet,
                attrs: attrs.clone(),
                expiration: SystemTime::now() + Duration::from_secs(3600),
                asof: 0,
            })
        })
    }

    fn renew_lease<'a>(
        &'a self,
        _ctx: Ctx<'a>,
        lease: &'a Lease,
    ) -> BoxFuture<'a, anyhow::Result<Lease>> {
        Box::pin(async move { Ok(lease.clone()) })
    }

    fn watch_lease<'a>(
        &'a self,
        ctx: Ctx<'a>,
        _sn: IP4Net,
        _sn6: IP6Net,
        _tx: mpsc::Sender<Vec<LeaseWatchResult>>,
    ) -> BoxFuture<'a, anyhow::Result<()>> {
        Box::pin(async move {
            ctx.cancelled().await;
            Ok(())
        })
    }

    fn watch_leases<'a>(
        &'a self,
        ctx: Ctx<'a>,
        _tx: mpsc::Sender<Vec<LeaseWatchResult>>,
    ) -> BoxFuture<'a, anyhow::Result<()>> {
        Box::pin(async move {
            ctx.cancelled().await;
            Ok(())
        })
    }

    fn complete_lease<'a>(
        &'a self,
        _ctx: Ctx<'a>,
        _lease: &'a Lease,
    ) -> BoxFuture<'a, anyhow::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn get_stored_mac_addresses<'a>(&'a self, _ctx: Ctx<'a>) -> BoxFuture<'a, (String, String)> {
        Box::pin(async move { self.macs.clone() })
    }

    fn get_stored_public_ip<'a>(&'a self, _ctx: Ctx<'a>) -> BoxFuture<'a, (String, String)> {
        Box::pin(async { (String::new(), String::new()) })
    }

    fn name(&self) -> String {
        "Fake Subnet Manager".to_string()
    }
}

/// Run a future inside a scratch netns on a single-threaded runtime
/// (multi-threaded workers would open sockets in the host netns). The ns
/// is removed even on panic, matching route_network/tests_netns.rs.
pub(crate) fn netns_block_on<F: std::future::Future<Output = anyhow::Result<()>>>(
    name: &str,
    fut: F,
) -> anyhow::Result<()> {
    // Best-effort cleanup of a stale ns from a crashed previous run.
    if let Ok(old) = netns_rs::NetNs::get(name) {
        let _ = old.remove();
    }
    let ns = netns_rs::NetNs::new(name)?;
    ns.enter()?;
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(fut)
    }));
    let removed = ns.remove();
    match result {
        Ok(inner) => {
            removed.map_err(|e| anyhow!("netns remove: {e}"))?;
            inner
        }
        Err(panic) => {
            let _ = removed;
            std::panic::resume_unwind(panic)
        }
    }
}

/// Create a dummy link `name` with the given v4/v6 addresses (the test's
/// "external interface") and bring it up; returns its ifindex.
pub(crate) async fn setup_ext_iface(
    nl: &Netlink,
    name: &str,
    v4: Option<(IpAddr, u8)>,
    v6: Option<(IpAddr, u8)>,
) -> anyhow::Result<u32> {
    nl.handle
        .link()
        .add(rtnetlink::LinkDummy::new(name).build())
        .execute()
        .await?;
    let link = super::link_info::get_link_by_name(nl, name).await?;
    let idx = link.header.index;
    if let Some((addr, prefix)) = v4 {
        nl.handle.address().add(idx, addr, prefix).execute().await?;
    }
    if let Some((addr, prefix)) = v6 {
        nl.handle.address().add(idx, addr, prefix).execute().await?;
    }
    nl.handle
        .link()
        .set(rtnetlink::LinkUnspec::new_with_index(idx).up().build())
        .execute()
        .await?;
    Ok(idx)
}

/// Minimal flannel Config for tests: 10.1.0.0/16 (/24 subnets) and
/// fd00:1::/64 (/80 subnets), backend JSON from `backend` if given.
pub(crate) fn test_config(enable_v4: bool, enable_v6: bool, backend: Option<&str>) -> Config {
    let backend = backend.map(|s| RawValue::from_string(s.to_string()).unwrap());
    Config {
        enable_ipv4: enable_v4,
        enable_ipv6: enable_v6,
        network: IP4Net {
            ip: IP4::from_bytes([10, 1, 0, 0]),
            prefix_len: 16,
        },
        ipv6_network: IP6Net {
            ip: IP6::from_std("fd00:1::".parse().unwrap()),
            prefix_len: 64,
        },
        subnet_len: 24,
        ipv6_subnet_len: 80,
        backend,
        ..Default::default()
    }
}

/// VXLAN BackendData JSON as written by new_subnet_attrs.
pub(crate) fn vxlan_backend_data(vni: u32, mac: &str) -> Box<RawValue> {
    RawValue::from_string(format!("{{\"VNI\":{vni},\"VtepMAC\":\"{mac}\"}}")).unwrap()
}
