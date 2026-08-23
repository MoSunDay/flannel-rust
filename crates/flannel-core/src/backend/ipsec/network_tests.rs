//! Tests for network.rs: MTU overhead arithmetic, policy-spec mapping
//! and a live-kernel add/update/delete orchestration run.

use super::xfrm::{self, DIR_OUT};
use super::{add_ipsec_policies, delete_ipsec_policies, new_network, policy_spec, DEFAULT_REQ_ID};
use crate::backend::ipsec::charon::Charon;
use crate::backend::traits::Network;
use crate::ip::{IP4Net, IP6Net};
use crate::lease::{Lease, LeaseAttrs, LeaseWatchResult};
use crate::subnet::config::Config;
use crate::subnet::manager::{Ctx, Manager};
use futures::future::BoxFuture;
use std::sync::Arc;
use std::time::UNIX_EPOCH;
use tokio::sync::mpsc;

/// Minimal Manager stub (none of these paths are exercised here).
struct NullManager;

impl Manager for NullManager {
    fn get_network_config<'a>(&'a self, _ctx: Ctx<'a>) -> BoxFuture<'a, anyhow::Result<Config>> {
        Box::pin(async { anyhow::bail!("not used") })
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
        _attrs: &'a LeaseAttrs,
    ) -> BoxFuture<'a, anyhow::Result<Lease>> {
        Box::pin(async { anyhow::bail!("not used") })
    }
    fn renew_lease<'a>(
        &'a self,
        _ctx: Ctx<'a>,
        _lease: &'a Lease,
    ) -> BoxFuture<'a, anyhow::Result<Lease>> {
        Box::pin(async { anyhow::bail!("not used") })
    }
    fn watch_lease<'a>(
        &'a self,
        _ctx: Ctx<'a>,
        _sn: IP4Net,
        _sn6: IP6Net,
        _tx: mpsc::Sender<Vec<LeaseWatchResult>>,
    ) -> BoxFuture<'a, anyhow::Result<()>> {
        Box::pin(std::future::pending())
    }
    fn watch_leases<'a>(
        &'a self,
        _ctx: Ctx<'a>,
        _tx: mpsc::Sender<Vec<LeaseWatchResult>>,
    ) -> BoxFuture<'a, anyhow::Result<()>> {
        Box::pin(std::future::pending())
    }
    fn complete_lease<'a>(
        &'a self,
        _ctx: Ctx<'a>,
        _lease: &'a Lease,
    ) -> BoxFuture<'a, anyhow::Result<()>> {
        Box::pin(async { Ok(()) })
    }
    fn get_stored_mac_addresses<'a>(&'a self, _ctx: Ctx<'a>) -> BoxFuture<'a, (String, String)> {
        Box::pin(async { (String::new(), String::new()) })
    }
    fn get_stored_public_ip<'a>(&'a self, _ctx: Ctx<'a>) -> BoxFuture<'a, (String, String)> {
        Box::pin(async { (String::new(), String::new()) })
    }
    fn name(&self) -> String {
        "null".to_string()
    }
}

fn lease(public_ip: &str, subnet: &str) -> Lease {
    Lease {
        enable_ipv4: true,
        enable_ipv6: false,
        subnet: subnet.parse().unwrap(),
        ipv6_subnet: IP6Net::default(),
        attrs: LeaseAttrs {
            public_ip: public_ip.parse().unwrap(),
            ..Default::default()
        },
        expiration: UNIX_EPOCH,
        asof: 0,
    }
}

#[test]
fn mtu_subtracts_ipsec_and_optional_udp_encap_overhead() {
    let sm: Arc<dyn Manager> = Arc::new(NullManager);
    let l = lease("10.0.0.1", "10.1.0.0/24");
    let plain = new_network(
        sm.clone(),
        1500,
        false,
        "pw".into(),
        Charon {
            esp_proposal: String::new(),
        },
        l.clone(),
    );
    assert_eq!(plain.mtu(), 1500 - 77);
    let encap = new_network(
        sm,
        1500,
        true,
        "pw".into(),
        Charon {
            esp_proposal: String::new(),
        },
        l,
    );
    assert_eq!(encap.mtu(), 1500 - 77 - 8);
}

#[test]
fn policy_spec_maps_subnets_to_selector_and_ips_to_template() {
    let local = lease("10.98.100.1", "10.98.1.0/24");
    let remote = lease("10.98.100.2", "10.98.2.0/24");
    let spec = policy_spec(&local, &remote, DIR_OUT, DEFAULT_REQ_ID);
    assert_eq!(spec.src.to_string(), "10.98.1.0");
    assert_eq!(spec.src_prefix, 24);
    assert_eq!(spec.dst.to_string(), "10.98.2.0");
    assert_eq!(spec.dst_prefix, 24);
    assert_eq!(spec.dir, DIR_OUT);
    assert_eq!(spec.tunnel_src.to_string(), "10.98.100.1");
    assert_eq!(spec.tunnel_dst.to_string(), "10.98.100.2");
    assert_eq!(spec.reqid, DEFAULT_REQ_ID);
}

/// Full add (twice, exercising the update path) then delete of all six
/// policies, checked against the kernel state.
#[tokio::test]
async fn policies_add_update_and_delete_lifecycle() {
    let local = lease("10.98.100.1", "10.98.1.0/24");
    let remote = lease("10.98.100.2", "10.98.2.0/24");
    add_ipsec_policies(&local, &remote, DEFAULT_REQ_ID)
        .await
        .expect("add policies");
    // second add hits the update branch and must not fail
    add_ipsec_policies(&local, &remote, DEFAULT_REQ_ID)
        .await
        .expect("add policies again (update path)");
    let out = policy_spec(&local, &remote, DIR_OUT, DEFAULT_REQ_ID);
    assert!(xfrm::get_policy(&out).unwrap().is_some());
    delete_ipsec_policies(&local, &remote, DEFAULT_REQ_ID)
        .await
        .expect("delete policies");
    assert!(xfrm::get_policy(&out).unwrap().is_none());
}
