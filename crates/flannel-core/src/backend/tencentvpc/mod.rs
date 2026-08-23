//! Port of pkg/backend/tencentvpc/tencentvpc.go (upstream cdf76059):
//! the "tencent-vpc" backend. Ensures the VPC route table holds one
//! route for this node's lease subnet (gateway = external address),
//! managing it through the Tencent Cloud VPC HTTP API with metadata
//! service lookups for region and VPC id.
//!
//! Go deviations (documented):
//! - The metadata base URL and VPC API endpoint are injectable
//!   constants ([`metadata::DEFAULT_METADATA_BASE`],
//!   [`api::DEFAULT_VPC_ENDPOINT`]) so tests can point at local mocks;
//!   Go hardcodes both.
//! - Go uses tencentcloud-sdk-go; here a minimal TC3-HMAC-SHA256
//!   client is hand-written in [`api`] (SDK unavailable offline).
//! - Go's `SimpleNetwork` reads `ExtIface.Iface.MTU` live; ours caches
//!   the MTU resolved at register time (see `simple_network.rs`).
//! - Go wraps `DescribeRouteTables` SDK errors with
//!   `fmt.Errorf("describe route table error: %v", ok)`, formatting a
//!   boolean and dropping the real error; the port propagates the API
//!   Code/Message from [`api`] instead.
//! - The "Unmarshal Configure" log redacts the access key secret (Go
//!   logs it in the clear).

mod api;
mod metadata;
#[cfg(test)]
#[path = "tencentvpc_tests.rs"]
mod tencentvpc_tests;

use crate::backend::common::ExternalInterface;
use crate::backend::simple_network::SimpleNetwork;
use crate::backend::traits::{Backend, Network};
use crate::ip::iface::{get_link_mtu, Netlink};
use crate::ip::IP4;
use crate::lease::LeaseAttrs;
use crate::subnet::config::Config;
use crate::subnet::manager::{Ctx, Manager};
use anyhow::{anyhow, bail};
use futures::future::BoxFuture;
use serde::Deserialize;
use std::net::IpAddr;
use std::sync::Arc;

use api::{RouteTable, VpcClient, DEFAULT_VPC_ENDPOINT};
use metadata::{get_vm_region, get_vm_vpcid, DEFAULT_METADATA_BASE};

/// Go `backendType` (registered in Go via `init()`).
pub const BACKEND_TYPE: &str = "tencent-vpc";

/// Gateway type of managed routes (Go `gatewayType` local constant).
const GATEWAY_TYPE: &str = "NORMAL_CVM";
/// Route type of managed routes (Go `routeType` local constant).
const ROUTE_TYPE: &str = "USER";

pub struct TencentVpcBackend {
    sm: Arc<dyn Manager>,
    ei: Arc<ExternalInterface>,
}

/// Port of Go `New`, registered as `"tencent-vpc"` (Go `init()`).
pub fn new_backend(
    sm: Arc<dyn Manager>,
    ei: Arc<ExternalInterface>,
) -> anyhow::Result<Box<dyn Backend>> {
    Ok(Box::new(TencentVpcBackend { sm, ei }))
}

/// Port of Go's anonymous config struct `{AccessKeyID, AccessKeySecret}`.
/// Debug is hand-written so the secret never reaches the logs.
#[derive(Default, Deserialize)]
#[serde(default)]
struct BackendConfig {
    #[serde(rename = "AccessKeyID")]
    access_key_id: String,
    #[serde(rename = "AccessKeySecret")]
    access_key_secret: String,
}

impl std::fmt::Debug for BackendConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackendConfig")
            .field("access_key_id", &self.access_key_id)
            .field("access_key_secret", &"<redacted>")
            .finish()
    }
}

/// Go: `json.Unmarshal(config.Backend, &cfg)` when Backend is non-empty.
fn parse_backend_config(config: &Config) -> anyhow::Result<BackendConfig> {
    let mut cfg = BackendConfig::default();
    if let Some(raw) = &config.backend {
        if !raw.get().is_empty() {
            cfg = serde_json::from_str(raw.get())
                .map_err(|e| anyhow!("error decoding VPC backend config: {e}"))?;
        }
    }
    Ok(cfg)
}

/// Port of Go `ip.FromIP(be.extIface.ExtAddr)` (Go panics; the port
/// fails with hostgw's message for the same conversion).
fn ext_addr_ip4(ei: &ExternalInterface) -> anyhow::Result<IP4> {
    match ei.ext_addr {
        Some(IpAddr::V4(v4)) => Ok(IP4::from_bytes(v4.octets())),
        _ => bail!("Address is not an IPv4 address"),
    }
}

impl Backend for TencentVpcBackend {
    fn register_network<'a>(
        &'a self,
        ctx: Ctx<'a>,
        config: &'a Config,
    ) -> BoxFuture<'a, anyhow::Result<Box<dyn Network>>> {
        Box::pin(register_network_with(
            ctx,
            config,
            &self.sm,
            &self.ei,
            DEFAULT_METADATA_BASE,
            DEFAULT_VPC_ENDPOINT,
        ))
    }
}

/// `register_network` with injectable metadata/VPC endpoints (Go
/// hardcodes both; see module docs).
async fn register_network_with(
    ctx: Ctx<'_>,
    config: &Config,
    sm: &Arc<dyn Manager>,
    ei: &ExternalInterface,
    metadata_base: &str,
    vpc_endpoint: &str,
) -> anyhow::Result<Box<dyn Network>> {
    // 1. Parse our configuration.
    let mut cfg = parse_backend_config(config)?;
    tracing::info!("Unmarshal Configure : {cfg:?}");

    // 2. Acquire the lease (Go sets only PublicIP, no BackendType).
    let ext_ip = ext_addr_ip4(ei)?;
    let attrs = LeaseAttrs {
        public_ip: ext_ip,
        ..Default::default()
    };
    let lease = match sm.acquire_lease(ctx, &attrs).await {
        Ok(lease) => lease,
        // Go: case context.Canceled, context.DeadlineExceeded.
        Err(e) if ctx.is_cancelled() => return Err(e),
        Err(e) => return Err(anyhow!("failed to acquire lease: {e}")),
    };

    // 3. Empty keys fall back to the environment (Go: os.Getenv).
    if cfg.access_key_id.is_empty() || cfg.access_key_secret.is_empty() {
        cfg.access_key_id = std::env::var("ACCESS_KEY_ID").unwrap_or_default();
        cfg.access_key_secret = std::env::var("ACCESS_KEY_SECRET").unwrap_or_default();
        if cfg.access_key_id.is_empty() || cfg.access_key_secret.is_empty() {
            bail!("ACCESS_KEY_ID and ACCESS_KEY_SECRET must be provided! ");
        }
    }

    // 4. Region and VPC id from the metadata service.
    let region = get_vm_region(metadata_base).await?;
    let vpc_id = get_vm_vpcid(metadata_base).await?;

    // 5. Find the route tables of our VPC.
    let client = VpcClient::new(
        &cfg.access_key_id,
        &cfg.access_key_secret,
        &region,
        vpc_endpoint,
    )?;
    let tables = client.describe_route_tables(&vpc_id).await?;
    if tables.is_empty() {
        bail!("no suitable routing table found");
    }

    // 6. Ensure the route for our subnet exists and is enabled.
    reconcile_routes(
        &client,
        &tables[0],
        &lease.subnet.to_string(),
        &ext_ip.to_string(),
    )
    .await?;

    // Go's SimpleNetwork reads ExtIface.Iface.MTU live; resolve once.
    let nl = Netlink::new().await?;
    let mtu = get_link_mtu(&nl, ei.iface_index).await?;
    Ok(Box::new(SimpleNetwork::new(lease, mtu)))
}

/// Port of Go's route scan: an enabled route matching (subnet, gateway,
/// NORMAL_CVM, USER) means nothing to do; a disabled match is deleted;
/// with no enabled match the route is created afterwards.
async fn reconcile_routes(
    client: &VpcClient,
    route_table: &RouteTable,
    subnet: &str,
    gateway: &str,
) -> anyhow::Result<()> {
    let mut exists = false;
    for route in &route_table.route_set {
        if route.destination_cidr_block == subnet
            && route.gateway_id == gateway
            && route.gateway_type == GATEWAY_TYPE
            && route.route_type == ROUTE_TYPE
        {
            if route.enabled {
                exists = true;
            } else {
                client
                    .delete_routes(&route_table.route_table_id, &route.route_id)
                    .await?;
            }
        }
    }
    if !exists {
        client
            .create_routes(&route_table.route_table_id, subnet, gateway)
            .await?;
    }
    Ok(())
}
