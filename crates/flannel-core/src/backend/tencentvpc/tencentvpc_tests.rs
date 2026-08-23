//! Full-flow tests: `register_network_with` against axum mocks of the
//! metadata service and VPC API endpoint (both injectable; Go hardcodes them).

use super::*;
use crate::ip::{IP4Net, IP6Net};
use crate::lease::{Lease, LeaseWatchResult};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::UNIX_EPOCH;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

const TEST_MAC: &str = "52:54:00:b4:00:01";
const TEST_VPC_ID: &str = "vpc-test01";

fn canned_lease() -> Lease {
    Lease {
        enable_ipv4: true,
        enable_ipv6: false,
        subnet: IP4Net::new(IP4::from_octets(10, 244, 7, 0), 24),
        ipv6_subnet: IP6Net::default(),
        attrs: LeaseAttrs::default(),
        expiration: UNIX_EPOCH,
        asof: 0,
    }
}

/// Records acquire_lease attrs; all other Manager methods unused here.
struct MockManager {
    lease: Lease,
    attrs_seen: Mutex<Option<LeaseAttrs>>,
}

impl Manager for MockManager {
    fn get_network_config<'a>(&'a self, _ctx: Ctx<'a>) -> BoxFuture<'a, anyhow::Result<Config>> {
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
        _ctx: Ctx<'a>,
        attrs: &'a LeaseAttrs,
    ) -> BoxFuture<'a, anyhow::Result<Lease>> {
        *self.attrs_seen.lock().unwrap() = Some(attrs.clone());
        let lease = self.lease.clone();
        Box::pin(async move { Ok(lease) })
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
    fn get_stored_mac_addresses<'a>(&'a self, _ctx: Ctx<'a>) -> BoxFuture<'a, (String, String)> {
        unimplemented!()
    }
    fn get_stored_public_ip<'a>(&'a self, _ctx: Ctx<'a>) -> BoxFuture<'a, (String, String)> {
        unimplemented!()
    }
    fn name(&self) -> String {
        "Mock Subnet Manager".to_string()
    }
}

fn test_ei() -> Arc<ExternalInterface> {
    Arc::new(ExternalInterface {
        iface_index: 1, // lo
        iface_name: "lo".to_string(),
        iface_addr: Some("127.0.0.1".parse().unwrap()),
        iface_v6_addr: None,
        ext_addr: Some("192.0.2.10".parse().unwrap()),
        ext_v6_addr: None,
    })
}

fn keys_config() -> Config {
    Config {
        backend: Some(
            serde_json::from_str(
                r#"{"AccessKeyID": "akid-test", "AccessKeySecret": "secret-test"}"#,
            )
            .unwrap(),
        ),
        ..Default::default()
    }
}

async fn serve(router: Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    addr
}

async fn meta_region() -> &'static str {
    "ap-guangzhou"
}

async fn meta_vpc_id(Path(mac): Path<String>) -> impl IntoResponse {
    if mac == TEST_MAC {
        (StatusCode::OK, TEST_VPC_ID).into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

async fn spawn_metadata(with_region: bool) -> String {
    let mut router = Router::new()
        .route("/latest/meta-data/mac", get(|| async { TEST_MAC }))
        .route(
            "/latest/meta-data/network/interfaces/macs/{mac}/vpc-id",
            get(meta_vpc_id),
        );
    if with_region {
        router = router.route("/latest/meta-data/placement/region", get(meta_region));
    }
    format!("http://{}", serve(router).await)
}

/// (X-TC-Action, JSON body) of every request against the mock VPC API.
type Captured = Arc<Mutex<Vec<(String, Value)>>>;

#[derive(Clone)]
struct ApiState {
    describe_response: Value,
    captured: Captured,
}

async fn api_handler(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Json<Value> {
    let action = headers
        .get("x-tc-action")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    state
        .captured
        .lock()
        .unwrap()
        .push((action.clone(), serde_json::from_slice(&body).unwrap()));
    if action == "DescribeRouteTables" {
        Json(state.describe_response)
    } else {
        Json(json!({"Response": {"RequestId": "req-ok"}}))
    }
}

async fn spawn_api(describe_response: Value) -> (String, Captured) {
    let captured: Captured = Arc::new(Mutex::new(Vec::new()));
    let router = Router::new()
        .route("/", post(api_handler))
        .with_state(ApiState {
            describe_response,
            captured: captured.clone(),
        });
    (format!("http://{}", serve(router).await), captured)
}

fn route_entry(
    route_id: &str,
    dst: &str,
    gateway: &str,
    gateway_type: &str,
    route_type: &str,
    enabled: bool,
) -> Value {
    json!({
        "RouteId": route_id,
        "DestinationCidrBlock": dst,
        "GatewayId": gateway,
        "GatewayType": gateway_type,
        "RouteType": route_type,
        "Enabled": enabled,
    })
}

fn describe_with(routes: Vec<Value>) -> Value {
    json!({
        "Response": {
            "RequestId": "req-describe",
            "TotalCount": 1,
            "RouteTableSet": [{
                "RouteTableId": "rtb-test01",
                "RouteSet": routes,
            }],
        }
    })
}

async fn run_full_flow(
    describe_response: Value,
    config: Config,
    with_region: bool,
) -> (anyhow::Result<Box<dyn Network>>, Arc<MockManager>, Captured) {
    let manager = Arc::new(MockManager {
        lease: canned_lease(),
        attrs_seen: Mutex::new(None),
    });
    let sm: Arc<dyn Manager> = manager.clone();
    let metadata_base = spawn_metadata(with_region).await;
    let (vpc_endpoint, captured) = spawn_api(describe_response).await;
    let token = CancellationToken::new();
    let result = register_network_with(
        &token,
        &config,
        &sm,
        &test_ei(),
        &metadata_base,
        &vpc_endpoint,
    )
    .await;
    (result, manager, captured)
}

#[tokio::test]
async fn register_creates_missing_route() {
    let unrelated = route_entry("5", "0.0.0.0/0", "igw-1", "NORMAL_CVM", "USER", true);
    let (result, manager, captured) =
        run_full_flow(describe_with(vec![unrelated]), keys_config(), true).await;
    let net = result.unwrap();
    assert_eq!(net.lease().subnet, canned_lease().subnet);
    assert_eq!(net.mtu(), 65536); // lo MTU on Linux

    // Go sets only PublicIP in the lease attrs (no BackendType).
    let attrs = manager.attrs_seen.lock().unwrap().clone().unwrap();
    assert_eq!(attrs.public_ip, IP4::from_octets(192, 0, 2, 10));
    assert!(attrs.backend_type.is_empty());

    let caps = captured.lock().unwrap();
    assert_eq!(caps.len(), 2);
    assert_eq!(caps[0].0, "DescribeRouteTables");
    assert_eq!(
        caps[0].1,
        json!({"Filters": [{"Name": "vpc-id", "Values": [TEST_VPC_ID]}]})
    );
    assert_eq!(caps[1].0, "CreateRoutes");
    assert_eq!(
        caps[1].1,
        json!({"RouteTableId": "rtb-test01", "Routes": [{
            "DestinationCidrBlock": "10.244.7.0/24",
            "GatewayType": "NORMAL_CVM",
            "GatewayId": "192.0.2.10",
            "Enabled": true,
        }]})
    );
}

#[tokio::test]
async fn register_keeps_enabled_matching_route() {
    let matching = route_entry(
        "42",
        "10.244.7.0/24",
        "192.0.2.10",
        "NORMAL_CVM",
        "USER",
        true,
    );
    let (result, _manager, captured) =
        run_full_flow(describe_with(vec![matching]), keys_config(), true).await;
    result.unwrap();
    let caps = captured.lock().unwrap();
    assert_eq!(caps.len(), 1);
    assert_eq!(caps[0].0, "DescribeRouteTables");
}

#[tokio::test]
async fn register_replaces_disabled_matching_route() {
    let disabled = route_entry(
        "42",
        "10.244.7.0/24",
        "192.0.2.10",
        "NORMAL_CVM",
        "USER",
        false,
    );
    let unrelated = route_entry("5", "0.0.0.0/0", "igw-1", "NORMAL_CVM", "USER", true);
    let (result, _manager, captured) = run_full_flow(
        describe_with(vec![disabled, unrelated]),
        keys_config(),
        true,
    )
    .await;
    result.unwrap();
    let caps = captured.lock().unwrap();
    assert_eq!(caps.len(), 3);
    assert_eq!(caps[0].0, "DescribeRouteTables");
    assert_eq!(caps[1].0, "DeleteRoutes");
    assert_eq!(
        caps[1].1,
        json!({"RouteTableId": "rtb-test01", "Routes": [{"RouteId": "42"}]})
    );
    assert_eq!(caps[2].0, "CreateRoutes");
}

#[tokio::test]
async fn register_fails_without_route_tables() {
    // RouteTableSet empty at the top level: Go's "no suitable routing
    // table found" branch (a table with an empty RouteSet is fine).
    let no_tables = json!({
        "Response": {"RequestId": "req-describe", "TotalCount": 0, "RouteTableSet": []}
    });
    let (result, _manager, _captured) = run_full_flow(no_tables, keys_config(), true).await;
    let err = result.err().unwrap();
    assert_eq!(err.to_string(), "no suitable routing table found");
}

#[tokio::test]
async fn register_requires_keys_when_missing() {
    std::env::remove_var("ACCESS_KEY_ID");
    std::env::remove_var("ACCESS_KEY_SECRET");
    let (result, _manager, _captured) =
        run_full_flow(describe_with(vec![]), Config::default(), true).await;
    let err = result.err().unwrap();
    // Go's message has a trailing space; matched exactly.
    assert_eq!(
        err.to_string(),
        "ACCESS_KEY_ID and ACCESS_KEY_SECRET must be provided! "
    );
}

#[tokio::test]
async fn register_propagates_metadata_region_error() {
    let (result, _manager, _captured) =
        run_full_flow(describe_with(vec![]), keys_config(), false).await;
    let err = result.err().unwrap();
    assert_eq!(err.to_string(), "get vm region error: <nil>");
}

#[test]
fn parse_backend_config_forms() {
    // No backend section: zero values (Go's empty struct literal).
    let cfg = parse_backend_config(&Config::default()).unwrap();
    assert!(cfg.access_key_id.is_empty() && cfg.access_key_secret.is_empty());

    // Valid backend section.
    let cfg = parse_backend_config(&keys_config()).unwrap();
    assert_eq!(cfg.access_key_id, "akid-test");
    assert_eq!(cfg.access_key_secret, "secret-test");

    // Decode failure keeps Go's error prefix.
    let bad: Config = Config {
        backend: Some(serde_json::from_str(r#"{"AccessKeyID": 123}"#).unwrap()),
        ..Default::default()
    };
    let err = parse_backend_config(&bad).err().unwrap();
    assert!(
        err.to_string()
            .starts_with("error decoding VPC backend config:"),
        "{err}"
    );

    // Debug never exposes the secret (Go logs it in the clear).
    let rendered = format!("{cfg:?}");
    assert!(rendered.contains("akid-test"));
    assert!(!rendered.contains("secret-test"));
}
