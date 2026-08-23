//! Tests for the hand-rolled TC3-HMAC-SHA256 VPC client: a signature
//! vector computed offline with python3 hmac/hashlib (independent of
//! the sha2/hmac crates the implementation uses), plus full request
//! roundtrips against an axum mock of the VPC API endpoint.

use super::*;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::post;
use axum::{Json, Router};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

/// One captured request against the mock VPC endpoint.
#[derive(Default, Debug)]
struct Captured {
    action: String,
    version: String,
    region: String,
    timestamp: String,
    authorization: String,
    content_type: String,
    host: String,
    body: Value,
}

type Captures = Arc<Mutex<Vec<Captured>>>;

async fn handle(
    State(captures): State<Captures>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Json<Value> {
    let get = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    };
    let action = get("x-tc-action");
    captures.lock().unwrap().push(Captured {
        version: get("x-tc-version"),
        region: get("x-tc-region"),
        timestamp: get("x-tc-timestamp"),
        authorization: get("authorization"),
        content_type: get("content-type"),
        host: get("host"),
        body: serde_json::from_slice(&body).unwrap(),
        action: action.clone(),
    });
    match action.as_str() {
        "DescribeRouteTables" => Json(json!({
            "Response": {
                "TotalCount": 1,
                "RequestId": "req-describe",
                "RouteTableSet": [{
                    "RouteTableId": "rtb-test01",
                    "RouteSet": [
                        {
                            "RouteId": "17",
                            "DestinationCidrBlock": "10.244.0.0/24",
                            "GatewayId": "192.0.2.10",
                            "GatewayType": "NORMAL_CVM",
                            "RouteType": "USER",
                            "Enabled": true
                        },
                        {
                            "RouteId": "18",
                            "DestinationCidrBlock": "0.0.0.0/0",
                            "GatewayId": "igw-1",
                            "GatewayType": "NORMAL_CVM",
                            "RouteType": "USER",
                            "Enabled": true
                        }
                    ]
                }]
            }
        })),
        _ => Json(json!({"Response": {"RequestId": "req-ok"}})),
    }
}

async fn serve(router: Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    addr
}

#[test]
fn tc3_signature_matches_offline_vector() {
    // Expected values computed offline with python3 hmac/hashlib for
    // exactly these inputs; the signature must not drift.
    let (date, signature) = tc3_signature(
        "Gu5t9xGARNpq86cd98joQYCN3TestKey",
        "vpc",
        "vpc.tencentcloudapi.com",
        1_551_113_065,
        r#"{"Filters":[{"Name":"vpc-id","Values":["vpc-123456"]}]}"#,
    );
    assert_eq!(date, "2019-02-25");
    assert_eq!(
        signature,
        "07134e15f86d5d1df10d0978a70341fe3b033d0b8f1a51def3c2a488d32f2afb"
    );
}

#[test]
fn utc_date_boundaries() {
    assert_eq!(utc_date(0), "1970-01-01");
    assert_eq!(utc_date(86_399), "1970-01-01");
    assert_eq!(utc_date(86_400), "1970-01-02");
    assert_eq!(utc_date(951_782_400), "2000-02-29"); // leap day
    assert_eq!(utc_date(1_551_113_065), "2019-02-25");
}

#[tokio::test]
async fn describe_create_delete_roundtrip() {
    let captures: Captures = Arc::new(Mutex::new(Vec::new()));
    let addr = serve(
        Router::new()
            .route("/", post(handle))
            .with_state(captures.clone()),
    )
    .await;
    let client = VpcClient::new(
        "AKIDtest",
        "secrettest",
        "ap-guangzhou",
        &format!("http://{addr}"),
    )
    .unwrap();

    // DescribeRouteTables: vpc-id filter sent, RouteTableSet parsed.
    let tables = client.describe_route_tables("vpc-abc123").await.unwrap();
    assert_eq!(tables.len(), 1);
    assert_eq!(tables[0].route_table_id, "rtb-test01");
    assert_eq!(tables[0].route_set.len(), 2);
    let route = &tables[0].route_set[0];
    assert_eq!(route.route_id, "17");
    assert_eq!(route.destination_cidr_block, "10.244.0.0/24");
    assert_eq!(route.gateway_id, "192.0.2.10");
    assert_eq!(route.gateway_type, "NORMAL_CVM");
    assert_eq!(route.route_type, "USER");
    assert!(route.enabled);

    client
        .create_routes("rtb-test01", "10.244.9.0/24", "192.0.2.99")
        .await
        .unwrap();
    client.delete_routes("rtb-test01", "17").await.unwrap();

    let caps = captures.lock().unwrap();
    assert_eq!(caps.len(), 3);

    // Header structure on every request.
    for cap in caps.iter() {
        assert_eq!(cap.version, "2017-03-12");
        assert_eq!(cap.region, "ap-guangzhou");
        assert_eq!(cap.content_type, "application/json");
        assert_eq!(cap.host, addr.to_string());
        assert!(cap.timestamp.parse::<i64>().is_ok());
        assert!(
            cap.authorization
                .starts_with("TC3-HMAC-SHA256 Credential=AKIDtest/"),
            "auth: {}",
            cap.authorization
        );
        let date = utc_date(cap.timestamp.parse().unwrap());
        assert!(
            cap.authorization.contains(&format!(
                "/{date}/vpc/tc3_request, SignedHeaders=content-type;host, Signature="
            )),
            "auth: {}",
            cap.authorization
        );
    }

    // Per-action bodies.
    assert_eq!(caps[0].action, "DescribeRouteTables");
    assert_eq!(
        caps[0].body,
        json!({"Filters":[{"Name":"vpc-id","Values":["vpc-abc123"]}]})
    );
    assert_eq!(caps[1].action, "CreateRoutes");
    assert_eq!(
        caps[1].body,
        json!({"RouteTableId":"rtb-test01","Routes":[{"DestinationCidrBlock":"10.244.9.0/24","GatewayType":"NORMAL_CVM","GatewayId":"192.0.2.99","Enabled":true}]})
    );
    assert_eq!(caps[2].action, "DeleteRoutes");
    assert_eq!(
        caps[2].body,
        json!({"RouteTableId":"rtb-test01","Routes":[{"RouteId":"17"}]})
    );
}

#[tokio::test]
async fn api_error_becomes_code_message() {
    let app = Router::new().route(
        "/error",
        post(async || {
            Json(json!({
                "Response": {
                    "Error": {
                        "Code": "InvalidVpcId.NotFound",
                        "Message": "vpc not found"
                    },
                    "RequestId": "req-err"
                }
            }))
        }),
    );
    let addr = serve(app).await;
    let client =
        VpcClient::new("id", "key", "ap-guangzhou", &format!("http://{addr}/error")).unwrap();
    let err = client
        .describe_route_tables("vpc-missing")
        .await
        .err()
        .unwrap();
    assert!(err.to_string().contains("InvalidVpcId.NotFound"), "{err}");
    assert!(err.to_string().contains("vpc not found"), "{err}");
}
