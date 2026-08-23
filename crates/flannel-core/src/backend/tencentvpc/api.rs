//! Minimal hand-written Tencent Cloud VPC API (2017-03-12) client.
//!
//! Go deviation: Go uses tencentcloud-sdk-go (`vpc.NewClientWithSecretId`,
//! `DescribeRouteTables`, `CreateRoutes`, `DeleteRoutes`). The SDK is not
//! available offline, so this module implements the TC3-HMAC-SHA256
//! signing scheme (https://cloud.tencent.com/document/api/215/30674) and
//! exactly the three VPC actions the backend needs, over plain JSON.
//!
//! The endpoint is injectable via [`VpcClient::new`] so tests can point
//! at a local mock; production call sites pass [`DEFAULT_VPC_ENDPOINT`].

#[cfg(test)]
#[path = "api_tests.rs"]
mod api_tests;

use anyhow::{anyhow, bail};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

/// Default VPC API endpoint (Go: SDK default). Injectable in tests.
pub const DEFAULT_VPC_ENDPOINT: &str = "https://vpc.tencentcloudapi.com";

/// `X-TC-Version` header value (Go package `vpc/v20170312`).
pub const VPC_API_VERSION: &str = "2017-03-12";

/// TC3 service name used in the credential scope.
const SERVICE: &str = "vpc";

/// Gateway type used when creating routes (Go `gatewayType`).
const GATEWAY_TYPE: &str = "NORMAL_CVM";

/// One entry of `Response.RouteTableSet[].RouteSet[]` (only the fields
/// this backend reads; Go's SDK `vpc.Route` has many more).
#[derive(Clone, Debug, Deserialize)]
pub struct Route {
    #[serde(rename = "RouteId")]
    pub route_id: String,
    #[serde(rename = "DestinationCidrBlock")]
    pub destination_cidr_block: String,
    #[serde(rename = "GatewayId")]
    pub gateway_id: String,
    #[serde(rename = "GatewayType")]
    pub gateway_type: String,
    #[serde(rename = "RouteType")]
    pub route_type: String,
    #[serde(rename = "Enabled")]
    pub enabled: bool,
}

/// One entry of `Response.RouteTableSet`.
#[derive(Clone, Debug, Deserialize)]
pub struct RouteTable {
    #[serde(rename = "RouteTableId")]
    pub route_table_id: String,
    #[serde(rename = "RouteSet", default)]
    pub route_set: Vec<Route>,
}

#[derive(Deserialize)]
struct DescribeRouteTablesPayload {
    #[serde(rename = "RouteTableSet", default)]
    route_table_set: Vec<RouteTable>,
}

#[derive(Deserialize)]
struct ApiError {
    #[serde(rename = "Code")]
    code: String,
    #[serde(rename = "Message")]
    message: String,
}

/// Client for the VPC API. Immutable except for the pooled HTTP client.
pub struct VpcClient {
    secret_id: String,
    secret_key: String,
    region: String,
    /// Full endpoint including scheme.
    endpoint: String,
    /// Host part of `endpoint` (with port when non-default); goes into
    /// the canonical request and is sent as the Host header.
    host: String,
    http: reqwest::Client,
}

impl VpcClient {
    /// `endpoint` is scheme + host[:port], e.g. [`DEFAULT_VPC_ENDPOINT`].
    pub fn new(
        secret_id: &str,
        secret_key: &str,
        region: &str,
        endpoint: &str,
    ) -> anyhow::Result<Self> {
        let url = url::Url::parse(endpoint)?;
        let host = url
            .host_str()
            .ok_or_else(|| anyhow!("endpoint has no host: {endpoint}"))?;
        let host = match url.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_string(),
        };
        Ok(Self {
            secret_id: secret_id.to_string(),
            secret_key: secret_key.to_string(),
            region: region.to_string(),
            endpoint: endpoint.to_string(),
            host,
            http: reqwest::Client::new(),
        })
    }

    /// Port of Go `DescribeRouteTables` with a `vpc-id` filter.
    pub async fn describe_route_tables(&self, vpc_id: &str) -> anyhow::Result<Vec<RouteTable>> {
        let payload = json!({"Filters": [{"Name": "vpc-id", "Values": [vpc_id]}]});
        let response = self.send("DescribeRouteTables", &payload).await?;
        let parsed: DescribeRouteTablesPayload = serde_json::from_value(response)?;
        Ok(parsed.route_table_set)
    }

    /// Port of Go `CreateRoutes` (GatewayType NORMAL_CVM, Enabled true).
    pub async fn create_routes(
        &self,
        route_table_id: &str,
        dst_cidr: &str,
        gateway_id: &str,
    ) -> anyhow::Result<()> {
        let payload = json!({
            "RouteTableId": route_table_id,
            "Routes": [{
                "DestinationCidrBlock": dst_cidr,
                "GatewayType": GATEWAY_TYPE,
                "GatewayId": gateway_id,
                "Enabled": true,
            }],
        });
        self.send("CreateRoutes", &payload).await?;
        Ok(())
    }

    /// Port of Go `DeleteRoutes` (routes addressed by RouteId only).
    pub async fn delete_routes(&self, route_table_id: &str, route_id: &str) -> anyhow::Result<()> {
        let payload = json!({
            "RouteTableId": route_table_id,
            "Routes": [{"RouteId": route_id}],
        });
        self.send("DeleteRoutes", &payload).await?;
        Ok(())
    }

    /// Sign and POST `payload` for `action`; returns the JSON
    /// `Response` object. API-level errors become anyhow errors
    /// carrying `Error.Code` and `Error.Message`.
    async fn send(&self, action: &str, payload: &Value) -> anyhow::Result<Value> {
        let body = payload.to_string();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| anyhow!("system clock before unix epoch: {e}"))?
            .as_secs() as i64;
        let (date, signature) =
            tc3_signature(&self.secret_key, SERVICE, &self.host, timestamp, &body);
        let authorization = format!(
            "TC3-HMAC-SHA256 Credential={}/{date}/{SERVICE}/tc3_request, \
             SignedHeaders=content-type;host, Signature={signature}",
            self.secret_id
        );

        let resp = self
            .http
            .post(&self.endpoint)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::HOST, &self.host)
            .header("X-TC-Action", action)
            .header("X-TC-Version", VPC_API_VERSION)
            .header("X-TC-Timestamp", timestamp.to_string())
            .header("X-TC-Region", &self.region)
            .header(reqwest::header::AUTHORIZATION, authorization)
            .body(body)
            .send()
            .await?;

        let envelope: Value = resp.json().await?;
        let response = envelope
            .get("Response")
            .cloned()
            .ok_or_else(|| anyhow!("API response missing \"Response\" field: {envelope}"))?;
        if let Some(error) = response.get("Error") {
            let api_error: ApiError = serde_json::from_value(error.clone())?;
            bail!(
                "Tencent Cloud API error. Code: {}, Message: {}",
                api_error.code,
                api_error.message
            );
        }
        Ok(response)
    }
}

/// Lowercase-hex SHA-256 digest of `data`.
fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex(&hasher.finalize())
}

/// Raw HMAC-SHA256 of `data` under `key`.
fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Lowercase hex encoding.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// UTC calendar date (YYYY-MM-DD) of a unix timestamp. Howard
/// Hinnant's civil-from-days algorithm; no chrono dependency.
fn utc_date(timestamp: i64) -> String {
    let z = timestamp.div_euclid(86_400) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097); // day of era [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = era * 400 + yoe + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

/// TC3-HMAC-SHA256 signature for POSTing `payload` to `host`, per
/// https://cloud.tencent.com/document/api/215/30674. The canonical
/// request is `POST /\n\ncontent-type:application/json\nhost:{host}\n
/// \ncontent-type;host\n{sha256(payload)}`. Returns `(date,
/// signature_hex)`; `date` (UTC date of `timestamp`) also goes into
/// the credential scope.
pub fn tc3_signature(
    secret_key: &str,
    service: &str,
    host: &str,
    timestamp: i64,
    payload: &str,
) -> (String, String) {
    let date = utc_date(timestamp);
    let canonical_request = format!(
        "POST\n/\n\ncontent-type:application/json\nhost:{host}\n\ncontent-type;host\n{}",
        sha256_hex(payload.as_bytes())
    );
    let string_to_sign = format!(
        "TC3-HMAC-SHA256\n{timestamp}\n{date}/{service}/tc3_request\n{}",
        sha256_hex(canonical_request.as_bytes())
    );
    let k_date = hmac_sha256(format!("TC3{secret_key}").as_bytes(), date.as_bytes());
    let k_service = hmac_sha256(&k_date, service.as_bytes());
    let k_signing = hmac_sha256(&k_service, b"tc3_request");
    let signature = hex(&hmac_sha256(&k_signing, string_to_sign.as_bytes()));
    (date, signature)
}
