//! Port of the Tencent Cloud VM metadata helpers of
//! pkg/backend/tencentvpc/tencentvpc.go (`get_vm_metadata`,
//! `get_vm_region`, `get_vm_vpcid`, upstream cdf76059). The backend
//! uses the metadata service to learn its own region and VPC id.
//!
//! Go deviations (documented):
//! - Go hardcodes the base URL `http://metadata.tencentyun.com`; here
//!   every function takes the base URL so tests can point at a local
//!   mock. Production call sites pass [`DEFAULT_METADATA_BASE`].
//! - Faithful Go quirk: `get_vm_metadata` reports every failure as
//!   "get vm region error: ..." and formats its (nil) error for a
//!   non-200 status, so that message reads "get vm region error:
//!   <nil>". Both strings are reproduced exactly.

use anyhow::anyhow;

/// Base URL of the Tencent Cloud VM metadata service (hardcoded in Go).
pub const DEFAULT_METADATA_BASE: &str = "http://metadata.tencentyun.com";

/// Port of Go `get_vm_metadata`: GET `url` and return the body; a
/// non-200 status or transport failure is an error.
async fn get_vm_metadata(url: &str) -> anyhow::Result<String> {
    let resp = match reqwest::get(url).await {
        Ok(resp) => resp,
        // Go: fmt.Errorf("get vm region error: %v", err)
        Err(e) => return Err(anyhow!("get vm region error: {e}")),
    };
    if resp.status() != reqwest::StatusCode::OK {
        // Go formats its nil err here: "get vm region error: <nil>".
        return Err(anyhow!("get vm region error: <nil>"));
    }
    Ok(resp.text().await?)
}

/// Port of Go `get_vm_region`: `{base}/latest/meta-data/placement/region`.
pub async fn get_vm_region(base: &str) -> anyhow::Result<String> {
    get_vm_metadata(&format!("{base}/latest/meta-data/placement/region")).await
}

/// Port of Go `get_vm_vpcid`: look up the MAC, then the per-MAC vpc-id.
pub async fn get_vm_vpcid(base: &str) -> anyhow::Result<String> {
    let mac = match get_vm_metadata(&format!("{base}/latest/meta-data/mac")).await {
        Ok(mac) => mac,
        Err(e) => return Err(anyhow!("get vm mac error: {e}")),
    };
    let url = format!("{base}/latest/meta-data/network/interfaces/macs/{mac}/vpc-id");
    match get_vm_metadata(&url).await {
        Ok(vpcid) => Ok(vpcid),
        Err(e) => Err(anyhow!("get vm vpcid error: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::Path;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use axum::routing::get;
    use axum::Router;
    use std::net::SocketAddr;

    const MAC: &str = "52:54:00:b4:00:01";

    async fn serve(router: Router) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        addr
    }

    async fn region_handler() -> &'static str {
        "ap-guangzhou"
    }

    async fn mac_handler() -> &'static str {
        MAC
    }

    async fn vpc_id_handler(Path(mac): Path<String>) -> impl IntoResponse {
        if mac == MAC {
            (StatusCode::OK, "vpc-abc123").into_response()
        } else {
            StatusCode::NOT_FOUND.into_response()
        }
    }

    fn full_router() -> Router {
        Router::new()
            .route("/latest/meta-data/placement/region", get(region_handler))
            .route("/latest/meta-data/mac", get(mac_handler))
            .route(
                "/latest/meta-data/network/interfaces/macs/{mac}/vpc-id",
                get(vpc_id_handler),
            )
    }

    #[tokio::test]
    async fn get_vm_region_happy_path() {
        let base = format!("http://{}", serve(full_router()).await);
        assert_eq!(get_vm_region(&base).await.unwrap(), "ap-guangzhou");
    }

    #[tokio::test]
    async fn get_vm_region_404_reports_nil_like_go() {
        let base = format!("http://{}", serve(Router::new()).await);
        let err = get_vm_region(&base).await.err().unwrap();
        assert_eq!(err.to_string(), "get vm region error: <nil>");
    }

    #[tokio::test]
    async fn get_vm_vpcid_happy_path() {
        let base = format!("http://{}", serve(full_router()).await);
        assert_eq!(get_vm_vpcid(&base).await.unwrap(), "vpc-abc123");
    }

    #[tokio::test]
    async fn get_vm_vpcid_mac_missing_wraps_inner_error() {
        let router = Router::new().route(
            "/latest/meta-data/network/interfaces/macs/{mac}/vpc-id",
            get(vpc_id_handler),
        );
        let base = format!("http://{}", serve(router).await);
        let err = get_vm_vpcid(&base).await.err().unwrap();
        assert_eq!(
            err.to_string(),
            "get vm mac error: get vm region error: <nil>"
        );
    }

    #[tokio::test]
    async fn get_vm_vpcid_vpc_lookup_missing_wraps_inner_error() {
        let router = Router::new()
            .route("/latest/meta-data/placement/region", get(region_handler))
            .route("/latest/meta-data/mac", get(mac_handler));
        let base = format!("http://{}", serve(router).await);
        let err = get_vm_vpcid(&base).await.err().unwrap();
        assert_eq!(
            err.to_string(),
            "get vm vpcid error: get vm region error: <nil>"
        );
    }
}
