//! healthz/readyz HTTP server. Port of Go `mustRunHealthz` (main.go,
//! upstream cdf76059): `GET /healthz` answers 200 "flanneld is running"
//! once the server is up; `GET /readyz` answers 200 "flanneld is ready"
//! only after the subnet file has been written (the shared ready flag),
//! otherwise 503 "flanneld is not ready yet". The server shuts down
//! gracefully when the daemon's cancel token fires.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Shared "flannel is ready" flag (Go: the `isReady atomic.Bool`).
pub type ReadyFlag = Arc<AtomicBool>;

/// Create a new ready flag, initially false.
pub fn new_ready_flag() -> ReadyFlag {
    Arc::new(AtomicBool::new(false))
}

async fn healthz_handler() -> &'static str {
    "flanneld is running"
}

async fn readyz_handler(State(ready): State<ReadyFlag>) -> impl IntoResponse {
    if ready.load(Ordering::SeqCst) {
        (StatusCode::OK, "flanneld is ready")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "flanneld is not ready yet")
    }
}

/// Router for the two health endpoints (separate fn for testability).
fn healthz_router(ready: ReadyFlag) -> Router {
    Router::new()
        .route("/healthz", get(healthz_handler))
        .route("/readyz", get(readyz_handler))
        .with_state(ready)
}

/// Start the healthz server on `listen_ip:port` (port 0 picks an
/// ephemeral port, used by tests). Returns the bound address plus the
/// server task handle. Go logs `Start healthz server on <addr>` before
/// serving; a bind failure panics in Go (`mustRun`), here it is an
/// error the daemon turns into exit 1.
pub async fn spawn_healthz(
    listen_ip: &str,
    port: u16,
    ready: ReadyFlag,
    cancel: CancellationToken,
) -> anyhow::Result<(SocketAddr, JoinHandle<()>)> {
    let address = format!("{listen_ip}:{port}");
    tracing::info!("Start healthz server on {address}");

    let listener = tokio::net::TcpListener::bind(&address)
        .await
        .map_err(|e| anyhow::anyhow!("bind {address}: {e}"))?;
    let local_addr = listener.local_addr()?;

    let handle = tokio::spawn(async move {
        let result = axum::serve(listener, healthz_router(ready))
            .with_graceful_shutdown(async move {
                cancel.cancelled().await;
            })
            .await;
        if let Err(e) = result {
            tracing::error!("Start healthz server error. {e}");
        }
    });
    Ok((local_addr, handle))
}
