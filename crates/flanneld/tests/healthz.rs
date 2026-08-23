//! healthz/readyz server tests: /healthz always 200 once up, /readyz
//! 503 until the ready flag flips, graceful shutdown on cancel.

use flanneld::healthz::{new_ready_flag, spawn_healthz};
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn healthz_and_readyz_lifecycle() {
    let ready = new_ready_flag();
    let cancel = CancellationToken::new();
    // Port 0: ephemeral port, no clash with other tests.
    let (addr, handle) = spawn_healthz("127.0.0.1", 0, ready.clone(), cancel.clone())
        .await
        .unwrap();

    let client = reqwest::Client::new();
    let healthz = client
        .get(format!("http://{addr}/healthz"))
        .send()
        .await
        .unwrap();
    assert_eq!(healthz.status(), 200);
    assert_eq!(healthz.text().await.unwrap(), "flanneld is running");

    // Not ready yet: 503 with the Go message.
    let readyz = client
        .get(format!("http://{addr}/readyz"))
        .send()
        .await
        .unwrap();
    assert_eq!(readyz.status(), 503);
    assert_eq!(readyz.text().await.unwrap(), "flanneld is not ready yet");

    // Subnet file written -> ready -> 200.
    ready.store(true, Ordering::SeqCst);
    let readyz = client
        .get(format!("http://{addr}/readyz"))
        .send()
        .await
        .unwrap();
    assert_eq!(readyz.status(), 200);
    assert_eq!(readyz.text().await.unwrap(), "flanneld is ready");

    // Unknown paths 404 (axum default).
    let nf = client
        .get(format!("http://{addr}/nope"))
        .send()
        .await
        .unwrap();
    assert_eq!(nf.status(), 404);

    // Cancel shuts the server down.
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .expect("server task exits after cancel")
        .unwrap();
    assert!(
        client
            .get(format!("http://{addr}/healthz"))
            .send()
            .await
            .is_err(),
        "server must be down after cancel"
    );
}

#[tokio::test]
async fn bind_failure_is_an_error() {
    let cancel = CancellationToken::new();
    // 203.0.113.0/24 (TEST-NET-3) is reserved and never assigned to a
    // local interface, so the bind must fail (EADDRNOTAVAIL).
    let err = spawn_healthz("203.0.113.1", 0, new_ready_flag(), cancel)
        .await
        .unwrap_err();
    assert!(err.to_string().starts_with("bind "));
}
