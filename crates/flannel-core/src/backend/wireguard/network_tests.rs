//! Tests for the wireguard run loop (network.rs): a failed watch session
//! must not end run() (the watch wrapper retries it), and run() must
//! return promptly on cancellation. No wg device is needed: no events are
//! ever processed.

use super::new_wireguard_network;
use crate::backend::common::ExternalInterface;
use crate::backend::traits::Network;
use crate::backend::wireguard::Mode;
use crate::ip::{IP4Net, IP6Net};
use crate::lease::{Lease, LeaseAttrs, LeaseWatchResult};
use crate::subnet::config::Config;
use crate::subnet::manager::{Ctx, Manager};
use futures::future::BoxFuture;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Manager whose first watch session fails and whose later sessions park
/// until cancellation (Go parity: a watch error never tears down the run
/// loop -- the watch is re-established).
struct ErrOnceManager(AtomicU32);

impl Manager for ErrOnceManager {
    fn get_network_config<'a>(&'a self, _ctx: Ctx<'a>) -> BoxFuture<'a, anyhow::Result<Config>> {
        Box::pin(async { Ok(Config::default()) })
    }
    fn handle_subnet_file<'a>(
        &'a self,
        _: &'a str,
        _: &'a Config,
        _: bool,
        _: IP4Net,
        _: IP6Net,
        _: u32,
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
        lease: &'a Lease,
    ) -> BoxFuture<'a, anyhow::Result<Lease>> {
        Box::pin(async move { Ok(lease.clone()) })
    }
    fn watch_lease<'a>(
        &'a self,
        _ctx: Ctx<'a>,
        _: IP4Net,
        _: IP6Net,
        _: mpsc::Sender<Vec<LeaseWatchResult>>,
    ) -> BoxFuture<'a, anyhow::Result<()>> {
        Box::pin(std::future::pending())
    }
    fn watch_leases<'a>(
        &'a self,
        _ctx: Ctx<'a>,
        tx: mpsc::Sender<Vec<LeaseWatchResult>>,
    ) -> BoxFuture<'a, anyhow::Result<()>> {
        Box::pin(async move {
            if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
                anyhow::bail!("boom");
            }
            // Hold the session channel open like the real managers do;
            // dropping it would look like an ended session.
            let _keep_open = tx;
            std::future::pending().await
        })
    }
    fn complete_lease<'a>(
        &'a self,
        _ctx: Ctx<'a>,
        _lease: &'a Lease,
    ) -> BoxFuture<'a, anyhow::Result<()>> {
        Box::pin(async { Ok(()) })
    }
    fn get_stored_mac_addresses<'a>(&'a self, _c: Ctx<'a>) -> BoxFuture<'a, (String, String)> {
        Box::pin(async { (String::new(), String::new()) })
    }
    fn get_stored_public_ip<'a>(&'a self, _c: Ctx<'a>) -> BoxFuture<'a, (String, String)> {
        Box::pin(async { (String::new(), String::new()) })
    }
    fn name(&self) -> String {
        "err-once".to_string()
    }
}

fn lease() -> Lease {
    Lease {
        enable_ipv4: true,
        enable_ipv6: false,
        subnet: IP4Net::new(crate::ip::IP4::from_octets(10, 1, 2, 0), 24),
        ipv6_subnet: IP6Net::default(),
        attrs: LeaseAttrs::default(),
        expiration: UNIX_EPOCH,
        asof: 0,
    }
}

/// A watch error must not end run(): the wrapper retries it (Go parity).
/// run() must still return promptly once the token is cancelled, joining
/// the watch task (no leaked task holding the channel sender).
#[tokio::test]
async fn run_survives_watch_error_and_returns_on_cancel() {
    let sm = Arc::new(ErrOnceManager(AtomicU32::new(0)));
    let net = new_wireguard_network(
        sm.clone(),
        Arc::new(ExternalInterface::default()),
        None,
        None,
        Mode::Ipv4,
        lease(),
        1500,
    );

    let ctx = CancellationToken::new();
    let tok = ctx.clone();
    let handle = tokio::spawn(async move { net.run(&tok).await });

    // Give the first watch session time to fail: run() must still be
    // serving (the pre-fix code tore the run loop down on this error).
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        sm.0.load(Ordering::SeqCst) >= 1,
        "watch session did not run"
    );
    assert!(
        !handle.is_finished(),
        "run() ended after a watch error instead of retrying"
    );

    ctx.cancel();
    tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .expect("run() should return after cancellation")
        .unwrap();
}
