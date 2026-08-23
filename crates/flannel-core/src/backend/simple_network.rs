//! Port of pkg/backend/simple_network.go (upstream cdf76059).
//!
//! Go's `SimpleNetwork` keeps the lease plus the whole `*ExternalInterface`
//! and reads `ExtIface.Iface.MTU` on demand; the Rust `ExternalInterface`
//! carries no MTU (see `common.rs`), so the MTU is resolved once at
//! construction and cached here.

use crate::backend::traits::Network;
use crate::lease::Lease;
use crate::subnet::manager::Ctx;
use futures::future::BoxFuture;

/// Simple network implementation: just holds the subnet lease and MTU;
/// `run` does nothing but wait for cancellation (Go: `<-ctx.Done()`).
pub struct SimpleNetwork {
    lease: Lease,
    mtu: u32,
}

impl SimpleNetwork {
    /// Go: `&backend.SimpleNetwork{SubnetLease: l, ExtIface: ei}` (the MTU
    /// of `ei`'s interface is resolved by the caller).
    pub fn new(lease: Lease, mtu: u32) -> Self {
        Self { lease, mtu }
    }
}

impl Network for SimpleNetwork {
    fn lease(&self) -> &Lease {
        &self.lease
    }

    fn mtu(&self) -> u32 {
        self.mtu
    }

    fn run<'a>(&'a self, ctx: Ctx<'a>) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            ctx.cancelled().await;
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ip::IP4Net;
    use crate::lease::LeaseAttrs;
    use std::time::{Duration, UNIX_EPOCH};
    use tokio_util::sync::CancellationToken;

    fn test_lease() -> Lease {
        Lease {
            enable_ipv4: true,
            enable_ipv6: false,
            subnet: IP4Net::default(),
            ipv6_subnet: crate::ip::IP6Net::default(),
            attrs: LeaseAttrs::default(),
            expiration: UNIX_EPOCH,
            asof: 0,
        }
    }

    #[test]
    fn accessors_return_stored_values() {
        let net = SimpleNetwork::new(test_lease(), 1450);
        assert_eq!(net.mtu(), 1450);
        assert_eq!(net.lease().subnet, IP4Net::default());
    }

    #[tokio::test]
    async fn run_blocks_until_cancelled() {
        let net = SimpleNetwork::new(test_lease(), 1500);
        let token = CancellationToken::new();
        let run = net.run(&token);

        // Not cancelled yet: run must still be pending.
        assert!(tokio::time::timeout(Duration::from_millis(20), run)
            .await
            .is_err());

        // Cancel: a fresh run future completes promptly.
        token.cancel();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), net.run(&token))
                .await
                .is_ok()
        );
    }
}
