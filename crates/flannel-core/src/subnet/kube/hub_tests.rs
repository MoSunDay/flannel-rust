//! EventHub backpressure regression tests: a slow subscriber must slow
//! the publisher (Go single-consumer semantics) instead of being evicted,
//! and a cancelled subscriber must be retired without disturbing the rest.

use super::EventHub;
use crate::ip::{IP4Net, IP6Net, IP4};
use crate::lease::{Event, EventType, Lease, LeaseAttrs};
use std::time::{Duration, UNIX_EPOCH};

fn subnet(n: u32) -> IP4Net {
    IP4Net::new(IP4(n), 24)
}

fn event(n: u32) -> Event {
    Event {
        event_type: EventType::Added,
        lease: Lease {
            enable_ipv4: true,
            enable_ipv6: false,
            subnet: subnet(n),
            ipv6_subnet: IP6Net::default(),
            attrs: LeaseAttrs::default(),
            expiration: UNIX_EPOCH,
            asof: 0,
        },
    }
}

/// A subscriber whose channel is full must BLOCK the publisher (backoff
/// is the informer's), and resume once it drains — never be dropped.
#[tokio::test]
async fn publish_blocks_until_slow_subscriber_drains() {
    let hub = EventHub::new(4);
    let mut rx = hub.subscribe();

    // Fill the subscriber channel (capacity = hub capacity + backlog).
    for n in 0..4 {
        hub.publish(event(n)).await;
    }

    // The next publish has no buffer slot: it must stay pending.
    let hub2 = hub.clone();
    let pending = tokio::spawn(async move { hub2.publish(event(100)).await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !pending.is_finished(),
        "publish must block while the subscriber is full"
    );

    // Draining one event lets the pending publish through: the SAME
    // subscriber is still registered (no eviction), and no event is lost
    // (drain order: 0, then the buffered 1..=3, then the blocked 100).
    let drained = rx.recv().await;
    assert_eq!(drained.map(|e| e.lease.subnet), Some(subnet(0)));
    tokio::time::timeout(Duration::from_secs(1), pending)
        .await
        .expect("publish completed after the subscriber drained")
        .unwrap();
    assert_eq!(rx.try_recv().map(|e| e.lease.subnet), Ok(subnet(1)));
    assert_eq!(rx.try_recv().map(|e| e.lease.subnet), Ok(subnet(2)));
    assert_eq!(rx.try_recv().map(|e| e.lease.subnet), Ok(subnet(3)));
    assert_eq!(rx.try_recv().map(|e| e.lease.subnet), Ok(subnet(100)));
}

/// A subscriber that goes away (watch returned / ctx cancelled) must be
/// retired: publish keeps succeeding and later subscribers are unaffected.
#[tokio::test]
async fn publish_retires_cancelled_subscriber_and_serves_the_rest() {
    let hub = EventHub::new(8);
    let (rx1, rx2) = (hub.subscribe(), hub.subscribe());
    drop(rx1); // subscriber 1 "cancelled"

    // Retired subscriber must not wedge or fail the publish.
    hub.publish(event(1)).await;

    let mut rx2 = rx2;
    assert_eq!(rx2.try_recv().map(|e| e.lease.subnet), Ok(subnet(1)));

    // A fresh subscriber still replays the backlog (event 1).
    let mut rx3 = hub.subscribe();
    assert_eq!(rx3.try_recv().map(|e| e.lease.subnet), Ok(subnet(1)));
    hub.publish(event(2)).await;
    assert_eq!(rx2.try_recv().map(|e| e.lease.subnet), Ok(subnet(2)));
    assert_eq!(rx3.try_recv().map(|e| e.lease.subnet), Ok(subnet(2)));
}
