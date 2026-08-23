//! Tests for the lease module. Expectations derived strictly from
//! pkg/lease/lease.go semantics (upstream has no watcher tests).

use super::*;
use std::time::UNIX_EPOCH;

fn lease(v4: bool, v6: bool, subnet: &str, ipv6_subnet: &str) -> Lease {
    Lease {
        enable_ipv4: v4,
        enable_ipv6: v6,
        subnet: subnet.parse().unwrap(),
        ipv6_subnet: ipv6_subnet.parse().unwrap(),
        attrs: LeaseAttrs::default(),
        expiration: UNIX_EPOCH,
        asof: 0,
    }
}

fn lease_with_public_ip(v4: bool, v6: bool, subnet: &str, ipv6_subnet: &str, ip: &str) -> Lease {
    let mut l = lease(v4, v6, subnet, ipv6_subnet);
    l.attrs.public_ip = ip.parse().unwrap();
    l
}

fn added(l: Lease) -> Event {
    Event {
        event_type: EventType::Added,
        lease: l,
    }
}

fn removed(l: Lease) -> Event {
    Event {
        event_type: EventType::Removed,
        lease: l,
    }
}

const V4A: &str = "10.1.1.0/24";
const V4B: &str = "10.1.2.0/24";
const V4OWN: &str = "10.1.99.0/24";
const V6A: &str = "fd00:1:1::/64";
const V6B: &str = "fd00:1:2::/64";
const V6OWN: &str = "fd00:1:99::/64";
const V6ZERO: &str = "::/0";

#[test]
fn event_type_discriminants_match_go() {
    assert_eq!(EventType::Added as i32, 0);
    assert_eq!(EventType::Removed as i32, 1);
}

// ---------------------------------------------------------------- same_subnet

#[test]
fn same_subnet_ipv4_only_uses_v4_subnet_only() {
    let a = lease(true, false, V4A, V6A);
    // different ipv6 subnets must not matter in the ipv4-only case
    let b = lease(true, false, V4A, V6B);
    assert!(same_subnet(true, false, &a, &b));
    let c = lease(true, false, V4B, V6A);
    assert!(!same_subnet(true, false, &a, &c));
}

#[test]
fn same_subnet_ipv6_only_uses_v6_subnet_only() {
    let a = lease(false, true, V4A, V6A);
    // different ipv4 subnets must not matter in the ipv6-only case
    let b = lease(false, true, V4B, V6A);
    assert!(same_subnet(false, true, &a, &b));
    let c = lease(false, true, V4A, V6B);
    assert!(!same_subnet(false, true, &a, &c));
}

#[test]
fn same_subnet_dual_stack_requires_both() {
    let a = lease(true, true, V4A, V6A);
    let both_equal = lease(true, true, V4A, V6A);
    assert!(same_subnet(true, true, &a, &both_equal));
    // only v4 equal
    let v4_only_equal = lease(true, true, V4A, V6B);
    assert!(!same_subnet(true, true, &a, &v4_only_equal));
    // only v6 equal
    let v6_only_equal = lease(true, true, V4B, V6A);
    assert!(!same_subnet(true, true, &a, &v6_only_equal));
}

#[test]
fn same_subnet_etcd_case_compares_v4_subnet() {
    let a = lease(false, false, V4A, V6ZERO);
    let b = lease(false, false, V4A, V6ZERO);
    assert!(same_subnet(false, false, &a, &b));
    let c = lease(false, false, V4B, V6ZERO);
    assert!(!same_subnet(false, false, &a, &c));
}

// ----------------------------------------------------------------------- new

#[test]
fn new_sets_own_lease_and_empty_list() {
    let own = lease(true, false, V4OWN, V6ZERO);
    let lw = LeaseWatcher::new(own.clone());
    assert_eq!(lw.own_lease, Some(own));
    assert!(lw.leases.is_empty());
}

// --------------------------------------------------------------------- reset

#[test]
fn reset_initial_snapshot_without_own_lease() {
    let mut lw = LeaseWatcher::new(lease(true, false, V4OWN, V6ZERO));
    let a = lease(true, false, V4A, V6ZERO);
    let b = lease(true, false, V4B, V6ZERO);

    let batch = lw.reset(&[a.clone(), b.clone()]);

    assert_eq!(batch, vec![added(a.clone()), added(b.clone())]);
    assert_eq!(lw.leases, vec![a, b]);
}

#[test]
fn reset_initial_snapshot_skips_own_lease_but_stores_it() {
    let own = lease(true, false, V4OWN, V6ZERO);
    let mut lw = LeaseWatcher::new(own.clone());
    let a = lease(true, false, V4A, V6ZERO);
    // same subnet as the own lease: skipped for events
    let own_dup = lease(true, false, V4OWN, V6ZERO);
    let b = lease(true, false, V4B, V6ZERO);

    let batch = lw.reset(&[a.clone(), own_dup.clone(), b.clone()]);

    assert_eq!(batch, vec![added(a.clone()), added(b.clone())]);
    // Go copies the whole input slice over, own lease included.
    assert_eq!(lw.leases, vec![a, own_dup, b]);
    assert_eq!(lw.own_lease, Some(own));
}

#[test]
fn reset_replace_same_subnet_emits_nothing() {
    let mut lw = LeaseWatcher::new(lease(true, false, V4OWN, V6ZERO));
    let a = lease_with_public_ip(true, false, V4A, V6ZERO, "192.168.1.1");
    lw.leases = vec![a];

    // Updated lease for the same subnet: consumed silently, list refreshed.
    let a2 = lease_with_public_ip(true, false, V4A, V6ZERO, "192.168.1.2");
    let batch = lw.reset(&[a2.clone()]);

    assert!(batch.is_empty());
    assert_eq!(lw.leases, vec![a2]);
}

#[test]
fn reset_removed_lease_emits_removed() {
    let mut lw = LeaseWatcher::new(lease(true, false, V4OWN, V6ZERO));
    let a = lease(true, false, V4A, V6ZERO);
    let b = lease(true, false, V4B, V6ZERO);
    lw.leases = vec![a.clone(), b.clone()];

    let batch = lw.reset(&[a.clone()]);

    assert_eq!(batch, vec![removed(b)]);
    assert_eq!(lw.leases, vec![a]);
}

#[test]
fn reset_mixed_add_and_remove_orders_added_first() {
    let own = lease(true, false, V4OWN, V6ZERO);
    let mut lw = LeaseWatcher::new(own.clone());
    let a = lease(true, false, V4A, V6ZERO);
    lw.leases = vec![a.clone()];
    let b = lease(true, false, V4B, V6ZERO);

    // Go emits Added events (input order) first, then Removed leftovers.
    let batch = lw.reset(&[b.clone(), own.clone()]);
    assert_eq!(batch, vec![added(b.clone()), removed(a)]);
    assert_eq!(lw.leases, vec![b, own]);
}

#[test]
fn reset_ipv6_only_watcher_matches_by_v6_subnet() {
    let own = lease(false, true, "0.0.0.0/0", V6OWN);
    let mut lw = LeaseWatcher::new(own.clone());
    // Same v6 subnet as a stored lease but different v4 subnet: the stored
    // lease's flags (ipv6-only) make these match, so no event.
    let stored = lease(false, true, V4A, V6A);
    lw.leases = vec![stored];
    let refreshed = lease(false, true, V4B, V6A);

    let batch = lw.reset(&[refreshed.clone(), own]);
    assert!(batch.is_empty());
    assert_eq!(lw.leases.len(), 2);
    assert_eq!(lw.leases[0], refreshed);
}

// -------------------------------------------------------------------- update

#[test]
fn update_add_new_lease() {
    let mut lw = LeaseWatcher::new(lease(true, false, V4OWN, V6ZERO));
    let a = lease(true, false, V4A, V6ZERO);

    let batch = lw.update(&[added(a.clone())]);

    assert_eq!(batch, vec![added(a.clone())]);
    assert_eq!(lw.leases, vec![a]);
}

#[test]
fn update_skips_events_matching_own_lease_subnet() {
    let own = lease(true, false, V4OWN, V6ZERO);
    let mut lw = LeaseWatcher::new(own.clone());
    // Same subnet as the own lease: both add and remove are dropped, using
    // the event lease's own enable flags for the comparison.
    let own_dup = lease(true, false, V4OWN, V6ZERO);

    let batch = lw.update(&[added(own_dup.clone()), removed(own_dup)]);

    assert!(batch.is_empty());
    assert!(lw.leases.is_empty());
}

#[test]
fn update_add_replaces_existing_same_subnet() {
    let mut lw = LeaseWatcher::new(lease(true, false, V4OWN, V6ZERO));
    let a = lease_with_public_ip(true, false, V4A, V6ZERO, "192.168.1.1");
    lw.leases = vec![a];
    let a2 = lease_with_public_ip(true, false, V4A, V6ZERO, "192.168.1.2");

    let batch = lw.update(&[added(a2.clone())]);

    // Set semantics: overwrite in place, no duplicate entry.
    assert_eq!(batch, vec![added(a2.clone())]);
    assert_eq!(lw.leases, vec![a2]);
}

#[test]
fn update_remove_existing_returns_stored_lease() {
    let mut lw = LeaseWatcher::new(lease(true, false, V4OWN, V6ZERO));
    let stored = lease_with_public_ip(true, false, V4A, V6ZERO, "192.168.1.1");
    lw.leases = vec![stored.clone()];
    // The event carries a bare lease; Go returns the stored copy.
    let bare = lease(true, false, V4A, V6ZERO);

    let batch = lw.update(&[removed(bare)]);

    assert_eq!(batch, vec![removed(stored)]);
    assert!(lw.leases.is_empty());
}

#[test]
fn update_remove_missing_returns_event_lease() {
    let mut lw = LeaseWatcher::new(lease(true, false, V4OWN, V6ZERO));
    let b = lease(true, false, V4B, V6ZERO);
    lw.leases = vec![b.clone()];
    let a = lease(true, false, V4A, V6ZERO);

    // Not found: Go logs an error and returns the passed lease.
    let batch = lw.update(&[removed(a.clone())]);

    assert_eq!(batch, vec![removed(a)]);
    assert_eq!(lw.leases, vec![b]);
}

#[test]
fn update_mixed_sequence() {
    let mut lw = LeaseWatcher::new(lease(true, true, V4OWN, V6OWN));
    let a = lease(true, true, V4A, V6A);
    let b = lease(true, true, V4B, V6B);
    lw.leases = vec![a.clone()];

    // Add b, remove a; then re-add a under its old subnet.
    let batch = lw.update(&[added(b.clone()), removed(a.clone())]);
    assert_eq!(batch, vec![added(b.clone()), removed(a.clone())]);
    assert_eq!(lw.leases, vec![b.clone()]);

    let batch = lw.update(&[added(a.clone())]);
    assert_eq!(batch, vec![added(a.clone())]);
    assert_eq!(lw.leases, vec![b, a]);
}

#[test]
fn update_dual_stack_add_needs_both_subnets_free() {
    let own = lease(true, true, V4OWN, V6OWN);
    let mut lw = LeaseWatcher::new(own.clone());
    // Stored lease shares only the v4 subnet with the incoming one; with
    // the stored lease's dual-stack flags that is NOT the same subnet, so
    // the incoming lease is appended, not overwritten.
    let stored = lease(true, true, V4A, V6A);
    lw.leases = vec![stored.clone()];
    let incoming = lease(true, true, V4A, V6B);

    let batch = lw.update(&[added(incoming.clone())]);

    assert_eq!(batch, vec![added(incoming.clone())]);
    assert_eq!(lw.leases, vec![stored, incoming]);
}

// ------------------------------------------------------- LeaseAttrs Display

#[test]
fn lease_attrs_display_full() {
    let attrs = LeaseAttrs {
        public_ip: "192.168.1.10".parse().unwrap(),
        public_ipv6: Some("fd00::1".parse().unwrap()),
        backend_type: "vxlan".to_string(),
        backend_data: Some(
            RawValue::from_string("{\"VNI\":1,\"VtepMAC\":\"aa:bb:cc:dd:ee:ff\"}".to_string())
                .unwrap(),
        ),
        backend_v6_data: Some(RawValue::from_string("{\"VNI\":2}".to_string()).unwrap()),
    };
    assert_eq!(
        attrs.to_string(),
        "BackendType: vxlan, PublicIP: 192.168.1.10, PublicIPv6: fd00::1, \
         BackendData: {\"VNI\":1,\"VtepMAC\":\"aa:bb:cc:dd:ee:ff\"}, \
         BackendV6Data: {\"VNI\":2}"
    );
}

#[test]
fn lease_attrs_display_nil_optionals() {
    let attrs = LeaseAttrs {
        public_ip: "10.0.0.1".parse().unwrap(),
        public_ipv6: None,
        backend_type: "host-gw".to_string(),
        backend_data: None,
        backend_v6_data: None,
    };
    assert_eq!(
        attrs.to_string(),
        "BackendType: host-gw, PublicIP: 10.0.0.1, PublicIPv6: (nil), \
         BackendData: (nil), BackendV6Data: (nil)"
    );
}
