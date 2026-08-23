//! Port of pkg/lease/lease.go: lease data types, events and LeaseWatcher.

use crate::ip::{IP4Net, IP6Net, IP4, IP6};
use serde_json::value::RawValue;
use std::fmt;
use std::time::SystemTime;

#[cfg(test)]
mod tests;

/// Lease change event kind (Go: `EventAdded` = 0, `EventRemoved` = 1).
#[repr(i32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EventType {
    Added = 0,
    Removed = 1,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Event {
    pub event_type: EventType,
    pub lease: Lease,
}

/// Extra information attached to a lease (Go: LeaseAttrs).
#[derive(Clone, Debug, Default)]
pub struct LeaseAttrs {
    pub public_ip: IP4,
    pub public_ipv6: Option<IP6>,
    pub backend_type: String,
    pub backend_data: Option<Box<RawValue>>,
    pub backend_v6_data: Option<Box<RawValue>>,
}

// `RawValue` does not implement PartialEq, so compare its raw JSON text.
impl PartialEq for LeaseAttrs {
    fn eq(&self, other: &Self) -> bool {
        self.public_ip == other.public_ip
            && self.public_ipv6 == other.public_ipv6
            && self.backend_type == other.backend_type
            && raw_eq(&self.backend_data, &other.backend_data)
            && raw_eq(&self.backend_v6_data, &other.backend_v6_data)
    }
}

fn raw_eq(a: &Option<Box<RawValue>>, b: &Option<Box<RawValue>>) -> bool {
    match (a, b) {
        (Some(x), Some(y)) => x.get() == y.get(),
        (None, None) => true,
        _ => false,
    }
}

/// A subnet lease held by a node.
#[derive(Clone, Debug, PartialEq)]
pub struct Lease {
    pub enable_ipv4: bool,
    pub enable_ipv6: bool,
    pub subnet: IP4Net,
    pub ipv6_subnet: IP6Net,
    pub attrs: LeaseAttrs,
    pub expiration: SystemTime,
    /// Only used by the etcd manager (not ported).
    pub asof: i64,
}

/// Result of a lease watch batch (Go: LeaseWatchResult). The etcd-only
/// `cursor` field is dropped; no etcd backend is ported.
#[derive(Clone, Debug, Default)]
pub struct LeaseWatchResult {
    /// Either events or snapshot is set. Empty events means the cursor was
    /// out of range and snapshot holds the current list (etcd semantics).
    pub events: Vec<Event>,
    pub snapshot: Vec<Lease>,
}

/// Tracks the local lease plus all other nodes' leases and derives events.
#[derive(Clone, Debug, Default)]
pub struct LeaseWatcher {
    /// Lease with the subnet of the local node (Go: OwnLease *Lease).
    pub own_lease: Option<Lease>,
    /// Leases with subnets from other nodes (Go: Leases []Lease).
    pub leases: Vec<Lease>,
}

impl LeaseWatcher {
    /// Go: `&lease.LeaseWatcher{OwnLease: ownLease}`.
    pub fn new(own_lease: Lease) -> Self {
        Self {
            own_lease: Some(own_lease),
            leases: Vec::new(),
        }
    }

    /// Reset is called by etcd-subnet when using a snapshot (Go: Reset).
    ///
    /// Leases from `leases` that match a stored lease (per `same_subnet`)
    /// keep it silently; new ones emit `Added`. Stored leases not present in
    /// `leases` emit `Removed`. The own lease is skipped. Finally the stored
    /// list is replaced by a copy of the whole `leases` input (Go copies
    /// everything over, the own lease included).
    pub fn reset(&mut self, leases: &[Lease]) -> Vec<Event> {
        // Go dereferences OwnLease; a nil own lease would panic there too.
        let own = self
            .own_lease
            .clone()
            .expect("LeaseWatcher::reset called without own_lease set");
        let mut batch: Vec<Event> = Vec::new();

        for nl in leases {
            let mut found = false;
            if same_subnet(nl.enable_ipv4, nl.enable_ipv6, &own, nl) {
                continue;
            }

            for i in 0..self.leases.len() {
                let matches = {
                    let ol = &self.leases[i];
                    same_subnet(ol.enable_ipv4, ol.enable_ipv6, ol, nl)
                };
                if matches {
                    self.leases.remove(i);
                    found = true;
                    break;
                }
            }

            if !found {
                // new lease
                batch.push(Event {
                    event_type: EventType::Added,
                    lease: nl.clone(),
                });
            }
        }

        for l in &self.leases {
            batch.push(Event {
                event_type: EventType::Removed,
                lease: l.clone(),
            });
        }

        // Copy the leases over (Go: make a fresh slice, never just assign).
        self.leases = leases.to_vec();

        batch
    }

    /// Update reads the leases in the events and depending on type, adds
    /// them or removes them (Go: Update). Events whose lease matches the
    /// own lease subnet (flag set taken from the event lease) are skipped.
    pub fn update(&mut self, events: &[Event]) -> Vec<Event> {
        let own = self
            .own_lease
            .clone()
            .expect("LeaseWatcher::update called without own_lease set");
        let mut batch: Vec<Event> = Vec::new();

        for e in events {
            if same_subnet(e.lease.enable_ipv4, e.lease.enable_ipv6, &own, &e.lease) {
                continue;
            }

            match e.event_type {
                EventType::Added => batch.push(self.add(&e.lease)),
                EventType::Removed => batch.push(self.remove(&e.lease)),
            }
        }

        batch
    }

    /// Add updates `leases`, adding the passed lease (either overwriting or
    /// appending). It makes `leases` a set (Go: add).
    fn add(&mut self, lease: &Lease) -> Event {
        for i in 0..self.leases.len() {
            let matches = {
                let l = &self.leases[i];
                same_subnet(l.enable_ipv4, l.enable_ipv6, l, lease)
            };
            if matches {
                self.leases[i] = lease.clone();
                return Event {
                    event_type: EventType::Added,
                    lease: self.leases[i].clone(),
                };
            }
        }

        self.leases.push(lease.clone());

        Event {
            event_type: EventType::Added,
            lease: self.leases[self.leases.len() - 1].clone(),
        }
    }

    /// Remove updates `leases`, removing the passed lease (Go: remove).
    /// Returns the stored lease when found, otherwise the passed lease.
    fn remove(&mut self, lease: &Lease) -> Event {
        for i in 0..self.leases.len() {
            let matches = {
                let l = &self.leases[i];
                same_subnet(l.enable_ipv4, l.enable_ipv6, l, lease)
            };
            if matches {
                let l = self.leases.remove(i);
                return Event {
                    event_type: EventType::Removed,
                    lease: l,
                };
            }
        }

        tracing::error!(
            "Removed subnet ({}) and ipv6 subnet ({}) were not found",
            lease.subnet,
            lease.ipv6_subnet
        );
        Event {
            event_type: EventType::Removed,
            lease: lease.clone(),
        }
    }
}

/// Checks if the subnets are the same in ipv4-only, ipv6-only and dualStack
/// cases (Go: sameSubnet). Note the flag set is a parameter; callers pass
/// either the new/event lease flags (own-lease comparison) or the stored
/// lease flags (set membership comparison), exactly as upstream does.
pub fn same_subnet(
    ipv4_enabled: bool,
    ipv6_enabled: bool,
    first_lease: &Lease,
    second_lease: &Lease,
) -> bool {
    // ipv4 only case
    if ipv4_enabled && !ipv6_enabled && first_lease.subnet == second_lease.subnet {
        return true;
    }
    // ipv6 only case
    if !ipv4_enabled && ipv6_enabled && first_lease.ipv6_subnet == second_lease.ipv6_subnet {
        return true;
    }
    // dualStack case
    if ipv4_enabled
        && ipv6_enabled
        && first_lease.subnet == second_lease.subnet
        && first_lease.ipv6_subnet == second_lease.ipv6_subnet
    {
        return true;
    }
    // etcd case
    if !ipv4_enabled && !ipv6_enabled && first_lease.subnet == second_lease.subnet {
        return true;
    }

    false
}

impl fmt::Display for LeaseAttrs {
    /// Byte-for-byte port of Go `(*LeaseAttrs).String()`. Go marshals the
    /// RawMessage fields (which compacts them) and prints `(nil)` on marshal
    /// errors; `RawValue` always holds valid JSON, so the raw text is
    /// printed verbatim (serializers emit it compact, matching Go).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "BackendType: {}, PublicIP: {}, ",
            self.backend_type, self.public_ip
        )?;
        match &self.public_ipv6 {
            Some(ip6) => write!(f, "PublicIPv6: {ip6}, ")?,
            None => write!(f, "PublicIPv6: (nil), ")?,
        }
        match &self.backend_data {
            Some(data) => write!(f, "BackendData: {}, ", data.get())?,
            None => write!(f, "BackendData: (nil), ")?,
        }
        match &self.backend_v6_data {
            Some(data) => write!(f, "BackendV6Data: {}", data.get()),
            None => write!(f, "BackendV6Data: (nil)"),
        }
    }
}
