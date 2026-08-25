//! Scenario registry: one entry per capability. All scenarios boot the
//! real daemon + real CNI; `skips` documents the two capabilities that
//! cannot run locally (external charon / cloud endpoints).

pub mod alloc;
pub mod extension;
pub mod healthz;
pub mod masq;
pub mod skips;
pub mod two_node;

use crate::Scenario;

pub fn all() -> Vec<Scenario> {
    let mut v = vec![alloc::scenario()];
    v.extend(two_node::scenarios());
    v.push(extension::scenario());
    v.extend(masq::scenarios());
    v.extend(healthz::scenarios());
    v.extend(skips::scenarios());
    v
}
