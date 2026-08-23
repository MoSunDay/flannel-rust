//! Port of flannel pkg/ip (IP4/IP6 arithmetic and nets).

pub mod ip6net;
pub mod ipnet;

pub use ip6net::{IP6Net, IP6};
pub use ipnet::{IP4Net, IP4};
