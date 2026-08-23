//! Port of flannel pkg/ip (IP4/IP6 arithmetic and nets).

pub mod iface;
pub mod ip6net;
pub mod ipnet;

pub use iface::{NetIface, Netlink};
pub use ip6net::{IP6Net, IP6};
pub use ipnet::{IP4Net, IP4};
