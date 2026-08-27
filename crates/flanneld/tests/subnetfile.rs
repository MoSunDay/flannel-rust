//! Tests for the subnet.env readers (`subnetfile` module): round-trip
//! against flannel-core's `write_subnet_file` (what the daemon writes),
//! multi-value entries, malformed lines, and missing-file behavior.

use flannel_core::ip::{IP4Net, IP6Net};
use flannel_core::subnet::config::Config;
use flannel_core::subnet::writefile::write_subnet_file;
use flanneld::subnetfile::*;
use std::str::FromStr;

fn write(path: &str, content: &str) {
    std::fs::write(path, content).unwrap();
}

/// Round trip: what `write_subnet_file` writes is exactly what the
/// daemon's prev-CIDR readers parse on the next start.
#[test]
fn round_trip_with_write_subnet_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("subnet.env");
    let path_str = path.display().to_string();

    let config = Config {
        enable_ipv4: true,
        enable_ipv6: true,
        network: IP4Net::from_str("10.244.0.0/16").unwrap(),
        ipv6_network: IP6Net::from_str("fc00::/48").unwrap(),
        ..Default::default()
    };
    let sn = IP4Net::from_str("10.244.1.0/24").unwrap();
    // Lease nets carry the first usable IP (host bits set); construct
    // directly since `IP6Net::from_str` masks like net.ParseCIDR.
    let v6sn = IP6Net {
        ip: "fc00::1:0".parse().unwrap(),
        prefix_len: 64,
    };
    write_subnet_file(&path_str, &config, true, sn, v6sn, 1450).unwrap();

    // write_subnet_file increments the lease IP by one (first usable);
    // the readers mask host bits like Go net.ParseCIDR, so the lease
    // address reads back as the NETWORK (Go main.go prev-subnet
    // comparisons and masq recycle are network-to-network).
    assert_eq!(
        read_cidr_from_subnet_file(&path_str, "FLANNEL_NETWORK").to_string(),
        "10.244.0.0/16"
    );
    assert_eq!(
        read_cidr_from_subnet_file(&path_str, "FLANNEL_SUBNET").to_string(),
        "10.244.1.0/24"
    );
    assert_eq!(
        read_ip6_cidr_from_subnet_file(&path_str, "FLANNEL_IPV6_NETWORK").to_string(),
        "fc00::/48"
    );
    assert_eq!(
        read_ip6_cidr_from_subnet_file(&path_str, "FLANNEL_IPV6_SUBNET").to_string(),
        "fc00::/64"
    );
}

/// Go `net.ParseCIDR`: host bits are masked, not rejected (`10.244.1.1/24`
/// parses to `10.244.1.0/24`), for both families.
#[test]
fn cidr_parses_mask_host_bits() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("subnet.env");
    let path_str = path.display().to_string();
    write(
        &path_str,
        "FLANNEL_SUBNET=10.244.1.1/24
",
    );

    assert_eq!(
        read_cidr_from_subnet_file(&path_str, "FLANNEL_SUBNET").to_string(),
        "10.244.1.0/24"
    );

    let path6 = dir.path().join("subnet6.env");
    let path6_str = path6.display().to_string();
    write(
        &path6_str,
        "FLANNEL_IPV6_SUBNET=fc00::1:1/64
",
    );
    assert_eq!(
        read_ip6_cidr_from_subnet_file(&path6_str, "FLANNEL_IPV6_SUBNET").to_string(),
        "fc00::/64"
    );
}

#[test]
fn reads_values_and_ignores_comments_and_blanks() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("subnet.env");
    let path_str = path.display().to_string();
    write(
        &path_str,
        "# a comment\n\nFLANNEL_NETWORK=10.244.0.0/16\nFLANNEL_MTU=1450\n",
    );
    assert_eq!(
        read_cidr_from_subnet_file(&path_str, "FLANNEL_NETWORK").to_string(),
        "10.244.0.0/16"
    );
    // Non-CIDR keys are present but not CIDRs: parsing fails -> default.
    assert_eq!(
        read_cidr_from_subnet_file(&path_str, "FLANNEL_MTU"),
        IP4Net::default()
    );
}

#[test]
fn multi_value_entries_comma_split() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("subnet.env");
    let path_str = path.display().to_string();
    write(&path_str, "FLANNEL_SUBNET=10.244.1.1/24,10.244.2.1/24\n");

    let cidrs = read_cidrs_from_subnet_file(&path_str, "FLANNEL_SUBNET");
    assert_eq!(cidrs.len(), 2);
    assert_eq!(cidrs[0].to_string(), "10.244.1.0/24");
    assert_eq!(cidrs[1].to_string(), "10.244.2.0/24");

    // Go's single-value reader returns the zero net when >1 entry.
    assert_eq!(
        read_cidr_from_subnet_file(&path_str, "FLANNEL_SUBNET"),
        IP4Net::default()
    );

    let v6 = read_ip6_cidrs_from_subnet_file(&path_str, "FLANNEL_SUBNET");
    assert!(v6.is_empty(), "v4 values do not parse as v6");
}

#[test]
fn malformed_lines_are_skipped() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("subnet.env");
    let path_str = path.display().to_string();
    write(
        &path_str,
        "not a pair\n=no_key\nFLANNEL_NETWORK=10.244.0.0/16\n",
    );
    assert_eq!(
        read_cidr_from_subnet_file(&path_str, "FLANNEL_NETWORK").to_string(),
        "10.244.0.0/16"
    );
}

#[test]
fn missing_key_and_missing_file_yield_defaults() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("subnet.env");
    let path_str = path.display().to_string();
    write(&path_str, "FLANNEL_MTU=1450\n");

    // Key absent: Go logs and returns the zero net / empty slice.
    assert_eq!(
        read_cidr_from_subnet_file(&path_str, "FLANNEL_NETWORK"),
        IP4Net::default()
    );
    assert!(read_cidrs_from_subnet_file(&path_str, "FLANNEL_NETWORK").is_empty());
    assert_eq!(
        read_ip6_cidr_from_subnet_file(&path_str, "FLANNEL_IPV6_NETWORK"),
        IP6Net::default()
    );
    assert!(read_ip6_cidrs_from_subnet_file(&path_str, "FLANNEL_IPV6_NETWORK").is_empty());

    // File absent: same defaults (Go os.IsNotExist skip).
    let missing = dir.path().join("nope").display().to_string();
    assert_eq!(
        read_cidr_from_subnet_file(&missing, "FLANNEL_NETWORK"),
        IP4Net::default()
    );
    assert!(read_cidrs_from_subnet_file(&missing, "FLANNEL_NETWORK").is_empty());
}
