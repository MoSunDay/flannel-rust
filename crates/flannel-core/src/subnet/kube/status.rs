//! Port of Go `CompleteLease` + `containsCIDR` (pkg/subnet/kube/kube.go,
//! upstream cdf76059).
//!
//! Deviations from Go (documented):
//! - Go's `clusterCIDRController` branch (ClusterCIDR resources) is not
//!   ported: the Rust port has no ClusterCIDR informer, so the branch is
//!   always nil and skipped.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::json;

use crate::kube::PatchType;
use crate::subnet::manager::Ctx;

use super::KubeSubnetManager;

/// Go: `CompleteLease` — clears NodeNetworkUnavailable once flannel runs.
pub(crate) async fn complete_lease(
    mgr: &KubeSubnetManager,
    _ctx: Ctx<'_>,
    _lease: &crate::lease::Lease,
) -> anyhow::Result<()> {
    // Go: clusterCIDRController startup/sync wait — not ported (always
    // nil in this port).
    if !mgr.set_node_network_unavailable {
        return Ok(());
    }

    let now = rfc3339_utc(SystemTime::now());
    let conditions = json!([{
        "type": "NetworkUnavailable",
        "status": "False",
        "reason": "FlannelIsUp",
        "message": "Flannel is running on this node",
        "lastTransitionTime": now,
        "lastHeartbeatTime": now,
    }]);
    let patch = json!({ "status": { "conditions": conditions } });
    // Go: `PatchStatus` — status.conditions are only accepted on the
    // /status subresource; the main endpoint ignores them (node would
    // stay NotReady).
    mgr.client
        .patch_node_status(&mgr.node_name, &patch, PatchType::StrategicMerge)
        .await?;
    Ok(())
}

/// RFC3339 UTC timestamp with second precision (`metav1.Now()` serializes
/// to RFC3339). Hand-rolled to avoid a chrono dependency: Howard
/// Hinnant's `civil_from_days` algorithm.
fn rfc3339_utc(t: SystemTime) -> String {
    let secs = t
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs();
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let (hour, min, sec) = (rem / 3600, (rem / 60) % 60, rem % 60);

    // civil_from_days (public domain): days since 1970-01-01 -> y/m/d.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // day of era [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day of year
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };

    format!("{year:04}-{m:02}-{d:02}T{hour:02}:{min:02}:{sec:02}Z")
}

#[cfg(test)]
mod tests {
    //! Includes a port of TestContainsCIDR (pkg/subnet/kube/kube_test.go).

    use super::*;
    use crate::ip::{IP4Net, IP6Net};
    use std::str::FromStr;

    #[test]
    fn rfc3339_known_epochs() {
        assert_eq!(rfc3339_utc(UNIX_EPOCH), "1970-01-01T00:00:00Z");
        let t = UNIX_EPOCH + Duration::from_secs(1_724_400_000); // 2024-08-23
        assert_eq!(rfc3339_utc(t), "2024-08-23T08:00:00Z");
        let t = UNIX_EPOCH + Duration::from_secs(951_782_400); // leap day
        assert_eq!(rfc3339_utc(t), "2000-02-29T00:00:00Z");
    }

    /// Port of Go TestContainsCIDR: containsCIDR is implemented as
    /// `IP4Net::contains_cidr` / `IP6Net::contains_cidr`.
    #[test]
    fn contains_cidr_table() {
        let v4_cases: &[(&str, &str, bool)] = &[
            ("10.244.0.0/16", "10.244.0.0/16", true),
            ("10.244.0.0/16", "10.244.0.0/24", true),
            ("10.244.0.0/16", "10.244.255.0/24", true),
            ("10.244.0.0/16", "10.244.0.0/15", false),
            ("10.244.0.0/16", "192.168.0.0/24", false),
        ];
        for (i, (a, b, expected)) in v4_cases.iter().enumerate() {
            let n1 = IP4Net::from_str(a).unwrap();
            let n2 = IP4Net::from_str(b).unwrap();
            assert_eq!(n1.contains_cidr(n2), *expected, "v4 case #{i}");
        }

        let v6_cases: &[(&str, &str, bool)] = &[
            ("2001:0db8:1234::/48", "2001:0db8:1234::/48", true),
            ("2001:0db8:1234::/48", "2001:0db8:1234::/64", true),
            ("2001:0db8:1234::/48", "2001:0db8:1234:ffff::/64", true),
            ("2001:0db8:1234::/48", "2001:0db8:1234::/47", false),
            ("2001:0db8:1234::/48", "fe02::/32", false),
        ];
        for (i, (a, b, expected)) in v6_cases.iter().enumerate() {
            let n1 = IP6Net::from_str(a).unwrap();
            let n2 = IP6Net::from_str(b).unwrap();
            assert_eq!(n1.contains_cidr(n2), *expected, "v6 case #{i}");
        }
    }
}
