//! Port of pkg/subnet/kube/annotations.go (upstream cdf76059): flannel's
//! node annotation keys, built from a configurable prefix.

use anyhow::anyhow;
use regex::Regex;

/// The annotation keys flannel sets/reads on nodes (Go: `annotations`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Annotations {
    pub subnet_kube_managed: String,
    pub backend_data: String,
    pub backend_v6_data: String,
    pub backend_type: String,
    pub backend_public_ip: String,
    pub backend_public_ipv6: String,
    pub backend_node_public_ip: String,
    pub backend_node_public_ipv6: String,
    pub backend_public_ip_overwrite: String,
    pub backend_public_ipv6_overwrite: String,
}

/// Go: `newAnnotations(prefix)`. Normalizes the prefix (appends "/" or
/// "-"), validates it against the Kubernetes annotation name rules and
/// derives every key from it. Error strings are identical to Go.
pub fn new_annotations(prefix: &str) -> anyhow::Result<Annotations> {
    let slash_cnt = prefix.matches('/').count();
    if slash_cnt > 1 {
        return Err(anyhow!(
            "subnet/kube: prefix can contain at most single slash"
        ));
    }
    let mut prefix = prefix.to_string();
    if slash_cnt == 0 {
        prefix.push('/');
    }
    if !prefix.ends_with('/') && !prefix.ends_with('-') {
        prefix.push('-');
    }

    // Matches the format used by Kubernetes for annotations:
    //   - must start with FQDN, contain at most one slash
    //   - only lowercase letters, numbers, underscores, hyphens, dots
    //     and slash.
    // Go uses unanchored `regexp.MatchString` with a trailing `$`; the
    // regex crate's `is_match` has identical search semantics.
    let re = Regex::new(r"(?:[a-z0-9_-]+\.)+[a-z0-9_-]+/(?:[a-z0-9_-]+-)?$")
        .expect("static annotation prefix regexp is valid");
    if !re.is_match(&prefix) {
        return Err(anyhow!(
            "subnet/kube: prefix must be in a format: fqdn/[0-9a-z-_]*"
        ));
    }

    Ok(Annotations {
        subnet_kube_managed: format!("{prefix}kube-subnet-manager"),
        backend_data: format!("{prefix}backend-data"),
        backend_v6_data: format!("{prefix}backend-v6-data"),
        backend_type: format!("{prefix}backend-type"),
        backend_public_ip: format!("{prefix}public-ip"),
        backend_node_public_ip: format!("{prefix}node-public-ip"),
        backend_public_ip_overwrite: format!("{prefix}public-ip-overwrite"),
        backend_public_ipv6: format!("{prefix}public-ipv6"),
        backend_node_public_ipv6: format!("{prefix}node-public-ipv6"),
        backend_public_ipv6_overwrite: format!("{prefix}public-ipv6-overwrite"),
    })
}

/// Read an annotation, treating a missing key as "" (Go map indexing).
pub(crate) fn annotation<'a>(
    map: &'a std::collections::BTreeMap<String, String>,
    key: &str,
) -> &'a str {
    map.get(key).map(String::as_str).unwrap_or("")
}

#[cfg(test)]
mod tests {
    //! Port of pkg/subnet/kube/annotations_test.go (upstream cdf76059).

    use super::new_annotations;

    #[test]
    fn new_annotations_prefix_rules() {
        let test_cases: &[(&str, &str, bool)] = &[
            (
                "flannel.alpha.coreos.com",
                "flannel.alpha.coreos.com/backend-type",
                false,
            ),
            (
                "flannel.alpha.coreos.com/",
                "flannel.alpha.coreos.com/backend-type",
                false,
            ),
            (
                "flannel.alpha.coreos.com/prefix",
                "flannel.alpha.coreos.com/prefix-backend-type",
                false,
            ),
            (
                "flannel.alpha.coreos.com/prefix-",
                "flannel.alpha.coreos.com/prefix-backend-type",
                false,
            ),
            ("org.com", "org.com/backend-type", false),
            ("org9.com", "org9.com/backend-type", false),
            ("org.com/9", "org.com/9-backend-type", false),
            // Not a fqdn.
            ("org", "", true),
            // Not a fqdn before /.
            ("org/", "", true),
            // Not a fqdn before /.
            ("org/prefix", "", true),
            // Uppercase letters.
            ("org.COM", "", true),
            // Uppercase letters.
            ("org.com/PREFIX", "", true),
        ];

        for (i, (prefix, expected_backend_type, has_error)) in test_cases.iter().enumerate() {
            match new_annotations(prefix) {
                Ok(as_) => {
                    assert!(!has_error, "#{i}: error = nil, want non-nil");
                    assert_eq!(
                        as_.backend_type, *expected_backend_type,
                        "#{i}: BackendType = {}, want {}",
                        as_.backend_type, expected_backend_type
                    );
                }
                Err(e) => {
                    assert!(has_error, "#{i}: error = {e}, want nil");
                }
            }
        }
    }

    /// Every key of the default prefix, to pin down the exact strings the
    /// apiserver sees (used by the integration tests' assertions).
    #[test]
    fn default_prefix_all_keys() {
        let a = new_annotations("flannel.alpha.coreos.com").unwrap();
        assert_eq!(
            a.subnet_kube_managed,
            "flannel.alpha.coreos.com/kube-subnet-manager"
        );
        assert_eq!(a.backend_data, "flannel.alpha.coreos.com/backend-data");
        assert_eq!(
            a.backend_v6_data,
            "flannel.alpha.coreos.com/backend-v6-data"
        );
        assert_eq!(a.backend_type, "flannel.alpha.coreos.com/backend-type");
        assert_eq!(a.backend_public_ip, "flannel.alpha.coreos.com/public-ip");
        assert_eq!(
            a.backend_node_public_ip,
            "flannel.alpha.coreos.com/node-public-ip"
        );
        assert_eq!(
            a.backend_public_ip_overwrite,
            "flannel.alpha.coreos.com/public-ip-overwrite"
        );
        assert_eq!(
            a.backend_public_ipv6,
            "flannel.alpha.coreos.com/public-ipv6"
        );
        assert_eq!(
            a.backend_node_public_ipv6,
            "flannel.alpha.coreos.com/node-public-ipv6"
        );
        assert_eq!(
            a.backend_public_ipv6_overwrite,
            "flannel.alpha.coreos.com/public-ipv6-overwrite"
        );
    }
}
