//! Unit tests for kube config resolution (api-url, in-cluster, kubeconfig
//! YAML). Env-mutating scenarios are confined to a single test fn so they
//! cannot race with each other.

use std::env;
use std::io::Write;
use std::path::PathBuf;

use super::client::KubeError;
use super::config::*;

fn tmp_file(content: &str) -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(content.as_bytes()).unwrap();
    f.flush().unwrap();
    f
}

const KUBECONFIG_YAML: &str = r#"
apiVersion: v1
kind: Config
current-context: dev
clusters:
- name: dev-cluster
  cluster:
    server: https://1.2.3.4:6443/
    certificate-authority: /tmp/dev-ca.crt
- name: insecure-cluster
  cluster:
    server: https://5.6.7.8:6443
    insecure-skip-tls-verify: true
contexts:
- name: dev
  context:
    cluster: dev-cluster
    user: dev-user
- name: insecure
  context:
    cluster: insecure-cluster
    user: insecure-user
users:
- name: dev-user
  user:
    token: test-token
- name: insecure-user
  user: {}
"#;

#[test]
fn from_api_url_ok() {
    let cfg = from_api_url("http://127.0.0.1:6444/").unwrap();
    assert_eq!(cfg.server, "http://127.0.0.1:6444");
    assert!(cfg.bearer_token.is_none());
    assert!(cfg.ca_path.is_none());
    assert!(!cfg.insecure_skip_tls_verify);
}

#[test]
fn from_api_url_rejects_bad_scheme_and_url() {
    assert!(matches!(
        from_api_url("ftp://example.com"),
        Err(KubeError::Config(m)) if m.contains("http(s)")
    ));
    assert!(matches!(
        from_api_url("not a url"),
        Err(KubeError::Config(_))
    ));
}

#[test]
fn in_cluster_with_envs_and_files() {
    let dir = tempfile::tempdir().unwrap();
    let token = dir.path().join("token");
    let ca = dir.path().join("ca.crt");
    std::fs::write(&token, "test-token\n").unwrap();
    std::fs::write(&ca, "dummy-ca").unwrap();
    let env = |key: &str| -> Option<String> {
        match key {
            "KUBERNETES_SERVICE_HOST" => Some("10.96.0.1".into()),
            "KUBERNETES_SERVICE_PORT" => Some("443".into()),
            _ => None,
        }
    };
    let cfg = in_cluster_with(env, &token, &ca).unwrap();
    assert_eq!(cfg.server, "https://10.96.0.1:443");
    assert_eq!(cfg.bearer_token.as_deref(), Some("test-token"));
    assert_eq!(cfg.ca_path.as_deref(), Some(ca.as_path()));
}

#[test]
fn in_cluster_wraps_ipv6_host_in_brackets() {
    let dir = tempfile::tempdir().unwrap();
    let token = dir.path().join("token");
    std::fs::write(&token, "test-token").unwrap();
    let env = |key: &str| -> Option<String> {
        match key {
            "KUBERNETES_SERVICE_HOST" => Some("fd00::1".into()),
            "KUBERNETES_SERVICE_PORT" => Some("6443".into()),
            _ => None,
        }
    };
    let cfg = in_cluster_with(env, &token, &dir.path().join("missing-ca")).unwrap();
    assert_eq!(cfg.server, "https://[fd00::1]:6443");
    assert!(cfg.ca_path.is_none());
}

#[test]
fn in_cluster_missing_env_or_token_errors() {
    let dir = tempfile::tempdir().unwrap();
    let token = dir.path().join("token");
    let no_env = |_key: &str| -> Option<String> { None };
    let err = in_cluster_with(no_env, &token, &token).unwrap_err();
    assert!(matches!(err, KubeError::Config(m) if m.contains("KUBERNETES_SERVICE_HOST")));

    let env = |key: &str| -> Option<String> {
        match key {
            "KUBERNETES_SERVICE_HOST" => Some("1.2.3.4".into()),
            "KUBERNETES_SERVICE_PORT" => Some("443".into()),
            _ => None,
        }
    };
    let err = in_cluster_with(env, &token, &token).unwrap_err();
    assert!(matches!(err, KubeError::Config(m) if m.contains("service account token")));
}

#[test]
fn kubeconfig_parse_token_and_ca() {
    let f = tmp_file(KUBECONFIG_YAML);
    let cfg = from_kubeconfig(f.path()).unwrap();
    assert_eq!(cfg.server, "https://1.2.3.4:6443");
    assert_eq!(cfg.bearer_token.as_deref(), Some("test-token"));
    assert_eq!(cfg.ca_path, Some(PathBuf::from("/tmp/dev-ca.crt")));
    assert!(!cfg.insecure_skip_tls_verify);
}

#[test]
fn kubeconfig_insecure_skip_tls_verify_and_token_file() {
    let token_file = tmp_file("file-token\n");
    let yaml = format!(
        r#"
current-context: ctx
clusters:
- name: c
  cluster:
    server: https://9.9.9.9:6443
    insecure-skip-tls-verify: true
contexts:
- name: ctx
  context: {{cluster: c, user: u}}
users:
- name: u
  user:
    tokenFile: {}
"#,
        token_file.path().display()
    );
    let f = tmp_file(&yaml);
    let cfg = from_kubeconfig(f.path()).unwrap();
    assert_eq!(cfg.server, "https://9.9.9.9:6443");
    assert_eq!(cfg.bearer_token.as_deref(), Some("file-token"));
    assert!(cfg.insecure_skip_tls_verify);
    assert!(cfg.ca_path.is_none());
}

#[test]
fn kubeconfig_unsupported_auth_errors_politely() {
    let yaml = r#"
current-context: ctx
clusters:
- name: c
  cluster: {server: "https://1.1.1.1:6443"}
contexts:
- name: ctx
  context: {cluster: c, user: cert-user}
users:
- name: cert-user
  user:
    client-certificate: /tmp/client.crt
    client-key: /tmp/client.key
"#;
    let f = tmp_file(yaml);
    let err = from_kubeconfig(f.path()).unwrap_err();
    assert!(
        matches!(&err, KubeError::Config(m) if m.contains("unsupported kubeconfig auth for user cert-user")),
        "unexpected error: {err}"
    );
}

#[test]
fn kubeconfig_missing_context_errors() {
    let f = tmp_file("current-context: nope\ncontexts: []\n");
    assert!(matches!(
        from_kubeconfig(f.path()),
        Err(KubeError::Config(m)) if m.contains("nope")
    ));
}

#[test]
fn resolve_explicit_args_and_env_fallbacks() {
    // Env-dependent: save and restore process env around the test.
    let saved = [
        "KUBERNETES_SERVICE_HOST",
        "KUBERNETES_SERVICE_PORT",
        "KUBECONFIG",
        "HOME",
    ]
    .map(|k| (k, env::var_os(k)));
    env::remove_var("KUBERNETES_SERVICE_HOST");
    env::remove_var("KUBERNETES_SERVICE_PORT");

    let kubeconfig = tmp_file(KUBECONFIG_YAML);
    let home = tempfile::tempdir().unwrap();
    env::set_var("HOME", home.path());
    env::remove_var("KUBECONFIG");

    // Explicit api url.
    let cfg = resolve("http://127.0.0.1:6444", "").unwrap();
    assert_eq!(cfg.server, "http://127.0.0.1:6444");
    assert!(cfg.bearer_token.is_none());

    // Explicit kubeconfig.
    let cfg = resolve("", kubeconfig.path().to_str().unwrap()).unwrap();
    assert_eq!(cfg.server, "https://1.2.3.4:6443");
    assert_eq!(cfg.bearer_token.as_deref(), Some("test-token"));

    // Both: api url overrides kubeconfig server, auth is kept.
    let cfg = resolve("http://127.0.0.1:9999", kubeconfig.path().to_str().unwrap()).unwrap();
    assert_eq!(cfg.server, "http://127.0.0.1:9999");
    assert_eq!(cfg.bearer_token.as_deref(), Some("test-token"));

    // Neither, nothing usable on disk: clear error.
    let err = resolve("", "").unwrap_err();
    assert!(
        matches!(&err, KubeError::Config(m) if m.contains("kubeconfig")),
        "unexpected error: {err}"
    );

    // Neither, but $KUBECONFIG points at a valid file.
    env::set_var("KUBECONFIG", kubeconfig.path());
    let cfg = resolve("", "").unwrap();
    assert_eq!(cfg.server, "https://1.2.3.4:6443");
    env::remove_var("KUBECONFIG");

    // Neither, but ~/.kube/config exists.
    let dot_kube = home.path().join(".kube");
    std::fs::create_dir_all(&dot_kube).unwrap();
    std::fs::copy(kubeconfig.path(), dot_kube.join("config")).unwrap();
    let cfg = resolve("", "").unwrap();
    assert_eq!(cfg.server, "https://1.2.3.4:6443");

    // Restore env.
    for (key, prev) in saved {
        match prev {
            Some(v) => env::set_var(key, v),
            None => env::remove_var(key),
        }
    }
}
