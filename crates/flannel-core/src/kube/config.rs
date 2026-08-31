//! Kube client configuration: direct API URL (k3as, plain HTTP, no auth),
//! in-cluster service account, and kubeconfig files.
//!
//! [`resolve`] mirrors Go client-go `clientcmd.BuildConfigFromFlags(apiUrl,
//! kubeconfigPath)`: explicit kubeconfig wins (api url overrides its
//! server), then explicit api url, then in-cluster, then `$KUBECONFIG`,
//! then `~/.kube/config`.

use std::env;
use std::fmt;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::client::KubeError;

/// In-cluster service account paths (client-go conventions).
pub const SERVICE_ACCOUNT_TOKEN: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";
pub const SERVICE_ACCOUNT_CA: &str = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";

/// Everything the client needs to reach the apiserver.
#[derive(Clone, PartialEq)]
pub struct KubeConfig {
    /// Base URL of the apiserver, e.g. `http://127.0.0.1:6444` or
    /// `https://10.0.0.1:6443` (no trailing slash).
    pub server: String,
    pub bearer_token: Option<String>,
    pub ca_path: Option<PathBuf>,
    pub insecure_skip_tls_verify: bool,
}

/// `Debug` that never prints the bearer token (configs get logged via
/// `{:?}` in error paths). Presence stays visible, `None` stays `None`.
impl fmt::Debug for KubeConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KubeConfig")
            .field("server", &self.server)
            .field(
                "bearer_token",
                &self.bearer_token.as_ref().map(|_| "<redacted>"),
            )
            .field("ca_path", &self.ca_path)
            .field("insecure_skip_tls_verify", &self.insecure_skip_tls_verify)
            .finish()
    }
}

/// Config for a bare apiserver URL (k3as/init-pro: plain HTTP, no auth).
pub fn from_api_url(url: &str) -> Result<KubeConfig, KubeError> {
    let parsed = url::Url::parse(url)
        .map_err(|e| KubeError::Config(format!("invalid api url {url:?}: {e}")))?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err(KubeError::Config(format!(
            "api url must be http(s): {url:?}"
        )));
    }
    Ok(KubeConfig {
        server: url.trim_end_matches('/').to_string(),
        bearer_token: None,
        ca_path: None,
        insecure_skip_tls_verify: false,
    })
}

/// In-cluster config (client-go semantics): KUBERNETES_SERVICE_HOST/PORT
/// envs plus the pod's service-account token; CA cert if present.
pub fn in_cluster() -> Result<KubeConfig, KubeError> {
    in_cluster_with(
        |key| env::var(key).ok(),
        Path::new(SERVICE_ACCOUNT_TOKEN),
        Path::new(SERVICE_ACCOUNT_CA),
    )
}

/// In-cluster config with injected env reader and file paths (testable).
pub(crate) fn in_cluster_with<F>(
    env: F,
    token_path: &Path,
    ca_path: &Path,
) -> Result<KubeConfig, KubeError>
where
    F: Fn(&str) -> Option<String>,
{
    let host = env("KUBERNETES_SERVICE_HOST").ok_or_else(|| {
        KubeError::Config("KUBERNETES_SERVICE_HOST not set (not in-cluster?)".to_string())
    })?;
    let port = env("KUBERNETES_SERVICE_PORT").ok_or_else(|| {
        KubeError::Config("KUBERNETES_SERVICE_PORT not set (not in-cluster?)".to_string())
    })?;
    let token = std::fs::read_to_string(token_path).map_err(|e| {
        KubeError::Config(format!(
            "unable to read service account token {}: {e}",
            token_path.display()
        ))
    })?;
    Ok(KubeConfig {
        server: format!("https://{}", join_host_port(&host, &port)),
        bearer_token: Some(token.trim().to_string()),
        ca_path: if ca_path.exists() {
            Some(ca_path.to_path_buf())
        } else {
            None
        },
        insecure_skip_tls_verify: false,
    })
}

/// Wrap IPv6 hosts in brackets; IPv4/hostnames pass through.
fn join_host_port(host: &str, port: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

#[derive(Deserialize)]
struct RawKubeconfig {
    #[serde(rename = "current-context", default)]
    current_context: String,
    #[serde(default)]
    contexts: Vec<NamedContext>,
    #[serde(default)]
    clusters: Vec<NamedCluster>,
    #[serde(default)]
    users: Vec<NamedUser>,
}

#[derive(Deserialize)]
struct NamedContext {
    name: String,
    context: ContextBody,
}

#[derive(Deserialize)]
struct ContextBody {
    cluster: String,
    user: String,
}

#[derive(Deserialize)]
struct NamedCluster {
    name: String,
    cluster: ClusterBody,
}

#[derive(Deserialize)]
struct ClusterBody {
    server: String,
    #[serde(rename = "certificate-authority")]
    certificate_authority: Option<String>,
    #[serde(rename = "insecure-skip-tls-verify", default)]
    insecure_skip_tls_verify: bool,
}

#[derive(Deserialize)]
struct NamedUser {
    name: String,
    #[serde(default)]
    user: serde_yaml::Value,
}

/// Config from a kubeconfig file (current-context; token or tokenFile auth).
pub fn from_kubeconfig(path: impl AsRef<Path>) -> Result<KubeConfig, KubeError> {
    let path = path.as_ref();
    let raw = std::fs::read_to_string(path).map_err(|e| {
        KubeError::Config(format!("unable to read kubeconfig {}: {e}", path.display()))
    })?;
    let kc: RawKubeconfig = serde_yaml::from_str(&raw)
        .map_err(|e| KubeError::Config(format!("invalid kubeconfig {}: {e}", path.display())))?;
    if kc.current_context.is_empty() {
        return Err(KubeError::Config(format!(
            "kubeconfig {} has no current-context",
            path.display()
        )));
    }
    let ctx = kc
        .contexts
        .iter()
        .find(|c| c.name == kc.current_context)
        .ok_or_else(|| {
            KubeError::Config(format!(
                "context {:?} not found in kubeconfig",
                kc.current_context
            ))
        })?;
    let cluster = kc
        .clusters
        .iter()
        .find(|c| c.name == ctx.context.cluster)
        .ok_or_else(|| {
            KubeError::Config(format!(
                "cluster {:?} not found in kubeconfig",
                ctx.context.cluster
            ))
        })?;
    let user = kc
        .users
        .iter()
        .find(|u| u.name == ctx.context.user)
        .ok_or_else(|| {
            KubeError::Config(format!(
                "user {:?} not found in kubeconfig",
                ctx.context.user
            ))
        })?;
    let token = user_token(&user.name, &user.user)?;
    Ok(KubeConfig {
        server: cluster.cluster.server.trim_end_matches('/').to_string(),
        bearer_token: Some(token),
        ca_path: cluster
            .cluster
            .certificate_authority
            .as_deref()
            .map(PathBuf::from),
        insecure_skip_tls_verify: cluster.cluster.insecure_skip_tls_verify,
    })
}

/// Extract a bearer token from a kubeconfig user entry. Only `token` and
/// `tokenFile` are supported; other auth (client certs, exec, ...) errors.
fn user_token(user_name: &str, user: &serde_yaml::Value) -> Result<String, KubeError> {
    let mut token: Option<String> = None;
    let mut token_file: Option<String> = None;
    if let Some(mapping) = user.as_mapping() {
        for (key, value) in mapping {
            match key.as_str() {
                Some("token") => token = value.as_str().map(str::to_string),
                Some("tokenFile") => token_file = value.as_str().map(str::to_string),
                Some(other) => {
                    return Err(KubeError::Config(format!(
                        "unsupported kubeconfig auth for user {user_name}: {other}"
                    )))
                }
                None => {
                    return Err(KubeError::Config(format!(
                        "unsupported kubeconfig auth for user {user_name}"
                    )))
                }
            }
        }
    }
    if let Some(t) = token {
        return Ok(t);
    }
    if let Some(p) = token_file {
        return std::fs::read_to_string(&p)
            .map(|t| t.trim().to_string())
            .map_err(|e| {
                KubeError::Config(format!(
                    "unable to read tokenFile {p:?} for user {user_name}: {e}"
                ))
            });
    }
    Err(KubeError::Config(format!(
        "unsupported kubeconfig auth for user {user_name}"
    )))
}

/// Resolve like Go `clientcmd.BuildConfigFromFlags(api_url, kubeconfig)`.
pub fn resolve(api_url: &str, kubeconfig_path: &str) -> Result<KubeConfig, KubeError> {
    if !kubeconfig_path.is_empty() {
        let mut cfg = from_kubeconfig(kubeconfig_path)?;
        if !api_url.is_empty() {
            // An explicit master URL overrides the kubeconfig server.
            cfg.server = from_api_url(api_url)?.server;
        }
        return Ok(cfg);
    }
    if !api_url.is_empty() {
        return from_api_url(api_url);
    }
    if let Ok(cfg) = in_cluster() {
        return Ok(cfg);
    }
    if let Some(path) = env_kubeconfig() {
        return from_kubeconfig(path);
    }
    match default_kubeconfig_path() {
        Some(path) if path.exists() => from_kubeconfig(path),
        _ => Err(KubeError::Config(
            "unable to resolve kube config: not running in-cluster and no kubeconfig \
             found (pass an api url or kubeconfig, or set $KUBECONFIG or \
             ~/.kube/config)"
                .to_string(),
        )),
    }
}

/// First existing path listed in $KUBECONFIG (':'-separated), if any.
fn env_kubeconfig() -> Option<PathBuf> {
    env::var("KUBECONFIG").ok().and_then(|value| {
        value
            .split(':')
            .map(|p| PathBuf::from(p.trim()))
            .find(|p| !p.as_os_str().is_empty() && p.exists())
    })
}

/// `~/.kube/config`, if $HOME is set.
fn default_kubeconfig_path() -> Option<PathBuf> {
    env::var("HOME")
        .ok()
        .map(|home| PathBuf::from(home).join(".kube").join("config"))
}
