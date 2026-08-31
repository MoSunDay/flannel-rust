//! Thin async apiserver client: GET pod, GET/LIST/PATCH/WATCH nodes.
//!
//! Works against a plain-HTTP apiserver (k3as/init-pro, no auth) and real
//! clusters (bearer token, custom CA, insecure-skip-tls-verify).

use futures::{Stream, StreamExt};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::pin::Pin;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use url::Url;

use super::config::KubeConfig;
use super::types::{is_expired, Node, NodeList, Pod, Status, WatchEvent};
use super::watch::decode_watch_stream;

/// Errors surfaced by the kube client.
#[derive(Debug, thiserror::Error)]
pub enum KubeError {
    #[error("http request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("apiserver error: {0}")]
    Api(Status),
    #[error("resource not found: {0}")]
    NotFound(String),
    #[error("resource version too old, relist required (410 Gone)")]
    Gone,
    #[error("kube configuration error: {0}")]
    Config(String),
    #[error("decode error: {0}")]
    Decode(String),
}

/// Patch content types accepted by the apiserver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchType {
    StrategicMerge,
    Merge,
}

impl PatchType {
    pub fn content_type(self) -> &'static str {
        match self {
            PatchType::StrategicMerge => "application/strategic-merge-patch+json",
            PatchType::Merge => "application/merge-patch+json",
        }
    }
}

/// Apiserver client. Cheap to clone (reqwest client is Arc-backed).
#[derive(Clone)]
pub struct KubeClient {
    http: reqwest::Client,
    base_url: String,
}

impl KubeClient {
    pub fn new(config: KubeConfig) -> Result<Self, KubeError> {
        // Bounded dial (30s, like the client-go transport Go flannel uses):
        // without it a black-holed apiserver stalls every non-watch call
        // for minutes. There is deliberately NO global `.timeout()`: the
        // watch streams (`watch_nodes`) are long-polls that must stay
        // unbounded for as long as the apiserver keeps them open.
        let mut builder = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(30))
            .use_rustls_tls();
        if let Some(token) = &config.bearer_token {
            let mut headers = reqwest::header::HeaderMap::new();
            let mut value = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))
                .map_err(|e| KubeError::Config(format!("invalid bearer token: {e}")))?;
            value.set_sensitive(true);
            headers.insert(AUTHORIZATION, value);
            builder = builder.default_headers(headers);
        }
        if config.insecure_skip_tls_verify {
            builder = builder.danger_accept_invalid_certs(true);
        }
        if let Some(ca) = &config.ca_path {
            let pem = std::fs::read(ca).map_err(|e| {
                KubeError::Config(format!("unable to read CA {}: {e}", ca.display()))
            })?;
            let cert = reqwest::Certificate::from_pem(&pem)
                .map_err(|e| KubeError::Config(format!("invalid CA cert {}: {e}", ca.display())))?;
            builder = builder.add_root_certificate(cert);
        }
        let http = builder.build().map_err(KubeError::Http)?;
        Ok(Self {
            http,
            base_url: config.server.trim_end_matches('/').to_string(),
        })
    }

    /// GET a pod (used for NODE_NAME discovery via pod.spec.nodeName).
    pub async fn get_pod(&self, namespace: &str, name: &str) -> Result<Pod, KubeError> {
        let url = self.endpoint(&format!("/api/v1/namespaces/{namespace}/pods/{name}"))?;
        self.request_json(self.http.get(url), &format!("pod {namespace}/{name}"))
            .await
    }

    /// GET a node; 404 maps to [`KubeError::NotFound`].
    pub async fn get_node(&self, name: &str) -> Result<Node, KubeError> {
        let url = self.endpoint(&format!("/api/v1/nodes/{name}"))?;
        self.request_json(self.http.get(url), &format!("node {name}"))
            .await
    }

    /// LIST nodes, optionally filtered (e.g. `spec.nodeName=<node>`).
    pub async fn list_nodes(&self, field_selector: Option<&str>) -> Result<NodeList, KubeError> {
        let mut url = self.endpoint("/api/v1/nodes")?;
        if let Some(selector) = field_selector {
            url.query_pairs_mut().append_pair("fieldSelector", selector);
        }
        self.request_json(self.http.get(url), "node list").await
    }

    /// PATCH a node's annotations/spec with the given patch document.
    pub async fn patch_node(
        &self,
        name: &str,
        patch: &Value,
        patch_type: PatchType,
    ) -> Result<Node, KubeError> {
        self.patch_node_at(name, "", patch, patch_type).await
    }

    /// PATCH the `status` subresource (Go: `Nodes().PatchStatus`): the
    /// only endpoint on which `status.conditions` writes are accepted.
    pub async fn patch_node_status(
        &self,
        name: &str,
        patch: &Value,
        patch_type: PatchType,
    ) -> Result<Node, KubeError> {
        self.patch_node_at(name, "/status", patch, patch_type).await
    }

    async fn patch_node_at(
        &self,
        name: &str,
        subresource: &str,
        patch: &Value,
        patch_type: PatchType,
    ) -> Result<Node, KubeError> {
        let url = self.endpoint(&format!("/api/v1/nodes/{name}{subresource}"))?;
        let body = serde_json::to_vec(patch)
            .map_err(|e| KubeError::Decode(format!("serializing patch: {e}")))?;
        let req = self
            .http
            .patch(url)
            .header(CONTENT_TYPE, patch_type.content_type())
            .body(body);
        self.request_json(req, &format!("node {name}")).await
    }

    /// WATCH nodes as a stream of typed events (boxed: `Unpin`, easy to
    /// store and select on).
    ///
    /// The stream ends when the apiserver closes the connection, on a
    /// decode error, or when `cancel` fires. A 410 response (HTTP level or
    /// ERROR watch frame) surfaces as [`KubeError::Gone`] so the caller can
    /// relist and resume with the fresh resource version.
    pub async fn watch_nodes(
        &self,
        field_selector: Option<&str>,
        resource_version: Option<&str>,
        allow_bookmarks: bool,
        cancel: CancellationToken,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<WatchEvent<Node>, KubeError>> + Send>>, KubeError>
    {
        let mut url = self.endpoint("/api/v1/nodes")?;
        {
            let mut q = url.query_pairs_mut();
            q.append_pair("watch", "true");
            if let Some(selector) = field_selector {
                q.append_pair("fieldSelector", selector);
            }
            if let Some(rv) = resource_version {
                q.append_pair("resourceVersion", rv);
            }
            if allow_bookmarks {
                q.append_pair("allowWatchBookmarks", "true");
            }
        }
        let resp = self.http.get(url).send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(status_error(status.as_u16(), &body));
        }
        let events = decode_watch_stream(resp.bytes_stream()).take_until(cancel.cancelled_owned());
        Ok(Box::pin(events))
    }

    fn endpoint(&self, path: &str) -> Result<Url, KubeError> {
        Url::parse(&format!("{}{}", self.base_url, path))
            .map_err(|e| KubeError::Config(format!("invalid server url {:?}: {e}", self.base_url)))
    }

    async fn request_json<T: DeserializeOwned>(
        &self,
        req: reqwest::RequestBuilder,
        resource: &str,
    ) -> Result<T, KubeError> {
        let resp = req.send().await?;
        let status = resp.status();
        let body = resp.text().await?;
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(KubeError::NotFound(resource.to_string()));
        }
        if !status.is_success() {
            return Err(status_error(status.as_u16(), &body));
        }
        serde_json::from_str(&body)
            .map_err(|e| KubeError::Decode(format!("decoding {resource}: {e}")))
    }
}

/// Map a non-success HTTP body to a typed error. The apiserver replies
/// with a Status JSON; fall back to the raw body when it is not.
fn status_error(code: u16, body: &str) -> KubeError {
    let mut status: Status = serde_json::from_str(body).unwrap_or_else(|_| Status {
        message: body.to_string(),
        reason: "Unknown".to_string(),
        code,
    });
    if status.code == 0 {
        status.code = code;
    }
    if is_expired(&status) {
        KubeError::Gone
    } else {
        KubeError::Api(status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patch_type_content_types() {
        assert_eq!(
            PatchType::StrategicMerge.content_type(),
            "application/strategic-merge-patch+json"
        );
        assert_eq!(
            PatchType::Merge.content_type(),
            "application/merge-patch+json"
        );
    }

    #[test]
    fn status_error_mapping() {
        let body = r#"{"kind":"Status","message":"too old","reason":"Expired","code":410}"#;
        assert!(matches!(status_error(410, body), KubeError::Gone));

        let body = r#"{"kind":"Status","message":"no","reason":"Forbidden","code":403}"#;
        match status_error(403, body) {
            KubeError::Api(s) => assert_eq!(s.reason, "Forbidden"),
            other => panic!("expected Api, got {other:?}"),
        }

        // Non-JSON body: raw text kept, HTTP code injected.
        match status_error(500, "oops") {
            KubeError::Api(s) => {
                assert_eq!(s.code, 500);
                assert_eq!(s.message, "oops");
            }
            other => panic!("expected Api, got {other:?}"),
        }
    }
}
