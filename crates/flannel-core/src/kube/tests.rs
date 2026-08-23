//! Integration tests: KubeClient against a mock apiserver built on axum.
//! Covers GET node/pod, LIST with fieldSelector, PATCH content types,
//! chunked WATCH streams, bearer auth forwarding, and 410 Gone handling.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use futures::StreamExt;
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;

use super::{KubeClient, KubeError, PatchType, WatchEventType};

/// Recorded PATCH requests: (content-type, body).
type PatchRecorder = Arc<Mutex<Vec<(String, String)>>>;

fn node_json(name: &str, rv: &str) -> Value {
    json!({
        "metadata": {
            "name": name,
            "uid": format!("uid-{name}"),
            "resourceVersion": rv,
            "annotations": {"flannel.alpha.coreos.com/kube-subnet-manager": "true"}
        },
        "spec": {"podCIDR": "10.244.1.0/24", "podCIDRs": ["10.244.1.0/24"]}
    })
}

async fn get_node(Path(name): Path<String>, headers: HeaderMap) -> Response {
    if name == "secure" {
        let authorized = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            == Some("Bearer test-token");
        if !authorized {
            return (
                StatusCode::UNAUTHORIZED,
                Json(
                    json!({"kind": "Status", "code": 401, "reason": "Unauthorized",
                            "message": "no bearer token"}),
                ),
            )
                .into_response();
        }
    }
    if name == "missing" {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"kind": "Status", "code": 404, "reason": "NotFound",
                        "message": format!("nodes \"{name}\" not found")})),
        )
            .into_response();
    }
    Json(node_json(&name, "10")).into_response()
}

async fn get_pod(Path((ns, name)): Path<(String, String)>) -> Response {
    Json(json!({
        "metadata": {"name": name},
        "spec": {"nodeName": format!("{ns}-host")}
    }))
    .into_response()
}

async fn patch_node(
    State(patches): State<PatchRecorder>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    patches
        .lock()
        .unwrap()
        .push((content_type, String::from_utf8_lossy(&body).into_owned()));
    let mut node = node_json(&name, "20");
    node["metadata"]["annotations"]["patched"] = json!("true");
    Json(node).into_response()
}

async fn list_or_watch(Query(params): Query<HashMap<String, String>>) -> Response {
    if params.get("watch").map(String::as_str) == Some("true") {
        return watch_response(&params);
    }
    let mut items = Vec::new();
    if let Some(selector) = params.get("fieldSelector") {
        // Model the apiserver: only nodes matching the selector come back.
        if let Some(name) = selector.strip_prefix("spec.nodeName=") {
            if name == "node1" {
                items.push(node_json(name, "10"));
            }
        }
    }
    Json(json!({"metadata": {"resourceVersion": "100"}, "items": items})).into_response()
}

/// Watch endpoint:
/// - resourceVersion=1    -> immediate 410 Gone with Status body
/// - resourceVersion=hang -> one event, then the stream stays open
/// - otherwise            -> one ADDED event split across two chunks plus
///                           one MODIFIED event, then close.
fn watch_response(params: &HashMap<String, String>) -> Response {
    let rv = params.get("resourceVersion").map(String::as_str);
    if rv == Some("1") {
        return (
            StatusCode::GONE,
            Json(json!({"kind": "Status", "code": 410, "reason": "Expired",
                        "message": "too old resource version: 1 (123)"})),
        )
            .into_response();
    }
    let first = format!(
        "{}\n",
        json!({"type": "ADDED", "object": node_json("node1", "11")})
    );
    let second = format!(
        "{}\n",
        json!({"type": "MODIFIED", "object": node_json("node1", "12")})
    );
    type Chunk = Result<Vec<u8>, std::io::Error>;
    let chunks: Vec<Chunk> = if rv == Some("hang") {
        vec![Ok(first.into_bytes())]
    } else {
        let mid = first.len() / 2;
        vec![
            Ok(first[..mid].as_bytes().to_vec()),
            Ok(first[mid..].as_bytes().to_vec()),
            Ok(second.into_bytes()),
        ]
    };
    let body: Body = if rv == Some("hang") {
        let stream = futures::stream::iter(chunks).chain(futures::stream::pending());
        Body::from_stream(
            Box::pin(stream) as std::pin::Pin<Box<dyn futures::Stream<Item = Chunk> + Send>>
        )
    } else {
        Body::from_stream(futures::stream::iter(chunks))
    };
    (StatusCode::OK, body).into_response()
}

async fn start_mock() -> (String, PatchRecorder) {
    let patches: PatchRecorder = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .route("/api/v1/nodes", get(list_or_watch))
        .route("/api/v1/nodes/{name}", get(get_node).patch(patch_node))
        .route("/api/v1/namespaces/{ns}/pods/{name}", get(get_pod))
        .with_state(patches.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), patches)
}

fn client_for(url: &str) -> KubeClient {
    let cfg = super::from_api_url(url).unwrap();
    KubeClient::new(cfg).unwrap()
}

#[tokio::test]
async fn get_node_and_not_found() {
    let (url, _) = start_mock().await;
    let client = client_for(&url);
    let node = client.get_node("node1").await.unwrap();
    assert_eq!(node.metadata.name, "node1");
    assert_eq!(node.metadata.uid, "uid-node1");
    assert_eq!(node.spec.pod_cidr.as_deref(), Some("10.244.1.0/24"));
    assert_eq!(node.spec.pod_cidrs, vec!["10.244.1.0/24".to_string()]);
    assert_eq!(
        node.metadata
            .annotations
            .get("flannel.alpha.coreos.com/kube-subnet-manager")
            .map(String::as_str),
        Some("true")
    );

    match client.get_node("missing").await {
        Err(KubeError::NotFound(resource)) => assert!(resource.contains("missing")),
        other => panic!("expected NotFound, got {other:?}"),
    }
}

#[tokio::test]
async fn get_pod_for_node_name_discovery() {
    let (url, _) = start_mock().await;
    let client = client_for(&url);
    let pod = client
        .get_pod("kube-system", "kube-flannel-ds-abc")
        .await
        .unwrap();
    assert_eq!(pod.metadata.name, "kube-flannel-ds-abc");
    assert_eq!(pod.spec.node_name.as_deref(), Some("kube-system-host"));
}

#[tokio::test]
async fn list_nodes_with_field_selector() {
    let (url, _) = start_mock().await;
    let client = client_for(&url);
    let list = client
        .list_nodes(Some("spec.nodeName=node1"))
        .await
        .unwrap();
    assert_eq!(list.items.len(), 1);
    assert_eq!(list.items[0].metadata.name, "node1");
    assert_eq!(list.metadata.resource_version.as_deref(), Some("100"));

    let empty = client
        .list_nodes(Some("spec.nodeName=other"))
        .await
        .unwrap();
    assert!(empty.items.is_empty());

    let all = client.list_nodes(None).await.unwrap();
    assert!(all.items.is_empty());
}

#[tokio::test]
async fn patch_node_content_type_and_body() {
    let (url, patches) = start_mock().await;
    let client = client_for(&url);
    let patch =
        json!({"metadata": {"annotations": {"flannel.alpha.coreos.com/public-ip": "1.2.3.4"}}});
    let node = client
        .patch_node("node1", &patch, PatchType::StrategicMerge)
        .await
        .unwrap();
    assert_eq!(node.metadata.name, "node1");
    assert_eq!(
        node.metadata.annotations.get("patched").map(String::as_str),
        Some("true")
    );

    client
        .patch_node(
            "node1",
            &json!({"metadata": {"labels": {"a": "b"}}}),
            PatchType::Merge,
        )
        .await
        .unwrap();

    let recorded = patches.lock().unwrap().clone();
    assert_eq!(recorded.len(), 2);
    assert_eq!(recorded[0].0, "application/strategic-merge-patch+json");
    assert_eq!(
        serde_json::from_str::<Value>(&recorded[0].1).unwrap(),
        patch
    );
    assert_eq!(recorded[1].0, "application/merge-patch+json");
    assert!(recorded[1].1.contains("\"labels\""));
}

#[tokio::test]
async fn watch_nodes_decodes_chunked_events() {
    let (url, _) = start_mock().await;
    let client = client_for(&url);
    let mut stream = client
        .watch_nodes(
            Some("spec.nodeName=node1"),
            None,
            true,
            CancellationToken::new(),
        )
        .await
        .unwrap();

    let mut events = Vec::new();
    while let Some(item) = stream.next().await {
        events.push(item.unwrap());
    }
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].event_type, WatchEventType::Added);
    assert_eq!(events[0].object.metadata.name, "node1");
    assert_eq!(
        events[0].object.metadata.resource_version.as_deref(),
        Some("11")
    );
    assert_eq!(events[1].event_type, WatchEventType::Modified);
    assert_eq!(
        events[1].object.metadata.resource_version.as_deref(),
        Some("12")
    );
}

#[tokio::test]
async fn watch_nodes_gone_on_410() {
    let (url, _) = start_mock().await;
    let client = client_for(&url);
    let result = client
        .watch_nodes(None, Some("1"), false, CancellationToken::new())
        .await;
    assert!(matches!(result, Err(KubeError::Gone)), "expected Gone");
}

#[tokio::test]
async fn watch_nodes_cancellation_ends_stream() {
    let (url, _) = start_mock().await;
    let client = client_for(&url);
    let cancel = CancellationToken::new();
    let mut stream = client
        .watch_nodes(None, Some("hang"), false, cancel.clone())
        .await
        .unwrap();

    let first = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("first event timed out")
        .expect("stream ended early")
        .expect("event decode error");
    assert_eq!(first.event_type, WatchEventType::Added);

    cancel.cancel();
    let end = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("cancel did not terminate stream");
    assert!(end.is_none());
}

#[tokio::test]
async fn bearer_token_is_forwarded() {
    let (url, _) = start_mock().await;
    let mut cfg = super::from_api_url(&url).unwrap();
    cfg.bearer_token = Some("test-token".to_string());
    let client = KubeClient::new(cfg).unwrap();
    let node = client.get_node("secure").await.unwrap();
    assert_eq!(node.metadata.name, "secure");

    let anonymous = client_for(&url);
    match anonymous.get_node("secure").await {
        Err(KubeError::Api(status)) => assert_eq!(status.code, 401),
        other => panic!("expected Api(401), got {other:?}"),
    }
}
