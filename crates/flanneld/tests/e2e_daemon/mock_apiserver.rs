//! Minimal in-memory kube apiserver mock for the flanneld e2e test.
//! Serves what the kube subnet manager touches: node GET/PATCH, node
//! LIST, and a WATCH endpoint that stays open without emitting frames
//! (the initial LIST already carries everything the daemon needs).

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct MockState {
    nodes: BTreeMap<String, Value>,
    rv: u64,
    patches: Vec<(String, String, Value)>,
}

#[derive(Clone)]
pub(crate) struct MockApiserver {
    state: Arc<Mutex<MockState>>,
    url: String,
}

impl MockApiserver {
    pub(crate) async fn start() -> Self {
        let api = Self {
            state: Arc::new(Mutex::new(MockState::default())),
            url: String::new(),
        };
        let app = Router::new()
            .route("/api/v1/nodes", get(list_or_watch_nodes))
            .route("/api/v1/nodes/{name}", get(get_node).patch(patch_node))
            .route(
                // Go PatchStatus: status.conditions writes land here.
                "/api/v1/nodes/{name}/status",
                get(get_node).patch(patch_node),
            )
            .with_state(api.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self {
            state: api.state,
            url: format!("http://{addr}"),
        }
    }

    pub(crate) fn url(&self) -> &str {
        &self.url
    }

    /// Insert/replace a node with podCIDR (controller-manager style).
    pub(crate) fn put_node(&self, name: &str, pod_cidr: &str) {
        let mut st = self.state.lock().unwrap();
        st.rv += 1;
        let node = json!({
            "metadata": {
                "name": name,
                "resourceVersion": st.rv.to_string(),
                "annotations": {},
            },
            "spec": {"podCIDR": pod_cidr, "podCIDRs": [pod_cidr]},
        });
        st.nodes.insert(name.to_string(), node);
    }

    pub(crate) fn node_annotations(&self, name: &str) -> BTreeMap<String, String> {
        let st = self.state.lock().unwrap();
        let mut out = BTreeMap::new();
        if let Some(node) = st.nodes.get(name) {
            if let Some(ann) = node
                .pointer("/metadata/annotations")
                .and_then(Value::as_object)
            {
                for (k, v) in ann {
                    out.insert(k.clone(), v.as_str().unwrap_or("").to_string());
                }
            }
        }
        out
    }

    /// Recorded PATCH requests: (content-type, node name, body).
    pub(crate) fn patches(&self) -> Vec<(String, String, Value)> {
        self.state.lock().unwrap().patches.clone()
    }
}

fn not_found(name: &str) -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({"kind": "Status", "code": 404, "reason": "NotFound",
                    "message": format!("{name} not found")})),
    )
        .into_response()
}

async fn get_node(State(api): State<MockApiserver>, Path(name): Path<String>) -> Response {
    let st = api.state.lock().unwrap();
    match st.nodes.get(&name) {
        Some(node) => Json(node.clone()).into_response(),
        None => not_found(&format!("nodes \"{name}\"")),
    }
}

/// Strategic-merge-ish PATCH: annotations key-merged, status replaced;
/// every patch is recorded for assertions.
async fn patch_node(
    State(api): State<MockApiserver>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let patch: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("bad patch: {e}")).into_response(),
    };

    let mut st = api.state.lock().unwrap();
    let Some(mut node) = st.nodes.get(&name).cloned() else {
        return not_found(&format!("nodes \"{name}\""));
    };
    st.patches.push((content_type, name.clone(), patch.clone()));

    if let Some(ann) = patch
        .pointer("/metadata/annotations")
        .and_then(Value::as_object)
    {
        let target = node
            .pointer_mut("/metadata/annotations")
            .and_then(Value::as_object_mut);
        if let Some(target) = target {
            for (k, v) in ann {
                if v.is_null() {
                    target.remove(k);
                } else {
                    target.insert(k.clone(), v.clone());
                }
            }
        }
    }
    if let Some(status) = patch.get("status") {
        node["status"] = status.clone();
    }

    st.rv += 1;
    node["metadata"]["resourceVersion"] = json!(st.rv.to_string());
    st.nodes.insert(name, node.clone());
    Json(node).into_response()
}

async fn list_or_watch_nodes(
    State(api): State<MockApiserver>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if params.get("watch").map(String::as_str) == Some("true") {
        // Open stream, no frames: the initial LIST already synced the
        // informer and the daemon-under-test triggers no lease events.
        let pending = futures::stream::pending::<Result<Vec<u8>, std::io::Error>>();
        return (StatusCode::OK, Body::from_stream(pending)).into_response();
    }
    let st = api.state.lock().unwrap();
    let items: Vec<&Value> = st.nodes.values().collect();
    Json(json!({
        "metadata": {"resourceVersion": st.rv.to_string()},
        "items": items,
    }))
    .into_response()
}
