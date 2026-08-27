//! Mock kube apiserver with a *working* watch stream: LIST, GET, PATCH
//! (annotations merge + status replace) and live ADDED/MODIFIED/DELETED
//! frames with resourceVersion replay — enough for two real flanneld
//! instances to discover each other's lease annotations.

use anyhow::{Context, Result};
use axum::body::{Body, Bytes};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex};

const HISTORY_LIMIT: usize = 512;

#[derive(Clone)]
struct Ev {
    rv: u64,
    kind: &'static str,
    node: Value,
}

#[derive(Default)]
struct MockState {
    nodes: BTreeMap<String, Value>,
    rv: u64,
    history: Vec<Ev>,
    patches: Vec<(String, String, Value)>, // (content-type, node name, body)
    tx: Option<broadcast::Sender<Ev>>,
}

pub struct MockApiserver {
    state: Arc<Mutex<MockState>>,
    port: u16,
    server: tokio::task::JoinHandle<()>,
}

impl MockApiserver {
    /// Bind on 0.0.0.0 so netns-side daemons reach it via the bridge /
    /// veth host IP; 127.0.0.1 also works for host-side callers.
    pub async fn start() -> Result<Arc<Self>> {
        let state = Arc::new(Mutex::new(MockState::default()));
        {
            let mut g = state.lock().await;
            let (tx, _) = broadcast::channel(HISTORY_LIMIT);
            g.tx = Some(tx);
        }
        let listener = tokio::net::TcpListener::bind("0.0.0.0:0")
            .await
            .context("binding mock apiserver")?;
        let port = listener.local_addr().context("apiserver addr")?.port();
        let app = Router::new()
            .route("/api/v1/nodes", get(list_or_watch_nodes))
            .route(
                "/api/v1/nodes/{name}",
                get(get_node).patch(patch_node).delete(delete_node),
            )
            .route(
                // Go PatchStatus: status.conditions writes land here.
                "/api/v1/nodes/{name}/status",
                get(get_node).patch(patch_node_status),
            )
            .with_state(state.clone());
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Ok(Arc::new(Self {
            state,
            port,
            server,
        }))
    }

    /// Base URL as reachable from inside a scratch netns (host-side IP).
    pub fn url_on(&self, ip: &str) -> String {
        format!("http://{ip}:{port}", port = self.port)
    }

    /// Insert (or replace) a node with a controller-manager-style podCIDR.
    pub async fn put_node(&self, name: &str, pod_cidr: &str) {
        let mut g = self.state.lock().await;
        let exists = g.nodes.contains_key(name);
        g.rv += 1;
        let node = json!({
            "metadata": {
                "name": name,
                "resourceVersion": g.rv.to_string(),
                "annotations": {}
            },
            "spec": { "podCIDR": pod_cidr, "podCIDRs": [pod_cidr] },
            "status": { "conditions": [] }
        });
        g.nodes.insert(name.to_string(), node.clone());
        let kind: &'static str = if exists { "MODIFIED" } else { "ADDED" };
        push(&mut g, kind, node);
    }

    /// Current annotations of a node (empty map if absent).
    pub async fn annotations(&self, name: &str) -> Value {
        let g = self.state.lock().await;
        g.nodes
            .get(name)
            .and_then(|n| n["metadata"]["annotations"].as_object())
            .cloned()
            .map(Value::Object)
            .unwrap_or_else(|| json!({}))
    }

    /// In-process strategic-merge-ish annotation patch (same semantics
    /// as the HTTP PATCH handler: keys merge, null deletes) -- lets the
    /// harness simulate a peer node acquiring/updating its lease.
    pub async fn patch_node_annotations(
        &self,
        name: &str,
        annotations: &BTreeMap<String, Value>,
    ) -> Result<()> {
        let mut g = self.state.lock().await;
        let Some(mut node) = g.nodes.get(name).cloned() else {
            anyhow::bail!("patch_node_annotations: no node {name}");
        };
        {
            let target = node["metadata"]["annotations"]
                .as_object_mut()
                .expect("annotations object");
            for (k, v) in annotations {
                if v.is_null() {
                    target.remove(k);
                } else {
                    target.insert(k.clone(), v.clone());
                }
            }
        }
        g.rv += 1;
        node["metadata"]["resourceVersion"] = json!(g.rv.to_string());
        g.nodes.insert(name.to_string(), node.clone());
        push(&mut g, "MODIFIED", node);
        Ok(())
    }

    /// Delete a node (simulates node removal -> DELETED watch frame).
    pub async fn delete_node(&self, name: &str) -> Result<()> {
        let mut g = self.state.lock().await;
        let Some(node) = g.nodes.remove(name) else {
            anyhow::bail!("delete_node: no node {name}");
        };
        g.rv += 1;
        push(&mut g, "DELETED", node);
        Ok(())
    }

    /// Recorded PATCH calls: (content-type, node name, body).
    pub async fn patches(&self) -> Vec<(String, String, Value)> {
        self.state.lock().await.patches.clone()
    }
}

impl Drop for MockApiserver {
    fn drop(&mut self) {
        self.server.abort();
    }
}

fn push(g: &mut MockState, kind: &'static str, node: Value) {
    let ev = Ev {
        rv: g.rv,
        kind,
        node,
    };
    g.history.push(ev.clone());
    if g.history.len() > HISTORY_LIMIT {
        g.history.drain(..g.history.len() - HISTORY_LIMIT);
    }
    if let Some(tx) = &g.tx {
        let _ = tx.send(ev);
    }
}

#[derive(Deserialize)]
struct NodeQuery {
    #[serde(rename = "watch", default)]
    watch: Option<bool>,
    #[serde(rename = "resourceVersion", default)]
    resource_version: Option<String>,
}

async fn list_or_watch_nodes(
    Query(q): Query<NodeQuery>,
    State(st): State<Arc<Mutex<MockState>>>,
) -> Response {
    if q.watch.unwrap_or(false) {
        let (replay, mut rx) = {
            let g = st.lock().await;
            let since: u64 = q.resource_version.and_then(|s| s.parse().ok()).unwrap_or(0);
            let replay = g
                .history
                .iter()
                .filter(|e| e.rv > since)
                .cloned()
                .collect::<Vec<_>>();
            let rx = g.tx.as_ref().expect("tx").subscribe();
            (replay, rx)
        };
        let stream = async_stream::stream! {
            for ev in replay {
                yield Ok::<Bytes, std::convert::Infallible>(frame(&ev));
            }
            loop {
                match rx.recv().await {
                    Ok(ev) => yield Ok::<Bytes, std::convert::Infallible>(frame(&ev)),
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => break,
                }
            }
        };
        (
            StatusCode::OK,
            [("content-type", "application/json")],
            Body::from_stream(stream),
        )
            .into_response()
    } else {
        let g = st.lock().await;
        let items: Vec<&Value> = g.nodes.values().collect();
        Json(json!({
            "kind": "NodeList",
            "apiVersion": "v1",
            "metadata": { "resourceVersion": g.rv.to_string() },
            "items": items,
        }))
        .into_response()
    }
}

fn frame(ev: &Ev) -> Bytes {
    let mut buf = serde_json::to_vec(&json!({ "type": ev.kind, "object": ev.node }))
        .expect("frame serializable");
    buf.push(b'\n');
    Bytes::from(buf)
}

async fn get_node(Path(name): Path<String>, State(st): State<Arc<Mutex<MockState>>>) -> Response {
    let g = st.lock().await;
    match g.nodes.get(&name) {
        Some(node) => Json(node.clone()).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "kind": "Status", "apiVersion": "v1", "status": "Failure",
                "reason": "NotFound", "code": 404,
                "message": format!("nodes \"{name}\" not found"),
            })),
        )
            .into_response(),
    }
}

/// Go strategic-merge-ish: annotation keys merge (null deletes), status is
/// replaced wholesale; every call is recorded for assertions.
async fn patch_node(
    Path(name): Path<String>,
    headers: HeaderMap,
    State(st): State<Arc<Mutex<MockState>>>,
    body: Bytes, // body-consuming extractors must come last
) -> Response {
    apply_patch(name, headers, st, body).await
}

/// PATCH `/nodes/{name}/status` (Go `PatchStatus`): recorded in the same
/// patch log so scenarios can assert the daemon took the subresource.
async fn patch_node_status(
    Path(name): Path<String>,
    headers: HeaderMap,
    State(st): State<Arc<Mutex<MockState>>>,
    body: Bytes,
) -> Response {
    apply_patch(name, headers, st, body).await
}

async fn apply_patch(
    name: String,
    headers: HeaderMap,
    st: Arc<Mutex<MockState>>,
    body: Bytes,
) -> Response {
    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let patch: Value = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"kind":"Status","status":"Failure","message":"bad patch"})),
            )
                .into_response();
        }
    };
    let mut g = st.lock().await;
    if !g.nodes.contains_key(&name) {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"kind":"Status","apiVersion":"v1","status":"Failure",
                        "reason":"NotFound","code":404})),
        )
            .into_response();
    }
    // Work on an owned clone so no borrow of `g` outlives the lock scope.
    let mut node = g.nodes.get(&name).cloned().expect("checked above");
    if let Some(ann) = patch
        .pointer("/metadata/annotations")
        .and_then(Value::as_object)
    {
        let target = node["metadata"]["annotations"]
            .as_object_mut()
            .expect("annotations object");
        for (k, v) in ann {
            if v.is_null() {
                target.remove(k);
            } else {
                target.insert(k.clone(), v.clone());
            }
        }
    }
    if let Some(status) = patch.get("status") {
        node["status"] = status.clone();
    }
    g.rv += 1;
    node["metadata"]["resourceVersion"] = json!(g.rv.to_string());
    g.patches.push((content_type, name.clone(), patch.clone()));
    g.nodes.insert(name.clone(), node.clone());
    push(&mut g, "MODIFIED", node.clone());
    Json(node).into_response()
}

/// Delete a node: removes it from the store and emits a DELETED frame
/// (the informer turns that into an EventRemoved).
async fn delete_node(
    Path(name): Path<String>,
    State(st): State<Arc<Mutex<MockState>>>,
) -> Response {
    let mut g = st.lock().await;
    match g.nodes.remove(&name) {
        Some(node) => {
            g.rv += 1;
            push(&mut g, "DELETED", node.clone());
            Json(node).into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({"kind":"Status","apiVersion":"v1","status":"Failure",
                        "reason":"NotFound","code":404})),
        )
            .into_response(),
    }
}
