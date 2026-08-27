//! In-memory mock apiserver (axum) for the kube subnet manager
//! integration tests: node CRUD, pods, strategic-merge PATCH recording
//! with state application, and a replayable WATCH stream with a 410
//! Gone injection knob.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use axum::body::{Body, Bytes};
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{json, Value};

type WatchTx = tokio::sync::mpsc::UnboundedSender<String>;

#[derive(Default)]
struct MockState {
    /// Current node objects keyed by name.
    nodes: BTreeMap<String, Value>,
    /// Monotonic resourceVersion.
    rv: u64,
    /// Change log: (rv, watch frame line) for watch replay.
    frames: Vec<(u64, String)>,
    /// Live watch connections.
    watchers: Vec<WatchTx>,
    /// Recorded PATCH requests to the main resource:
    /// (content-type, node name, body).
    patches: Vec<(String, String, Value)>,
    /// Recorded PATCH requests to the /status subresource
    /// (content-type, node name, body).
    status_patches: Vec<(String, String, Value)>,
    /// Pods: (namespace, name) -> nodeName.
    pods: HashMap<(String, String), String>,
    /// Next N watch requests get 410 Gone (relist exercise).
    gone_pending: usize,
}

/// Handle to the mock: test-side mutation/inspection plus the axum state.
#[derive(Clone)]
pub(crate) struct MockApiserver {
    state: Arc<Mutex<MockState>>,
}

impl MockApiserver {
    pub(crate) async fn start() -> (String, MockApiserver) {
        let api = MockApiserver {
            state: Arc::new(Mutex::new(MockState::default())),
        };
        let app = Router::new()
            .route("/api/v1/nodes", get(list_or_watch_nodes))
            .route("/api/v1/nodes/{name}", get(get_node).patch(patch_node))
            .route(
                "/api/v1/nodes/{name}/status",
                get(get_node).patch(patch_node_status),
            )
            .route("/api/v1/namespaces/{ns}/pods/{name}", get(get_pod))
            .with_state(api.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}"), api)
    }

    /// Insert/replace a node (like the controller-manager would): bumps
    /// resourceVersion, records a watch frame, notifies watchers.
    pub(crate) fn put_node(
        &self,
        name: &str,
        pod_cidrs: &[&str],
        annotations: &BTreeMap<String, String>,
    ) {
        let mut st = self.state.lock().unwrap();
        st.rv += 1;
        let event_type = if st.nodes.contains_key(name) {
            "MODIFIED"
        } else {
            "ADDED"
        };
        let node = node_json(name, &st.rv.to_string(), pod_cidrs, annotations);
        st.nodes.insert(name.to_string(), node.clone());
        let frame = format!("{}\n", json!({"type": event_type, "object": node}));
        let rv = st.rv;
        st.frames.push((rv, frame.clone()));
        notify_watchers(&mut st, frame);
    }

    pub(crate) fn delete_node(&self, name: &str) {
        let mut st = self.state.lock().unwrap();
        let Some(node) = st.nodes.remove(name) else {
            return;
        };
        st.rv += 1;
        let frame = format!("{}\n", json!({"type": "DELETED", "object": node}));
        let rv = st.rv;
        st.frames.push((rv, frame.clone()));
        notify_watchers(&mut st, frame);
    }

    pub(crate) fn set_pod(&self, namespace: &str, name: &str, node_name: &str) {
        self.state.lock().unwrap().pods.insert(
            (namespace.to_string(), name.to_string()),
            node_name.to_string(),
        );
    }

    /// Next `n` watch requests answer 410 Gone.
    pub(crate) fn expect_gone(&self, n: usize) {
        self.state.lock().unwrap().gone_pending += n;
    }

    /// Close all live watch streams (apiserver restart); the informer
    /// must relist and resume.
    pub(crate) fn drop_watch(&self) {
        self.state.lock().unwrap().watchers.clear();
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

    /// Recorded patches: (content-type, node, body).
    pub(crate) fn patches(&self) -> Vec<(String, String, Value)> {
        self.state.lock().unwrap().patches.clone()
    }

    /// Recorded /status-subresource patches: (content-type, node, body).
    pub(crate) fn status_patches(&self) -> Vec<(String, String, Value)> {
        self.state.lock().unwrap().status_patches.clone()
    }

    pub(crate) fn node_status(&self, name: &str) -> Option<Value> {
        self.state
            .lock()
            .unwrap()
            .nodes
            .get(name)?
            .get("status")
            .cloned()
    }
}

fn notify_watchers(st: &mut MockState, frame: String) {
    st.watchers.retain(|tx| tx.send(frame.clone()).is_ok());
}

fn node_json(
    name: &str,
    rv: &str,
    pod_cidrs: &[&str],
    annotations: &BTreeMap<String, String>,
) -> Value {
    let mut spec = json!({});
    if let Some((first, rest)) = pod_cidrs.split_first() {
        spec["podCIDR"] = json!(first);
        if !rest.is_empty() {
            spec["podCIDRs"] = json!(pod_cidrs);
        }
    }
    json!({
        "metadata": {
            "name": name,
            "uid": format!("uid-{name}"),
            "resourceVersion": rv,
            "annotations": annotations,
        },
        "spec": spec,
    })
}

fn not_found(what: &str) -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({"kind": "Status", "code": 404, "reason": "NotFound",
                    "message": format!("{what} not found")})),
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

async fn get_pod(
    State(api): State<MockApiserver>,
    Path((ns, name)): Path<(String, String)>,
) -> Response {
    let st = api.state.lock().unwrap();
    match st.pods.get(&(ns.clone(), name.clone())) {
        Some(node_name) => Json(json!({
            "metadata": {"name": name},
            "spec": {"nodeName": node_name},
        }))
        .into_response(),
        None => not_found(&format!("pods \"{name}\"")),
    }
}

/// Records the patch, then applies it strategic-merge style: annotations
/// are key-merged (JSON null deletes), `status` is replaced. Bumps rv
/// and emits a MODIFIED watch frame, like the apiserver would.
async fn patch_node(
    State(api): State<MockApiserver>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    apply_patch(api, name, headers, body, Target::Main).await
}

/// PATCH `/nodes/{name}/status` (Go `PatchStatus`): recorded separately
/// so tests can prove status writes take the subresource endpoint.
async fn patch_node_status(
    State(api): State<MockApiserver>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    apply_patch(api, name, headers, body, Target::Status).await
}

/// Which endpoint a patch was recorded on.
#[derive(Clone, Copy, PartialEq)]
enum Target {
    Main,
    Status,
}

async fn apply_patch(
    api: MockApiserver,
    name: String,
    headers: HeaderMap,
    body: Bytes,
    target: Target,
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
    match target {
        Target::Main => st.patches.push((content_type, name.clone(), patch.clone())),
        Target::Status => st
            .status_patches
            .push((content_type, name.clone(), patch.clone())),
    }

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
    let frame = format!("{}\n", json!({"type": "MODIFIED", "object": node}));
    st.nodes.insert(name.clone(), node.clone());
    let rv = st.rv;
    st.frames.push((rv, frame.clone()));
    notify_watchers(&mut st, frame);
    drop(st);
    Json(node).into_response()
}

async fn list_or_watch_nodes(
    State(api): State<MockApiserver>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if params.get("watch").map(String::as_str) == Some("true") {
        return watch_nodes(api, &params);
    }
    let st = api.state.lock().unwrap();
    let items: Vec<&Value> = st.nodes.values().collect();
    Json(json!({
        "metadata": {"resourceVersion": st.rv.to_string()},
        "items": items,
    }))
    .into_response()
}

/// WATCH: replays recorded frames newer than resourceVersion, then
/// streams live frames. `gone_pending` > 0 answers 410 Gone first.
fn watch_nodes(api: MockApiserver, params: &HashMap<String, String>) -> Response {
    let mut st = api.state.lock().unwrap();
    if st.gone_pending > 0 {
        st.gone_pending -= 1;
        drop(st);
        return (
            StatusCode::GONE,
            Json(json!({"kind": "Status", "code": 410, "reason": "Expired",
                        "message": "too old resource version"})),
        )
            .into_response();
    }
    let since: u64 = params
        .get("resourceVersion")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let replay: String = st
        .frames
        .iter()
        .filter(|(rv, _)| *rv > since)
        .map(|(_, frame)| frame.as_str())
        .collect();
    st.watchers.push(tx);
    drop(st);

    let stream = async_stream::stream! {
        if !replay.is_empty() {
            yield Ok::<Vec<u8>, std::io::Error>(replay.into_bytes());
        }
        let mut rx = rx;
        while let Some(frame) = rx.recv().await {
            yield Ok(frame.into_bytes());
        }
    };
    (StatusCode::OK, Body::from_stream(stream)).into_response()
}
