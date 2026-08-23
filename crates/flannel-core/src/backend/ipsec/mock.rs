//! In-process mock VICI server for the ipsec tests (not ported from Go;
//! stands in for charon's vici socket). Accepts any number of sequential
//! connections, records every CMD_REQUEST (command name + decoded
//! message) and answers with CMD_RESPONSE {success: yes} — or
//! {success: no, err: <msg>} in `Fail` mode.

use super::{read_packet, write_packet, ViciMessage, CMD_REQUEST, CMD_RESPONSE};
use std::io;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// How the mock answers requests.
pub(crate) enum MockResponse {
    /// `{success: "yes"}`.
    Ok,
    /// `{success: "no", err: <msg>}`.
    Fail(String),
}

/// Running mock server; records all requests. Dropping stops it.
pub(crate) struct MockServer {
    /// Unix socket path clients should connect to.
    pub(crate) path: String,
    /// (command name, decoded message) in arrival order.
    pub(crate) requests: Arc<Mutex<Vec<(String, ViciMessage)>>>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Bind the mock socket at a unique temp-dir path and start the
/// accept loop on a background thread.
pub(crate) fn spawn_mock(response: MockResponse) -> MockServer {
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let path = format!(
        "{}/vici-mock-{id}-{}.sock",
        std::env::temp_dir().display(),
        std::process::id()
    );
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).expect("bind mock VICI socket");
    listener
        .set_nonblocking(true)
        .expect("non-blocking mock listener");
    let requests: Arc<Mutex<Vec<(String, ViciMessage)>>> = Arc::new(Mutex::new(Vec::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let (t_requests, t_stop) = (requests.clone(), stop.clone());
    let handle = thread::spawn(move || {
        while !t_stop.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((conn, _)) => handle_connection(conn, &t_requests, &response),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });
    MockServer {
        path,
        requests,
        stop,
        handle: Some(handle),
    }
}

/// Serve one connection until the peer closes it.
fn handle_connection(
    mut conn: UnixStream,
    requests: &Arc<Mutex<Vec<(String, ViciMessage)>>>,
    response: &MockResponse,
) {
    loop {
        let Ok((ptype, body)) = read_packet(&mut conn) else {
            return;
        };
        if ptype != CMD_REQUEST || body.is_empty() {
            continue;
        }
        let name_len = body[0] as usize;
        let name = String::from_utf8_lossy(&body[1..1 + name_len.min(body.len() - 1)]).into_owned();
        let msg = ViciMessage::parse(&body[1 + name_len..]).unwrap_or_default();
        requests.lock().unwrap().push((name, msg));
        let resp = match response {
            MockResponse::Ok => ViciMessage::new().key("success", "yes"),
            MockResponse::Fail(err) => ViciMessage::new().key("success", "no").key("err", err),
        };
        if write_packet(&mut conn, CMD_RESPONSE, &resp.encode()).is_err() {
            return;
        }
    }
}
