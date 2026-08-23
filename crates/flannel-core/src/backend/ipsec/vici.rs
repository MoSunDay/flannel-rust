//! Minimal strongSwan VICI client: flannel's Go code uses
//! bronze1man/goStrongswanVici, so the protocol is implemented from
//! strongSwan's VICI spec (libcharon/plugins/vici/README.md): a packet
//! is u32 BE length + u8 type + payload; CMD_REQUEST=0 (u8 name-len,
//! name, message), CMD_RESPONSE=1, CMD_UNKNOWN=2, EVENT_CONFIRM=3,
//! EVENT_CONFIRM_FAILED=4, EVENT_REGISTER=5, EVENT_UNREGISTER=6,
//! EVENT=7, EVENT_UNKNOWN=8; segments SECTION_START=1 (u8 name-len,
//! name), SECTION_END=2, KEY_VALUE=3 (u8 key-len, key, u16 BE
//! value-len, value), LIST_START=4 (u8 name-len, name), LIST_ITEM=5
//! (u16 BE value-len, value), LIST_END=6. Blocking std I/O: async
//! callers use `spawn_blocking`. Go deviation: goStrongswanVici runs an
//! async event-dispatch loop; this client is synchronous and never
//! subscribes to events.

use std::io::{self, ErrorKind, Read, Write};
use std::os::unix::net::UnixStream;

#[cfg(test)]
#[path = "mock.rs"]
pub(crate) mod mock;
#[cfg(test)]
#[path = "vici_tests.rs"]
mod vici_tests;

// Packet payload types (strongSwan vici_message_t).
const CMD_REQUEST: u8 = 0;
const CMD_RESPONSE: u8 = 1;
const CMD_UNKNOWN: u8 = 2;
// Message segment types (strongSwan vici_packet_t encoding).
const SECTION_START: u8 = 1;
const SECTION_END: u8 = 2;
const KEY_VALUE: u8 = 3;
const LIST_START: u8 = 4;
const LIST_ITEM: u8 = 5;
const LIST_END: u8 = 6;
/// One ordered segment of a VICI message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ViciSegment {
    /// KEY_VALUE: `key = value` (raw bytes; usually UTF-8 text).
    Key(String, Vec<u8>),
    /// LIST_START/LIST_ITEM*/LIST_END: `name = [items]`.
    List(String, Vec<Vec<u8>>),
    /// SECTION_START/SECTION_END: nested message under `name`.
    Section(String, ViciMessage),
}

impl ViciSegment {
    /// The segment's key/list/section name.
    pub fn name(&self) -> &str {
        match self {
            ViciSegment::Key(k, _) | ViciSegment::List(k, _) | ViciSegment::Section(k, _) => k,
        }
    }
}

/// Ordered VICI message: builder (key/list/section + encode) and the
/// decoded form produced by [`ViciMessage::parse`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ViciMessage {
    segments: Vec<ViciSegment>,
}

impl ViciMessage {
    pub fn new() -> Self {
        Self::default()
    }
    /// Append a KEY_VALUE segment (Go: struct field with `vici:"key"`).
    pub fn key(mut self, key: &str, value: impl AsRef<[u8]>) -> Self {
        self.segments
            .push(ViciSegment::Key(key.to_string(), value.as_ref().to_vec()));
        self
    }
    /// Append a LIST segment with one LIST_ITEM per entry.
    pub fn list(mut self, name: &str, items: &[String]) -> Self {
        let items = items.iter().map(|s| s.as_bytes().to_vec()).collect();
        self.segments
            .push(ViciSegment::List(name.to_string(), items));
        self
    }
    /// Append a SECTION segment wrapping the nested message.
    pub fn section(mut self, name: &str, inner: ViciMessage) -> Self {
        self.segments
            .push(ViciSegment::Section(name.to_string(), inner));
        self
    }
    /// Encode into VICI message bytes (no packet framing).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_segments(&self.segments, &mut out);
        out
    }
    /// Decode a full VICI message body (inverse of [`encode`](Self::encode)).
    pub fn parse(bytes: &[u8]) -> io::Result<Self> {
        let mut off = 0usize;
        let segments = parse_segments(bytes, &mut off)?;
        if off != bytes.len() {
            return Err(bad("trailing bytes in VICI message"));
        }
        Ok(Self { segments })
    }
    /// First segment stored under `name`, if any.
    pub fn get(&self, name: &str) -> Option<&ViciSegment> {
        self.segments.iter().find(|s| s.name() == name)
    }
    /// KEY_VALUE segment decoded as UTF-8 lossy text.
    pub fn get_str(&self, name: &str) -> Option<String> {
        let ViciSegment::Key(_, v) = self.get(name)? else {
            return None;
        };
        Some(String::from_utf8_lossy(v).into_owned())
    }
    /// LIST items of the named segment.
    #[allow(dead_code)] // mirrors Go vici `List`; exercised by tests
    pub fn get_list(&self, name: &str) -> Option<&[Vec<u8>]> {
        let ViciSegment::List(_, items) = self.get(name)? else {
            return None;
        };
        Some(items)
    }
    /// Nested SECTION message under `name`.
    #[allow(dead_code)] // mirrors Go vici `GetSection`; exercised by tests
    pub fn get_section(&self, name: &str) -> Option<&ViciMessage> {
        let ViciSegment::Section(_, inner) = self.get(name)? else {
            return None;
        };
        Some(inner)
    }
}

fn encode_segments(segments: &[ViciSegment], out: &mut Vec<u8>) {
    for seg in segments {
        match seg {
            ViciSegment::Key(k, v) => {
                out.push(KEY_VALUE);
                push_name(out, k);
                out.extend_from_slice(&(v.len() as u16).to_be_bytes());
                out.extend_from_slice(v);
            }
            ViciSegment::List(name, items) => {
                out.push(LIST_START);
                push_name(out, name);
                for item in items {
                    out.push(LIST_ITEM);
                    out.extend_from_slice(&(item.len() as u16).to_be_bytes());
                    out.extend_from_slice(item);
                }
                out.push(LIST_END);
            }
            ViciSegment::Section(name, inner) => {
                out.push(SECTION_START);
                push_name(out, name);
                encode_segments(&inner.segments, out);
                out.push(SECTION_END);
            }
        }
    }
}

fn bad(msg: impl Into<String>) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, msg.into())
}

fn push_name(out: &mut Vec<u8>, name: &str) {
    out.push(name.len() as u8);
    out.extend_from_slice(name.as_bytes());
}

fn parse_segments(bytes: &[u8], off: &mut usize) -> io::Result<Vec<ViciSegment>> {
    let mut out = Vec::new();
    while *off < bytes.len() {
        match bytes[*off] {
            SECTION_START => {
                *off += 1;
                let name = read_name(bytes, off)?;
                let inner = parse_segments(bytes, off)?;
                out.push(ViciSegment::Section(name, ViciMessage { segments: inner }));
            }
            SECTION_END => {
                *off += 1;
                return Ok(out);
            }
            KEY_VALUE => {
                *off += 1;
                let key = read_name(bytes, off)?;
                let value = read_u16_bytes(bytes, off)?;
                out.push(ViciSegment::Key(key, value));
            }
            LIST_START => {
                *off += 1;
                let name = read_name(bytes, off)?;
                let mut items = Vec::new();
                loop {
                    if *off >= bytes.len() {
                        return Err(bad("unterminated VICI list"));
                    }
                    match bytes[*off] {
                        LIST_ITEM => {
                            *off += 1;
                            items.push(read_u16_bytes(bytes, off)?);
                        }
                        LIST_END => {
                            *off += 1;
                            break;
                        }
                        other => return Err(bad(format!("segment {other} inside VICI list"))),
                    }
                }
                out.push(ViciSegment::List(name, items));
            }
            other => return Err(bad(format!("unknown VICI segment type {other}"))),
        }
    }
    Ok(out)
}

fn read_name(bytes: &[u8], off: &mut usize) -> io::Result<String> {
    let len = *bytes.get(*off).ok_or_else(|| bad("truncated VICI name"))? as usize;
    *off += 1;
    let raw = bytes
        .get(*off..*off + len)
        .ok_or_else(|| bad("truncated VICI name"))?;
    *off += len;
    Ok(String::from_utf8_lossy(raw).into_owned())
}

fn read_u16_bytes(bytes: &[u8], off: &mut usize) -> io::Result<Vec<u8>> {
    let len = bytes
        .get(*off..*off + 2)
        .map(|b| u16::from_be_bytes(b.try_into().unwrap()) as usize)
        .ok_or_else(|| bad("truncated VICI length"))?;
    *off += 2;
    let value = bytes
        .get(*off..*off + len)
        .ok_or_else(|| bad("truncated VICI value"))?;
    *off += len;
    Ok(value.to_vec())
}

/// One length-prefixed VICI packet: u32 BE length (type byte
/// included) + u8 type + payload.
fn write_packet(w: &mut impl Write, ptype: u8, payload: &[u8]) -> io::Result<()> {
    let len = (payload.len() + 1) as u32;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(&[ptype])?;
    w.write_all(payload)?;
    w.flush()
}

fn read_packet(r: &mut impl Read) -> io::Result<(u8, Vec<u8>)> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 {
        return Err(io::Error::new(ErrorKind::InvalidData, "empty VICI packet"));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    Ok((body[0], body[1..].to_vec()))
}

/// CMD_REQUEST body: u8 name-len + name + encoded message.
fn cmd_request_payload(name: &str, msg: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(1 + name.len() + msg.len());
    payload.push(name.len() as u8);
    payload.extend_from_slice(name.as_bytes());
    payload.extend_from_slice(msg);
    payload
}

/// `load-conn` IKE config (Go: goStrongswanVici.IKEConf, flannel fields; `local-1`/`remote-1` auth both "psk").
pub struct IkeConf {
    pub local_addrs: Vec<String>,
    pub remote_addrs: Vec<String>,
    pub proposals: Vec<String>,
    pub version: String,
    pub keying_tries: String,
    pub encap: String,
    /// Single child SA section name (Go childConfMap key).
    pub child_name: String,
    pub child: ChildConf,
}

/// Child SA config (Go: goStrongswanVici.ChildSAConf, flannel's fields).
pub struct ChildConf {
    pub local_ts: Vec<String>,
    pub remote_ts: Vec<String>,
    pub esp_proposals: Vec<String>,
    pub start_action: String,
    pub close_action: String,
    pub dpd_action: String,
    pub mode: String,
    pub reqid: String,
    pub rekey_time: String,
    pub install_policy: String,
}

/// A synchronous VICI connection (Go: goStrongswanVici.ClientConn).
pub struct ViciConn {
    stream: UnixStream,
}

impl ViciConn {
    /// Go: `net.Dial(uri.network, uri.address)` with network "unix".
    pub fn connect(path: &str) -> io::Result<Self> {
        Ok(Self {
            stream: UnixStream::connect(path)?,
        })
    }
    /// Send CMD_REQUEST `name` with encoded `msg`, wait for the
    /// CMD_RESPONSE (CMD_UNKNOWN -> error; stray events skipped).
    pub fn request(&mut self, name: &str, msg: &[u8]) -> io::Result<ViciMessage> {
        write_packet(
            &mut self.stream,
            CMD_REQUEST,
            &cmd_request_payload(name, msg),
        )?;
        loop {
            let (ptype, body) = read_packet(&mut self.stream)?;
            match ptype {
                CMD_RESPONSE => return ViciMessage::parse(&body),
                CMD_UNKNOWN => {
                    return Err(io::Error::new(
                        ErrorKind::InvalidInput,
                        format!("unknown VICI command {name}"),
                    ))
                }
                // EVENT / EVENT_CONFIRM / EVENT_UNKNOWN / ...: not
                // subscribed, ignore like the Go client's dispatcher.
                _ => continue,
            }
        }
    }
    /// Go: `client.Close()`.
    pub fn close(self) -> io::Result<()> {
        self.stream.shutdown(std::net::Shutdown::Both)
    }
    /// "load-shared" with keys `type`/`data` + list `owners` (Go:
    /// goStrongswanVici.LoadShared of a `Key`).
    pub fn load_shared(&mut self, typ: &str, data: &[u8], owners: &[String]) -> io::Result<()> {
        let msg = ViciMessage::new()
            .key("type", typ)
            .key("data", data)
            .list("owners", owners);
        let resp = self.request("load-shared", &msg.encode())?;
        check_success(&resp)
    }
    /// "load-conn": one top-level connection section containing the IKE
    /// settings, the psk `local-1`/`remote-1` auth sections and one
    /// child SA (Go: goStrongswanVici.LoadConn).
    pub fn load_conn(&mut self, name: &str, ike: &IkeConf) -> io::Result<()> {
        let child = &ike.child;
        let child_msg = ViciMessage::new()
            .list("local_ts", &child.local_ts)
            .list("remote_ts", &child.remote_ts)
            .list("esp_proposals", &child.esp_proposals)
            .key("start_action", &child.start_action)
            .key("close_action", &child.close_action)
            .key("dpd_action", &child.dpd_action)
            .key("mode", &child.mode)
            .key("reqid", &child.reqid)
            .key("rekey_time", &child.rekey_time)
            .key("install_policy", &child.install_policy);
        let msg = ViciMessage::new().section(
            name,
            ViciMessage::new()
                .list("local_addrs", &ike.local_addrs)
                .list("remote_addrs", &ike.remote_addrs)
                .list("proposals", &ike.proposals)
                .key("version", &ike.version)
                .key("keying_tries", &ike.keying_tries)
                .key("encap", &ike.encap)
                .section("local-1", ViciMessage::new().key("auth", "psk"))
                .section("remote-1", ViciMessage::new().key("auth", "psk"))
                .section(
                    "children",
                    ViciMessage::new().section(&ike.child_name, child_msg),
                ),
        );
        let resp = self.request("load-conn", &msg.encode())?;
        check_success(&resp)
    }
    /// "unload-conn" with key `name` (Go: goStrongswanVici.UnloadConn).
    pub fn unload_conn(&mut self, name: &str) -> io::Result<()> {
        let msg = ViciMessage::new().key("name", name);
        let resp = self.request("unload-conn", &msg.encode())?;
        check_success(&resp)
    }
}

/// Go: `if response.Success != "yes" { return errors.New(response.Err) }`.
fn check_success(resp: &ViciMessage) -> io::Result<()> {
    match resp.get_str("success").as_deref() {
        Some("yes") => Ok(()),
        _ => Err(io::Error::other(
            resp.get_str("err")
                .unwrap_or_else(|| "unknown error".into()),
        )),
    }
}
