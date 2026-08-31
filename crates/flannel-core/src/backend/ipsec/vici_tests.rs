//! Tests for vici.rs: message encode/decode round-trips, framing over a
//! socketpair, and full request/response against the in-process mock.

use super::mock::{spawn_mock, MockResponse};
use super::{read_packet, write_packet, ChildConf, IkeConf, ViciConn, ViciMessage};
use std::io::Read;

#[test]
fn message_round_trip() {
    let msg = ViciMessage::new()
        .key("k0", "v0")
        .section(
            "outer",
            ViciMessage::new()
                .key("k1", "v1")
                .list("lst", &["a".to_string(), "b".to_string()])
                .key("k2", "v2"),
        )
        .key("k3", "v3");
    let bytes = msg.encode();
    let parsed = ViciMessage::parse(&bytes).expect("parse");
    assert_eq!(parsed, msg);
    // accessors on the parsed message
    assert_eq!(parsed.get_str("k3").as_deref(), Some("v3"));
    let outer = parsed.get_section("outer").expect("outer section");
    assert_eq!(outer.get_str("k1").as_deref(), Some("v1"));
    assert_eq!(
        outer.get_list("lst"),
        Some([b"a".to_vec(), b"b".to_vec()].as_slice())
    );
    assert_eq!(parsed.get_str("missing"), None);
}

#[test]
fn parse_rejects_garbage() {
    assert!(ViciMessage::parse(&[]).is_ok()); // empty message = no segments
    assert!(ViciMessage::parse(&[99]).is_err()); // unknown segment type
    assert!(ViciMessage::parse(&[3, 5, b'a']).is_err()); // truncated value
}

#[test]
fn packet_framing_over_socketpair() {
    let (mut a, mut b) = std::os::unix::net::UnixStream::pair().unwrap();
    let payload = b"hello".to_vec();
    write_packet(&mut a, 7, &payload).unwrap();
    let (ptype, body) = read_packet(&mut b).unwrap();
    assert_eq!(ptype, 7);
    assert_eq!(body, payload);
    // EOF surfaces as an error (not Ok)
    drop(a);
    assert!(read_packet(&mut b).is_err());
    // sanity: nothing else pending
    let mut rest = Vec::new();
    assert!(b.read_to_end(&mut rest).is_ok());
}

fn requests(mock: &super::mock::MockServer) -> Vec<(String, ViciMessage)> {
    mock.requests.lock().unwrap().clone()
}

#[test]
fn load_shared_ok_and_records_fields() {
    let mock = spawn_mock(MockResponse::Ok);
    let mut conn = ViciConn::connect(&mock.path).unwrap();
    let secret = b"secret-of-at-least-96-characters-long-enough-to-pass-minPasswordLength";
    conn.load_shared("IKE", secret, &["10.0.0.2".to_string()])
        .expect("load-shared");
    let recorded = requests(&mock);
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].0, "load-shared");
    let msg = &recorded[0].1;
    assert_eq!(msg.get_str("type").as_deref(), Some("IKE"));
    assert_eq!(
        msg.get("data"),
        Some(&super::ViciSegment::Key(
            "data".to_string(),
            secret.to_vec()
        ))
    );
    assert_eq!(
        msg.get_list("owners"),
        Some([b"10.0.0.2".to_vec()].as_slice())
    );
}

#[test]
fn error_response_surfaces() {
    let mock = spawn_mock(MockResponse::Fail("boom".into()));
    let mut conn = ViciConn::connect(&mock.path).unwrap();
    let err = conn
        .load_shared("IKE", b"x", &["10.0.0.2".to_string()])
        .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("boom"), "{msg}");
}

fn sample_ike() -> IkeConf {
    IkeConf {
        local_addrs: vec!["10.0.0.1".to_string()],
        remote_addrs: vec!["10.0.0.2".to_string()],
        proposals: vec!["aes256-sha256-modp4096".to_string()],
        version: "2".to_string(),
        keying_tries: "0".to_string(),
        encap: "true".to_string(),
        child_name: "10.1.0.0/24-10.2.0.0/24".to_string(),
        child: ChildConf {
            local_ts: vec!["10.1.0.0/24".to_string()],
            remote_ts: vec!["10.2.0.0/24".to_string()],
            esp_proposals: vec!["aes128gcm16-sha256-prfsha256-ecp256".to_string()],
            start_action: "start".to_string(),
            close_action: "trap".to_string(),
            dpd_action: "restart".to_string(),
            mode: "tunnel".to_string(),
            reqid: "11".to_string(),
            rekey_time: "1h".to_string(),
            install_policy: "no".to_string(),
        },
    }
}

#[test]
fn load_conn_encodes_nested_tree() {
    let mock = spawn_mock(MockResponse::Ok);
    let mut conn = ViciConn::connect(&mock.path).unwrap();
    conn.load_conn("conn-1", &sample_ike()).expect("load-conn");
    let recorded = requests(&mock);
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].0, "load-conn");
    // everything is nested under the connection name (Go map encoding)
    let top = recorded[0].1.get_section("conn-1").expect("conn section");
    assert_eq!(top.get_str("version").as_deref(), Some("2"));
    assert_eq!(top.get_str("keying_tries").as_deref(), Some("0"));
    assert_eq!(top.get_str("encap").as_deref(), Some("true"));
    assert_eq!(
        top.get_list("proposals"),
        Some([b"aes256-sha256-modp4096".to_vec()].as_slice())
    );
    assert_eq!(
        top.get_list("local_addrs"),
        Some([b"10.0.0.1".to_vec()].as_slice())
    );
    // local-1/remote-1 auth sections both psk
    assert_eq!(
        top.get_section("local-1")
            .and_then(|s| s.get_str("auth"))
            .as_deref(),
        Some("psk")
    );
    assert_eq!(
        top.get_section("remote-1")
            .and_then(|s| s.get_str("auth"))
            .as_deref(),
        Some("psk")
    );
    // child section nested under children/<child_name> with Go defaults
    let child = top
        .get_section("children")
        .and_then(|c| c.get_section("10.1.0.0/24-10.2.0.0/24"))
        .expect("child section");
    assert_eq!(child.get_str("mode").as_deref(), Some("tunnel"));
    assert_eq!(child.get_str("start_action").as_deref(), Some("start"));
    assert_eq!(child.get_str("close_action").as_deref(), Some("trap"));
    assert_eq!(child.get_str("dpd_action").as_deref(), Some("restart"));
    assert_eq!(child.get_str("rekey_time").as_deref(), Some("1h"));
    assert_eq!(child.get_str("install_policy").as_deref(), Some("no"));
    assert_eq!(child.get_str("reqid").as_deref(), Some("11"));
    assert_eq!(
        child.get_list("local_ts"),
        Some([b"10.1.0.0/24".to_vec()].as_slice())
    );
    assert_eq!(
        child.get_list("esp_proposals"),
        Some([b"aes128gcm16-sha256-prfsha256-ecp256".to_vec()].as_slice())
    );
}

#[test]
fn unload_conn_ok() {
    let mock = spawn_mock(MockResponse::Ok);
    let mut conn = ViciConn::connect(&mock.path).unwrap();
    conn.unload_conn("conn-1").expect("unload-conn");
    let recorded = requests(&mock);
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].0, "unload-conn");
    assert_eq!(recorded[0].1.get_str("name").as_deref(), Some("conn-1"));
}

#[test]
fn read_packet_rejects_length_words_beyond_the_cap() {
    use super::MAX_PACKET_LEN;
    // Only the 4-byte length word is on the wire: if read_packet sized
    // its buffer from it before validating, this test would allocate
    // gigabytes and then fail with UnexpectedEof instead of this error.
    for len in [MAX_PACKET_LEN as u32 + 1, u32::MAX] {
        let wire = len.to_be_bytes().to_vec();
        let err = read_packet(&mut wire.as_slice()).expect_err("{len} must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains(&MAX_PACKET_LEN.to_string()),
            "error names the limit: {err}"
        );
    }
}

#[test]
fn read_packet_still_accepts_frames_up_to_the_cap() {
    use super::MAX_PACKET_LEN;
    // boundary: a frame of exactly the limit is legitimate
    let mut body = vec![0xaau8; MAX_PACKET_LEN];
    body[0] = 7; // packet type byte
    let mut wire = (MAX_PACKET_LEN as u32).to_be_bytes().to_vec();
    wire.extend_from_slice(&body);
    let (ptype, payload) = read_packet(&mut wire.as_slice()).unwrap();
    assert_eq!(ptype, 7);
    assert_eq!(payload, vec![0xaa; MAX_PACKET_LEN - 1]);
}
