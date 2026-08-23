//! Watch stream decoding.
//!
//! The apiserver watch endpoint emits newline-delimited JSON frames:
//! `{"type":"ADDED","object":{...}}\n`. A frame may be split across
//! arbitrary chunk (TCP segment) boundaries or batched several per chunk,
//! so the decoder buffers partial lines until a `\n` arrives. ERROR frames
//! carry a `Status` instead of a node and are surfaced as `Err` so callers
//! can relist on 410/Expired.

use std::fmt;

use futures::{Stream, StreamExt};
use serde::Deserialize;

use super::client::KubeError;
use super::types::{is_expired, Node, Status, WatchEvent, WatchEventType};

/// Decode a chunked byte stream into typed node watch events.
///
/// Chunk items may be any byte container (`Vec<u8>`, `bytes::Bytes`, ...).
/// The returned stream terminates on the first decode error, a transport
/// error, an ERROR watch frame (as `Err`), or end of input.
pub fn decode_watch_stream<S, B, E>(
    stream: S,
) -> impl Stream<Item = Result<WatchEvent<Node>, KubeError>> + Send
where
    S: Stream<Item = Result<B, E>> + Send + 'static,
    B: AsRef<[u8]> + Send + 'static,
    E: fmt::Display + Send + 'static,
{
    async_stream::try_stream! {
        let mut buf: Vec<u8> = Vec::new();
        futures::pin_mut!(stream);
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| {
                KubeError::Decode(format!("watch stream transport error: {e}"))
            })?;
            buf.extend_from_slice(chunk.as_ref());
            for event in decode_lines(&mut buf)? {
                yield event;
            }
        }
        // Tolerate a final frame without a trailing newline.
        if !buf.is_empty() {
            let line = take_trailing(&mut buf);
            if !line.is_empty() {
                yield parse_watch_line(&line)?;
            }
        }
    }
}

/// Parse one complete watch frame line (without the trailing newline).
///
/// Dispatch: `{"type":..., "object":{...}}` is first decoded with the
/// object kept as raw JSON; ERROR frames decode `object` as [`Status`]
/// (410/"Expired" maps to [`KubeError::Gone`], others to
/// [`KubeError::Api`]), all other frames decode `object` as [`Node`].
pub fn parse_watch_line(line: &str) -> Result<WatchEvent<Node>, KubeError> {
    #[derive(Deserialize)]
    struct Frame {
        #[serde(rename = "type")]
        event_type: WatchEventType,
        object: serde_json::Value,
    }
    let frame: Frame = serde_json::from_str(line)
        .map_err(|e| KubeError::Decode(format!("invalid watch frame {line:?}: {e}")))?;
    match frame.event_type {
        WatchEventType::Error => {
            let status: Status = serde_json::from_value(frame.object).map_err(|e| {
                KubeError::Decode(format!("invalid ERROR status in watch frame: {e}"))
            })?;
            if is_expired(&status) {
                Err(KubeError::Gone)
            } else {
                Err(KubeError::Api(status))
            }
        }
        event_type => {
            let node: Node = serde_json::from_value(frame.object).map_err(|e| {
                KubeError::Decode(format!("invalid node in {event_type:?} watch frame: {e}"))
            })?;
            Ok(WatchEvent {
                event_type,
                object: node,
            })
        }
    }
}

/// Drain every complete `\n`-terminated line from `buf`, decoding each.
fn decode_lines(buf: &mut Vec<u8>) -> Result<Vec<WatchEvent<Node>>, KubeError> {
    let mut events = Vec::new();
    while let Some(pos) = buf.iter().position(|&b| b == b'\n') {
        let mut line: Vec<u8> = buf.drain(..=pos).collect();
        line.pop(); // drop '\n'
        if line.last() == Some(&b'\r') {
            line.pop(); // tolerate CRLF
        }
        if line.is_empty() {
            continue;
        }
        let text = String::from_utf8(line)
            .map_err(|e| KubeError::Decode(format!("watch frame is not valid UTF-8: {e}")))?;
        events.push(parse_watch_line(&text)?);
    }
    Ok(events)
}

/// Take whatever remains in `buf` as a final line (strips CR/LF tails).
fn take_trailing(buf: &mut Vec<u8>) -> String {
    let mut line: Vec<u8> = std::mem::take(buf);
    while matches!(line.last(), Some(b'\n') | Some(b'\r')) {
        line.pop();
    }
    String::from_utf8_lossy(&line).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{stream, TryStreamExt};

    fn node_obj(name: &str, rv: &str) -> serde_json::Value {
        serde_json::json!({
            "metadata": {"name": name, "uid": "uid-1", "resourceVersion": rv,
                         "annotations": {"flannel.alpha.coreos.com/backend-type": "vxlan"}},
            "spec": {"podCIDR": "10.244.1.0/24", "podCIDRs": ["10.244.1.0/24"]}
        })
    }

    fn frame(typ: &str, object: serde_json::Value) -> String {
        format!("{}\n", serde_json::json!({"type": typ, "object": object}))
    }

    async fn decode_chunks(chunks: Vec<Vec<u8>>) -> Result<Vec<WatchEvent<Node>>, KubeError> {
        let s = stream::iter(chunks.into_iter().map(Ok::<_, std::io::Error>));
        decode_watch_stream(s).try_collect().await
    }

    #[tokio::test]
    async fn single_event_one_chunk() {
        let events = decode_chunks(vec![frame("ADDED", node_obj("node1", "10")).into()])
            .await
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, WatchEventType::Added);
        assert_eq!(events[0].object.metadata.name, "node1");
        assert_eq!(
            events[0].object.metadata.resource_version.as_deref(),
            Some("10")
        );
        assert_eq!(
            events[0].object.spec.pod_cidr.as_deref(),
            Some("10.244.1.0/24")
        );
    }

    #[tokio::test]
    async fn event_split_across_three_chunks() {
        let line = frame("MODIFIED", node_obj("node1", "11"));
        let bytes = line.as_bytes();
        let third = bytes.len() / 3;
        let chunks = vec![
            bytes[..third].to_vec(),
            bytes[third..2 * third].to_vec(),
            bytes[2 * third..].to_vec(),
        ];
        let events = decode_chunks(chunks).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, WatchEventType::Modified);
        assert_eq!(
            events[0].object.metadata.resource_version.as_deref(),
            Some("11")
        );
    }

    #[tokio::test]
    async fn three_events_in_one_chunk() {
        let mut data = String::new();
        data.push_str(&frame("ADDED", node_obj("node1", "1")));
        data.push_str(&frame("MODIFIED", node_obj("node1", "2")));
        data.push_str(&frame("DELETED", node_obj("node1", "3")));
        let events = decode_chunks(vec![data.into_bytes()]).await.unwrap();
        let kinds: Vec<_> = events.iter().map(|e| e.event_type).collect();
        assert_eq!(
            kinds,
            vec![
                WatchEventType::Added,
                WatchEventType::Modified,
                WatchEventType::Deleted
            ]
        );
        let rvs: Vec<_> = events
            .iter()
            .map(|e| e.object.metadata.resource_version.clone().unwrap())
            .collect();
        assert_eq!(rvs, vec!["1", "2", "3"]);
    }

    #[tokio::test]
    async fn bookmark_event() {
        let obj = serde_json::json!({"metadata": {"name": "node1", "resourceVersion": "42"}});
        let events = decode_chunks(vec![frame("BOOKMARK", obj).into()])
            .await
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, WatchEventType::Bookmark);
        assert_eq!(
            events[0].object.metadata.resource_version.as_deref(),
            Some("42")
        );
    }

    #[tokio::test]
    async fn error_event_expired_maps_to_gone() {
        let status = serde_json::json!({
            "kind": "Status", "message": "too old resource version: 1 (123)",
            "reason": "Expired", "code": 410
        });
        let err = decode_chunks(vec![frame("ERROR", status).into()])
            .await
            .unwrap_err();
        assert!(matches!(err, KubeError::Gone));
    }

    #[tokio::test]
    async fn error_event_with_status_surfaces_api_error() {
        let status = serde_json::json!({
            "kind": "Status", "message": "field label not supported",
            "reason": "BadRequest", "code": 400
        });
        let err = decode_chunks(vec![frame("ERROR", status).into()])
            .await
            .unwrap_err();
        match err {
            KubeError::Api(s) => {
                assert_eq!(s.code, 400);
                assert_eq!(s.reason, "BadRequest");
                assert!(s.message.contains("field label"));
                assert!(s.to_string().contains("BadRequest"));
            }
            other => panic!("expected Api error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn garbage_line_is_decode_error() {
        let err = decode_chunks(vec![b"this is not json\n".to_vec()])
            .await
            .unwrap_err();
        assert!(matches!(err, KubeError::Decode(_)));
    }

    #[tokio::test]
    async fn crlf_line_endings_tolerated() {
        let mut data = frame("ADDED", node_obj("node1", "10"));
        data.insert(data.len() - 1, '\r'); // ends with \r\n
        let events = decode_chunks(vec![data.into_bytes()]).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].object.metadata.name, "node1");
    }

    #[tokio::test]
    async fn trailing_frame_without_newline() {
        let mut data = frame("ADDED", node_obj("node1", "10"));
        data.pop(); // strip trailing '\n'
        let events = decode_chunks(vec![data.into_bytes()]).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, WatchEventType::Added);
    }

    #[tokio::test]
    async fn parse_watch_line_rejects_unknown_event_type() {
        let err = parse_watch_line("{\"type\":\"WEIRD\",\"object\":{}}").unwrap_err();
        assert!(matches!(err, KubeError::Decode(_)));
    }

    #[tokio::test]
    async fn upstream_chunk_error_is_surfaced() {
        let s = stream::iter(vec![
            Ok::<_, std::io::Error>(frame("ADDED", node_obj("n", "1")).into_bytes()),
            Err(std::io::Error::other("connection reset")),
        ]);
        let err: KubeError = decode_watch_stream(s)
            .try_collect::<Vec<_>>()
            .await
            .unwrap_err();
        assert!(matches!(err, KubeError::Decode(m) if m.contains("connection reset")));
    }
}
