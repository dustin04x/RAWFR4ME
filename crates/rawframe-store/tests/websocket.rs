//! Persistence tests for structured WebSocket recordings: byte-exact payloads,
//! policy-driven omission, additive schema, and export inclusion.

use std::fs;

use chrono::{DateTime, TimeZone, Utc};
use rawframe_core::models::session::{Project, Session};
use rawframe_core::models::traffic::TrafficSource;
use rawframe_core::models::websocket::{
    WebSocketConnection, WebSocketConnectionId, WebSocketConnectionState, WebSocketDirection,
    WebSocketFrame, WebSocketFrameId, WebSocketInterceptionOutcome, WebSocketMessage,
    WebSocketMessageId, WebSocketOpcode,
};
use rawframe_core::storage::StoragePolicy;
use rawframe_store::store::DEFAULT_MAX_BYTES;
use rawframe_store::{SCHEMA_VERSION, Store};
use tempfile::TempDir;

fn open(dir: &TempDir, session: &Session, policy: StoragePolicy) -> Store {
    Store::open(
        dir.path().join("sessions.db"),
        &Project::default_project(),
        session,
        policy,
        DEFAULT_MAX_BYTES,
    )
    .expect("store opens")
}

fn stamp(second: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 11, 19, 12, 0, second)
        .single()
        .expect("valid timestamp")
}

fn connection(source: TrafficSource) -> WebSocketConnection {
    WebSocketConnection {
        id: WebSocketConnectionId(1),
        source,
        host: "ws.rawframe.test".into(),
        port: 443,
        path: "/v1/stream".into(),
        tls: true,
        subprotocol: Some("chat".into()),
        extensions: None,
        state: WebSocketConnectionState::Closed,
        started_at: stamp(0),
        closed_at: Some(stamp(30)),
        frames: 3,
        messages: 1,
        bytes_client_to_server: 5,
        bytes_server_to_client: 260,
        error: None,
    }
}

fn frame(
    id: u64,
    direction: WebSocketDirection,
    opcode: WebSocketOpcode,
    payload: Vec<u8>,
) -> WebSocketFrame {
    let mut frame = WebSocketFrame::new(
        WebSocketFrameId(id),
        WebSocketConnectionId(1),
        direction,
        opcode,
        true,
        direction == WebSocketDirection::ClientToServer,
        payload,
        false,
    );
    frame.timestamp = stamp(id as u32);
    frame
}

/// Payload bytes that are not valid UTF-8 and include every byte value.
fn binary_payload() -> Vec<u8> {
    (0..=255u8).collect()
}

#[test]
fn binary_frames_and_messages_round_trip_bytes_and_metadata() {
    let dir = TempDir::new().unwrap();
    let session = Session::new("websocket-binary");
    let mut store = open(
        &dir,
        &session,
        StoragePolicy {
            persist_bodies: true,
            persist_sensitive_headers: true,
        },
    );

    let mut connection = connection(TrafficSource::Intercepted);
    connection.frames = 3;
    let mut text = frame(
        1,
        WebSocketDirection::ClientToServer,
        WebSocketOpcode::Text,
        b"hello".to_vec(),
    );
    let binary = frame(
        2,
        WebSocketDirection::ServerToClient,
        WebSocketOpcode::Continuation,
        binary_payload(),
    );
    let mut cancelled = frame(
        3,
        WebSocketDirection::ServerToClient,
        WebSocketOpcode::Ping,
        b"keepalive".to_vec(),
    );
    cancelled.interception = WebSocketInterceptionOutcome::Cancelled;
    text.truncated = true;

    let mut message = WebSocketMessage::new(
        WebSocketMessageId(1),
        WebSocketConnectionId(1),
        WebSocketDirection::ServerToClient,
        WebSocketOpcode::Binary,
        binary_payload(),
        vec![WebSocketFrameId(2)],
        binary_payload().len(),
        false,
        true,
    );
    message.timestamp = stamp(4);

    store
        .write_websocket(
            std::slice::from_ref(&connection),
            &[text.clone(), binary.clone(), cancelled.clone()],
            std::slice::from_ref(&message),
        )
        .unwrap();

    let recordings = store.load_websocket(&session.id, 10).unwrap();
    assert_eq!(recordings.len(), 1);
    let restored = &recordings[0];
    assert_eq!(restored.connection, connection);
    assert_eq!(restored.frames.len(), 3);
    assert_eq!(restored.frames, vec![text, binary, cancelled]);
    assert_eq!(
        restored.frames[1].payload,
        binary_payload(),
        "binary payloads keep every byte"
    );
    assert_eq!(restored.messages, vec![message]);
    assert_eq!(restored.messages[0].payload, binary_payload());
    assert!(!restored.messages[0].payload_omitted);
    assert!(restored.messages[0].complete);

    assert_eq!(SCHEMA_VERSION, 4);
    assert_eq!(store.count_websocket(&session.id).unwrap(), 1);
}

#[test]
fn metadata_only_policy_withholds_websocket_payloads_without_losing_lengths() {
    let dir = TempDir::new().unwrap();
    let session = Session::new("websocket-metadata");
    let mut store = open(
        &dir,
        &session,
        StoragePolicy {
            persist_bodies: false,
            persist_sensitive_headers: false,
        },
    );

    let text = frame(
        1,
        WebSocketDirection::ClientToServer,
        WebSocketOpcode::Text,
        br#"{"token":"super-secret"}"#.to_vec(),
    );
    let len = text.payload_len;
    let message = WebSocketMessage::new(
        WebSocketMessageId(1),
        WebSocketConnectionId(1),
        WebSocketDirection::ClientToServer,
        WebSocketOpcode::Text,
        br#"{"token":"super-secret"}"#.to_vec(),
        vec![WebSocketFrameId(1)],
        len,
        false,
        true,
    );
    store
        .write_websocket(
            &[connection(TrafficSource::Intercepted)],
            &[text],
            &[message],
        )
        .unwrap();

    let recordings = store.load_websocket(&session.id, 10).unwrap();
    let restored = &recordings[0];
    assert_eq!(restored.frames.len(), 1);
    assert_eq!(
        restored.frames[0].payload,
        Vec::<u8>::new(),
        "withheld payloads are not silently restored as empty content"
    );
    assert!(restored.frames[0].payload_omitted);
    assert_eq!(
        restored.frames[0].payload_len, len,
        "the original length stays available"
    );
    assert_eq!(restored.messages[0].payload, Vec::<u8>::new());
    assert!(restored.messages[0].payload_omitted);
    assert_eq!(restored.messages[0].payload_len, len);
    assert_eq!(
        restored.connection.subprotocol.as_deref(),
        Some("chat"),
        "connection provenance is not message content and is always stored"
    );
}

#[test]
fn export_appends_websocket_recordings_and_marks_omitted_payloads() {
    let dir = TempDir::new().unwrap();
    let session = Session::new("websocket-export");
    let mut store = open(
        &dir,
        &session,
        StoragePolicy {
            persist_bodies: true,
            persist_sensitive_headers: true,
        },
    );
    let connection = connection(TrafficSource::Repeater);
    let text = frame(
        1,
        WebSocketDirection::ClientToServer,
        WebSocketOpcode::Text,
        br#"{"subscribe":"prices"}"#.to_vec(),
    );
    store.write_websocket(&[connection], &[text], &[]).unwrap();

    let export = dir.path().join("session.jsonl");
    let summary = store.export_session(&session.id, &export).unwrap();
    assert_eq!(summary.records, 0);
    assert_eq!(summary.websocket_connections, 1);
    let text = fs::read_to_string(&export).unwrap();
    let line: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
    assert_eq!(line["format"], "rawframe.websocket.v1");
    assert_eq!(line["connection"]["source"], "repeater");
    assert_eq!(line["frames"][0]["opcode"], "text");
    assert_eq!(
        line["frames"][0]["payload"]["text"],
        r#"{"subscribe":"prices"}"#
    );

    // Switching to metadata-only export re-encodes the already stored payload
    // under the current policy rather than leaking it.
    store.set_policy(StoragePolicy::metadata_only());
    let redacted = dir.path().join("redacted.jsonl");
    store.export_session(&session.id, &redacted).unwrap();
    let text = fs::read_to_string(&redacted).unwrap();
    let line: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
    assert_eq!(line["frames"][0]["payload"]["omitted"], true);
    assert_eq!(
        line["frames"][0]["payload"]["length"],
        br#"{"subscribe":"prices"}"#.len()
    );
}

#[test]
fn limits_and_unknown_sessions_are_reported_explicitly() {
    let dir = TempDir::new().unwrap();
    let session = Session::new("websocket-limits");
    let mut store = open(&dir, &session, StoragePolicy::metadata_only());

    let mut newest = connection(TrafficSource::Intercepted);
    newest.id = WebSocketConnectionId(2);
    newest.started_at = stamp(20);
    let mut oldest = connection(TrafficSource::Intercepted);
    oldest.id = WebSocketConnectionId(1);
    oldest.started_at = stamp(10);
    store.write_websocket(&[oldest, newest], &[], &[]).unwrap();

    let limited = store.load_websocket(&session.id, 1).unwrap();
    assert_eq!(limited.len(), 1);
    assert_eq!(
        limited[0].connection.id,
        WebSocketConnectionId(2),
        "the limit keeps the newest connections"
    );
    assert_eq!(store.load_websocket(&session.id, 0).unwrap().len(), 2);

    let other = Session::new("other");
    assert!(store.load_websocket(&other.id, 10).is_err());
    assert_eq!(store.count_websocket(&other.id).unwrap(), 0);
}
