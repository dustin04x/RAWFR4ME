//! Encoding, loading, and export of structured WebSocket recordings.
//!
//! Frames and messages keep their payload bytes as SQL `BLOB`s. When the storage
//! policy does not persist bodies, the payload column is `NULL` and the omitted
//! flag is set, so a restored recording never pretends a withheld payload was
//! empty. Provenance (direction, opcode, FIN, mask, outcome) is always stored
//! because it contains no message content.

use rawframe_core::models::session::SessionId;
use rawframe_core::models::websocket::{
    WebSocketConnection, WebSocketConnectionId, WebSocketConnectionState, WebSocketDirection,
    WebSocketFrame, WebSocketFrameId, WebSocketInterceptionOutcome, WebSocketMessage,
    WebSocketMessageId, WebSocketOpcode,
};
use rawframe_core::storage::StoragePolicy;
use rusqlite::{Connection, OptionalExtension, Transaction};
use serde_json::json;

use crate::error::StoreError;
use crate::record::{now_stamp, parse_stored_time};

/// One persisted WebSocket connection with its captured frames and messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebSocketRecording {
    pub connection: WebSocketConnection,
    pub frames: Vec<WebSocketFrame>,
    pub messages: Vec<WebSocketMessage>,
}

const UPSERT_CONNECTION: &str = r#"
INSERT INTO websocket_connections (
    session_id, connection_id, source, host, port, path, tls, subprotocol,
    extensions, state, started_at, closed_at, frames, messages,
    bytes_client_to_server, bytes_server_to_client, error, updated_at
) VALUES (
    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18
)
ON CONFLICT(session_id, connection_id) DO UPDATE SET
    source = excluded.source,
    host = excluded.host,
    port = excluded.port,
    path = excluded.path,
    tls = excluded.tls,
    subprotocol = excluded.subprotocol,
    extensions = excluded.extensions,
    state = excluded.state,
    started_at = excluded.started_at,
    closed_at = excluded.closed_at,
    frames = excluded.frames,
    messages = excluded.messages,
    bytes_client_to_server = excluded.bytes_client_to_server,
    bytes_server_to_client = excluded.bytes_server_to_client,
    error = excluded.error,
    updated_at = excluded.updated_at
"#;

const UPSERT_FRAME: &str = r#"
INSERT INTO websocket_frames (
    session_id, connection_id, frame_id, direction, opcode, fin, rsv1, masked,
    payload, payload_len, payload_omitted, truncated, outcome, captured_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
ON CONFLICT(session_id, frame_id) DO UPDATE SET
    direction = excluded.direction,
    opcode = excluded.opcode,
    fin = excluded.fin,
    rsv1 = excluded.rsv1,
    masked = excluded.masked,
    payload = excluded.payload,
    payload_len = excluded.payload_len,
    payload_omitted = excluded.payload_omitted,
    truncated = excluded.truncated,
    outcome = excluded.outcome,
    captured_at = excluded.captured_at
"#;

const UPSERT_MESSAGE: &str = r#"
INSERT INTO websocket_messages (
    session_id, connection_id, message_id, direction, opcode, payload,
    payload_len, payload_omitted, frame_ids, complete, truncated, captured_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
ON CONFLICT(session_id, message_id) DO UPDATE SET
    direction = excluded.direction,
    opcode = excluded.opcode,
    payload = excluded.payload,
    payload_len = excluded.payload_len,
    payload_omitted = excluded.payload_omitted,
    frame_ids = excluded.frame_ids,
    complete = excluded.complete,
    truncated = excluded.truncated,
    captured_at = excluded.captured_at
"#;

/// Writes connections, frames, and messages in the caller's transaction.
pub(crate) fn write(
    tx: &Transaction<'_>,
    session_id: &SessionId,
    connections: &[WebSocketConnection],
    frames: &[WebSocketFrame],
    messages: &[WebSocketMessage],
    policy: StoragePolicy,
) -> Result<(), StoreError> {
    let updated_at = now_stamp();
    if !connections.is_empty() {
        let mut statement = tx.prepare_cached(UPSERT_CONNECTION)?;
        for connection in connections {
            statement.execute(rusqlite::params![
                session_id.0,
                connection.id.0 as i64,
                source_str(connection.source),
                connection.host,
                connection.port,
                connection.path,
                connection.tls as i64,
                connection.subprotocol,
                connection.extensions,
                state_str(connection.state),
                timestamp(connection.started_at),
                connection.closed_at.map(timestamp),
                connection.frames as i64,
                connection.messages as i64,
                connection.bytes_client_to_server as i64,
                connection.bytes_server_to_client as i64,
                connection.error,
                updated_at,
            ])?;
        }
    }

    if !frames.is_empty() {
        let mut statement = tx.prepare_cached(UPSERT_FRAME)?;
        for frame in frames {
            let omitted = !policy.persist_bodies && !frame.payload.is_empty();
            let payload = if policy.persist_bodies {
                Some(frame.payload.as_slice())
            } else {
                None
            };
            statement.execute(rusqlite::params![
                session_id.0,
                frame.connection_id.0 as i64,
                frame.id.0 as i64,
                direction_str(frame.direction),
                opcode_str(frame.opcode),
                frame.fin as i64,
                frame.rsv1 as i64,
                frame.masked as i64,
                payload,
                frame.payload_len as i64,
                omitted as i64,
                frame.truncated as i64,
                outcome_str(frame.interception),
                timestamp(frame.timestamp),
            ])?;
        }
    }

    if !messages.is_empty() {
        let mut statement = tx.prepare_cached(UPSERT_MESSAGE)?;
        for message in messages {
            let omitted = !policy.persist_bodies && !message.payload.is_empty();
            let payload = if policy.persist_bodies {
                Some(message.payload.as_slice())
            } else {
                None
            };
            let frame_ids =
                serde_json::to_string(&message.frame_ids.iter().map(|id| id.0).collect::<Vec<_>>())
                    .unwrap_or_else(|_| "[]".into());
            statement.execute(rusqlite::params![
                session_id.0,
                message.connection_id.0 as i64,
                message.id.0 as i64,
                direction_str(message.direction),
                opcode_str(message.opcode),
                payload,
                message.payload_len as i64,
                omitted as i64,
                frame_ids,
                message.complete as i64,
                message.truncated as i64,
                timestamp(message.timestamp),
            ])?;
        }
    }
    Ok(())
}

/// Loads up to `limit` connections (newest first, then restored to
/// chronological order) with their frames and messages.
pub(crate) fn load(
    conn: &Connection,
    session_id: &SessionId,
    limit: usize,
) -> Result<Vec<WebSocketRecording>, StoreError> {
    let fetch = if limit == 0 { -1 } else { limit as i64 };
    let mut statement = conn.prepare(
        "SELECT connection_id, source, host, port, path, tls, subprotocol, extensions, state, \
         started_at, closed_at, frames, messages, bytes_client_to_server, \
         bytes_server_to_client, error \
         FROM websocket_connections WHERE session_id = ?1 \
         ORDER BY started_at DESC, connection_id DESC LIMIT ?2",
    )?;
    let rows = statement.query_map(rusqlite::params![session_id.0, fetch], |row| {
        let started_at: String = row.get("started_at")?;
        let closed_at: Option<String> = row.get("closed_at")?;
        Ok(WebSocketConnection {
            id: WebSocketConnectionId(row.get::<_, i64>("connection_id")?.max(0) as u64),
            source: parse_source(&row.get::<_, String>("source")?),
            host: row.get("host")?,
            port: row.get::<_, i64>("port")?.clamp(0, u16::MAX as i64) as u16,
            path: row.get("path")?,
            tls: row.get::<_, i64>("tls")? != 0,
            subprotocol: row.get("subprotocol")?,
            extensions: row.get("extensions")?,
            state: parse_state(&row.get::<_, String>("state")?),
            started_at: parse_stored_time(&started_at).unwrap_or_else(chrono::Utc::now),
            closed_at: closed_at.as_deref().and_then(parse_stored_time),
            frames: row.get::<_, i64>("frames")?.max(0) as usize,
            messages: row.get::<_, i64>("messages")?.max(0) as usize,
            bytes_client_to_server: row.get::<_, i64>("bytes_client_to_server")?.max(0) as u64,
            bytes_server_to_client: row.get::<_, i64>("bytes_server_to_client")?.max(0) as u64,
            error: row.get("error")?,
        })
    })?;

    let mut recordings = Vec::new();
    for row in rows {
        let connection = row?;
        let frames = load_frames(conn, session_id, connection.id)?;
        let messages = load_messages(conn, session_id, connection.id)?;
        recordings.push(WebSocketRecording {
            connection,
            frames,
            messages,
        });
    }
    recordings.reverse();
    Ok(recordings)
}

fn load_frames(
    conn: &Connection,
    session_id: &SessionId,
    connection_id: WebSocketConnectionId,
) -> Result<Vec<WebSocketFrame>, StoreError> {
    let mut statement = conn.prepare(
        "SELECT frame_id, direction, opcode, fin, rsv1, masked, payload, payload_len, \
         payload_omitted, truncated, outcome, captured_at FROM websocket_frames \
         WHERE session_id = ?1 AND connection_id = ?2 ORDER BY frame_id ASC",
    )?;
    let rows = statement.query_map(
        rusqlite::params![session_id.0, connection_id.0 as i64],
        |row| {
            let captured_at: String = row.get("captured_at")?;
            Ok(WebSocketFrame {
                id: WebSocketFrameId(row.get::<_, i64>("frame_id")?.max(0) as u64),
                connection_id,
                direction: parse_direction(&row.get::<_, String>("direction")?),
                opcode: parse_opcode(&row.get::<_, String>("opcode")?),
                fin: row.get::<_, i64>("fin")? != 0,
                rsv1: row.get::<_, i64>("rsv1")? != 0,
                masked: row.get::<_, i64>("masked")? != 0,
                payload: row
                    .get::<_, Option<Vec<u8>>>("payload")?
                    .unwrap_or_default(),
                payload_len: row.get::<_, i64>("payload_len")?.max(0) as usize,
                payload_omitted: row.get::<_, i64>("payload_omitted")? != 0,
                truncated: row.get::<_, i64>("truncated")? != 0,
                timestamp: parse_stored_time(&captured_at).unwrap_or_else(chrono::Utc::now),
                interception: parse_outcome(&row.get::<_, String>("outcome")?),
            })
        },
    )?;
    let mut frames = Vec::new();
    for row in rows {
        frames.push(row?);
    }
    Ok(frames)
}

fn load_messages(
    conn: &Connection,
    session_id: &SessionId,
    connection_id: WebSocketConnectionId,
) -> Result<Vec<WebSocketMessage>, StoreError> {
    let mut statement = conn.prepare(
        "SELECT message_id, direction, opcode, payload, payload_len, payload_omitted, \
         frame_ids, complete, truncated, captured_at FROM websocket_messages \
         WHERE session_id = ?1 AND connection_id = ?2 ORDER BY message_id ASC",
    )?;
    let rows = statement.query_map(
        rusqlite::params![session_id.0, connection_id.0 as i64],
        |row| {
            let captured_at: String = row.get("captured_at")?;
            let frame_ids: String = row.get("frame_ids")?;
            let raw_ids: Vec<u64> = serde_json::from_str(&frame_ids).unwrap_or_default();
            Ok(WebSocketMessage {
                id: WebSocketMessageId(row.get::<_, i64>("message_id")?.max(0) as u64),
                connection_id,
                direction: parse_direction(&row.get::<_, String>("direction")?),
                opcode: parse_opcode(&row.get::<_, String>("opcode")?),
                payload: row
                    .get::<_, Option<Vec<u8>>>("payload")?
                    .unwrap_or_default(),
                payload_len: row.get::<_, i64>("payload_len")?.max(0) as usize,
                payload_omitted: row.get::<_, i64>("payload_omitted")? != 0,
                frame_ids: raw_ids.into_iter().map(WebSocketFrameId).collect(),
                complete: row.get::<_, i64>("complete")? != 0,
                truncated: row.get::<_, i64>("truncated")? != 0,
                timestamp: parse_stored_time(&captured_at).unwrap_or_else(chrono::Utc::now),
            })
        },
    )?;
    let mut messages = Vec::new();
    for row in rows {
        messages.push(row?);
    }
    Ok(messages)
}

/// Number of stored WebSocket connections for a session (used by status text).
pub(crate) fn count(conn: &Connection, session_id: &SessionId) -> Result<usize, StoreError> {
    let count: Option<i64> = conn
        .query_row(
            "SELECT COUNT(*) FROM websocket_connections WHERE session_id = ?1",
            rusqlite::params![session_id.0],
            |row| row.get(0),
        )
        .optional()?;
    Ok(count.unwrap_or(0).max(0) as usize)
}

/// Builds the redacted export line for one recording.
pub(crate) fn export_json(
    recording: &WebSocketRecording,
    policy: StoragePolicy,
) -> serde_json::Value {
    let connection = &recording.connection;
    json!({
        "format": "rawframe.websocket.v1",
        "connection": {
            "id": connection.id.0,
            "source": source_str(connection.source),
            "host": connection.host,
            "port": connection.port,
            "path": connection.path,
            "tls": connection.tls,
            "subprotocol": connection.subprotocol,
            "extensions": connection.extensions,
            "state": state_str(connection.state),
            "started_at": connection.started_at.to_rfc3339(),
            "closed_at": connection.closed_at.map(|value| value.to_rfc3339()),
            "frames": connection.frames,
            "messages": connection.messages,
            "bytes_client_to_server": connection.bytes_client_to_server,
            "bytes_server_to_client": connection.bytes_server_to_client,
            "error": connection.error,
        },
        "frames": recording.frames.iter().map(|frame| {
            let omitted = frame.payload_omitted
                || (!policy.persist_bodies && !frame.payload.is_empty());
            json!({
                "id": frame.id.0,
                "direction": direction_str(frame.direction),
                "opcode": opcode_str(frame.opcode),
                "fin": frame.fin,
                "rsv1": frame.rsv1,
                "masked": frame.masked,
                "payload": payload_json(&frame.payload, frame.payload_len, omitted, frame.truncated),
                "outcome": outcome_str(frame.interception),
                "captured_at": frame.timestamp.to_rfc3339(),
            })
        }).collect::<Vec<_>>(),
        "messages": recording.messages.iter().map(|message| {
            let omitted = message.payload_omitted
                || (!policy.persist_bodies && !message.payload.is_empty());
            json!({
                "id": message.id.0,
                "direction": direction_str(message.direction),
                "opcode": opcode_str(message.opcode),
                "frame_ids": message.frame_ids.iter().map(|id| id.0).collect::<Vec<_>>(),
                "complete": message.complete,
                "payload": payload_json(&message.payload, message.payload_len, omitted, message.truncated),
                "captured_at": message.timestamp.to_rfc3339(),
            })
        }).collect::<Vec<_>>(),
    })
}

fn payload_json(
    payload: &[u8],
    full_len: usize,
    omitted: bool,
    truncated: bool,
) -> serde_json::Value {
    if omitted {
        return json!({
            "omitted": true,
            "reason": "storage policy does not persist bodies",
            "length": full_len,
        });
    }
    match std::str::from_utf8(payload) {
        Ok(text) => json!({
            "encoding": "utf-8",
            "text": text,
            "length": full_len,
            "truncated": truncated,
        }),
        Err(_) => {
            use base64::Engine as _;
            let encoded = base64::engine::general_purpose::STANDARD.encode(payload);
            json!({
                "encoding": "base64",
                "base64": encoded,
                "length": full_len,
                "truncated": truncated,
            })
        }
    }
}

fn timestamp(value: chrono::DateTime<chrono::Utc>) -> String {
    value.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}

fn direction_str(direction: WebSocketDirection) -> &'static str {
    match direction {
        WebSocketDirection::ClientToServer => "client_to_server",
        WebSocketDirection::ServerToClient => "server_to_client",
    }
}

fn parse_direction(value: &str) -> WebSocketDirection {
    match value {
        "server_to_client" => WebSocketDirection::ServerToClient,
        _ => WebSocketDirection::ClientToServer,
    }
}

fn opcode_str(opcode: WebSocketOpcode) -> &'static str {
    match opcode {
        WebSocketOpcode::Text => "text",
        WebSocketOpcode::Binary => "binary",
        WebSocketOpcode::Close => "close",
        WebSocketOpcode::Ping => "ping",
        WebSocketOpcode::Pong => "pong",
        WebSocketOpcode::Continuation => "continuation",
        WebSocketOpcode::Unknown(_) => "unknown",
    }
}

fn parse_opcode(value: &str) -> WebSocketOpcode {
    match value {
        "binary" => WebSocketOpcode::Binary,
        "close" => WebSocketOpcode::Close,
        "ping" => WebSocketOpcode::Ping,
        "pong" => WebSocketOpcode::Pong,
        "continuation" => WebSocketOpcode::Continuation,
        "unknown" => WebSocketOpcode::Unknown(0),
        _ => WebSocketOpcode::Text,
    }
}

fn state_str(state: WebSocketConnectionState) -> &'static str {
    match state {
        WebSocketConnectionState::Handshaking => "handshaking",
        WebSocketConnectionState::Open => "open",
        WebSocketConnectionState::Closing => "closing",
        WebSocketConnectionState::Closed => "closed",
        WebSocketConnectionState::Failed => "failed",
    }
}

fn parse_state(value: &str) -> WebSocketConnectionState {
    match value {
        "handshaking" => WebSocketConnectionState::Handshaking,
        "open" => WebSocketConnectionState::Open,
        "closing" => WebSocketConnectionState::Closing,
        "failed" => WebSocketConnectionState::Failed,
        _ => WebSocketConnectionState::Closed,
    }
}

fn outcome_str(outcome: WebSocketInterceptionOutcome) -> &'static str {
    match outcome {
        WebSocketInterceptionOutcome::Forwarded => "forwarded",
        WebSocketInterceptionOutcome::Modified => "modified",
        WebSocketInterceptionOutcome::Dropped => "dropped",
        WebSocketInterceptionOutcome::Cancelled => "cancelled",
        WebSocketInterceptionOutcome::TimedOut => "timed_out",
    }
}

fn parse_outcome(value: &str) -> WebSocketInterceptionOutcome {
    match value {
        "modified" => WebSocketInterceptionOutcome::Modified,
        "dropped" => WebSocketInterceptionOutcome::Dropped,
        "cancelled" => WebSocketInterceptionOutcome::Cancelled,
        "timed_out" => WebSocketInterceptionOutcome::TimedOut,
        _ => WebSocketInterceptionOutcome::Forwarded,
    }
}

fn source_str(source: rawframe_core::models::traffic::TrafficSource) -> &'static str {
    use rawframe_core::models::traffic::TrafficSource;
    match source {
        TrafficSource::Intercepted => "intercepted",
        TrafficSource::Simulated => "simulated",
        TrafficSource::Authored => "authored",
        TrafficSource::Repeater => "repeater",
        TrafficSource::Intruder => "intruder",
        TrafficSource::Restored => "restored",
    }
}

fn parse_source(value: &str) -> rawframe_core::models::traffic::TrafficSource {
    use rawframe_core::models::traffic::TrafficSource;
    match value {
        "repeater" => TrafficSource::Repeater,
        "simulated" => TrafficSource::Simulated,
        "authored" => TrafficSource::Authored,
        "intruder" => TrafficSource::Intruder,
        "restored" => TrafficSource::Restored,
        _ => TrafficSource::Intercepted,
    }
}
