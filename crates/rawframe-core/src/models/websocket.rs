//! Shared WebSocket domain models. These are transport-neutral contracts; socket
//! and database I/O live in the proxy and store crates.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WebSocketConnectionId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WebSocketFrameId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WebSocketMessageId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebSocketDirection {
    ClientToServer,
    ServerToClient,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebSocketOpcode {
    Text,
    Binary,
    Close,
    Ping,
    Pong,
    Continuation,
    Unknown(u8),
}

impl WebSocketOpcode {
    pub const fn is_control(self) -> bool {
        matches!(self, Self::Close | Self::Ping | Self::Pong)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebSocketConnectionState {
    Handshaking,
    Open,
    Closing,
    Closed,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebSocketInterceptionOutcome {
    Forwarded,
    Modified,
    Dropped,
    Cancelled,
    TimedOut,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebSocketFrameDecision {
    Forward,
    ForwardModified { payload: Vec<u8> },
    Drop,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebSocketFrame {
    pub id: WebSocketFrameId,
    pub connection_id: WebSocketConnectionId,
    pub direction: WebSocketDirection,
    pub opcode: WebSocketOpcode,
    pub fin: bool,
    pub rsv1: bool,
    pub masked: bool,
    pub payload: Vec<u8>,
    pub payload_len: usize,
    pub truncated: bool,
    pub timestamp: DateTime<Utc>,
    pub interception: WebSocketInterceptionOutcome,
}

impl WebSocketFrame {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: WebSocketFrameId,
        connection_id: WebSocketConnectionId,
        direction: WebSocketDirection,
        opcode: WebSocketOpcode,
        fin: bool,
        masked: bool,
        payload: Vec<u8>,
        truncated: bool,
    ) -> Self {
        let payload_len = payload.len();
        Self {
            id,
            connection_id,
            direction,
            opcode,
            fin,
            rsv1: false,
            masked,
            payload,
            payload_len,
            truncated,
            timestamp: Utc::now(),
            interception: WebSocketInterceptionOutcome::Forwarded,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebSocketMessage {
    pub id: WebSocketMessageId,
    pub connection_id: WebSocketConnectionId,
    pub direction: WebSocketDirection,
    pub opcode: WebSocketOpcode,
    pub payload: Vec<u8>,
    pub frame_ids: Vec<WebSocketFrameId>,
    pub complete: bool,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebSocketConnection {
    pub id: WebSocketConnectionId,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub tls: bool,
    pub subprotocol: Option<String>,
    pub extensions: Option<String>,
    pub state: WebSocketConnectionState,
    pub started_at: DateTime<Utc>,
    pub closed_at: Option<DateTime<Utc>>,
    pub frames: usize,
    pub messages: usize,
    pub bytes_client_to_server: u64,
    pub bytes_server_to_client: u64,
    pub error: Option<String>,
}
