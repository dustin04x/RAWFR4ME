//! Contracts for operator-authored WebSocket sessions.
//!
//! The WebSocket Repeater shares the proxy's scope policy, address policy, and
//! verified TLS configuration, but it is a separate client: it never passes
//! through the interception relay and its frames are labelled
//! [`crate::models::traffic::TrafficSource::Repeater`].
//!
//! Sessions are addressed by a small numeric id chosen by the interface. The
//! service maps each session to one upstream connection at a time; opening the
//! same session again replaces the previous connection.

use serde::{Deserialize, Serialize};

use crate::models::traffic::TrafficSource;
use crate::models::websocket::{WebSocketConnection, WebSocketConnectionId, WebSocketOpcode};

/// Connection ids for authored sessions live above the proxy and restored
/// ranges so a repeater connection can never collide with captured traffic.
pub const WEBSOCKET_REPEATER_ID_BASE: u64 = 3_000_000;

/// Commands accepted by the WebSocket Repeater service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebSocketRepeaterCommand {
    /// Open (or replace) a session against an explicit target.
    Open {
        session: u64,
        host: String,
        port: u16,
        path: String,
        tls: bool,
        subprotocol: Option<String>,
    },
    /// Send one complete, unfragmented frame.
    Send {
        session: u64,
        opcode: WebSocketOpcode,
        payload: Vec<u8>,
    },
    /// Close the upstream connection with a normal closure.
    Close {
        session: u64,
    },
    /// Cancel an in-flight connection attempt or session.
    Cancel {
        session: u64,
    },
    /// Replace the live scope used for future session opens.
    UpdateScope(crate::models::config::Scope),
    Shutdown,
}

pub type WebSocketRepeaterCommandSender = tokio::sync::mpsc::Sender<WebSocketRepeaterCommand>;

/// Events published by the WebSocket Repeater service.
#[derive(Debug, Clone)]
pub enum WebSocketRepeaterEvent {
    /// The upstream handshake completed. The connection is already recorded in
    /// the WebSocket workspace with `TrafficSource::Repeater`.
    Opened {
        session: u64,
        connection: Box<WebSocketConnection>,
    },
    /// The session ended normally.
    Closed { session: u64, reason: String },
    /// The session ended because of a validation, scope, policy, or transport
    /// failure. `blocked` distinguishes a local refusal from an upstream error.
    Failed {
        session: u64,
        error: String,
        blocked: bool,
    },
}

impl WebSocketRepeaterEvent {
    pub const fn session(&self) -> u64 {
        match self {
            Self::Opened { session, .. }
            | Self::Closed { session, .. }
            | Self::Failed { session, .. } => *session,
        }
    }
}

/// A recorded connection can seed a new authored session without retyping the
/// target. Only connection metadata is reused; no captured frame is replayed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebSocketRepeaterTarget {
    pub host: String,
    pub port: u16,
    pub path: String,
    pub tls: bool,
    pub subprotocol: Option<String>,
}

impl WebSocketRepeaterTarget {
    pub fn from_connection(connection: &WebSocketConnection) -> Self {
        Self {
            host: connection.host.clone(),
            port: connection.port,
            path: connection.path.clone(),
            tls: connection.tls,
            subprotocol: connection.subprotocol.clone(),
        }
    }

    /// Repeater connections are authored: they are never presented as live
    /// captures, even when they were seeded from one.
    pub const fn source() -> TrafficSource {
        TrafficSource::Repeater
    }
}

pub fn session_connection_id(session: u64) -> WebSocketConnectionId {
    WebSocketConnectionId(WEBSOCKET_REPEATER_ID_BASE + session)
}
