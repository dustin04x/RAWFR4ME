//! Operator-authored WebSocket sessions for the WebSocket Repeater.
//!
//! Every session is independent: it validates its destination against the live
//! scope *before* any DNS lookup or connection, verifies upstream TLS with the
//! same configuration as the proxy, and labels its traffic as Repeater output.
//! Frames are the unit of interaction, matching the interception relay.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;

use chrono::Utc;
use rawframe_core::models::config::{ProxyConfiguration, Scope};
use rawframe_core::models::message::Scheme;
use rawframe_core::models::traffic::TrafficSource;
use rawframe_core::models::websocket::{
    WebSocketConnection, WebSocketConnectionState, WebSocketDirection, WebSocketFrame,
    WebSocketFrameId, WebSocketInterceptionOutcome, WebSocketOpcode,
};
use rawframe_core::websocket::{
    WEBSOCKET_REPEATER_ID_BASE, WebSocketRepeaterCommand, WebSocketRepeaterEvent,
    session_connection_id,
};
use rawframe_core::{AppEvent, EventSender};
use rawframe_proxy::destination::Destination;
use rawframe_proxy::websocket::client::{
    WebSocketClient, WebSocketClientConfig, WebSocketClientError,
};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

const SESSION_COMMAND_CAPACITY: usize = 8;
const READER_FRAME_CAPACITY: usize = 32;

#[derive(Debug, Clone)]
pub struct WebSocketRepeaterConfig {
    pub allow_private_upstreams: bool,
    pub connect_timeout: Duration,
    pub idle_timeout: Duration,
    pub max_frame_bytes: usize,
    pub max_message_bytes: usize,
    pub max_sessions: usize,
    pub capture_bytes: usize,
    pub trust_file: Option<std::path::PathBuf>,
}

impl WebSocketRepeaterConfig {
    pub fn from_proxy(config: &ProxyConfiguration) -> Self {
        Self {
            allow_private_upstreams: config.allow_private_upstreams,
            connect_timeout: Duration::from_secs(config.connect_timeout_secs),
            idle_timeout: Duration::from_secs(config.websocket_idle_timeout_secs),
            max_frame_bytes: config.websocket_max_frame_bytes,
            max_message_bytes: config.websocket_max_message_bytes,
            max_sessions: config.websocket_max_connections.min(8),
            capture_bytes: config.websocket_capture_bytes,
            trust_file: config.tls_upstream_trust_file.clone(),
        }
    }
}

enum SessionCommand {
    Send {
        opcode: WebSocketOpcode,
        payload: Vec<u8>,
    },
    Close,
}

/// Runs until shutdown. Session tasks report completion on a shared channel so
/// the active-session count is always exact, even after failures.
pub async fn run_websocket_service(
    mut commands: mpsc::Receiver<WebSocketRepeaterCommand>,
    config: WebSocketRepeaterConfig,
    events: EventSender,
    scope: Arc<RwLock<Scope>>,
) {
    let config = Arc::new(config);
    let frame_ids = Arc::new(std::sync::atomic::AtomicU64::new(
        WEBSOCKET_REPEATER_ID_BASE + 1,
    ));
    let mut sessions: HashMap<u64, mpsc::Sender<SessionCommand>> = HashMap::new();
    let mut tasks: JoinSet<()> = JoinSet::new();
    let (done_tx, mut done_rx) = mpsc::channel::<u64>(16);
    let shutdown = CancellationToken::new();

    loop {
        tokio::select! {
            command = commands.recv() => {
                match command {
                    Some(WebSocketRepeaterCommand::Open { session, host, port, path, tls, subprotocol }) => {
                        if sessions.len() >= config.max_sessions {
                            let _ = events.send(AppEvent::WebSocketRepeater(
                                WebSocketRepeaterEvent::Failed {
                                    session,
                                    error: format!(
                                        "WebSocket Repeater session limit reached ({})",
                                        config.max_sessions
                                    ),
                                    blocked: true,
                                },
                            ));
                            continue;
                        }
                        if let Some(previous) = sessions.remove(&session) {
                            let _ = previous.try_send(SessionCommand::Close);
                        }
                        let (session_tx, session_rx) = mpsc::channel(SESSION_COMMAND_CAPACITY);
                        sessions.insert(session, session_tx);
                        let task_config = config.clone();
                        let task_events = events.clone();
                        let task_scope = scope.clone();
                        let task_ids = frame_ids.clone();
                        let task_done = done_tx.clone();
                        let task_shutdown = shutdown.clone();
                        tasks.spawn(async move {
                            run_session(
                                session,
                                SessionTarget { host, port, path, tls, subprotocol },
                                task_config,
                                task_events,
                                task_scope,
                                session_rx,
                                task_ids,
                                task_done,
                                task_shutdown,
                            )
                            .await;
                        });
                    }
                    Some(WebSocketRepeaterCommand::Send { session, opcode, payload }) => {
                        if let Some(sender) = sessions.get(&session)
                            && sender
                                .try_send(SessionCommand::Send { opcode, payload })
                                .is_err()
                        {
                            let _ = events.send(AppEvent::WebSocketRepeater(
                                WebSocketRepeaterEvent::Failed {
                                    session,
                                    error: "WebSocket Repeater is busy; the frame was not queued"
                                        .into(),
                                    blocked: true,
                                },
                            ));
                        }
                    }
                    Some(WebSocketRepeaterCommand::Close { session }) => {
                        if let Some(sender) = sessions.get(&session) {
                            let _ = sender.try_send(SessionCommand::Close);
                        }
                    }
                    Some(WebSocketRepeaterCommand::Cancel { session }) => {
                        if let Some(sender) = sessions.remove(&session) {
                            let _ = sender.try_send(SessionCommand::Close);
                        }
                    }
                    Some(WebSocketRepeaterCommand::UpdateScope(updated)) => {
                        if let Ok(mut current) = scope.write() {
                            *current = updated;
                        }
                    }
                    Some(WebSocketRepeaterCommand::Shutdown) | None => break,
                }
            }
            Some(session) = done_rx.recv() => {
                sessions.remove(&session);
            }
            _ = shutdown.cancelled() => break,
        }
    }

    shutdown.cancel();
    for (_, sender) in sessions {
        let _ = sender.try_send(SessionCommand::Close);
    }
    while tasks.join_next().await.is_some() {}
}

struct SessionTarget {
    host: String,
    port: u16,
    path: String,
    tls: bool,
    subprotocol: Option<String>,
}

#[allow(clippy::too_many_arguments)]
async fn run_session(
    session: u64,
    target: SessionTarget,
    config: Arc<WebSocketRepeaterConfig>,
    events: EventSender,
    scope: Arc<RwLock<Scope>>,
    mut commands: mpsc::Receiver<SessionCommand>,
    frame_ids: Arc<std::sync::atomic::AtomicU64>,
    done: mpsc::Sender<u64>,
    shutdown: CancellationToken,
) {
    let result = session_inner(
        session,
        &target,
        &config,
        &events,
        &scope,
        &mut commands,
        &frame_ids,
        &shutdown,
    )
    .await;
    if let Err(SessionEnd::Failed { error, blocked }) = result {
        let _ = events.send(AppEvent::WebSocketRepeater(
            WebSocketRepeaterEvent::Failed {
                session,
                error,
                blocked,
            },
        ));
    }
    let _ = done.send(session).await;
}

enum SessionEnd {
    Closed(String),
    Failed { error: String, blocked: bool },
}

#[allow(clippy::too_many_arguments)]
async fn session_inner(
    session: u64,
    target: &SessionTarget,
    config: &WebSocketRepeaterConfig,
    events: &EventSender,
    scope: &Arc<RwLock<Scope>>,
    commands: &mut mpsc::Receiver<SessionCommand>,
    frame_ids: &Arc<std::sync::atomic::AtomicU64>,
    shutdown: &CancellationToken,
) -> Result<SessionEnd, SessionEnd> {
    let scheme = if target.tls {
        Scheme::Https
    } else {
        Scheme::Http
    };
    let destination = Destination::from_parts(scheme, &target.host, target.port, &target.path)
        .map_err(|rejection| SessionEnd::Failed {
            error: rejection.message,
            blocked: true,
        })?;
    let permitted = scope
        .read()
        .map(|scope| destination.is_permitted(&scope))
        .unwrap_or(false);
    if !permitted {
        return Err(SessionEnd::Failed {
            error: format!(
                "destination {}:{} is outside the configured scope",
                target.host, target.port
            ),
            blocked: true,
        });
    }

    let client_config = WebSocketClientConfig {
        allow_private_upstreams: config.allow_private_upstreams,
        connect_timeout: config.connect_timeout,
        max_frame_bytes: config.max_frame_bytes,
        trust_file: config.trust_file.clone(),
    };
    let client = tokio::select! {
        _ = shutdown.cancelled() => {
            return Ok(SessionEnd::Closed("service shutdown".into()));
        }
        result = WebSocketClient::connect(&destination, target.subprotocol.as_deref(), &client_config) => {
            match result {
                Ok(client) => client,
                Err(error) => {
                    let blocked = matches!(
                        error,
                        WebSocketClientError::Rejected(_)
                    );
                    return Err(SessionEnd::Failed { error: error.to_string(), blocked });
                }
            }
        }
    };
    let subprotocol = client.subprotocol().map(str::to_string);

    let connection_id = session_connection_id(session);
    let mut connection = WebSocketConnection {
        id: connection_id,
        source: TrafficSource::Repeater,
        host: target.host.clone(),
        port: target.port,
        path: target.path.clone(),
        tls: target.tls,
        subprotocol,
        extensions: None,
        state: WebSocketConnectionState::Open,
        started_at: Utc::now(),
        closed_at: None,
        frames: 0,
        messages: 0,
        bytes_client_to_server: 0,
        bytes_server_to_client: 0,
        error: None,
    };
    let _ = events.send(AppEvent::WebSocketConnection(Box::new(connection.clone())));
    let _ = events.send(AppEvent::WebSocketRepeater(
        WebSocketRepeaterEvent::Opened {
            session,
            connection: Box::new(connection.clone()),
        },
    ));

    let (mut reader, mut writer) = client.into_split();
    let (frame_tx, mut frame_rx) = mpsc::channel(READER_FRAME_CAPACITY);
    let reader_task = tokio::spawn(async move {
        loop {
            match reader.receive().await {
                Ok(frame) => {
                    if frame_tx.send(Ok(frame)).await.is_err() {
                        return;
                    }
                }
                Err(error) => {
                    let _ = frame_tx.send(Err(error)).await;
                    return;
                }
            }
        }
    });

    let idle = tokio::time::sleep(config.idle_timeout);
    tokio::pin!(idle);
    let mut fragments = Fragment::default();
    let end: SessionEnd;

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                writer.send_close(1001, "service shutdown").await;
                end = SessionEnd::Closed("service shutdown".into());
                break;
            }
            command = commands.recv() => {
                match command {
                    Some(SessionCommand::Send { opcode, payload }) => {
                        if payload.len() > config.max_frame_bytes {
                            end = SessionEnd::Failed {
                                error: format!(
                                    "frame of {} bytes exceeds the {} byte limit",
                                    payload.len(), config.max_frame_bytes
                                ),
                                blocked: true,
                            };
                            break;
                        }
                        if let Err(error) = writer.send(opcode, payload.clone()).await {
                            end = SessionEnd::Failed { error: error.to_string(), blocked: false };
                            break;
                        }
                        let frame = capture_frame(
                            frame_ids, connection_id, WebSocketDirection::ClientToServer,
                            opcode, true, true, payload, config.capture_bytes,
                        );
                        connection.frames += 1;
                        connection.bytes_client_to_server += frame.payload_len as u64;
                        let _ = events.send(AppEvent::WebSocketFrame(Box::new(frame)));
                        idle.as_mut().reset(tokio::time::Instant::now() + config.idle_timeout);
                    }
                    Some(SessionCommand::Close) | None => {
                        writer.send_close(1000, "operator closed the session").await;
                        end = SessionEnd::Closed("operator closed the session".into());
                        break;
                    }
                }
            }
            frame = frame_rx.recv() => {
                match frame {
                    Some(Ok(frame)) => {
                        idle.as_mut().reset(tokio::time::Instant::now() + config.idle_timeout);
                        match frame.opcode {
                            WebSocketOpcode::Ping => {
                                if writer.send(WebSocketOpcode::Pong, frame.payload).await.is_err() {
                                    end = SessionEnd::Failed {
                                        error: "failed to answer an upstream ping".into(),
                                        blocked: false,
                                    };
                                    break;
                                }
                            }
                            WebSocketOpcode::Pong => {}
                            WebSocketOpcode::Close => {
                                writer.send_close(1000, "").await;
                                end = SessionEnd::Closed("upstream closed the session".into());
                                break;
                            }
                            opcode => {
                                if let Err(reason) = fragments.accept(
                                    opcode,
                                    frame.fin,
                                    &frame.payload,
                                    config.max_message_bytes,
                                ) {
                                    writer.send_close(1009, reason).await;
                                    end = SessionEnd::Failed {
                                        error: reason.into(),
                                        blocked: false,
                                    };
                                    break;
                                }
                                let captured = capture_frame(
                                    frame_ids, connection_id, WebSocketDirection::ServerToClient,
                                    opcode, frame.fin, false, frame.payload, config.capture_bytes,
                                );
                                connection.frames += 1;
                                connection.bytes_server_to_client += captured.payload_len as u64;
                                let _ = events.send(AppEvent::WebSocketFrame(Box::new(captured)));
                            }
                        }
                    }
                    Some(Err(error)) => {
                        end = SessionEnd::Failed { error: error.to_string(), blocked: false };
                        break;
                    }
                    None => {
                        end = SessionEnd::Closed("upstream closed the session".into());
                        break;
                    }
                }
            }
            _ = &mut idle => {
                writer.send_close(1001, "idle timeout").await;
                end = SessionEnd::Closed("idle timeout".into());
                break;
            }
        }
    }

    reader_task.abort();
    connection.state = match &end {
        SessionEnd::Closed(_) => WebSocketConnectionState::Closed,
        SessionEnd::Failed { .. } => WebSocketConnectionState::Failed,
    };
    connection.closed_at = Some(Utc::now());
    if let SessionEnd::Failed { error, .. } = &end {
        connection.error = Some(error.clone());
    }
    let _ = events.send(AppEvent::WebSocketConnection(Box::new(connection)));
    if let SessionEnd::Closed(reason) = &end {
        let _ = events.send(AppEvent::WebSocketRepeater(
            WebSocketRepeaterEvent::Closed {
                session,
                reason: reason.clone(),
            },
        ));
    }
    Ok(end)
}

#[allow(clippy::too_many_arguments)]
fn capture_frame(
    frame_ids: &Arc<std::sync::atomic::AtomicU64>,
    connection_id: rawframe_core::models::websocket::WebSocketConnectionId,
    direction: WebSocketDirection,
    opcode: WebSocketOpcode,
    fin: bool,
    masked: bool,
    payload: Vec<u8>,
    capture_bytes: usize,
) -> WebSocketFrame {
    let payload_len = payload.len();
    let truncated = payload_len > capture_bytes;
    let stored = if truncated {
        payload[..capture_bytes].to_vec()
    } else {
        payload
    };
    let mut frame = WebSocketFrame::new(
        WebSocketFrameId(frame_ids.fetch_add(1, std::sync::atomic::Ordering::Relaxed)),
        connection_id,
        direction,
        opcode,
        fin,
        masked,
        stored,
        truncated,
    );
    frame.payload_len = payload_len;
    frame.interception = WebSocketInterceptionOutcome::Forwarded;
    frame
}

/// Tracks fragmented messages only to enforce the size ceiling and validate
/// completed text payloads. Individual frames are still captured and emitted.
#[derive(Default)]
struct Fragment {
    opcode: Option<WebSocketOpcode>,
    bytes: Vec<u8>,
}

impl Fragment {
    fn accept(
        &mut self,
        opcode: WebSocketOpcode,
        fin: bool,
        payload: &[u8],
        max_message_bytes: usize,
    ) -> Result<(), &'static str> {
        match opcode {
            WebSocketOpcode::Continuation => {
                let Some(start) = self.opcode else {
                    return Err("continuation frame without a started message");
                };
                if self.bytes.len() + payload.len() > max_message_bytes {
                    return Err("reassembled message exceeds the configured limit");
                }
                self.bytes.extend_from_slice(payload);
                if fin {
                    if start == WebSocketOpcode::Text && std::str::from_utf8(&self.bytes).is_err() {
                        return Err("completed text message is not valid UTF-8");
                    }
                    self.opcode = None;
                    self.bytes.clear();
                }
            }
            WebSocketOpcode::Text | WebSocketOpcode::Binary => {
                if self.opcode.is_some() {
                    return Err("new data frame before the fragmented message completed");
                }
                if payload.len() > max_message_bytes {
                    return Err("message exceeds the configured limit");
                }
                if fin {
                    if opcode == WebSocketOpcode::Text && std::str::from_utf8(payload).is_err() {
                        return Err("text message is not valid UTF-8");
                    }
                } else {
                    self.opcode = Some(opcode);
                    self.bytes = payload.to_vec();
                }
            }
            WebSocketOpcode::Close | WebSocketOpcode::Ping | WebSocketOpcode::Pong => {}
            WebSocketOpcode::Unknown(_) => return Err("unknown data opcode"),
        }
        Ok(())
    }
}
