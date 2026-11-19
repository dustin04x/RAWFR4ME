//! HTTP/1.1 WebSocket handshake and frame-level relay.
//!
//! RAWFRAME terminates the client handshake at the proxy, performs its own
//! handshake with the upstream, and then relays individual RFC 6455 frames.
//! Because frames — not messages — cross the relay boundary, every frame can be
//! captured, paused, modified, dropped, or cancelled independently in both
//! directions.
//!
//! Only traditional `Upgrade: websocket` handshakes are accepted. RFC 8441
//! extended CONNECT over HTTP/2 is not advertised: RAWFRAME does not bridge an
//! HTTP/2 stream into the WebSocket relay, so claiming support would be unsafe.
//! Compression extensions are not negotiated, so no reserved bits are expected.

pub mod client;
mod frame;
mod intercept;

pub(crate) use intercept::WebSocketInterceptor;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::Utc;
use http_body_util::BodyExt;
use hyper::header::{CONNECTION, UPGRADE};
use hyper::upgrade::{OnUpgrade, Upgraded};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rawframe_core::models::message::Scheme;
use rawframe_core::models::traffic::{
    InterceptionMetadata, TrafficEntry, TrafficKind, TrafficSource, TrafficState, TrafficTimings,
};
use rawframe_core::models::websocket::{
    WebSocketConnection, WebSocketConnectionId, WebSocketConnectionState, WebSocketDirection,
    WebSocketFrame, WebSocketFrameDecision, WebSocketFrameId, WebSocketInterceptionOutcome,
    WebSocketMessage, WebSocketMessageId, WebSocketOpcode,
};
use rawframe_core::models::{HttpRequest, HttpResponse};
use rawframe_core::{AppEvent, EventSender};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::watch;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;

use crate::body::ProxyBody;
use crate::destination::Destination;
use crate::service::ServiceContext;
use crate::tls::intercept::{
    build_upstream_tls_config_with_trust_file, upstream_connector, upstream_server_name,
};

use self::frame::{FrameError, close_frame, mask_key, read_frame, write_frame};

/// Relay streams are boxed so plain TCP and TLS share one connection path.
trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}

const MAX_HANDSHAKE_HEAD_BYTES: usize = 16 * 1024;
const CLOSE_GRACE: Duration = Duration::from_secs(2);

pub(crate) async fn handle(
    mut request: Request<hyper::body::Incoming>,
    context: ServiceContext,
    destination: Destination,
    id: u64,
    captured_request: HttpRequest,
    started_at: chrono::DateTime<Utc>,
    started: Instant,
) -> Response<ProxyBody> {
    let configuration = context.config.proxy.clone();

    // ---- validate the client handshake ------------------------------------
    let Some(key_header) = request.headers().get("Sec-WebSocket-Key") else {
        return error_response(StatusCode::BAD_REQUEST, "missing Sec-WebSocket-Key");
    };
    let Ok(key) = key_header.to_str() else {
        return error_response(StatusCode::BAD_REQUEST, "invalid Sec-WebSocket-Key");
    };
    let accept = derive_accept_key(key.as_bytes());

    let version = request
        .headers()
        .get("Sec-WebSocket-Version")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if version != "13" {
        return error_response(StatusCode::BAD_REQUEST, "unsupported Sec-WebSocket-Version");
    }

    let offered_protocols: Vec<String> = request
        .headers()
        .get_all("Sec-WebSocket-Protocol")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|token| token.trim().to_string())
        .filter(|token| !token.is_empty())
        .collect();

    if !destination.is_permitted(&context.scope_snapshot()) {
        let rejection = destination.scope_rejection();
        return error_response(rejection.status, rejection.message);
    }

    // ---- bound concurrent WebSocket connections ---------------------------
    let Ok(permit) = context.websocket_slots.clone().try_acquire_owned() else {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "WebSocket connection limit reached",
        );
    };

    let connect_timeout = Duration::from_secs(configuration.connect_timeout_secs);
    let allow_private = configuration.allow_private_upstreams;

    // ---- connect upstream (TCP, plus TLS for wss://) ----------------------
    let tcp =
        match crate::destination::connect_upstream(&destination, allow_private, connect_timeout)
            .await
        {
            Ok(stream) => stream,
            Err(rejection) => return error_response(rejection.status, rejection.message),
        };

    let upstream_stream: Box<dyn AsyncStream> = if destination.scheme == Scheme::Https {
        let tls_config = match build_upstream_tls_config_with_trust_file(
            configuration.tls_upstream_trust_file.as_deref(),
        ) {
            Ok(config) => config,
            Err(error) => {
                return error_response(StatusCode::BAD_GATEWAY, error.to_string());
            }
        };
        let connector = upstream_connector(Arc::new(tls_config));
        let server_name = match upstream_server_name(&destination.host) {
            Ok(name) => name,
            Err(error) => {
                return error_response(StatusCode::BAD_GATEWAY, error.to_string());
            }
        };
        match timeout(connect_timeout, connector.connect(server_name, tcp)).await {
            Ok(Ok(stream)) => Box::new(stream),
            Ok(Err(error)) => {
                return error_response(
                    StatusCode::BAD_GATEWAY,
                    format!("upstream TLS handshake failed: {error}"),
                );
            }
            Err(_) => {
                return error_response(
                    StatusCode::GATEWAY_TIMEOUT,
                    "upstream TLS handshake timed out",
                );
            }
        }
    } else {
        Box::new(tcp)
    };

    // ---- upstream WebSocket handshake -------------------------------------
    let authority = if destination.port == destination.scheme.default_port() {
        destination.host.clone()
    } else {
        format!("{}:{}", destination.host, destination.port)
    };
    let target = if destination.target.is_empty() {
        "/"
    } else {
        destination.target.as_str()
    };
    let mut head = String::with_capacity(512);
    head.push_str(&format!("GET {target} HTTP/1.1\r\n"));
    head.push_str(&format!("Host: {authority}\r\n"));
    head.push_str("Upgrade: websocket\r\nConnection: Upgrade\r\n");
    head.push_str(&format!("Sec-WebSocket-Key: {key}\r\n"));
    head.push_str("Sec-WebSocket-Version: 13\r\n");
    for header in captured_request.headers.iter() {
        let lower = header.name.to_ascii_lowercase();
        // Hop-by-hop and handshake headers are regenerated. Compression is not
        // negotiated so no reserved frame bits can appear unexpectedly.
        if matches!(
            lower.as_str(),
            "host"
                | "upgrade"
                | "connection"
                | "sec-websocket-key"
                | "sec-websocket-version"
                | "sec-websocket-extensions"
                | "proxy-connection"
                | "proxy-authorization"
                | "content-length"
                | "transfer-encoding"
                | "te"
        ) {
            continue;
        }
        head.push_str(&format!("{}: {}\r\n", header.name, header.value));
    }
    head.push_str("\r\n");

    let mut upstream_stream = upstream_stream;
    if let Err(error) = upstream_stream.write_all(head.as_bytes()).await {
        return error_response(
            StatusCode::BAD_GATEWAY,
            format!("upstream WebSocket request failed: {error}"),
        );
    }
    if let Err(error) = upstream_stream.flush().await {
        return error_response(
            StatusCode::BAD_GATEWAY,
            format!("upstream WebSocket request failed: {error}"),
        );
    }

    let upstream_head =
        match timeout(connect_timeout, read_handshake_head(&mut upstream_stream)).await {
            Ok(Ok(head)) => head,
            Ok(Err(error)) => {
                return error_response(
                    StatusCode::BAD_GATEWAY,
                    format!("upstream WebSocket handshake failed: {error}"),
                );
            }
            Err(_) => {
                return error_response(
                    StatusCode::GATEWAY_TIMEOUT,
                    "upstream WebSocket handshake timed out",
                );
            }
        };

    let response_head = match parse_response_head(&upstream_head) {
        Ok(head) => head,
        Err(reason) => {
            return error_response(
                StatusCode::BAD_GATEWAY,
                format!("invalid upstream WebSocket response: {reason}"),
            );
        }
    };
    if response_head.status != 101 {
        return error_response(
            StatusCode::BAD_GATEWAY,
            format!(
                "upstream did not switch protocols: {} {}",
                response_head.status, response_head.reason
            ),
        );
    }
    if !header_contains_token(&response_head, "upgrade", "websocket")
        || !header_contains_token(&response_head, "connection", "upgrade")
    {
        return error_response(
            StatusCode::BAD_GATEWAY,
            "upstream 101 response is missing WebSocket upgrade headers",
        );
    }
    let upstream_accept = header_value(&response_head, "sec-websocket-accept").unwrap_or("");
    if upstream_accept != accept {
        return error_response(
            StatusCode::BAD_GATEWAY,
            "upstream Sec-WebSocket-Accept did not match the client key",
        );
    }
    let selected_protocol =
        header_value(&response_head, "sec-websocket-protocol").map(str::to_string);
    if let Some(protocol) = &selected_protocol
        && !offered_protocols.iter().any(|offered| offered == protocol)
    {
        return error_response(
            StatusCode::BAD_GATEWAY,
            "upstream selected a subprotocol the client did not offer",
        );
    }

    // ---- attribute ids and capture the handshake --------------------------
    let connection_id = WebSocketConnectionId(next_ws_id(&context));
    let mut connection = WebSocketConnection {
        id: connection_id,
        source: TrafficSource::Intercepted,
        host: destination.host.clone(),
        port: destination.port,
        path: target.to_string(),
        tls: destination.scheme == Scheme::Https,
        subprotocol: selected_protocol.clone(),
        extensions: None,
        state: WebSocketConnectionState::Open,
        started_at,
        closed_at: None,
        frames: 0,
        messages: 0,
        bytes_client_to_server: 0,
        bytes_server_to_client: 0,
        error: None,
    };

    let mut http_response = HttpResponse::new(101);
    for header in &response_head.headers {
        if header.0.eq_ignore_ascii_case("sec-websocket-extensions") {
            continue;
        }
        http_response
            .headers
            .append(header.0.clone(), header.1.clone());
    }
    if !http_response
        .headers
        .iter()
        .any(|header| header.name.eq_ignore_ascii_case("Sec-WebSocket-Accept"))
    {
        http_response
            .headers
            .append("Sec-WebSocket-Accept", accept.clone());
    }

    let mut request_entry = captured_request;
    request_entry.version = "WebSocket".to_string();
    let mut timings = TrafficTimings::starting_at(started_at);
    timings.finish(started.elapsed().as_millis() as u64);
    let traffic_entry = TrafficEntry {
        id: rawframe_core::TrafficId(id),
        request: request_entry,
        response: Some(http_response),
        state: TrafficState::Completed,
        source: TrafficSource::Intercepted,
        timings,
        error: None,
        note: Some(format!("WebSocket connection #{} opened", connection_id.0)),
        kind: TrafficKind::WebSocket,
        tunnel: None,
        original_request: None,
        final_request: None,
        interception: InterceptionMetadata::default(),
        body_omitted: false,
        redacted_headers: 0,
        repeater_origin: None,
        intruder_payloads: None,
        intruder_origin: None,
    };
    let _ = context
        .events
        .send_async(AppEvent::TrafficCaptured(Box::new(traffic_entry)))
        .await;
    let _ = context
        .events
        .send_async(AppEvent::WebSocketConnection(Box::new(connection.clone())))
        .await;

    // ---- respond to the client --------------------------------------------
    let mut builder = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(UPGRADE, "websocket")
        .header(CONNECTION, "Upgrade")
        .header("Sec-WebSocket-Accept", accept.as_str());
    if let Some(protocol) = &selected_protocol {
        builder = builder.header("Sec-WebSocket-Protocol", protocol.as_str());
    }

    let on_upgrade = match request.extensions_mut().remove::<OnUpgrade>() {
        Some(upgrade) => upgrade,
        None => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "WebSocket upgrade is unavailable on this connection",
            );
        }
    };

    let empty: ProxyBody = http_body_util::Empty::new()
        .map_err(|never| match never {})
        .boxed();
    let response = match builder.body(empty) {
        Ok(response) => response,
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to build 101 response",
            );
        }
    };

    // ---- relay frames in one bounded task per connection ------------------
    let events = context.events.clone();
    let interceptor = context.websockets.clone();
    let ws_ids = context.ws_ids.clone();
    let max_frame = configuration.websocket_max_frame_bytes;
    let max_message = configuration.websocket_max_message_bytes;
    let capture_limit = configuration.websocket_capture_bytes;
    let idle = Duration::from_secs(configuration.websocket_idle_timeout_secs);
    let mut shutdown = context.shutdown.clone();
    let tracker = context.tracker.clone();

    tracker.spawn(async move {
        let upgraded: Upgraded = match on_upgrade.await {
            Ok(upgraded) => upgraded,
            Err(_) => {
                connection.state = WebSocketConnectionState::Failed;
                connection.error = Some("client upgrade was not completed".into());
                connection.closed_at = Some(Utc::now());
                let _ = events
                    .send_async(AppEvent::WebSocketConnection(Box::new(connection)))
                    .await;
                return;
            }
        };
        drop(permit);

        let client_stream: Box<dyn AsyncStream> = Box::new(TokioIo::new(upgraded));
        let connection = Arc::new(Mutex::new(connection));
        let (closed_tx, closed_rx) = watch::channel(false);
        let (close_tx, close_rx) = watch::channel::<Option<(u16, String)>>(None);

        let params = RelayParams {
            events: events.clone(),
            interceptor,
            ws_ids,
            connection: connection.clone(),
            connection_id,
            max_frame,
            max_message,
            capture_limit,
            idle,
            shutdown: shutdown.clone(),
            closed: closed_tx.clone(),
            close_to_client: close_tx.clone(),
        };

        let (client_read, client_write) = tokio::io::split(client_stream);
        let (upstream_read, upstream_write) = tokio::io::split(upstream_stream);

        let mut client_task = tokio::spawn(relay(
            client_read,
            upstream_write,
            params.direction(WebSocketDirection::ClientToServer, true),
            closed_rx.clone(),
            close_rx.clone(),
        ));
        let mut upstream_task = tokio::spawn(relay(
            upstream_read,
            client_write,
            params.direction(WebSocketDirection::ServerToClient, false),
            closed_rx,
            close_rx,
        ));

        let end = tokio::select! {
            result = &mut client_task => Some(result),
            result = &mut upstream_task => Some(result),
            _ = shutdown.changed() => None,
        };
        let mut error = None;
        if let Some(Ok(Err(reason))) = end {
            error = Some(reason);
        }
        let _ = closed_tx.send(true);
        // A JoinHandle that already completed must not be polled again.
        if !client_task.is_finished() {
            let _ = timeout(CLOSE_GRACE, &mut client_task).await;
        }
        if !upstream_task.is_finished() {
            let _ = timeout(CLOSE_GRACE, &mut upstream_task).await;
        }
        client_task.abort();
        upstream_task.abort();

        let snapshot = {
            let mut guard = connection
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            guard.state = if error.is_some() {
                WebSocketConnectionState::Failed
            } else {
                WebSocketConnectionState::Closed
            };
            guard.error = error;
            guard.closed_at = Some(Utc::now());
            guard.clone()
        };
        let _ = events
            .send_async(AppEvent::WebSocketConnection(Box::new(snapshot)))
            .await;
    });

    response
}

fn next_ws_id(context: &ServiceContext) -> u64 {
    context.ws_ids.fetch_add(1, Ordering::Relaxed)
}

#[derive(Clone)]
struct RelayParams {
    events: EventSender,
    interceptor: WebSocketInterceptor,
    ws_ids: Arc<AtomicU64>,
    connection: Arc<Mutex<WebSocketConnection>>,
    connection_id: WebSocketConnectionId,
    max_frame: usize,
    max_message: usize,
    capture_limit: usize,
    idle: Duration,
    shutdown: watch::Receiver<bool>,
    closed: watch::Sender<bool>,
    /// Protocol closes that must be delivered to the client writer, which is
    /// owned by the opposite direction's task.
    close_to_client: watch::Sender<Option<(u16, String)>>,
}

impl RelayParams {
    fn direction(&self, direction: WebSocketDirection, mask: bool) -> DirectionParams {
        DirectionParams {
            base: self.clone(),
            direction,
            mask,
            writer_is_client: direction == WebSocketDirection::ServerToClient,
        }
    }
}

struct DirectionParams {
    base: RelayParams,
    direction: WebSocketDirection,
    mask: bool,
    writer_is_client: bool,
}

/// A completed data message assembled from one or more frames.
struct AssembledMessage {
    opcode: WebSocketOpcode,
    frame_ids: Vec<WebSocketFrameId>,
    payload: Vec<u8>,
    total: usize,
    truncated: bool,
}

/// Reassembles fragmented data messages with a hard size ceiling.
#[derive(Default)]
struct Assembler {
    opcode: Option<WebSocketOpcode>,
    frame_ids: Vec<WebSocketFrameId>,
    payload: Vec<u8>,
    total: usize,
    truncated: bool,
}

impl Assembler {
    /// Adds a captured frame payload. `payload` is already truncated to the
    /// capture limit; `full_len` keeps the true message size visible.
    fn push(
        &mut self,
        opcode: WebSocketOpcode,
        fin: bool,
        frame_id: WebSocketFrameId,
        payload: &[u8],
        full_len: usize,
        limit: usize,
    ) -> Option<AssembledMessage> {
        let started = match opcode {
            WebSocketOpcode::Continuation => self.opcode.is_some(),
            WebSocketOpcode::Text | WebSocketOpcode::Binary => self.opcode.is_none(),
            _ => return None,
        };
        if !started {
            return None;
        }
        if self.opcode.is_none() {
            self.opcode = Some(opcode);
        }
        self.frame_ids.push(frame_id);
        self.total = self.total.saturating_add(full_len);
        if self.payload.len() < limit {
            let room = limit - self.payload.len();
            self.payload
                .extend_from_slice(&payload[..payload.len().min(room)]);
        }
        if self.total > limit || payload.len() < full_len {
            self.truncated = true;
        }
        if !fin {
            return None;
        }
        let opcode = self.opcode.take()?;
        let frame_ids = std::mem::take(&mut self.frame_ids);
        let payload = std::mem::take(&mut self.payload);
        let total = self.total;
        let truncated = self.truncated;
        *self = Self::default();
        Some(AssembledMessage {
            opcode,
            frame_ids,
            payload,
            total,
            truncated,
        })
    }
}

/// Relays one direction until the peer closes, a protocol error occurs, the
/// connection is cancelled, or the idle timeout elapses.
async fn relay<R, W>(
    mut reader: R,
    mut writer: W,
    params: DirectionParams,
    mut closed: watch::Receiver<bool>,
    mut close_to_client: watch::Receiver<Option<(u16, String)>>,
) -> Result<(), String>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let base = &params.base;
    let mut shutdown = base.shutdown.clone();
    let mut assembler = Assembler::default();
    let mut close_sent = false;
    let mut last_error: Option<String> = None;

    loop {
        if *closed.borrow() {
            break;
        }

        let read = tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            _ = close_to_client.changed() => {
                let pending = {
                    let value = close_to_client.borrow();
                    value.clone()
                };
                if params.writer_is_client
                    && let Some((code, reason)) = pending
                {
                    let _ = write_frame(&mut writer, &close_frame(code, &reason), None).await;
                }
                break;
            }
            _ = closed.changed() => break,
            result = timeout(base.idle, read_frame(&mut reader, base.max_frame, params.mask)) => result,
        };

        let frame = match read {
            Err(_) => {
                last_error = Some("WebSocket idle timeout".into());
                let _ = base
                    .close_to_client
                    .send(Some((1001, "idle timeout".into())));
                break;
            }
            Ok(Err(FrameError::Closed)) => break,
            Ok(Err(FrameError::Protocol(reason))) => {
                last_error = Some(reason.to_string());
                let _ = base.close_to_client.send(Some((1002, reason.to_string())));
                if params.writer_is_client {
                    let close = close_frame(1002, reason);
                    let _ = write_frame(&mut writer, &close, None).await;
                }
                close_sent = true;
                break;
            }
            Ok(Err(FrameError::TooLarge { len, max })) => {
                // Consume a bounded prefix of the refused payload. Closing a
                // socket that still has unread bytes causes a TCP reset, which
                // would discard the close frame we are about to send.
                let mut remaining = len.min(1024 * 1024);
                let mut sink = [0u8; 8192];
                while remaining > 0 {
                    let take = remaining.min(sink.len());
                    match timeout(Duration::from_millis(500), reader.read(&mut sink[..take])).await
                    {
                        Ok(Ok(0)) | Err(_) => break,
                        Ok(Ok(read)) => remaining = remaining.saturating_sub(read),
                        Ok(Err(_)) => break,
                    }
                }
                last_error = Some(format!("frame of {len} bytes exceeds the {max} byte limit"));
                let _ = base
                    .close_to_client
                    .send(Some((1009, "frame too large".into())));
                if params.writer_is_client {
                    let close = close_frame(1009, "frame too large");
                    let _ = write_frame(&mut writer, &close, None).await;
                }
                close_sent = true;
                break;
            }
            Ok(Err(FrameError::Io(error))) => {
                last_error = Some(format!("stream error: {error}"));
                break;
            }
            Ok(Ok(frame)) => frame,
        };

        let frame_id = WebSocketFrameId(base.ws_ids.fetch_add(1, Ordering::Relaxed));
        let full_len = frame.payload.len();
        let captured = &frame.payload[..full_len.min(base.capture_limit)];
        let mut record = WebSocketFrame::new(
            frame_id,
            base.connection_id,
            params.direction,
            frame.opcode,
            frame.fin,
            frame.masked,
            captured.to_vec(),
            captured.len() < full_len,
        );
        record.rsv1 = frame.rsv1;
        let _ = base
            .events
            .send_async(AppEvent::WebSocketFrame(Box::new(record.clone())))
            .await;

        // Control and data frames are both reviewable. A camera-style relay
        // forwards unchanged unless the operator decides otherwise.
        let pause = base.interceptor.pause(&record).await;
        if pause.outcome != WebSocketInterceptionOutcome::Forwarded {
            record.interception = pause.outcome;
            let _ = base
                .events
                .send_async(AppEvent::WebSocketFrame(Box::new(record.clone())))
                .await;
        }
        if pause.terminal {
            last_error = Some(format!("frame #{frame_id:?} {}", pause.outcome.label()));
            let _ = base
                .close_to_client
                .send(Some((1001, "interception cancelled".into())));
            if params.writer_is_client {
                let close = close_frame(1001, "interception cancelled");
                let _ = write_frame(&mut writer, &close, None).await;
            }
            close_sent = true;
            break;
        }
        if pause.decision == WebSocketFrameDecision::Drop {
            continue;
        }

        let mut outgoing = frame.clone();
        if let WebSocketFrameDecision::ForwardModified { payload } = &pause.decision {
            if outgoing.opcode.is_control() && payload.len() > self::frame::MAX_CONTROL_PAYLOAD {
                last_error = Some("modified control frame exceeds 125 bytes".into());
                let close = close_frame(1002, "invalid control frame");
                let _ = write_frame(&mut writer, &close, None).await;
                close_sent = true;
                break;
            }
            outgoing.payload = payload.clone();
        }

        {
            let mut connection = base
                .connection
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            connection.frames += 1;
            match params.direction {
                WebSocketDirection::ClientToServer => {
                    connection.bytes_client_to_server += full_len as u64
                }
                WebSocketDirection::ServerToClient => {
                    connection.bytes_server_to_client += full_len as u64
                }
            }
        }

        let mask = if params.mask {
            Some(mask_key(frame_id.0))
        } else {
            None
        };
        if let Err(error) = write_frame(&mut writer, &outgoing, mask).await {
            last_error = Some(format!("failed to forward frame: {error}"));
            break;
        }
        if outgoing.opcode.is_control() {
            if outgoing.opcode == WebSocketOpcode::Close {
                close_sent = true;
                break;
            }
        } else if let Some(message) = assembler.push(
            outgoing.opcode,
            outgoing.fin,
            frame_id,
            &outgoing.payload[..outgoing.payload.len().min(base.capture_limit)],
            outgoing.payload.len(),
            base.max_message,
        ) {
            let message = WebSocketMessage::new(
                WebSocketMessageId(base.ws_ids.fetch_add(1, Ordering::Relaxed)),
                base.connection_id,
                params.direction,
                message.opcode,
                message.payload,
                message.frame_ids,
                message.total,
                message.truncated,
                true,
            );
            {
                let mut connection = base
                    .connection
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                connection.messages += 1;
            }
            let _ = base
                .events
                .send_async(AppEvent::WebSocketMessage(Box::new(message)))
                .await;
        }
    }

    if !close_sent {
        let pending = {
            let value = base.close_to_client.borrow();
            value.clone()
        };
        match pending {
            Some((code, reason)) if params.writer_is_client => {
                let _ = write_frame(&mut writer, &close_frame(code, &reason), None).await;
            }
            Some(_) => {}
            None => {
                let _ = write_frame(&mut writer, &close_frame(1000, ""), None).await;
            }
        }
    }
    let _ = base.closed.send(true);
    match last_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// Handshake parsing
// ---------------------------------------------------------------------------

struct ResponseHead {
    status: u16,
    reason: String,
    headers: Vec<(String, String)>,
}

fn header_value<'a>(head: &'a ResponseHead, name: &str) -> Option<&'a str> {
    head.headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn header_contains_token(head: &ResponseHead, name: &str, token: &str) -> bool {
    head.headers
        .iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case(name))
        .any(|(_, value)| {
            value
                .split(',')
                .any(|candidate| candidate.trim().eq_ignore_ascii_case(token))
        })
}

async fn read_handshake_head<S>(stream: &mut S) -> std::io::Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut head = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    loop {
        let read = stream.read(&mut byte).await?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "upstream closed during handshake",
            ));
        }
        head.push(byte[0]);
        if head.len() >= MAX_HANDSHAKE_HEAD_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "upstream handshake head exceeds the limit",
            ));
        }
        if head.ends_with(b"\r\n\r\n") {
            return Ok(head);
        }
    }
}

fn parse_response_head(bytes: &[u8]) -> Result<ResponseHead, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "response head is not UTF-8".to_string())?;
    let mut lines = text.split("\r\n");
    let status_line = lines.next().ok_or("empty response")?;
    let mut parts = status_line.splitn(3, ' ');
    let protocol = parts.next().unwrap_or("");
    if !protocol.starts_with("HTTP/1.") {
        return Err("unsupported upstream protocol".into());
    }
    let status: u16 = parts
        .next()
        .ok_or("missing status code")?
        .parse()
        .map_err(|_| "invalid status code".to_string())?;
    let reason = parts.next().unwrap_or("").to_string();
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| "malformed header".to_string())?;
        headers.push((name.trim().to_string(), value.trim().to_string()));
    }
    Ok(ResponseHead {
        status,
        reason,
        headers,
    })
}

pub(crate) fn is_websocket_upgrade(request: &Request<hyper::body::Incoming>) -> bool {
    if request.method() != hyper::Method::GET {
        return false;
    }
    let upgrade = request
        .headers()
        .get(hyper::header::UPGRADE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);
    let connection = request
        .headers()
        .get(hyper::header::CONNECTION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let connection_ok = connection
        .split(',')
        .any(|token| token.trim().eq_ignore_ascii_case("upgrade"));
    let has_key = request.headers().contains_key("Sec-WebSocket-Key");
    let version_ok = request
        .headers()
        .get("Sec-WebSocket-Version")
        .and_then(|value| value.to_str().ok())
        == Some("13");
    upgrade && connection_ok && has_key && version_ok
}

fn error_response(status: StatusCode, message: impl Into<String>) -> Response<ProxyBody> {
    let body: ProxyBody = http_body_util::Full::new(bytes::Bytes::from(message.into()))
        .map_err(|never| match never {})
        .boxed();
    Response::builder()
        .status(status)
        .body(body)
        .unwrap_or_else(|_| {
            Response::new(
                http_body_util::Full::new(bytes::Bytes::new())
                    .map_err(|never| match never {})
                    .boxed(),
            )
        })
}
