//! HTTP/1.1 WebSocket handshake and bidirectional frame relay.
//!
//! Only traditional `Upgrade: websocket` handshakes are supported. RFC 8441
//! extended CONNECT over HTTP/2 is intentionally not advertised: Hyper can
//! negotiate `SETTINGS_ENABLE_CONNECT_PROTOCOL`, but RAWFRAME does not yet
//! bridge a WebSocket over an HTTP/2 stream end to end.

use std::time::{Duration, Instant};

use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use hyper::header::{CONNECTION, UPGRADE};
use hyper::upgrade::OnUpgrade;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rawframe_core::AppEvent;
use rawframe_core::models::traffic::{TrafficEntry, TrafficKind, TrafficState, TrafficTimings};
use rawframe_core::models::{HttpRequest, HttpResponse};
use tokio::time::timeout;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::Role;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

use crate::destination::Destination;
use crate::tls::intercept::{
    build_upstream_tls_config_with_trust_file, upstream_connector, upstream_server_name,
};

pub(crate) async fn handle(
    mut request: Request<hyper::body::Incoming>,
    context: crate::service::ServiceContext,
    destination: Destination,
    id: u64,
    captured_request: HttpRequest,
    started_at: chrono::DateTime<Utc>,
    started: Instant,
) -> Response<crate::body::ProxyBody> {
    use crate::body::ProxyBody;
    use http_body_util::{BodyExt, Empty};

    // ---- validate handshake headers ---------------------------------------
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
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if version != "13" {
        return error_response(StatusCode::BAD_REQUEST, "unsupported Sec-WebSocket-Version");
    }

    if !destination.is_permitted(&context.scope_snapshot()) {
        let rejection = destination.scope_rejection();
        return error_response(rejection.status, rejection.message);
    }

    let connect_timeout = Duration::from_secs(context.config.proxy.connect_timeout_secs);
    let allow_private = context.config.proxy.allow_private_upstreams;

    // ---- connect upstream (TCP, plus TLS for wss://) ----------------------
    let tcp =
        match crate::destination::connect_upstream(&destination, allow_private, connect_timeout)
            .await
        {
            Ok(stream) => stream,
            Err(rejection) => {
                return error_response(rejection.status, rejection.message);
            }
        };

    let upstream_stream = if destination.scheme == rawframe_core::models::message::Scheme::Https {
        let tls_config = match build_upstream_tls_config_with_trust_file(
            context.config.proxy.tls_upstream_trust_file.as_deref(),
        ) {
            Ok(config) => config,
            Err(error) => {
                return error_response(StatusCode::BAD_GATEWAY, error.to_string());
            }
        };
        let connector = upstream_connector(std::sync::Arc::new(tls_config));
        let server_name = match upstream_server_name(&destination.host) {
            Ok(name) => name,
            Err(error) => {
                return error_response(StatusCode::BAD_GATEWAY, error.to_string());
            }
        };
        match timeout(connect_timeout, connector.connect(server_name, tcp)).await {
            Ok(Ok(stream)) => tokio_util::either::Either::Right(stream),
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
        tokio_util::either::Either::Left(tcp)
    };

    // ---- upstream WebSocket handshake -------------------------------------
    let scheme = if destination.scheme == rawframe_core::models::message::Scheme::Https {
        "wss"
    } else {
        "ws"
    };
    let authority = if destination.port == destination.scheme.default_port() {
        destination.host.clone()
    } else {
        format!("{}:{}", destination.host, destination.port)
    };
    let uri = format!(
        "{}://{}{}",
        scheme,
        authority,
        if destination.target.is_empty() {
            "/"
        } else {
            &destination.target
        }
    );

    let mut upstream_request = hyper::Request::builder()
        .method("GET")
        .uri(uri.as_str())
        .header("Host", authority.as_str())
        .header("Upgrade", "websocket")
        .header("Connection", "Upgrade")
        .header("Sec-WebSocket-Key", key)
        .header("Sec-WebSocket-Version", "13");

    // Forward the remaining handshake headers (subprotocol, extensions, origin, cookies).
    for header in captured_request.headers.iter() {
        let name = header.name.as_str();
        let lower = name.to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "host" | "upgrade" | "connection" | "sec-websocket-key" | "sec-websocket-version"
        ) {
            continue;
        }
        if let Ok(value) = hyper::header::HeaderValue::from_str(&header.value) {
            upstream_request = upstream_request.header(name, value);
        }
    }

    let upstream_request = match upstream_request.body(()) {
        Ok(request) => request,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid upstream WebSocket request",
            );
        }
    };

    let mut ws_config = WebSocketConfig::default();
    ws_config.max_message_size = Some(2 * 1024 * 1024);
    ws_config.max_frame_size = Some(2 * 1024 * 1024);

    let (mut upstream_ws, upstream_response) =
        match tokio_tungstenite::client_async(upstream_request, upstream_stream).await {
            Ok(result) => result,
            Err(error) => {
                return error_response(
                    StatusCode::BAD_GATEWAY,
                    format!("upstream WebSocket handshake failed: {error}"),
                );
            }
        };

    if upstream_response.status() != StatusCode::SWITCHING_PROTOCOLS {
        return error_response(
            StatusCode::BAD_GATEWAY,
            format!(
                "upstream did not switch protocols: {}",
                upstream_response.status()
            ),
        );
    }

    // ---- capture the handshake --------------------------------------------
    let mut http_response = HttpResponse::new(101);
    for (name, value) in upstream_response.headers().iter() {
        http_response
            .headers
            .append(name.as_str(), value.to_str().unwrap_or("").to_string());
    }
    // Ensure the client sees the computed accept key even if the upstream omitted it.
    if !http_response
        .headers
        .iter()
        .any(|h| h.name.eq_ignore_ascii_case("Sec-WebSocket-Accept"))
    {
        http_response
            .headers
            .append("Sec-WebSocket-Accept", accept.clone());
    }

    let mut entry = captured_request;
    entry.version = "WebSocket".to_string();
    let mut timings = TrafficTimings::starting_at(started_at);
    timings.finish(started.elapsed().as_millis() as u64);
    let traffic_entry = TrafficEntry {
        id: rawframe_core::TrafficId(id),
        request: entry,
        response: Some(http_response.clone()),
        state: TrafficState::Completed,
        source: rawframe_core::models::traffic::TrafficSource::Intercepted,
        timings,
        error: None,
        note: Some("WebSocket handshake completed".to_string()),
        kind: TrafficKind::WebSocket,
        tunnel: None,
        original_request: None,
        final_request: None,
        interception: rawframe_core::models::traffic::InterceptionMetadata::default(),
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

    // ---- respond to the client --------------------------------------------
    let mut builder = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(UPGRADE, "websocket")
        .header(CONNECTION, "Upgrade")
        .header("Sec-WebSocket-Accept", accept.as_str());

    if let Some(value) = upstream_response
        .headers()
        .get("Sec-WebSocket-Protocol")
        .and_then(|v| v.to_str().ok())
    {
        builder = builder.header("Sec-WebSocket-Protocol", value);
    }
    if let Some(value) = upstream_response
        .headers()
        .get("Sec-WebSocket-Extensions")
        .and_then(|v| v.to_str().ok())
    {
        builder = builder.header("Sec-WebSocket-Extensions", value);
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

    let empty: ProxyBody = Empty::new().map_err(|never| match never {}).boxed();
    let response = match builder.body(empty) {
        Ok(response) => response,
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to build 101 response",
            );
        }
    };

    // ---- relay frames in a background task --------------------------------
    let tracker = context.tracker.clone();
    let context = context.clone();
    let host = destination.host.clone();
    let port = destination.port;
    let path = destination.target.clone();
    tracker.spawn(async move {
        let upgraded = match on_upgrade.await {
            Ok(upgraded) => upgraded,
            Err(_) => return,
        };
        let client_stream = TokioIo::new(upgraded);
        let mut client_ws =
            WebSocketStream::from_raw_socket(client_stream, Role::Server, Some(ws_config)).await;

        let host = host;
        let port = port;
        let path = path;
        let context = context;

        loop {
            tokio::select! {
                message = client_ws.next() => {
                    match message {
                        Some(Ok(message)) => {
                            emit_frame(&context, id, "client_to_server", &message, &host, port, &path).await;
                            if upstream_ws.send(message).await.is_err() {
                                break;
                            }
                        }
                        Some(Err(_)) | None => break,
                    }
                }
                message = upstream_ws.next() => {
                    match message {
                        Some(Ok(message)) => {
                            emit_frame(&context, id, "server_to_client", &message, &host, port, &path).await;
                            if client_ws.send(message).await.is_err() {
                                break;
                            }
                        }
                        Some(Err(_)) | None => break,
                    }
                }
            }
        }

        let _ = client_ws.close(None).await;
        let _ = upstream_ws.close(None).await;
    });

    response
}

async fn emit_frame(
    context: &crate::service::ServiceContext,
    connection_id: u64,
    direction: &str,
    message: &Message,
    host: &str,
    port: u16,
    path: &str,
) {
    let (opcode, size) = match message {
        Message::Text(text) => ("text", text.len()),
        Message::Binary(data) => ("binary", data.len()),
        Message::Ping(data) => ("ping", data.len()),
        Message::Pong(data) => ("pong", data.len()),
        Message::Close(frame) => ("close", frame.as_ref().map(|f| f.reason.len()).unwrap_or(0)),
        Message::Frame(_) => ("frame", 0),
    };

    let mut request = HttpRequest::new(
        "WS",
        rawframe_core::models::message::Scheme::Https,
        host.to_string(),
        port,
        path.to_string(),
    );
    request.version = "WebSocket".to_string();
    let mut timings = TrafficTimings::starting_now();
    timings.finish(0);
    let entry = TrafficEntry {
        id: rawframe_core::TrafficId(connection_id.wrapping_mul(1000) + 1),
        request,
        response: None,
        state: TrafficState::Completed,
        source: rawframe_core::models::traffic::TrafficSource::Intercepted,
        timings,
        error: None,
        note: Some(format!("{direction} {opcode} {size} bytes")),
        kind: TrafficKind::WebSocket,
        tunnel: None,
        original_request: None,
        final_request: None,
        interception: rawframe_core::models::traffic::InterceptionMetadata::default(),
        body_omitted: false,
        redacted_headers: 0,
        repeater_origin: None,
        intruder_payloads: None,
        intruder_origin: None,
    };
    let _ = context
        .events
        .send_async(AppEvent::TrafficCaptured(Box::new(entry)))
        .await;
}

fn error_response(
    status: StatusCode,
    message: impl Into<String>,
) -> Response<crate::body::ProxyBody> {
    use crate::body::ProxyBody;
    use http_body_util::{BodyExt, Full};
    let body: ProxyBody = Full::new(bytes::Bytes::from(message.into()))
        .map_err(|never| match never {})
        .boxed();
    Response::builder()
        .status(status)
        .body(body)
        .unwrap_or_else(|_| {
            Response::new(
                Full::new(bytes::Bytes::new())
                    .map_err(|never| match never {})
                    .boxed(),
            )
        })
}

pub(crate) fn is_websocket_upgrade(request: &Request<hyper::body::Incoming>) -> bool {
    if request.method() != hyper::Method::GET {
        return false;
    }
    let upgrade = request
        .headers()
        .get(hyper::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);
    let connection = request
        .headers()
        .get(hyper::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let connection_ok = connection
        .split(',')
        .any(|token| token.trim().eq_ignore_ascii_case("upgrade"));
    let has_key = request.headers().contains_key("Sec-WebSocket-Key");
    let version_ok = request
        .headers()
        .get("Sec-WebSocket-Version")
        .and_then(|v| v.to_str().ok())
        == Some("13");
    upgrade && connection_ok && has_key && version_ok
}
