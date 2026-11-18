//! Per-request proxy handling: forwarding, capture, and CONNECT upgrades.

use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::{Duration, Instant};

use bytes::Bytes;
use chrono::{DateTime, Utc};
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::header::{
    CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, HOST, HeaderMap, HeaderName, HeaderValue,
    PROXY_AUTHENTICATE, PROXY_AUTHORIZATION, TE, TRAILER, TRANSFER_ENCODING, UPGRADE,
};
use hyper::service::service_fn;
use hyper::upgrade::OnUpgrade;
use hyper::{Method, Request, Response, StatusCode, Version};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rawframe_core::h2;
use rawframe_core::models::HttpResponse;
use rawframe_core::models::traffic::{TrafficEntry, TrafficTimings, TunnelMetadata, TunnelOutcome};
use rawframe_core::{AppConfig, AppEvent, EventSender};
use tokio::sync::{Mutex, Semaphore, watch};
use tokio::time::timeout;
use tokio_util::task::TaskTracker;

use crate::body::{BodyCapture, BodyEnd, BoxError, GuardedBody, ProxyBody};
use crate::destination::{Destination, capture_headers, connect_upstream};
use crate::interception::{InterceptionManager, PauseOutcome};
use crate::server::next_id;
use crate::tls::TlsController;
use crate::tunnel::relay;

/// Bound on simultaneously open HTTP/2 streams per client connection. It is
/// deliberately generous enough for a real browser but small enough that one
/// connection cannot exhaust the task/body budget.
const MAX_H2_STREAMS: u32 = 128;
/// Bound on the encoded header list a peer may send, in bytes. HTTP/2's default
/// is unlimited; RAWFRAME keeps a ceiling.
const MAX_H2_HEADER_LIST: u32 = 64 * 1024;

#[derive(Clone)]
pub(crate) struct ServiceContext {
    pub config: Arc<AppConfig>,
    /// Live scope rules. Edited from the interface without restarting the
    /// listener; every new request and CONNECT is checked against the current
    /// snapshot, and a read lock is held only for the lookup itself.
    pub scope: Arc<std::sync::RwLock<rawframe_core::models::config::Scope>>,
    pub events: EventSender,
    pub ids: Arc<AtomicU64>,
    pub tracker: TaskTracker,
    pub tunnels: Arc<Semaphore>,
    pub shutdown: watch::Receiver<bool>,
    pub interception: InterceptionManager,
    pub tls: Arc<TlsController>,
}

/// An upstream HTTP connection in either protocol. HTTP/2 senders are cloned per
/// stream, so concurrent decrypted requests multiplex instead of serialising;
/// HTTP/1.1 keeps the single-flight mutex it has always used.
enum UpstreamClient {
    Http1(Arc<Mutex<hyper::client::conn::http1::SendRequest<ProxyBody>>>),
    Http2(hyper::client::conn::http2::SendRequest<ProxyBody>),
}

impl UpstreamClient {
    fn is_h2(&self) -> bool {
        matches!(self, Self::Http2(_))
    }

    async fn send(&self, request: Request<ProxyBody>) -> Result<Response<Incoming>, hyper::Error> {
        match self {
            Self::Http1(sender) => sender.lock().await.send_request(request).await,
            // Cloning the HTTP/2 sender dispatches a new stream; the lock, were
            // one used, would cover dispatch only, never the response body.
            Self::Http2(sender) => sender.clone().send_request(request).await,
        }
    }
}

impl ServiceContext {
    pub(crate) fn scope_snapshot(&self) -> rawframe_core::models::config::Scope {
        self.scope
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

pub(crate) async fn handle_request(
    request: Request<Incoming>,
    context: ServiceContext,
) -> Response<ProxyBody> {
    if request.method() == Method::CONNECT {
        if context.tls.is_enabled().await {
            handle_connect_intercepted(request, context).await
        } else {
            handle_connect(request, context).await
        }
    } else {
        handle_http(request, context).await
    }
}

async fn handle_http(request: Request<Incoming>, context: ServiceContext) -> Response<ProxyBody> {
    let started_at = Utc::now();
    let started = Instant::now();
    let destination = match Destination::from_http_request(&request) {
        Ok(destination) => destination,
        Err(rejection) => return error_response(rejection.status, rejection.message),
    };
    let id = next_id(&context.ids);
    let captured_request = destination.capture_request(&request);
    if !destination.is_permitted(&context.scope_snapshot()) {
        let rejection = destination.scope_rejection();
        return reject_live(
            &context,
            id,
            captured_request,
            started_at,
            rejection.status,
            rejection.message,
            false,
        )
        .await;
    }

    if let Some(length) = declared_length(request.headers())
        && length > context.config.proxy.max_body_bytes as u64
    {
        return reject_live(
            &context,
            id,
            captured_request,
            started_at,
            StatusCode::PAYLOAD_TOO_LARGE,
            "request body exceeds the configured limit",
            false,
        )
        .await;
    }

    // WebSocket upgrades are handled on their own long-lived path; they are not
    // paused as ordinary HTTP requests.
    if crate::websocket::is_websocket_upgrade(&request) {
        return crate::websocket::handle(
            request,
            context,
            destination,
            id,
            captured_request,
            started_at,
            started,
        )
        .await;
    }

    // Determine if this request should be intercepted before any upstream work.
    // Intercepted requests are buffered so they can be inspected/modified/dropped
    // without contacting upstream while pending.
    let should_pause = context.interception.should_pause(&captured_request).await;
    if should_pause {
        return handle_http_intercepted(
            request,
            context,
            destination,
            id,
            captured_request,
            started_at,
            started,
        )
        .await;
    }

    let connectivity = connect_upstream(
        &destination,
        context.config.proxy.allow_private_upstreams,
        Duration::from_secs(context.config.proxy.connect_timeout_secs),
    )
    .await;
    let upstream = match connectivity {
        Ok(stream) => stream,
        Err(rejection) => {
            return reject_live(
                &context,
                id,
                captured_request,
                started_at,
                rejection.status,
                rejection.message,
                false,
            )
            .await;
        }
    };

    let handshake = timeout(
        Duration::from_secs(context.config.proxy.connect_timeout_secs),
        hyper::client::conn::http1::handshake(TokioIo::new(upstream)),
    )
    .await;
    let (mut sender, connection) = match handshake {
        Ok(Ok(pair)) => pair,
        Ok(Err(error)) => {
            return reject_live(
                &context,
                id,
                captured_request,
                started_at,
                StatusCode::BAD_GATEWAY,
                format!("upstream HTTP handshake failed: {error}"),
                false,
            )
            .await;
        }
        Err(_) => {
            return reject_live(
                &context,
                id,
                captured_request,
                started_at,
                StatusCode::GATEWAY_TIMEOUT,
                "upstream HTTP handshake timed out",
                false,
            )
            .await;
        }
    };
    context.tracker.spawn(async move {
        let _ = connection.await;
    });

    let (parts, body) = request.into_parts();
    let request_body_capture = BodyCapture::default();
    let guarded_request_body = GuardedBody::new(
        body,
        context.config.proxy.max_body_bytes,
        request_body_capture.clone(),
        Duration::from_secs(context.config.proxy.idle_timeout_secs),
        declared_length(&parts.headers).map(|length| length as usize),
        None,
    );
    let upstream_body: ProxyBody = guarded_request_body
        .map_err(|error| -> BoxError { error })
        .boxed();
    let upstream_request = match build_upstream_request(
        parts.method,
        parts.version,
        parts.headers,
        &destination,
        upstream_body,
    ) {
        Ok(request) => request,
        Err(message) => {
            return reject_live(
                &context,
                id,
                captured_request,
                started_at,
                StatusCode::BAD_REQUEST,
                message,
                false,
            )
            .await;
        }
    };

    let mut entry = live_entry(id, captured_request.clone(), started_at);
    entry.original_request = Some(captured_request.clone());
    entry.final_request = Some(captured_request.clone());
    let _ = entry.forward();
    let _ = context
        .events
        .send_async(AppEvent::TrafficCaptured(Box::new(entry)))
        .await;

    let response = timeout(
        Duration::from_secs(context.config.proxy.upstream_timeout_secs),
        sender.send_request(upstream_request),
    )
    .await;

    let upstream_response = match response {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => {
            let (status, message) = if request_body_capture.exceeded() {
                (
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "request body exceeded the configured limit".to_string(),
                )
            } else if request_body_capture.timed_out() {
                (
                    StatusCode::REQUEST_TIMEOUT,
                    "request body stalled beyond the idle timeout".to_string(),
                )
            } else {
                (
                    StatusCode::BAD_GATEWAY,
                    format!("upstream request failed: {error}"),
                )
            };
            return reject_live(
                &context,
                id,
                captured_request,
                started_at,
                status,
                message,
                true,
            )
            .await;
        }
        Err(_) => {
            return reject_live(
                &context,
                id,
                captured_request,
                started_at,
                StatusCode::GATEWAY_TIMEOUT,
                "upstream response timed out",
                true,
            )
            .await;
        }
    };

    let declared_response_length = declared_length(upstream_response.headers());
    if let Some(length) = declared_response_length
        && length > context.config.proxy.max_response_bytes as u64
    {
        return reject_live(
            &context,
            id,
            captured_request,
            started_at,
            StatusCode::BAD_GATEWAY,
            "upstream response exceeds the configured limit",
            true,
        )
        .await;
    }

    let status = upstream_response.status();
    let version = upstream_response.version();
    let response_headers = capture_headers(upstream_response.headers());
    let (parts, upstream_body) = upstream_response.into_parts();
    let base_response = HttpResponse {
        status: status.as_u16(),
        reason: status.canonical_reason().unwrap_or_default().to_string(),
        version: version_string(version),
        headers: response_headers,
        body: Vec::new(),
    };

    let mut head_entry = live_entry(
        id,
        request_with_body(&captured_request, &request_body_capture),
        started_at,
    );
    head_entry.original_request = Some(request_with_body(&captured_request, &request_body_capture));
    head_entry.final_request = head_entry.original_request.clone();
    let _ = head_entry.forward();
    head_entry.response = Some(base_response.clone());
    let _ = context
        .events
        .send_async(AppEvent::TrafficUpdated(Box::new(head_entry)))
        .await;

    let response_body_capture = BodyCapture::default();
    let finalizer_response_capture = response_body_capture.clone();
    let finalizer_request_capture = request_body_capture.clone();
    let finalizer_request = captured_request.clone();
    let finalizer_response = base_response.clone();
    let finalizer_events = context.events.clone();
    let finalizer_started_at = started_at;
    let finalizer_started = started;
    let on_end: Box<dyn FnOnce(BodyEnd) + Send + Sync> = Box::new(move |end| {
        let duration_ms = finalizer_started.elapsed().as_millis() as u64;
        let request = request_with_body(&finalizer_request, &finalizer_request_capture);
        let mut final_response = finalizer_response.clone();
        final_response.body = finalizer_response_capture.bytes();
        let mut entry = live_entry(id, request.clone(), finalizer_started_at);
        entry.original_request = Some(request.clone());
        entry.final_request = Some(request.clone());
        let _ = entry.forward();
        entry.response = Some(final_response.clone());
        match end {
            BodyEnd::Complete => {
                let _ = entry.complete(final_response, duration_ms);
            }
            BodyEnd::LimitExceeded => {
                entry.note = Some("Response stream truncated at the configured limit".into());
                let _ = entry.fail("upstream response exceeded the configured limit");
            }
            BodyEnd::IdleTimeout => {
                let _ = entry.fail("upstream response body stalled beyond the idle timeout");
            }
            BodyEnd::Aborted => {
                let _ = entry.fail("response body ended before completion");
            }
        }
        spawn_event(finalizer_events, AppEvent::TrafficUpdated(Box::new(entry)));
    });

    let guarded_response_body = GuardedBody::new(
        upstream_body,
        context.config.proxy.max_response_bytes,
        response_body_capture,
        Duration::from_secs(context.config.proxy.idle_timeout_secs),
        declared_response_length.map(|length| length as usize),
        Some(on_end),
    );
    let body: ProxyBody = guarded_response_body
        .map_err(|error| -> BoxError { error })
        .boxed();
    let mut response = Response::new(body);
    *response.status_mut() = status;
    *response.version_mut() = Version::HTTP_11;
    let mut headers = parts.headers;
    filter_headers(&mut headers, true);
    *response.headers_mut() = headers;
    response
}

async fn handle_http_intercepted(
    request: Request<Incoming>,
    context: ServiceContext,
    initial_destination: Destination,
    id: u64,
    mut captured_request: rawframe_core::models::HttpRequest,
    started_at: DateTime<Utc>,
    started: Instant,
) -> Response<ProxyBody> {
    let (parts, body) = request.into_parts();
    // Buffer request body so it can be inspected/edited/dropped before upstream.
    let collected = match timeout(
        Duration::from_secs(context.config.proxy.upstream_timeout_secs),
        body.collect(),
    )
    .await
    {
        Ok(Ok(collected)) => collected,
        Ok(Err(error)) => {
            return reject_live(
                &context,
                id,
                captured_request,
                started_at,
                StatusCode::BAD_REQUEST,
                format!("failed to read request body: {error}"),
                false,
            )
            .await;
        }
        Err(_) => {
            return reject_live(
                &context,
                id,
                captured_request,
                started_at,
                StatusCode::REQUEST_TIMEOUT,
                "timed out while reading request body for interception",
                false,
            )
            .await;
        }
    };
    let body_bytes = collected.to_bytes();
    if body_bytes.len() > context.config.proxy.max_body_bytes {
        return reject_live(
            &context,
            id,
            captured_request,
            started_at,
            StatusCode::PAYLOAD_TOO_LARGE,
            "request body exceeds the configured limit",
            false,
        )
        .await;
    }
    captured_request.body = body_bytes.to_vec();
    captured_request.headers = capture_headers(&parts.headers);
    captured_request
        .headers
        .insert("Host", initial_destination.authority.clone());

    let mut paused_entry = live_entry(id, captured_request.clone(), started_at);
    paused_entry.original_request = Some(captured_request.clone());
    paused_entry.interception.intercepted = true;
    let outcome = context
        .interception
        .pause(rawframe_core::models::TrafficId(id), paused_entry, None)
        .await;

    let (effective_request, modified, destination) = match outcome {
        PauseOutcome::ForwardedUnchanged => (captured_request.clone(), false, initial_destination),
        PauseOutcome::ForwardedModified(edited) => {
            let final_req = match editable_to_http_request(&edited) {
                Ok(req) => req,
                Err(message) => {
                    let mut entry = live_entry(id, captured_request.clone(), started_at);
                    entry.original_request = Some(captured_request.clone());
                    entry.interception.intercepted = true;
                    entry.interception.modified = true;
                    let _ = entry.fail(format!("modified request is invalid: {message}"));
                    let _ = context
                        .events
                        .send_async(AppEvent::TrafficUpdated(Box::new(entry)))
                        .await;
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        format!("modified request is invalid: {message}"),
                    );
                }
            };
            let dest = match destination_from_http_request(&final_req) {
                Ok(dest) => dest,
                Err(rejection) => {
                    let mut entry = live_entry(id, captured_request.clone(), started_at);
                    entry.original_request = Some(captured_request.clone());
                    entry.final_request = Some(final_req);
                    entry.interception.intercepted = true;
                    entry.interception.modified = true;
                    let _ = entry.fail(rejection.message.clone());
                    let _ = context
                        .events
                        .send_async(AppEvent::TrafficUpdated(Box::new(entry)))
                        .await;
                    return error_response(rejection.status, rejection.message);
                }
            };
            if !dest.is_permitted(&context.scope_snapshot()) {
                let rejection = dest.scope_rejection();
                let mut entry = live_entry(id, captured_request.clone(), started_at);
                entry.original_request = Some(captured_request.clone());
                entry.final_request = Some(final_req);
                entry.interception.intercepted = true;
                entry.interception.modified = true;
                let _ = entry.fail(rejection.message.clone());
                let _ = context
                    .events
                    .send_async(AppEvent::TrafficUpdated(Box::new(entry)))
                    .await;
                return error_response(rejection.status, rejection.message);
            }
            (final_req, true, dest)
        }
        PauseOutcome::Dropped => {
            let mut entry = live_entry(id, captured_request.clone(), started_at);
            entry.original_request = Some(captured_request.clone());
            entry.final_request = Some(captured_request.clone());
            let _ = entry.drop_request();
            entry.interception.intercepted = true;
            let _ = context
                .events
                .send_async(AppEvent::TrafficUpdated(Box::new(entry)))
                .await;
            // Dropped: never reaches upstream. Return a local response to the client.
            return error_response(StatusCode::FORBIDDEN, "request dropped by interception");
        }
        PauseOutcome::TimedOut => {
            let mut entry = live_entry(id, captured_request.clone(), started_at);
            entry.original_request = Some(captured_request.clone());
            entry.final_request = Some(captured_request.clone());
            let _ = entry.timeout_interception("interception timed out");
            entry.interception.intercepted = true;
            let _ = context
                .events
                .send_async(AppEvent::TrafficUpdated(Box::new(entry)))
                .await;
            return error_response(StatusCode::GATEWAY_TIMEOUT, "interception timed out");
        }
        PauseOutcome::Cancelled(reason) | PauseOutcome::Rejected(reason) => {
            let mut entry = live_entry(id, captured_request.clone(), started_at);
            entry.original_request = Some(captured_request.clone());
            entry.final_request = Some(captured_request.clone());
            let _ = entry.cancel_interception(reason.clone());
            entry.interception.intercepted = true;
            let _ = context
                .events
                .send_async(AppEvent::TrafficUpdated(Box::new(entry)))
                .await;
            return error_response(StatusCode::SERVICE_UNAVAILABLE, reason);
        }
    };

    if effective_request.body.len() > context.config.proxy.max_body_bytes {
        return reject_live(
            &context,
            id,
            captured_request,
            started_at,
            StatusCode::PAYLOAD_TOO_LARGE,
            "request body exceeds the configured limit",
            false,
        )
        .await;
    }

    let connectivity = connect_upstream(
        &destination,
        context.config.proxy.allow_private_upstreams,
        Duration::from_secs(context.config.proxy.connect_timeout_secs),
    )
    .await;
    let upstream = match connectivity {
        Ok(stream) => stream,
        Err(rejection) => {
            let mut entry = live_entry(id, effective_request.clone(), started_at);
            entry.original_request = Some(captured_request.clone());
            entry.final_request = Some(effective_request.clone());
            entry.interception.intercepted = true;
            entry.interception.modified = modified;
            entry.response = Some(error_model(rejection.status, &rejection.message));
            let _ = entry.fail(rejection.message.clone());
            let _ = context
                .events
                .send_async(AppEvent::TrafficUpdated(Box::new(entry)))
                .await;
            return error_response(rejection.status, rejection.message);
        }
    };

    let handshake = timeout(
        Duration::from_secs(context.config.proxy.connect_timeout_secs),
        hyper::client::conn::http1::handshake(TokioIo::new(upstream)),
    )
    .await;
    let (mut sender, connection) = match handshake {
        Ok(Ok(pair)) => pair,
        Ok(Err(error)) => {
            let message = format!("upstream HTTP handshake failed: {error}");
            let mut entry = live_entry(id, effective_request.clone(), started_at);
            entry.original_request = Some(captured_request.clone());
            entry.final_request = Some(effective_request.clone());
            entry.interception.intercepted = true;
            entry.interception.modified = modified;
            entry.response = Some(error_model(StatusCode::BAD_GATEWAY, &message));
            let _ = entry.fail(message.clone());
            let _ = context
                .events
                .send_async(AppEvent::TrafficUpdated(Box::new(entry)))
                .await;
            return error_response(StatusCode::BAD_GATEWAY, message);
        }
        Err(_) => {
            let message = "upstream HTTP handshake timed out".to_string();
            let mut entry = live_entry(id, effective_request.clone(), started_at);
            entry.original_request = Some(captured_request.clone());
            entry.final_request = Some(effective_request.clone());
            entry.interception.intercepted = true;
            entry.interception.modified = modified;
            entry.response = Some(error_model(StatusCode::GATEWAY_TIMEOUT, &message));
            let _ = entry.fail(message.clone());
            let _ = context
                .events
                .send_async(AppEvent::TrafficUpdated(Box::new(entry)))
                .await;
            return error_response(StatusCode::GATEWAY_TIMEOUT, message);
        }
    };
    context.tracker.spawn(async move {
        let _ = connection.await;
    });

    let upstream_request = match build_upstream_request_from_model(&effective_request, &destination)
    {
        Ok(req) => req,
        Err(message) => {
            let mut entry = live_entry(id, effective_request.clone(), started_at);
            entry.original_request = Some(captured_request.clone());
            entry.final_request = Some(effective_request.clone());
            entry.interception.intercepted = true;
            entry.interception.modified = modified;
            entry.response = Some(error_model(StatusCode::BAD_REQUEST, &message));
            let _ = entry.fail(message.clone());
            let _ = context
                .events
                .send_async(AppEvent::TrafficUpdated(Box::new(entry)))
                .await;
            return error_response(StatusCode::BAD_REQUEST, message);
        }
    };

    let mut forwarded_entry = live_entry(id, effective_request.clone(), started_at);
    forwarded_entry.original_request = Some(captured_request.clone());
    forwarded_entry.final_request = Some(effective_request.clone());
    forwarded_entry.interception.intercepted = true;
    forwarded_entry.interception.modified = modified;
    let _ = forwarded_entry.forward();
    let _ = context
        .events
        .send_async(AppEvent::TrafficCaptured(Box::new(forwarded_entry)))
        .await;

    let response = timeout(
        Duration::from_secs(context.config.proxy.upstream_timeout_secs),
        sender.send_request(upstream_request),
    )
    .await;

    let upstream_response = match response {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => {
            let message = format!("upstream request failed: {error}");
            let mut entry = live_entry(id, effective_request.clone(), started_at);
            entry.original_request = Some(captured_request.clone());
            entry.final_request = Some(effective_request.clone());
            entry.interception.intercepted = true;
            entry.interception.modified = modified;
            entry.response = Some(error_model(StatusCode::BAD_GATEWAY, &message));
            let _ = entry.fail(message.clone());
            let _ = context
                .events
                .send_async(AppEvent::TrafficUpdated(Box::new(entry)))
                .await;
            return error_response(StatusCode::BAD_GATEWAY, message);
        }
        Err(_) => {
            let message = "upstream response timed out".to_string();
            let mut entry = live_entry(id, effective_request.clone(), started_at);
            entry.original_request = Some(captured_request.clone());
            entry.final_request = Some(effective_request.clone());
            entry.interception.intercepted = true;
            entry.interception.modified = modified;
            entry.response = Some(error_model(StatusCode::GATEWAY_TIMEOUT, &message));
            let _ = entry.fail(message.clone());
            let _ = context
                .events
                .send_async(AppEvent::TrafficUpdated(Box::new(entry)))
                .await;
            return error_response(StatusCode::GATEWAY_TIMEOUT, message);
        }
    };

    let declared_response_length = declared_length(upstream_response.headers());
    if let Some(length) = declared_response_length
        && length > context.config.proxy.max_response_bytes as u64
    {
        let message = "upstream response exceeds the configured limit".to_string();
        let mut entry = live_entry(id, effective_request.clone(), started_at);
        entry.original_request = Some(captured_request.clone());
        entry.final_request = Some(effective_request.clone());
        entry.interception.intercepted = true;
        entry.interception.modified = modified;
        entry.response = Some(error_model(StatusCode::BAD_GATEWAY, &message));
        let _ = entry.fail(message.clone());
        let _ = context
            .events
            .send_async(AppEvent::TrafficUpdated(Box::new(entry)))
            .await;
        return error_response(StatusCode::BAD_GATEWAY, message);
    }

    let status = upstream_response.status();
    let version = upstream_response.version();
    let response_headers = capture_headers(upstream_response.headers());
    let (parts, upstream_body) = upstream_response.into_parts();
    let base_response = HttpResponse {
        status: status.as_u16(),
        reason: status.canonical_reason().unwrap_or_default().to_string(),
        version: version_string(version),
        headers: response_headers,
        body: Vec::new(),
    };

    let mut head_entry = live_entry(id, effective_request.clone(), started_at);
    head_entry.original_request = Some(captured_request.clone());
    head_entry.final_request = Some(effective_request.clone());
    head_entry.interception.intercepted = true;
    head_entry.interception.modified = modified;
    let _ = head_entry.forward();
    head_entry.response = Some(base_response.clone());
    let _ = context
        .events
        .send_async(AppEvent::TrafficUpdated(Box::new(head_entry)))
        .await;

    let response_body_capture = BodyCapture::default();
    let finalizer_response_capture = response_body_capture.clone();
    let finalizer_response = base_response.clone();
    let finalizer_events = context.events.clone();
    let finalizer_started_at = started_at;
    let finalizer_started = started;
    let final_original = captured_request.clone();
    let final_effective = effective_request.clone();
    let on_end: Box<dyn FnOnce(BodyEnd) + Send + Sync> = Box::new(move |end| {
        let duration_ms = finalizer_started.elapsed().as_millis() as u64;
        let mut final_response = finalizer_response.clone();
        final_response.body = finalizer_response_capture.bytes();
        let mut entry = live_entry(id, final_effective.clone(), finalizer_started_at);
        entry.original_request = Some(final_original.clone());
        entry.final_request = Some(final_effective.clone());
        entry.interception.intercepted = true;
        entry.interception.modified = modified;
        let _ = entry.forward();
        entry.response = Some(final_response.clone());
        match end {
            BodyEnd::Complete => {
                let _ = entry.complete(final_response, duration_ms);
            }
            BodyEnd::LimitExceeded => {
                entry.note = Some("Response stream truncated at the configured limit".into());
                let _ = entry.fail("upstream response exceeded the configured limit");
            }
            BodyEnd::IdleTimeout => {
                let _ = entry.fail("upstream response body stalled beyond the idle timeout");
            }
            BodyEnd::Aborted => {
                let _ = entry.fail("response body ended before completion");
            }
        }
        spawn_event(finalizer_events, AppEvent::TrafficUpdated(Box::new(entry)));
    });

    let guarded_response_body = GuardedBody::new(
        upstream_body,
        context.config.proxy.max_response_bytes,
        response_body_capture,
        Duration::from_secs(context.config.proxy.idle_timeout_secs),
        declared_response_length.map(|length| length as usize),
        Some(on_end),
    );
    let body: ProxyBody = guarded_response_body
        .map_err(|error| -> BoxError { error })
        .boxed();
    let mut response = Response::new(body);
    *response.status_mut() = status;
    *response.version_mut() = Version::HTTP_11;
    let mut headers = parts.headers;
    filter_headers(&mut headers, true);
    *response.headers_mut() = headers;
    response
}

fn editable_to_http_request(
    edited: &rawframe_core::models::EditableHttpRequest,
) -> Result<rawframe_core::models::HttpRequest, String> {
    let (scheme, host, port, target) = parse_edited_target(&edited.target)?;
    let method = edited.method.trim().to_uppercase();
    if method.is_empty() {
        return Err("method must not be empty".into());
    }
    if !method.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || matches!(
                c,
                '!' | '#'
                    | '$'
                    | '%'
                    | '&'
                    | '\''
                    | '*'
                    | '+'
                    | '-'
                    | '.'
                    | '^'
                    | '_'
                    | '`'
                    | '|'
                    | '~'
            )
    }) {
        return Err("method contains invalid characters".into());
    }
    let mut req = rawframe_core::models::HttpRequest::new(method, scheme, host, port, target);
    req.version = edited.version.clone();
    req.headers = edited.headers.clone();
    // ensure Host matches authority
    req.headers.insert("Host", req.authority());
    req.body = edited.body.clone();
    Ok(req)
}

fn parse_edited_target(
    target: &str,
) -> Result<(rawframe_core::models::message::Scheme, String, u16, String), String> {
    let trimmed = target.trim();
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        let uri: hyper::Uri = trimmed
            .parse()
            .map_err(|_| "invalid absolute target URI".to_string())?;
        let scheme = match uri.scheme_str() {
            Some("http") => rawframe_core::models::message::Scheme::Http,
            Some("https") => rawframe_core::models::message::Scheme::Https,
            _ => return Err("unsupported target scheme".into()),
        };
        let auth = uri
            .authority()
            .ok_or_else(|| "absolute target missing authority".to_string())?;
        let host = crate::destination::normalize_host(auth.host())
            .ok_or_else(|| "invalid host".to_string())?;
        let port = auth.port_u16().unwrap_or_else(|| scheme.default_port());
        let path = uri
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());
        Ok((scheme, host, port, path))
    } else {
        // origin-form; keep existing host/port assumptions not possible here, so require absolute URL
        // but accept origin-form only if caller set meaningful host header? safer: require absolute URL.
        Err(
            "modified target must be an absolute http:// or https:// URL for M3 proxy forwarding"
                .into(),
        )
    }
}

fn destination_from_http_request(
    req: &rawframe_core::models::HttpRequest,
) -> Result<Destination, crate::destination::Rejection> {
    let authority = format_authority(&req.host, req.port, req.scheme);
    let uri = format!(
        "{}://{}{}",
        req.scheme.as_str(),
        authority,
        if req.target.is_empty() {
            "/"
        } else {
            &req.target
        }
    );
    let hyper_req = Request::builder()
        .method(req.method.as_str())
        .uri(uri.as_str())
        .body(())
        .map_err(|_| crate::destination::Rejection::bad_request("invalid modified request"))?;
    Destination::from_http_request(&hyper_req)
}

/// Destination parsing for a request inside an already-terminated/intercepted
/// HTTPS session. HTTPS targets are permitted because RAWFRAME is the TLS
/// endpoint; the caller must still enforce the session authority.
fn destination_from_https_request(
    req: &rawframe_core::models::HttpRequest,
) -> Result<Destination, crate::destination::Rejection> {
    let authority = format_authority(&req.host, req.port, req.scheme);
    let uri = format!(
        "{}://{}{}",
        req.scheme.as_str(),
        authority,
        if req.target.is_empty() {
            "/"
        } else {
            &req.target
        }
    );
    let hyper_req = Request::builder()
        .method(req.method.as_str())
        .uri(uri.as_str())
        .body(())
        .map_err(|_| crate::destination::Rejection::bad_request("invalid modified request"))?;
    Destination::from_intercepted_absolute_request(&hyper_req)
}

fn format_authority(
    host: &str,
    port: u16,
    scheme: rawframe_core::models::message::Scheme,
) -> String {
    let host_part = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    if port == scheme.default_port() {
        host_part
    } else {
        format!("{host_part}:{port}")
    }
}

fn build_upstream_request_from_model(
    request: &rawframe_core::models::HttpRequest,
    destination: &Destination,
) -> Result<Request<ProxyBody>, String> {
    let body = Bytes::from(request.body.clone());
    let body: ProxyBody = Full::new(body).map_err(|never| match never {}).boxed();
    let mut headers = HeaderMap::new();
    for header in request.headers.iter() {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(header.name.as_bytes()),
            HeaderValue::from_bytes(header.value.as_bytes()),
        ) {
            headers.append(name, value);
        }
    }
    let method = Method::from_bytes(request.method.as_bytes())
        .map_err(|_| "invalid HTTP method".to_string())?;
    build_upstream_request(method, Version::HTTP_11, headers, destination, body)
}

async fn handle_connect_intercepted(
    mut request: Request<Incoming>,
    context: ServiceContext,
) -> Response<ProxyBody> {
    use crate::tls::intercept::{
        server_acceptor_for_destination, upstream_connector, upstream_server_name,
    };
    use hyper::client::conn::http1 as client_http1;
    use hyper::client::conn::http2 as client_http2;
    use hyper::server::conn::http1 as server_http1;
    use hyper::server::conn::http2 as server_http2;
    use hyper_util::rt::{TokioIo, TokioTimer};

    let started_at = Utc::now();
    let started = Instant::now();
    let destination = match Destination::from_connect_request(&request) {
        Ok(destination) => destination,
        Err(rejection) => return error_response(rejection.status, rejection.message),
    };
    let id = next_id(&context.ids);
    let captured_request = destination.capture_connect_request(&request);

    // Scope/address policy before leaf issuance, upstream resolution/connect, or TLS.
    if !destination.is_permitted(&context.scope_snapshot()) {
        let rejection = destination.scope_rejection();
        return reject_connect(
            &context,
            id,
            captured_request,
            started_at,
            rejection.status,
            rejection.message,
        )
        .await;
    }

    let Some(tls) = context.tls.runtime().await else {
        return reject_connect(
            &context,
            id,
            captured_request,
            started_at,
            StatusCode::INTERNAL_SERVER_ERROR,
            "TLS interception runtime is unavailable",
        )
        .await;
    };

    let permit = match context.tunnels.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return reject_connect(
                &context,
                id,
                captured_request,
                started_at,
                StatusCode::SERVICE_UNAVAILABLE,
                "too many concurrent tunnels",
            )
            .await;
        }
    };

    let Some(on_upgrade) = request.extensions_mut().remove::<OnUpgrade>() else {
        return reject_connect(
            &context,
            id,
            captured_request,
            started_at,
            StatusCode::INTERNAL_SERVER_ERROR,
            "CONNECT upgrade is unavailable on this connection",
        )
        .await;
    };

    let connect_timeout = Duration::from_secs(context.config.proxy.connect_timeout_secs);

    // Resolve once and connect only to policy-permitted addresses.
    let upstream_tcp = match connect_upstream(
        &destination,
        context.config.proxy.allow_private_upstreams,
        connect_timeout,
    )
    .await
    {
        Ok(stream) => stream,
        Err(rejection) => {
            return reject_connect(
                &context,
                id,
                captured_request,
                started_at,
                rejection.status,
                rejection.message,
            )
            .await;
        }
    };

    // Prepare the client-facing certificate for the validated CONNECT identity.
    let acceptor =
        match server_acceptor_for_destination(tls.leaf_issuer.clone(), &destination.host).await {
            Ok(acceptor) => acceptor,
            Err(error) => {
                return reject_connect(
                    &context,
                    id,
                    captured_request,
                    started_at,
                    StatusCode::BAD_GATEWAY,
                    format!("failed to prepare interception certificate: {error}"),
                )
                .await;
            }
        };

    // Upstream TLS is a separate session. Verification and hostname checks are
    // mandatory and completed before we tell the client CONNECT succeeded.
    let server_name = match upstream_server_name(&destination.host) {
        Ok(name) => name,
        Err(error) => {
            return reject_connect(
                &context,
                id,
                captured_request,
                started_at,
                StatusCode::BAD_GATEWAY,
                format!("invalid upstream TLS server name: {error}"),
            )
            .await;
        }
    };
    let connector = upstream_connector(tls.upstream_config.clone());
    let upstream_tls = match timeout(
        connect_timeout,
        connector.connect(server_name, upstream_tcp),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => {
            return reject_connect(
                &context,
                id,
                captured_request,
                started_at,
                StatusCode::BAD_GATEWAY,
                format!("upstream TLS verification failed: {error}"),
            )
            .await;
        }
        Err(_) => {
            return reject_connect(
                &context,
                id,
                captured_request,
                started_at,
                StatusCode::GATEWAY_TIMEOUT,
                "upstream TLS handshake timed out",
            )
            .await;
        }
    };
    // The upstream leg negotiates its own ALPN. It is checked, never assumed: a
    // server that selects nothing (or http/1.1) keeps the HTTP/1.1 client.
    let upstream_protocol = upstream_tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
    let upstream_h2 = h2::alpn_is_h2(upstream_protocol.as_deref());
    let upstream_client = if upstream_h2 {
        match timeout(
            connect_timeout,
            client_http2::handshake(TokioExecutor::new(), TokioIo::new(upstream_tls)),
        )
        .await
        {
            Ok(Ok((sender, connection))) => {
                let mut shutdown_conn = context.shutdown.clone();
                context.tracker.spawn(async move {
                    tokio::select! {
                        _ = connection => {}
                        _ = shutdown_conn.changed() => {}
                    }
                });
                UpstreamClient::Http2(sender)
            }
            Ok(Err(error)) => {
                return reject_connect(
                    &context,
                    id,
                    captured_request,
                    started_at,
                    StatusCode::BAD_GATEWAY,
                    format!("upstream HTTP/2 handshake failed: {error}"),
                )
                .await;
            }
            Err(_) => {
                return reject_connect(
                    &context,
                    id,
                    captured_request,
                    started_at,
                    StatusCode::GATEWAY_TIMEOUT,
                    "upstream HTTP/2 handshake timed out",
                )
                .await;
            }
        }
    } else {
        match timeout(
            connect_timeout,
            client_http1::handshake(TokioIo::new(upstream_tls)),
        )
        .await
        {
            Ok(Ok((sender, connection))) => {
                let mut shutdown_conn = context.shutdown.clone();
                context.tracker.spawn(async move {
                    tokio::select! {
                        _ = connection => {}
                        _ = shutdown_conn.changed() => {}
                    }
                });
                UpstreamClient::Http1(Arc::new(Mutex::new(sender)))
            }
            Ok(Err(error)) => {
                return reject_connect(
                    &context,
                    id,
                    captured_request,
                    started_at,
                    StatusCode::BAD_GATEWAY,
                    format!("upstream HTTP/1.1 handshake failed: {error}"),
                )
                .await;
            }
            Err(_) => {
                return reject_connect(
                    &context,
                    id,
                    captured_request,
                    started_at,
                    StatusCode::GATEWAY_TIMEOUT,
                    "upstream HTTP/1.1 handshake timed out",
                )
                .await;
            }
        }
    };
    let upstream_label = if upstream_h2 { "HTTP/2" } else { "HTTP/1.1" };

    // Record CONNECT establishment for an intercepted (decrypted) HTTPS session.
    // This is never represented as an opaque tunnel.
    let mut session_entry = live_entry(id, captured_request, started_at);
    session_entry.response = Some(connect_response_model());
    session_entry.note = Some(format!(
        "HTTPS interception session established (upstream TLS verified; upstream {upstream_label})"
    ));
    let _ = session_entry.forward();
    let _ = session_entry.complete(
        connect_response_model(),
        started.elapsed().as_millis() as u64,
    );
    let _ = context
        .events
        .send_async(AppEvent::TrafficCaptured(Box::new(session_entry)))
        .await;

    let tunnel_context = context.clone();
    let idle = Duration::from_secs(context.config.proxy.idle_timeout_secs);
    let dest = destination.clone();
    let upstream_client = Arc::new(upstream_client);
    context.tracker.spawn(async move {
        let _permit = permit;
        let upgraded = match timeout(connect_timeout, on_upgrade).await {
            Ok(Ok(upgraded)) => TokioIo::new(upgraded),
            Ok(Err(error)) => {
                let _ = tunnel_context
                    .events
                    .send_async(AppEvent::Notice(rawframe_core::Notice::warning(format!(
                        "Intercepted CONNECT upgrade failed for {}: {error}",
                        dest.authority
                    ))))
                    .await;
                return;
            }
            Err(_) => {
                let _ = tunnel_context
                    .events
                    .send_async(AppEvent::Notice(rawframe_core::Notice::warning(format!(
                        "Intercepted CONNECT upgrade timed out for {}",
                        dest.authority
                    ))))
                    .await;
                return;
            }
        };

        let client_tls = match timeout(connect_timeout, acceptor.accept(upgraded)).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => {
                let _ = tunnel_context
                    .events
                    .send_async(AppEvent::Notice(rawframe_core::Notice::warning(format!(
                        "Client TLS handshake failed for {}: {error}",
                        dest.authority
                    ))))
                    .await;
                return;
            }
            Err(_) => {
                let _ = tunnel_context
                    .events
                    .send_async(AppEvent::Notice(rawframe_core::Notice::warning(format!(
                        "Client TLS handshake timed out for {}",
                        dest.authority
                    ))))
                    .await;
                return;
            }
        };

        // The client-facing leg negotiates independently of the upstream leg.
        // Serving h2 is decided by the ALPN result of this handshake alone.
        let client_h2 = h2::alpn_is_h2(client_tls.get_ref().1.alpn_protocol());
        let service_dest = dest.clone();
        let service_ctx = tunnel_context.clone();
        let service_upstream = upstream_client.clone();
        let service = service_fn(move |req: Request<Incoming>| {
            let context = service_ctx.clone();
            let destination = service_dest.clone();
            let upstream = service_upstream.clone();
            async move {
                Ok::<_, Infallible>(
                    handle_intercepted_https_request(
                        req,
                        context,
                        destination,
                        upstream,
                        client_h2,
                    )
                    .await,
                )
            }
        });
        let mut shutdown = tunnel_context.shutdown.clone();
        if client_h2 {
            let mut http = server_http2::Builder::new(TokioExecutor::new());
            http.timer(TokioTimer::new());
            http.max_concurrent_streams(MAX_H2_STREAMS);
            http.max_header_list_size(MAX_H2_HEADER_LIST);
            let connection = http.serve_connection(TokioIo::new(client_tls), service);
            tokio::pin!(connection);
            tokio::select! {
                result = &mut connection => {
                    if let Err(error) = result {
                        let _ = tunnel_context
                            .events
                            .send_async(AppEvent::Notice(rawframe_core::Notice::warning(
                                format!(
                                    "Intercepted HTTP/2 session ended for {}: {error}",
                                    dest.authority
                                ),
                            )))
                            .await;
                    }
                }
                _ = shutdown.changed() => {
                    connection.as_mut().graceful_shutdown();
                    let _ = timeout(Duration::from_secs(2), &mut connection).await;
                }
            }
        } else {
            let mut http = server_http1::Builder::new();
            http.timer(TokioTimer::new());
            http.header_read_timeout(Some(idle));
            let connection = http.serve_connection(TokioIo::new(client_tls), service);
            tokio::pin!(connection);
            tokio::select! {
                result = &mut connection => {
                    if let Err(error) = result {
                        let _ = tunnel_context
                            .events
                            .send_async(AppEvent::Notice(rawframe_core::Notice::warning(
                                format!(
                                    "Intercepted HTTPS session ended for {}: {error}",
                                    dest.authority
                                ),
                            )))
                            .await;
                    }
                }
                _ = shutdown.changed() => {
                    // Let in-flight requests observe cancellation and publish
                    // their terminal state before the connection is closed.
                    connection.as_mut().graceful_shutdown();
                    let _ = timeout(Duration::from_secs(2), &mut connection).await;
                }
            }
        }
    });

    let mut response = Response::new(empty_body());
    *response.status_mut() = StatusCode::OK;
    response
}

async fn handle_intercepted_https_request(
    request: Request<Incoming>,
    context: ServiceContext,
    tunnel_destination: Destination,
    upstream: Arc<UpstreamClient>,
    client_h2: bool,
) -> Response<ProxyBody> {
    let started_at = Utc::now();
    let started = Instant::now();
    let id = next_id(&context.ids);

    // Build captured request for this decrypted HTTPS request (origin-form inside tunnel).
    let method = request.method().as_str().to_string();
    let target = request
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let mut captured_request = rawframe_core::models::HttpRequest::new(
        method,
        rawframe_core::models::message::Scheme::Https,
        tunnel_destination.host.clone(),
        tunnel_destination.port,
        target,
    );
    captured_request.version = version_string(request.version());
    captured_request.headers = capture_headers(request.headers());
    captured_request.headers.insert(
        "Host",
        authority_for_host(
            &tunnel_destination.host,
            tunnel_destination.port,
            rawframe_core::models::message::Scheme::Https,
        ),
    );

    // Scope check per request (defense in depth).
    if !tunnel_destination.is_permitted(&context.scope_snapshot()) {
        let rejection = tunnel_destination.scope_rejection();
        return reject_live(
            &context,
            id,
            captured_request,
            started_at,
            rejection.status,
            rejection.message,
            false,
        )
        .await;
    }

    if let Some(length) = declared_length(request.headers())
        && length > context.config.proxy.max_body_bytes as u64
    {
        return reject_live(
            &context,
            id,
            captured_request,
            started_at,
            StatusCode::PAYLOAD_TOO_LARGE,
            "request body exceeds the configured limit",
            false,
        )
        .await;
    }
    let (parts, body) = request.into_parts();
    let limited = http_body_util::Limited::new(body, context.config.proxy.max_body_bytes);
    let collected = match timeout(
        Duration::from_secs(context.config.proxy.upstream_timeout_secs),
        limited.collect(),
    )
    .await
    {
        Ok(Ok(collected)) => collected,
        Ok(Err(error)) => {
            return reject_live(
                &context,
                id,
                captured_request,
                started_at,
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("request body could not be read within the configured limit: {error}"),
                false,
            )
            .await;
        }
        Err(_) => {
            return reject_live(
                &context,
                id,
                captured_request,
                started_at,
                StatusCode::REQUEST_TIMEOUT,
                "timed out while reading request body for interception",
                false,
            )
            .await;
        }
    };
    let body_bytes = collected.to_bytes();
    if body_bytes.len() > context.config.proxy.max_body_bytes {
        return reject_live(
            &context,
            id,
            captured_request,
            started_at,
            StatusCode::PAYLOAD_TOO_LARGE,
            "request body exceeds the configured limit",
            false,
        )
        .await;
    }
    captured_request.body = body_bytes.to_vec();
    captured_request.headers = capture_headers(&parts.headers);
    captured_request.headers.insert(
        "Host",
        authority_for_host(
            &tunnel_destination.host,
            tunnel_destination.port,
            rawframe_core::models::message::Scheme::Https,
        ),
    );

    let should_pause = context.interception.should_pause(&captured_request).await;
    let (effective_request, modified) = if should_pause {
        let mut paused_entry = live_entry(id, captured_request.clone(), started_at);
        paused_entry.original_request = Some(captured_request.clone());
        paused_entry.interception.intercepted = true;
        let outcome = context
            .interception
            .pause(rawframe_core::models::TrafficId(id), paused_entry, None)
            .await;
        match outcome {
            PauseOutcome::ForwardedUnchanged => (captured_request.clone(), false),
            PauseOutcome::ForwardedModified(edited) => {
                let final_req = match editable_to_http_request(&edited) {
                    Ok(mut req) => {
                        // The editor's version field is not the wire protocol: the
                        // protocol was fixed by the TLS/ALPN handshake. Record what
                        // the client actually spoke so history cannot claim a
                        // modified HTTP/2 request was HTTP/1.1 (or vice versa).
                        req.version = captured_request.version.clone();
                        req
                    }
                    Err(message) => {
                        let mut entry = live_entry(id, captured_request.clone(), started_at);
                        entry.original_request = Some(captured_request.clone());
                        entry.interception.intercepted = true;
                        entry.interception.modified = true;
                        let _ = entry.fail(format!("modified request is invalid: {message}"));
                        let _ = context
                            .events
                            .send_async(AppEvent::TrafficUpdated(Box::new(entry)))
                            .await;
                        return error_response(
                            StatusCode::BAD_REQUEST,
                            format!("modified request is invalid: {message}"),
                        );
                    }
                };
                let dest = match destination_from_https_request(&final_req) {
                    Ok(dest) => dest,
                    Err(rejection) => {
                        let mut entry = live_entry(id, captured_request.clone(), started_at);
                        entry.original_request = Some(captured_request.clone());
                        entry.final_request = Some(final_req);
                        entry.interception.intercepted = true;
                        entry.interception.modified = true;
                        let _ = entry.fail(rejection.message.clone());
                        let _ = context
                            .events
                            .send_async(AppEvent::TrafficUpdated(Box::new(entry)))
                            .await;
                        return error_response(rejection.status, rejection.message);
                    }
                };
                if !dest.is_permitted(&context.scope_snapshot()) {
                    let rejection = dest.scope_rejection();
                    let mut entry = live_entry(id, captured_request.clone(), started_at);
                    entry.original_request = Some(captured_request.clone());
                    entry.final_request = Some(final_req);
                    entry.interception.intercepted = true;
                    entry.interception.modified = true;
                    let _ = entry.fail(rejection.message.clone());
                    let _ = context
                        .events
                        .send_async(AppEvent::TrafficUpdated(Box::new(entry)))
                        .await;
                    return error_response(rejection.status, rejection.message);
                }
                // Intercepted HTTPS session is bound to the established upstream TLS connection.
                if dest.scheme != rawframe_core::models::message::Scheme::Https
                    || dest.host != tunnel_destination.host
                    || dest.port != tunnel_destination.port
                {
                    let message = "modified destination must remain within the intercepted HTTPS session authority".to_string();
                    let mut entry = live_entry(id, captured_request.clone(), started_at);
                    entry.original_request = Some(captured_request.clone());
                    entry.final_request = Some(final_req);
                    entry.interception.intercepted = true;
                    entry.interception.modified = true;
                    let _ = entry.fail(message.clone());
                    let _ = context
                        .events
                        .send_async(AppEvent::TrafficUpdated(Box::new(entry)))
                        .await;
                    return error_response(StatusCode::BAD_REQUEST, message);
                }
                (final_req, true)
            }
            PauseOutcome::Dropped => {
                let mut entry = live_entry(id, captured_request.clone(), started_at);
                entry.original_request = Some(captured_request.clone());
                entry.final_request = Some(captured_request.clone());
                let _ = entry.drop_request();
                entry.interception.intercepted = true;
                let _ = context
                    .events
                    .send_async(AppEvent::TrafficUpdated(Box::new(entry)))
                    .await;
                return error_response(StatusCode::FORBIDDEN, "request dropped by interception");
            }
            PauseOutcome::TimedOut => {
                let mut entry = live_entry(id, captured_request.clone(), started_at);
                entry.original_request = Some(captured_request.clone());
                entry.final_request = Some(captured_request.clone());
                let _ = entry.timeout_interception("interception timed out");
                entry.interception.intercepted = true;
                let _ = context
                    .events
                    .send_async(AppEvent::TrafficUpdated(Box::new(entry)))
                    .await;
                return error_response(StatusCode::GATEWAY_TIMEOUT, "interception timed out");
            }
            PauseOutcome::Cancelled(reason) | PauseOutcome::Rejected(reason) => {
                let mut entry = live_entry(id, captured_request.clone(), started_at);
                entry.original_request = Some(captured_request.clone());
                entry.final_request = Some(captured_request.clone());
                let _ = entry.cancel_interception(reason.clone());
                entry.interception.intercepted = true;
                let _ = context
                    .events
                    .send_async(AppEvent::TrafficUpdated(Box::new(entry)))
                    .await;
                return error_response(StatusCode::SERVICE_UNAVAILABLE, reason);
            }
        }
    } else {
        (captured_request.clone(), false)
    };

    // Forward over the established, verified upstream TLS connection.
    let dest_for_req = match destination_from_https_request(&effective_request) {
        Ok(d) => d,
        Err(rejection) => {
            return reject_live(
                &context,
                id,
                effective_request,
                started_at,
                rejection.status,
                rejection.message,
                false,
            )
            .await;
        }
    };
    let upstream_request = match if upstream.is_h2() {
        build_upstream_h2_request_from_model(&effective_request, &dest_for_req)
    } else {
        build_upstream_request_from_model(&effective_request, &dest_for_req)
    } {
        Ok(req) => req,
        Err(message) => {
            let mut entry = live_entry(id, effective_request.clone(), started_at);
            entry.original_request = Some(captured_request.clone());
            entry.final_request = Some(effective_request.clone());
            entry.interception.intercepted = should_pause;
            entry.interception.modified = modified;
            let _ = entry.fail(message.clone());
            let _ = context
                .events
                .send_async(AppEvent::TrafficCaptured(Box::new(entry)))
                .await;
            return error_response(StatusCode::BAD_REQUEST, message);
        }
    };

    let mut forwarded_entry = live_entry(id, effective_request.clone(), started_at);
    forwarded_entry.original_request = Some(captured_request.clone());
    forwarded_entry.final_request = Some(effective_request.clone());
    forwarded_entry.interception.intercepted = should_pause;
    forwarded_entry.interception.modified = modified;
    let _ = forwarded_entry.forward();
    let _ = context
        .events
        .send_async(AppEvent::TrafficCaptured(Box::new(forwarded_entry)))
        .await;

    let send_result = timeout(
        Duration::from_secs(context.config.proxy.upstream_timeout_secs),
        upstream.send(upstream_request),
    )
    .await;
    let upstream_response = match send_result {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => {
            let message = format!("upstream request failed: {error}");
            let mut entry = live_entry(id, effective_request.clone(), started_at);
            entry.original_request = Some(captured_request.clone());
            entry.final_request = Some(effective_request.clone());
            entry.interception.intercepted = should_pause;
            entry.interception.modified = modified;
            let _ = entry.fail(message.clone());
            let _ = context
                .events
                .send_async(AppEvent::TrafficUpdated(Box::new(entry)))
                .await;
            return error_response(StatusCode::BAD_GATEWAY, message);
        }
        Err(_) => {
            let message = "upstream response timed out".to_string();
            let mut entry = live_entry(id, effective_request.clone(), started_at);
            entry.original_request = Some(captured_request.clone());
            entry.final_request = Some(effective_request.clone());
            entry.interception.intercepted = should_pause;
            entry.interception.modified = modified;
            let _ = entry.fail(message.clone());
            let _ = context
                .events
                .send_async(AppEvent::TrafficUpdated(Box::new(entry)))
                .await;
            return error_response(StatusCode::GATEWAY_TIMEOUT, message);
        }
    };

    let declared_response_length = declared_length(upstream_response.headers());
    if let Some(length) = declared_response_length
        && length > context.config.proxy.max_response_bytes as u64
    {
        let message = "upstream response exceeds the configured limit".to_string();
        let mut entry = live_entry(id, effective_request.clone(), started_at);
        entry.original_request = Some(captured_request.clone());
        entry.final_request = Some(effective_request.clone());
        entry.interception.intercepted = should_pause;
        entry.interception.modified = modified;
        let _ = entry.fail(message.clone());
        let _ = context
            .events
            .send_async(AppEvent::TrafficUpdated(Box::new(entry)))
            .await;
        return error_response(StatusCode::BAD_GATEWAY, message);
    }

    let status = upstream_response.status();
    let version = upstream_response.version();
    let response_headers = capture_headers(upstream_response.headers());
    let (parts_resp, upstream_body) = upstream_response.into_parts();
    let base_response = HttpResponse {
        status: status.as_u16(),
        reason: status.canonical_reason().unwrap_or_default().to_string(),
        version: version_string(version),
        headers: response_headers,
        body: Vec::new(),
    };

    let mut head_entry = live_entry(id, effective_request.clone(), started_at);
    head_entry.original_request = Some(captured_request.clone());
    head_entry.final_request = Some(effective_request.clone());
    head_entry.interception.intercepted = should_pause;
    head_entry.interception.modified = modified;
    let _ = head_entry.forward();
    head_entry.response = Some(base_response.clone());
    let _ = context
        .events
        .send_async(AppEvent::TrafficUpdated(Box::new(head_entry)))
        .await;

    let response_body_capture = BodyCapture::default();
    let finalizer_response_capture = response_body_capture.clone();
    let finalizer_response = base_response.clone();
    let finalizer_events = context.events.clone();
    let finalizer_started_at = started_at;
    let finalizer_started = started;
    let final_original = captured_request.clone();
    let final_effective = effective_request.clone();
    let intercepted_flag = should_pause;
    let on_end: Box<dyn FnOnce(BodyEnd) + Send + Sync> = Box::new(move |end| {
        let duration_ms = finalizer_started.elapsed().as_millis() as u64;
        let mut final_response = finalizer_response.clone();
        final_response.body = finalizer_response_capture.bytes();
        let mut entry = live_entry(id, final_effective.clone(), finalizer_started_at);
        entry.original_request = Some(final_original.clone());
        entry.final_request = Some(final_effective.clone());
        entry.interception.intercepted = intercepted_flag;
        entry.interception.modified = modified;
        let _ = entry.forward();
        entry.response = Some(final_response.clone());
        match end {
            BodyEnd::Complete => {
                let _ = entry.complete(final_response, duration_ms);
            }
            BodyEnd::LimitExceeded => {
                entry.note = Some("Response stream truncated at the configured limit".into());
                let _ = entry.fail("upstream response exceeded the configured limit");
            }
            BodyEnd::IdleTimeout => {
                let _ = entry.fail("upstream response body stalled beyond the idle timeout");
            }
            BodyEnd::Aborted => {
                let _ = entry.fail("response body ended before completion");
            }
        }
        spawn_event(finalizer_events, AppEvent::TrafficUpdated(Box::new(entry)));
    });

    let guarded_response_body = GuardedBody::new(
        upstream_body,
        context.config.proxy.max_response_bytes,
        response_body_capture,
        Duration::from_secs(context.config.proxy.idle_timeout_secs),
        declared_response_length.map(|length| length as usize),
        Some(on_end),
    );
    let body: ProxyBody = guarded_response_body
        .map_err(|error| -> BoxError { error })
        .boxed();
    let mut response = Response::new(body);
    *response.status_mut() = status;
    // hyper validates the response version against the connection it encodes
    // on, so mirror the client-facing protocol. The captured response keeps the
    // upstream's real version above.
    *response.version_mut() = if client_h2 {
        Version::HTTP_2
    } else {
        Version::HTTP_11
    };
    let mut headers = parts_resp.headers;
    filter_headers(&mut headers, true);
    *response.headers_mut() = headers;
    response
}

fn authority_for_host(
    host: &str,
    port: u16,
    scheme: rawframe_core::models::message::Scheme,
) -> String {
    let host_part = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    if port == scheme.default_port() {
        host_part
    } else {
        format!("{host_part}:{port}")
    }
}

async fn handle_connect(
    mut request: Request<Incoming>,
    context: ServiceContext,
) -> Response<ProxyBody> {
    let started_at = Utc::now();
    let started = Instant::now();
    let destination = match Destination::from_connect_request(&request) {
        Ok(destination) => destination,
        Err(rejection) => return error_response(rejection.status, rejection.message),
    };
    let id = next_id(&context.ids);
    let captured_request = destination.capture_connect_request(&request);
    if !destination.is_permitted(&context.scope_snapshot()) {
        let rejection = destination.scope_rejection();
        return reject_connect(
            &context,
            id,
            captured_request,
            started_at,
            rejection.status,
            rejection.message,
        )
        .await;
    }

    let permit = match context.tunnels.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return reject_connect(
                &context,
                id,
                captured_request,
                started_at,
                StatusCode::SERVICE_UNAVAILABLE,
                "too many concurrent tunnels",
            )
            .await;
        }
    };

    let upstream = match connect_upstream(
        &destination,
        context.config.proxy.allow_private_upstreams,
        Duration::from_secs(context.config.proxy.connect_timeout_secs),
    )
    .await
    {
        Ok(upstream) => upstream,
        Err(rejection) => {
            return reject_connect(
                &context,
                id,
                captured_request,
                started_at,
                rejection.status,
                rejection.message,
            )
            .await;
        }
    };

    let Some(on_upgrade) = request.extensions_mut().remove::<OnUpgrade>() else {
        return reject_connect(
            &context,
            id,
            captured_request,
            started_at,
            StatusCode::INTERNAL_SERVER_ERROR,
            "CONNECT upgrade is unavailable on this connection",
        )
        .await;
    };

    let initial_metadata = TunnelMetadata {
        outcome: TunnelOutcome::Active,
        ..TunnelMetadata::default()
    };
    let mut entry = TrafficEntry::tunnel(
        rawframe_core::models::TrafficId(id),
        captured_request.clone(),
        initial_metadata.clone(),
        started_at,
    );
    entry.response = Some(connect_response_model());
    let _ = entry.forward();
    let _ = context
        .events
        .send_async(AppEvent::TrafficCaptured(Box::new(entry)))
        .await;

    let tunnel_context = context.clone();
    let idle = Duration::from_secs(context.config.proxy.idle_timeout_secs);
    let upgrade_timeout = Duration::from_secs(context.config.proxy.connect_timeout_secs);
    let base_request = captured_request;
    context.tracker.spawn(async move {
        let upgraded = timeout(upgrade_timeout, on_upgrade).await;
        let upgraded = match upgraded {
            Ok(Ok(upgraded)) => upgraded,
            Ok(Err(error)) => {
                finish_tunnel_failure(
                    &tunnel_context,
                    id,
                    base_request,
                    started_at,
                    format!("CONNECT upgrade failed: {error}"),
                )
                .await;
                return;
            }
            Err(_) => {
                finish_tunnel_failure(
                    &tunnel_context,
                    id,
                    base_request,
                    started_at,
                    "CONNECT upgrade timed out".to_string(),
                )
                .await;
                return;
            }
        };

        let result = relay(
            TokioIo::new(upgraded),
            upstream,
            idle,
            tunnel_context.shutdown.clone(),
        )
        .await;
        let duration_ms = started.elapsed().as_millis() as u64;
        let metadata = TunnelMetadata {
            client_to_upstream_bytes: result.client_to_upstream_bytes,
            upstream_to_client_bytes: result.upstream_to_client_bytes,
            outcome: result.outcome,
        };
        let mut entry = TrafficEntry::tunnel(
            rawframe_core::models::TrafficId(id),
            base_request,
            metadata,
            started_at,
        );
        let mut response = connect_response_model();
        response.body = Vec::new();
        entry.response = Some(response.clone());
        let _ = entry.forward();
        entry.note = Some(format!(
            "Opaque CONNECT tunnel: {} · {} up · {} down",
            result.detail,
            human_bytes(result.client_to_upstream_bytes),
            human_bytes(result.upstream_to_client_bytes)
        ));
        match result.outcome {
            TunnelOutcome::Closed => {
                let _ = entry.complete(response, duration_ms);
            }
            TunnelOutcome::TimedOut | TunnelOutcome::Failed => {
                let _ = entry.fail(result.detail);
            }
            TunnelOutcome::Active => {}
        }
        let _ = tunnel_context
            .events
            .send_async(AppEvent::TrafficUpdated(Box::new(entry)))
            .await;
        drop(permit);
    });

    let mut response = Response::new(empty_body());
    *response.status_mut() = StatusCode::OK;
    response
}

async fn finish_tunnel_failure(
    context: &ServiceContext,
    id: u64,
    request: rawframe_core::models::HttpRequest,
    started_at: DateTime<Utc>,
    message: String,
) {
    let mut entry = TrafficEntry::tunnel(
        rawframe_core::models::TrafficId(id),
        request,
        TunnelMetadata {
            outcome: TunnelOutcome::Failed,
            ..TunnelMetadata::default()
        },
        started_at,
    );
    entry.response = Some(connect_response_model());
    let _ = entry.forward();
    entry.note = Some(message.clone());
    let _ = entry.fail(message);
    let _ = context
        .events
        .send_async(AppEvent::TrafficUpdated(Box::new(entry)))
        .await;
}

/// Builds the upstream message for an HTTP/2 connection. The absolute URI is the
/// single source of `:scheme`, `:authority`, and `:path`; pseudo-headers are
/// never written into the regular header list, and HTTP/1.1 connection-specific
/// fields (including `Host`) are removed.
fn build_upstream_h2_request_from_model(
    request: &rawframe_core::models::HttpRequest,
    destination: &Destination,
) -> Result<Request<ProxyBody>, String> {
    let body = Bytes::from(request.body.clone());
    let body: ProxyBody = Full::new(body).map_err(|never| match never {}).boxed();
    let mut headers = HeaderMap::new();
    for header in h2::sanitize_headers_for_h2(&request.headers).iter() {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(header.name.as_bytes()),
            HeaderValue::from_bytes(header.value.as_bytes()),
        ) {
            headers.append(name, value);
        }
    }
    // The body length is known and hyper sets it; a stale authored value would
    // be a protocol error.
    headers.remove(CONTENT_LENGTH);
    headers.remove(TRANSFER_ENCODING);
    let method = Method::from_bytes(request.method.as_bytes())
        .map_err(|_| "invalid HTTP method".to_string())?;
    let uri = h2::absolute_uri(request)
        .parse::<hyper::Uri>()
        .map_err(|_| "invalid absolute URI for HTTP/2".to_string())?;
    // The authority in the URI is derived from the already-validated destination
    // model, so this cannot redirect the request past scope enforcement.
    debug_assert_eq!(
        uri.authority().map(|a| a.as_str()),
        Some(destination.authority.as_str())
    );
    let mut upstream = Request::new(body);
    *upstream.method_mut() = method;
    *upstream.uri_mut() = uri;
    *upstream.version_mut() = Version::HTTP_2;
    *upstream.headers_mut() = headers;
    Ok(upstream)
}

fn build_upstream_request(
    method: Method,
    _version: Version,
    mut headers: HeaderMap,
    destination: &Destination,
    body: ProxyBody,
) -> Result<Request<ProxyBody>, String> {
    filter_headers(&mut headers, false);
    headers.remove(CONTENT_LENGTH);
    headers.remove(TRANSFER_ENCODING);
    headers.remove(HOST);
    let host = HeaderValue::from_str(&destination.authority)
        .map_err(|_| "invalid destination authority".to_string())?;
    headers.insert(HOST, host);

    let mut request = Request::new(body);
    *request.method_mut() = method;
    *request.uri_mut() = destination
        .target
        .parse()
        .map_err(|_| "invalid origin-form target".to_string())?;
    *request.version_mut() = Version::HTTP_11;
    *request.headers_mut() = headers;
    Ok(request)
}

fn live_entry(
    id: u64,
    request: rawframe_core::models::HttpRequest,
    started_at: DateTime<Utc>,
) -> TrafficEntry {
    let mut entry = TrafficEntry::new(rawframe_core::models::TrafficId(id), request);
    entry.timings = TrafficTimings::starting_at(started_at);
    entry
}

fn request_with_body(
    request: &rawframe_core::models::HttpRequest,
    capture: &BodyCapture,
) -> rawframe_core::models::HttpRequest {
    let mut request = request.clone();
    request.body = capture.bytes();
    request
}

async fn reject_live(
    context: &ServiceContext,
    id: u64,
    request: rawframe_core::models::HttpRequest,
    started_at: DateTime<Utc>,
    status: StatusCode,
    message: impl Into<String>,
    already_forwarded: bool,
) -> Response<ProxyBody> {
    let message = message.into();
    let response = error_model(status, &message);
    let mut entry = live_entry(id, request, started_at);
    if already_forwarded {
        let _ = entry.forward();
    }
    entry.response = Some(response);
    let _ = entry.fail(&message);
    let event = if already_forwarded {
        AppEvent::TrafficUpdated(Box::new(entry))
    } else {
        AppEvent::TrafficCaptured(Box::new(entry))
    };
    let _ = context.events.send_async(event).await;
    error_response(status, message)
}

async fn reject_connect(
    context: &ServiceContext,
    id: u64,
    request: rawframe_core::models::HttpRequest,
    started_at: DateTime<Utc>,
    status: StatusCode,
    message: impl Into<String>,
) -> Response<ProxyBody> {
    let message = message.into();
    let mut entry = TrafficEntry::tunnel(
        rawframe_core::models::TrafficId(id),
        request,
        TunnelMetadata {
            outcome: TunnelOutcome::Failed,
            ..TunnelMetadata::default()
        },
        started_at,
    );
    entry.response = Some(error_model(status, &message));
    entry.note = Some(message.clone());
    let _ = entry.fail(message.clone());
    let _ = context
        .events
        .send_async(AppEvent::TrafficCaptured(Box::new(entry)))
        .await;
    error_response(status, message)
}

fn error_model(status: StatusCode, message: &str) -> HttpResponse {
    HttpResponse::with_body(
        status.as_u16(),
        "text/plain; charset=utf-8",
        message.as_bytes().to_vec(),
    )
}

fn connect_response_model() -> HttpResponse {
    let mut response = HttpResponse::new(200);
    response.reason = "Connection Established".to_string();
    response
}

fn error_response(status: StatusCode, message: impl Into<String>) -> Response<ProxyBody> {
    let message = message.into();
    let body = Bytes::from(message);
    let length = body.len();
    let body: ProxyBody = Full::new(body).map_err(|never| match never {}).boxed();
    let mut response = Response::new(body);
    *response.status_mut() = status;
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    if let Ok(value) = HeaderValue::from_str(&length.to_string()) {
        response.headers_mut().insert(CONTENT_LENGTH, value);
    }
    response
        .headers_mut()
        .insert(CONNECTION, HeaderValue::from_static("close"));
    response
}

fn empty_body() -> ProxyBody {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn declared_length(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()
}

fn filter_headers(headers: &mut HeaderMap, response: bool) {
    let connection_headers: Vec<HeaderName> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect();

    for name in connection_headers {
        headers.remove(name);
    }
    for name in [
        CONNECTION,
        PROXY_AUTHORIZATION,
        PROXY_AUTHENTICATE,
        TE,
        TRAILER,
        TRANSFER_ENCODING,
        UPGRADE,
        HeaderName::from_static("keep-alive"),
        HeaderName::from_static("proxy-connection"),
    ] {
        headers.remove(name);
    }
    if response {
        headers.remove(CONTENT_LENGTH);
    }
}

fn spawn_event(events: EventSender, event: AppEvent) {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(async move {
            let _ = events.send_async(event).await;
        });
    } else {
        let _ = events.send(event);
    }
}

fn version_string(version: Version) -> String {
    match version {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_11 => "HTTP/1.1",
        Version::HTTP_2 => "HTTP/2.0",
        Version::HTTP_3 => "HTTP/3.0",
        _ => "HTTP/1.1",
    }
    .to_string()
}

fn human_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}
