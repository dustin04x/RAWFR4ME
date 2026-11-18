//! Independent HTTP/1.1 and HTTP/2 execution engine for the Repeater.
//!
//! Every execution resolves the destination exactly once, validates every
//! resolved address, connects only to those addresses, and verifies upstream TLS
//! with the platform (or explicitly configured) trust store. There is no code
//! path through the proxy's CONNECT tunnel, local MITM CA, or interception queue.

use std::sync::Arc;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{CONTENT_LENGTH, HOST, HeaderName, HeaderValue};
use hyper::{Method, Request, Version};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rawframe_core::h2;
use rawframe_core::models::config::{ProxyConfiguration, Scope};
use rawframe_core::models::message::{HttpRequest, HttpResponse, Scheme};
use rawframe_core::models::traffic::{TrafficEntry, TrafficId, TrafficSource, TrafficState};
use rawframe_core::repeater::{
    MAX_REDIRECTS, RedirectHop, RepeaterExecutionPhase, RepeaterResult, RepeaterTimings,
    validate_request,
};
use rawframe_proxy::destination::{Destination, capture_headers, resolve_destination};
use rawframe_proxy::tls_api::build_upstream_tls_config_with_trust_file;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;

/// Limits for Repeater execution. These come from the shared proxy
/// configuration but concurrency is deliberately smaller: a handful of manual
/// requests should never create a traffic flood.
#[derive(Debug, Clone)]
pub struct RepeaterConfig {
    pub allow_private_upstreams: bool,
    pub max_request_body: usize,
    pub max_response_bytes: usize,
    pub connect_timeout: Duration,
    pub response_timeout: Duration,
    pub idle_timeout: Duration,
    pub max_concurrent: usize,
    pub trust_file: Option<std::path::PathBuf>,
}

impl RepeaterConfig {
    pub fn from_proxy(config: &ProxyConfiguration) -> Self {
        Self {
            allow_private_upstreams: config.allow_private_upstreams,
            max_request_body: config.max_body_bytes,
            max_response_bytes: config.max_response_bytes,
            connect_timeout: Duration::from_secs(config.connect_timeout_secs),
            response_timeout: Duration::from_secs(config.upstream_timeout_secs),
            idle_timeout: Duration::from_secs(config.idle_timeout_secs),
            max_concurrent: 4,
            trust_file: config.tls_upstream_trust_file.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionFailure {
    Validation(String),
    Busy(String),
    Blocked(String),
    Dns(String),
    Connect(String),
    Tls(String),
    Timeout(String),
    Cancelled,
    Redirect(String),
    Protocol(String),
}

impl ExecutionFailure {
    pub fn message(&self) -> String {
        match self {
            Self::Validation(message)
            | Self::Busy(message)
            | Self::Blocked(message)
            | Self::Dns(message)
            | Self::Connect(message)
            | Self::Tls(message)
            | Self::Timeout(message)
            | Self::Redirect(message)
            | Self::Protocol(message) => message.clone(),
            Self::Cancelled => "execution cancelled".to_string(),
        }
    }

    pub fn phase(&self) -> RepeaterExecutionPhase {
        match self {
            Self::Validation(_) | Self::Dns(_) | Self::Connect(_) | Self::Tls(_) => {
                RepeaterExecutionPhase::Failed
            }
            Self::Busy(_) => RepeaterExecutionPhase::Failed,
            Self::Blocked(_) => RepeaterExecutionPhase::Blocked,
            Self::Timeout(_) => RepeaterExecutionPhase::TimedOut,
            Self::Cancelled => RepeaterExecutionPhase::Cancelled,
            Self::Redirect(_) => RepeaterExecutionPhase::Failed,
            Self::Protocol(_) => RepeaterExecutionPhase::Failed,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ExecutionOutcome {
    pub result: RepeaterResult,
    pub phase: RepeaterExecutionPhase,
    pub failure: Option<ExecutionFailure>,
}

impl ExecutionOutcome {
    pub fn is_success(&self) -> bool {
        self.failure.is_none() && self.result.response.is_some()
    }
}

pub struct RepeaterEngine {
    config: RepeaterConfig,
    scope: Arc<RwLock<Scope>>,
    permits: Arc<Semaphore>,
    concurrency: usize,
    tls: Result<Arc<ClientConfig>, String>,
}

impl RepeaterEngine {
    pub fn new(config: RepeaterConfig, scope: Arc<RwLock<Scope>>) -> Self {
        let tls = build_upstream_tls_config_with_trust_file(config.trust_file.as_deref())
            .map(Arc::new)
            .map_err(|error| format!("upstream TLS trust store unavailable: {error}"));
        let concurrency = config.max_concurrent.max(1);
        let permits = Arc::new(Semaphore::new(concurrency));
        Self {
            config,
            scope,
            permits,
            concurrency,
            tls,
        }
    }

    pub fn max_concurrent(&self) -> usize {
        self.concurrency
    }

    pub fn tls_available(&self) -> bool {
        self.tls.is_ok()
    }

    pub fn update_scope(&self, scope: Scope) {
        *self
            .scope
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = scope;
    }

    fn scope_snapshot(&self) -> Scope {
        self.scope
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Executes one request (and, if requested, safe redirect hops). Returns a
    /// result for every outcome, including validation and scope failures, so the
    /// interface never has to invent a response or hide the reason.
    pub async fn execute<F>(
        &self,
        request: &HttpRequest,
        follow_redirects: bool,
        cancel: CancellationToken,
        progress: F,
    ) -> ExecutionOutcome
    where
        F: Fn(RepeaterExecutionPhase) + Send + Sync,
    {
        let started = Instant::now();
        let _permit = match self.permits.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                return self.failure(
                    request,
                    started,
                    RepeaterTimings::default(),
                    Vec::new(),
                    None,
                    ExecutionFailure::Busy(
                        "too many concurrent Repeater executions; wait for one to finish".into(),
                    ),
                );
            }
        };

        let mut current = request.clone();
        if !current.headers.contains("host") {
            current.headers.insert("Host", current.authority());
        }
        let mut timings = RepeaterTimings::default();
        let mut redirects: Vec<RedirectHop> = Vec::new();
        let mut warnings = Vec::new();

        loop {
            progress(RepeaterExecutionPhase::Validating);
            if let Err(error) = validate_request(&current, self.config.max_request_body) {
                return self.failure(
                    &current,
                    started,
                    timings,
                    redirects,
                    None,
                    ExecutionFailure::Validation(error.to_string()),
                );
            }
            if cancel.is_cancelled() {
                return self.cancelled(&current, started, timings, redirects, None);
            }

            let destination = match Destination::from_parts(
                current.scheme,
                &current.host,
                current.port,
                &current.target,
            ) {
                Ok(destination) => destination,
                Err(rejection) => {
                    return self.failure(
                        &current,
                        started,
                        timings,
                        redirects,
                        None,
                        ExecutionFailure::Validation(rejection.message),
                    );
                }
            };

            // Scope is re-read for every hop. A redirect cannot smuggle a
            // request outside the allowlist.
            if !destination.is_permitted(&self.scope_snapshot()) {
                return self.failure(
                    &current,
                    started,
                    timings,
                    redirects,
                    None,
                    ExecutionFailure::Blocked(format!(
                        "destination {}:{} is outside the configured scope",
                        current.host, current.port
                    )),
                );
            }
            if current.scheme == Scheme::Https && self.tls.is_err() {
                return self.failure(
                    &current,
                    started,
                    timings,
                    redirects,
                    None,
                    ExecutionFailure::Tls(
                        self.tls
                            .as_ref()
                            .err()
                            .cloned()
                            .unwrap_or_else(|| "upstream TLS is unavailable".into()),
                    ),
                );
            }

            progress(RepeaterExecutionPhase::Connecting);
            let resolve_started = Instant::now();
            let addresses = match resolve_destination(
                &destination,
                self.config.allow_private_upstreams,
                self.config.connect_timeout,
            )
            .await
            {
                Ok(addresses) => addresses,
                Err(rejection) => {
                    let kind = if rejection.status == hyper::StatusCode::FORBIDDEN {
                        ExecutionFailure::Blocked(rejection.message)
                    } else {
                        ExecutionFailure::Dns(rejection.message)
                    };
                    return self.failure(&current, started, timings, redirects, None, kind);
                }
            };
            timings.dns_ms = Some(elapsed_ms(resolve_started));

            let connect_started = Instant::now();
            let tcp = match timeout_or_cancel(
                self.config.connect_timeout,
                TcpStream::connect(&addresses[..]),
                &cancel,
            )
            .await
            {
                Ok(Ok(Ok(stream))) => stream,
                Ok(Ok(Err(error))) => {
                    return self.failure(
                        &current,
                        started,
                        timings,
                        redirects,
                        None,
                        ExecutionFailure::Connect(format!("upstream connection failed: {error}")),
                    );
                }
                Ok(Err(_)) => {
                    return self.failure(
                        &current,
                        started,
                        timings,
                        redirects,
                        None,
                        ExecutionFailure::Timeout("upstream connection timed out".into()),
                    );
                }
                Err(()) => {
                    return self.cancelled(&current, started, timings, redirects, None);
                }
            };
            timings.connect_ms = Some(elapsed_ms(connect_started));

            let stream = match current.scheme {
                Scheme::Http => Stream::Plain(tcp),
                Scheme::Https => {
                    let tls_started = Instant::now();
                    let server_name = match ServerName::try_from(current.host.clone()) {
                        Ok(name) => name,
                        Err(_) => {
                            return self.failure(
                                &current,
                                started,
                                timings,
                                redirects,
                                None,
                                ExecutionFailure::Tls("invalid upstream TLS server name".into()),
                            );
                        }
                    };
                    let config = self
                        .tls
                        .as_ref()
                        .expect("TLS availability checked above")
                        .clone();
                    let connector = TlsConnector::from(config);
                    match timeout_or_cancel(
                        self.config.connect_timeout,
                        connector.connect(server_name, tcp),
                        &cancel,
                    )
                    .await
                    {
                        Ok(Ok(Ok(stream))) => {
                            timings.tls_ms = Some(elapsed_ms(tls_started));
                            Stream::Tls(Box::new(stream))
                        }
                        Ok(Ok(Err(error))) => {
                            return self.failure(
                                &current,
                                started,
                                timings,
                                redirects,
                                None,
                                ExecutionFailure::Tls(format!(
                                    "upstream TLS verification failed: {error}"
                                )),
                            );
                        }
                        Ok(Err(_)) => {
                            return self.failure(
                                &current,
                                started,
                                timings,
                                redirects,
                                None,
                                ExecutionFailure::Timeout(
                                    "upstream TLS handshake timed out".into(),
                                ),
                            );
                        }
                        Err(()) => {
                            return self.cancelled(&current, started, timings, redirects, None);
                        }
                    }
                }
            };

            // ALPN is checked, never assumed. Plaintext HTTP stays HTTP/1.1
            // (RAWFRAME does not implement h2c), and TLS uses HTTP/2 only when
            // the server actually selected `h2`.
            let h2_negotiated = match &stream {
                Stream::Plain(_) => false,
                Stream::Tls(tls) => h2::alpn_is_h2(tls.get_ref().1.alpn_protocol()),
            };

            let mut sender = if h2_negotiated {
                let handshake = timeout_or_cancel(
                    self.config.connect_timeout,
                    hyper::client::conn::http2::handshake(
                        TokioExecutor::new(),
                        TokioIo::new(stream),
                    ),
                    &cancel,
                )
                .await;
                match handshake {
                    Ok(Ok(Ok((sender, connection)))) => {
                        spawn_connection(connection);
                        Sender::Http2(sender)
                    }
                    Ok(Ok(Err(error))) => {
                        return self.failure(
                            &current,
                            started,
                            timings,
                            redirects,
                            None,
                            ExecutionFailure::Protocol(format!(
                                "upstream HTTP/2 handshake failed: {error}"
                            )),
                        );
                    }
                    Ok(Err(_)) => {
                        return self.failure(
                            &current,
                            started,
                            timings,
                            redirects,
                            None,
                            ExecutionFailure::Timeout("upstream HTTP/2 handshake timed out".into()),
                        );
                    }
                    Err(()) => {
                        return self.cancelled(&current, started, timings, redirects, None);
                    }
                }
            } else {
                let handshake = timeout_or_cancel(
                    self.config.connect_timeout,
                    hyper::client::conn::http1::handshake(TokioIo::new(stream)),
                    &cancel,
                )
                .await;
                match handshake {
                    Ok(Ok(Ok((sender, connection)))) => {
                        spawn_connection(connection);
                        Sender::Http1(sender)
                    }
                    Ok(Ok(Err(error))) => {
                        return self.failure(
                            &current,
                            started,
                            timings,
                            redirects,
                            None,
                            ExecutionFailure::Protocol(format!(
                                "upstream HTTP handshake failed: {error}"
                            )),
                        );
                    }
                    Ok(Err(_)) => {
                        return self.failure(
                            &current,
                            started,
                            timings,
                            redirects,
                            None,
                            ExecutionFailure::Timeout("upstream HTTP handshake timed out".into()),
                        );
                    }
                    Err(()) => {
                        return self.cancelled(&current, started, timings, redirects, None);
                    }
                }
            };

            let request_headers = match hyper_headers(&current) {
                Ok(headers) => headers,
                Err(message) => {
                    return self.failure(
                        &current,
                        started,
                        timings,
                        redirects,
                        None,
                        ExecutionFailure::Validation(message),
                    );
                }
            };
            let method = match Method::from_bytes(current.method.as_bytes()) {
                Ok(method) => method,
                Err(_) => {
                    return self.failure(
                        &current,
                        started,
                        timings,
                        redirects,
                        None,
                        ExecutionFailure::Validation("invalid HTTP method".into()),
                    );
                }
            };
            let uri = match current.target.parse::<hyper::Uri>() {
                Ok(uri) => uri,
                Err(_) => {
                    return self.failure(
                        &current,
                        started,
                        timings,
                        redirects,
                        None,
                        ExecutionFailure::Validation("invalid request target URI".into()),
                    );
                }
            };
            let mut upstream_request = Request::new(Full::new(Bytes::from(current.body.clone())));
            *upstream_request.method_mut() = method;
            *upstream_request.version_mut() = if h2_negotiated {
                Version::HTTP_2
            } else {
                Version::HTTP_11
            };
            if h2_negotiated {
                // Absolute URI carries :scheme/:authority/:path; pseudo-headers
                // never appear in the regular header list, and connection-specific
                // HTTP/1.1 fields (including Host) are dropped.
                let absolute = match h2::absolute_uri(&current).parse::<hyper::Uri>() {
                    Ok(uri) => uri,
                    Err(_) => {
                        return self.failure(
                            &current,
                            started,
                            timings,
                            redirects,
                            None,
                            ExecutionFailure::Validation("invalid absolute URI for HTTP/2".into()),
                        );
                    }
                };
                *upstream_request.uri_mut() = absolute;
                let sanitized = h2::sanitize_headers_for_h2(&current.headers);
                let mut headers = hyper::HeaderMap::new();
                for header in sanitized.iter() {
                    if let (Ok(name), Ok(value)) = (
                        hyper::header::HeaderName::from_bytes(header.name.as_bytes()),
                        HeaderValue::from_bytes(header.value.as_bytes()),
                    ) {
                        headers.append(name, value);
                    }
                }
                *upstream_request.headers_mut() = headers;
            } else {
                *upstream_request.uri_mut() = uri;
                *upstream_request.headers_mut() = request_headers;
                if !upstream_request.headers().contains_key(HOST)
                    && let Ok(value) = HeaderValue::from_str(&current.authority())
                {
                    upstream_request.headers_mut().insert(HOST, value);
                }
            }
            if let Some(length) = upstream_request.headers().get(CONTENT_LENGTH)
                && length
                    .to_str()
                    .ok()
                    .and_then(|value| value.trim().parse::<usize>().ok())
                    != Some(current.body.len())
            {
                upstream_request.headers_mut().remove(CONTENT_LENGTH);
            }

            progress(RepeaterExecutionPhase::Sending);
            let send_started = Instant::now();
            let response = timeout_or_cancel(
                self.config.response_timeout,
                async {
                    match &mut sender {
                        Sender::Http1(sender) => sender.send_request(upstream_request).await,
                        Sender::Http2(sender) => sender.send_request(upstream_request).await,
                    }
                },
                &cancel,
            )
            .await;
            let response = match response {
                Ok(Ok(Ok(response))) => response,
                Ok(Ok(Err(error))) => {
                    return self.failure(
                        &current,
                        started,
                        timings,
                        redirects,
                        None,
                        ExecutionFailure::Protocol(format!("upstream request failed: {error}")),
                    );
                }
                Ok(Err(_)) => {
                    return self.failure(
                        &current,
                        started,
                        timings,
                        redirects,
                        None,
                        ExecutionFailure::Timeout("upstream response timed out".into()),
                    );
                }
                Err(()) => {
                    return self.cancelled(&current, started, timings, redirects, None);
                }
            };
            timings.send_ms = Some(elapsed_ms(send_started));
            timings.ttfb_ms = Some(elapsed_ms(send_started));

            progress(RepeaterExecutionPhase::Receiving);
            let status = response.status();
            let version = response.version();
            let response_headers = capture_headers(response.headers());
            let (_parts, mut body) = response.into_parts();
            let (body_bytes, truncated, collection_failure) =
                self.collect_body(&mut body, &cancel).await;
            let response_model = HttpResponse {
                status: status.as_u16(),
                reason: status.canonical_reason().unwrap_or_default().to_string(),
                version: version_string(version),
                headers: response_headers,
                body: body_bytes,
            };
            timings.total_ms = elapsed_ms(started);

            if let Some(failure) = collection_failure {
                let mut result = self.result(
                    &current,
                    ResultParts {
                        response: Some(response_model),
                        timings,
                        redirects,
                        truncated,
                        warnings,
                    },
                    Some(failure.message()),
                );
                result.sent_at = chrono::Utc::now();
                return ExecutionOutcome {
                    result,
                    phase: failure.phase(),
                    failure: Some(failure),
                };
            }

            let location = response_model.headers.get("location").map(str::to_string);
            let redirect_status = matches!(status.as_u16(), 301 | 302 | 303 | 307 | 308);
            if follow_redirects
                && redirect_status
                && let Some(location) = location
            {
                if redirects.len() >= MAX_REDIRECTS {
                    return self.failure_with_response(
                        &current,
                        started,
                        ResultParts {
                            response: Some(response_model),
                            timings,
                            redirects,
                            truncated,
                            warnings,
                        },
                        ExecutionFailure::Redirect(format!(
                            "redirect limit of {MAX_REDIRECTS} hops reached; final response not followed"
                        )),
                    );
                }
                let previous_url = current.url();
                match redirect_request(&current, &location) {
                    Ok(mut next) => {
                        let cross_origin = next.scheme != current.scheme
                            || next.host != current.host
                            || next.port != current.port;
                        if cross_origin {
                            // Never forward credentials to a different origin.
                            next.headers.remove_all("authorization");
                            next.headers.remove_all("proxy-authorization");
                            next.headers.remove_all("cookie");
                            next.headers.remove_all("x-api-key");
                            next.headers.remove_all("x-auth-token");
                            next.headers.remove_all("x-csrf-token");
                        }
                        if should_rewrite_to_get(status.as_u16(), &current.method) {
                            next.method = "GET".into();
                            next.body.clear();
                            next.headers.remove_all("content-length");
                            next.headers.remove_all("content-type");
                            next.headers.remove_all("transfer-encoding");
                        }
                        next.headers.insert("Host", next.authority());
                        // Revalidate the redirect target before announcing the
                        // hop. The original 3xx response stays visible when the
                        // destination is blocked.
                        if let Ok(destination) = Destination::from_parts(
                            next.scheme,
                            &next.host,
                            next.port,
                            &next.target,
                        ) && !destination.is_permitted(&self.scope_snapshot())
                        {
                            redirects.push(RedirectHop {
                                status: status.as_u16(),
                                from: previous_url,
                                to: next.url(),
                                cross_origin,
                            });
                            return self.failure_with_response(
                                &current,
                                started,
                                ResultParts {
                                    response: Some(response_model),
                                    timings,
                                    redirects,
                                    truncated,
                                    warnings,
                                },
                                ExecutionFailure::Blocked(format!(
                                    "redirect destination {}:{} is outside the configured scope",
                                    next.host, next.port
                                )),
                            );
                        }
                        redirects.push(RedirectHop {
                            status: status.as_u16(),
                            from: previous_url,
                            to: next.url(),
                            cross_origin,
                        });
                        if !next.target.starts_with('/') && next.target != "*" {
                            return self.failure_with_response(
                                &current,
                                started,
                                ResultParts {
                                    response: Some(response_model),
                                    timings,
                                    redirects,
                                    truncated,
                                    warnings,
                                },
                                ExecutionFailure::Redirect(
                                    "redirect target is not an origin-form HTTP path".into(),
                                ),
                            );
                        }
                        current = next;
                        continue;
                    }
                    Err(message) => {
                        warnings.push(format!("redirect not followed: {message}"));
                        timings.total_ms = elapsed_ms(started);
                        let result = self.result(
                            &current,
                            ResultParts {
                                response: Some(response_model),
                                timings,
                                redirects,
                                truncated,
                                warnings,
                            },
                            None,
                        );
                        return ExecutionOutcome {
                            result,
                            phase: RepeaterExecutionPhase::Completed,
                            failure: None,
                        };
                    }
                }
            }

            if truncated {
                warnings.push(format!(
                    "response body truncated at the configured {}-byte limit",
                    self.config.max_response_bytes
                ));
            }
            timings.total_ms = elapsed_ms(started);
            let result = self.result(
                &current,
                ResultParts {
                    response: Some(response_model),
                    timings,
                    redirects,
                    truncated,
                    warnings,
                },
                None,
            );
            return ExecutionOutcome {
                result,
                phase: RepeaterExecutionPhase::Completed,
                failure: None,
            };
        }
    }

    async fn collect_body(
        &self,
        body: &mut Incoming,
        cancel: &CancellationToken,
    ) -> (Vec<u8>, bool, Option<ExecutionFailure>) {
        let limit = self.config.max_response_bytes;
        let mut collected = Vec::new();
        let mut truncated = false;
        loop {
            let frame = tokio::select! {
                _ = cancel.cancelled() => {
                    return (collected, truncated, Some(ExecutionFailure::Cancelled));
                }
                frame = tokio::time::timeout(self.config.idle_timeout, body.frame()) => frame,
            };
            match frame {
                Ok(Some(Ok(frame))) => {
                    if let Some(data) = frame.data_ref() {
                        if collected.len() >= limit {
                            truncated = true;
                            break;
                        }
                        let remaining = limit - collected.len();
                        if data.len() > remaining {
                            collected.extend_from_slice(&data[..remaining]);
                            truncated = true;
                            break;
                        }
                        collected.extend_from_slice(data);
                    }
                }
                Ok(Some(Err(error))) => {
                    return (
                        collected,
                        truncated,
                        Some(ExecutionFailure::Protocol(format!(
                            "response body ended with an error: {error}"
                        ))),
                    );
                }
                Ok(None) => break,
                Err(_) => {
                    return (
                        collected,
                        truncated,
                        Some(ExecutionFailure::Timeout(
                            "response body stalled beyond the idle timeout".into(),
                        )),
                    );
                }
            }
        }
        (collected, truncated, None)
    }

    fn failure(
        &self,
        request: &HttpRequest,
        started: Instant,
        timings: RepeaterTimings,
        redirects: Vec<RedirectHop>,
        response: Option<HttpResponse>,
        failure: ExecutionFailure,
    ) -> ExecutionOutcome {
        let result = self.result(
            request,
            ResultParts {
                response,
                timings,
                redirects,
                truncated: false,
                warnings: Vec::new(),
            },
            Some(failure.message()),
        );
        let mut result = result;
        result.timings.total_ms = elapsed_ms(started);
        ExecutionOutcome {
            result,
            phase: failure.phase(),
            failure: Some(failure),
        }
    }

    fn failure_with_response(
        &self,
        request: &HttpRequest,
        started: Instant,
        parts: ResultParts,
        failure: ExecutionFailure,
    ) -> ExecutionOutcome {
        let mut result = self.result(request, parts, Some(failure.message()));
        result.timings.total_ms = elapsed_ms(started);
        ExecutionOutcome {
            result,
            phase: failure.phase(),
            failure: Some(failure),
        }
    }

    fn cancelled(
        &self,
        request: &HttpRequest,
        started: Instant,
        timings: RepeaterTimings,
        redirects: Vec<RedirectHop>,
        response: Option<HttpResponse>,
    ) -> ExecutionOutcome {
        self.failure(
            request,
            started,
            timings,
            redirects,
            response,
            ExecutionFailure::Cancelled,
        )
    }

    fn result(
        &self,
        request: &HttpRequest,
        parts: ResultParts,
        error: Option<String>,
    ) -> RepeaterResult {
        let response_bytes = parts
            .response
            .as_ref()
            .map(|response| response.body.len())
            .unwrap_or_default();
        RepeaterResult {
            request: request.clone(),
            response: parts.response,
            timings: parts.timings,
            redirects: parts.redirects,
            truncated: parts.truncated,
            response_bytes,
            error,
            warnings: parts.warnings,
            sent_at: chrono::Utc::now(),
        }
    }
}

fn hyper_headers(request: &HttpRequest) -> Result<hyper::HeaderMap, String> {
    let mut headers = hyper::HeaderMap::new();
    for header in request.headers.iter() {
        let name = HeaderName::from_bytes(header.name.as_bytes())
            .map_err(|_| format!("invalid header name '{}'", header.name))?;
        let value = HeaderValue::from_bytes(header.value.as_bytes())
            .map_err(|_| format!("invalid value for header '{}'", header.name))?;
        headers.append(name, value);
    }
    Ok(headers)
}

fn should_rewrite_to_get(status: u16, method: &str) -> bool {
    if method.eq_ignore_ascii_case("HEAD") {
        return false;
    }
    match status {
        303 => true,
        301 | 302 => method.eq_ignore_ascii_case("POST"),
        _ => false,
    }
}

fn redirect_request(base: &HttpRequest, location: &str) -> Result<HttpRequest, String> {
    let location = location.trim();
    if location.is_empty() {
        return Err("redirect has an empty Location".into());
    }
    let location = if let Some(rest) = location.strip_prefix("//") {
        format!("{}://{rest}", base.scheme)
    } else if location.starts_with("http://") || location.starts_with("https://") {
        location.to_string()
    } else if location.contains("://") {
        return Err("redirect Location must use http or https".into());
    } else if let Some(query) = location.strip_prefix('?') {
        let path = base.target.split('?').next().unwrap_or("/");
        format!("{}://{}{}?{}", base.scheme, base.authority(), path, query)
    } else if location.starts_with('/') {
        format!("{}://{}{}", base.scheme, base.authority(), location)
    } else {
        let path = base.target.split('?').next().unwrap_or("/");
        let directory = match path.rfind('/') {
            Some(index) => &path[..=index],
            None => "/",
        };
        format!(
            "{}://{}{}{}",
            base.scheme,
            base.authority(),
            directory,
            location
        )
    };
    let uri: hyper::Uri = location
        .parse()
        .map_err(|_| "redirect Location is not a valid URL".to_string())?;
    let scheme = match uri.scheme_str() {
        Some("http") => Scheme::Http,
        Some("https") => Scheme::Https,
        _ => return Err("redirect Location must use http or https".into()),
    };
    let authority = uri
        .authority()
        .ok_or_else(|| "redirect Location is missing an authority".to_string())?;
    let host = authority.host().trim_matches(['[', ']']).to_string();
    let port = authority
        .port_u16()
        .unwrap_or_else(|| scheme.default_port());
    let target = uri
        .path_and_query()
        .map(|path| path.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    if port == 0 {
        return Err("redirect target has an invalid port".into());
    }
    let mut next = HttpRequest::new(base.method.clone(), scheme, host, port, target);
    next.version = base.version.clone();
    next.headers = base.headers.clone();
    next.body = base.body.clone();
    Ok(next)
}

fn version_string(version: Version) -> String {
    match version {
        Version::HTTP_10 => "HTTP/1.0".into(),
        Version::HTTP_2 => "HTTP/2.0".into(),
        Version::HTTP_3 => "HTTP/3.0".into(),
        _ => "HTTP/1.1".into(),
    }
}

/// An established upstream connection in whichever protocol ALPN selected.
enum Sender {
    Http1(hyper::client::conn::http1::SendRequest<Full<Bytes>>),
    Http2(hyper::client::conn::http2::SendRequest<Full<Bytes>>),
}

/// Drives an upstream connection future. The Repeater owns the request/response
/// pair; the connection task only services framing.
fn spawn_connection<C>(connection: C)
where
    C: std::future::Future<Output = Result<(), hyper::Error>> + Send + 'static,
{
    tokio::spawn(async move {
        let _ = connection.await;
    });
}

fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
}

async fn timeout_or_cancel<T, F>(
    duration: Duration,
    future: F,
    cancel: &CancellationToken,
) -> Result<Result<T, tokio::time::error::Elapsed>, ()>
where
    F: std::future::Future<Output = T>,
{
    tokio::select! {
        _ = cancel.cancelled() => Err(()),
        result = tokio::time::timeout(duration, future) => Ok(result),
    }
}

enum Stream {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

/// The response-dependent half of a result, kept together so the result helpers
/// do not grow unbounded argument lists as metrics are added.
struct ResultParts {
    response: Option<HttpResponse>,
    timings: RepeaterTimings,
    redirects: Vec<RedirectHop>,
    truncated: bool,
    warnings: Vec<String>,
}

impl AsyncRead for Stream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
            Self::Tls(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
            Self::Tls(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => std::pin::Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => std::pin::Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
            Self::Tls(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
        }
    }
}

/// Converts an execution outcome into the persisted transaction model. The
/// source is always `Repeater`, so it can never be mistaken for live proxy
/// traffic, and the original capture reference is preserved.
pub fn entry_from_outcome(
    id: TrafficId,
    outcome: &ExecutionOutcome,
    origin: Option<TrafficId>,
    origin_request: Option<HttpRequest>,
) -> TrafficEntry {
    let mut entry = TrafficEntry::new(id, outcome.result.request.clone());
    entry.source = TrafficSource::Repeater;
    entry.repeater_origin = origin;
    entry.original_request = origin_request;
    entry.final_request = Some(outcome.result.request.clone());
    entry.timings.completed_at = Some(chrono::Utc::now());
    entry.timings.duration_ms = Some(outcome.result.timings.total_ms);
    entry.response = outcome.result.response.clone();
    entry.note = if outcome.result.warnings.is_empty() {
        None
    } else {
        Some(outcome.result.warnings.join("; "))
    };
    if let Some(failure) = &outcome.failure {
        entry.error = Some(failure.message());
        entry.state = match outcome.phase {
            RepeaterExecutionPhase::TimedOut => TrafficState::TimedOut,
            RepeaterExecutionPhase::Cancelled => TrafficState::Cancelled,
            RepeaterExecutionPhase::Blocked => TrafficState::Failed,
            _ => TrafficState::Failed,
        };
    } else {
        entry.state = TrafficState::Completed;
    }
    entry
}

#[cfg(test)]
mod tests {
    use super::*;
    use rawframe_core::models::message::Scheme;

    #[test]
    fn redirect_resolution_handles_relative_and_absolute_locations() {
        let base = HttpRequest::new(
            "GET",
            Scheme::Https,
            "api.rawframe.test",
            443,
            "/v1/things?x=1",
        );

        let absolute = redirect_request(&base, "http://other.test:8081/next").unwrap();
        assert_eq!(absolute.scheme, Scheme::Http);
        assert_eq!(absolute.host, "other.test");
        assert_eq!(absolute.port, 8081);
        assert_eq!(absolute.target, "/next");

        let relative = redirect_request(&base, "other").unwrap();
        assert_eq!(relative.target, "/v1/other");

        let root = redirect_request(&base, "/root").unwrap();
        assert_eq!(root.target, "/root");

        let query = redirect_request(&base, "?page=2").unwrap();
        assert_eq!(query.target, "/v1/things?page=2");
    }

    #[test]
    fn post_redirect_methods_follow_http_semantics() {
        assert!(should_rewrite_to_get(303, "PUT"));
        assert!(should_rewrite_to_get(301, "POST"));
        assert!(!should_rewrite_to_get(307, "POST"));
        assert!(!should_rewrite_to_get(308, "PUT"));
        assert!(!should_rewrite_to_get(302, "GET"));
        assert!(!should_rewrite_to_get(303, "HEAD"));
    }

    #[test]
    fn rejected_redirect_schemes_are_reported() {
        let base = HttpRequest::new("GET", Scheme::Http, "a.test", 80, "/");
        assert!(redirect_request(&base, "file:///etc/passwd").is_err());
        assert!(redirect_request(&base, "https:///missing").is_err());
    }

    #[test]
    fn repeater_entries_have_repeater_provenance() {
        let result = RepeaterResult {
            request: HttpRequest::new("GET", Scheme::Http, "a.test", 80, "/"),
            response: Some(HttpResponse::new(200)),
            timings: RepeaterTimings::default(),
            redirects: Vec::new(),
            truncated: false,
            response_bytes: 0,
            error: None,
            warnings: Vec::new(),
            sent_at: chrono::Utc::now(),
        };
        let outcome = ExecutionOutcome {
            result,
            phase: RepeaterExecutionPhase::Completed,
            failure: None,
        };
        let entry = entry_from_outcome(
            TrafficId(2_000_001),
            &outcome,
            Some(TrafficId(14)),
            Some(HttpRequest::new(
                "GET",
                Scheme::Http,
                "a.test",
                80,
                "/original",
            )),
        );
        assert_eq!(entry.source, TrafficSource::Repeater);
        assert_eq!(entry.state, TrafficState::Completed);
        assert_eq!(entry.repeater_origin, Some(TrafficId(14)));
        assert!(!entry.is_live_capture());
    }
}
