//! Repeater execution contracts and request validation.
//!
//! This module deliberately contains no networking. It defines the vocabulary
//! shared by the execution engine, the terminal interface, and persistence so a
//! Repeater result cannot be confused with proxy traffic and no second HTTP
//! message model is invented.
//!
//! Validation here is a security boundary: the engine calls it before every
//! connection (including every redirect hop), and the editor can surface the
//! same actionable errors without contacting a network.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::models::message::{HttpRequest, HttpResponse};
use crate::models::session::RepeaterId;
use crate::models::traffic::{TrafficEntry, TrafficId};

/// Interface identifiers for Repeater transactions. Restored history uses
/// `1_000_000 + row_id`, so Repeater results start above that range.
pub const REPEATER_ID_BASE: u64 = 2_000_000;

pub const MAX_REPEATER_HEADERS: usize = 256;
pub const MAX_REPEATER_HEADER_BYTES: usize = 64 * 1024;
pub const MAX_REPEATER_TARGET_BYTES: usize = 8 * 1024;
pub const MAX_REDIRECTS: usize = 5;

/// States a Repeater tab can be in. None of these are inferred from a response
/// status: a 403 from upstream and a local scope block are different states.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepeaterExecutionPhase {
    Draft,
    Validating,
    Connecting,
    Sending,
    Receiving,
    Completed,
    Failed,
    Cancelled,
    TimedOut,
    /// Rejected by scope, address policy, or request framing before any
    /// connection was allowed.
    Blocked,
}

impl RepeaterExecutionPhase {
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Draft => "DRAFT",
            Self::Validating => "VALIDATING",
            Self::Connecting => "CONNECTING",
            Self::Sending => "SENDING",
            Self::Receiving => "RECEIVING",
            Self::Completed => "COMPLETED",
            Self::Failed => "FAILED",
            Self::Cancelled => "CANCELLED",
            Self::TimedOut => "TIMED OUT",
            Self::Blocked => "BLOCKED",
        }
    }

    pub const fn is_active(&self) -> bool {
        matches!(
            self,
            Self::Validating | Self::Connecting | Self::Sending | Self::Receiving
        )
    }

    pub const fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::Cancelled | Self::TimedOut | Self::Blocked
        )
    }
}

/// Measured phases for one execution. Values are optional because a phase may
/// not happen (plain HTTP has no TLS) or may fail before it completes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepeaterTimings {
    pub dns_ms: Option<u64>,
    pub connect_ms: Option<u64>,
    pub tls_ms: Option<u64>,
    pub send_ms: Option<u64>,
    /// Time to first response byte (headers), measured from send start.
    pub ttfb_ms: Option<u64>,
    pub total_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedirectHop {
    pub status: u16,
    pub from: String,
    pub to: String,
    /// True when the hop changed scheme, host, or port.
    pub cross_origin: bool,
}

/// The real outcome of one Repeater execution. A response may exist together
/// with an error (for example a 302 whose redirect target was blocked).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepeaterResult {
    /// The exact request that was last transmitted (after redirect handling and
    /// any Host insertion). Never the editor text.
    pub request: HttpRequest,
    pub response: Option<HttpResponse>,
    pub timings: RepeaterTimings,
    pub redirects: Vec<RedirectHop>,
    pub truncated: bool,
    pub response_bytes: usize,
    pub error: Option<String>,
    pub warnings: Vec<String>,
    pub sent_at: chrono::DateTime<chrono::Utc>,
}

impl RepeaterResult {
    pub fn is_success(&self) -> bool {
        self.response.is_some() && self.error.is_none()
    }

    pub fn status(&self) -> Option<u16> {
        self.response.as_ref().map(|response| response.status)
    }
}

/// Commands accepted by the Repeater execution service. Every execution is
/// revalidated from scratch; `execution` correlates asynchronous state updates
/// and cancellation with one tab.
#[derive(Debug, Clone)]
pub enum RepeaterCommand {
    Execute {
        tab: RepeaterId,
        execution: u64,
        request: HttpRequest,
        follow_redirects: bool,
        /// Captured History entry this draft was opened from, if any.
        origin: Option<TrafficId>,
        /// The captured request as it existed before editing. Stored with the
        /// result so a restored Repeater transaction keeps its original
        /// reference; it is never sent or re-executed.
        origin_request: Option<Box<HttpRequest>>,
    },
    Cancel {
        execution: u64,
    },
    /// Replace the live scope used for future executions. Existing executions
    /// keep the snapshot they were admitted under.
    UpdateScope(crate::models::config::Scope),
    Shutdown,
}

pub type RepeaterCommandSender = tokio::sync::mpsc::Sender<RepeaterCommand>;

/// Events published by the Repeater service.
#[derive(Debug, Clone)]
pub enum RepeaterEvent {
    Phase {
        tab: RepeaterId,
        execution: u64,
        phase: RepeaterExecutionPhase,
    },
    Completed {
        tab: RepeaterId,
        execution: u64,
        phase: RepeaterExecutionPhase,
        result: Box<RepeaterResult>,
        /// Persistable transaction. Its source is `Repeater`; it is never
        /// presented as live proxy traffic.
        entry: Box<TrafficEntry>,
    },
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum RequestValidationError {
    #[error("request method must not be empty")]
    EmptyMethod,
    #[error("invalid HTTP method '{0}': only token characters are allowed")]
    InvalidMethod(String),
    #[error("CONNECT is not supported by Repeater; use the proxy for tunnels")]
    ConnectUnsupported,
    #[error("request target must start with '/' (or be '*' for OPTIONS)")]
    InvalidTarget,
    #[error("request target may not contain a fragment ('#')")]
    TargetFragment,
    #[error("request target contains whitespace or control characters")]
    TargetControl,
    #[error("request target exceeds {MAX_REPEATER_TARGET_BYTES} bytes")]
    TargetTooLong,
    #[error("destination host is missing or invalid")]
    InvalidHost,
    #[error("destination port must not be zero")]
    InvalidPort,
    #[error("invalid header name '{0}'")]
    InvalidHeaderName(String),
    #[error("header '{0}' contains a line break or control character")]
    InvalidHeaderValue(String),
    #[error("more than {MAX_REPEATER_HEADERS} header fields")]
    TooManyHeaders,
    #[error("request headers exceed {MAX_REPEATER_HEADER_BYTES} bytes")]
    HeadersTooLarge,
    #[error("multiple Host headers are ambiguous; use exactly one")]
    MultipleHostHeaders,
    #[error("Content-Length is not a valid non-negative integer")]
    InvalidContentLength,
    #[error("duplicate Content-Length headers are not allowed")]
    DuplicateContentLength,
    #[error(
        "Content-Length ({declared}) does not match the {actual}-byte request body; \
         update the header or the body"
    )]
    ContentLengthMismatch { declared: u64, actual: usize },
    #[error(
        "Transfer-Encoding is not supported in Repeater because the engine frames the \
         request body itself; remove Transfer-Encoding"
    )]
    TransferEncodingUnsupported,
    #[error("request body is {actual} bytes, above the configured {limit}-byte limit")]
    BodyTooLarge { actual: usize, limit: usize },
}

/// Validates a request document before transmission. This is intentionally
/// independent of hyper so invalid framing cannot be "repaired" silently by a
/// client library.
pub fn validate_request(
    request: &HttpRequest,
    max_body_bytes: usize,
) -> Result<(), RequestValidationError> {
    let method = request.method.trim();
    if method.is_empty() {
        return Err(RequestValidationError::EmptyMethod);
    }
    if !is_token(method) {
        return Err(RequestValidationError::InvalidMethod(method.to_string()));
    }
    if method.eq_ignore_ascii_case("CONNECT") {
        return Err(RequestValidationError::ConnectUnsupported);
    }

    if request.target != "*" && !request.target.starts_with('/') {
        return Err(RequestValidationError::InvalidTarget);
    }
    if request.target.contains('#') {
        return Err(RequestValidationError::TargetFragment);
    }
    if request.target.len() > MAX_REPEATER_TARGET_BYTES {
        return Err(RequestValidationError::TargetTooLong);
    }
    if request
        .target
        .chars()
        .any(|ch| ch.is_control() || ch.is_whitespace())
    {
        return Err(RequestValidationError::TargetControl);
    }
    if request.target == "*" && !method.eq_ignore_ascii_case("OPTIONS") {
        return Err(RequestValidationError::InvalidTarget);
    }

    let host = request.host.trim();
    if host.is_empty()
        || host
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace() || matches!(ch, '/' | '@' | '\\'))
    {
        return Err(RequestValidationError::InvalidHost);
    }
    if request.port == 0 {
        return Err(RequestValidationError::InvalidPort);
    }

    if request.headers.len() > MAX_REPEATER_HEADERS {
        return Err(RequestValidationError::TooManyHeaders);
    }
    let mut header_bytes = 0usize;
    for header in request.headers.iter() {
        if !is_token(&header.name) {
            return Err(RequestValidationError::InvalidHeaderName(
                header.name.clone(),
            ));
        }
        if header
            .value
            .chars()
            .any(|ch| ch == '\r' || ch == '\n' || (ch.is_control() && ch != '\t'))
        {
            return Err(RequestValidationError::InvalidHeaderValue(
                header.name.clone(),
            ));
        }
        header_bytes += header.name.len() + header.value.len() + 4;
    }
    if header_bytes > MAX_REPEATER_HEADER_BYTES {
        return Err(RequestValidationError::HeadersTooLarge);
    }

    let hosts = request.headers.get_all("host").count();
    if hosts > 1 {
        return Err(RequestValidationError::MultipleHostHeaders);
    }

    let content_lengths: Vec<&str> = request.headers.get_all("content-length").collect();
    if content_lengths.len() > 1 {
        return Err(RequestValidationError::DuplicateContentLength);
    }
    if let Some(value) = content_lengths.first() {
        let declared: u64 = value
            .trim()
            .parse()
            .map_err(|_| RequestValidationError::InvalidContentLength)?;
        if declared != request.body.len() as u64 {
            return Err(RequestValidationError::ContentLengthMismatch {
                declared,
                actual: request.body.len(),
            });
        }
    }
    if request
        .headers
        .get_all("transfer-encoding")
        .next()
        .is_some()
    {
        return Err(RequestValidationError::TransferEncodingUnsupported);
    }

    if request.body.len() > max_body_bytes {
        return Err(RequestValidationError::BodyTooLarge {
            actual: request.body.len(),
            limit: max_body_bytes,
        });
    }

    Ok(())
}

fn is_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

/// A normalized header difference for two executions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderDifference {
    pub name: String,
    pub previous: Vec<String>,
    pub current: Vec<String>,
}

/// Comparison of two executions of the same Repeater request. Based only on
/// received bytes and measured timings; never on synthesized labels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionComparison {
    pub status_changed: Option<(u16, u16)>,
    pub duration_delta_ms: i64,
    pub size_delta: i64,
    pub header_changes: Vec<HeaderDifference>,
    pub body_changed: bool,
    pub first_body_difference: Option<usize>,
}

pub fn compare_executions(
    previous: &RepeaterResult,
    current: &RepeaterResult,
) -> ExecutionComparison {
    let previous_status = previous.status();
    let current_status = current.status();
    let status_changed = match (previous_status, current_status) {
        (Some(before), Some(after)) if before != after => Some((before, after)),
        _ => None,
    };

    let mut header_changes = Vec::new();
    let previous_headers = header_map(previous.response.as_ref());
    let current_headers = header_map(current.response.as_ref());
    let names: std::collections::BTreeSet<&String> = previous_headers
        .keys()
        .chain(current_headers.keys())
        .collect();
    for name in names {
        let before = previous_headers.get(name).cloned().unwrap_or_default();
        let after = current_headers.get(name).cloned().unwrap_or_default();
        if before != after {
            header_changes.push(HeaderDifference {
                name: name.clone(),
                previous: before,
                current: after,
            });
        }
    }

    let previous_body = previous
        .response
        .as_ref()
        .map(|response| response.body.as_slice())
        .unwrap_or_default();
    let current_body = current
        .response
        .as_ref()
        .map(|response| response.body.as_slice())
        .unwrap_or_default();
    let first_body_difference = previous_body
        .iter()
        .zip(current_body)
        .position(|(left, right)| left != right)
        .or_else(|| {
            (previous_body.len() != current_body.len())
                .then_some(previous_body.len().min(current_body.len()))
        });

    ExecutionComparison {
        status_changed,
        duration_delta_ms: current.timings.total_ms as i64 - previous.timings.total_ms as i64,
        size_delta: current.response_bytes as i64 - previous.response_bytes as i64,
        header_changes,
        body_changed: first_body_difference.is_some(),
        first_body_difference,
    }
}

fn header_map(response: Option<&HttpResponse>) -> BTreeMap<String, Vec<String>> {
    let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
    if let Some(response) = response {
        for header in response.headers.iter() {
            map.entry(header.name.to_ascii_lowercase())
                .or_default()
                .push(header.value.clone());
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::message::{HttpResponse, Scheme};
    use crate::models::traffic::{TrafficId, TrafficSource};

    fn request() -> HttpRequest {
        HttpRequest::new("GET", Scheme::Https, "api.rawframe.test", 443, "/v1/users")
    }

    #[test]
    fn valid_requests_pass_and_host_is_optional_in_the_model() {
        let mut request = request();
        assert!(validate_request(&request, 1024).is_ok());

        request.headers.remove_all("Host");
        assert!(validate_request(&request, 1024).is_ok());
    }

    #[test]
    fn invalid_methods_and_targets_are_rejected() {
        let mut request = request();
        request.method = "GE T".into();
        assert!(matches!(
            validate_request(&request, 1024),
            Err(RequestValidationError::InvalidMethod(_))
        ));

        request.method = "GET".into();
        request.target = "relative".into();
        assert!(matches!(
            validate_request(&request, 1024),
            Err(RequestValidationError::InvalidTarget)
        ));

        request.target = "/path with space".into();
        assert!(matches!(
            validate_request(&request, 1024),
            Err(RequestValidationError::TargetControl)
        ));

        request.target = "/path#fragment".into();
        assert!(matches!(
            validate_request(&request, 1024),
            Err(RequestValidationError::TargetFragment)
        ));
    }

    #[test]
    fn connect_is_explicitly_unsupported() {
        let mut request = request();
        request.method = "CONNECT".into();
        assert_eq!(
            validate_request(&request, 1024),
            Err(RequestValidationError::ConnectUnsupported)
        );
    }

    #[test]
    fn header_names_and_values_are_validated() {
        let mut req = request();
        req.headers.append("Bad Header", "x");
        assert!(matches!(
            validate_request(&req, 1024),
            Err(RequestValidationError::InvalidHeaderName(_))
        ));

        let mut req = request();
        req.headers.append("X-Test", "one\r\ntwo");
        assert!(matches!(
            validate_request(&req, 1024),
            Err(RequestValidationError::InvalidHeaderValue(_))
        ));
    }

    #[test]
    fn framing_headers_cannot_be_ambiguous() {
        let mut req = request();
        req.body = b"hello".to_vec();
        req.headers.append("Content-Length", "4");
        assert_eq!(
            validate_request(&req, 1024),
            Err(RequestValidationError::ContentLengthMismatch {
                declared: 4,
                actual: 5
            })
        );

        let mut req = request();
        req.headers.append("Content-Length", "0");
        req.headers.append("Content-Length", "0");
        assert_eq!(
            validate_request(&req, 1024),
            Err(RequestValidationError::DuplicateContentLength)
        );

        let mut req = request();
        req.headers.append("Transfer-Encoding", "chunked");
        req.headers.append("Content-Length", "0");
        assert_eq!(
            validate_request(&req, 1024),
            Err(RequestValidationError::TransferEncodingUnsupported)
        );
    }

    #[test]
    fn body_limit_is_enforced_before_any_network_work() {
        let mut request = request();
        request.body = vec![0; 32];
        assert_eq!(
            validate_request(&request, 16),
            Err(RequestValidationError::BodyTooLarge {
                actual: 32,
                limit: 16
            })
        );
    }

    #[test]
    fn phases_distinguish_active_and_terminal_states() {
        assert!(RepeaterExecutionPhase::Connecting.is_active());
        assert!(!RepeaterExecutionPhase::Draft.is_active());
        assert!(RepeaterExecutionPhase::Blocked.is_terminal());
        assert_eq!(RepeaterExecutionPhase::TimedOut.label(), "TIMED OUT");
    }

    fn result(status: u16, body: &[u8], duration: u64) -> RepeaterResult {
        let mut response = HttpResponse::with_body(status, "text/plain", body);
        response.headers.append("X-Trace", "one");
        RepeaterResult {
            request: request(),
            response: Some(response),
            timings: RepeaterTimings {
                total_ms: duration,
                ..RepeaterTimings::default()
            },
            redirects: Vec::new(),
            truncated: false,
            response_bytes: body.len(),
            error: None,
            warnings: Vec::new(),
            sent_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn comparison_reports_real_differences() {
        let before = result(200, b"hello", 10);
        let mut after = result(201, b"hallo!", 17);
        after
            .response
            .as_mut()
            .unwrap()
            .headers
            .insert("X-Trace", "two");
        let comparison = compare_executions(&before, &after);

        assert_eq!(comparison.status_changed, Some((200, 201)));
        assert_eq!(comparison.duration_delta_ms, 7);
        assert_eq!(comparison.size_delta, 1);
        assert!(comparison.body_changed);
        assert_eq!(comparison.first_body_difference, Some(1));
        assert!(
            comparison
                .header_changes
                .iter()
                .any(|change| change.name == "x-trace")
        );
    }

    #[test]
    fn comparison_handles_identical_executions() {
        let before = result(200, b"same", 10);
        let after = result(200, b"same", 10);
        let comparison = compare_executions(&before, &after);
        assert!(comparison.status_changed.is_none());
        assert!(!comparison.body_changed);
        assert!(comparison.header_changes.is_empty());
    }

    #[test]
    fn repeater_entries_are_not_live_proxy_traffic() {
        let mut entry = TrafficEntry::new(TrafficId(REPEATER_ID_BASE + 1), request());
        entry.source = TrafficSource::Repeater;
        assert!(!entry.is_live_capture());
        assert_eq!(entry.source.label(), "REPEATER");
    }
}
