//! Passive analysis of immutable captured traffic.
//!
//! This crate intentionally has no proxy, network, runtime, storage, or TUI
//! dependency. Analysis is deterministic and never modifies its input.

use chrono::{DateTime, Utc};
use rawframe_core::models::session::SessionId;
use rawframe_core::models::websocket::{WebSocketConnection, WebSocketMessage, WebSocketOpcode};
use rawframe_core::models::{
    message::Scheme,
    traffic::{TrafficEntry, TrafficId, TrafficSource},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::thread::{self, JoinHandle};

pub const RULESET_VERSION: &str = "2";
pub const ANALYSIS_QUEUE_CAPACITY: usize = 64;
pub const ANALYSIS_RESULT_CAPACITY: usize = 64;
pub const MAX_QUEUED_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_SNAPSHOT_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
    Confirmed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Transport,
    Headers,
    Cookies,
    Disclosure,
    WebSocket,
    Protocol,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    New,
    Open,
    Acknowledged,
    Dismissed,
    Resolved,
    Reopened,
}

pub fn valid_status_transition(from: FindingStatus, to: FindingStatus) -> bool {
    use FindingStatus::*;
    from == to
        || matches!(
            (from, to),
            (New, Open | Acknowledged | Dismissed)
                | (Open, Acknowledged | Dismissed | Resolved)
                | (Acknowledged | Dismissed | Resolved, Reopened)
                | (Reopened, Open | Acknowledged | Dismissed | Resolved)
        )
}

pub fn parse_status(value: &str) -> Option<FindingStatus> {
    match value {
        "new" => Some(FindingStatus::New),
        "open" => Some(FindingStatus::Open),
        "acknowledged" => Some(FindingStatus::Acknowledged),
        "dismissed" => Some(FindingStatus::Dismissed),
        "resolved" => Some(FindingStatus::Resolved),
        "reopened" => Some(FindingStatus::Reopened),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSide {
    Request,
    Response,
    WebSocketHandshake,
    WebSocketMessage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub traffic_id: TrafficId,
    pub side: EvidenceSide,
    pub field: String,
    pub value: Option<String>,
    pub explanation: String,
    pub redacted: bool,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub rule_id: String,
    pub rule_version: String,
    pub category: Category,
    pub severity: Severity,
    pub confidence: Confidence,
    pub title: String,
    pub description: String,
    pub technical_explanation: String,
    pub impact: String,
    pub remediation: String,
    pub evidence: Vec<Evidence>,
    pub origin: String,
    pub resource: String,
    pub related_traffic: Vec<TrafficId>,
    pub first_observed: DateTime<Utc>,
    pub last_observed: DateTime<Utc>,
    pub occurrence_count: u64,
    pub status: FindingStatus,
    pub fingerprint: String,
    /// Session scope is assigned by the application/store boundary. Rule
    /// evaluation itself remains independent of persistence.
    #[serde(default)]
    pub session_id: Option<SessionId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleInfo {
    pub id: &'static str,
    pub name: &'static str,
    pub category: Category,
    pub description: &'static str,
    pub severity: Severity,
    pub confidence: Confidence,
}

struct FindingDraft<'a> {
    rule: &'a str,
    category: Category,
    severity: Severity,
    confidence: Confidence,
    title: String,
    description: &'a str,
    impact: &'a str,
    remediation: &'a str,
    side: EvidenceSide,
    field: &'a str,
    value: Option<String>,
    redacted: bool,
    truncated: bool,
    explanation: &'a str,
}

macro_rules! finding {
    ($entry:expr, $rule:expr, $category:expr, $severity:expr, $confidence:expr, $title:expr, $description:expr, $impact:expr, $remediation:expr, $side:expr, $field:expr, $value:expr, $redacted:expr, $truncated:expr, $explanation:expr) => {
        make_finding(
            $entry,
            FindingDraft {
                rule: $rule,
                category: $category,
                severity: $severity,
                confidence: $confidence,
                title: $title.into(),
                description: $description,
                impact: $impact,
                remediation: $remediation,
                side: $side,
                field: $field,
                value: $value,
                redacted: $redacted,
                truncated: $truncated,
                explanation: $explanation,
            },
        )
    };
}

pub const RULES: &[RuleInfo] = &[
    RuleInfo {
        id: "http.missing_hsts",
        name: "Missing HSTS",
        category: Category::Transport,
        description: "HTTPS response does not advertise HTTP Strict Transport Security.",
        severity: Severity::Low,
        confidence: Confidence::High,
    },
    RuleInfo {
        id: "http.missing_nosniff",
        name: "Missing nosniff",
        category: Category::Headers,
        description: "HTML response does not set X-Content-Type-Options to nosniff.",
        severity: Severity::Informational,
        confidence: Confidence::High,
    },
    RuleInfo {
        id: "http.missing_referrer_policy",
        name: "Missing Referrer-Policy",
        category: Category::Headers,
        description: "HTML response does not declare a Referrer-Policy.",
        severity: Severity::Informational,
        confidence: Confidence::High,
    },
    RuleInfo {
        id: "http.missing_csp",
        name: "Missing Content-Security-Policy",
        category: Category::Headers,
        description: "HTML response has no non-empty Content-Security-Policy field.",
        severity: Severity::Informational,
        confidence: Confidence::High,
    },
    RuleInfo {
        id: "http.missing_frame_protection",
        name: "Missing framing protection",
        category: Category::Headers,
        description: "HTML response has no effective CSP frame-ancestors or X-Frame-Options protection.",
        severity: Severity::Informational,
        confidence: Confidence::High,
    },
    RuleInfo {
        id: "http.missing_permissions_policy",
        name: "Missing Permissions-Policy",
        category: Category::Headers,
        description: "HTML response has no non-empty Permissions-Policy field.",
        severity: Severity::Informational,
        confidence: Confidence::High,
    },
    RuleInfo {
        id: "http.cookie_missing_secure",
        name: "Cookie missing Secure",
        category: Category::Cookies,
        description: "A Set-Cookie field lacks the Secure attribute.",
        severity: Severity::Low,
        confidence: Confidence::High,
    },
    RuleInfo {
        id: "http.cookie_missing_httponly",
        name: "Cookie missing HttpOnly",
        category: Category::Cookies,
        description: "A Set-Cookie field lacks the HttpOnly attribute.",
        severity: Severity::Low,
        confidence: Confidence::High,
    },
    RuleInfo {
        id: "http.cookie_missing_samesite",
        name: "Cookie missing SameSite",
        category: Category::Cookies,
        description: "A Set-Cookie field lacks an explicit SameSite attribute.",
        severity: Severity::Informational,
        confidence: Confidence::High,
    },
    RuleInfo {
        id: "websocket.plaintext_transport",
        name: "WebSocket uses plaintext transport",
        category: Category::WebSocket,
        description: "Captured WebSocket handshake used ws:// without TLS.",
        severity: Severity::Medium,
        confidence: Confidence::Confirmed,
    },
    RuleInfo {
        id: "websocket.error_disclosure",
        name: "WebSocket message contains error details",
        category: Category::Disclosure,
        description: "Captured text message contains a conservative stack-trace or debug marker.",
        severity: Severity::Low,
        confidence: Confidence::Low,
    },
    RuleInfo {
        id: "http.plaintext_credentials",
        name: "Credential indicator sent over plaintext HTTP",
        category: Category::Transport,
        description: "Captured HTTP request contains an authentication header or contextually named credential field.",
        severity: Severity::Medium,
        confidence: Confidence::High,
    },
    RuleInfo {
        id: "http.technology_banner",
        name: "Version-bearing technology banner",
        category: Category::Disclosure,
        description: "Response header discloses a server or framework version.",
        severity: Severity::Informational,
        confidence: Confidence::High,
    },
    RuleInfo {
        id: "http.debug_header",
        name: "Debug-related response header",
        category: Category::Disclosure,
        description: "Response contains a known debug or runtime version header.",
        severity: Severity::Low,
        confidence: Confidence::High,
    },
    RuleInfo {
        id: "http.response_error_disclosure",
        name: "Response contains diagnostic details",
        category: Category::Disclosure,
        description: "Response body contains a narrow stack trace, filesystem path, or detailed error marker.",
        severity: Severity::Low,
        confidence: Confidence::Low,
    },
    RuleInfo {
        id: "http.private_address_disclosure",
        name: "Response discloses a private address",
        category: Category::Disclosure,
        description: "Response body contains an RFC1918 IPv4 literal.",
        severity: Severity::Informational,
        confidence: Confidence::Medium,
    },
    RuleInfo {
        id: "websocket.sensitive_message",
        name: "Sensitive field in WebSocket message",
        category: Category::Disclosure,
        description: "Captured complete text message contains a non-empty contextually sensitive field.",
        severity: Severity::Medium,
        confidence: Confidence::Medium,
    },
];

#[derive(Debug, Clone, Default)]
pub struct RuleConfig {
    pub disabled: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct AnalysisResult {
    pub traffic_id: TrafficId,
    /// Optional caller scope disambiguates identical traffic IDs in separate sessions.
    pub scope: Option<String>,
    pub generation: u64,
    pub findings: Vec<Finding>,
}

enum AnalysisJob {
    Analyze {
        entry: Box<TrafficEntry>,
        scope: Option<String>,
        bytes: usize,
        generation: u64,
    },
    AnalyzeWebSocket {
        entry: Box<TrafficEntry>,
        connection: Box<WebSocketConnection>,
        message: Option<Box<WebSocketMessage>>,
        bytes: usize,
        generation: u64,
    },
}

/// One bounded worker keeps parsing and rule evaluation off the TUI thread.
/// Cancellation invalidates queued snapshots by generation; no runtime or
/// networking capability is present in this crate.
pub struct AnalysisScheduler {
    jobs: Option<SyncSender<AnalysisJob>>,
    results: Receiver<AnalysisResult>,
    generation: Arc<AtomicU64>,
    queued_bytes: Arc<AtomicUsize>,
    pending_jobs: Arc<AtomicUsize>,
    join: Option<JoinHandle<()>>,
}

impl AnalysisScheduler {
    pub fn new(config: RuleConfig) -> std::io::Result<Self> {
        let (job_tx, job_rx) = mpsc::sync_channel(ANALYSIS_QUEUE_CAPACITY);
        let (result_tx, result_rx) = mpsc::sync_channel(ANALYSIS_RESULT_CAPACITY);
        let generation = Arc::new(AtomicU64::new(1));
        let queued_bytes = Arc::new(AtomicUsize::new(0));
        let worker_generation = generation.clone();
        let worker_bytes = queued_bytes.clone();
        let pending_jobs = Arc::new(AtomicUsize::new(0));
        let worker_pending = pending_jobs.clone();
        let join = thread::Builder::new()
            .name("rawframe-analysis".into())
            .spawn(move || {
                while let Ok(job) = job_rx.recv() {
                    let (entry, scope, bytes, generation, websocket) = match job {
                        AnalysisJob::Analyze {
                            entry,
                            scope,
                            bytes,
                            generation,
                        } => (entry, scope, bytes, generation, None),
                        AnalysisJob::AnalyzeWebSocket {
                            entry,
                            connection,
                            message,
                            bytes,
                            generation,
                        } => (entry, None, bytes, generation, Some((connection, message))),
                    };
                    if worker_generation.load(Ordering::Acquire) == generation {
                        let mut findings = analyze(&entry, &config);
                        if let Some((connection, message)) = websocket {
                            findings.extend(analyze_websocket(
                                &entry,
                                &connection,
                                message.as_deref(),
                                &config,
                            ));
                            findings = deduplicate(findings);
                        }
                        let result = AnalysisResult {
                            traffic_id: entry.id,
                            scope,
                            generation,
                            findings,
                        };
                        // Backpressure is deliberate: a slow consumer stops
                        // further work instead of growing a result queue.
                        if result_tx.send(result).is_err() {
                            worker_bytes.fetch_sub(bytes, Ordering::AcqRel);
                            worker_pending.fetch_sub(1, Ordering::AcqRel);
                            break;
                        }
                    }
                    worker_bytes.fetch_sub(bytes, Ordering::AcqRel);
                    worker_pending.fetch_sub(1, Ordering::AcqRel);
                }
            })?;
        Ok(Self {
            jobs: Some(job_tx),
            results: result_rx,
            generation,
            queued_bytes,
            pending_jobs,
            join: Some(join),
        })
    }

    pub fn schedule(&self, entry: TrafficEntry) -> Result<u64, ScheduleError> {
        self.schedule_scoped(entry, None)
    }

    pub fn schedule_scoped(
        &self,
        entry: TrafficEntry,
        scope: Option<String>,
    ) -> Result<u64, ScheduleError> {
        let bytes = entry.request.body.len().saturating_add(
            entry
                .response
                .as_ref()
                .map_or(0, |response| response.body.len()),
        );
        if bytes > MAX_SNAPSHOT_BYTES {
            return Err(ScheduleError::SnapshotTooLarge);
        }
        let mut current = self.queued_bytes.load(Ordering::Acquire);
        loop {
            let next = current.saturating_add(bytes.max(1));
            if next > MAX_QUEUED_SNAPSHOT_BYTES {
                return Err(ScheduleError::QueueBytesFull);
            }
            match self.queued_bytes.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
        let generation = self.generation.load(Ordering::Acquire);
        let job = AnalysisJob::Analyze {
            entry: Box::new(entry),
            scope,
            bytes: bytes.max(1),
            generation,
        };
        let Some(sender) = self.jobs.as_ref() else {
            self.queued_bytes.fetch_sub(bytes.max(1), Ordering::AcqRel);
            return Err(ScheduleError::Stopped);
        };
        self.pending_jobs.fetch_add(1, Ordering::AcqRel);
        match sender.try_send(job) {
            Ok(()) => Ok(generation),
            Err(TrySendError::Full(_)) => {
                self.queued_bytes.fetch_sub(bytes.max(1), Ordering::AcqRel);
                self.pending_jobs.fetch_sub(1, Ordering::AcqRel);
                Err(ScheduleError::QueueFull)
            }
            Err(TrySendError::Disconnected(_)) => {
                self.queued_bytes.fetch_sub(bytes.max(1), Ordering::AcqRel);
                self.pending_jobs.fetch_sub(1, Ordering::AcqRel);
                Err(ScheduleError::Stopped)
            }
        }
    }

    pub fn schedule_websocket(
        &self,
        entry: TrafficEntry,
        connection: WebSocketConnection,
        message: Option<WebSocketMessage>,
    ) -> Result<u64, ScheduleError> {
        let bytes = message
            .as_ref()
            .map_or(1, |message| message.payload.len().max(1));
        if bytes > MAX_SNAPSHOT_BYTES {
            return Err(ScheduleError::SnapshotTooLarge);
        }
        reserve_queue_bytes(&self.queued_bytes, bytes)?;
        let generation = self.generation.load(Ordering::Acquire);
        let Some(sender) = self.jobs.as_ref() else {
            self.queued_bytes.fetch_sub(bytes, Ordering::AcqRel);
            return Err(ScheduleError::Stopped);
        };
        self.pending_jobs.fetch_add(1, Ordering::AcqRel);
        match sender.try_send(AnalysisJob::AnalyzeWebSocket {
            entry: Box::new(entry),
            connection: Box::new(connection),
            message: message.map(Box::new),
            bytes,
            generation,
        }) {
            Ok(()) => Ok(generation),
            Err(TrySendError::Full(_)) => {
                self.queued_bytes.fetch_sub(bytes, Ordering::AcqRel);
                self.pending_jobs.fetch_sub(1, Ordering::AcqRel);
                Err(ScheduleError::QueueFull)
            }
            Err(TrySendError::Disconnected(_)) => {
                self.queued_bytes.fetch_sub(bytes, Ordering::AcqRel);
                self.pending_jobs.fetch_sub(1, Ordering::AcqRel);
                Err(ScheduleError::Stopped)
            }
        }
    }

    pub fn cancel_pending(&self) -> u64 {
        self.generation
            .fetch_add(1, Ordering::AcqRel)
            .saturating_add(1)
    }

    pub fn try_result(&self) -> Result<AnalysisResult, mpsc::TryRecvError> {
        self.results.try_recv()
    }

    pub fn queued_bytes(&self) -> usize {
        self.queued_bytes.load(Ordering::Acquire)
    }
    pub fn current_generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }
    pub fn pending_jobs(&self) -> usize {
        self.pending_jobs.load(Ordering::Acquire)
    }
}

fn reserve_queue_bytes(queue: &AtomicUsize, bytes: usize) -> Result<(), ScheduleError> {
    let mut current = queue.load(Ordering::Acquire);
    loop {
        let next = current.saturating_add(bytes);
        if next > MAX_QUEUED_SNAPSHOT_BYTES {
            return Err(ScheduleError::QueueBytesFull);
        }
        match queue.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return Ok(()),
            Err(actual) => current = actual,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScheduleError {
    QueueFull,
    QueueBytesFull,
    SnapshotTooLarge,
    Stopped,
}

impl std::fmt::Display for ScheduleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ScheduleError {}

impl Drop for AnalysisScheduler {
    fn drop(&mut self) {
        self.generation.fetch_add(1, Ordering::AcqRel);
        if let Some(sender) = self.jobs.take() {
            drop(sender);
        }
        if let Some(join) = self.join.take() {
            while !join.is_finished() {
                while self.results.try_recv().is_ok() {}
                thread::sleep(std::time::Duration::from_millis(1));
            }
            let _ = join.join();
        }
    }
}

/// Analyze one captured transaction. Duplicate rule/context findings are folded
/// by a stable fingerprint; input traffic is borrowed and never changed.
pub fn analyze(entry: &TrafficEntry, config: &RuleConfig) -> Vec<Finding> {
    if !matches!(
        entry.source,
        TrafficSource::Intercepted | TrafficSource::Restored
    ) {
        return Vec::new();
    }
    let Some(response) = entry.response.as_ref() else {
        return Vec::new();
    };
    let disabled = |rule: &str| config.disabled.iter().any(|value| value == rule);
    let html = response
        .content_type()
        .is_some_and(|value| value.to_ascii_lowercase().starts_with("text/html"));
    let mut findings = Vec::new();
    if entry.request.scheme == Scheme::Https
        && !response
            .headers
            .get_all("strict-transport-security")
            .any(|v| !v.trim().is_empty())
        && !disabled("http.missing_hsts")
    {
        findings.push(finding!(entry, "http.missing_hsts", Category::Transport, Severity::Low, Confidence::High, "HTTPS response is missing Strict-Transport-Security", "The captured HTTPS response did not advertise HSTS. This is a hardening observation and does not establish that an HTTP downgrade occurred.", "Browsers may continue to accept plaintext HTTP for this origin unless another policy or prior HSTS state applies.", "Configure Strict-Transport-Security at the HTTPS origin after confirming that the entire host is HTTPS-capable.", EvidenceSide::Response, "Strict-Transport-Security", None, false, false, "Header was absent from the captured response."));
    }
    if html {
        if !response
            .headers
            .get_all("x-content-type-options")
            .any(|v| v.eq_ignore_ascii_case("nosniff"))
            && !disabled("http.missing_nosniff")
        {
            findings.push(finding!(entry, "http.missing_nosniff", Category::Headers, Severity::Informational, Confidence::High, "HTML response lacks X-Content-Type-Options: nosniff", "The captured HTML response did not provide the browser MIME-sniffing restriction.", "MIME sniffing can cause browsers to interpret content differently from the declared type in some contexts.", "Set X-Content-Type-Options: nosniff and serve accurate Content-Type values.", EvidenceSide::Response, "X-Content-Type-Options", None, false, false, "Header was absent or did not equal nosniff."));
        }
        if !response
            .headers
            .get_all("referrer-policy")
            .any(|v| !v.trim().is_empty())
            && !disabled("http.missing_referrer_policy")
        {
            findings.push(finding!(entry, "http.missing_referrer_policy", Category::Headers, Severity::Informational, Confidence::High, "HTML response lacks Referrer-Policy", "The captured HTML response did not declare a referrer policy.", "Depending on browser defaults and navigation context, URLs may be disclosed in referrer information.", "Set an explicit policy such as strict-origin-when-cross-origin or no-referrer where appropriate.", EvidenceSide::Response, "Referrer-Policy", None, false, false, "Header was absent from the captured response."));
        }
        if !has_nonempty_header(&response.headers, "content-security-policy")
            && !disabled("http.missing_csp")
        {
            findings.push(finding!(entry, "http.missing_csp", Category::Headers, Severity::Informational, Confidence::High, "HTML response lacks Content-Security-Policy", "The captured HTML response did not declare a CSP.", "A policy can reduce the impact of some injection flaws, but its absence does not establish XSS.", "Design and deploy a restrictive Content-Security-Policy appropriate to the application.", EvidenceSide::Response, "Content-Security-Policy", None, false, false, "No non-empty CSP field was present on this HTML response."));
        }
        let csp_frames = response
            .headers
            .get_all("content-security-policy")
            .any(csp_has_frame_ancestors);
        let xfo_frames = response
            .headers
            .get_all("x-frame-options")
            .any(valid_frame_options);
        if !csp_frames && !xfo_frames && !disabled("http.missing_frame_protection") {
            findings.push(finding!(entry, "http.missing_frame_protection", Category::Headers, Severity::Informational, Confidence::High, "HTML response lacks framing protection", "No effective frame-ancestors or X-Frame-Options directive was observed.", "The response may be embeddable; this observation alone does not prove exploitable clickjacking.", "Set CSP frame-ancestors, or an appropriate X-Frame-Options value for legacy clients.", EvidenceSide::Response, "CSP frame-ancestors / X-Frame-Options", None, false, false, "No recognized framing directive was found in captured response headers."));
        }
        if !has_nonempty_header(&response.headers, "permissions-policy")
            && !disabled("http.missing_permissions_policy")
        {
            findings.push(finding!(entry, "http.missing_permissions_policy", Category::Headers, Severity::Informational, Confidence::High, "HTML response lacks Permissions-Policy", "The captured HTML response did not declare Permissions-Policy.", "Browser features remain governed by defaults and other policy layers.", "Declare only the browser features the application needs, with appropriate origins.", EvidenceSide::Response, "Permissions-Policy", None, false, false, "No non-empty Permissions-Policy field was present."));
        }
    }

    if entry.request.scheme == Scheme::Http && !disabled("http.plaintext_credentials") {
        if entry.request.headers.contains("authorization") {
            findings.push(finding!(entry, "http.plaintext_credentials", Category::Transport, Severity::Medium, Confidence::High, "Authentication header observed over plaintext HTTP", "The captured request carried an Authorization field over HTTP.", "An on-path observer may read or replay authentication material; the header value is not retained here.", "Use HTTPS for authenticated requests and rotate credentials if exposure is suspected.", EvidenceSide::Request, "Authorization", Some("<redacted>".into()), true, false, "Authorization field presence is evidence; the full header value is deliberately withheld."));
        }
        if !entry.body_omitted {
            if entry.request.headers.get("content-type").is_some_and(|v| {
                v.to_ascii_lowercase()
                    .starts_with("application/x-www-form-urlencoded")
            }) && let Ok(form) = std::str::from_utf8(&entry.request.body)
            {
                for key in form.split('&').filter_map(|pair| {
                    pair.split_once('=')
                        .map(|(key, value)| (decode_form_component(key), value))
                }) {
                    if !key.1.is_empty() && is_sensitive_parameter(&key.0) {
                        let label = sensitive_parameter_label(&key.0);
                        findings.push(finding!(entry, "http.plaintext_credentials", Category::Transport, Severity::Medium, Confidence::High, "Sensitive form field observed over plaintext HTTP", "A contextually sensitive, non-empty form field was captured in an HTTP request.", "The value may be exposed to an on-path observer; its content is never copied into the finding.", "Submit credential-bearing forms only over HTTPS.", EvidenceSide::Request, "form field", Some(label.into()), true, entry.body_omitted, "Only the sensitive field category is retained; its value is redacted."));
                    }
                }
            }
            for (key, value) in query_parameters(&entry.request.target) {
                if !value.is_empty() && is_sensitive_parameter(&key) {
                    let label = sensitive_parameter_label(&key);
                    findings.push(finding!(entry, "http.plaintext_credentials", Category::Transport, Severity::Medium, Confidence::High, "Sensitive URL parameter observed over plaintext HTTP", "A contextually sensitive, non-empty URL parameter was captured in an HTTP request.", "URLs may be retained by intermediaries or logs; the parameter value is never copied into the finding.", "Avoid placing credentials in URLs and use HTTPS for all requests.", EvidenceSide::Request, "query parameter", Some(label.into()), true, false, "Only the parameter category is retained; the URL value is redacted."));
                }
            }
            for cookie_header in entry.request.headers.get_all("cookie") {
                if cookie_header.eq_ignore_ascii_case("<redacted>") {
                    continue;
                }
                for cookie in cookie_header.split(';') {
                    let Some((name, value)) = cookie.trim().split_once('=') else {
                        continue;
                    };
                    if !value.trim().is_empty() && is_sensitive_parameter(name) {
                        findings.push(finding!(entry, "http.plaintext_credentials", Category::Transport, Severity::Medium, Confidence::High, "Session-like cookie observed over plaintext HTTP", "A contextually session-related cookie was sent over HTTP.", "An on-path observer may capture the cookie; its value is never copied into the finding.", "Use HTTPS and set Secure on session cookies.", EvidenceSide::Request, "Cookie name", Some(sensitive_parameter_label(name).into()), true, false, "Only a recognized cookie-name category is retained."));
                    }
                }
            }
        }
    }

    if !disabled("http.technology_banner") {
        for header in response.headers.iter().filter(|header| {
            matches!(
                header.name.to_ascii_lowercase().as_str(),
                "server" | "x-powered-by"
            )
        }) {
            if header.value.chars().any(|ch| ch.is_ascii_digit()) {
                findings.push(finding!(entry, "http.technology_banner", Category::Disclosure, Severity::Informational, Confidence::High, "Response discloses a version-bearing technology banner", "A captured server/framework response header contains a version indicator.", "Technology identification can help prioritize research but does not establish a vulnerability.", "Remove unnecessary version details from public response headers where practical.", EvidenceSide::Response, &header.name, Some("version-bearing banner present".into()), false, false, "The version string itself is not copied into the finding."));
            }
        }
    }
    if !disabled("http.debug_header") {
        for header in response.headers.iter().filter(|header| {
            matches!(
                header.name.to_ascii_lowercase().as_str(),
                "x-debug" | "x-debug-token" | "x-aspnet-version" | "x-aspnetmvc-version"
            )
        }) {
            findings.push(finding!(entry, "http.debug_header", Category::Disclosure, Severity::Low, Confidence::High, "Response contains a debug/runtime header", "A known debug or runtime-identification header was present.", "The field may expose implementation details or debug state; no exploitability is inferred.", "Remove debug-only response headers from production responses.", EvidenceSide::Response, &header.name, None, false, false, "Header name is retained; its value is not needed for this observation."));
        }
    }
    if !entry.body_omitted
        && let Some(body) = response_body_text(response)
    {
        let lower = body.to_ascii_lowercase();
        if !disabled("http.response_error_disclosure") {
            let marker = [
                "java.lang.",
                "traceback (most recent call last)",
                "stack trace:",
                "exception in thread ",
                " at /var/www/",
                " at /srv/",
            ]
            .into_iter()
            .find(|marker| lower.contains(marker));
            let detailed_error = response.status >= 500
                && [
                    "uncaught exception",
                    "fatal error",
                    "database connection failed",
                    "internal server error:",
                ]
                .iter()
                .any(|marker| lower.contains(marker));
            if let Some(marker) = marker.or(detailed_error.then_some("server error detail")) {
                findings.push(finding!(entry, "http.response_error_disclosure", Category::Disclosure, Severity::Low, Confidence::Low, "Response may expose diagnostic details", "Captured response content contains a narrow stack-trace or server-error indicator.", "Diagnostic details may reveal implementation behavior or internal paths.", "Return generic client errors and keep detailed diagnostics in protected server logs.", EvidenceSide::Response, "response body marker", Some(marker.into()), false, false, "Only a fixed marker is retained; response body content is not copied."));
            }
        }
        let diagnostic_context = [
            "traceback",
            "stack trace",
            "exception",
            "error",
            "/srv/",
            "/var/www/",
        ]
        .iter()
        .any(|marker| lower.contains(marker));
        if !disabled("http.private_address_disclosure")
            && diagnostic_context
            && contains_private_ipv4(&lower)
        {
            findings.push(finding!(
                entry,
                "http.private_address_disclosure",
                Category::Disclosure,
                Severity::Informational,
                Confidence::Medium,
                "Response contains a private IPv4 address",
                "Captured response text includes an RFC1918 address literal.",
                "Internal addressing can reveal network topology; the address itself is withheld.",
                "Avoid exposing internal addresses in public responses unless required.",
                EvidenceSide::Response,
                "response body address",
                Some("<private IPv4 address redacted>".into()),
                true,
                false,
                "An RFC1918 address was detected; the literal is not persisted."
            ));
        }
    }
    for cookie in response.headers.get_all("set-cookie") {
        if cookie.eq_ignore_ascii_case("<redacted>") || cookie.is_empty() {
            continue;
        }
        let Some((name, _)) = cookie.split_once('=') else {
            continue;
        };
        let name = name.trim();
        if name.is_empty() || name.chars().any(char::is_control) {
            continue;
        }
        let attrs: Vec<&str> = cookie.split(';').skip(1).map(str::trim).collect();
        let has = |attribute: &str| {
            attrs.iter().any(|a| {
                a.split('=')
                    .next()
                    .is_some_and(|key| key.trim().eq_ignore_ascii_case(attribute))
            })
        };
        let prefix_host = name.starts_with("__Host-");
        let prefix_secure = name.starts_with("__Secure-") || prefix_host;
        if !has("secure") && !disabled("http.cookie_missing_secure") {
            findings.push(finding!(entry, "http.cookie_missing_secure", Category::Cookies, Severity::Low, Confidence::High, format!("Cookie {name} lacks Secure"), "A captured Set-Cookie field did not include Secure.", "The browser may send this cookie over plaintext HTTP if it is otherwise in scope.", "Add Secure to cookies that must only travel over HTTPS. __Host- and __Secure- prefixed cookies require it.", EvidenceSide::Response, "Set-Cookie attributes", Some(name.to_string()), false, entry.body_omitted, "Cookie name is retained; the cookie value is never copied into the finding."));
        }
        if !has("httponly") && !disabled("http.cookie_missing_httponly") {
            findings.push(finding!(entry, "http.cookie_missing_httponly", Category::Cookies, Severity::Low, Confidence::High, format!("Cookie {name} lacks HttpOnly"), "A captured Set-Cookie field did not include HttpOnly.", "Client-side scripts may be able to read this cookie; impact depends on its purpose and application behavior.", "Add HttpOnly to cookies that do not need JavaScript access.", EvidenceSide::Response, "Set-Cookie attributes", Some(name.to_string()), false, entry.body_omitted, "Only cookie name and attribute state are retained."));
        }
        if !attrs.iter().any(|a| {
            a.split_once('=')
                .is_some_and(|(key, _)| key.trim().eq_ignore_ascii_case("samesite"))
        }) && !disabled("http.cookie_missing_samesite")
        {
            findings.push(finding!(
                entry,
                "http.cookie_missing_samesite",
                Category::Cookies,
                Severity::Informational,
                Confidence::High,
                format!("Cookie {name} lacks SameSite"),
                "A captured Set-Cookie field did not set SameSite explicitly.",
                "Cross-site cookie behavior may depend on user-agent defaults.",
                "Set an explicit SameSite policy consistent with the cookie's cross-site use.",
                EvidenceSide::Response,
                "Set-Cookie attributes",
                Some(name.to_string()),
                false,
                entry.body_omitted,
                "Only cookie name and attribute state are retained."
            ));
        }
        // Prefix constraints are protocol requirements; do not make additional
        // claims from malformed cookies beyond the missing Secure observation.
        let _ = prefix_secure;
    }
    deduplicate(findings)
}

/// Analyze captured WebSocket metadata and one reassembled message. Binary,
/// omitted, incomplete, and truncated payloads are never interpreted as text.
pub fn analyze_websocket(
    entry: &TrafficEntry,
    connection: &WebSocketConnection,
    message: Option<&WebSocketMessage>,
    config: &RuleConfig,
) -> Vec<Finding> {
    if connection.source != TrafficSource::Intercepted
        && connection.source != TrafficSource::Restored
    {
        return Vec::new();
    }
    let mut findings = Vec::new();
    if !connection.tls
        && !config
            .disabled
            .iter()
            .any(|id| id == "websocket.plaintext_transport")
    {
        findings.push(finding!(
            entry,
            "websocket.plaintext_transport",
            Category::WebSocket,
            Severity::Medium,
            Confidence::Confirmed,
            "WebSocket handshake used plaintext transport",
            "The captured WebSocket connection did not use TLS.",
            "Messages and handshake metadata can be observed or modified by an on-path party.",
            "Use wss:// for WebSocket connections that carry sensitive or authenticated data.",
            EvidenceSide::WebSocketHandshake,
            "transport",
            Some("ws://".into()),
            false,
            false,
            "Captured connection metadata reports TLS disabled."
        ));
    }
    let Some(message) = message else {
        return deduplicate(findings);
    };
    if message.opcode != WebSocketOpcode::Text
        || message.payload_omitted
        || message.truncated
        || !message.complete
    {
        return deduplicate(findings);
    }
    let Ok(text) = std::str::from_utf8(&message.payload) else {
        return deduplicate(findings);
    };
    let lower = text.to_ascii_lowercase();
    if !config
        .disabled
        .iter()
        .any(|id| id == "websocket.error_disclosure")
    {
        let marker = [
            "java.lang.",
            " at /var/www/",
            "stack trace:",
            "traceback (most recent call last)",
            "exception in thread ",
        ]
        .into_iter()
        .find(|marker| lower.contains(marker));
        if let Some(marker) = marker {
            let mut finding = finding!(
                entry,
                "websocket.error_disclosure",
                Category::Disclosure,
                Severity::Low,
                Confidence::Low,
                "WebSocket message may disclose error details",
                "A captured text message contains a stack-trace or debug marker.",
                "Error details may reveal implementation paths or framework behavior.",
                "Return generic client errors and keep diagnostic traces in protected server logs.",
                EvidenceSide::WebSocketMessage,
                &format!("message #{}", message.id.0),
                Some(marker.to_string()),
                false,
                false,
                "Only the matched marker and message identifier are retained; payload contents are not copied."
            );
            finding.fingerprint = format!(
                "websocket.error_disclosure|{}|{}|{}",
                finding.origin, finding.resource, marker
            );
            finding.id = finding.fingerprint.clone();
            findings.push(finding);
        }
    }
    if !config
        .disabled
        .iter()
        .any(|id| id == "websocket.sensitive_message")
    {
        for label in sensitive_fields(text).into_iter().take(16) {
            let mut finding = finding!(
                entry,
                "websocket.sensitive_message",
                Category::Disclosure,
                Severity::Medium,
                Confidence::Medium,
                "WebSocket text message contains a sensitive field",
                "A complete captured text message contains a non-empty password, token, or session-like field.",
                "The field may expose authentication material to message recipients or other observers; its value is never retained.",
                "Avoid sending reusable secrets in WebSocket messages and protect authenticated channels with WSS.",
                EvidenceSide::WebSocketMessage,
                &format!("message #{} · {label}", message.id.0),
                Some(format!("non-empty {label} field")),
                false,
                false,
                "Only the message ID and normalized field category are stored; raw payload values are excluded."
            );
            finding.fingerprint = format!(
                "websocket.sensitive_message|{}|{}|{label}",
                finding.origin, finding.resource
            );
            finding.id = finding.fingerprint.clone();
            findings.push(finding);
        }
    }
    deduplicate(findings)
}

fn has_nonempty_header(headers: &rawframe_core::models::headers::Headers, name: &str) -> bool {
    headers.get_all(name).any(|value| !value.trim().is_empty())
}

fn csp_has_frame_ancestors(value: &str) -> bool {
    value
        .split(';')
        .filter_map(|directive| directive.split_whitespace().next())
        .any(|name| name.eq_ignore_ascii_case("frame-ancestors"))
}

fn valid_frame_options(value: &str) -> bool {
    let value = value.trim();
    value.eq_ignore_ascii_case("deny") || value.eq_ignore_ascii_case("sameorigin")
}

fn sensitive_parameter_label(name: &str) -> &'static str {
    let normalized = name
        .trim()
        .trim_matches(['"', '\'', '`'])
        .to_ascii_lowercase()
        .replace(['-', '_'], "");
    if normalized.contains("password") || normalized == "passwd" || normalized == "pwd" {
        "password"
    } else if normalized.contains("session") || normalized == "sid" {
        "session"
    } else if normalized.contains("token")
        || normalized.contains("apikey")
        || normalized.contains("secret")
    {
        "token"
    } else {
        "authentication"
    }
}

fn is_sensitive_parameter(name: &str) -> bool {
    let normalized = name
        .trim()
        .trim_matches(['"', '\'', '`'])
        .to_ascii_lowercase()
        .replace(['-', '_'], "");
    [
        "password",
        "passwd",
        "pwd",
        "token",
        "accesstoken",
        "refreshtoken",
        "session",
        "sessionid",
        "sid",
        "apikey",
        "clientsecret",
        "authorization",
        "auth",
    ]
    .contains(&normalized.as_str())
}

fn decode_form_component(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let pair = &value[index + 1..index + 3];
                if let Ok(byte) = u8::from_str_radix(pair, 16) {
                    decoded.push(byte);
                    index += 3;
                } else {
                    decoded.push(bytes[index]);
                    index += 1;
                }
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

fn query_parameters(target: &str) -> Vec<(String, String)> {
    target.split_once('?').map_or_else(Vec::new, |(_, query)| {
        query
            .split('&')
            .filter_map(|pair| {
                let (key, value) = pair.split_once('=')?;
                Some((decode_form_component(key), value.to_string()))
            })
            .collect()
    })
}

fn response_body_text(response: &rawframe_core::models::message::HttpResponse) -> Option<String> {
    if response.body.is_empty() {
        return None;
    }
    let content_type = response
        .content_type()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if !(content_type.starts_with("text/")
        || content_type.contains("json")
        || content_type.contains("xml"))
    {
        return None;
    }
    std::str::from_utf8(&response.body).ok().map(str::to_owned)
}

fn contains_private_ipv4(text: &str) -> bool {
    text.split(|ch: char| !(ch.is_ascii_digit() || ch == '.'))
        .any(|candidate| {
            candidate
                .parse::<std::net::Ipv4Addr>()
                .is_ok_and(|ip| ip.is_private())
        })
}

fn sensitive_fields(text: &str) -> Vec<&'static str> {
    let mut labels = Vec::new();
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(text) {
        fn walk(value: &serde_json::Value, labels: &mut Vec<&'static str>) {
            match value {
                serde_json::Value::Object(map) => {
                    for (key, value) in map {
                        if is_sensitive_parameter(key) && sensitive_value(value) {
                            labels.push(sensitive_parameter_label(key));
                        }
                        walk(value, labels);
                    }
                }
                serde_json::Value::Array(values) => {
                    for value in values {
                        walk(value, labels);
                    }
                }
                _ => {}
            }
        }
        walk(&value, &mut labels);
    }
    for part in text.split(['&', ';', ',', '\n', '\r', '\t', ' ']) {
        let Some((key, value)) = part.split_once(['=', ':']) else {
            continue;
        };
        if is_sensitive_parameter(key) && !value.trim_matches(['"', '\'', '}', ']']).is_empty() {
            labels.push(sensitive_parameter_label(key));
        }
    }
    labels.sort_unstable();
    labels.dedup();
    labels
}

fn sensitive_value(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(value) => {
            !value.trim().is_empty()
                && !matches!(value.as_str(), "<redacted>" | "REDACTED" | "null")
        }
        serde_json::Value::Number(_) => true,
        _ => false,
    }
}

fn make_finding(entry: &TrafficEntry, draft: FindingDraft<'_>) -> Finding {
    let FindingDraft {
        rule,
        category,
        severity,
        confidence,
        title,
        description,
        impact,
        remediation,
        side,
        field,
        value,
        redacted,
        truncated,
        explanation,
    } = draft;
    let origin = format!(
        "{}://{}:{}",
        entry.request.scheme,
        entry.request.host.to_ascii_lowercase(),
        entry.request.port
    );
    let path = entry.request.target.split('?').next().unwrap_or("/");
    let digest = Sha256::digest(path.as_bytes());
    let resource = format!(
        "path-sha256:{}",
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    let fingerprint = format!(
        "{rule}|{origin}|{resource}|{field}|{}",
        value.as_deref().unwrap_or("")
    );
    Finding {
        id: fingerprint.clone(),
        rule_id: rule.to_string(),
        rule_version: RULESET_VERSION.into(),
        category,
        severity,
        confidence,
        title,
        description: description.into(),
        technical_explanation: explanation.into(),
        impact: impact.into(),
        remediation: remediation.into(),
        evidence: vec![Evidence {
            traffic_id: entry.id,
            side,
            field: field.into(),
            value,
            explanation: explanation.into(),
            redacted,
            truncated,
        }],
        origin,
        resource,
        related_traffic: vec![entry.id],
        first_observed: entry.timings.started_at,
        last_observed: entry.timings.started_at,
        occurrence_count: 1,
        status: FindingStatus::New,
        fingerprint,
        session_id: None,
    }
}

fn deduplicate(findings: Vec<Finding>) -> Vec<Finding> {
    let mut indexed = BTreeMap::new();
    for finding in findings {
        indexed
            .entry(finding.fingerprint.clone())
            .or_insert(finding);
    }
    indexed.into_values().collect()
}

/// Merge observations from distinct captured entries. Existing analyst choices
/// survive reanalysis; a finding marked resolved is reopened only when evidence
/// for its fingerprint is observed again.
pub fn merge_observations(
    existing: &mut BTreeMap<String, Finding>,
    incoming: impl IntoIterator<Item = Finding>,
) {
    for mut observation in incoming {
        match existing.get_mut(&observation.fingerprint) {
            Some(current) => {
                current.first_observed = current.first_observed.min(observation.first_observed);
                current.last_observed = current.last_observed.max(observation.last_observed);
                let new_traffic = observation
                    .related_traffic
                    .iter()
                    .any(|id| !current.related_traffic.contains(id));
                let new_message = observation.evidence.iter().any(|evidence| {
                    evidence.side == EvidenceSide::WebSocketMessage
                        && !current.evidence.contains(evidence)
                });
                let new_occurrence = new_traffic || new_message;
                if new_occurrence {
                    current.occurrence_count = current
                        .occurrence_count
                        .saturating_add(observation.occurrence_count);
                }
                for id in observation.related_traffic.drain(..) {
                    if !current.related_traffic.contains(&id) {
                        current.related_traffic.push(id);
                    }
                }
                for evidence in observation.evidence.drain(..) {
                    if !current.evidence.contains(&evidence) {
                        current.evidence.push(evidence);
                    }
                }
                if new_occurrence && current.status == FindingStatus::Resolved {
                    current.status = FindingStatus::Reopened;
                }
            }
            None => {
                existing.insert(observation.fingerprint.clone(), observation);
            }
        }
    }
}

/// Serialize a report using only the already-redacted structured finding data.
pub fn export_json(
    project: &str,
    session: &str,
    analyzed_at: DateTime<Utc>,
    findings: &[Finding],
) -> Result<String, serde_json::Error> {
    #[derive(Serialize)]
    struct Report<'a> {
        project: &'a str,
        session: &'a str,
        analyzed_at: DateTime<Utc>,
        ruleset_version: &'static str,
        limitations: &'static str,
        findings: &'a [Finding],
    }
    serde_json::to_string_pretty(&Report {
        project,
        session,
        analyzed_at,
        ruleset_version: RULESET_VERSION,
        limitations: "Passive observations of captured traffic only; findings do not establish exploitation and may have context-dependent false positives.",
        findings,
    })
}

/// Render a concise, human-readable report. Values in evidence are bounded
/// metadata produced by the rules, never raw traffic bodies or credentials.
pub fn export_markdown(
    project: &str,
    session: &str,
    analyzed_at: DateTime<Utc>,
    findings: &[Finding],
) -> String {
    let mut out = format!(
        "# RAWFRAME Passive Analysis\n\nProject: {project}  \nSession: {session}  \nAnalyzed: {}  \nRuleset: {}\n\nFindings: {}\n",
        analyzed_at.to_rfc3339(),
        RULESET_VERSION,
        findings.len()
    );
    for finding in findings {
        out.push_str(&format!("\n## {} — {:?} ({:?} confidence)\n\n- Rule: `{}` v{}\n- Session: `{}`\n- Target: `{}` `{}`\n- Status: {:?}\n- First observed: {}\n- Last observed: {}\n- Occurrences: {}\n\n{}\n\n**Impact:** {}\n\n**Remediation:** {}\n\n**Evidence:**\n", finding.title, finding.severity, finding.confidence, finding.rule_id, finding.rule_version, finding.session_id.as_ref().map_or("unavailable", |id| id.0.as_str()), finding.origin, finding.resource, finding.status, finding.first_observed.to_rfc3339(), finding.last_observed.to_rfc3339(), finding.occurrence_count, finding.description, finding.impact, finding.remediation));
        for evidence in &finding.evidence {
            out.push_str(&format!(
                "- Traffic {} {:?} `{}`{}: {}\n",
                evidence.traffic_id,
                evidence.side,
                evidence.field,
                evidence
                    .value
                    .as_deref()
                    .map(|v| format!(" = {v}"))
                    .unwrap_or_default(),
                evidence.explanation
            ));
        }
    }
    out.push_str("\nThese are passive observations of captured traffic. They do not establish exploitation. Applicability and false positives depend on deployment and client context.\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rawframe_core::models::{
        message::{HttpRequest, HttpResponse},
        traffic::{TrafficEntry, TrafficId},
        websocket::{
            WebSocketConnection, WebSocketConnectionId, WebSocketConnectionState,
            WebSocketDirection, WebSocketMessage, WebSocketMessageId, WebSocketOpcode,
        },
    };
    use std::collections::BTreeSet;
    use std::time::Duration;

    fn sample(scheme: Scheme, content_type: &str, cookies: &[&str]) -> TrafficEntry {
        let request = HttpRequest::new(
            "GET",
            scheme,
            "example.test",
            scheme.default_port(),
            "/page?token=DO_NOT_PERSIST",
        );
        let mut response = HttpResponse::with_body(200, content_type, b"hello".to_vec());
        for cookie in cookies {
            response.headers.append("Set-Cookie", *cookie);
        }
        let mut entry = TrafficEntry::new(TrafficId(41), request);
        entry.response = Some(response);
        entry
    }

    fn ws_connection(tls: bool) -> WebSocketConnection {
        WebSocketConnection {
            id: WebSocketConnectionId(9),
            source: TrafficSource::Intercepted,
            host: "example.test".into(),
            port: if tls { 443 } else { 80 },
            path: "/socket".into(),
            tls,
            subprotocol: None,
            extensions: None,
            state: WebSocketConnectionState::Open,
            started_at: Utc::now(),
            closed_at: None,
            frames: 1,
            messages: 1,
            bytes_client_to_server: 0,
            bytes_server_to_client: 0,
            error: None,
        }
    }

    fn ws_message(opcode: WebSocketOpcode, payload: &[u8]) -> WebSocketMessage {
        WebSocketMessage {
            id: WebSocketMessageId(17),
            connection_id: WebSocketConnectionId(9),
            direction: WebSocketDirection::ServerToClient,
            opcode,
            payload: payload.into(),
            payload_len: payload.len(),
            payload_omitted: false,
            frame_ids: vec![],
            complete: true,
            truncated: false,
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn websocket_rules_are_conservative_and_never_copy_payloads() {
        let entry = sample(Scheme::Http, "application/octet-stream", &[]);
        let insecure = ws_connection(false);
        let handshake_only = analyze_websocket(&entry, &insecure, None, &RuleConfig::default());
        assert_eq!(handshake_only.len(), 1);
        assert_eq!(handshake_only[0].rule_id, "websocket.plaintext_transport");
        let error = ws_message(
            WebSocketOpcode::Text,
            b"java.lang.IllegalStateException: /srv/app/hidden",
        );
        let found = analyze_websocket(&entry, &insecure, Some(&error), &RuleConfig::default());
        assert!(
            found
                .iter()
                .any(|f| f.rule_id == "websocket.plaintext_transport")
        );
        let disclosure = found
            .iter()
            .find(|f| f.rule_id == "websocket.error_disclosure")
            .unwrap();
        assert_eq!(disclosure.confidence, Confidence::Low);
        let serialized = serde_json::to_string(&found).unwrap();
        assert!(!serialized.contains("/srv/app/hidden"));
        assert!(serialized.contains("message #17"));

        let next_message = WebSocketMessage {
            id: WebSocketMessageId(18),
            ..error.clone()
        };
        let next = analyze_websocket(
            &entry,
            &insecure,
            Some(&next_message),
            &RuleConfig::default(),
        );
        let mut merged = BTreeMap::new();
        merge_observations(&mut merged, found.clone());
        merge_observations(&mut merged, next);
        let disclosure = merged
            .values()
            .find(|f| f.rule_id == "websocket.error_disclosure")
            .unwrap();
        assert_eq!(disclosure.occurrence_count, 2);
        assert_eq!(disclosure.evidence.len(), 2);

        let secure = ws_connection(true);
        let ordinary = ws_message(WebSocketOpcode::Text, b"connected");
        assert!(
            analyze_websocket(&entry, &secure, Some(&ordinary), &RuleConfig::default()).is_empty()
        );
        let binary = ws_message(WebSocketOpcode::Binary, b"java.lang.secret");
        assert!(
            analyze_websocket(&entry, &secure, Some(&binary), &RuleConfig::default()).is_empty()
        );
    }

    #[test]
    fn websocket_incomplete_redacted_and_truncated_text_is_not_interpreted() {
        let entry = sample(Scheme::Https, "application/octet-stream", &[]);
        let secure = ws_connection(true);
        let mut message = ws_message(WebSocketOpcode::Text, b"stack trace:");
        message.truncated = true;
        assert!(
            analyze_websocket(&entry, &secure, Some(&message), &RuleConfig::default()).is_empty()
        );
        message.truncated = false;
        message.payload_omitted = true;
        message.payload.clear();
        assert!(
            analyze_websocket(&entry, &secure, Some(&message), &RuleConfig::default()).is_empty()
        );
        message.payload_omitted = false;
        message.complete = false;
        assert!(
            analyze_websocket(&entry, &secure, Some(&message), &RuleConfig::default()).is_empty()
        );
    }

    #[test]
    fn detects_contextual_https_and_html_headers_without_secrets() {
        let entry = sample(
            Scheme::Https,
            "text/html; charset=utf-8",
            &["sid=topsecret; Path=/"],
        );
        let findings = analyze(&entry, &RuleConfig::default());
        assert!(findings.iter().any(|f| f.rule_id == "http.missing_hsts"));
        assert!(findings.iter().any(|f| f.rule_id == "http.missing_nosniff"));
        assert!(findings.iter().any(|f| f.title.contains("sid")));
        let serialized = serde_json::to_string(&findings).unwrap();
        assert!(!serialized.contains("topsecret"));
        assert!(!serialized.contains("DO_NOT_PERSIST"));
    }

    #[test]
    fn secure_irrelevant_and_well_configured_fields_are_not_reported() {
        let mut entry = sample(
            Scheme::Http,
            "image/png",
            &["__Host-id=x; Secure; HttpOnly; SameSite=Strict; Path=/"],
        );
        entry.request.target = "/image.png".into();
        entry
            .response
            .as_mut()
            .unwrap()
            .headers
            .append("X-Content-Type-Options", "nosniff");
        entry
            .response
            .as_mut()
            .unwrap()
            .headers
            .append("Referrer-Policy", "no-referrer");
        let headers = &mut entry.response.as_mut().unwrap().headers;
        headers.append(
            "Content-Security-Policy",
            "default-src 'self'; frame-ancestors 'none'",
        );
        headers.append("Permissions-Policy", "camera=()");
        assert!(analyze(&entry, &RuleConfig::default()).is_empty());
    }

    #[test]
    fn each_http_header_rule_has_independent_applicability_and_empty_boundary_coverage() {
        let mut https = sample(Scheme::Https, "text/html", &[]);
        https
            .response
            .as_mut()
            .unwrap()
            .headers
            .append("sTrIcT-tRaNsPoRt-SeCuRiTy", "");
        let rules: Vec<_> = analyze(&https, &RuleConfig::default())
            .into_iter()
            .map(|f| f.rule_id)
            .collect();
        assert!(rules.contains(&"http.missing_hsts".into()));
        assert!(rules.contains(&"http.missing_nosniff".into()));
        assert!(rules.contains(&"http.missing_referrer_policy".into()));

        let mut http = sample(Scheme::Http, "text/html", &[]);
        http.response
            .as_mut()
            .unwrap()
            .headers
            .append("X-Content-Type-Options", "nosniff");
        http.response
            .as_mut()
            .unwrap()
            .headers
            .append("Referrer-Policy", "no-referrer");
        let rules: Vec<_> = analyze(&http, &RuleConfig::default())
            .into_iter()
            .map(|f| f.rule_id)
            .collect();
        assert!(!rules.contains(&"http.missing_hsts".into()));
        assert!(!rules.contains(&"http.missing_nosniff".into()));
        assert!(!rules.contains(&"http.missing_referrer_policy".into()));

        http.response
            .as_mut()
            .unwrap()
            .headers
            .append("Referrer-Policy", "");
        assert!(
            !analyze(&http, &RuleConfig::default())
                .iter()
                .any(|f| f.rule_id == "http.missing_referrer_policy")
        );
    }

    #[test]
    fn cookie_attributes_are_case_insensitive_and_values_with_commas_are_not_split() {
        let entry = sample(
            Scheme::Https,
            "text/html",
            &[
                "sid=\"alpha,beta\"; Path=/; sAmEsItE=Lax; HttpOnly",
                "__Host-id=hidden; Path=/; HttpOnly; SameSite=Strict",
                "__Secure-key=value; Secure; HttpOnly; SameSite=None",
                "malformed-cookie",
            ],
        );
        let findings = analyze(&entry, &RuleConfig::default());
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "http.cookie_missing_secure" && f.title.contains("sid"))
        );
        assert!(findings.iter().any(|f| f.rule_id == "http.cookie_missing_secure" && f.title.contains("__Host-id")));
        assert!(
            !findings
                .iter()
                .any(|f| f.rule_id.starts_with("http.cookie_") && f.title.contains("__Secure-key"))
        );
        let encoded = serde_json::to_string(&findings).unwrap();
        assert!(!encoded.contains("alpha,beta"));
        assert!(!encoded.contains("hidden"));
    }

    #[test]
    fn header_rules_cover_csp_framing_permissions_duplicates_and_non_html_context() {
        let mut entry = sample(Scheme::Https, "text/html", &[]);
        let initial = analyze(&entry, &RuleConfig::default());
        assert!(initial.iter().any(|f| f.rule_id == "http.missing_csp"));
        assert!(
            initial
                .iter()
                .any(|f| f.rule_id == "http.missing_frame_protection")
        );
        assert!(
            initial
                .iter()
                .any(|f| f.rule_id == "http.missing_permissions_policy")
        );
        let headers = &mut entry.response.as_mut().unwrap().headers;
        headers.append("Content-Security-Policy", "default-src 'self'");
        headers.append("Content-Security-Policy", "frame-ancestors 'self'");
        headers.append("X-Frame-Options", "DENY");
        headers.append("Permissions-Policy", "camera=()");
        let findings = analyze(&entry, &RuleConfig::default());
        assert!(!findings.iter().any(|f| matches!(
            f.rule_id.as_str(),
            "http.missing_csp"
                | "http.missing_frame_protection"
                | "http.missing_permissions_policy"
        )));

        let mut irrelevant = sample(Scheme::Https, "image/png", &[]);
        irrelevant
            .response
            .as_mut()
            .unwrap()
            .headers
            .append("X-Frame-Options", "ALLOW-FROM https://example.test");
        assert!(
            !analyze(&irrelevant, &RuleConfig::default())
                .iter()
                .any(|f| f.rule_id == "http.missing_frame_protection")
        );
    }

    #[test]
    fn plaintext_credential_rule_is_contextual_and_redacts_basic_form_url_and_cookie_values() {
        let mut request = HttpRequest::new(
            "POST",
            Scheme::Http,
            "example.test",
            80,
            "/login?access_token=url-secret",
        );
        request
            .headers
            .append("Authorization", "Basic YWxpY2U6cGFzc3dvcmQtc2VjcmV0");
        request
            .headers
            .append("Content-Type", "application/x-www-form-urlencoded");
        request
            .headers
            .append("Cookie", "sid=session-secret; theme=dark");
        request.body = b"password=form-secret&note=ordinary".to_vec();
        let mut entry = TrafficEntry::new(TrafficId(91), request);
        entry.response = Some(HttpResponse::with_body(200, "text/plain", b"ok".to_vec()));
        let findings = analyze(&entry, &RuleConfig::default())
            .into_iter()
            .filter(|f| f.rule_id == "http.plaintext_credentials")
            .collect::<Vec<_>>();
        assert!(findings.len() >= 4);
        let json = serde_json::to_string(&findings).unwrap();
        for secret in [
            "YWxpY2U6",
            "password-secret",
            "form-secret",
            "url-secret",
            "session-secret",
        ] {
            assert!(!json.contains(secret));
        }
        assert!(
            findings
                .iter()
                .all(|f| f.evidence.iter().all(|e| e.redacted))
        );

        let mut https = sample(Scheme::Https, "text/html", &[]);
        https
            .request
            .headers
            .append("Authorization", "Basic private");
        https.request.target = "/login?password=private".into();
        assert!(
            !analyze(&https, &RuleConfig::default())
                .iter()
                .any(|f| f.rule_id == "http.plaintext_credentials")
        );

        let mut omitted = entry.clone();
        omitted.body_omitted = true;
        let findings = analyze(&omitted, &RuleConfig::default());
        assert!(
            !findings
                .iter()
                .any(|f| f.evidence.iter().any(|e| e.field == "form field"))
        );
    }

    #[test]
    fn disclosure_rules_require_version_debug_or_diagnostic_context() {
        let mut entry = sample(Scheme::Https, "text/plain", &[]);
        let response = entry.response.as_mut().unwrap();
        response.headers.append("Server", "ExampleServer/2.4");
        response.headers.append("X-Debug-Token", "debug-secret");
        response.status = 500;
        response.body =
            b"Traceback (most recent call last): /srv/private/app.py 192.168.10.5".to_vec();
        let findings = analyze(&entry, &RuleConfig::default());
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "http.technology_banner")
        );
        assert!(findings.iter().any(|f| f.rule_id == "http.debug_header"));
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "http.response_error_disclosure")
        );
        let private = findings
            .iter()
            .find(|f| f.rule_id == "http.private_address_disclosure")
            .unwrap();
        assert!(private.evidence[0].redacted);
        let text = serde_json::to_string(&findings).unwrap();
        for secret in ["debug-secret", "192.168.10.5", "/srv/private/app.py"] {
            assert!(!text.contains(secret));
        }

        let mut ordinary = sample(Scheme::Https, "text/plain", &[]);
        ordinary
            .response
            .as_mut()
            .unwrap()
            .headers
            .append("Server", "ExampleServer");
        ordinary.response.as_mut().unwrap().body =
            b"The app handles 192.168.10.5 in this example".to_vec();
        assert!(
            !analyze(&ordinary, &RuleConfig::default())
                .iter()
                .any(|f| f.rule_id == "http.technology_banner"
                    || f.rule_id == "http.private_address_disclosure"
                    || f.rule_id == "http.response_error_disclosure")
        );
    }

    #[test]
    fn websocket_sensitive_json_fields_are_redacted_and_deduplicated() {
        let entry = sample(Scheme::Https, "application/octet-stream", &[]);
        let secure = ws_connection(true);
        let message = ws_message(
            WebSocketOpcode::Text,
            br#"{"access_token":"ws-secret-abc","event":"login"}"#,
        );
        let findings = analyze_websocket(&entry, &secure, Some(&message), &RuleConfig::default());
        let sensitive = findings
            .iter()
            .find(|f| f.rule_id == "websocket.sensitive_message")
            .unwrap();
        assert_eq!(sensitive.confidence, Confidence::Medium);
        assert!(sensitive.evidence[0].field.contains("message #17"));
        let json = serde_json::to_string(&findings).unwrap();
        assert!(!json.contains("ws-secret-abc"));
        let next = WebSocketMessage {
            id: WebSocketMessageId(18),
            ..message.clone()
        };
        let mut aggregate = BTreeMap::new();
        merge_observations(&mut aggregate, findings.clone());
        merge_observations(
            &mut aggregate,
            analyze_websocket(&entry, &secure, Some(&next), &RuleConfig::default()),
        );
        let same = aggregate
            .values()
            .find(|f| f.rule_id == "websocket.sensitive_message")
            .unwrap();
        assert_eq!(same.occurrence_count, 2);
        assert_eq!(same.evidence.len(), 2);

        let ordinary = ws_message(
            WebSocketOpcode::Text,
            b"passwords are important; contact support",
        );
        assert!(
            !analyze_websocket(&entry, &secure, Some(&ordinary), &RuleConfig::default())
                .iter()
                .any(|f| f.rule_id == "websocket.sensitive_message")
        );
    }

    #[test]
    fn redacted_cookie_and_disabled_rules_are_skipped() {
        let entry = sample(Scheme::Https, "text/html", &["<redacted>"]);
        let disabled = RuleConfig {
            disabled: RULES.iter().map(|rule| rule.id.to_string()).collect(),
        };
        assert!(analyze(&entry, &disabled).is_empty());
        assert!(
            !analyze(&entry, &RuleConfig::default())
                .iter()
                .any(|f| f.category == Category::Cookies)
        );
    }

    #[test]
    fn repeated_set_cookie_fields_are_distinct_and_header_order_does_not_change_ids() {
        let first = sample(Scheme::Https, "text/html", &["a=secret1", "b=secret2"]);
        let findings = analyze(&first, &RuleConfig::default());
        assert!(findings.iter().any(|f| f.title.contains("a")));
        assert!(findings.iter().any(|f| f.title.contains("b")));
        assert!(findings.iter().all(|f| !f.fingerprint.contains("secret")));
    }

    #[test]
    fn http2_uses_shared_representation_and_query_values_never_enter_fingerprints() {
        let mut entry = sample(Scheme::Https, "text/html", &[]);
        entry.request.version = "HTTP/2".into();
        entry.response.as_mut().unwrap().version = "HTTP/2".into();
        let findings = analyze(&entry, &RuleConfig::default());
        assert!(!findings.is_empty());
        assert!(findings.iter().all(|f| !f.fingerprint.contains("token")));
    }

    #[test]
    fn path_values_are_not_persisted_and_simulated_rows_are_excluded() {
        let mut entry = sample(Scheme::Https, "text/html", &[]);
        entry.request.target = "/reset/sensitive-path-token".into();
        let findings = analyze(&entry, &RuleConfig::default());
        let serialized = serde_json::to_string(&findings).unwrap();
        assert!(!serialized.contains("sensitive-path-token"));
        assert!(
            findings
                .iter()
                .all(|finding| finding.resource.starts_with("path-sha256:"))
        );
        entry.source = TrafficSource::Simulated;
        assert!(analyze(&entry, &RuleConfig::default()).is_empty());
    }

    #[test]
    fn merge_updates_counts_and_preserves_dismissal_then_reopens_resolved() {
        let entry = sample(Scheme::Https, "text/html", &[]);
        let first = analyze(&entry, &RuleConfig::default()).remove(0);
        let mut store = BTreeMap::new();
        merge_observations(&mut store, [first.clone()]);
        store.get_mut(&first.fingerprint).unwrap().status = FindingStatus::Dismissed;
        let mut repeated = first.clone();
        repeated.related_traffic = vec![TrafficId(42)];
        for evidence in &mut repeated.evidence {
            evidence.traffic_id = TrafficId(42);
        }
        merge_observations(&mut store, [repeated.clone()]);
        assert_eq!(store[&first.fingerprint].occurrence_count, 2);
        assert_eq!(store[&first.fingerprint].status, FindingStatus::Dismissed);
        store.get_mut(&first.fingerprint).unwrap().status = FindingStatus::Resolved;
        let mut later = repeated;
        later.related_traffic = vec![TrafficId(43)];
        for evidence in &mut later.evidence {
            evidence.traffic_id = TrafficId(43);
        }
        merge_observations(&mut store, [later]);
        assert_eq!(store[&first.fingerprint].status, FindingStatus::Reopened);
    }

    #[test]
    fn lifecycle_transition_matrix_rejects_invalid_shortcuts() {
        use FindingStatus::*;
        for (from, to) in [
            (New, Acknowledged),
            (New, Dismissed),
            (Acknowledged, Reopened),
            (Dismissed, Reopened),
            (Open, Resolved),
            (Resolved, Reopened),
            (Reopened, Open),
        ] {
            assert!(valid_status_transition(from, to), "{from:?} -> {to:?}");
        }
        for (from, to) in [
            (New, Resolved),
            (Acknowledged, Dismissed),
            (Dismissed, Open),
            (Resolved, Acknowledged),
        ] {
            assert!(!valid_status_transition(from, to), "{from:?} -> {to:?}");
        }
    }

    #[test]
    fn reanalysis_of_same_traffic_does_not_increase_occurrence_count() {
        let entry = sample(Scheme::Https, "text/html", &[]);
        let findings = analyze(&entry, &RuleConfig::default());
        let mut merged = BTreeMap::new();
        merge_observations(&mut merged, findings.clone());
        merge_observations(&mut merged, findings);
        assert!(merged.values().all(|finding| finding.occurrence_count == 1));
    }

    #[test]
    fn exports_are_deterministic_and_do_not_contain_capture_secrets() {
        let entry = sample(Scheme::Https, "text/html", &["session=needle-secret"]);
        let findings = analyze(&entry, &RuleConfig::default());
        let json = export_json("project", "session", entry.timings.started_at, &findings).unwrap();
        let markdown = export_markdown("project", "session", entry.timings.started_at, &findings);
        for report in [&json, &markdown] {
            assert!(!report.contains("needle-secret"));
            assert!(!report.contains("DO_NOT_PERSIST"));
            assert!(report.to_ascii_lowercase().contains("passive observations"));
        }
    }

    #[test]
    fn scheduler_rejects_oversized_snapshots_and_cancellation_invalidates_pending_generation() {
        let scheduler = AnalysisScheduler::new(RuleConfig::default()).unwrap();
        let mut oversized = sample(Scheme::Https, "text/html", &[]);
        oversized.request.body = vec![b'x'; MAX_SNAPSHOT_BYTES + 1];
        assert_eq!(
            scheduler.schedule(oversized),
            Err(ScheduleError::SnapshotTooLarge)
        );
        let entry = sample(Scheme::Https, "text/html", &[]);
        let scheduled = scheduler.schedule(entry).unwrap();
        let cancelled_generation = scheduler.cancel_pending();
        assert!(cancelled_generation > scheduled);
        assert!(scheduler.queued_bytes() <= MAX_QUEUED_SNAPSHOT_BYTES);
    }

    #[test]
    fn scheduler_returns_results_off_thread_and_applies_backpressure() {
        let scheduler = AnalysisScheduler::new(RuleConfig::default()).unwrap();
        let entry = sample(Scheme::Https, "text/html", &[]);
        let generation = scheduler.schedule(entry.clone()).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            match scheduler.try_result() {
                Ok(result) => {
                    assert_eq!(result.traffic_id, entry.id);
                    assert_eq!(result.generation, generation);
                    assert!(!result.findings.is_empty());
                    break;
                }
                Err(mpsc::TryRecvError::Empty) if std::time::Instant::now() < deadline => {
                    thread::sleep(std::time::Duration::from_millis(1));
                }
                other => panic!("analysis result not received: {other:?}"),
            }
        }
    }

    #[test]
    fn scheduler_analyzes_a_quiet_websocket_handshake_without_waiting_for_messages() {
        let scheduler = AnalysisScheduler::new(RuleConfig::default()).unwrap();
        let entry = sample(Scheme::Http, "application/octet-stream", &[]);
        scheduler
            .schedule_websocket(entry, ws_connection(false), None)
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            match scheduler.try_result() {
                Ok(result) => {
                    assert!(
                        result
                            .findings
                            .iter()
                            .any(|finding| finding.rule_id == "websocket.plaintext_transport")
                    );
                    break;
                }
                Err(mpsc::TryRecvError::Empty) if std::time::Instant::now() < deadline => {
                    thread::sleep(std::time::Duration::from_millis(1))
                }
                other => panic!("WebSocket analysis result not received: {other:?}"),
            }
        }
    }

    #[test]
    fn scheduler_processes_large_history_in_bounded_batches_with_stable_order() {
        let scheduler = AnalysisScheduler::new(RuleConfig::default()).unwrap();
        let mut received = Vec::new();
        for base in (0..256u64).step_by(32) {
            for id in base..(base + 32) {
                let mut entry = sample(Scheme::Https, "text/html", &[]);
                entry.id = TrafficId(id + 1);
                scheduler.schedule(entry).unwrap();
            }
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            while received.len() < (base + 32) as usize {
                match scheduler.try_result() {
                    Ok(result) => received.push(result.traffic_id.0),
                    Err(mpsc::TryRecvError::Empty) if std::time::Instant::now() < deadline => {
                        thread::sleep(std::time::Duration::from_millis(1))
                    }
                    other => panic!("bounded batch stalled at {base}: {other:?}"),
                }
            }
        }
        assert_eq!(received, (1..=256).collect::<Vec<_>>());
        assert_eq!(scheduler.queued_bytes(), 0);
    }

    #[test]
    fn scheduler_scope_disambiguates_reused_traffic_ids_across_sessions() {
        let scheduler = AnalysisScheduler::new(RuleConfig::default()).unwrap();
        let mut first = sample(Scheme::Https, "text/html", &[]);
        first.id = TrafficId(5);
        let mut second = first.clone();
        second.request.target = "/other".into();
        scheduler
            .schedule_scoped(first, Some("session-a".into()))
            .unwrap();
        scheduler
            .schedule_scoped(second, Some("session-b".into()))
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let mut scopes = BTreeSet::new();
        while scopes.len() < 2 && std::time::Instant::now() < deadline {
            if let Ok(result) = scheduler.try_result() {
                scopes.insert(result.scope.unwrap());
            } else {
                thread::sleep(Duration::from_millis(2));
            }
        }
        assert_eq!(
            scopes,
            BTreeSet::from(["session-a".into(), "session-b".into()])
        );
    }

    #[test]
    fn scheduler_cancellation_discards_queued_generations() {
        let scheduler = AnalysisScheduler::new(RuleConfig::default()).unwrap();
        for id in 1..=32 {
            let mut entry = sample(Scheme::Https, "text/html", &[]);
            entry.id = TrafficId(id);
            scheduler.schedule(entry).unwrap();
        }
        scheduler.cancel_pending();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while scheduler.pending_jobs() != 0 && std::time::Instant::now() < deadline {
            let _ = scheduler.try_result();
            thread::sleep(std::time::Duration::from_millis(1));
        }
        assert_eq!(scheduler.pending_jobs(), 0);
        assert_eq!(scheduler.queued_bytes(), 0);
    }
}
