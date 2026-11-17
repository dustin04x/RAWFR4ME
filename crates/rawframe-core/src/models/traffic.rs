//! Captured transactions and their interception lifecycle.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::message::{HttpRequest, HttpResponse, StatusClass};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TrafficId(pub u64);

impl std::fmt::Display for TrafficId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Distinguishes genuinely captured traffic from local UI fixtures. Simulated
/// entries are always labelled in the interface and never forwarded anywhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TrafficKind {
    /// A captured HTTP request and its response.
    #[default]
    Http,
    /// Opaque bytes relayed after a successful CONNECT. The tunnel contents are
    /// never inspected or decrypted.
    ConnectTunnel,
}

impl TrafficKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Http => "HTTP",
            Self::ConnectTunnel => "TUNNEL",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TunnelOutcome {
    #[default]
    Active,
    Closed,
    TimedOut,
    Failed,
}

impl TunnelOutcome {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Active => "ACTIVE",
            Self::Closed => "CLOSED",
            Self::TimedOut => "TIMED OUT",
            Self::Failed => "FAILED",
        }
    }
}

/// Metadata for an opaque HTTPS tunnel. Contents are not captured or decoded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TunnelMetadata {
    pub client_to_upstream_bytes: u64,
    pub upstream_to_client_bytes: u64,
    pub outcome: TunnelOutcome,
}

impl TunnelMetadata {
    pub fn total_bytes(&self) -> u64 {
        self.client_to_upstream_bytes + self.upstream_to_client_bytes
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrafficSource {
    /// Captured live from a proxied connection during this run.
    Intercepted,
    Simulated,
    /// Authored in the Repeater but never executed.
    Authored,
    /// Executed by the Repeater against a real upstream. Never proxy traffic.
    Repeater,
    /// Loaded from the session database. Restored entries are never live and are
    /// never forwarded, even though they were originally intercepted.
    Restored,
}

impl TrafficSource {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Intercepted => "LIVE",
            Self::Simulated => "SIM",
            Self::Authored => "AUTH",
            Self::Repeater => "REPEATER",
            Self::Restored => "RESTORED",
        }
    }

    pub const fn is_simulated(self) -> bool {
        matches!(self, Self::Simulated)
    }

    pub const fn is_restored(self) -> bool {
        matches!(self, Self::Restored)
    }
}

/// Lifecycle states for a captured request.
///
/// `Captured -> Paused -> Modified? -> Forwarded -> Completed`, or
/// `Paused -> Dropped`. Terminal states are `Completed`, `Dropped`, and
/// `Failed`. Transitions are validated so the UI cannot invent a completion for
/// a request that was never forwarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrafficState {
    Captured,
    Paused,
    Modified,
    Forwarded,
    Dropped,
    Completed,
    Failed,
    TimedOut,
    Cancelled,
}

impl std::fmt::Display for TrafficState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

impl TrafficState {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Captured => "CAPTURED",
            Self::Paused => "PAUSED",
            Self::Modified => "MODIFIED",
            Self::Forwarded => "FORWARDED",
            Self::Dropped => "DROPPED",
            Self::Completed => "COMPLETED",
            Self::Failed => "FAILED",
            Self::TimedOut => "TIMED OUT",
            Self::Cancelled => "CANCELLED",
        }
    }

    /// Requests that are still waiting on an operator decision or the upstream.
    pub const fn is_pending(self) -> bool {
        matches!(
            self,
            Self::Captured | Self::Paused | Self::Modified | Self::Forwarded
        )
    }

    pub const fn is_awaiting_decision(self) -> bool {
        matches!(self, Self::Captured | Self::Paused | Self::Modified)
    }

    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Dropped | Self::Failed | Self::TimedOut | Self::Cancelled
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficTimings {
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub duration_ms: Option<u64>,
}

impl TrafficTimings {
    pub fn starting_now() -> Self {
        Self {
            started_at: Utc::now(),
            completed_at: None,
            duration_ms: None,
        }
    }

    pub fn starting_at(started_at: DateTime<Utc>) -> Self {
        Self {
            started_at,
            completed_at: None,
            duration_ms: None,
        }
    }

    pub fn finish(&mut self, duration_ms: u64) {
        self.completed_at = Some(Utc::now());
        self.duration_ms = Some(duration_ms);
    }
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[error("invalid traffic state transition: {from} -> {to}")]
pub struct TransitionError {
    pub from: TrafficState,
    pub to: TrafficState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EditableHttpRequest {
    pub method: String,
    pub target: String,
    pub version: String,
    pub host: String,
    pub port: u16,
    pub scheme: super::message::Scheme,
    pub headers: super::headers::Headers,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct InterceptionMetadata {
    pub intercepted: bool,
    pub modified: bool,
    pub queue_position: Option<usize>,
    pub client_addr: Option<String>,
    pub arrival_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficEntry {
    pub id: TrafficId,
    pub request: HttpRequest,
    pub response: Option<HttpResponse>,
    pub state: TrafficState,
    pub source: TrafficSource,
    pub timings: TrafficTimings,
    pub error: Option<String>,
    /// Free-form operator annotation. Never derived from target responses.
    pub note: Option<String>,
    #[serde(default)]
    pub kind: TrafficKind,
    /// Present only for CONNECT tunnels. The tunnel payload is opaque.
    #[serde(default)]
    pub tunnel: Option<TunnelMetadata>,
    #[serde(default)]
    pub original_request: Option<HttpRequest>,
    #[serde(default)]
    pub final_request: Option<HttpRequest>,
    #[serde(default)]
    pub interception: InterceptionMetadata,
    /// True when this entry was restored from the session database and the
    /// operator's storage policy did not allow bodies to be written. The
    /// inspector states this explicitly instead of showing an empty body.
    #[serde(default)]
    pub body_omitted: bool,
    /// Number of sensitive header values masked before this entry was written.
    #[serde(default)]
    pub redacted_headers: usize,
    /// Captured History entry this Repeater transaction was based on, if any.
    /// Persisted so a restored result keeps its original reference without ever
    /// re-executing it.
    #[serde(default)]
    pub repeater_origin: Option<TrafficId>,
}

impl TrafficEntry {
    pub fn new(id: TrafficId, request: HttpRequest) -> Self {
        Self {
            id,
            request,
            response: None,
            state: TrafficState::Captured,
            source: TrafficSource::Intercepted,
            timings: TrafficTimings::starting_now(),
            error: None,
            note: None,
            kind: TrafficKind::Http,
            tunnel: None,
            original_request: None,
            final_request: None,
            interception: InterceptionMetadata::default(),
            body_omitted: false,
            redacted_headers: 0,
            repeater_origin: None,
        }
    }

    pub fn simulated(id: TrafficId, request: HttpRequest, started_at: DateTime<Utc>) -> Self {
        Self {
            id,
            request,
            response: None,
            state: TrafficState::Captured,
            source: TrafficSource::Simulated,
            timings: TrafficTimings::starting_at(started_at),
            error: None,
            note: None,
            kind: TrafficKind::Http,
            tunnel: None,
            original_request: None,
            final_request: None,
            interception: InterceptionMetadata::default(),
            body_omitted: false,
            redacted_headers: 0,
            repeater_origin: None,
        }
    }

    pub fn tunnel(
        id: TrafficId,
        request: HttpRequest,
        metadata: TunnelMetadata,
        started_at: DateTime<Utc>,
    ) -> Self {
        let mut entry = Self::new(id, request);
        entry.timings = TrafficTimings::starting_at(started_at);
        entry.kind = TrafficKind::ConnectTunnel;
        entry.tunnel = Some(metadata);
        entry
    }

    pub fn is_tunnel(&self) -> bool {
        self.kind == TrafficKind::ConnectTunnel
    }

    fn transition(&mut self, next: TrafficState) -> Result<(), TransitionError> {
        let allowed = match self.state {
            TrafficState::Captured => matches!(
                next,
                TrafficState::Paused
                    | TrafficState::Forwarded
                    | TrafficState::Dropped
                    | TrafficState::Failed
                    | TrafficState::TimedOut
                    | TrafficState::Cancelled
            ),
            TrafficState::Paused => matches!(
                next,
                TrafficState::Modified
                    | TrafficState::Forwarded
                    | TrafficState::Dropped
                    | TrafficState::Failed
                    | TrafficState::TimedOut
                    | TrafficState::Cancelled
            ),
            TrafficState::Modified => matches!(
                next,
                TrafficState::Paused
                    | TrafficState::Forwarded
                    | TrafficState::Dropped
                    | TrafficState::Failed
                    | TrafficState::TimedOut
                    | TrafficState::Cancelled
            ),
            TrafficState::Forwarded => {
                matches!(
                    next,
                    TrafficState::Completed
                        | TrafficState::Failed
                        | TrafficState::TimedOut
                        | TrafficState::Cancelled
                )
            }
            TrafficState::Dropped
            | TrafficState::Completed
            | TrafficState::Failed
            | TrafficState::TimedOut
            | TrafficState::Cancelled => false,
        };

        if allowed {
            self.state = next;
            Ok(())
        } else {
            Err(TransitionError {
                from: self.state,
                to: next,
            })
        }
    }

    pub fn pause(&mut self) -> Result<(), TransitionError> {
        self.transition(TrafficState::Paused)
    }

    pub fn mark_modified(&mut self) -> Result<(), TransitionError> {
        self.transition(TrafficState::Modified)
    }

    pub fn forward(&mut self) -> Result<(), TransitionError> {
        self.transition(TrafficState::Forwarded)
    }

    pub fn drop_request(&mut self) -> Result<(), TransitionError> {
        self.transition(TrafficState::Dropped)?;
        self.timings.completed_at = Some(Utc::now());
        Ok(())
    }

    pub fn complete(
        &mut self,
        response: HttpResponse,
        duration_ms: u64,
    ) -> Result<(), TransitionError> {
        self.transition(TrafficState::Completed)?;
        self.response = Some(response);
        self.timings.completed_at = Some(Utc::now());
        self.timings.duration_ms = Some(duration_ms);
        Ok(())
    }

    pub fn fail(&mut self, error: impl Into<String>) -> Result<(), TransitionError> {
        self.transition(TrafficState::Failed)?;
        self.error = Some(error.into());
        self.timings.completed_at = Some(Utc::now());
        Ok(())
    }

    pub fn status_class(&self) -> Option<StatusClass> {
        self.response.as_ref().map(HttpResponse::status_class)
    }

    pub fn status_label(&self) -> String {
        match &self.response {
            Some(response) => response.status.to_string(),
            None => self.state.label().to_string(),
        }
    }

    pub fn size_bytes(&self) -> usize {
        self.response
            .as_ref()
            .map_or_else(|| self.request.body.len(), |response| response.body.len())
    }

    pub fn duration_ms(&self) -> Option<u64> {
        self.timings.duration_ms
    }

    pub fn is_paused(&self) -> bool {
        self.state == TrafficState::Paused
    }

    pub fn is_live_capture(&self) -> bool {
        self.source == TrafficSource::Intercepted
    }

    /// Restored entries are read-only history loaded from the session database.
    pub fn is_restored(&self) -> bool {
        self.source.is_restored()
    }

    /// Executed by Repeater. These are persisted, but never live proxy traffic
    /// and never re-executed when restored.
    pub fn is_repeater(&self) -> bool {
        self.source == TrafficSource::Repeater
    }

    pub fn timeout_interception(
        &mut self,
        message: impl Into<String>,
    ) -> Result<(), TransitionError> {
        self.transition(TrafficState::TimedOut)?;
        self.error = Some(message.into());
        self.timings.completed_at = Some(Utc::now());
        Ok(())
    }

    pub fn cancel_interception(
        &mut self,
        message: impl Into<String>,
    ) -> Result<(), TransitionError> {
        self.transition(TrafficState::Cancelled)?;
        self.error = Some(message.into());
        self.timings.completed_at = Some(Utc::now());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::message::Scheme;

    fn request() -> HttpRequest {
        HttpRequest::new("GET", Scheme::Https, "api.rawframe.test", 443, "/v1/users")
    }

    fn entry() -> TrafficEntry {
        TrafficEntry::new(TrafficId(1), request())
    }

    #[test]
    fn valid_lifecycle_reaches_completed() {
        let mut entry = entry();
        entry.pause().unwrap();
        entry.mark_modified().unwrap();
        entry.forward().unwrap();
        entry.complete(HttpResponse::new(200), 42).unwrap();

        assert_eq!(entry.state, TrafficState::Completed);
        assert_eq!(entry.status_label(), "200");
        assert_eq!(entry.duration_ms(), Some(42));
        assert!(entry.timings.completed_at.is_some());
    }

    #[test]
    fn invalid_transitions_are_rejected() {
        let mut entry = entry();
        let error = entry.complete(HttpResponse::new(200), 10).unwrap_err();
        assert_eq!(error.from, TrafficState::Captured);
        assert_eq!(error.to, TrafficState::Completed);
        assert_eq!(entry.state, TrafficState::Captured);

        entry.drop_request().unwrap();
        assert!(entry.forward().is_err());
        assert_eq!(entry.state, TrafficState::Dropped);
    }

    #[test]
    fn dropping_records_completion_time_without_a_duration() {
        let mut entry = entry();
        entry.pause().unwrap();
        entry.drop_request().unwrap();

        assert_eq!(entry.state, TrafficState::Dropped);
        assert!(entry.timings.completed_at.is_some());
        assert_eq!(entry.timings.duration_ms, None);
        assert_eq!(entry.status_label(), "DROPPED");
    }

    #[test]
    fn failure_keeps_the_error_and_is_terminal() {
        let mut entry = entry();
        entry.forward().unwrap();
        entry.fail("upstream TLS verification failed").unwrap();

        assert_eq!(entry.state, TrafficState::Failed);
        assert_eq!(
            entry.error.as_deref(),
            Some("upstream TLS verification failed")
        );
        assert!(entry.pause().is_err());
    }

    #[test]
    fn simulated_entries_are_labelled() {
        let entry = TrafficEntry::simulated(TrafficId(9), request(), Utc::now());
        assert!(entry.source.is_simulated());
        assert_eq!(entry.source.label(), "SIM");
        assert!(!entry.is_live_capture());
    }

    #[test]
    fn restored_entries_are_never_live() {
        let mut entry = entry();
        entry.source = TrafficSource::Restored;
        assert!(entry.is_restored());
        assert!(!entry.is_live_capture());
        assert_eq!(entry.source.label(), "RESTORED");
    }

    #[test]
    fn state_predicates_match_the_documented_lifecycle() {
        assert!(TrafficState::Paused.is_awaiting_decision());
        assert!(!TrafficState::Forwarded.is_awaiting_decision());
        assert!(TrafficState::Forwarded.is_pending());
        assert!(TrafficState::Completed.is_terminal());
        assert!(TrafficState::Dropped.is_terminal());
        assert!(TrafficState::Failed.is_terminal());
    }
}
