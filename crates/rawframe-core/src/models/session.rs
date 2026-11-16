//! Sessions and Repeater documents.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::message::{HttpRequest, HttpResponse};
use super::traffic::TrafficSource;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionId(pub String);

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A named testing session. Sessions group captured traffic and Repeater tabs
/// so engagements remain separable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    pub id: SessionId,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub notes: Option<String>,
}

impl Session {
    pub fn new(name: impl Into<String>) -> Self {
        let now = Utc::now();
        let nanos = now.timestamp_nanos_opt().unwrap_or_default();
        Self {
            id: SessionId(format!("sess-{nanos:x}")),
            name: name.into(),
            created_at: now,
            notes: None,
        }
    }

    pub fn demo() -> Self {
        let mut session = Self::new("demo session");
        session.notes = Some("Simulated fixtures only. No network traffic is generated.".into());
        session
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RepeaterId(pub u64);

impl std::fmt::Display for RepeaterId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A reusable request document. The Repeater owns an editable representation;
/// this model records the last successfully parsed request and its provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepeaterRequest {
    pub id: RepeaterId,
    pub title: String,
    pub request: HttpRequest,
    pub source: TrafficSource,
    pub response: Option<HttpResponse>,
    pub last_sent_at: Option<DateTime<Utc>>,
}

impl RepeaterRequest {
    pub fn new(
        id: RepeaterId,
        title: impl Into<String>,
        request: HttpRequest,
        source: TrafficSource,
    ) -> Self {
        Self {
            id,
            title: title.into(),
            request,
            source,
            response: None,
            last_sent_at: None,
        }
    }

    pub fn is_simulated(&self) -> bool {
        self.source.is_simulated()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::message::Scheme;

    #[test]
    fn sessions_have_unique_identifiers() {
        let first = Session::new("engagement-a");
        let second = Session::new("engagement-b");
        assert_ne!(first.id, second.id);
        assert_eq!(first.name, "engagement-a");
        assert!(first.notes.is_none());
    }

    #[test]
    fn demo_session_is_explicit_about_simulation() {
        let session = Session::demo();
        assert!(session.notes.unwrap().contains("Simulated"));
    }

    #[test]
    fn repeater_documents_keep_provenance() {
        let request = HttpRequest::new("GET", Scheme::Https, "api.rawframe.test", 443, "/v1/users");
        let repeater =
            RepeaterRequest::new(RepeaterId(1), "users", request, TrafficSource::Simulated);

        assert!(repeater.is_simulated());
        assert!(repeater.response.is_none());
        assert!(repeater.last_sent_at.is_none());
        assert_eq!(repeater.id.to_string(), "1");
    }
}
