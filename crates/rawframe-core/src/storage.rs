//! Persistence contracts shared by the storage worker and the interface.
//!
//! This module contains no I/O: it defines the command/event vocabulary so the
//! TUI never links SQLite and the storage worker never renders anything. The
//! SQLite implementation lives in `rawframe-store`.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::models::config::StorageConfiguration;
use crate::models::session::{SessionId, SessionSummary};
use crate::models::traffic::TrafficEntry;

/// Bounded so a stalled database applies backpressure to the capture pump
/// instead of growing memory without limit.
pub const STORAGE_COMMAND_QUEUE: usize = 64;

/// What the operator allows the database to contain.
///
/// Both fields default to `false`. With these defaults RAWFRAME stores request
/// and response metadata, duplicate-preserving header *names*, and the
/// placeholder `<redacted>` for sensitive header values; bodies are not written
/// at all (they are stored as SQL `NULL`, never as empty bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct StoragePolicy {
    pub persist_bodies: bool,
    pub persist_sensitive_headers: bool,
}

impl StoragePolicy {
    pub fn from_config(config: &StorageConfiguration) -> Self {
        Self {
            persist_bodies: config.persist_bodies,
            persist_sensitive_headers: config.persist_sensitive_headers,
        }
    }

    pub const fn metadata_only() -> Self {
        Self {
            persist_bodies: false,
            persist_sensitive_headers: false,
        }
    }

    pub fn apply_to_config(self, config: &mut StorageConfiguration) {
        config.persist_bodies = self.persist_bodies;
        config.persist_sensitive_headers = self.persist_sensitive_headers;
    }
}

/// Runtime state of the persistence layer, surfaced in the interface so the
/// operator always knows whether captured traffic is being stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageStatus {
    pub enabled: bool,
    pub database_path: Option<PathBuf>,
    pub session_id: Option<SessionId>,
    pub persisted: u64,
    /// Captures the writer could not enqueue. Non-zero means data was dropped
    /// rather than silently lost.
    pub dropped: u64,
    pub policy: StoragePolicy,
    /// Set when the database could not be opened, migrated, or written. The
    /// proxy keeps running; persistence is disabled for the rest of the session.
    pub error: Option<String>,
}

impl Default for StorageStatus {
    fn default() -> Self {
        Self {
            enabled: false,
            database_path: None,
            session_id: None,
            persisted: 0,
            dropped: 0,
            policy: StoragePolicy::metadata_only(),
            error: None,
        }
    }
}

impl StorageStatus {
    pub fn enabled(path: impl Into<PathBuf>, session_id: SessionId, policy: StoragePolicy) -> Self {
        Self {
            enabled: true,
            database_path: Some(path.into()),
            session_id: Some(session_id),
            persisted: 0,
            dropped: 0,
            policy,
            error: None,
        }
    }

    pub fn disabled() -> Self {
        Self::default()
    }

    pub fn failed(path: Option<PathBuf>, error: impl Into<String>) -> Self {
        Self {
            enabled: false,
            database_path: path,
            session_id: None,
            persisted: 0,
            dropped: 0,
            policy: StoragePolicy::metadata_only(),
            error: Some(error.into()),
        }
    }
}

/// Requests sent from the interface to the storage worker. Queries are
/// asynchronous: the answer arrives as [`StorageEvent`] on the application bus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageCommand {
    ListSessions,
    LoadSession {
        session_id: SessionId,
        limit: usize,
    },
    /// Export a session as redacted JSON Lines. Redaction is decided by the
    /// stored policy, not by the current screen state.
    ExportSession {
        session_id: SessionId,
        path: PathBuf,
    },
    SetPolicy(StoragePolicy),
    Shutdown,
}

/// Storage results delivered to the interface.
#[derive(Debug, Clone)]
pub enum StorageEvent {
    Status(StorageStatus),
    Sessions(Vec<SessionSummary>),
    SessionLoaded {
        session_id: SessionId,
        entries: Vec<TrafficEntry>,
        /// True when the session holds more records than the requested limit.
        truncated: bool,
    },
    Exported {
        session_id: SessionId,
        path: PathBuf,
        records: usize,
        redacted_headers: usize,
        bodies_omitted: usize,
    },
    Failed(String),
}

pub type StorageCommandSender = mpsc::Sender<StorageCommand>;
pub type StorageCommandReceiver = mpsc::Receiver<StorageCommand>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_store_no_bodies_or_secret_values() {
        let policy = StoragePolicy::default();
        assert!(!policy.persist_bodies);
        assert!(!policy.persist_sensitive_headers);

        let config = StorageConfiguration::default();
        assert_eq!(StoragePolicy::from_config(&config), policy);
    }

    #[test]
    fn status_reports_failure_without_claiming_persistence() {
        let status = StorageStatus::failed(Some(PathBuf::from("/tmp/x.db")), "disk full");
        assert!(!status.enabled);
        assert_eq!(status.error.as_deref(), Some("disk full"));
        assert_eq!(status.persisted, 0);
    }

    #[test]
    fn enabled_status_carries_the_session_and_path() {
        let status = StorageStatus::enabled(
            PathBuf::from("/tmp/sessions.db"),
            SessionId("sess-1".into()),
            StoragePolicy::metadata_only(),
        );
        assert!(status.enabled);
        assert_eq!(status.session_id.unwrap().0, "sess-1");
        assert!(status.error.is_none());
    }
}
