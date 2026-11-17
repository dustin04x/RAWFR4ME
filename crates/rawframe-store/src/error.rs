//! Storage errors. Every variant is reportable to the interface without a panic.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("database failed its integrity check: {0}")]
    Corrupt(String),
    #[error("database schema version {found} is newer than this build supports ({supported})")]
    SchemaTooNew { found: u32, supported: u32 },
    #[error(
        "database size limit of {0} bytes was reached; persistence stopped to protect the disk"
    )]
    Full(u64),
    #[error("session {0} does not exist in the database")]
    UnknownSession(String),
    #[error("database is unavailable: {0}")]
    Unavailable(String),
}

impl StoreError {
    /// True when retrying is pointless and the worker should stop writing.
    pub fn is_fatal(&self) -> bool {
        matches!(
            self,
            Self::Corrupt(_) | Self::Full(_) | Self::SchemaTooNew { .. } | Self::Unavailable(_)
        )
    }

    pub fn is_size_limit(&self) -> bool {
        match self {
            Self::Full(_) => true,
            Self::Sqlite(rusqlite::Error::SqliteFailure(failure, _)) => {
                failure.code == rusqlite::ErrorCode::DiskFull
            }
            _ => false,
        }
    }
}
