//! Versioned schema migrations for the local session database.
//!
//! Migrations are applied in order inside a transaction and recorded in both
//! `schema_migrations` and SQLite's `user_version`. A future version only needs
//! to append an arm here; existing databases are upgraded in place, and a
//! database newer than this build is refused instead of being modified.

use rusqlite::{Connection, TransactionBehavior};

use crate::error::StoreError;

/// Schema version understood by this build.
pub const SCHEMA_VERSION: u32 = 1;

/// Applies every migration the database is missing.
pub fn migrate(conn: &mut Connection) -> Result<u32, StoreError> {
    conn.pragma_update(None, "foreign_keys", true)?;
    let current: u32 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if current > SCHEMA_VERSION {
        return Err(StoreError::SchemaTooNew {
            found: current,
            supported: SCHEMA_VERSION,
        });
    }

    let mut version = current;
    while version < SCHEMA_VERSION {
        let next = version + 1;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(SCHEMA_V1)?;
        tx.execute(
            "INSERT OR REPLACE INTO schema_migrations(version, applied_at) VALUES (?1, ?2)",
            rusqlite::params![next, chrono::Utc::now().to_rfc3339()],
        )?;
        tx.pragma_update(None, "user_version", next)?;
        tx.commit()?;
        tracing::info!(version = next, "applied database migration");
        version = next;
    }
    Ok(version)
}

const SCHEMA_V1: &str = r#"
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS projects (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id           TEXT PRIMARY KEY,
    project_id   TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    notes        TEXT,
    closed_at    TEXT,
    close_reason TEXT,
    recovered    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS traffic (
    row_id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id             TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    traffic_id             INTEGER NOT NULL,
    kind                   TEXT NOT NULL,
    source                 TEXT NOT NULL,
    state                  TEXT NOT NULL,
    method                 TEXT NOT NULL,
    scheme                 TEXT NOT NULL,
    host                   TEXT NOT NULL,
    port                   INTEGER NOT NULL,
    target                 TEXT NOT NULL,
    version                TEXT NOT NULL,
    request_headers        TEXT NOT NULL,
    request_body           BLOB,
    request_body_omitted   INTEGER NOT NULL DEFAULT 0,
    redacted_headers       INTEGER NOT NULL DEFAULT 0,
    response_status        INTEGER,
    response_reason        TEXT,
    response_version       TEXT,
    response_headers       TEXT,
    response_body          BLOB,
    response_body_omitted  INTEGER NOT NULL DEFAULT 0,
    started_at             TEXT NOT NULL,
    completed_at           TEXT,
    duration_ms            INTEGER,
    error                  TEXT,
    note                   TEXT,
    original_request       TEXT,
    final_request          TEXT,
    interception           TEXT,
    tunnel                 TEXT,
    incomplete             INTEGER NOT NULL DEFAULT 0,
    updated_at             TEXT NOT NULL,
    UNIQUE(session_id, traffic_id)
);

CREATE INDEX IF NOT EXISTS idx_traffic_session_started
    ON traffic(session_id, started_at);
CREATE INDEX IF NOT EXISTS idx_traffic_host ON traffic(host);
CREATE INDEX IF NOT EXISTS idx_traffic_method ON traffic(method);
CREATE INDEX IF NOT EXISTS idx_traffic_status ON traffic(response_status);
CREATE INDEX IF NOT EXISTS idx_traffic_state ON traffic(state);
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrations_are_idempotent_and_versioned() {
        let mut conn = Connection::open_in_memory().unwrap();
        assert_eq!(migrate(&mut conn).unwrap(), SCHEMA_VERSION);
        assert_eq!(migrate(&mut conn).unwrap(), SCHEMA_VERSION);

        let recorded: u32 = conn
            .query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(recorded, SCHEMA_VERSION);

        let user_version: u32 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(user_version, SCHEMA_VERSION);
    }

    #[test]
    fn future_schema_versions_are_refused() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "user_version", SCHEMA_VERSION + 5)
            .unwrap();
        assert!(matches!(
            migrate(&mut conn),
            Err(StoreError::SchemaTooNew { .. })
        ));
    }
}
