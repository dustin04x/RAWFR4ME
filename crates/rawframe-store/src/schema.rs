//! Versioned schema migrations for the local session database.
//!
//! Migrations are applied in order inside a transaction and recorded in both
//! `schema_migrations` and SQLite's `user_version`. A future version only needs
//! to append an arm here; existing databases are upgraded in place, and a
//! database newer than this build is refused instead of being modified.

use rusqlite::{Connection, TransactionBehavior};

use crate::error::StoreError;

/// Schema version understood by this build.
pub const SCHEMA_VERSION: u32 = 2;

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
        match next {
            1 => tx.execute_batch(SCHEMA_V1)?,
            2 => tx.execute_batch(SCHEMA_V2)?,
            other => {
                return Err(StoreError::Unavailable(format!(
                    "missing migration for schema version {other}"
                )));
            }
        }
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

/// M6: remember which captured request a Repeater execution was based on.
/// Existing M5 databases are upgraded in place; no history is recreated.
const SCHEMA_V2: &str = r#"
ALTER TABLE traffic ADD COLUMN repeater_origin INTEGER;
"#;

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
    use crate::store::Store;
    use chrono::Utc;
    use rawframe_core::models::session::{Project, ProjectId, Session, SessionId};
    use rawframe_core::models::traffic::{TrafficSource, TrafficState};
    use rawframe_core::storage::StoragePolicy;

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
    fn an_m5_database_upgrades_in_place_without_losing_rows() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA_V1).unwrap();
        conn.pragma_update(None, "user_version", 1).unwrap();
        conn.execute(
            "INSERT INTO projects(id, name, created_at) VALUES ('p', 'p', '2026-01-01T00:00:00Z')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO sessions(id, project_id, name, created_at) VALUES ('s', 'p', 's', '2026-01-01T00:00:00Z')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO traffic(session_id, traffic_id, kind, source, state, method, scheme, \
             host, port, target, version, request_headers, started_at, updated_at) \
             VALUES ('s', 1, 'http', 'intercepted', 'completed', 'GET', 'https', 'a.test', 443, \
             '/', 'HTTP/1.1', '[]', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
            [],
        )
        .unwrap();

        assert_eq!(migrate(&mut conn).unwrap(), 2);
        let rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM traffic", [], |row| row.get(0))
            .unwrap();
        assert_eq!(rows, 1, "upgrade must preserve existing history");
        let column: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('traffic') WHERE name = 'repeater_origin'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(column, 1);
    }

    #[test]
    fn an_m5_fixture_preserves_headers_bodies_redaction_and_lifecycle() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("m5.db");
        let project = Project {
            id: ProjectId("p".into()),
            name: "M5 fixture".into(),
            created_at: Utc::now(),
        };
        let session = Session {
            id: SessionId("s".into()),
            project_id: project.id.clone(),
            name: "M5 session".into(),
            created_at: Utc::now(),
            notes: Some("fixture".into()),
        };

        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(SCHEMA_V1).unwrap();
            conn.pragma_update(None, "user_version", 1).unwrap();
            conn.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (1, ?1)",
                rusqlite::params!["2026-01-01T00:00:00Z"],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO projects(id, name, created_at) VALUES ('p', 'M5 fixture', ?1)",
                rusqlite::params!["2026-01-01T00:00:00Z"],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO sessions(id, project_id, name, notes, created_at) \
                 VALUES ('s', 'p', 'M5 session', 'fixture', ?1)",
                rusqlite::params!["2026-01-01T00:00:00Z"],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO traffic(session_id, traffic_id, kind, source, state, method, \
                 scheme, host, port, target, version, request_headers, request_body, \
                 redacted_headers, response_status, response_reason, response_version, \
                 response_headers, response_body, started_at, completed_at, duration_ms, \
                 note, incomplete, updated_at) VALUES (\
                 's', 7, 'http', 'intercepted', 'completed', 'POST', 'https', 'api.test', \
                 443, '/v1/items', 'HTTP/1.1', ?1, ?2, 2, 201, 'Created', 'HTTP/1.1', \
                 ?3, ?4, '2026-01-01T00:00:00Z', '2026-01-01T00:00:02Z', 2000, \
                 'M5 note', 0, '2026-01-01T00:00:02Z')",
                rusqlite::params![
                    r#"[["Set-Cookie","a=1"],["Set-Cookie","b=2"],["Authorization","<redacted>"]]"#,
                    vec![0u8, 0xff, 0x80, b'o', b'k'],
                    r#"[["Set-Cookie","x=1"],["X-Api-Key","<redacted>"]]"#,
                    vec![0u8, 0xfe, b'o', b'k'],
                ],
            )
            .unwrap();
        }

        let policy = StoragePolicy {
            persist_bodies: true,
            persist_sensitive_headers: true,
        };
        let store = Store::open(
            &path,
            &project,
            &session,
            policy,
            crate::store::DEFAULT_MAX_BYTES,
        )
        .expect("M6 opens and migrates the M5 fixture");
        let (entries, truncated) = store.load_session(&session.id, 10).unwrap();
        assert!(!truncated);
        assert_eq!(entries.len(), 1, "no history rows were lost or recreated");
        let entry = &entries[0];
        assert_eq!(entry.source, TrafficSource::Restored);
        assert_eq!(entry.state, TrafficState::Completed);
        assert_eq!(entry.repeater_origin, None, "new column defaults to NULL");
        assert_eq!(
            entry
                .request
                .headers
                .get_all("set-cookie")
                .collect::<Vec<_>>(),
            ["a=1", "b=2"],
            "ordered duplicate request headers survive the migration"
        );
        assert_eq!(
            entry
                .response
                .as_ref()
                .unwrap()
                .headers
                .get_all("set-cookie")
                .collect::<Vec<_>>(),
            ["x=1"]
        );
        assert_eq!(entry.request.body, vec![0u8, 0xff, 0x80, b'o', b'k']);
        assert_eq!(
            entry.response.as_ref().unwrap().body,
            vec![0u8, 0xfe, b'o', b'k']
        );
        assert_eq!(entry.redacted_headers, 2);
        assert_eq!(entry.note.as_deref(), Some("M5 note"));
        assert_eq!(entry.timings.duration_ms, Some(2000));
        assert_eq!(
            entry.timings.started_at.to_rfc3339(),
            "2026-01-01T00:00:00+00:00"
        );
        drop(store);

        // Reopening must not apply version 2 again or alter the stored fixture.
        let store = Store::open(
            &path,
            &project,
            &session,
            policy,
            crate::store::DEFAULT_MAX_BYTES,
        )
        .expect("migrated database reopens");
        let (entries, _) = store.load_session(&session.id, 10).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].request.body, vec![0u8, 0xff, 0x80, b'o', b'k']);
        drop(store);
        let conn = Connection::open(&path).unwrap();
        let version: u32 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, 2);
        let applied: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM schema_migrations WHERE version = 2",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(applied, 1, "migration was recorded exactly once");
        let rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM traffic", [], |row| row.get(0))
            .unwrap();
        assert_eq!(rows, 1);
    }

    #[test]
    fn a_failed_migration_preserves_the_database_and_is_not_recreated() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("broken-m5.db");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(SCHEMA_V1).unwrap();
            // Simulate a damaged/partially migrated M5 database where the new
            // column already exists but the version still says 1.
            conn.execute_batch("ALTER TABLE traffic ADD COLUMN repeater_origin INTEGER;")
                .unwrap();
            conn.pragma_update(None, "user_version", 1).unwrap();
            conn.execute(
                "INSERT INTO projects(id, name, created_at) VALUES ('p', 'p', '2026-01-01T00:00:00Z')",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO sessions(id, project_id, name, created_at) \
                 VALUES ('s', 'p', 's', '2026-01-01T00:00:00Z')",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO traffic(session_id, traffic_id, kind, source, state, method, \
                 scheme, host, port, target, version, request_headers, started_at, updated_at) \
                 VALUES ('s', 1, 'http', 'intercepted', 'completed', 'GET', 'https', 'a.test', \
                 443, '/', 'HTTP/1.1', '[]', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
                [],
            )
            .unwrap();
        }

        let project = Project::default_project();
        let session = Session::new("migration failure");
        let result = Store::open(
            &path,
            &project,
            &session,
            StoragePolicy::metadata_only(),
            crate::store::DEFAULT_MAX_BYTES,
        );
        assert!(result.is_err(), "duplicate column must fail the migration");
        assert!(path.exists(), "the operator's database is never deleted");
        let conn = Connection::open(&path).unwrap();
        let rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM traffic", [], |row| row.get(0))
            .unwrap();
        assert_eq!(rows, 1, "the original row is still present");
        let version: u32 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, 1, "failed migration did not claim success");
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
