//! The SQLite-backed session store.
//!
//! One [`Store`] owns one `Connection` and is confined to the storage worker
//! thread, so no proxy connection ever touches SQLite. Durability is preferred
//! over throughput (`synchronous=FULL`, WAL): a crash can lose at most the
//! transaction in flight, never acknowledged history.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use rawframe_core::models::session::{Project, Session, SessionId, SessionSummary};
use rawframe_core::models::traffic::{TrafficEntry, TunnelMetadata};
use rawframe_core::storage::StoragePolicy;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior};
use serde_json::json;

use crate::error::StoreError;
use crate::record::{TrafficRecord, decode_row, now_stamp, restored_traffic_id};
use crate::schema;

/// Default ceiling for the database file. Reaching it stops persistence with an
/// explicit error instead of filling the operator's disk.
pub const DEFAULT_MAX_BYTES: u64 = 512 * 1024 * 1024;

const UPSERT_TRAFFIC: &str = r#"
INSERT INTO traffic (
    session_id, traffic_id, kind, source, state, method, scheme, host, port,
    target, version, request_headers, request_body, request_body_omitted,
    redacted_headers, response_status, response_reason, response_version,
    response_headers, response_body, response_body_omitted, started_at,
    completed_at, duration_ms, error, note, original_request, final_request,
    interception, tunnel, repeater_origin, incomplete, updated_at
) VALUES (
    :session_id, :traffic_id, :kind, :source, :state, :method, :scheme, :host,
    :port, :target, :version, :request_headers, :request_body,
    :request_body_omitted, :redacted_headers, :response_status,
    :response_reason, :response_version, :response_headers, :response_body,
    :response_body_omitted, :started_at, :completed_at, :duration_ms, :error,
    :note, :original_request, :final_request, :interception, :tunnel,
    :repeater_origin, :incomplete, :updated_at
)
ON CONFLICT(session_id, traffic_id) DO UPDATE SET
    kind = excluded.kind,
    source = excluded.source,
    state = excluded.state,
    method = excluded.method,
    scheme = excluded.scheme,
    host = excluded.host,
    port = excluded.port,
    target = excluded.target,
    version = excluded.version,
    request_headers = excluded.request_headers,
    request_body = excluded.request_body,
    request_body_omitted = excluded.request_body_omitted,
    redacted_headers = excluded.redacted_headers,
    response_status = excluded.response_status,
    response_reason = excluded.response_reason,
    response_version = excluded.response_version,
    response_headers = excluded.response_headers,
    response_body = excluded.response_body,
    response_body_omitted = excluded.response_body_omitted,
    started_at = excluded.started_at,
    completed_at = excluded.completed_at,
    duration_ms = excluded.duration_ms,
    error = excluded.error,
    note = excluded.note,
    original_request = excluded.original_request,
    final_request = excluded.final_request,
    interception = excluded.interception,
    tunnel = excluded.tunnel,
    repeater_origin = excluded.repeater_origin,
    incomplete = excluded.incomplete,
    updated_at = excluded.updated_at
"#;

const TRAFFIC_COLUMNS: &str = "row_id, traffic_id, kind, source, state, method, scheme, host, \
     port, target, version, request_headers, request_body, request_body_omitted, \
     redacted_headers, response_status, response_reason, response_version, \
     response_headers, response_body, response_body_omitted, started_at, completed_at, \
     duration_ms, error, note, original_request, final_request, interception, tunnel, \
     repeater_origin, incomplete";

/// An open, migrated database bound to the current session.
pub struct Store {
    conn: Connection,
    path: PathBuf,
    session: Session,
    policy: StoragePolicy,
    max_bytes: u64,
}

/// Outcome of an export, reported back to the interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportSummary {
    pub records: usize,
    pub redacted_headers: usize,
    pub bodies_omitted: usize,
}

impl Store {
    /// Opens (or creates) the database and registers the current session.
    ///
    /// Failure is returned rather than panicked: the caller keeps the proxy
    /// running with persistence disabled and surfaces the reason.
    pub fn open(
        path: impl AsRef<Path>,
        project: &Project,
        session: &Session,
        policy: StoragePolicy,
        max_bytes: u64,
    ) -> Result<Self, StoreError> {
        let path = path.as_ref().to_path_buf();
        create_parent(&path)?;
        let mut conn = Connection::open(&path)?;
        restrict_permissions(&path)?;

        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get::<_, String>(0))?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.pragma_update(None, "foreign_keys", true)?;
        conn.pragma_update(None, "temp_store", "MEMORY")?;
        conn.pragma_update(None, "journal_size_limit", 64 * 1024 * 1024)?;

        let check: String = conn.pragma_query_value(None, "quick_check", |row| row.get(0))?;
        if !check.eq_ignore_ascii_case("ok") {
            return Err(StoreError::Corrupt(check));
        }

        schema::migrate(&mut conn)?;

        let page_size: i64 = conn.pragma_query_value(None, "page_size", |row| row.get(0))?;
        let pages = (max_bytes / (page_size.max(512) as u64)).max(16) as i64;
        conn.pragma_update(None, "max_page_count", pages)?;

        let mut store = Self {
            conn,
            path,
            session: session.clone(),
            policy,
            max_bytes,
        };
        store.register_project(project)?;
        store.register_session(session)?;
        store.recover_interrupted()?;
        Ok(store)
    }

    /// Opens an existing database for read-only work (listing and exporting)
    /// without registering a new session or recovering interrupted runs.
    pub fn open_existing(
        path: impl AsRef<Path>,
        policy: StoragePolicy,
    ) -> Result<Self, StoreError> {
        let path = path.as_ref().to_path_buf();
        if !path.exists() {
            return Err(StoreError::Unavailable(format!(
                "database {} does not exist",
                path.display()
            )));
        }
        let mut conn = Connection::open(&path)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.pragma_update(None, "foreign_keys", true)?;
        let check: String = conn.pragma_query_value(None, "quick_check", |row| row.get(0))?;
        if !check.eq_ignore_ascii_case("ok") {
            return Err(StoreError::Corrupt(check));
        }
        schema::migrate(&mut conn)?;
        Ok(Self {
            conn,
            path,
            session: Session::new("export"),
            policy,
            max_bytes: DEFAULT_MAX_BYTES,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn session(&self) -> &Session {
        &self.session
    }

    pub fn policy(&self) -> StoragePolicy {
        self.policy
    }

    /// Policy changes apply to future writes only; rows already written keep the
    /// redaction they were stored with. This is deliberate: rewriting history
    /// could either destroy evidence or reveal secrets the operator chose to mask.
    pub fn set_policy(&mut self, policy: StoragePolicy) {
        self.policy = policy;
    }

    fn register_project(&self, project: &Project) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT OR IGNORE INTO projects(id, name, created_at) VALUES (?1, ?2, ?3)",
            rusqlite::params![project.id.0, project.name, project.created_at.to_rfc3339()],
        )?;
        Ok(())
    }

    fn register_session(&self, session: &Session) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT OR IGNORE INTO sessions(id, project_id, name, created_at, notes) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                session.id.0,
                session.project_id.0,
                session.name,
                session.created_at.to_rfc3339(),
                session.notes,
            ],
        )?;
        Ok(())
    }

    /// Closes sessions left open by a previous run and marks their pending
    /// transactions as incomplete, so history never claims an unfinished
    /// request completed.
    fn recover_interrupted(&mut self) -> Result<usize, StoreError> {
        let now = now_stamp();
        let stale = self.conn.execute(
            "UPDATE sessions SET closed_at = ?1, close_reason = 'unclean shutdown', recovered = 1 \
             WHERE closed_at IS NULL AND id <> ?2",
            rusqlite::params![now, self.session.id.0],
        )?;
        // Any non-terminal row written before the last clean shutdown belongs to
        // an interrupted run.
        self.conn.execute(
            "UPDATE traffic SET incomplete = 1 \
             WHERE incomplete = 0 AND state NOT IN ('completed','dropped','failed','timed_out','cancelled')",
            [],
        )?;
        Ok(stale)
    }

    /// Marks the current session as closed cleanly. Called on shutdown.
    pub fn close(&mut self, reason: &str) -> Result<(), StoreError> {
        self.conn.execute(
            "UPDATE sessions SET closed_at = ?1, close_reason = ?2 WHERE id = ?3",
            rusqlite::params![now_stamp(), reason, self.session.id.0],
        )?;
        self.conn
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        Ok(())
    }

    /// Inserts or updates one transaction. A single entry uses the same batched
    /// path as many, so lifecycle updates and captures share one code path.
    pub fn write_entry(&mut self, entry: &TrafficEntry) -> Result<(), StoreError> {
        self.write_batch(std::slice::from_ref(entry))
    }

    /// Writes a group of transactions in one synchronous transaction. Either all
    /// rows are durable or none are.
    pub fn write_batch(&mut self, entries: &[TrafficEntry]) -> Result<(), StoreError> {
        if entries.is_empty() {
            return Ok(());
        }
        let records: Vec<TrafficRecord> = entries
            .iter()
            .map(|entry| TrafficRecord::encode(entry, self.policy))
            .collect();
        let max_bytes = self.max_bytes;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        {
            let mut statement = tx.prepare_cached(UPSERT_TRAFFIC)?;
            let updated_at = now_stamp();
            for record in &records {
                statement
                    .execute(rusqlite::named_params! {
                        ":session_id": self.session.id.0,
                        ":traffic_id": record.traffic_id,
                        ":kind": record.kind,
                        ":source": record.source,
                        ":state": record.state,
                        ":method": record.method,
                        ":scheme": record.scheme,
                        ":host": record.host,
                        ":port": record.port,
                        ":target": record.target,
                        ":version": record.version,
                        ":request_headers": record.request_headers,
                        ":request_body": record.request_body,
                        ":request_body_omitted": record.request_body_omitted,
                        ":redacted_headers": record.redacted_headers as i64,
                        ":response_status": record.response.as_ref().map(|r| r.status),
                        ":response_reason": record.response.as_ref().map(|r| r.reason.as_str()),
                        ":response_version": record.response.as_ref().map(|r| r.version.as_str()),
                        ":response_headers": record.response.as_ref().map(|r| r.headers.as_str()),
                        ":response_body": record.response.as_ref().and_then(|r| r.body.as_ref()),
                        ":response_body_omitted": record.response.as_ref().is_some_and(|r| r.body_omitted),
                        ":started_at": record.started_at,
                        ":completed_at": record.completed_at,
                        ":duration_ms": record.duration_ms.map(|value| value as i64),
                        ":error": record.error,
                        ":note": record.note,
                        ":original_request": record.original_request,
                        ":final_request": record.final_request,
                        ":interception": record.interception,
                        ":tunnel": record.tunnel,
                        ":repeater_origin": record.repeater_origin,
                        ":incomplete": record.incomplete,
                        ":updated_at": updated_at,
                    })
                    .map_err(|error| map_write_error(error, max_bytes))?;
            }
        }
        tx.commit()
            .map_err(|error| map_write_error(error, max_bytes))?;
        Ok(())
    }

    /// Sessions newest first, with record and incomplete counts.
    pub fn list_sessions(&self) -> Result<Vec<SessionSummary>, StoreError> {
        let mut statement = self.conn.prepare(
            "SELECT s.id, s.name, s.project_id, p.name AS project_name, s.created_at, s.recovered,
                    (SELECT COUNT(*) FROM traffic t WHERE t.session_id = s.id) AS records,
                    (SELECT COUNT(*) FROM traffic t WHERE t.session_id = s.id AND t.incomplete = 1) AS incomplete,
                    (SELECT MAX(t.started_at) FROM traffic t WHERE t.session_id = s.id) AS last_activity
             FROM sessions s JOIN projects p ON p.id = s.project_id
             ORDER BY s.created_at DESC",
        )?;
        let rows = statement.query_map([], |row| {
            let created_at: String = row.get("created_at")?;
            let last_activity: Option<String> = row.get("last_activity")?;
            Ok(SessionSummary {
                id: SessionId(row.get("id")?),
                name: row.get("name")?,
                project_id: rawframe_core::models::session::ProjectId(row.get("project_id")?),
                project_name: row.get("project_name")?,
                created_at: crate::record::parse_stored_time(&created_at).unwrap_or_else(Utc::now),
                records: row.get::<_, i64>("records")?.max(0) as usize,
                incomplete: row.get::<_, i64>("incomplete")?.max(0) as usize,
                last_activity_at: last_activity
                    .as_deref()
                    .and_then(crate::record::parse_stored_time),
                recovered: row.get::<_, i64>("recovered")? != 0,
            })
        })?;
        let mut sessions = Vec::new();
        for row in rows {
            sessions.push(row?);
        }
        Ok(sessions)
    }

    pub fn session_exists(&self, session_id: &SessionId) -> Result<bool, StoreError> {
        let found: Option<i64> = self
            .conn
            .query_row(
                "SELECT 1 FROM sessions WHERE id = ?1",
                rusqlite::params![session_id.0],
                |row| row.get(0),
            )
            .optional()?;
        Ok(found.is_some())
    }

    /// Loads a session as restored, read-only entries. `truncated` reports that
    /// more rows exist than the requested limit.
    pub fn load_session(
        &self,
        session_id: &SessionId,
        limit: usize,
    ) -> Result<(Vec<TrafficEntry>, bool), StoreError> {
        if !self.session_exists(session_id)? {
            return Err(StoreError::UnknownSession(session_id.0.clone()));
        }
        // Load the newest `limit` transactions (then restore chronological
        // order) so a large session shows recent work rather than dropping it.
        let sql = format!(
            "SELECT {TRAFFIC_COLUMNS} FROM traffic WHERE session_id = ?1 \
             ORDER BY started_at DESC, traffic_id DESC LIMIT ?2"
        );
        let fetch = if limit == 0 {
            -1
        } else {
            (limit as i64).saturating_add(1)
        };
        let mut statement = self.conn.prepare(&sql)?;
        let rows = statement.query_map(rusqlite::params![session_id.0, fetch], |row| {
            let row_id: i64 = row.get("row_id")?;
            decode_row(row, restored_traffic_id(row_id))
        })?;

        let mut entries = Vec::new();
        for row in rows {
            entries.push(row?);
        }
        let truncated = limit > 0 && entries.len() > limit;
        entries.truncate(limit.min(entries.len()));
        entries.reverse();
        Ok((entries, truncated))
    }

    /// Writes redacted JSON Lines for a session to `path`.
    ///
    /// The file is built in a sibling temporary file and renamed into place, so
    /// an interrupted export never leaves a half-written history that looks
    /// complete. Files are owner-only on Unix.
    pub fn export_session(
        &self,
        session_id: &SessionId,
        path: &Path,
    ) -> Result<ExportSummary, StoreError> {
        if !self.session_exists(session_id)? {
            return Err(StoreError::UnknownSession(session_id.0.clone()));
        }
        let name: String = self.conn.query_row(
            "SELECT name FROM sessions WHERE id = ?1",
            rusqlite::params![session_id.0],
            |row| row.get(0),
        )?;
        let sql = format!(
            "SELECT {TRAFFIC_COLUMNS} FROM traffic WHERE session_id = ?1 \
             ORDER BY started_at ASC, traffic_id ASC"
        );
        let mut statement = self.conn.prepare(&sql)?;
        let mut rows = statement.query(rusqlite::params![session_id.0])?;

        create_parent(path)?;
        let unique = format!("{}.{}.tmp", path.display(), std::process::id());
        let temp_path = PathBuf::from(&unique);
        let mut summary = ExportSummary {
            records: 0,
            redacted_headers: 0,
            bodies_omitted: 0,
        };

        {
            let file = fs::File::create(&temp_path)?;
            restrict_permissions(&temp_path)?;
            let mut writer = std::io::BufWriter::new(file);
            while let Some(row) = rows.next()? {
                let row_id: i64 = row.get("row_id")?;
                let entry = decode_row(row, restored_traffic_id(row_id))?;
                let record = TrafficRecord::encode(&entry, self.policy);
                summary.redacted_headers += entry.redacted_headers;
                let request_omitted = row.get::<_, i64>("request_body_omitted").unwrap_or(0) != 0;
                let response_omitted = row.get::<_, i64>("response_body_omitted").unwrap_or(0) != 0;
                if request_omitted || response_omitted {
                    summary.bodies_omitted += 1;
                }

                let line = json!({
                    "format": "rawframe.history.v1",
                    "session": { "id": session_id.0, "name": name },
                    "traffic_id": row.get::<_, i64>("traffic_id").unwrap_or_default(),
                    "restored_as": entry.id.0,
                    "restored": true,
                    "kind": record.kind,
                    // decode_row labels loaded entries as restored; export must
                    // report the producer that was actually stored instead.
                    "stored_source": row.get::<_, String>("source").unwrap_or_else(|_| "restored".into()),
                    "state": record.state,
                    "method": entry.request.method,
                    "scheme": record.scheme,
                    "host": entry.request.host,
                    "port": entry.request.port,
                    "target": entry.request.target,
                    "version": entry.request.version,
                    "request_headers": entry.request.headers.iter().map(|header| json!({
                        "name": header.name,
                        "value": header.value,
                    })).collect::<Vec<_>>(),
                    "request_body": body_json(&entry.request.body, request_omitted),
                    "response": entry.response.as_ref().map(|response| json!({
                        "status": response.status,
                        "reason": response.reason,
                        "version": response.version,
                        "headers": response.headers.iter().map(|header| json!({
                            "name": header.name,
                            "value": header.value,
                        })).collect::<Vec<_>>(),
                        "body": body_json(&response.body, response_omitted),
                    })),
                    "tunnel": entry.tunnel.as_ref().map(tunnel_json),
                    "repeater_origin": entry.repeater_origin.map(|id| id.0),
                    "started_at": entry.timings.started_at.to_rfc3339(),
                    "completed_at": entry.timings.completed_at.map(|value| value.to_rfc3339()),
                    "duration_ms": entry.timings.duration_ms,
                    "error": entry.error,
                    "note": entry.note,
                    "incomplete": entry.state.is_pending(),
                });
                if let Err(error) = writeln!(writer, "{line}") {
                    drop(writer);
                    let _ = fs::remove_file(&temp_path);
                    return Err(StoreError::Io(error));
                }
                summary.records += 1;
            }
            writer.flush()?;
        }

        fs::rename(&temp_path, path)?;
        Ok(summary)
    }

    /// True when the database still reports itself healthy.
    pub fn quick_check(&self) -> Result<(), StoreError> {
        let check: String = self
            .conn
            .pragma_query_value(None, "quick_check", |row| row.get(0))?;
        if check.eq_ignore_ascii_case("ok") {
            Ok(())
        } else {
            Err(StoreError::Corrupt(check))
        }
    }

    /// Number of stored transactions for the current session.
    pub fn count_records(&self, session_id: &SessionId) -> Result<usize, StoreError> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM traffic WHERE session_id = ?1",
            rusqlite::params![session_id.0],
            |row| row.get(0),
        )?;
        Ok(count.max(0) as usize)
    }
}

fn map_write_error(error: rusqlite::Error, max_bytes: u64) -> StoreError {
    let mapped = StoreError::from(error);
    if mapped.is_size_limit() {
        StoreError::Full(max_bytes)
    } else {
        mapped
    }
}

fn body_json(body: &[u8], omitted: bool) -> serde_json::Value {
    if omitted {
        return json!({ "omitted": true, "reason": "storage policy does not persist bodies" });
    }
    match std::str::from_utf8(body) {
        Ok(text) => json!({ "encoding": "utf-8", "text": text }),
        Err(_) => json!({ "encoding": "hex", "hex": hex(body) }),
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

fn tunnel_json(tunnel: &TunnelMetadata) -> serde_json::Value {
    json!({
        "client_to_upstream_bytes": tunnel.client_to_upstream_bytes,
        "upstream_to_client_bytes": tunnel.upstream_to_client_bytes,
        "outcome": tunnel.outcome.label(),
    })
}

fn create_parent(path: &Path) -> Result<(), StoreError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
        }
    }
    Ok(())
}

fn restrict_permissions(path: &Path) -> Result<(), StoreError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Default database location: `$XDG_DATA_HOME/rawframe/sessions.db` or the
/// platform data directory, matching how the CLI resolves configuration.
pub fn default_database_path() -> PathBuf {
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("rawframe").join("sessions.db")
}

/// Parses a stored timestamp, exposed for the session browser and tests.
pub fn parse_timestamp(text: &str) -> Option<DateTime<Utc>> {
    crate::record::parse_stored_time(text)
}
