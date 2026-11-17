//! Conversion between captured [`TrafficEntry`] values and database rows.
//!
//! The storage policy is applied here, on the write path, so no code path can
//! accidentally insert an unredacted secret or an unrequested body. Bodies that
//! are not persisted become SQL `NULL` (never zero-length BLOBs), and the
//! omitted flag is carried back to the interface on restore.

use chrono::{DateTime, SecondsFormat, Utc};
use rawframe_core::models::headers::Headers;
use rawframe_core::models::message::{HttpRequest, HttpResponse, Scheme};
use rawframe_core::models::traffic::{
    InterceptionMetadata, TrafficEntry, TrafficId, TrafficKind, TrafficSource, TrafficState,
    TrafficTimings, TunnelMetadata,
};
use rawframe_core::storage::StoragePolicy;
use rusqlite::Row;
use rusqlite::types::Type;
use serde::{Deserialize, Serialize};

/// Restored entries are given interface identifiers above the live range
/// (which starts at 1,000) so a restored row can never be mistaken for a live
/// capture, even though the original capture id is stored separately.
pub const RESTORED_ID_BASE: u64 = 1_000_000;

pub fn restored_traffic_id(row_id: i64) -> TrafficId {
    TrafficId(RESTORED_ID_BASE + row_id as u64)
}

/// A transaction encoded for insertion, with the policy already applied.
#[derive(Debug, Clone)]
pub struct TrafficRecord {
    pub traffic_id: i64,
    pub kind: &'static str,
    pub source: &'static str,
    pub state: &'static str,
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub target: String,
    pub version: String,
    pub request_headers: String,
    pub request_body: Option<Vec<u8>>,
    pub request_body_omitted: bool,
    pub redacted_headers: usize,
    pub response: Option<ResponseRecord>,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub duration_ms: Option<u64>,
    pub error: Option<String>,
    pub note: Option<String>,
    pub original_request: Option<String>,
    pub final_request: Option<String>,
    pub interception: String,
    pub tunnel: Option<String>,
    pub repeater_origin: Option<i64>,
    pub incomplete: bool,
}

#[derive(Debug, Clone)]
pub struct ResponseRecord {
    pub status: u16,
    pub reason: String,
    pub version: String,
    pub headers: String,
    pub body: Option<Vec<u8>>,
    pub body_omitted: bool,
}

impl TrafficRecord {
    pub fn encode(entry: &TrafficEntry, policy: StoragePolicy) -> Self {
        let (request_headers, mut redacted_headers) =
            encode_headers(&entry.request.headers, policy);
        let request_body = encode_body(&entry.request.body, policy);

        let response = entry.response.as_ref().map(|response| {
            let (headers, redacted) = encode_headers(&response.headers, policy);
            redacted_headers += redacted;
            ResponseRecord {
                status: response.status,
                reason: response.reason.clone(),
                version: response.version.clone(),
                headers,
                body: encode_body(&response.body, policy),
                body_omitted: !policy.persist_bodies && !response.body.is_empty(),
            }
        });

        Self {
            traffic_id: entry.id.0 as i64,
            kind: kind_str(entry.kind),
            // Provenance is preserved verbatim; the loader always presents it as
            // restored, but the export keeps what actually produced the record.
            source: source_str(entry.source),
            state: state_str(entry.state),
            method: entry.request.method.clone(),
            scheme: scheme_str(entry.request.scheme).to_string(),
            host: entry.request.host.clone(),
            port: entry.request.port,
            target: entry.request.target.clone(),
            version: entry.request.version.clone(),
            request_headers,
            request_body_omitted: !policy.persist_bodies && !entry.request.body.is_empty(),
            request_body,
            redacted_headers,
            response,
            started_at: timestamp(entry.timings.started_at),
            completed_at: entry.timings.completed_at.map(timestamp),
            duration_ms: entry.timings.duration_ms,
            error: entry.error.clone(),
            note: entry.note.clone(),
            original_request: encode_sub_request(entry.original_request.as_ref(), policy),
            final_request: encode_sub_request(entry.final_request.as_ref(), policy),
            interception: serde_json::to_string(&entry.interception)
                .unwrap_or_else(|_| "{}".into()),
            tunnel: entry
                .tunnel
                .as_ref()
                .and_then(|tunnel| serde_json::to_string(tunnel).ok()),
            repeater_origin: entry.repeater_origin.map(|id| id.0 as i64),
            incomplete: !entry.state.is_terminal(),
        }
    }

    /// True when any body in this record was withheld by policy.
    pub fn body_omitted(&self) -> bool {
        self.request_body_omitted || self.response.as_ref().is_some_and(|r| r.body_omitted)
    }
}

fn kind_str(kind: TrafficKind) -> &'static str {
    match kind {
        TrafficKind::Http => "http",
        TrafficKind::ConnectTunnel => "connect_tunnel",
    }
}

fn parse_kind(value: &str) -> TrafficKind {
    match value {
        "connect_tunnel" => TrafficKind::ConnectTunnel,
        _ => TrafficKind::Http,
    }
}

fn source_str(source: TrafficSource) -> &'static str {
    match source {
        TrafficSource::Intercepted => "intercepted",
        TrafficSource::Simulated => "simulated",
        TrafficSource::Authored => "authored",
        TrafficSource::Repeater => "repeater",
        TrafficSource::Restored => "restored",
    }
}

fn state_str(state: TrafficState) -> &'static str {
    match state {
        TrafficState::Captured => "captured",
        TrafficState::Paused => "paused",
        TrafficState::Modified => "modified",
        TrafficState::Forwarded => "forwarded",
        TrafficState::Dropped => "dropped",
        TrafficState::Completed => "completed",
        TrafficState::Failed => "failed",
        TrafficState::TimedOut => "timed_out",
        TrafficState::Cancelled => "cancelled",
    }
}

fn parse_state(value: &str) -> TrafficState {
    match value {
        "paused" => TrafficState::Paused,
        "modified" => TrafficState::Modified,
        "forwarded" => TrafficState::Forwarded,
        "dropped" => TrafficState::Dropped,
        "completed" => TrafficState::Completed,
        "failed" => TrafficState::Failed,
        "timed_out" => TrafficState::TimedOut,
        "cancelled" => TrafficState::Cancelled,
        _ => TrafficState::Captured,
    }
}

fn scheme_str(scheme: Scheme) -> &'static str {
    match scheme {
        Scheme::Http => "http",
        Scheme::Https => "https",
    }
}

fn parse_scheme(value: &str) -> Scheme {
    match value {
        "https" => Scheme::Https,
        _ => Scheme::Http,
    }
}

fn timestamp(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Micros, true)
}

fn encode_body(body: &[u8], policy: StoragePolicy) -> Option<Vec<u8>> {
    if policy.persist_bodies {
        Some(body.to_vec())
    } else {
        None
    }
}

#[derive(Serialize, Deserialize)]
struct HeaderWire {
    name: String,
    value: String,
}

fn encode_headers(headers: &Headers, policy: StoragePolicy) -> (String, usize) {
    let mut redacted = 0;
    let wire: Vec<HeaderWire> = headers
        .iter()
        .map(|header| {
            let value = if !policy.persist_sensitive_headers && Headers::is_sensitive(&header.name)
            {
                redacted += 1;
                "<redacted>".to_string()
            } else {
                header.value.clone()
            };
            HeaderWire {
                name: header.name.clone(),
                value,
            }
        })
        .collect();
    (
        serde_json::to_string(&wire).unwrap_or_else(|_| "[]".into()),
        redacted,
    )
}

fn decode_headers(value: &str) -> Headers {
    match serde_json::from_str::<Vec<HeaderWire>>(value) {
        Ok(wire) => {
            let mut headers = Headers::new();
            for header in wire {
                headers.append(header.name, header.value);
            }
            headers
        }
        Err(_) => Headers::new(),
    }
}

#[derive(Serialize, Deserialize)]
struct RequestWire {
    request: HttpRequest,
    #[serde(default)]
    body_omitted: bool,
}

fn encode_sub_request(request: Option<&HttpRequest>, policy: StoragePolicy) -> Option<String> {
    let request = request?;
    let mut stored = request.clone();
    let mut body_omitted = false;
    if !policy.persist_sensitive_headers {
        let (redacted, _) = stored.headers.redacted();
        stored.headers = redacted;
    }
    if !policy.persist_bodies && !stored.body.is_empty() {
        stored.body.clear();
        body_omitted = true;
    }
    serde_json::to_string(&RequestWire {
        request: stored,
        body_omitted,
    })
    .ok()
}

fn decode_sub_request(value: Option<String>, omitted: &mut bool) -> Option<HttpRequest> {
    let wire: RequestWire = serde_json::from_str(value.as_deref()?).ok()?;
    if wire.body_omitted {
        *omitted = true;
    }
    Some(wire.request)
}

fn parse_time(text: &str, column: &str) -> rusqlite::Result<DateTime<Utc>> {
    match DateTime::parse_from_rfc3339(text) {
        Ok(value) => Ok(value.with_timezone(&Utc)),
        Err(error) => Err(rusqlite::Error::FromSqlConversionFailure(
            0,
            Type::Text,
            Box::new(std::io::Error::other(format!(
                "invalid {column} timestamp {text:?}: {error}"
            ))),
        )),
    }
}

fn optional_time(text: Option<String>, column: &str) -> rusqlite::Result<Option<DateTime<Utc>>> {
    text.map(|text| parse_time(&text, column)).transpose()
}

/// Decodes a stored row back into a restored, read-only traffic entry.
pub fn decode_row(row: &Row<'_>, interface_id: TrafficId) -> rusqlite::Result<TrafficEntry> {
    let request = HttpRequest {
        method: row.get("method")?,
        scheme: parse_scheme(&row.get::<_, String>("scheme")?),
        host: row.get("host")?,
        port: row.get("port")?,
        target: row.get("target")?,
        version: row.get("version")?,
        headers: decode_headers(&row.get::<_, String>("request_headers")?),
        body: row
            .get::<_, Option<Vec<u8>>>("request_body")?
            .unwrap_or_default(),
    };

    let mut omitted = row.get::<_, i64>("request_body_omitted")? != 0;
    let original_request = decode_sub_request(row.get("original_request")?, &mut omitted);
    let final_request = decode_sub_request(row.get("final_request")?, &mut omitted);

    let response = match row.get::<_, Option<u16>>("response_status")? {
        Some(status) => {
            let headers_text: Option<String> = row.get("response_headers")?;
            let body_omitted: i64 = row.get("response_body_omitted")?;
            if body_omitted != 0 {
                omitted = true;
            }
            Some(HttpResponse {
                status,
                reason: row
                    .get::<_, Option<String>>("response_reason")?
                    .unwrap_or_default(),
                version: row
                    .get::<_, Option<String>>("response_version")?
                    .unwrap_or_else(|| "HTTP/1.1".to_string()),
                headers: headers_text
                    .as_deref()
                    .map(decode_headers)
                    .unwrap_or_default(),
                body: row
                    .get::<_, Option<Vec<u8>>>("response_body")?
                    .unwrap_or_default(),
            })
        }
        None => None,
    };

    let interception = row
        .get::<_, String>("interception")
        .ok()
        .and_then(|text| serde_json::from_str::<InterceptionMetadata>(&text).ok())
        .unwrap_or_default();
    let tunnel = row
        .get::<_, Option<String>>("tunnel")?
        .and_then(|text| serde_json::from_str::<TunnelMetadata>(&text).ok());

    Ok(TrafficEntry {
        id: interface_id,
        request,
        response,
        state: parse_state(&row.get::<_, String>("state")?),
        source: TrafficSource::Restored,
        timings: TrafficTimings {
            started_at: parse_time(&row.get::<_, String>("started_at")?, "started_at")?,
            completed_at: optional_time(row.get("completed_at")?, "completed_at")?,
            duration_ms: row
                .get::<_, Option<i64>>("duration_ms")?
                .map(|value| value.max(0) as u64),
        },
        error: row.get("error")?,
        note: row.get("note")?,
        kind: parse_kind(&row.get::<_, String>("kind")?),
        tunnel,
        original_request,
        final_request,
        interception,
        body_omitted: omitted,
        redacted_headers: row.get::<_, i64>("redacted_headers")?.max(0) as usize,
        repeater_origin: row
            .get::<_, Option<i64>>("repeater_origin")?
            .map(|value| TrafficId(value.max(0) as u64)),
    })
}

/// Utility kept for callers that need a UTC timestamp from SQLite text.
pub fn parse_stored_time(text: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(text)
        .ok()
        .map(|value| value.with_timezone(&Utc))
}

/// Helper for exports: RFC 3339 in UTC.
pub fn now_stamp() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Micros, true)
}
