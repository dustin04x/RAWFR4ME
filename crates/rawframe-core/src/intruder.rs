//! Intruder contracts: payload positions, payload sources, attack plans, and
//! execution vocabulary.
//!
//! This module deliberately contains no networking, filesystem, or terminal
//! code. It is the single definition of what a payload position is, how a
//! request template expands, and exactly how many requests a strategy will
//! generate *before* any connection is attempted. The execution engine, the
//! interface, and persistence all share these types so a generated request can
//! never be confused with captured traffic or a hand-authored Repeater draft.
//!
//! Payload positions are written as `§value§` inside a component: the enclosed
//! text is the original literal, and an active position replaces it with a
//! payload. Markers are scanned at the byte level, so a body that is not valid
//! UTF-8 is handled without re-encoding or corruption.

use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;

use crate::models::headers::Headers;
use crate::models::message::{HttpRequest, Scheme, StatusClass};
use crate::models::traffic::{TrafficId, TrafficState};
use crate::repeater::{ExecutionComparison, RepeaterExecutionPhase, RepeaterResult};

/// Delimiter for a payload position. `§` is a single Unicode character encoded
/// as two bytes, so scanning stays byte-accurate for binary bodies.
pub const MARKER: &str = "§";
const MARKER_BYTES: &[u8] = MARKER.as_bytes();

/// Above this many positions a request is almost always a mistake, and the
/// combination count for Cartesian strategies grows beyond what an operator can
/// review.
pub const MAX_POSITIONS: usize = 16;
pub const MAX_POSITION_LABEL: usize = 48;
pub const MAX_PAYLOAD_SETS: usize = 16;
pub const MAX_PAYLOADS_PER_SET: usize = 512;
pub const MAX_PAYLOAD_BYTES: usize = 4096;
/// Hard ceiling on a single plan. Checked before a plan is built, so an
/// expensive attack is rejected instead of materialized and then discarded.
pub const MAX_GENERATED_REQUESTS: u64 = 2048;
pub const MAX_CONCURRENCY: usize = 8;
pub const DEFAULT_CONCURRENCY: usize = 2;
pub const MAX_RATE_PER_SECOND: u32 = 20;
pub const DEFAULT_RATE_PER_SECOND: u32 = 2;
pub const DEFAULT_MAX_DURATION_SECS: u64 = 300;
pub const MAX_DURATION_SECS: u64 = 1800;
/// Local wordlists are read incrementally and capped; the raw file is never
/// loaded wholesale into memory.
pub const MAX_WORDLIST_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_WORDLIST_LINE_BYTES: usize = 4096;
/// Intruder transactions are persisted with a distinct id range so they can
/// never collide with proxy captures (base 1), restored history (1M), or
/// Repeater results (2M).
pub const INTRUDER_ID_BASE: u64 = 3_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PositionId(pub u16);

impl std::fmt::Display for PositionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Where a position lives in the request. Path and query positions share the
/// request target on the wire but are reported separately because they are
/// usually attacked differently.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum PositionArea {
    Path,
    Query,
    Header { index: usize, name: String },
    Body,
}

impl PositionArea {
    pub fn label(&self) -> &str {
        match self {
            Self::Path => "path",
            Self::Query => "query",
            Self::Header { name, .. } => name,
            Self::Body => "body",
        }
    }

    pub const fn kind_label(&self) -> &'static str {
        match self {
            Self::Path => "PATH",
            Self::Query => "QUERY",
            Self::Header { .. } => "HEADER",
            Self::Body => "BODY",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Position {
    pub id: PositionId,
    pub area: PositionArea,
    /// The original literal the marker enclosed. Kept byte-exact so an inactive
    /// position restores exactly what the capture had.
    pub literal: Vec<u8>,
    /// Display label, unique within the template (duplicates get `#2`, `#3`).
    pub label: String,
}

impl Position {
    pub fn literal_display(&self) -> String {
        String::from_utf8_lossy(&self.literal).into_owned()
    }
}

/// One component of a request split into literal runs and payload slots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Segment {
    Literal(Vec<u8>),
    Slot { id: PositionId, literal: Vec<u8> },
}

/// A parsed template: ordered segments plus the positions they define.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TemplateAnalysis {
    pub target: Vec<Segment>,
    pub headers: Vec<(String, Vec<Segment>)>,
    pub body: Vec<Segment>,
    pub positions: Vec<Position>,
}

impl TemplateAnalysis {
    pub fn position(&self, id: PositionId) -> Option<&Position> {
        self.positions.iter().find(|position| position.id == id)
    }

    pub fn position_ids(&self) -> Vec<PositionId> {
        self.positions.iter().map(|position| position.id).collect()
    }

    pub fn contains(&self, id: PositionId) -> bool {
        self.position(id).is_some()
    }
}

/// The editable request used by an attack. Method, scheme, destination, and
/// version are fixed by the source capture; only the target, header values, and
/// body carry markers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntruderTemplate {
    pub method: String,
    pub scheme: Scheme,
    pub host: String,
    pub port: u16,
    pub version: String,
    pub target: String,
    /// Ordered headers, duplicates preserved. Values may contain markers;
    /// names may not.
    pub headers: Vec<(String, String)>,
    /// Raw body bytes. May contain markers and may be arbitrary binary data.
    pub body: Vec<u8>,
}

impl IntruderTemplate {
    /// Seeds a template from a real capture with no positions marked.
    pub fn from_request(request: &HttpRequest) -> Self {
        Self {
            method: request.method.clone(),
            scheme: request.scheme,
            host: request.host.clone(),
            port: request.port,
            version: request.version.clone(),
            target: request.target.clone(),
            headers: request
                .headers
                .iter()
                .map(|header| (header.name.clone(), header.value.clone()))
                .collect(),
            body: request.body.clone(),
        }
    }

    pub fn authority(&self) -> String {
        let default = self.scheme.default_port();
        if self.port == default {
            self.host.clone()
        } else if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    pub fn url(&self) -> String {
        format!("{}://{}{}", self.scheme, self.authority(), self.target)
    }

    /// The editable request line and headers. The body is edited separately so
    /// binary bodies are never forced through UTF-8.
    pub fn head_text(&self) -> String {
        let mut text = format!("{} {} {}\n", self.method, self.target, self.version);
        for (name, value) in &self.headers {
            text.push_str(name);
            text.push_str(": ");
            text.push_str(value);
            text.push('\n');
        }
        text
    }

    /// Replaces method, target, and ordered headers from editor text. A malformed
    /// line is reported rather than dropped: silently discarding a header would
    /// change the request the operator believes they are sending.
    pub fn set_head_text(&mut self, text: &str) -> Result<(), TemplateError> {
        let mut lines = text.split('\n').peekable();
        let request_line = loop {
            match lines.next() {
                Some(line) => {
                    let line = line.trim_end_matches('\r');
                    if !line.trim().is_empty() {
                        break line;
                    }
                }
                None => return Err(TemplateError::InvalidHead("request line is missing".into())),
            }
        };
        let mut parts = request_line.split_whitespace();
        let method = parts
            .next()
            .ok_or_else(|| TemplateError::InvalidHead("request method is missing".into()))?;
        let target = parts
            .next()
            .ok_or_else(|| TemplateError::InvalidHead("request target is missing".into()))?;
        let version = parts.next().unwrap_or("HTTP/1.1");
        if version != "HTTP/1.0" && version != "HTTP/1.1" {
            return Err(TemplateError::InvalidHead(format!(
                "unsupported HTTP version '{version}'"
            )));
        }
        if target.contains(char::is_whitespace) {
            return Err(TemplateError::InvalidHead(
                "request target contains whitespace".into(),
            ));
        }

        let mut headers: Vec<(String, String)> = Vec::new();
        for raw in lines {
            let line = raw.trim_end_matches('\r');
            if line.is_empty() {
                break;
            }
            if line.starts_with('#') || line.starts_with("//") {
                // Comments are shown as-is but never sent. Ignoring them here is
                // explicit so a commented-out header cannot be transmitted.
                continue;
            }
            let Some((name, value)) = line.split_once(':') else {
                return Err(TemplateError::InvalidHead(format!(
                    "header line '{line}' has no ':' separator"
                )));
            };
            let name = name.trim();
            if name.is_empty() {
                return Err(TemplateError::InvalidHead("header name is empty".into()));
            }
            if find_marker(name.as_bytes()).is_some() {
                return Err(TemplateError::MarkerInHeaderName(name.to_string()));
            }
            headers.push((name.to_string(), value.trim_start().to_string()));
        }

        self.method = method.to_ascii_uppercase();
        self.target = target.to_string();
        self.version = version.to_string();
        self.headers = headers;
        Ok(())
    }

    pub fn body_text(&self) -> Option<&str> {
        std::str::from_utf8(&self.body).ok()
    }

    /// Sets the body from editor text. The text is stored byte-exact; markers in
    /// it become positions.
    pub fn set_body_text(&mut self, text: &str) {
        self.body = text.as_bytes().to_vec();
    }

    pub fn has_markers(&self) -> bool {
        find_marker(self.target.as_bytes()).is_some()
            || self
                .headers
                .iter()
                .any(|(_, value)| find_marker(value.as_bytes()).is_some())
            || find_marker(&self.body).is_some()
    }

    pub fn clear_markers(&mut self) {
        self.target = strip_all_markers(&self.target);
        for (_, value) in self.headers.iter_mut() {
            *value = strip_all_markers(value);
        }
        if let Ok(spans) = split_segments(&self.body) {
            let mut restored = Vec::with_capacity(self.body.len());
            let mut cursor = 0usize;
            for (open, close, literal) in spans.1 {
                restored.extend_from_slice(&self.body[cursor..open]);
                restored.extend_from_slice(literal);
                cursor = close;
            }
            restored.extend_from_slice(&self.body[cursor..]);
            self.body = restored;
        }
    }

    /// Wraps the whole body in a single position. This is the only way to mark
    /// a body that cannot be edited as text, and it is byte-exact.
    pub fn mark_whole_body(&mut self) {
        if self.body.is_empty() || find_marker(&self.body).is_some() {
            return;
        }
        let mut marked = Vec::with_capacity(self.body.len() + MARKER_BYTES.len() * 2);
        marked.extend_from_slice(MARKER_BYTES);
        marked.extend_from_slice(&self.body);
        marked.extend_from_slice(MARKER_BYTES);
        self.body = marked;
    }

    /// Splits the request into literal runs and slots, assigning stable position
    /// ids in document order: target, then headers, then body.
    pub fn analyze(&self) -> Result<TemplateAnalysis, TemplateError> {
        let mut positions: Vec<Position> = Vec::new();
        let query_at = self.target.as_bytes().iter().position(|byte| *byte == b'?');
        let target = analyze_component(
            self.target.as_bytes(),
            |offset| match query_at {
                Some(index) if offset >= index => PositionArea::Query,
                _ => PositionArea::Path,
            },
            &mut positions,
        )?;

        let mut headers = Vec::with_capacity(self.headers.len());
        for (index, (name, value)) in self.headers.iter().enumerate() {
            if find_marker(name.as_bytes()).is_some() {
                return Err(TemplateError::MarkerInHeaderName(name.clone()));
            }
            let header_name = name.clone();
            let segments = analyze_component(
                value.as_bytes(),
                move |_| PositionArea::Header {
                    index,
                    name: header_name.clone(),
                },
                &mut positions,
            )?;
            headers.push((name.clone(), segments));
        }

        let body = analyze_component(&self.body, |_| PositionArea::Body, &mut positions)?;
        label_positions(&mut positions);

        Ok(TemplateAnalysis {
            target,
            headers,
            body,
            positions,
        })
    }

    /// Expands the template with the supplied payloads. Positions absent from
    /// `slots` keep their original literal, which is exactly how Sniper leaves
    /// untouched positions alone.
    pub fn expand(
        &self,
        analysis: &TemplateAnalysis,
        slots: &BTreeMap<PositionId, Vec<u8>>,
    ) -> Result<HttpRequest, TemplateError> {
        let target = expand_text(&analysis.target, slots)?;
        let mut headers = Headers::new();
        for (name, segments) in &analysis.headers {
            headers.append(name.clone(), expand_text(segments, slots)?);
        }
        let body = expand_bytes(&analysis.body, slots);

        Ok(HttpRequest {
            method: self.method.clone(),
            scheme: self.scheme,
            host: self.host.clone(),
            port: self.port,
            target,
            version: self.version.clone(),
            headers,
            body,
        })
    }
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum TemplateError {
    #[error("payload marker is not closed; every {MARKER} must be paired")]
    UnmatchedMarker,
    #[error("request contains more than {MAX_POSITIONS} payload positions")]
    TooManyPositions,
    #[error("a payload marker may not appear inside a header name ('{0}')")]
    MarkerInHeaderName(String),
    #[error("invalid request head: {0}")]
    InvalidHead(String),
    #[error("payload for position {0} is not valid UTF-8 and cannot be placed in a URL or header")]
    NonUtf8Payload(PositionId),
}

fn find_marker(haystack: &[u8]) -> Option<usize> {
    if haystack.len() < MARKER_BYTES.len() {
        return None;
    }
    haystack
        .windows(MARKER_BYTES.len())
        .position(|window| window == MARKER_BYTES)
}

fn analyze_component(
    bytes: &[u8],
    mut area: impl FnMut(usize) -> PositionArea,
    positions: &mut Vec<Position>,
) -> Result<Vec<Segment>, TemplateError> {
    let (_, slots) = split_segments(bytes)?;
    let mut segments = Vec::new();
    let mut cursor = 0usize;
    for (open, close, literal) in slots {
        if open > cursor {
            segments.push(Segment::Literal(bytes[cursor..open].to_vec()));
        }
        if positions.len() >= MAX_POSITIONS {
            return Err(TemplateError::TooManyPositions);
        }
        let id = PositionId((positions.len() + 1) as u16);
        positions.push(Position {
            id,
            area: area(open),
            literal: literal.to_vec(),
            label: String::new(),
        });
        segments.push(Segment::Slot {
            id,
            literal: literal.to_vec(),
        });
        cursor = close;
    }
    if cursor < bytes.len() {
        segments.push(Segment::Literal(bytes[cursor..].to_vec()));
    }
    Ok(segments)
}

/// Splits bytes into literal runs and marker spans. Returns the literal-only
/// bytes plus `(open, close_after_marker, inner)` spans.
#[allow(clippy::type_complexity)]
fn split_segments(bytes: &[u8]) -> Result<(Vec<u8>, Vec<(usize, usize, &[u8])>), TemplateError> {
    let mut literal = Vec::new();
    let mut spans = Vec::new();
    let mut cursor = 0usize;
    while let Some(open_rel) = find_marker(&bytes[cursor..]) {
        let open = cursor + open_rel;
        let Some(close_rel) = find_marker(&bytes[open + MARKER_BYTES.len()..]) else {
            return Err(TemplateError::UnmatchedMarker);
        };
        let close_at = open + MARKER_BYTES.len() + close_rel;
        literal.extend_from_slice(&bytes[cursor..open]);
        spans.push((
            open,
            close_at + MARKER_BYTES.len(),
            &bytes[open + MARKER_BYTES.len()..close_at],
        ));
        cursor = close_at + MARKER_BYTES.len();
    }
    literal.extend_from_slice(&bytes[cursor..]);
    Ok((literal, spans))
}

/// Removes marker delimiters while keeping the literals they enclosed, so
/// clearing positions restores exactly the captured values.
fn strip_all_markers(text: &str) -> String {
    let bytes = text.as_bytes();
    match split_segments(bytes) {
        Ok((_, spans)) => {
            if spans.is_empty() {
                return text.to_string();
            }
            let mut out = String::with_capacity(text.len());
            let mut cursor = 0usize;
            for (open, close, literal) in spans {
                out.push_str(&String::from_utf8_lossy(&bytes[cursor..open]));
                out.push_str(&String::from_utf8_lossy(literal));
                cursor = close;
            }
            out.push_str(&String::from_utf8_lossy(&bytes[cursor..]));
            out
        }
        Err(_) => text.to_string(),
    }
}

fn label_positions(positions: &mut [Position]) {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for position in positions.iter_mut() {
        let base = position.area.label().to_string();
        let count = counts.entry(base.clone()).or_insert(0);
        *count += 1;
        let label = if *count == 1 {
            base
        } else {
            format!("{base} #{count}")
        };
        position.label = truncate_chars(&label, MAX_POSITION_LABEL);
    }
}

fn truncate_chars(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        text.to_string()
    } else {
        text.chars().take(max.saturating_sub(1)).collect::<String>() + "…"
    }
}

fn expand_bytes(segments: &[Segment], slots: &BTreeMap<PositionId, Vec<u8>>) -> Vec<u8> {
    let mut out = Vec::new();
    for segment in segments {
        match segment {
            Segment::Literal(bytes) => out.extend_from_slice(bytes),
            Segment::Slot { id, literal } => {
                out.extend_from_slice(slots.get(id).unwrap_or(literal));
            }
        }
    }
    out
}

fn expand_text(
    segments: &[Segment],
    slots: &BTreeMap<PositionId, Vec<u8>>,
) -> Result<String, TemplateError> {
    let mut out = String::new();
    for segment in segments {
        match segment {
            Segment::Literal(bytes) => out.push_str(&String::from_utf8_lossy(bytes)),
            Segment::Slot { id, literal } => match slots.get(id) {
                Some(payload) => {
                    let text = std::str::from_utf8(payload)
                        .map_err(|_| TemplateError::NonUtf8Payload(*id))?;
                    out.push_str(text);
                }
                None => out.push_str(&String::from_utf8_lossy(literal)),
            },
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Payload sources

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadSource {
    /// Typed by the operator for this session.
    Manual,
    /// A small, harmless demonstration set.
    BuiltIn,
    /// A reusable session-local named list.
    NamedList,
    /// Imported from a local text file, bounded and read incrementally.
    Wordlist,
}

impl PayloadSource {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Manual => "MANUAL",
            Self::BuiltIn => "BUILT-IN",
            Self::NamedList => "LIST",
            Self::Wordlist => "WORDLIST",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadSet {
    pub id: u32,
    pub name: String,
    pub source: PayloadSource,
    pub payloads: Vec<Vec<u8>>,
}

impl PayloadSet {
    /// Parses one payload per line. A single trailing newline is not a payload;
    /// interior blank lines are preserved as intentional empty payloads.
    pub fn manual(id: u32, name: impl Into<String>, text: &str) -> Result<Self, PayloadError> {
        let trimmed = text.strip_suffix('\n').unwrap_or(text);
        let trimmed = trimmed.strip_suffix('\r').unwrap_or(trimmed);
        let payloads: Vec<Vec<u8>> = if trimmed.is_empty() && text.is_empty() {
            Vec::new()
        } else {
            trimmed
                .split('\n')
                .map(|line| line.strip_suffix('\r').unwrap_or(line).as_bytes().to_vec())
                .collect()
        };
        if payloads.len() > MAX_PAYLOADS_PER_SET {
            return Err(PayloadError::TooMany {
                count: payloads.len(),
                limit: MAX_PAYLOADS_PER_SET,
            });
        }
        for payload in &payloads {
            if payload.len() > MAX_PAYLOAD_BYTES {
                return Err(PayloadError::TooLarge {
                    bytes: payload.len(),
                    limit: MAX_PAYLOAD_BYTES,
                });
            }
        }
        Ok(Self {
            id,
            name: name.into(),
            source: PayloadSource::Manual,
            payloads,
        })
    }

    /// The built-in set is intentionally mundane: it demonstrates the mechanics
    /// of each strategy without shipping an exploit list.
    pub fn builtin(id: u32) -> Self {
        Self {
            id,
            name: "built-in demo values".into(),
            source: PayloadSource::BuiltIn,
            payloads: ["1", "2", "test", "example", "true", "false", "0", ""]
                .iter()
                .map(|value| value.as_bytes().to_vec())
                .collect(),
        }
    }

    pub fn len(&self) -> usize {
        self.payloads.len()
    }

    pub fn is_empty(&self) -> bool {
        self.payloads.is_empty()
    }

    pub fn summary(&self) -> String {
        format!("{} · {} payloads", self.source.label(), self.payloads.len())
    }

    fn validate(&self) -> Result<(), PlanError> {
        if self.payloads.is_empty() {
            return Err(PlanError::EmptyPayloadSet(self.name.clone()));
        }
        if self.payloads.len() > MAX_PAYLOADS_PER_SET {
            return Err(PlanError::PayloadSetTooLarge {
                name: self.name.clone(),
                count: self.payloads.len(),
                limit: MAX_PAYLOADS_PER_SET,
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum PayloadError {
    #[error("payload list has {count} entries, above the {limit}-entry limit")]
    TooMany { count: usize, limit: usize },
    #[error("a payload is {bytes} bytes, above the {limit}-byte limit")]
    TooLarge { bytes: usize, limit: usize },
}

// ---------------------------------------------------------------------------
// Attack strategies

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    /// One position at a time; every other position keeps its literal.
    Sniper,
    /// The same payload in every enabled position at once.
    BatteringRam,
    /// One payload per position per request, advancing in lockstep.
    Pitchfork,
    /// Every combination of every list.
    ClusterBomb,
}

impl Strategy {
    pub const ALL: [Self; 4] = [
        Self::Sniper,
        Self::BatteringRam,
        Self::Pitchfork,
        Self::ClusterBomb,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Sniper => "Sniper",
            Self::BatteringRam => "Battering ram",
            Self::Pitchfork => "Pitchfork",
            Self::ClusterBomb => "Cluster bomb",
        }
    }

    pub const fn short_label(self) -> &'static str {
        match self {
            Self::Sniper => "SNIPER",
            Self::BatteringRam => "RAM",
            Self::Pitchfork => "PITCHFORK",
            Self::ClusterBomb => "CLUSTER",
        }
    }

    pub const fn description(self) -> &'static str {
        match self {
            Self::Sniper => "one position at a time; other positions keep their original value",
            Self::BatteringRam => "the same payload in every enabled position",
            Self::Pitchfork => "one list per position, advanced in lockstep",
            Self::ClusterBomb => "every combination of every list",
        }
    }

    pub const fn next(self) -> Self {
        match self {
            Self::Sniper => Self::BatteringRam,
            Self::BatteringRam => Self::Pitchfork,
            Self::Pitchfork => Self::ClusterBomb,
            Self::ClusterBomb => Self::Sniper,
        }
    }

    pub const fn previous(self) -> Self {
        match self {
            Self::Sniper => Self::ClusterBomb,
            Self::BatteringRam => Self::Sniper,
            Self::Pitchfork => Self::BatteringRam,
            Self::ClusterBomb => Self::Pitchfork,
        }
    }
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum PlanError {
    #[error("mark at least one payload position before running an attack")]
    NoPositions,
    #[error("payload set '{0}' is empty")]
    EmptyPayloadSet(String),
    #[error("payload set '{name}' has {count} entries, above the {limit}-entry limit")]
    PayloadSetTooLarge {
        name: String,
        count: usize,
        limit: usize,
    },
    #[error("position {position} refers to payload set {index}, which does not exist")]
    MissingSet { position: PositionId, index: usize },
    #[error(
        "Pitchfork needs one payload list per position: position '{position}' has {actual} \
         payloads but {expected} were expected"
    )]
    LengthMismatch {
        position: String,
        expected: usize,
        actual: usize,
    },
    #[error("Pitchfork needs a separate payload list for each of the {0} positions")]
    NotEnoughSets(usize),
    #[error("the combination count for this strategy overflows a 64-bit integer")]
    CountOverflow,
    #[error("plan would generate {count} requests, above the {limit}-request ceiling")]
    TooManyRequests { count: u64, limit: u64 },
}

/// A fully materialized, deterministic plan. Only combination *indices* are
/// stored, so a plan of 2048 requests with 16 positions costs a few hundred
/// kilobytes rather than megabytes of duplicated request bodies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttackPlan {
    pub strategy: Strategy,
    /// Enabled positions in document order. Combination indices refer to this
    /// order.
    pub positions: Vec<PositionId>,
    /// Distinct payload lists used by this plan, in position order (Battering
    /// Ram collapses to a single entry).
    pub payloads: Vec<Vec<Vec<u8>>>,
    /// One row per generated request; `None` leaves the position at its literal.
    pub combinations: Vec<Vec<Option<u32>>>,
    pub count: u64,
}

impl AttackPlan {
    pub fn is_empty(&self) -> bool {
        self.combinations.is_empty()
    }

    /// Resolves one combination into the concrete payloads for each position.
    /// Payload lists are stored in position order, except Battering Ram, which
    /// shares a single list across every position.
    pub fn slots(&self, index: usize) -> Option<BTreeMap<PositionId, Vec<u8>>> {
        let row = self.combinations.get(index)?;
        let mut slots = BTreeMap::new();
        for (position_index, (position, payload_index)) in
            self.positions.iter().zip(row.iter()).enumerate()
        {
            if let Some(payload_index) = payload_index {
                let list = if self.payloads.len() == 1 {
                    self.payloads.first()?
                } else {
                    self.payloads.get(position_index)?
                };
                slots.insert(*position, list.get(*payload_index as usize)?.clone());
            }
        }
        Some(slots)
    }

    /// Expands the first `limit` combinations for preview. Each returned request
    /// is exactly what the engine would send for that index.
    pub fn preview(
        &self,
        template: &IntruderTemplate,
        analysis: &TemplateAnalysis,
        limit: usize,
    ) -> Vec<Result<HttpRequest, TemplateError>> {
        (0..self.combinations.len().min(limit))
            .map(|index| match self.slots(index) {
                Some(slots) => template.expand(analysis, &slots),
                None => Err(TemplateError::InvalidHead(format!(
                    "combination {index} is out of range"
                ))),
            })
            .collect()
    }

    /// Human-readable payload combination for one request.
    pub fn combination_display(&self, index: usize) -> Vec<String> {
        let Some(slots) = self.slots(index) else {
            return Vec::new();
        };
        self.positions
            .iter()
            .filter_map(|position| slots.get(position))
            .map(|payload| String::from_utf8_lossy(payload).into_owned())
            .collect()
    }
}

/// Computes the exact request count for a strategy without materializing the
/// plan. Every arithmetic step is overflow-checked and compared with the
/// ceiling, so an operator cannot start an attack that is larger than declared.
pub fn plan_count(
    strategy: Strategy,
    positions: &[PositionId],
    assignment: &BTreeMap<PositionId, usize>,
    sets: &[PayloadSet],
) -> Result<u64, PlanError> {
    if positions.is_empty() {
        return Err(PlanError::NoPositions);
    }
    let lists = resolve_lists(strategy, positions, assignment, sets)?;
    if lists.is_empty() {
        return Err(PlanError::NoPositions);
    }
    for list in &lists {
        if list.is_empty() {
            return Err(PlanError::EmptyPayloadSet("payload list".into()));
        }
    }

    let count = match strategy {
        Strategy::Sniper => {
            let mut total: u64 = 0;
            for list in &lists {
                total = total
                    .checked_add(list.len() as u64)
                    .ok_or(PlanError::CountOverflow)?;
            }
            total
        }
        Strategy::BatteringRam => lists[0].len() as u64,
        Strategy::Pitchfork => {
            let expected = lists[0].len();
            for (index, list) in lists.iter().enumerate() {
                if list.len() != expected {
                    return Err(PlanError::LengthMismatch {
                        position: positions
                            .get(index)
                            .map(|id| id.to_string())
                            .unwrap_or_else(|| index.to_string()),
                        expected,
                        actual: list.len(),
                    });
                }
            }
            expected as u64
        }
        Strategy::ClusterBomb => {
            let mut total: u64 = 1;
            for list in &lists {
                total = total
                    .checked_mul(list.len() as u64)
                    .ok_or(PlanError::CountOverflow)?;
            }
            total
        }
    };

    if count == 0 {
        return Err(PlanError::NoPositions);
    }
    if count > MAX_GENERATED_REQUESTS {
        return Err(PlanError::TooManyRequests {
            count,
            limit: MAX_GENERATED_REQUESTS,
        });
    }
    Ok(count)
}

fn resolve_lists<'a>(
    strategy: Strategy,
    positions: &[PositionId],
    assignment: &BTreeMap<PositionId, usize>,
    sets: &'a [PayloadSet],
) -> Result<Vec<&'a Vec<Vec<u8>>>, PlanError> {
    if sets.is_empty() {
        return Err(PlanError::MissingSet {
            position: positions[0],
            index: 0,
        });
    }
    let set_for = |index: usize| -> Option<&'a PayloadSet> { sets.get(index) };
    let resolve = |position: &PositionId| -> Result<&'a PayloadSet, PlanError> {
        let index = assignment.get(position).copied().unwrap_or(0);
        set_for(index).ok_or(PlanError::MissingSet {
            position: *position,
            index,
        })
    };

    let lists = match strategy {
        Strategy::BatteringRam => {
            // A single shared list drives every position, so the operator cannot
            // accidentally pair unequal lists.
            let set = resolve(&positions[0])?;
            vec![&set.payloads]
        }
        Strategy::Sniper | Strategy::ClusterBomb => {
            let mut lists = Vec::with_capacity(positions.len());
            for position in positions {
                lists.push(&resolve(position)?.payloads);
            }
            lists
        }
        Strategy::Pitchfork => {
            if sets.len() < positions.len() {
                return Err(PlanError::NotEnoughSets(positions.len()));
            }
            let mut lists = Vec::with_capacity(positions.len());
            for position in positions {
                lists.push(&resolve(position)?.payloads);
            }
            lists
        }
    };

    for set in sets {
        set.validate()?;
    }
    Ok(lists)
}

/// Builds the deterministic plan. Combination order is documented per strategy
/// and covered by tests:
///
/// * Sniper — positions in document order, payloads in list order.
/// * Battering ram — payloads in list order.
/// * Pitchfork — index order, all positions advancing together.
/// * Cluster bomb — odometer with the **last** position varying fastest.
pub fn build_plan(
    strategy: Strategy,
    positions: &[PositionId],
    assignment: &BTreeMap<PositionId, usize>,
    sets: &[PayloadSet],
) -> Result<AttackPlan, PlanError> {
    let count = plan_count(strategy, positions, assignment, sets)?;
    let lists = resolve_lists(strategy, positions, assignment, sets)?;
    let payloads: Vec<Vec<Vec<u8>>> = lists.iter().map(|list| (*list).clone()).collect();

    let mut combinations: Vec<Vec<Option<u32>>> = Vec::with_capacity(count as usize);
    match strategy {
        Strategy::Sniper => {
            for (position_index, list) in lists.iter().enumerate() {
                for payload_index in 0..list.len() {
                    let mut row = vec![None; positions.len()];
                    row[position_index] = Some(payload_index as u32);
                    combinations.push(row);
                }
            }
        }
        Strategy::BatteringRam => {
            for payload_index in 0..payloads[0].len() {
                combinations.push(vec![Some(payload_index as u32); positions.len()]);
            }
        }
        Strategy::Pitchfork => {
            for payload_index in 0..payloads[0].len() {
                combinations.push(vec![Some(payload_index as u32); positions.len()]);
            }
        }
        Strategy::ClusterBomb => {
            let mut indices = vec![0u32; positions.len()];
            for _ in 0..count {
                combinations.push(indices.iter().map(|index| Some(*index)).collect());
                // Advance the odometer from the end so the last position varies
                // fastest, which keeps adjacent requests easy to compare.
                for position in (0..indices.len()).rev() {
                    indices[position] += 1;
                    if (indices[position] as usize) < payloads[position].len() {
                        break;
                    }
                    indices[position] = 0;
                }
            }
        }
    }

    Ok(AttackPlan {
        strategy,
        positions: positions.to_vec(),
        payloads,
        combinations,
        count,
    })
}

// ---------------------------------------------------------------------------
// Execution vocabulary

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntruderPhase {
    /// No plan is running.
    Idle,
    Running,
    Paused,
    /// Cancellation requested; in-flight requests are draining.
    Cancelling,
    Finished,
}

impl IntruderPhase {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Idle => "IDLE",
            Self::Running => "RUNNING",
            Self::Paused => "PAUSED",
            Self::Cancelling => "CANCELLING",
            Self::Finished => "FINISHED",
        }
    }

    pub const fn is_active(self) -> bool {
        matches!(self, Self::Running | Self::Paused | Self::Cancelling)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntruderOutcome {
    /// A response was received. The status code is evidence, not a finding.
    Response,
    Blocked,
    TimedOut,
    Failed,
    Cancelled,
    /// Queued but never sent because the run was paused long enough to hit the
    /// duration ceiling or was cancelled first.
    NotSent,
}

impl IntruderOutcome {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Response => "RESPONSE",
            Self::Blocked => "BLOCKED",
            Self::TimedOut => "TIMEOUT",
            Self::Failed => "FAILED",
            Self::Cancelled => "CANCELLED",
            Self::NotSent => "NOT SENT",
        }
    }

    pub fn from_phase(phase: RepeaterExecutionPhase, has_response: bool) -> Self {
        match phase {
            RepeaterExecutionPhase::Completed => Self::Response,
            RepeaterExecutionPhase::Blocked => Self::Blocked,
            RepeaterExecutionPhase::TimedOut => Self::TimedOut,
            RepeaterExecutionPhase::Cancelled => Self::Cancelled,
            _ if has_response => Self::Response,
            _ => Self::Failed,
        }
    }
}

/// One generated request and the real response it produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntruderResult {
    /// Persisted transaction id, from [`INTRUDER_ID_BASE`].
    pub id: TrafficId,
    pub run: u64,
    /// Zero-based combination index; deterministic for a plan.
    pub index: u64,
    /// Payloads applied to the enabled positions, in plan position order.
    pub payloads: Vec<Vec<u8>>,
    pub positions: Vec<PositionId>,
    pub result: RepeaterResult,
    pub phase: RepeaterExecutionPhase,
}

impl IntruderResult {
    pub fn outcome(&self) -> IntruderOutcome {
        IntruderOutcome::from_phase(self.phase.clone(), self.result.response.is_some())
    }

    pub fn status(&self) -> Option<u16> {
        self.result.status()
    }

    pub fn size(&self) -> usize {
        self.result.response_bytes
    }

    pub fn duration_ms(&self) -> u64 {
        self.result.timings.total_ms
    }

    pub fn content_type(&self) -> Option<&str> {
        self.result
            .response
            .as_ref()
            .and_then(|response| response.content_type())
    }

    /// Payload combination as display text. Callers must sanitize before
    /// rendering: payloads and responses are attacker-influenced data.
    pub fn payload_display(&self) -> Vec<String> {
        self.payloads
            .iter()
            .map(|payload| String::from_utf8_lossy(payload).into_owned())
            .collect()
    }

    /// Difference from a chosen baseline. Uses measured bytes and timings only.
    pub fn comparison(&self, baseline: &IntruderResult) -> ExecutionComparison {
        crate::repeater::compare_executions(&baseline.result, &self.result)
    }

    pub fn error(&self) -> Option<&str> {
        self.result.error.as_deref()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultSort {
    Index,
    Status,
    Size,
    Duration,
}

impl ResultSort {
    pub const ALL: [Self; 4] = [Self::Index, Self::Status, Self::Size, Self::Duration];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Index => "request",
            Self::Status => "status",
            Self::Size => "size",
            Self::Duration => "duration",
        }
    }

    pub const fn next(self) -> Self {
        match self {
            Self::Index => Self::Status,
            Self::Status => Self::Size,
            Self::Size => Self::Duration,
            Self::Duration => Self::Index,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ResultFilter {
    pub query: String,
    pub status_class: Option<StatusClass>,
    pub outcome: Option<IntruderOutcome>,
}

impl ResultFilter {
    pub fn is_empty(&self) -> bool {
        self.query.trim().is_empty() && self.status_class.is_none() && self.outcome.is_none()
    }

    pub fn clear(&mut self) {
        self.query.clear();
        self.status_class = None;
        self.outcome = None;
    }

    pub fn matches(&self, result: &IntruderResult) -> bool {
        if let Some(class) = self.status_class {
            match result.status() {
                Some(status) if StatusClass::from_code(status) == class => {}
                _ => return false,
            }
        }
        if let Some(outcome) = self.outcome
            && result.outcome() != outcome
        {
            return false;
        }
        let query = self.query.trim().to_ascii_lowercase();
        if query.is_empty() {
            return true;
        }
        if result
            .result
            .request
            .url()
            .to_ascii_lowercase()
            .contains(&query)
        {
            return true;
        }
        if result
            .payload_display()
            .iter()
            .any(|payload| payload.to_ascii_lowercase().contains(&query))
        {
            return true;
        }
        if result
            .error()
            .is_some_and(|error| error.to_ascii_lowercase().contains(&query))
        {
            return true;
        }
        false
    }
}

/// Deterministic ordering for the results table. Ties fall back to the request
/// index so rows never jump between frames.
pub fn sorted_indices(
    results: &[IntruderResult],
    filter: &ResultFilter,
    sort: ResultSort,
    descending: bool,
) -> Vec<usize> {
    let mut indices: Vec<usize> = results
        .iter()
        .enumerate()
        .filter(|(_, result)| filter.matches(result))
        .map(|(index, _)| index)
        .collect();
    indices.sort_by(|left, right| {
        let a = &results[*left];
        let b = &results[*right];
        let ordering = match sort {
            ResultSort::Index => a.index.cmp(&b.index),
            ResultSort::Status => a.status().cmp(&b.status()),
            ResultSort::Size => a.size().cmp(&b.size()),
            ResultSort::Duration => a.duration_ms().cmp(&b.duration_ms()),
        }
        .then_with(|| a.index.cmp(&b.index));
        if descending {
            ordering.reverse()
        } else {
            ordering
        }
    });
    indices
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntruderStopReason {
    /// Every planned request reached a terminal outcome.
    Complete,
    Cancelled,
    /// The configured maximum execution duration was reached.
    DurationLimit,
    /// The engine stopped because the command channel closed.
    Shutdown,
}

impl IntruderStopReason {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Complete => "COMPLETE",
            Self::Cancelled => "CANCELLED",
            Self::DurationLimit => "DURATION LIMIT",
            Self::Shutdown => "SHUTDOWN",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IntruderSummary {
    pub planned: u64,
    pub sent: u64,
    pub responded: u64,
    pub blocked: u64,
    pub timed_out: u64,
    pub failed: u64,
    pub cancelled: u64,
    pub not_sent: u64,
    pub duration_ms: u64,
    pub reason: Option<IntruderStopReason>,
}

impl IntruderSummary {
    pub fn record(&mut self, outcome: IntruderOutcome) {
        self.sent += 1;
        match outcome {
            IntruderOutcome::Response => self.responded += 1,
            IntruderOutcome::Blocked => self.blocked += 1,
            IntruderOutcome::TimedOut => self.timed_out += 1,
            IntruderOutcome::Failed => self.failed += 1,
            IntruderOutcome::Cancelled => self.cancelled += 1,
            IntruderOutcome::NotSent => {
                self.sent -= 1;
                self.not_sent += 1;
            }
        }
    }

    pub fn terminal(&self) -> u64 {
        self.responded
            + self.blocked
            + self.timed_out
            + self.failed
            + self.cancelled
            + self.not_sent
    }
}

/// A run request handed to the engine. It carries the complete, already-computed
/// plan so the engine never regenerates combinations differently from the preview
/// the operator confirmed.
#[derive(Debug, Clone)]
pub struct IntruderLaunch {
    pub template: IntruderTemplate,
    pub analysis: TemplateAnalysis,
    pub plan: AttackPlan,
    pub concurrency: usize,
    pub rate_per_second: u32,
    pub follow_redirects: bool,
    pub max_duration_secs: u64,
    /// Captured History entry the template came from, if any.
    pub origin: Option<TrafficId>,
}

impl IntruderLaunch {
    pub fn validate(&self) -> Result<(), String> {
        if self.plan.combinations.len() as u64 != self.plan.count {
            return Err("plan count does not match its combinations".into());
        }
        if self.plan.count == 0 || self.plan.count > MAX_GENERATED_REQUESTS {
            return Err(format!(
                "plan must contain between 1 and {MAX_GENERATED_REQUESTS} requests"
            ));
        }
        if !(1..=MAX_CONCURRENCY).contains(&self.concurrency) {
            return Err(format!("concurrency must be 1..={MAX_CONCURRENCY}"));
        }
        if !(1..=MAX_RATE_PER_SECOND).contains(&self.rate_per_second) {
            return Err(format!(
                "rate must be 1..={MAX_RATE_PER_SECOND} requests/second"
            ));
        }
        if self.max_duration_secs == 0 || self.max_duration_secs > MAX_DURATION_SECS {
            return Err(format!(
                "duration limit must be 1..={MAX_DURATION_SECS} seconds"
            ));
        }
        for position in &self.plan.positions {
            if !self.analysis.contains(*position) {
                return Err(format!("plan refers to unknown position {position}"));
            }
        }
        Ok(())
    }
}

/// Commands accepted by the Intruder service. `run` identifies one attack so
/// late events can never be attributed to a newer run.
#[derive(Debug, Clone)]
pub enum IntruderCommand {
    /// Ask the engine to read a bounded local wordlist. Reading happens off the
    /// UI thread and never executes the content.
    LoadWordlist {
        request: u64,
        path: std::path::PathBuf,
    },
    Start {
        run: u64,
        launch: Box<IntruderLaunch>,
    },
    Pause {
        run: u64,
    },
    Resume {
        run: u64,
    },
    Cancel {
        run: u64,
    },
    Shutdown,
}

pub type IntruderCommandSender = tokio::sync::mpsc::Sender<IntruderCommand>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WordlistOutcome {
    pub request: u64,
    /// Display label only: the full path is shown in the UI, never sent.
    pub path: String,
    pub payloads: Vec<Vec<u8>>,
    /// Lines skipped because they were blank or above the line-length limit.
    pub skipped: usize,
    /// Lines skipped because they were not valid UTF-8. The raw bytes are never
    /// silently reinterpreted.
    pub invalid_utf8: usize,
    /// True when the file exceeded the byte or payload-count limit.
    pub truncated: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub enum IntruderEvent {
    Started {
        run: u64,
        total: u64,
    },
    /// Pause, resume, and cancellation transitions. Progress itself is derived
    /// from [`IntruderEvent::Completed`] events, not from this hint.
    Phase {
        run: u64,
        phase: IntruderPhase,
    },
    /// One generated request reached a terminal outcome.
    Completed {
        run: u64,
        result: Box<IntruderResult>,
        entry: Box<crate::models::traffic::TrafficEntry>,
    },
    Finished {
        run: u64,
        summary: IntruderSummary,
    },
    /// A run was refused before any request was generated (for example a
    /// concurrent run, or an invalid launch). No traffic was produced.
    Failed {
        run: u64,
        error: String,
    },
    Wordlist(WordlistOutcome),
}

/// Maps an Intruder result to the persisted transaction model. Provenance is
/// always `Intruder`, never live proxy traffic, and the payload combination is
/// attached as bounded metadata rather than being inferred from the request.
pub fn intruder_entry(
    id: TrafficId,
    result: &IntruderResult,
    template_request: &HttpRequest,
    origin: Option<TrafficId>,
) -> crate::models::traffic::TrafficEntry {
    use crate::models::traffic::{TrafficEntry, TrafficSource};

    let mut entry = TrafficEntry::new(id, result.result.request.clone());
    entry.source = TrafficSource::Intruder;
    entry.intruder_origin = origin;
    entry.original_request = Some(template_request.clone());
    entry.final_request = Some(result.result.request.clone());
    entry.timings.completed_at = Some(chrono::Utc::now());
    entry.timings.duration_ms = Some(result.result.timings.total_ms);
    entry.response = result.result.response.clone();
    entry.intruder_payloads = Some(result.payloads.clone());
    entry.note = if result.result.warnings.is_empty() {
        None
    } else {
        Some(result.result.warnings.join("; "))
    };
    if let Some(error) = &result.result.error {
        entry.error = Some(error.clone());
        entry.state = match result.phase {
            RepeaterExecutionPhase::TimedOut => TrafficState::TimedOut,
            RepeaterExecutionPhase::Cancelled => TrafficState::Cancelled,
            _ => TrafficState::Failed,
        };
    } else {
        entry.state = TrafficState::Completed;
    }
    entry
}

/// Empty index used by callers that need a stable default.
pub fn no_positions() -> BTreeSet<PositionId> {
    BTreeSet::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::message::Scheme;
    use crate::repeater::RepeaterTimings;

    fn request() -> HttpRequest {
        let mut request = HttpRequest::new(
            "POST",
            Scheme::Http,
            "lab.rawframe.test",
            8080,
            "/api/users",
        );
        request.headers.append("X-Role", "user");
        request.body = br#"{"name":"alice"}"#.to_vec();
        request
    }

    fn template() -> IntruderTemplate {
        IntruderTemplate::from_request(&request())
    }

    fn set(name: &str, values: &[&str]) -> PayloadSet {
        PayloadSet {
            id: 0,
            name: name.into(),
            source: PayloadSource::Manual,
            payloads: values
                .iter()
                .map(|value| value.as_bytes().to_vec())
                .collect(),
        }
    }

    fn assignment(pairs: &[(u16, usize)]) -> BTreeMap<PositionId, usize> {
        pairs
            .iter()
            .map(|(id, index)| (PositionId(*id), *index))
            .collect()
    }

    #[test]
    fn marker_free_templates_have_no_positions() {
        let analysis = template().analyze().unwrap();
        assert!(analysis.positions.is_empty());
        assert!(analysis.target.len() == 1);
    }

    #[test]
    fn positions_are_found_in_target_headers_and_body() {
        let mut template = template();
        template.target = "/api/§users§/§42§?role=§user§".into();
        template.headers[1].1 = "§token§".into();
        template.body = "{\"name\":\"§alice§\"}".as_bytes().to_vec();

        let analysis = template.analyze().unwrap();
        let ids: Vec<u16> = analysis.positions.iter().map(|p| p.id.0).collect();
        assert_eq!(ids, vec![1, 2, 3, 4, 5]);
        assert_eq!(analysis.positions[0].area, PositionArea::Path);
        assert_eq!(analysis.positions[1].area, PositionArea::Path);
        assert_eq!(analysis.positions[2].area, PositionArea::Query);
        assert_eq!(
            analysis.positions[3].area,
            PositionArea::Header {
                index: 1,
                name: "X-Role".into()
            }
        );
        assert_eq!(analysis.positions[4].area, PositionArea::Body);
        assert_eq!(analysis.positions[3].literal, b"token");
        assert_eq!(analysis.positions[3].label, "X-Role");
        assert_eq!(analysis.positions[4].label, "body");
    }

    #[test]
    fn duplicate_areas_get_distinct_labels() {
        let mut template = template();
        template.target = "/a?x=§1§&y=§2§".into();
        let analysis = template.analyze().unwrap();
        // Both are query positions, so the second is disambiguated.
        assert_eq!(analysis.positions[0].label, "query");
        assert_eq!(analysis.positions[1].label, "query #2");
    }

    #[test]
    fn unmatched_markers_are_rejected() {
        let mut template = template();
        template.target = "/api/§users".into();
        assert_eq!(
            template.analyze(),
            Err(TemplateError::UnmatchedMarker),
            "an unclosed marker must never be silently treated as literal text"
        );
    }

    #[test]
    fn markers_in_header_names_are_rejected() {
        let mut template = template();
        template.headers.push(("§X§-Role".into(), "admin".into()));
        assert!(matches!(
            template.analyze(),
            Err(TemplateError::MarkerInHeaderName(_))
        ));
    }

    #[test]
    fn position_limit_is_enforced() {
        let mut template = template();
        template.target = (0..MAX_POSITIONS + 1)
            .map(|index| format!("/§{index}§"))
            .collect();
        assert_eq!(template.analyze(), Err(TemplateError::TooManyPositions));
    }

    #[test]
    fn expansion_uses_literals_for_inactive_positions() {
        let mut template = template();
        template.target = "/api/§users§/profile?role=§user§".into();
        let analysis = template.analyze().unwrap();
        let mut slots = BTreeMap::new();
        slots.insert(PositionId(1), b"admins".to_vec());

        let expanded = template.expand(&analysis, &slots).unwrap();
        assert_eq!(expanded.target, "/api/admins/profile?role=user");
        assert_eq!(expanded.method, "POST");
        assert_eq!(expanded.host, "lab.rawframe.test");
        assert_eq!(expanded.port, 8080);
    }

    #[test]
    fn ordered_duplicate_headers_survive_expansion() {
        let mut template = template();
        template.headers = vec![
            ("Host".into(), "lab.rawframe.test:8080".into()),
            ("X-Tag".into(), "one".into()),
            ("X-Tag".into(), "§two§".into()),
        ];
        let analysis = template.analyze().unwrap();
        let mut slots = BTreeMap::new();
        slots.insert(PositionId(1), b"replaced".to_vec());
        let expanded = template.expand(&analysis, &slots).unwrap();
        let values: Vec<&str> = expanded.headers.get_all("x-tag").collect();
        assert_eq!(values, vec!["one", "replaced"]);
    }

    #[test]
    fn binary_bodies_are_marked_and_expanded_without_text_decoding() {
        let mut template = template();
        template.body = vec![0x00, 0xff, 0xfe, b'o', b'k'];
        template.mark_whole_body();
        let analysis = template.analyze().unwrap();
        assert_eq!(analysis.positions.len(), 1);
        assert_eq!(
            analysis.positions[0].literal,
            vec![0x00, 0xff, 0xfe, b'o', b'k']
        );

        let mut slots = BTreeMap::new();
        slots.insert(PositionId(1), vec![0xde, 0xad, 0xbe, 0xef]);
        let expanded = template.expand(&analysis, &slots).unwrap();
        assert_eq!(expanded.body, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn non_utf8_payloads_cannot_enter_a_target_or_header() {
        let mut template = template();
        template.target = "/§x§".into();
        template.headers[1].1 = "§y§".into();
        let analysis = template.analyze().unwrap();
        let mut slots = BTreeMap::new();
        slots.insert(PositionId(1), vec![0xff, 0xfe]);
        assert_eq!(
            template.expand(&analysis, &slots),
            Err(TemplateError::NonUtf8Payload(PositionId(1)))
        );
    }

    #[test]
    fn head_text_round_trips_headers_and_markers() {
        let mut template = template();
        template.target = "/a/§b§".into();
        let text = template.head_text();
        let mut parsed = IntruderTemplate::from_request(&request());
        parsed.set_head_text(&text).unwrap();
        assert_eq!(parsed.target, "/a/§b§");
        assert_eq!(parsed.headers, template.headers);
        assert_eq!(parsed.method, "POST");
    }

    #[test]
    fn malformed_head_lines_are_reported() {
        let mut template = template();
        assert!(matches!(
            template.set_head_text("GET / HTTP/1.1\nBrokenHeader\n"),
            Err(TemplateError::InvalidHead(_))
        ));
        assert!(matches!(
            template.set_head_text("GET / HTTP/9.9\n"),
            Err(TemplateError::InvalidHead(_))
        ));
        assert!(matches!(
            template.set_head_text(""),
            Err(TemplateError::InvalidHead(_))
        ));
    }

    #[test]
    fn manual_payloads_preserve_interior_blanks() {
        let set = PayloadSet::manual(0, "manual", "a\n\nb\n").unwrap();
        assert_eq!(set.payloads.len(), 3);
        assert_eq!(set.payloads[1], Vec::<u8>::new());
        assert_eq!(set.name, "manual");

        let empty = PayloadSet::manual(0, "empty", "").unwrap();
        assert!(empty.is_empty());
    }

    #[test]
    fn payload_limits_are_enforced() {
        let long = "x".repeat(MAX_PAYLOAD_BYTES + 1);
        assert!(matches!(
            PayloadSet::manual(0, "long", &long),
            Err(PayloadError::TooLarge { .. })
        ));
    }

    #[test]
    fn builtin_set_is_small_and_harmless() {
        let set = PayloadSet::builtin(0);
        assert_eq!(set.source, PayloadSource::BuiltIn);
        assert!(set.len() <= 16);
        assert!(set.payloads.iter().all(|payload| payload.len() <= 8));
    }

    fn sniper_positions() -> (IntruderTemplate, TemplateAnalysis) {
        let mut template = template();
        template.target = "/api/§users§?role=§user§".into();
        let analysis = template.analyze().unwrap();
        (template, analysis)
    }

    #[test]
    fn sniper_counts_and_order_are_deterministic() {
        let (_, analysis) = sniper_positions();
        let positions = analysis.position_ids();
        let sets = [set("one", &["a", "b"]), set("two", &["1", "2", "3"])];
        let assign = assignment(&[(1, 0), (2, 1)]);

        assert_eq!(
            plan_count(Strategy::Sniper, &positions, &assign, &sets).unwrap(),
            5
        );
        let plan = build_plan(Strategy::Sniper, &positions, &assign, &sets).unwrap();
        assert_eq!(plan.count, 5);
        assert_eq!(plan.combination_display(0), vec!["a"]);
        assert_eq!(plan.combination_display(1), vec!["b"]);
        assert_eq!(plan.combination_display(2), vec!["1"]);
        assert_eq!(plan.combination_display(4), vec!["3"]);
    }

    #[test]
    fn sniper_leaves_other_positions_at_their_literal() {
        let (template, analysis) = sniper_positions();
        let positions = analysis.position_ids();
        let sets = [set("one", &["a"]), set("two", &["x"])];
        let assign = assignment(&[(1, 0), (2, 1)]);
        let plan = build_plan(Strategy::Sniper, &positions, &assign, &sets).unwrap();
        let expanded = plan.preview(&template, &analysis, 2);

        assert_eq!(
            expanded[0].as_ref().unwrap().target,
            "/api/a?role=user",
            "the second position keeps its original literal"
        );
        assert_eq!(expanded[1].as_ref().unwrap().target, "/api/users?role=x");
    }

    #[test]
    fn battering_ram_applies_one_payload_everywhere() {
        let (template, analysis) = sniper_positions();
        let positions = analysis.position_ids();
        let sets = [set("shared", &["a", "b"])];
        let plan = build_plan(Strategy::BatteringRam, &positions, &assignment(&[]), &sets).unwrap();
        assert_eq!(plan.count, 2);
        assert_eq!(plan.combination_display(1), vec!["b", "b"]);
        let preview = plan.preview(&template, &analysis, 2);
        assert_eq!(preview[1].as_ref().unwrap().target, "/api/b?role=b");
    }

    #[test]
    fn pitchfork_advances_lists_in_lockstep() {
        let (template, analysis) = sniper_positions();
        let positions = analysis.position_ids();
        let sets = [set("first", &["a", "b"]), set("second", &["1", "2"])];
        let assign = assignment(&[(1, 0), (2, 1)]);
        let plan = build_plan(Strategy::Pitchfork, &positions, &assign, &sets).unwrap();
        assert_eq!(plan.count, 2);
        assert_eq!(plan.combination_display(0), vec!["a", "1"]);
        assert_eq!(
            plan.preview(&template, &analysis, 2)[1]
                .as_ref()
                .unwrap()
                .target,
            "/api/b?role=2"
        );
    }

    #[test]
    fn pitchfork_rejects_unequal_lists() {
        let (_, analysis) = sniper_positions();
        let positions = analysis.position_ids();
        let sets = [set("first", &["a", "b"]), set("second", &["1"])];
        let assign = assignment(&[(1, 0), (2, 1)]);
        assert!(matches!(
            plan_count(Strategy::Pitchfork, &positions, &assign, &sets),
            Err(PlanError::LengthMismatch { .. })
        ));
    }

    #[test]
    fn cluster_bomb_is_the_cartesian_product_with_last_varying_fastest() {
        let (_, analysis) = sniper_positions();
        let positions = analysis.position_ids();
        let sets = [set("first", &["a", "b"]), set("second", &["1", "2", "3"])];
        let assign = assignment(&[(1, 0), (2, 1)]);
        assert_eq!(
            plan_count(Strategy::ClusterBomb, &positions, &assign, &sets).unwrap(),
            6
        );
        let plan = build_plan(Strategy::ClusterBomb, &positions, &assign, &sets).unwrap();
        let order: Vec<Vec<String>> = (0..6).map(|i| plan.combination_display(i)).collect();
        assert_eq!(
            order,
            vec![
                vec!["a", "1"],
                vec!["a", "2"],
                vec!["a", "3"],
                vec!["b", "1"],
                vec!["b", "2"],
                vec!["b", "3"],
            ]
        );
    }

    #[test]
    fn cluster_bomb_ceiling_is_rejected_before_building() {
        let (_, analysis) = sniper_positions();
        let positions = analysis.position_ids();
        let sets = [
            set("first", &["a", "b", "c", "d"]),
            set("second", &["a", "b", "c", "d"]),
        ];
        let assign = assignment(&[(1, 0), (2, 1)]);
        assert_eq!(
            plan_count(Strategy::ClusterBomb, &positions, &assign, &sets).unwrap(),
            16
        );

        // 16 * 512 exceeds the 2048 ceiling; each list stays within its own limit.
        let big: Vec<String> = (0..MAX_PAYLOADS_PER_SET).map(|i| i.to_string()).collect();
        let big_refs: Vec<&str> = big.iter().map(String::as_str).collect();
        let sets = [set("first", &big_refs), set("second", &big_refs)];
        assert!(matches!(
            plan_count(Strategy::ClusterBomb, &positions, &assign, &sets),
            Err(PlanError::TooManyRequests { .. })
        ));
    }

    #[test]
    fn count_overflow_is_detected() {
        let positions: Vec<PositionId> = (1..=16).map(PositionId).collect();
        let huge: Vec<Vec<u8>> = vec![b"x".to_vec(); MAX_PAYLOADS_PER_SET];
        let sets: Vec<PayloadSet> = (0..16)
            .map(|index| PayloadSet {
                id: index as u32,
                name: format!("s{index}"),
                source: PayloadSource::Manual,
                payloads: huge.clone(),
            })
            .collect();
        // 512^16 does not fit in a u64; the checked multiply must report it
        // rather than wrapping to a small, deceptively safe count.
        assert_eq!(
            plan_count(Strategy::ClusterBomb, &positions, &assignment(&[]), &sets),
            Err(PlanError::CountOverflow)
        );
    }

    #[test]
    fn ceiling_is_enforced_below_the_overflow_point() {
        let positions = vec![PositionId(1), PositionId(2), PositionId(3), PositionId(4)];
        let huge: Vec<Vec<u8>> = vec![b"x".to_vec(); 512];
        let sets: Vec<PayloadSet> = (0..4)
            .map(|index| PayloadSet {
                id: index as u32,
                name: format!("s{index}"),
                source: PayloadSource::Manual,
                payloads: huge.clone(),
            })
            .collect();
        // 512^4 = 68_719_476_736: representable, so the ceiling catches it.
        assert!(matches!(
            plan_count(Strategy::ClusterBomb, &positions, &assignment(&[]), &sets),
            Err(PlanError::TooManyRequests { .. })
        ));
    }

    #[test]
    fn empty_and_missing_inputs_are_explicit() {
        let positions = vec![PositionId(1)];
        assert_eq!(
            plan_count(Strategy::Sniper, &[], &assignment(&[]), &[set("a", &["1"])]),
            Err(PlanError::NoPositions)
        );
        assert!(matches!(
            plan_count(
                Strategy::Sniper,
                &positions,
                &assignment(&[]),
                &[set("a", &[])]
            ),
            Err(PlanError::EmptyPayloadSet(_))
        ));
        assert!(matches!(
            plan_count(
                Strategy::Sniper,
                &positions,
                &assignment(&[(1, 4)]),
                &[set("a", &["1"])]
            ),
            Err(PlanError::MissingSet { .. })
        ));
    }

    #[test]
    fn launch_validation_rejects_unsafe_settings() {
        let (template, analysis) = sniper_positions();
        let positions = analysis.position_ids();
        let sets = [set("one", &["a"])];
        let assign = assignment(&[(1, 0)]);
        let plan = build_plan(Strategy::Sniper, &positions, &assign, &sets).unwrap();
        let launch = IntruderLaunch {
            template,
            analysis,
            plan,
            concurrency: DEFAULT_CONCURRENCY,
            rate_per_second: DEFAULT_RATE_PER_SECOND,
            follow_redirects: false,
            max_duration_secs: DEFAULT_MAX_DURATION_SECS,
            origin: None,
        };
        assert!(launch.validate().is_ok());

        let mut too_fast = launch.clone();
        too_fast.rate_per_second = MAX_RATE_PER_SECOND + 1;
        assert!(too_fast.validate().is_err());

        let mut too_many = launch.clone();
        too_many.concurrency = MAX_CONCURRENCY + 1;
        assert!(too_many.validate().is_err());

        let mut forever = launch;
        forever.max_duration_secs = MAX_DURATION_SECS + 1;
        assert!(forever.validate().is_err());
    }

    fn result(index: u64, status: u16, size: usize, duration: u64) -> IntruderResult {
        let mut response = crate::models::message::HttpResponse::new(status);
        response.body = vec![b'x'; size];
        IntruderResult {
            id: TrafficId(INTRUDER_ID_BASE + index),
            run: 1,
            index,
            payloads: vec![format!("p{index}").into_bytes()],
            positions: vec![PositionId(1)],
            phase: RepeaterExecutionPhase::Completed,
            result: RepeaterResult {
                request: request(),
                response: Some(response),
                timings: RepeaterTimings {
                    total_ms: duration,
                    ..RepeaterTimings::default()
                },
                redirects: Vec::new(),
                truncated: false,
                response_bytes: size,
                error: None,
                warnings: Vec::new(),
                sent_at: chrono::Utc::now(),
            },
        }
    }

    #[test]
    fn result_filtering_covers_query_status_and_outcome() {
        let mut results = vec![
            result(0, 200, 10, 5),
            result(1, 403, 20, 9),
            result(2, 500, 30, 1),
        ];
        results[2].phase = RepeaterExecutionPhase::TimedOut;

        let mut filter = ResultFilter::default();
        assert_eq!(
            sorted_indices(&results, &filter, ResultSort::Index, false).len(),
            3
        );

        filter.query = "p1".into();
        assert_eq!(
            sorted_indices(&results, &filter, ResultSort::Index, false),
            vec![1],
            "payload text is searchable"
        );

        filter.clear();
        filter.status_class = Some(StatusClass::ClientError);
        assert_eq!(
            sorted_indices(&results, &filter, ResultSort::Index, false),
            vec![1]
        );

        filter.clear();
        filter.outcome = Some(IntruderOutcome::TimedOut);
        assert_eq!(
            sorted_indices(&results, &filter, ResultSort::Index, false),
            vec![2]
        );
    }

    #[test]
    fn result_sorting_is_stable_and_deterministic() {
        let results = vec![
            result(0, 500, 10, 50),
            result(1, 200, 30, 10),
            result(2, 404, 20, 30),
        ];
        assert_eq!(
            sorted_indices(&results, &ResultFilter::default(), ResultSort::Size, false),
            vec![0, 2, 1]
        );
        assert_eq!(
            sorted_indices(
                &results,
                &ResultFilter::default(),
                ResultSort::Status,
                false
            ),
            vec![1, 2, 0]
        );
        assert_eq!(
            sorted_indices(
                &results,
                &ResultFilter::default(),
                ResultSort::Duration,
                true
            ),
            vec![0, 2, 1]
        );
    }

    #[test]
    fn outcome_classification_never_fabricates_a_response() {
        assert_eq!(
            IntruderOutcome::from_phase(RepeaterExecutionPhase::Blocked, false),
            IntruderOutcome::Blocked
        );
        assert_eq!(
            IntruderOutcome::from_phase(RepeaterExecutionPhase::TimedOut, false),
            IntruderOutcome::TimedOut
        );
        assert_eq!(
            IntruderOutcome::from_phase(RepeaterExecutionPhase::Completed, true),
            IntruderOutcome::Response
        );
        assert_eq!(
            IntruderOutcome::from_phase(RepeaterExecutionPhase::Failed, false),
            IntruderOutcome::Failed
        );
    }

    #[test]
    fn summary_counts_only_real_outcomes() {
        let mut summary = IntruderSummary {
            planned: 4,
            ..IntruderSummary::default()
        };
        summary.record(IntruderOutcome::Response);
        summary.record(IntruderOutcome::Blocked);
        summary.record(IntruderOutcome::NotSent);
        assert_eq!(summary.sent, 2);
        assert_eq!(summary.not_sent, 1);
        assert_eq!(summary.terminal(), 3);
    }

    #[test]
    fn intruder_entries_carry_provenance_and_payloads() {
        let result = result(1, 200, 4, 12);
        let entry = intruder_entry(
            TrafficId(INTRUDER_ID_BASE + 1),
            &result,
            &request(),
            Some(TrafficId(9)),
        );
        assert_eq!(
            entry.source,
            crate::models::traffic::TrafficSource::Intruder
        );
        assert!(!entry.is_live_capture());
        assert_eq!(entry.intruder_origin, Some(TrafficId(9)));
        assert_eq!(entry.intruder_payloads, Some(vec![b"p1".to_vec()]));
    }

    #[test]
    fn clearing_markers_restores_the_original_values() {
        let mut template = template();
        template.target = "/api/§users§?role=§user§".into();
        template.headers[1].1 = "§admin§".into();
        template.clear_markers();
        assert_eq!(template.target, "/api/users?role=user");
        assert_eq!(template.headers[1].1, "admin");
        assert!(!template.has_markers());
    }
}
