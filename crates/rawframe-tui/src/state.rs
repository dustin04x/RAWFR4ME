//! UI-local state. This module owns view state only; it performs no I/O.

use std::time::Instant;

use rawframe_core::models::message::{HttpRequest, Scheme};
use rawframe_core::models::session::{RepeaterId, RepeaterRequest};
use rawframe_core::models::traffic::{TrafficId, TrafficSource};
use rawframe_core::repeater::{
    ExecutionComparison, RepeaterExecutionPhase, RepeaterResult, compare_executions,
};
use rawframe_core::{Notice, fixtures};

use crate::interaction::{InspectorView, MessageSide, SettingId};
use crate::text::TextBuffer;

#[derive(Debug, Clone, Default)]
pub struct SearchState {
    pub active: bool,
}

#[derive(Debug, Clone)]
pub struct InspectorState {
    pub side: MessageSide,
    pub view: InspectorView,
    pub scroll: u16,
}

impl Default for InspectorState {
    fn default() -> Self {
        Self {
            side: MessageSide::Request,
            view: InspectorView::Raw,
            scroll: 0,
        }
    }
}

impl InspectorState {
    pub fn reset(&mut self) {
        self.scroll = 0;
    }

    pub fn scroll_by(&mut self, delta: i32) {
        let next = if delta.is_negative() {
            self.scroll.saturating_sub(delta.unsigned_abs() as u16)
        } else {
            self.scroll.saturating_add(delta as u16)
        };
        self.scroll = next;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepeaterOrigin {
    Blank,
    Simulated(TrafficId),
    Captured(TrafficId),
}

impl RepeaterOrigin {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Blank => "NEW",
            Self::Simulated(_) => "SIM",
            Self::Captured(_) => "LIVE",
        }
    }

    pub const fn source(self) -> TrafficSource {
        match self {
            Self::Blank => TrafficSource::Authored,
            Self::Simulated(_) => TrafficSource::Simulated,
            Self::Captured(_) => TrafficSource::Intercepted,
        }
    }

    pub const fn is_simulated(self) -> bool {
        matches!(self, Self::Simulated(_))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepeaterView {
    Raw,
    Headers,
    Body,
    Json,
    Hex,
    Compare,
}

impl RepeaterView {
    pub const ALL: [Self; 6] = [
        Self::Raw,
        Self::Headers,
        Self::Body,
        Self::Json,
        Self::Hex,
        Self::Compare,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Raw => "Raw",
            Self::Headers => "Headers",
            Self::Body => "Body",
            Self::Json => "JSON",
            Self::Hex => "Hex",
            Self::Compare => "Compare",
        }
    }

    pub const fn next(self) -> Self {
        match self {
            Self::Raw => Self::Headers,
            Self::Headers => Self::Body,
            Self::Body => Self::Json,
            Self::Json => Self::Hex,
            Self::Hex => Self::Compare,
            Self::Compare => Self::Raw,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RepeaterTab {
    pub document: RepeaterRequest,
    pub editor: TextBuffer,
    pub origin: RepeaterOrigin,
    pub parse_error: Option<String>,
    pub parse_summary: Option<String>,
    pub dirty: bool,
    /// Captured request before any edits. `None` for a blank authored tab.
    pub original_request: Option<HttpRequest>,
    /// Editor text at construction, used by Reset and dirty detection.
    pub source_editor: String,
    pub source_request: HttpRequest,
    /// Raw captured body. If the body section is not edited, this exact byte
    /// sequence is sent even when the body is binary and the editor is lossy.
    pub source_body: Vec<u8>,
    pub source_body_text: String,
    pub body_binary: bool,
    pub execution: RepeaterExecutionPhase,
    pub active_execution: Option<u64>,
    pub response: Option<RepeaterResult>,
    pub executions: Vec<RepeaterResult>,
    pub follow_redirects: bool,
}

impl RepeaterTab {
    pub fn new(id: RepeaterId, request: HttpRequest, origin: RepeaterOrigin, redact: bool) -> Self {
        let title = tab_title(&request);
        let document = RepeaterRequest::new(id, title, request.clone(), origin.source());
        let text = editable_request_text(&request, redact);
        let editor = TextBuffer::from_text(&text);
        let source_body_text = editor_body_text(&text).to_string();
        let body_binary = std::str::from_utf8(&request.body).is_err();
        let mut tab = Self {
            document,
            editor,
            origin,
            parse_error: None,
            parse_summary: None,
            dirty: false,
            original_request: if matches!(origin, RepeaterOrigin::Blank) {
                None
            } else {
                Some(request.clone())
            },
            source_editor: text,
            source_request: request.clone(),
            source_body: request.body.clone(),
            source_body_text,
            body_binary,
            execution: RepeaterExecutionPhase::Draft,
            active_execution: None,
            response: None,
            executions: Vec::new(),
            follow_redirects: false,
        };
        tab.refresh_parse();
        tab
    }

    pub fn title(&self) -> &str {
        &self.document.title
    }

    pub fn scheme(&self) -> Scheme {
        self.document.request.scheme
    }

    /// Re-parses the editor buffer. A valid parse updates the document model; an
    /// invalid one keeps the last valid document and exposes the error. A
    /// binary body is preserved byte-for-byte while its body section is
    /// unchanged, so editing a header cannot silently corrupt it.
    pub fn refresh_parse(&mut self) {
        let text = self.editor.text();
        if text == self.source_editor {
            // Unedited documents keep their exact captured values. This is what
            // prevents a display-redacted header from becoming the literal
            // string "<redacted>" on the wire.
            self.document.request = self.source_request.clone();
            self.dirty = false;
            self.parse_error = None;
            self.parse_summary = Some(summary(&self.document.request));
            return;
        }
        let body_text = editor_body_text(&text);
        let body_unchanged = body_text == self.source_body_text;
        match rawframe_http::parse_request(&text, self.document.request.scheme) {
            Ok(mut request) => {
                if body_unchanged {
                    request.body = self.source_body.clone();
                }
                self.document.title = tab_title(&request);
                self.document.request = request;
                self.parse_error = None;
                self.parse_summary = Some(summary(&self.document.request));
                self.dirty = text != self.source_editor;
                if self.active_execution.is_none() && self.response.is_some() {
                    self.execution = RepeaterExecutionPhase::Draft;
                }
            }
            Err(error) => {
                self.parse_error = Some(error.to_string());
                self.parse_summary = None;
                self.dirty = true;
            }
        }
    }

    pub fn is_simulated(&self) -> bool {
        self.origin.is_simulated()
    }

    pub fn url(&self) -> String {
        self.document.request.url()
    }

    pub fn is_busy(&self) -> bool {
        self.active_execution.is_some() && self.execution.is_active()
    }

    pub fn reset_edits(&mut self) {
        let Some(original) = self.original_request.clone() else {
            return;
        };
        self.document.request = original.clone();
        self.document.title = tab_title(&original);
        self.source_request = original.clone();
        self.source_body = original.body.clone();
        self.editor = TextBuffer::from_text(&self.source_editor);
        self.dirty = false;
        self.execution = RepeaterExecutionPhase::Draft;
        self.parse_error = None;
        self.refresh_parse();
    }

    /// The exact request to execute. Redacted placeholders in an edited header
    /// are restored from the original capture by name/occurrence, so enabling
    /// display redaction cannot turn captured credentials into the literal
    /// string `<redacted>` on the wire.
    pub fn execution_request(&self) -> HttpRequest {
        let mut request = self.document.request.clone();
        let Some(original) = &self.original_request else {
            return request;
        };
        if !request
            .headers
            .iter()
            .any(|header| header.value == "<redacted>")
        {
            return request;
        }
        let original_headers = original.headers.clone();
        let mut seen: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        let mut merged = rawframe_core::models::Headers::new();
        for header in request.headers.iter() {
            if header.value == "<redacted>" {
                let key = header.name.to_ascii_lowercase();
                let index = seen.entry(key.clone()).or_insert(0);
                let replacement = original_headers
                    .get_all(&key)
                    .nth(*index)
                    .map(str::to_string)
                    .unwrap_or_else(|| header.value.clone());
                *index += 1;
                merged.append(header.name.clone(), replacement);
            } else {
                merged.append(header.name.clone(), header.value.clone());
            }
        }
        request.headers = merged;
        request
    }

    pub fn set_phase(&mut self, execution: u64, phase: RepeaterExecutionPhase) {
        if self.active_execution != Some(execution) {
            return;
        }
        self.execution = phase;
    }

    pub fn complete(
        &mut self,
        execution: u64,
        phase: RepeaterExecutionPhase,
        result: RepeaterResult,
    ) -> bool {
        if self.active_execution != Some(execution) {
            return false;
        }
        self.active_execution = None;
        self.execution = phase;
        self.response = Some(result.clone());
        self.executions.push(result);
        if self.executions.len() > 8 {
            self.executions.remove(0);
        }
        true
    }

    pub fn comparison(&self) -> Option<ExecutionComparison> {
        let length = self.executions.len();
        if length < 2 {
            return None;
        }
        Some(compare_executions(
            &self.executions[length - 2],
            &self.executions[length - 1],
        ))
    }

    pub fn clear_response(&mut self) {
        self.response = None;
        self.execution = RepeaterExecutionPhase::Draft;
    }
}

fn summary(request: &HttpRequest) -> String {
    format!(
        "{} {} · {} headers · {} B",
        request.method,
        request.authority(),
        request.headers.len(),
        request.body.len()
    )
}

fn editable_request_text(request: &HttpRequest, redact: bool) -> String {
    let mut output = format!("{} {} {}\n", request.method, request.url(), request.version);
    for line in request.headers.display_lines(redact) {
        output.push_str(&line);
        output.push('\n');
    }
    output.push('\n');
    output.push_str(&request.body_text());
    output
}

fn editor_body_text(text: &str) -> &str {
    if let Some(index) = text.find("\n\n") {
        &text[index + 2..]
    } else if let Some(index) = text.find("\r\n\r\n") {
        &text[index + 4..]
    } else {
        ""
    }
}

fn tab_title(request: &HttpRequest) -> String {
    let target = if request.target.chars().count() > 28 {
        let mut truncated: String = request.target.chars().take(27).collect();
        truncated.push('…');
        truncated
    } else {
        request.target.clone()
    };
    format!("{} {}", request.method, target)
}

#[derive(Debug, Clone)]
pub struct RepeaterState {
    pub tabs: Vec<RepeaterTab>,
    pub active: usize,
    pub editing: bool,
    pub response_scroll: u16,
    pub view: RepeaterView,
    next_id: u64,
    next_execution: u64,
}

impl RepeaterState {
    pub fn demo(redact: bool) -> Self {
        let mut state = Self::empty();
        let entries = fixtures::simulated_traffic();
        for id in [14, 1] {
            if let Some(entry) = entries.iter().find(|entry| entry.id == TrafficId(id)) {
                state.add_request(
                    entry.request.clone(),
                    RepeaterOrigin::Simulated(entry.id),
                    redact,
                );
            }
        }
        state.active = 0;
        state
    }

    pub fn empty() -> Self {
        Self {
            tabs: Vec::new(),
            active: 0,
            editing: false,
            response_scroll: 0,
            view: RepeaterView::Raw,
            next_id: 1,
            next_execution: 1,
        }
    }

    pub fn add_request(
        &mut self,
        request: HttpRequest,
        origin: RepeaterOrigin,
        redact: bool,
    ) -> usize {
        let id = RepeaterId(self.next_id);
        self.next_id += 1;
        self.tabs
            .push(RepeaterTab::new(id, request, origin, redact));
        self.active = self.tabs.len() - 1;
        self.editing = false;
        self.response_scroll = 0;
        self.active
    }

    pub fn new_blank(&mut self) -> usize {
        let request = HttpRequest::new("GET", Scheme::Https, "example.test", 443, "/");
        self.add_request(request, RepeaterOrigin::Blank, false)
    }

    /// Duplicates the active draft into an independent tab. Execution state and
    /// responses are intentionally not copied, so tabs cannot overwrite each
    /// other's results.
    pub fn duplicate_active(&mut self) -> Option<usize> {
        let tab = self.active_tab()?.clone();
        let id = RepeaterId(self.next_id);
        self.next_id += 1;
        let mut copy = RepeaterTab::new(id, tab.document.request.clone(), tab.origin, false);
        copy.editor = tab.editor.clone();
        copy.dirty = tab.dirty;
        copy.follow_redirects = tab.follow_redirects;
        copy.original_request = tab.original_request.clone();
        copy.source_editor = tab.source_editor.clone();
        copy.source_request = tab.source_request.clone();
        copy.source_body = tab.source_body.clone();
        copy.source_body_text = tab.source_body_text.clone();
        copy.body_binary = tab.body_binary;
        copy.refresh_parse();
        self.tabs.push(copy);
        self.active = self.tabs.len() - 1;
        self.editing = false;
        self.response_scroll = 0;
        Some(self.active)
    }

    pub fn next_execution_id(&mut self) -> u64 {
        let id = self.next_execution;
        self.next_execution += 1;
        id
    }

    pub fn active_tab_by_id(&mut self, id: RepeaterId) -> Option<&mut RepeaterTab> {
        self.tabs.iter_mut().find(|tab| tab.document.id == id)
    }

    pub fn view_next(&mut self) {
        self.view = self.view.next();
        self.response_scroll = 0;
    }

    pub fn view(&mut self, view: RepeaterView) {
        self.view = view;
        self.response_scroll = 0;
    }

    pub fn active_tab(&self) -> Option<&RepeaterTab> {
        self.tabs.get(self.active)
    }

    pub fn active_tab_mut(&mut self) -> Option<&mut RepeaterTab> {
        self.tabs.get_mut(self.active)
    }

    /// Closes the active tab. The last remaining tab is replaced by a fresh blank
    /// document so the workspace always remains usable.
    pub fn close_active(&mut self) {
        if self.tabs.len() <= 1 {
            self.tabs.clear();
            self.active = 0;
            self.editing = false;
            self.new_blank();
            return;
        }
        self.tabs.remove(self.active);
        if self.active >= self.tabs.len() {
            self.active = self.tabs.len() - 1;
        }
        self.editing = false;
    }

    pub fn select(&mut self, index: usize) {
        if index < self.tabs.len() {
            self.active = index;
            self.editing = false;
            self.response_scroll = 0;
        }
    }

    pub fn select_next(&mut self) {
        if !self.tabs.is_empty() {
            self.select((self.active + 1) % self.tabs.len());
        }
    }

    pub fn select_previous(&mut self) {
        if !self.tabs.is_empty() {
            self.select((self.active + self.tabs.len() - 1) % self.tabs.len());
        }
    }

    pub fn has_unsaved_changes(&self) -> bool {
        self.tabs.iter().any(|tab| tab.dirty)
    }
}

#[derive(Debug, Clone)]
pub struct SettingEdit {
    pub id: SettingId,
    pub buffer: String,
}

#[derive(Debug, Clone, Default)]
pub struct SettingsState {
    pub selected: usize,
    pub edit: Option<SettingEdit>,
}

/// Inline editor for the live target-scope allowlist. Rules are parsed with the
/// same grammar as `--scope`, so the interface cannot invent a rule the proxy
/// would interpret differently.
#[derive(Debug, Clone, Default)]
pub struct ScopeEditorState {
    pub selected: usize,
    pub input: String,
    pub error: Option<String>,
}

impl ScopeEditorState {
    pub fn move_selection(&mut self, delta: i32, len: usize) {
        if len == 0 {
            self.selected = 0;
            return;
        }
        let next = (self.selected as i64 + i64::from(delta)).clamp(0, len as i64 - 1);
        self.selected = next as usize;
    }
}

impl SettingsState {
    pub fn select_next(&mut self) {
        self.selected = (self.selected + 1).min(SettingId::ALL.len() - 1);
    }

    pub fn select_previous(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    pub fn selected_id(&self) -> SettingId {
        SettingId::ALL[self.selected.min(SettingId::ALL.len() - 1)]
    }
}

#[derive(Debug, Clone)]
pub struct PaletteState {
    pub query: String,
    pub selected: usize,
    pub scroll: u16,
}

impl PaletteState {
    pub fn new() -> Self {
        Self {
            query: String::new(),
            selected: 0,
            scroll: 0,
        }
    }

    pub fn set_query(&mut self, query: String) {
        self.query = query;
        self.selected = 0;
        self.scroll = 0;
    }
}

impl Default for PaletteState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MenuAction {
    Inspect(TrafficId),
    Replay(TrafficId),
    Edit(TrafficId),
    Forward(TrafficId),
    Drop(TrafficId),
    CloseRepeaterTab(usize),
    ToggleRedaction,
    OpenPalette,
    OpenHelp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MenuItem {
    pub label: &'static str,
    pub action: MenuAction,
    pub danger: bool,
}

#[derive(Debug, Clone)]
pub struct ContextMenuState {
    pub x: u16,
    pub y: u16,
    pub items: Vec<MenuItem>,
    pub selected: usize,
}

impl ContextMenuState {
    pub fn new(x: u16, y: u16, items: Vec<MenuItem>) -> Self {
        Self {
            x,
            y,
            items,
            selected: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmAction {
    Quit,
    CloseRepeaterTab(usize),
}

#[derive(Debug, Clone)]
pub struct ConfirmState {
    pub title: String,
    pub body: String,
    pub confirm_label: &'static str,
    pub action: ConfirmAction,
}

#[derive(Debug, Clone)]
pub struct Toast {
    pub notice: Notice,
    pub expires_at: Instant,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeater_demo_tabs_are_seeded_and_labelled_simulated() {
        let state = RepeaterState::demo(true);
        assert_eq!(state.tabs.len(), 2);
        assert!(state.tabs.iter().all(RepeaterTab::is_simulated));
        assert_eq!(state.active_tab().unwrap().origin.label(), "SIM");
        assert!(state.active_tab().unwrap().editor.text().contains("Host:"));
    }

    #[test]
    fn editing_a_captured_binary_request_preserves_bytes_and_restores_redacted_headers() {
        let mut request =
            HttpRequest::new("POST", Scheme::Https, "upload.rawframe.test", 443, "/bin");
        request
            .headers
            .append("Authorization", "Bearer real-secret");
        request.body = vec![0x00, 0xff, 0x90, 0x80, b'a'];
        let mut tab = RepeaterTab::new(
            rawframe_core::models::session::RepeaterId(1),
            request.clone(),
            RepeaterOrigin::Captured(TrafficId(4)),
            true,
        );
        assert!(tab.editor.text().contains("<redacted>"));
        assert!(!tab.editor.text().contains("real-secret"));

        let text = tab.editor.text().replace("\r\n", "\n");
        let (head, body) = text.split_once("\n\n").expect("separator");
        let edited = format!("{head}\nX-Debug: 1\n\n{body}");
        tab.editor = TextBuffer::from_text(&edited);
        tab.refresh_parse();
        assert!(tab.parse_error.is_none());
        assert_eq!(tab.document.request.body, request.body);
        assert_eq!(tab.document.request.headers.get("x-debug"), Some("1"));

        let executable = tab.execution_request();
        assert_eq!(
            executable.headers.get("authorization"),
            Some("Bearer real-secret")
        );
        assert_eq!(executable.body, request.body);
    }

    #[test]
    fn parsing_updates_the_document_and_reports_errors() {
        let mut state = RepeaterState::empty();
        state.new_blank();
        let tab = state.active_tab_mut().unwrap();
        assert!(tab.parse_error.is_none());

        tab.editor = TextBuffer::from_text("GET / HTTP/1.1\nHost: api.rawframe.test");
        tab.refresh_parse();
        assert!(tab.parse_error.is_none());
        assert_eq!(tab.document.request.host, "api.rawframe.test");

        tab.editor = TextBuffer::from_text("this is not http");
        tab.refresh_parse();
        assert!(tab.parse_error.is_some());
        assert_eq!(tab.document.request.host, "api.rawframe.test");
    }

    #[test]
    fn closing_the_last_tab_leaves_a_blank_editor() {
        let mut state = RepeaterState::empty();
        state.new_blank();
        state.close_active();
        assert_eq!(state.tabs.len(), 1);
        assert_eq!(state.active_tab().unwrap().origin, RepeaterOrigin::Blank);
    }

    #[test]
    fn settings_selection_stays_in_bounds() {
        let mut state = SettingsState::default();
        for _ in 0..30 {
            state.select_next();
        }
        assert_eq!(state.selected, SettingId::ALL.len() - 1);
        for _ in 0..30 {
            state.select_previous();
        }
        assert_eq!(state.selected, 0);
        assert_eq!(state.selected_id(), SettingId::BindAddress);
    }

    #[test]
    fn redaction_controls_seeded_editor_content() {
        let entries = fixtures::simulated_traffic();
        let entry = entries
            .iter()
            .find(|entry| entry.id == TrafficId(14))
            .unwrap();
        let redacted = RepeaterTab::new(
            RepeaterId(1),
            entry.request.clone(),
            RepeaterOrigin::Simulated(entry.id),
            true,
        );
        let visible = RepeaterTab::new(
            RepeaterId(2),
            entry.request.clone(),
            RepeaterOrigin::Simulated(entry.id),
            false,
        );

        assert!(redacted.editor.text().contains("<redacted>"));
        assert!(!redacted.editor.text().contains("fixture-operator-token"));
        assert!(visible.editor.text().contains("fixture-operator-token"));
    }
}
