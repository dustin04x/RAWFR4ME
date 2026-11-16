//! UI-local state. This module owns view state only; it performs no I/O.

use std::time::Instant;

use rawframe_core::models::message::{HttpRequest, Scheme};
use rawframe_core::models::session::{RepeaterId, RepeaterRequest};
use rawframe_core::models::traffic::{TrafficId, TrafficSource};
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

#[derive(Debug, Clone)]
pub struct RepeaterTab {
    pub document: RepeaterRequest,
    pub editor: TextBuffer,
    pub origin: RepeaterOrigin,
    pub parse_error: Option<String>,
    pub parse_summary: Option<String>,
    pub dirty: bool,
}

impl RepeaterTab {
    pub fn new(id: RepeaterId, request: HttpRequest, origin: RepeaterOrigin, redact: bool) -> Self {
        let title = tab_title(&request);
        let document = RepeaterRequest::new(id, title, request.clone(), origin.source());
        let editor = TextBuffer::from_text(&request.to_display_text(redact));
        let mut tab = Self {
            document,
            editor,
            origin,
            parse_error: None,
            parse_summary: None,
            dirty: false,
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
    /// invalid one keeps the last valid document and exposes the error.
    pub fn refresh_parse(&mut self) {
        let text = self.editor.text();
        match rawframe_http::parse_request(&text, self.document.request.scheme) {
            Ok(request) => {
                let summary = format!(
                    "{} {} · {} headers · {} B",
                    request.method,
                    request.authority(),
                    request.headers.len(),
                    request.body.len()
                );
                self.document.title = tab_title(&request);
                self.document.request = request;
                self.parse_error = None;
                self.parse_summary = Some(summary);
            }
            Err(error) => {
                self.parse_error = Some(error.to_string());
                self.parse_summary = None;
            }
        }
    }

    pub fn is_simulated(&self) -> bool {
        self.origin.is_simulated()
    }

    pub fn url(&self) -> String {
        self.document.request.url()
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
    next_id: u64,
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
            next_id: 1,
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
