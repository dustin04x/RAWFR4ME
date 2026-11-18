//! UI-local state. This module owns view state only; it performs no I/O.

use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::time::Instant;

use chrono::Utc;
use rawframe_core::decoder::{
    DECODER_MAX_PIPELINE_STEPS, OutputFormat, PipelineFailure, PipelineRun, PipelineStep,
    Transform, TransformLimits, TransformOutput, execute_pipeline,
};
use rawframe_core::models::message::{HttpRequest, Scheme};
use rawframe_core::models::session::{RepeaterId, RepeaterRequest};
use rawframe_core::models::traffic::{TrafficId, TrafficSource};
use rawframe_core::repeater::{
    ExecutionComparison, RepeaterExecutionPhase, RepeaterResult, compare_executions,
};
use rawframe_core::security::sanitize_for_display;
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

    /// Replaces only the request body while preserving the original capture and
    /// the editor header section. The exact bytes are retained for sending; the
    /// editor receives a lossy display for binary output. Framing headers are
    /// rewritten so the engine will not reject a stale length.
    pub fn replace_body(&mut self, body: Vec<u8>) {
        let body_text = sanitize_for_display(&String::from_utf8_lossy(&body));
        let text = self.editor.text();
        let mut lines: Vec<String> = text.split('\n').map(ToOwned::to_owned).collect();
        let blank = lines
            .iter()
            .position(|line| line.trim().is_empty())
            .unwrap_or_else(|| {
                lines.push(String::new());
                lines.len() - 1
            });
        if blank > 0 {
            let mut headers: Vec<String> = lines[1..blank]
                .iter()
                .filter(|line| {
                    let lower = line.to_ascii_lowercase();
                    !lower.starts_with("content-length:")
                        && !lower.starts_with("transfer-encoding:")
                })
                .cloned()
                .collect();
            if !body.is_empty() {
                headers.push(format!("Content-Length: {}", body.len()));
            }
            let request_line = lines.remove(0);
            lines = std::iter::once(request_line)
                .chain(headers)
                .chain([String::new(), String::new()])
                .collect();
        }
        let mut new_text = lines.join("\n");
        new_text.push_str(&body_text);
        self.editor = TextBuffer::from_text(&new_text);
        self.source_body = body;
        self.source_body_text = body_text;
        self.body_binary = std::str::from_utf8(&self.source_body).is_err();
        self.dirty = true;
        self.refresh_parse();
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecoderFocus {
    Input,
    Pipeline,
    Output,
}

impl DecoderFocus {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Input => "INPUT",
            Self::Pipeline => "PIPELINE",
            Self::Output => "OUTPUT",
        }
    }
}

#[derive(Debug, Clone)]
pub struct DecoderHistoryEntry {
    pub sequence: u64,
    pub steps: Vec<Transform>,
    pub input_bytes: usize,
    pub output_bytes: usize,
    pub result: String,
    pub at: String,
}

/// View-local Decoder state. Execution is delegated to the core pipeline on a
/// worker thread; this state owns only buffers, selection, and presentation.
#[derive(Debug)]
pub struct DecoderState {
    pub input: TextBuffer,
    pub input_bytes: Vec<u8>,
    pub input_source: String,
    pub input_binary: bool,
    pub source_label: String,
    pub output: Option<TransformOutput>,
    pub displayed_bytes: Vec<u8>,
    pub displayed_format: OutputFormat,
    pub displayed_label: String,
    pub displayed_note: Option<String>,
    pub output_display: String,
    pub display_truncated: bool,
    pub output_scroll: u16,
    pub pipeline: Vec<Transform>,
    pub selected_transform: usize,
    pub selected_step: usize,
    pub view_step: Option<usize>,
    pub steps: Vec<PipelineStep>,
    pub error: Option<PipelineFailure>,
    pub focus: DecoderFocus,
    pub editing: bool,
    pub history: Vec<DecoderHistoryEntry>,
    pub history_open: bool,
    pub history_scroll: u16,
    pub running: bool,
    pub limits: TransformLimits,
    pub clipboard_requested: Option<String>,
    next_run: u64,
    active_run: Option<u64>,
    pending: Option<Receiver<(u64, PipelineRun)>>,
}

impl Default for DecoderState {
    fn default() -> Self {
        Self::new()
    }
}

impl DecoderState {
    pub fn new() -> Self {
        Self {
            input: TextBuffer::from_text(""),
            input_bytes: Vec::new(),
            input_source: String::new(),
            input_binary: false,
            source_label: "MANUAL INPUT".into(),
            output: None,
            displayed_bytes: Vec::new(),
            displayed_format: OutputFormat::Text,
            displayed_label: "OUTPUT".into(),
            displayed_note: None,
            output_display: String::new(),
            display_truncated: false,
            output_scroll: 0,
            pipeline: Vec::new(),
            selected_transform: 0,
            selected_step: 0,
            view_step: None,
            steps: Vec::new(),
            error: None,
            focus: DecoderFocus::Input,
            editing: false,
            history: Vec::new(),
            history_open: false,
            history_scroll: 0,
            running: false,
            limits: TransformLimits::default(),
            clipboard_requested: None,
            next_run: 1,
            active_run: None,
            pending: None,
        }
    }

    pub fn selected_transform(&self) -> Transform {
        Transform::ALL[self
            .selected_transform
            .min(Transform::ALL.len().saturating_sub(1))]
    }

    pub fn select_transform(&mut self, delta: i32) {
        let len = Transform::ALL.len() as i32;
        let next = (self.selected_transform as i32 + delta).rem_euclid(len);
        self.selected_transform = next as usize;
    }

    pub fn toggle_direction(&mut self) {
        if let Some(toggled) = self.selected_transform().toggled_direction()
            && let Some(index) = Transform::ALL.iter().position(|item| *item == toggled)
        {
            self.selected_transform = index;
        }
    }

    pub fn add_step(&mut self) -> Result<(), String> {
        if self.pipeline.len() >= DECODER_MAX_PIPELINE_STEPS {
            return Err(format!(
                "Pipeline is limited to {DECODER_MAX_PIPELINE_STEPS} steps."
            ));
        }
        self.invalidate_run();
        self.pipeline.push(self.selected_transform());
        self.selected_step = self.pipeline.len() - 1;
        self.focus = DecoderFocus::Pipeline;
        Ok(())
    }

    pub fn remove_step(&mut self) {
        if self.pipeline.is_empty() {
            return;
        }
        self.invalidate_run();
        let index = self.selected_step.min(self.pipeline.len() - 1);
        self.pipeline.remove(index);
        self.selected_step = self
            .selected_step
            .min(self.pipeline.len().saturating_sub(1));
        if self.view_step.is_some() {
            self.show_final_output();
        }
    }

    pub fn move_step(&mut self, delta: i32) {
        if self.pipeline.len() < 2 {
            return;
        }
        let target =
            (self.selected_step as i32 + delta).clamp(0, self.pipeline.len() as i32 - 1) as usize;
        if target == self.selected_step {
            return;
        }
        self.invalidate_run();
        self.pipeline.swap(self.selected_step, target);
        self.selected_step = target;
        if self.view_step.is_some() {
            self.show_final_output();
        }
    }

    pub fn select_step(&mut self, delta: i32) {
        if self.pipeline.is_empty() {
            self.selected_step = 0;
            return;
        }
        let target = (self.selected_step as i32 + delta).clamp(0, self.pipeline.len() as i32 - 1);
        self.selected_step = target as usize;
    }

    pub fn preview_selected_step(&mut self) {
        let Some(step) = self.steps.get(self.selected_step) else {
            return;
        };
        self.view_step = Some(self.selected_step);
        self.set_display(
            step.output.clone(),
            step.format,
            format!(
                "STEP {} · {}",
                self.selected_step + 1,
                step.transform.label()
            ),
            step.note.clone(),
        );
    }

    pub fn show_final_output(&mut self) {
        self.view_step = None;
        if let Some(output) = &self.output {
            self.set_display(
                output.bytes.clone(),
                output.format,
                "OUTPUT".into(),
                output.note.clone(),
            );
        } else {
            self.displayed_bytes.clear();
            self.displayed_format = OutputFormat::Text;
            self.displayed_label = "OUTPUT".into();
            self.displayed_note = None;
            self.output_display.clear();
            self.display_truncated = false;
        }
    }

    pub fn load_input(&mut self, bytes: Vec<u8>, source: impl Into<String>) {
        self.invalidate_run();
        let binary = std::str::from_utf8(&bytes).is_err();
        let text = sanitize_for_display(&String::from_utf8_lossy(&bytes));
        self.input = TextBuffer::from_text(&text);
        self.input_source = text;
        self.input_bytes = bytes;
        self.input_binary = binary;
        self.source_label = source.into();
        self.output_scroll = 0;
        self.show_final_output();
    }

    /// Called after every input edit. An unchanged body preserves exact binary
    /// bytes; any edit switches to the visible UTF-8 text deliberately.
    pub fn sync_input(&mut self) {
        let text = self.input.text();
        if text == self.input_source {
            return;
        }
        self.invalidate_run();
        self.input_bytes = text.clone().into_bytes();
        self.input_source = text;
        self.input_binary = false;
    }

    pub fn execute(&mut self) -> Result<(), String> {
        if self.running {
            return Err("A transformation is already running.".into());
        }
        self.sync_input();
        let id = self.next_run;
        self.next_run += 1;
        let (sender, receiver) = mpsc::channel();
        let input = self.input_bytes.clone();
        let steps = self.pipeline.clone();
        let limits = self.limits;
        std::thread::Builder::new()
            .name("rawframe-decoder".into())
            .spawn(move || {
                let run = execute_pipeline(&input, &steps, limits);
                let _ = sender.send((id, run));
            })
            .map_err(|error| format!("Could not start Decoder worker: {error}"))?;
        self.active_run = Some(id);
        self.pending = Some(receiver);
        self.running = true;
        self.error = None;
        self.view_step = None;
        self.output_scroll = 0;
        Ok(())
    }

    /// Polls the worker. Returns true when a new result was applied.
    pub fn poll(&mut self) -> bool {
        let Some(receiver) = &self.pending else {
            return false;
        };
        match receiver.try_recv() {
            Ok((id, run)) => {
                self.pending = None;
                if Some(id) != self.active_run {
                    return false;
                }
                self.active_run = None;
                self.running = false;
                self.apply_run(run);
                true
            }
            Err(TryRecvError::Empty) => false,
            Err(TryRecvError::Disconnected) => {
                self.pending = None;
                self.active_run = None;
                self.running = false;
                self.error = Some(PipelineFailure {
                    step_index: 0,
                    transform: None,
                    message: "Decoder worker stopped without a result.".into(),
                });
                true
            }
        }
    }

    fn apply_run(&mut self, run: PipelineRun) {
        let sequence = self.next_run.saturating_sub(1);
        let result = match (&run.error, &run.output) {
            (None, Some(output)) => format!("OK · {}", output.format.label()),
            (Some(error), _) => format!("FAILED · {}", error.label()),
            _ => "NO OUTPUT".into(),
        };
        self.history.insert(
            0,
            DecoderHistoryEntry {
                sequence,
                steps: self.pipeline.clone(),
                input_bytes: run.input_bytes,
                output_bytes: run.total_output_bytes(),
                result,
                at: Utc::now().format("%H:%M:%S").to_string(),
            },
        );
        self.history.truncate(64);
        self.steps = run.steps;
        self.error = run.error;
        self.output = run.output;
        self.view_step = None;
        self.show_final_output();
        self.output_scroll = 0;
    }

    pub fn clear_input_output(&mut self) {
        self.invalidate_run();
        self.input = TextBuffer::from_text("");
        self.input_bytes.clear();
        self.input_source.clear();
        self.input_binary = false;
        self.source_label = "MANUAL INPUT".into();
        self.output = None;
        self.steps.clear();
        self.error = None;
        self.show_final_output();
        self.output_scroll = 0;
    }

    pub fn clear_pipeline(&mut self) {
        self.invalidate_run();
        self.pipeline.clear();
        self.selected_step = 0;
        self.steps.clear();
        self.error = None;
        self.show_final_output();
    }

    pub fn swap_input_output(&mut self) {
        let Some(output) = self.output.clone() else {
            return;
        };
        let old_input = self.input_bytes.clone();
        self.load_input(output.bytes, "SWAPPED FROM OUTPUT");
        self.output = Some(TransformOutput {
            bytes: old_input.clone(),
            format: rawframe_core::decoder::detect_format(&old_input),
            note: Some("Previous input after swap.".into()),
        });
        self.show_final_output();
    }

    pub fn copy_displayed(&mut self) -> bool {
        if self.displayed_bytes.is_empty() && self.output_display.is_empty() {
            return false;
        }
        let text = if self.displayed_format.is_binary() {
            self.output_display.clone()
        } else {
            String::from_utf8_lossy(&self.displayed_bytes).into_owned()
        };
        self.clipboard_requested = Some(text);
        true
    }

    pub fn take_clipboard_request(&mut self) -> Option<String> {
        self.clipboard_requested.take()
    }

    pub fn select_history(&mut self, delta: i32) {
        let next = (i64::from(self.history_scroll) + i64::from(delta)).max(0) as u16;
        self.history_scroll = next.min(self.history.len().saturating_sub(1) as u16);
    }

    fn invalidate_run(&mut self) {
        if self.running {
            self.running = false;
            self.active_run = None;
            self.pending = None;
        }
    }

    fn set_display(
        &mut self,
        bytes: Vec<u8>,
        format: OutputFormat,
        label: String,
        note: Option<String>,
    ) {
        let (display, truncated) = display_bytes(&bytes, format);
        self.displayed_bytes = bytes;
        self.displayed_format = format;
        self.displayed_label = label;
        self.displayed_note = note;
        self.output_display = display;
        self.display_truncated = truncated;
        self.output_scroll = 0;
    }
}

const DISPLAY_LIMIT: usize = 128 * 1024;

fn display_bytes(bytes: &[u8], format: OutputFormat) -> (String, bool) {
    if bytes.is_empty() {
        return (String::new(), false);
    }
    if format.is_binary() {
        let limit = bytes.len().min(DISPLAY_LIMIT);
        let mut text = String::new();
        for (offset, chunk) in bytes[..limit].chunks(16).enumerate() {
            let mut hex = String::new();
            let mut ascii = String::new();
            for byte in chunk {
                use std::fmt::Write as _;
                let _ = write!(hex, "{byte:02x} ");
                ascii.push(if byte.is_ascii_graphic() || *byte == b' ' {
                    *byte as char
                } else {
                    '.'
                });
            }
            use std::fmt::Write as _;
            let _ = writeln!(text, "{:08x}  {hex:<48} |{ascii}|", offset * 16);
        }
        if limit < bytes.len() {
            use std::fmt::Write as _;
            let _ = writeln!(
                text,
                "[display truncated at {limit} bytes of {}]",
                bytes.len()
            );
        }
        return (text, limit < bytes.len());
    }
    let text = sanitize_for_display(&String::from_utf8_lossy(bytes));
    if text.len() > DISPLAY_LIMIT {
        let mut end = DISPLAY_LIMIT;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        (
            format!(
                "{}\n[display truncated at {DISPLAY_LIMIT} bytes of {}]",
                &text[..end],
                bytes.len()
            ),
            true,
        )
    } else {
        (text, false)
    }
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

#[derive(Debug, Clone)]
pub enum ConfirmAction {
    Quit,
    CloseRepeaterTab(usize),
    /// Start a confirmed attack. The plan is captured when the prompt opens, so
    /// confirming sends exactly the preview the operator reviewed.
    IntruderStart(Box<rawframe_core::IntruderLaunch>),
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
