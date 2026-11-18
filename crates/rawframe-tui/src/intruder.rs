//! Intruder workspace state.
//!
//! The interface owns the template, the payload sources, the chosen strategy, and
//! the results it has received. It never opens a socket and never expands a
//! request for transmission: the plan it previews is the plan the engine runs,
//! and the engine re-validates every generated request before connecting.
//!
//! Positions are edited through components, not by typing marker characters.
//! Selecting a component and pressing `M` wraps its current value in `§…§`; the
//! parsed position list, the plan count, and the preview all update immediately
//! from the same analysis the engine uses.

use std::collections::{BTreeMap, BTreeSet};

use rawframe_core::models::HttpRequest;
use rawframe_core::models::traffic::TrafficId;
use rawframe_core::{
    AttackPlan, DEFAULT_CONCURRENCY, DEFAULT_MAX_DURATION_SECS, DEFAULT_RATE_PER_SECOND,
    IntruderLaunch, IntruderPhase, IntruderResult, IntruderSummary, IntruderTemplate,
    MAX_CONCURRENCY, MAX_DURATION_SECS, MAX_GENERATED_REQUESTS, MAX_POSITIONS, MAX_RATE_PER_SECOND,
    PayloadSet, PlanError, PositionArea, PositionId, ResultFilter, ResultSort, Strategy,
    TemplateAnalysis, TemplateError, WordlistOutcome, build_plan, plan_count, sorted_indices,
};

use crate::text::TextBuffer;

/// How many expanded requests the preview panel shows.
pub const PREVIEW_LIMIT: usize = 8;
pub const MAX_RESULTS_HELD: usize = MAX_GENERATED_REQUESTS as usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntruderView {
    Setup,
    Results,
}

impl IntruderView {
    pub fn toggled(self) -> Self {
        match self {
            Self::Setup => Self::Results,
            Self::Results => Self::Setup,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Setup => "SETUP",
            Self::Results => "RESULTS",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntruderFocus {
    Request,
    Positions,
    Payloads,
    Strategy,
    Results,
    Inspector,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntruderResultView {
    Raw,
    Headers,
    Body,
    Payloads,
    Compare,
}

impl IntruderResultView {
    pub const ALL: [Self; 5] = [
        Self::Raw,
        Self::Headers,
        Self::Body,
        Self::Payloads,
        Self::Compare,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Raw => "Raw",
            Self::Headers => "Headers",
            Self::Body => "Body",
            Self::Payloads => "Payloads",
            Self::Compare => "Compare",
        }
    }

    pub const fn next(self) -> Self {
        match self {
            Self::Raw => Self::Headers,
            Self::Headers => Self::Body,
            Self::Body => Self::Payloads,
            Self::Payloads => Self::Compare,
            Self::Compare => Self::Raw,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditTarget {
    Head,
    Body,
    Payloads,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptKind {
    NewListName,
    RenameList,
    WordlistPath,
    FilterQuery,
}

#[derive(Debug, Clone)]
pub struct IntruderPrompt {
    pub kind: PromptKind,
    pub buffer: String,
}

impl IntruderPrompt {
    pub fn new(kind: PromptKind, buffer: impl Into<String>) -> Self {
        Self {
            kind,
            buffer: buffer.into(),
        }
    }

    pub fn title(&self) -> &'static str {
        match self.kind {
            PromptKind::NewListName => "NEW PAYLOAD LIST",
            PromptKind::RenameList => "RENAME PAYLOAD LIST",
            PromptKind::WordlistPath => "IMPORT WORDLIST · absolute or relative path",
            PromptKind::FilterQuery => "FILTER RESULTS · status, payload, URL or error text",
        }
    }
}

/// A markable component of the request. Marking one wraps its current value, so
/// the operator never hand-edits marker characters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CandidateKind {
    Path,
    Query(usize),
    Header(usize),
    Body,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub kind: CandidateKind,
    pub label: String,
    pub preview: String,
    /// True when this component currently contains a payload position.
    pub marked: bool,
}

impl Candidate {
    pub const fn area_label(&self) -> &'static str {
        match self.kind {
            CandidateKind::Path => "PATH",
            CandidateKind::Query(_) => "QUERY",
            CandidateKind::Header(_) => "HEADER",
            CandidateKind::Body => "BODY",
        }
    }
}

pub struct IntruderState {
    pub view: IntruderView,
    pub template: Option<IntruderTemplate>,
    pub head: TextBuffer,
    pub body: TextBuffer,
    pub body_editable: bool,
    pub payload_text: TextBuffer,
    pub analysis: TemplateAnalysis,
    pub error: Option<String>,
    pub candidates: Vec<Candidate>,
    pub selection: usize,
    pub position_selection: usize,
    pub focus: IntruderFocus,
    pub sets: Vec<PayloadSet>,
    pub active_set: usize,
    pub assignments: BTreeMap<PositionId, usize>,
    pub enabled: BTreeSet<PositionId>,
    pub strategy: Strategy,
    pub concurrency: usize,
    pub rate: u32,
    pub follow_redirects: bool,
    pub max_duration_secs: u64,
    pub plan: Option<Result<AttackPlan, PlanError>>,
    pub preview: Vec<Result<HttpRequest, TemplateError>>,
    pub run: u64,
    pub phase: IntruderPhase,
    pub completed: u64,
    pub total: u64,
    pub results: Vec<IntruderResult>,
    pub summary: Option<IntruderSummary>,
    pub filter: ResultFilter,
    pub sort: ResultSort,
    pub sort_descending: bool,
    pub result_selection: usize,
    pub baseline: Option<u64>,
    pub inspector_view: IntruderResultView,
    pub editing: bool,
    pub edit_target: EditTarget,
    pub origin: Option<TrafficId>,
    pub original_request: Option<HttpRequest>,
    pub prompt: Option<IntruderPrompt>,
    pub pending_wordlist: Option<u64>,
    pub wordlist_notice: Option<String>,
    pub rows: u16,
    pub cols: u16,
}

impl Default for IntruderState {
    fn default() -> Self {
        Self::new()
    }
}

impl IntruderState {
    pub fn new() -> Self {
        Self {
            view: IntruderView::Setup,
            template: None,
            head: TextBuffer::from_text(""),
            body: TextBuffer::from_text(""),
            body_editable: true,
            payload_text: TextBuffer::from_text(""),
            analysis: TemplateAnalysis::default(),
            error: None,
            candidates: Vec::new(),
            selection: 0,
            position_selection: 0,
            focus: IntruderFocus::Request,
            sets: vec![PayloadSet::builtin(0)],
            active_set: 0,
            assignments: BTreeMap::new(),
            enabled: BTreeSet::new(),
            strategy: Strategy::Sniper,
            concurrency: DEFAULT_CONCURRENCY,
            rate: DEFAULT_RATE_PER_SECOND,
            follow_redirects: false,
            max_duration_secs: DEFAULT_MAX_DURATION_SECS,
            plan: None,
            preview: Vec::new(),
            run: 0,
            phase: IntruderPhase::Idle,
            completed: 0,
            total: 0,
            results: Vec::new(),
            summary: None,
            filter: ResultFilter::default(),
            sort: ResultSort::Index,
            sort_descending: false,
            result_selection: 0,
            baseline: None,
            inspector_view: IntruderResultView::Raw,
            editing: false,
            edit_target: EditTarget::Head,
            origin: None,
            original_request: None,
            prompt: None,
            pending_wordlist: None,
            wordlist_notice: None,
            rows: 10,
            cols: 60,
        }
    }

    /// Loads a request into the editor. The template is a copy: the source
    /// capture, Repeater draft, or stored history entry is never mutated.
    pub fn load_request(&mut self, request: &HttpRequest, origin: Option<TrafficId>) {
        self.template = Some(IntruderTemplate::from_request(request));
        self.original_request = Some(request.clone());
        self.origin = origin;
        self.view = IntruderView::Setup;
        self.focus = IntruderFocus::Request;
        self.editing = false;
        self.results.clear();
        self.summary = None;
        self.phase = IntruderPhase::Idle;
        self.completed = 0;
        self.total = 0;
        self.baseline = None;
        self.error = None;
        self.selection = 0;
        self.sync_buffers();
        self.refresh();
    }

    /// Rebuilds the head/body/payload editors from the template and active list.
    pub fn sync_buffers(&mut self) {
        if let Some(template) = &self.template {
            self.head = TextBuffer::from_text(&template.head_text());
            self.body_editable = template.body_text().is_some();
            self.body = match template.body_text() {
                Some(text) => TextBuffer::from_text(text),
                None => TextBuffer::from_text(""),
            };
        }
        self.sync_payload_buffer();
    }

    fn sync_payload_buffer(&mut self) {
        let text = self
            .sets
            .get(self.active_set)
            .map(|set| {
                let mut text = String::new();
                for (index, payload) in set.payloads.iter().enumerate() {
                    if index > 0 {
                        text.push('\n');
                    }
                    text.push_str(&String::from_utf8_lossy(payload));
                }
                text
            })
            .unwrap_or_default();
        self.payload_text = TextBuffer::from_text(&text);
    }

    pub fn has_template(&self) -> bool {
        self.template.is_some()
    }

    /// Commits the active editor buffer into the template or payload list.
    /// Validation failures stay visible in the workspace; nothing is dropped.
    pub fn apply_edit(&mut self) {
        let head = self.head.text();
        let body = self.body.text();
        let payload_text = self.payload_text.text();
        let active = self.active_set;
        let name = self
            .sets
            .get(active)
            .map(|set| set.name.clone())
            .unwrap_or_else(|| "manual".into());

        let result: Result<(), String> = match self.edit_target {
            EditTarget::Head => match self.template.as_mut() {
                Some(template) => template
                    .set_head_text(&head)
                    .map_err(|error| error.to_string()),
                None => return,
            },
            EditTarget::Body => {
                let Some(template) = self.template.as_mut() else {
                    return;
                };
                if template.body_text().is_some() {
                    template.set_body_text(&body);
                }
                Ok(())
            }
            EditTarget::Payloads => match PayloadSet::manual(active as u32, name, &payload_text) {
                Ok(mut set) => {
                    // The operator has taken ownership of the values: the list is
                    // a session-local named list from now on, not the imported
                    // file and not the built-in set.
                    set.source = rawframe_core::PayloadSource::NamedList;
                    self.sets[active] = set;
                    Ok(())
                }
                Err(error) => Err(error.to_string()),
            },
        };
        match result {
            Ok(()) => {
                self.error = None;
            }
            Err(error) => {
                self.error = Some(error);
            }
        }
        self.refresh();
    }

    /// Recomputes positions, preview, and the exact planned request count.
    pub fn refresh(&mut self) {
        let Some(template) = &self.template else {
            self.analysis = TemplateAnalysis::default();
            self.candidates.clear();
            self.plan = None;
            self.preview.clear();
            return;
        };
        match template.analyze() {
            Ok(analysis) => {
                // A previous syntax/edit complaint no longer describes the
                // request on screen. Execution failures are set elsewhere.
                self.error = None;
                self.analysis = analysis;
                self.candidates = candidates_for(template);
            }
            Err(error) => {
                self.error = Some(error.to_string());
                self.analysis = TemplateAnalysis::default();
                self.candidates = candidates_for(template);
                self.plan = None;
                self.preview.clear();
                return;
            }
        }

        let ids: BTreeSet<PositionId> = self.analysis.positions.iter().map(|p| p.id).collect();
        self.enabled.retain(|id| ids.contains(id));
        for id in &ids {
            self.enabled.insert(*id);
            self.assignments.entry(*id).or_insert(0);
        }
        self.assignments.retain(|id, _| ids.contains(id));
        if self.selection >= self.candidates.len() {
            self.selection = self.candidates.len().saturating_sub(1);
        }
        if self.position_selection >= self.analysis.positions.len() {
            self.position_selection = self.analysis.positions.len().saturating_sub(1);
        }
        self.recompute_plan();
    }

    pub fn enabled_positions(&self) -> Vec<PositionId> {
        self.analysis
            .positions
            .iter()
            .map(|position| position.id)
            .filter(|id| self.enabled.contains(id))
            .collect()
    }

    fn recompute_plan(&mut self) {
        let positions = self.enabled_positions();
        let Some(template) = &self.template else {
            self.plan = None;
            self.preview.clear();
            return;
        };
        let result = build_plan(self.strategy, &positions, &self.assignments, &self.sets);
        match &result {
            Ok(plan) => {
                self.preview = plan.preview(template, &self.analysis, PREVIEW_LIMIT);
            }
            Err(_) => self.preview.clear(),
        }
        self.plan = Some(result);
    }

    /// Recounts without rebuilding the plan; used by the setup summary.
    pub fn planned_count(&self) -> Result<u64, PlanError> {
        plan_count(
            self.strategy,
            &self.enabled_positions(),
            &self.assignments,
            &self.sets,
        )
    }

    pub fn plan_status(&self) -> String {
        match self.planned_count() {
            Ok(count) => format!("{count} REQUEST{}", if count == 1 { "" } else { "S" }),
            Err(error) => error.to_string(),
        }
    }

    pub fn build_launch(&self) -> Result<IntruderLaunch, String> {
        let template = self
            .template
            .clone()
            .ok_or_else(|| "no request is loaded".to_string())?;
        let plan = match &self.plan {
            Some(Ok(plan)) => plan.clone(),
            Some(Err(error)) => return Err(error.to_string()),
            None => return Err("the attack plan is not ready".into()),
        };
        let launch = IntruderLaunch {
            template,
            analysis: self.analysis.clone(),
            plan,
            concurrency: self.concurrency,
            rate_per_second: self.rate,
            follow_redirects: self.follow_redirects,
            max_duration_secs: self.max_duration_secs,
            origin: self.origin,
        };
        launch.validate()?;
        Ok(launch)
    }

    pub fn candidates(&self) -> &[Candidate] {
        &self.candidates
    }

    pub fn selected_candidate(&self) -> Option<&Candidate> {
        self.candidates.get(self.selection)
    }

    pub fn select_candidate(&mut self, delta: i32) {
        if self.candidates.is_empty() {
            self.selection = 0;
            return;
        }
        let len = self.candidates.len() as i32;
        let next = (self.selection as i32 + delta).clamp(0, len - 1);
        self.selection = next as usize;
    }

    /// Marks or unmarks the selected component. This is the whole position
    /// editor: no marker characters are typed by hand.
    pub fn toggle_selected_marker(&mut self) {
        let Some(candidate) = self.candidates.get(self.selection).cloned() else {
            return;
        };
        let Some(template) = self.template.as_mut() else {
            return;
        };
        apply_candidate(template, &candidate);
        self.refresh();
    }

    pub fn toggle_position_enabled(&mut self) {
        let ids = self.analysis.position_ids();
        if ids.is_empty() {
            return;
        }
        let index = self.position_selection.min(ids.len() - 1);
        let Some(position) = self.analysis.position(ids[index]) else {
            return;
        };
        if !self.enabled.insert(position.id) {
            self.enabled.remove(&position.id);
        }
        self.recompute_plan();
    }

    pub fn cycle_position_set(&mut self, delta: i32) {
        let positions = self.enabled_positions();
        if positions.is_empty() {
            return;
        }
        let index = self.position_selection.min(positions.len() - 1);
        let id = positions[index];
        let current = self.assignments.get(&id).copied().unwrap_or(0) as i32;
        let next = (current + delta).rem_euclid(self.sets.len().max(1) as i32);
        self.assignments.insert(id, next as usize);
        self.recompute_plan();
    }

    pub fn clear_positions(&mut self) {
        let Some(template) = self.template.as_mut() else {
            return;
        };
        template.clear_markers();
        self.enabled.clear();
        self.assignments.clear();
        self.sync_buffers();
        self.refresh();
    }

    pub fn strategy_next(&mut self) {
        self.strategy = self.strategy.next();
        self.recompute_plan();
    }

    pub fn strategy_previous(&mut self) {
        self.strategy = self.strategy.previous();
        self.recompute_plan();
    }

    pub fn cycle_concurrency(&mut self) {
        self.concurrency = if self.concurrency >= MAX_CONCURRENCY {
            1
        } else {
            self.concurrency + 1
        };
    }

    pub fn cycle_rate(&mut self) {
        self.rate = if self.rate >= MAX_RATE_PER_SECOND {
            1
        } else {
            self.rate + 1
        };
    }

    pub fn cycle_duration(&mut self) {
        let steps = [30u64, 60, 120, 300, 600, MAX_DURATION_SECS];
        let index = steps
            .iter()
            .position(|value| *value >= self.max_duration_secs)
            .unwrap_or(0);
        self.max_duration_secs = steps[(index + 1) % steps.len()];
    }

    pub fn toggle_redirects(&mut self) {
        self.follow_redirects = !self.follow_redirects;
    }

    // --- payload sources -------------------------------------------------

    pub fn active_set(&self) -> Option<&PayloadSet> {
        self.sets.get(self.active_set)
    }

    pub fn set_name(&self, index: usize) -> &str {
        self.sets
            .get(index)
            .map(|set| set.name.as_str())
            .unwrap_or("")
    }

    pub fn select_set(&mut self, index: usize) {
        if self.sets.is_empty() {
            return;
        }
        self.active_set = index.min(self.sets.len() - 1);
        self.sync_payload_buffer();
    }

    pub fn next_set(&mut self) {
        if !self.sets.is_empty() {
            self.select_set((self.active_set + 1) % self.sets.len());
        }
    }

    pub fn previous_set(&mut self) {
        if !self.sets.is_empty() {
            self.select_set((self.active_set + self.sets.len() - 1) % self.sets.len());
        }
    }

    pub fn add_list(&mut self, name: &str) -> Result<(), String> {
        if self.sets.len() >= rawframe_core::MAX_PAYLOAD_SETS {
            return Err(format!(
                "at most {} payload lists are supported",
                rawframe_core::MAX_PAYLOAD_SETS
            ));
        }
        let name = name.trim();
        if name.is_empty() {
            return Err("a payload list needs a name".into());
        }
        if self.sets.iter().any(|set| set.name == name) {
            return Err(format!("a payload list named '{name}' already exists"));
        }
        let id = self.sets.len() as u32;
        self.sets
            .push(PayloadSet::manual(id, name, "").map_err(|error| error.to_string())?);
        self.active_set = self.sets.len() - 1;
        self.sync_payload_buffer();
        Ok(())
    }

    pub fn rename_active_set(&mut self, name: &str) -> Result<(), String> {
        let name = name.trim();
        if name.is_empty() {
            return Err("a payload list needs a name".into());
        }
        if self
            .sets
            .iter()
            .enumerate()
            .any(|(index, set)| index != self.active_set && set.name == name)
        {
            return Err(format!("a payload list named '{name}' already exists"));
        }
        if let Some(set) = self.sets.get_mut(self.active_set) {
            set.name = name.to_string();
        }
        Ok(())
    }

    pub fn delete_active_set(&mut self) -> Result<(), String> {
        if self.sets.len() <= 1 {
            return Err("the last payload list cannot be deleted".into());
        }
        self.sets.remove(self.active_set);
        for (index, set) in self.sets.iter_mut().enumerate() {
            set.id = index as u32;
        }
        self.active_set = self.active_set.min(self.sets.len() - 1);
        // Re-point assignments at the remaining lists.
        for index in self.assignments.values_mut() {
            *index = (*index).min(self.sets.len() - 1);
        }
        self.sync_payload_buffer();
        self.recompute_plan();
        Ok(())
    }

    pub fn add_builtin_set(&mut self) -> Result<(), String> {
        if self.sets.len() >= rawframe_core::MAX_PAYLOAD_SETS {
            return Err("payload list limit reached".into());
        }
        let mut set = PayloadSet::builtin(self.sets.len() as u32);
        let mut index = 1;
        let base = set.name.clone();
        while self.sets.iter().any(|existing| existing.name == set.name) {
            index += 1;
            set.name = format!("{base} {index}");
        }
        self.sets.push(set);
        self.active_set = self.sets.len() - 1;
        self.sync_payload_buffer();
        Ok(())
    }

    /// Applies a wordlist read that came back from the engine.
    pub fn apply_wordlist(&mut self, outcome: WordlistOutcome) {
        self.pending_wordlist = None;
        if let Some(error) = &outcome.error
            && outcome.payloads.is_empty()
        {
            self.wordlist_notice = Some(error.clone());
            return;
        }
        let name = std::path::Path::new(&outcome.path)
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "wordlist".into());
        let mut set = PayloadSet {
            id: self.sets.len() as u32,
            name: name.clone(),
            source: rawframe_core::PayloadSource::Wordlist,
            payloads: outcome.payloads.clone(),
        };
        let mut index = 1;
        while self.sets.iter().any(|existing| existing.name == set.name) {
            index += 1;
            set.name = format!("{name} {index}");
        }
        if self.sets.len() < rawframe_core::MAX_PAYLOAD_SETS {
            self.sets.push(set);
            self.active_set = self.sets.len() - 1;
            self.sync_payload_buffer();
        }
        let mut notice = format!(
            "Imported {} payloads from {}",
            outcome.payloads.len(),
            outcome.path
        );
        if outcome.skipped > 0 {
            notice.push_str(&format!(
                " · {} blank/oversized lines skipped",
                outcome.skipped
            ));
        }
        if outcome.invalid_utf8 > 0 {
            notice.push_str(&format!(
                " · {} lines skipped because they were not valid UTF-8",
                outcome.invalid_utf8
            ));
        }
        if outcome.truncated {
            notice.push_str(" · file truncated at an Intruder limit");
        }
        if let Some(error) = &outcome.error {
            notice.push_str(&format!(" · {error}"));
        }
        self.wordlist_notice = Some(notice);
    }

    // --- execution state -------------------------------------------------

    pub fn is_active(&self) -> bool {
        self.phase.is_active()
    }

    pub fn begin_run(&mut self, run: u64, total: u64) {
        self.run = run;
        self.total = total;
        self.completed = 0;
        self.results.clear();
        self.summary = None;
        self.baseline = None;
        self.result_selection = 0;
        self.phase = IntruderPhase::Running;
        self.error = None;
        self.view = IntruderView::Results;
        self.focus = IntruderFocus::Results;
    }

    pub fn record_result(&mut self, result: IntruderResult) {
        if result.run != self.run {
            return;
        }
        if let Some(existing) = self
            .results
            .iter_mut()
            .find(|existing| existing.id == result.id)
        {
            *existing = result;
        } else if self.results.len() < MAX_RESULTS_HELD {
            self.results.push(result);
            self.results.sort_by_key(|result| result.index);
        }
        self.completed = self.results.len() as u64;
    }

    pub fn apply_phase(&mut self, run: u64, phase: IntruderPhase) {
        if run == self.run {
            self.phase = phase;
        }
    }

    pub fn finish_run(&mut self, run: u64, summary: IntruderSummary) {
        if run != self.run {
            return;
        }
        self.completed = summary.terminal();
        self.total = summary.planned;
        self.summary = Some(summary);
        self.phase = IntruderPhase::Finished;
    }

    pub fn fail_run(&mut self, run: u64, error: String) {
        if run != self.run {
            return;
        }
        self.error = Some(error);
        self.phase = IntruderPhase::Finished;
    }

    pub fn progress(&self) -> (u64, u64) {
        (self.completed, self.total)
    }

    // --- results ---------------------------------------------------------

    pub fn filtered_results(&self) -> Vec<usize> {
        sorted_indices(&self.results, &self.filter, self.sort, self.sort_descending)
    }

    pub fn selected_result(&self) -> Option<&IntruderResult> {
        let indices = self.filtered_results();
        indices
            .get(self.result_selection.min(indices.len().saturating_sub(1)))
            .and_then(|index| self.results.get(*index))
    }

    pub fn select_result(&mut self, delta: i32) {
        let len = self.filtered_results().len();
        if len == 0 {
            self.result_selection = 0;
            return;
        }
        self.result_selection =
            (self.result_selection as i32 + delta).clamp(0, len as i32 - 1) as usize;
    }

    pub fn cycle_sort(&mut self) {
        self.sort = self.sort.next();
    }

    pub fn toggle_sort_order(&mut self) {
        self.sort_descending = !self.sort_descending;
    }

    pub fn cycle_status_filter(&mut self) {
        use rawframe_core::models::StatusClass;
        const CLASSES: [StatusClass; 6] = [
            StatusClass::Success,
            StatusClass::Redirection,
            StatusClass::ClientError,
            StatusClass::ServerError,
            StatusClass::Informational,
            StatusClass::Unknown,
        ];
        self.filter.status_class = match self.filter.status_class {
            None => Some(CLASSES[0]),
            Some(current) => match CLASSES.iter().position(|class| *class == current) {
                Some(index) if index + 1 < CLASSES.len() => Some(CLASSES[index + 1]),
                _ => None,
            },
        };
    }

    pub fn cycle_outcome_filter(&mut self) {
        use rawframe_core::IntruderOutcome;
        const OUTCOMES: [IntruderOutcome; 6] = [
            IntruderOutcome::Response,
            IntruderOutcome::Blocked,
            IntruderOutcome::TimedOut,
            IntruderOutcome::Failed,
            IntruderOutcome::Cancelled,
            IntruderOutcome::NotSent,
        ];
        self.filter.outcome = match self.filter.outcome {
            None => Some(OUTCOMES[0]),
            Some(current) => match OUTCOMES.iter().position(|outcome| *outcome == current) {
                Some(index) if index + 1 < OUTCOMES.len() => Some(OUTCOMES[index + 1]),
                _ => None,
            },
        };
    }

    pub fn clear_filters(&mut self) {
        self.filter.clear();
        self.result_selection = 0;
    }

    pub fn set_baseline(&mut self) {
        if let Some(result) = self.selected_result() {
            self.baseline = Some(result.index);
        }
    }

    pub fn baseline_result(&self) -> Option<&IntruderResult> {
        let index = self.baseline?;
        self.results.iter().find(|result| result.index == index)
    }

    pub fn cycle_view(&mut self) {
        self.inspector_view = self.inspector_view.next();
    }

    pub fn baseline_label(&self) -> String {
        match self.baseline {
            Some(index) => format!("BASELINE #{index}"),
            None => "NO BASELINE".into(),
        }
    }

    pub fn position_rows(&self) -> Vec<PositionRow> {
        self.analysis
            .positions
            .iter()
            .map(|position| PositionRow {
                id: position.id,
                area: match &position.area {
                    PositionArea::Path => "PATH".to_string(),
                    PositionArea::Query => "QUERY".to_string(),
                    PositionArea::Header { name, .. } => format!("HDR {name}"),
                    PositionArea::Body => "BODY".to_string(),
                },
                literal: String::from_utf8_lossy(&position.literal).into_owned(),
                enabled: self.enabled.contains(&position.id),
                set: self.assignments.get(&position.id).copied().unwrap_or(0),
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PositionRow {
    pub id: PositionId,
    pub area: String,
    pub literal: String,
    pub enabled: bool,
    pub set: usize,
}

/// Builds the component list for the position editor. Order matches the request:
/// path, query values, header values, body.
fn candidates_for(template: &IntruderTemplate) -> Vec<Candidate> {
    let mut candidates = Vec::new();
    let (path, query) = match template.target.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (template.target.as_str(), None),
    };
    if !path.is_empty() {
        candidates.push(Candidate {
            kind: CandidateKind::Path,
            label: "path".into(),
            preview: preview_text(path),
            marked: path.contains(rawframe_core::MARKER),
        });
    }
    if let Some(query) = query {
        for (index, field) in query.split('&').enumerate() {
            if field.is_empty() {
                continue;
            }
            let (name, value) = field.split_once('=').unwrap_or((field, ""));
            candidates.push(Candidate {
                kind: CandidateKind::Query(index),
                label: format!("query · {name}"),
                preview: preview_text(value),
                marked: field.contains(rawframe_core::MARKER),
            });
        }
    }
    for (index, (name, value)) in template.headers.iter().enumerate() {
        candidates.push(Candidate {
            kind: CandidateKind::Header(index),
            label: format!("header · {name}"),
            preview: preview_text(value),
            marked: value.contains(rawframe_core::MARKER),
        });
    }
    if !template.body.is_empty() {
        let preview = match template.body_text() {
            Some(text) => preview_text(text),
            None => format!("{} binary bytes", template.body.len()),
        };
        candidates.push(Candidate {
            kind: CandidateKind::Body,
            label: "body".into(),
            preview,
            marked: find_marker(&template.body),
        });
    }
    candidates
}

fn find_marker(bytes: &[u8]) -> bool {
    let marker = rawframe_core::MARKER.as_bytes();
    bytes.len() >= marker.len() && bytes.windows(marker.len()).any(|window| window == marker)
}

fn preview_text(text: &str) -> String {
    let cleaned = text.replace(rawframe_core::MARKER, "");
    let cleaned = crate::components::truncate(&cleaned, 48);
    if cleaned.is_empty() {
        "(empty)".into()
    } else {
        cleaned
    }
}

/// Wraps or unwraps the component's current value. Wrapping is always applied to
/// the whole component, so a generated request can never contain a partially
/// marked value by accident.
pub fn apply_candidate(template: &mut IntruderTemplate, candidate: &Candidate) {
    let marker = rawframe_core::MARKER;
    match candidate.kind {
        CandidateKind::Path => {
            let (path, rest) = match template.target.split_once('?') {
                Some((path, query)) => (path.to_string(), format!("?{query}")),
                None => (template.target.clone(), String::new()),
            };
            template.target = format!("{}{rest}", wrap_value(&path, marker));
        }
        CandidateKind::Query(index) => {
            let Some((path, query)) = template.target.split_once('?') else {
                return;
            };
            let mut fields: Vec<String> = query.split('&').map(str::to_string).collect();
            if let Some(field) = fields.get(index).cloned() {
                let name = field
                    .split_once('=')
                    .map(|(name, _)| name)
                    .unwrap_or(field.as_str())
                    .to_string();
                let value = field
                    .split_once('=')
                    .map(|(_, value)| value)
                    .unwrap_or_default()
                    .to_string();
                fields[index] = match field.split_once('=') {
                    Some(_) => format!("{name}={}", wrap_value(&value, marker)),
                    None => wrap_value(&name, marker),
                };
                template.target = format!("{path}?{}", fields.join("&"));
            }
        }
        CandidateKind::Header(index) => {
            if let Some((_, value)) = template.headers.get_mut(index) {
                *value = wrap_value(value, marker);
            }
        }
        CandidateKind::Body => {
            // Only the body is unwrapped: other components keep their positions.
            if find_marker(&template.body) {
                template.body = strip_markers(&template.body);
            } else {
                template.mark_whole_body();
            }
        }
    }
}

/// Wraps `value` unless it is already wrapped; an already wrapped value is
/// unwrapped with its literal restored.
fn strip_markers(bytes: &[u8]) -> Vec<u8> {
    let marker = rawframe_core::MARKER.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index..].starts_with(marker) {
            index += marker.len();
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    out
}

fn wrap_value(value: &str, marker: &str) -> String {
    if let Some(inner) = value
        .strip_prefix(marker)
        .and_then(|rest| rest.strip_suffix(marker))
    {
        inner.to_string()
    } else if value.contains(marker) {
        // A partially marked value is normalized by dropping stray markers and
        // then wrapping the literal: the analysis never sees an odd marker.
        let cleaned = value.replace(marker, "");
        format!("{marker}{cleaned}{marker}")
    } else if value.is_empty() {
        format!("{marker}{marker}")
    } else {
        format!("{marker}{value}{marker}")
    }
}

/// Number of positions the editor refuses to exceed, surfaced in the UI.
pub const POSITION_LIMIT: usize = MAX_POSITIONS;

#[cfg(test)]
mod tests {
    use super::*;
    use rawframe_core::models::message::Scheme;

    fn request() -> HttpRequest {
        let mut request = HttpRequest::new(
            "POST",
            Scheme::Http,
            "lab.rawframe.test",
            8080,
            "/api/users?role=user",
        );
        request.headers.append("X-Token", "abc123");
        request.body = br#"{"name":"alice"}"#.to_vec();
        request
    }

    fn state() -> IntruderState {
        let mut state = IntruderState::new();
        state.load_request(&request(), Some(TrafficId(11)));
        state
    }

    #[test]
    fn loading_a_request_never_mutates_the_source() {
        let source = request();
        let mut state = IntruderState::new();
        state.load_request(&source, None);
        state.template.as_mut().unwrap().target.push_str("/x");
        assert_eq!(source.target, "/api/users?role=user");
        assert_eq!(
            state.original_request.as_ref().unwrap().target,
            source.target
        );
    }

    #[test]
    fn components_are_listed_in_request_order() {
        let state = state();
        // `HttpRequest::new` adds a Host header, so the list is path, query,
        // Host, X-Token, body — every markable component, in document order.
        let kinds: Vec<&str> = state
            .candidates()
            .iter()
            .map(Candidate::area_label)
            .collect();
        assert_eq!(kinds, vec!["PATH", "QUERY", "HEADER", "HEADER", "BODY"]);
        assert_eq!(state.candidates()[1].preview, "user");
        assert_eq!(state.candidates()[3].label, "header · X-Token");
    }

    #[test]
    fn marking_a_component_creates_one_position_and_updates_the_plan() {
        let mut state = state();
        assert!(state.position_rows().is_empty());
        state.selection = 3; // X-Token header
        state.toggle_selected_marker();
        assert_eq!(state.position_rows().len(), 1);
        assert_eq!(state.position_rows()[0].area, "HDR X-Token");
        assert_eq!(state.position_rows()[0].literal, "abc123");
        assert!(state.candidates()[3].marked);
        // The built-in list has eight demonstration values, so one position is
        // immediately previewable.
        assert_eq!(state.planned_count().unwrap(), 8);
    }

    #[test]
    fn toggling_the_same_component_restores_the_original_value() {
        let mut state = state();
        state.selection = 0;
        state.toggle_selected_marker();
        assert!(state.template.as_ref().unwrap().target.starts_with("§/"));
        state.toggle_selected_marker();
        assert!(state.position_rows().is_empty());
        assert_eq!(
            state.template.as_ref().unwrap().target,
            "/api/users?role=user"
        );
    }

    #[test]
    fn a_query_value_is_marked_without_touching_the_path() {
        let mut state = state();
        state.selection = 1;
        state.toggle_selected_marker();
        let template = state.template.as_ref().unwrap();
        assert_eq!(template.target, "/api/users?role=§user§");
        assert_eq!(state.position_rows()[0].area, "QUERY");
    }

    #[test]
    fn a_body_position_is_byte_exact_for_binary_payloads() {
        let mut request = request();
        request.body = vec![0x00, 0xff, 0xfe];
        let mut state = IntruderState::new();
        state.load_request(&request, None);
        state.selection = state.candidates().len() - 1;
        state.toggle_selected_marker();
        assert_eq!(state.position_rows().len(), 1);
        assert_eq!(state.position_rows()[0].area, "BODY");
        assert!(find_marker(&state.template.as_ref().unwrap().body));
    }

    #[test]
    fn malformed_manually_typed_markers_surface_an_error() {
        let mut state = state();
        state.head = TextBuffer::from_text("GET /api/§users HTTP/1.1\nHost: x\n");
        state.edit_target = EditTarget::Head;
        state.apply_edit();
        assert!(
            state
                .error
                .as_deref()
                .is_some_and(|error| error.contains("marker")),
            "unmatched markers must be reported, not ignored"
        );
        assert!(state.plan.is_none());
    }

    #[test]
    fn positions_can_be_disabled_and_re_enabled() {
        let mut state = state();
        state.selection = 3;
        state.toggle_selected_marker();
        assert_eq!(state.enabled_positions().len(), 1);
        state.toggle_position_enabled();
        assert!(state.enabled_positions().is_empty());
        assert!(matches!(state.planned_count(), Err(PlanError::NoPositions)));
        state.toggle_position_enabled();
        assert_eq!(state.enabled_positions().len(), 1);
    }

    #[test]
    fn payload_sets_are_created_renamed_and_deleted_without_duplicates() {
        let mut state = state();
        state.add_list("candidates").unwrap();
        assert_eq!(state.sets.len(), 2);
        assert!(state.add_list("candidates").is_err());
        state.rename_active_set("names").unwrap();
        assert_eq!(state.set_name(1), "names");
        state.delete_active_set().unwrap();
        assert_eq!(state.sets.len(), 1);
        assert!(state.delete_active_set().is_err(), "the last list is kept");
    }

    #[test]
    fn manual_payload_edits_drive_the_plan_count() {
        let mut state = state();
        state.selection = 3;
        state.toggle_selected_marker();
        state.payload_text = TextBuffer::from_text("one\ntwo\nthree");
        state.edit_target = EditTarget::Payloads;
        state.apply_edit();
        assert_eq!(state.sets[0].payloads.len(), 3);
        assert_eq!(state.planned_count().unwrap(), 3);
    }

    #[test]
    fn all_four_strategies_change_the_planned_count() {
        let mut state = state();
        state.selection = 3;
        state.toggle_selected_marker();
        state.selection = 1;
        state.toggle_selected_marker();
        state.payload_text = TextBuffer::from_text("a\nb");
        state.edit_target = EditTarget::Payloads;
        state.apply_edit();
        state.add_list("second").unwrap();
        state.payload_text = TextBuffer::from_text("1\n2\n3");
        state.apply_edit();
        // Give the X-Token position the three-value list so cluster bomb has a
        // genuinely asymmetric product.
        state.assignments.insert(PositionId(2), 1);
        state.recompute_plan();

        // Sniper iterates one position at a time: 2 + 3 requests.
        assert_eq!(state.strategy, Strategy::Sniper);
        assert_eq!(state.planned_count().unwrap(), 5);
        state.strategy_next();
        assert_eq!(state.strategy, Strategy::BatteringRam);
        assert_eq!(state.planned_count().unwrap(), 2);
        state.strategy_next();
        assert_eq!(state.strategy, Strategy::Pitchfork);
        // 2 and 3 payloads cannot be paired index-by-index.
        assert!(matches!(
            state.planned_count(),
            Err(PlanError::LengthMismatch { .. })
        ));
        // Equal-length lists make pitchfork valid again.
        state.assignments.insert(PositionId(2), 0);
        state.recompute_plan();
        assert_eq!(state.planned_count().unwrap(), 2);
        state.assignments.insert(PositionId(2), 1);
        state.recompute_plan();
        state.strategy_next();
        assert_eq!(state.strategy, Strategy::ClusterBomb);
        assert_eq!(state.planned_count().unwrap(), 6);
    }

    #[test]
    fn the_plan_is_rejected_above_the_request_ceiling() {
        let mut state = state();
        state.selection = 3;
        state.toggle_selected_marker();
        state.selection = 1;
        state.toggle_selected_marker();
        state.strategy = Strategy::ClusterBomb;
        let values: String = (0..512).map(|index| format!("{index}\n")).collect();
        state.payload_text = TextBuffer::from_text(&values);
        state.edit_target = EditTarget::Payloads;
        state.apply_edit();
        state.add_list("second").unwrap();
        state.payload_text = TextBuffer::from_text(&values);
        state.apply_edit();
        // The first list is still assigned to both positions, so make the second
        // position use the second list.
        state.assignments.insert(PositionId(1), 0);
        state.assignments.insert(PositionId(2), 1);
        state.recompute_plan();
        assert!(matches!(
            state.planned_count(),
            Err(PlanError::TooManyRequests { .. })
        ));
        assert!(state.build_launch().is_err());
    }

    #[test]
    fn preview_matches_the_launch_plan() {
        let mut state = state();
        state.selection = 3;
        state.toggle_selected_marker();
        state.payload_text = TextBuffer::from_text("one\ntwo");
        state.edit_target = EditTarget::Payloads;
        state.apply_edit();
        assert_eq!(state.preview.len(), 2);
        let launch = state.build_launch().unwrap();
        assert_eq!(launch.plan.count, 2);
        assert_eq!(launch.origin, Some(TrafficId(11)));
        let first = launch.plan.preview(&launch.template, &launch.analysis, 2);
        assert_eq!(
            first[0].as_ref().unwrap().headers.get("x-token"),
            Some("one")
        );
    }

    #[test]
    fn results_are_recorded_filtered_and_sorted() {
        use rawframe_core::repeater::{RepeaterResult, RepeaterTimings};

        fn result(index: u64, status: u16, size: usize) -> IntruderResult {
            let mut response = rawframe_core::models::HttpResponse::new(status);
            response.body = vec![b'x'; size];
            IntruderResult {
                id: TrafficId(3_000_000 + index),
                run: 1,
                index,
                payloads: vec![format!("p{index}").into_bytes()],
                positions: vec![PositionId(1)],
                phase: rawframe_core::RepeaterExecutionPhase::Completed,
                result: RepeaterResult {
                    request: request(),
                    response: Some(response),
                    timings: RepeaterTimings::default(),
                    redirects: Vec::new(),
                    truncated: false,
                    response_bytes: size,
                    error: None,
                    warnings: Vec::new(),
                    sent_at: chrono::Utc::now(),
                },
            }
        }

        let mut state = state();
        state.begin_run(1, 3);
        state.record_result(result(0, 200, 10));
        state.record_result(result(1, 403, 30));
        state.record_result(result(2, 200, 20));
        assert_eq!(state.completed, 3);

        state.sort = ResultSort::Size;
        assert_eq!(state.filtered_results(), vec![0, 2, 1]);
        state.filter.query = "p1".into();
        assert_eq!(state.filtered_results(), vec![1]);
        state.clear_filters();

        state.result_selection = 1;
        state.set_baseline();
        assert_eq!(state.baseline, Some(2));
        assert!(state.baseline_result().is_some());
    }

    #[test]
    fn late_results_from_an_older_run_are_ignored() {
        let mut state = state();
        state.begin_run(2, 1);
        state.completed = 0;
        state.record_result(IntruderResult {
            id: TrafficId(3_000_001),
            run: 1,
            index: 0,
            payloads: Vec::new(),
            positions: Vec::new(),
            phase: rawframe_core::RepeaterExecutionPhase::Completed,
            result: rawframe_core::repeater::RepeaterResult {
                request: request(),
                response: None,
                timings: Default::default(),
                redirects: Vec::new(),
                truncated: false,
                response_bytes: 0,
                error: None,
                warnings: Vec::new(),
                sent_at: chrono::Utc::now(),
            },
        });
        assert!(state.results.is_empty());
    }

    #[test]
    fn the_operating_limits_stay_inside_the_engine_limits() {
        let mut state = state();
        for _ in 0..MAX_CONCURRENCY + 3 {
            state.cycle_concurrency();
        }
        assert!(state.concurrency <= MAX_CONCURRENCY);
        for _ in 0..MAX_RATE_PER_SECOND + 3 {
            state.cycle_rate();
        }
        assert!(state.rate <= MAX_RATE_PER_SECOND);
        for _ in 0..8 {
            state.cycle_duration();
        }
        assert!(state.max_duration_secs <= MAX_DURATION_SECS);
        assert!(!state.follow_redirects, "redirects are off by default");
    }
}
