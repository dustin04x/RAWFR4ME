//! Application controller for the terminal shell.
//!
//! The controller owns presentation state and consumes [`AppEvent`]s from the
//! event bus. Networking and storage services are absent in this milestone; the
//! UI keeps their boundary explicit instead of faking live behaviour.

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use chrono::Utc;
use ratatui::layout::{Position, Rect};
use rawframe_core::models::config::ScopeRule;
use rawframe_core::models::session::{SessionId, SessionSummary};
use rawframe_core::models::traffic::{TrafficEntry, TrafficId, TrafficSource, TrafficState};
use rawframe_core::models::{AppConfig, Session};
use rawframe_core::repeater::{
    RepeaterCommand, RepeaterCommandSender, RepeaterEvent, RepeaterExecutionPhase, validate_request,
};
use rawframe_core::storage::{
    StorageCommand, StorageCommandSender, StorageEvent, StoragePolicy, StorageStatus,
};
use rawframe_core::{
    AppCommand, AppEvent, CommandSender, EventBus, EventSender, HistoryFilter, Notice, ProxyState,
    TlsStatus,
};

use crate::commands::{CommandId, CommandSpec, filter_commands};
use crate::components::lifecycle;
use crate::interaction::{ActionId, Focus, HitTarget, MessageSide, NavSection, SettingId};
use crate::layout::{AppLayout, DragTarget, LayoutState, compute};
use crate::state::{
    ConfirmAction, ConfirmState, ContextMenuState, DecoderState, InspectorState, MenuAction,
    MenuItem, PaletteState, RepeaterOrigin, RepeaterState, RepeaterTab, ScopeEditorState,
    SearchState, SettingEdit, SettingsState, Toast,
};
use crate::text::TextBuffer;
use crate::theme::Theme;

const TOAST_LIFETIME: Duration = Duration::from_secs(6);
const MAX_TOASTS: usize = 4;
const DEFAULT_AREA: Rect = Rect::new(0, 0, 120, 36);

#[derive(Debug, Clone)]
pub(crate) struct InterceptionWorkbench {
    pub selected: Option<TrafficId>,
    pub editor: TextBuffer,
    pub original: Option<rawframe_core::models::HttpRequest>,
    pub parse_error: Option<String>,
    pub validation_error: Option<String>,
    pub dirty: bool,
    pub editing: bool,
    pub queue_pending: usize,
    pub queue_capacity: usize,
    #[allow(dead_code)]
    pub last_decision: Option<String>,
}

impl Default for InterceptionWorkbench {
    fn default() -> Self {
        Self {
            selected: None,
            editor: TextBuffer::from_text(""),
            original: None,
            parse_error: None,
            validation_error: None,
            dirty: false,
            editing: false,
            queue_pending: 0,
            queue_capacity: 0,
            last_decision: None,
        }
    }
}

pub struct App {
    pub(crate) config: AppConfig,
    pub(crate) theme: Theme,
    pub(crate) session: Session,
    pub(crate) nav: NavSection,
    pub(crate) focus: Focus,
    pub(crate) layout: LayoutState,
    pub(crate) proxy_state: ProxyState,
    pub(crate) proxy_address: Option<SocketAddr>,
    pub(crate) proxy_sender: Option<CommandSender>,
    pub(crate) repeater_sender: Option<RepeaterCommandSender>,
    pub(crate) traffic: Vec<TrafficEntry>,
    pub(crate) proxy_selected: Option<TrafficId>,
    pub(crate) history_selected: Option<TrafficId>,
    pub(crate) history_filter: HistoryFilter,
    pub(crate) search: SearchState,
    pub(crate) inspector: InspectorState,
    pub(crate) repeater: RepeaterState,
    pub(crate) decoder: DecoderState,
    pub(crate) settings: SettingsState,
    pub(crate) palette: Option<PaletteState>,
    pub(crate) context_menu: Option<ContextMenuState>,
    pub(crate) help_open: bool,
    pub(crate) confirm: Option<ConfirmState>,
    pub(crate) notices: Vec<Toast>,
    pub(crate) events: EventBus,
    pub(crate) should_quit: bool,
    pub(crate) last_area: Rect,
    pub(crate) render: crate::interaction::RenderOutput,
    pub(crate) hover: Option<HitTarget>,
    pub(crate) pointer: Option<Position>,
    pub(crate) drag: Option<DragTarget>,
    pub(crate) last_click: Option<(Instant, Position, HitTarget)>,
    pub(crate) interception: InterceptionWorkbench,
    pub(crate) tls_status: TlsStatus,
    /// Persistence status as reported by the storage worker. The TUI never
    /// opens the database; it only renders this state and sends commands.
    pub(crate) storage: StorageStatus,
    pub(crate) storage_sender: Option<StorageCommandSender>,
    pub(crate) sessions: Vec<SessionSummary>,
    pub(crate) sessions_open: bool,
    pub(crate) sessions_selected: usize,
    pub(crate) sessions_loading: bool,
    /// Session whose history was restored into the read-only History view.
    pub(crate) restored_session: Option<(SessionId, String)>,
    pub(crate) scope_editor: Option<ScopeEditorState>,
}

impl App {
    pub fn new(config: AppConfig) -> Self {
        Self::with_event_bus(config, EventBus::new())
    }

    pub fn with_event_bus(config: AppConfig, events: EventBus) -> Self {
        let theme = Theme::from_preset(config.appearance.accent);
        let traffic = rawframe_core::fixtures::simulated_traffic();
        let repeater = RepeaterState::demo(config.appearance.redact_sensitive_headers);

        let mut app = Self {
            config,
            theme,
            session: Session::demo(),
            nav: NavSection::Proxy,
            focus: Focus::Content,
            layout: LayoutState::default(),
            proxy_state: ProxyState::Stopped,
            proxy_address: None,
            proxy_sender: None,
            repeater_sender: None,
            traffic,
            proxy_selected: None,
            history_selected: None,
            history_filter: HistoryFilter::default(),
            search: SearchState::default(),
            inspector: InspectorState::default(),
            repeater,
            decoder: DecoderState::new(),
            settings: SettingsState::default(),
            palette: None,
            context_menu: None,
            help_open: false,
            confirm: None,
            notices: Vec::new(),
            events,
            should_quit: false,
            last_area: DEFAULT_AREA,
            render: crate::interaction::RenderOutput::default(),
            hover: None,
            pointer: None,
            drag: None,
            last_click: None,
            interception: InterceptionWorkbench::default(),
            tls_status: TlsStatus::disabled(),
            storage: StorageStatus::disabled(),
            storage_sender: None,
            sessions: Vec::new(),
            sessions_open: false,
            sessions_selected: 0,
            sessions_loading: false,
            restored_session: None,
            scope_editor: None,
        };
        app.ensure_selections();
        app.notify(Notice::info(
            "Fixtures loaded. Press P on the Proxy screen to start the local HTTP engine.",
        ));
        app
    }

    pub fn demo() -> Self {
        Self::new(AppConfig::default())
    }

    pub fn event_sender(&self) -> EventSender {
        self.events.sender()
    }

    /// Registers an independent event stream for a background service (the CLI
    /// capture pump). Events already queued before subscribing are not replayed.
    pub fn subscribe_events(&mut self) -> rawframe_core::EventReceiver {
        self.events.subscribe()
    }

    /// Marks persistence as deliberately disabled (for example `--no-persist`).
    pub fn report_storage_disabled(&mut self) {
        self.storage = StorageStatus::disabled();
        self.notify_warning(
            "Persistence is disabled (--no-persist): captures are kept in memory only and are lost on exit.",
        );
    }

    /// Reports a persistence failure that happened before the storage worker
    /// existed, so the interface never implies traffic is being stored.
    pub fn report_storage_failure(&mut self, path: Option<std::path::PathBuf>, error: String) {
        self.storage = StorageStatus::failed(path, error.clone());
        self.notify_error(format!(
            "Persistence unavailable: {error}. The proxy runs, but captured traffic will not be stored."
        ));
    }

    pub fn nav(&self) -> NavSection {
        self.nav
    }

    pub fn focus(&self) -> Focus {
        self.focus
    }

    pub fn theme(&self) -> Theme {
        self.theme
    }

    pub fn config(&self) -> &AppConfig {
        &self.config
    }

    pub fn session(&self) -> &Session {
        &self.session
    }

    pub fn traffic(&self) -> &[TrafficEntry] {
        &self.traffic
    }

    pub fn notices(&self) -> &[Toast] {
        &self.notices
    }

    pub fn should_quit(&self) -> bool {
        self.should_quit
    }

    pub fn engine_available(&self) -> bool {
        self.proxy_sender.is_some()
    }

    /// Connects the UI command boundary to the proxy worker. The TUI does not
    /// depend on the proxy crate; the CLI composition root owns that wiring.
    pub fn attach_proxy_commands(&mut self, sender: CommandSender) {
        self.proxy_sender = Some(sender);
    }

    /// Connects the independent Repeater execution service. Without it the
    /// workspace can edit drafts but never pretends to transmit.
    pub fn attach_repeater_commands(&mut self, sender: RepeaterCommandSender) {
        self.repeater_sender = Some(sender);
    }

    pub fn repeater_engine_available(&self) -> bool {
        self.repeater_sender.is_some()
    }

    /// Connects storage commands. The database itself stays in the worker.
    pub fn attach_storage_commands(&mut self, sender: StorageCommandSender) {
        self.storage_sender = Some(sender);
    }

    pub fn storage_status(&self) -> &StorageStatus {
        &self.storage
    }

    pub fn sessions_open(&self) -> bool {
        self.sessions_open
    }

    pub fn sessions(&self) -> &[SessionSummary] {
        &self.sessions
    }

    pub fn sessions_selected(&self) -> usize {
        self.sessions_selected
    }

    pub fn sessions_loading(&self) -> bool {
        self.sessions_loading
    }

    pub fn restored_session_label(&self) -> Option<&str> {
        self.restored_session
            .as_ref()
            .map(|(_, name)| name.as_str())
    }

    pub fn restored_entry_count(&self) -> usize {
        self.traffic
            .iter()
            .filter(|entry| entry.source == TrafficSource::Restored)
            .count()
    }

    pub fn scope_editor(&self) -> Option<&ScopeEditorState> {
        self.scope_editor.as_ref()
    }

    pub fn scope_rules(&self) -> &[ScopeRule] {
        &self.config.proxy.scope.allowlist
    }

    pub fn proxy_address(&self) -> Option<SocketAddr> {
        self.proxy_address
    }

    pub fn proxy_state(&self) -> ProxyState {
        self.proxy_state
    }

    pub fn palette_results(&self) -> Vec<&'static CommandSpec> {
        match &self.palette {
            Some(palette) => filter_commands(&palette.query),
            None => Vec::new(),
        }
    }

    pub fn active_repeater_tab(&self) -> Option<&RepeaterTab> {
        self.repeater.active_tab()
    }

    /// In-flight requests shown on the Proxy screen, newest first.
    pub fn pending_entries(&self) -> Vec<&TrafficEntry> {
        let mut entries: Vec<&TrafficEntry> = self
            .traffic
            .iter()
            .filter(|entry| entry.state.is_pending())
            .collect();
        entries.sort_by_key(|entry| std::cmp::Reverse(entry.id));
        entries
    }

    /// Proxy workspace contents: live captures only (completed HTTP
    /// transactions and CONNECT tunnel metadata plus paused interceptions).
    /// Simulated fixtures are history data and are never presented here.
    pub fn proxy_entries(&self) -> Vec<&TrafficEntry> {
        let mut live: Vec<&TrafficEntry> = self
            .traffic
            .iter()
            .filter(|entry| entry.is_live_capture())
            .collect();
        live.sort_by_key(|entry| std::cmp::Reverse(entry.id));
        live
    }

    pub fn live_capture_count(&self) -> usize {
        self.traffic
            .iter()
            .filter(|entry| entry.is_live_capture())
            .count()
    }

    pub fn has_any_live_capture(&self) -> bool {
        self.live_capture_count() > 0
    }

    pub fn tunnel_count(&self) -> usize {
        self.traffic
            .iter()
            .filter(|entry| entry.is_tunnel())
            .count()
    }

    /// Filtered HTTP history, newest first.
    pub fn history_entries(&self) -> Vec<&TrafficEntry> {
        let mut entries: Vec<&TrafficEntry> = self
            .traffic
            .iter()
            .filter(|entry| self.history_filter.matches(entry))
            .collect();
        entries.sort_by_key(|entry| std::cmp::Reverse(entry.id));
        entries
    }

    pub fn history_hosts(&self) -> Vec<String> {
        let hosts: BTreeSet<String> = self
            .traffic
            .iter()
            .map(|entry| entry.request.host.clone())
            .collect();
        hosts.into_iter().collect()
    }

    pub fn history_selected_id(&self) -> Option<TrafficId> {
        self.history_selected
    }

    pub fn settings_selected(&self) -> SettingId {
        self.settings.selected_id()
    }

    pub fn repeater_is_editing(&self) -> bool {
        self.repeater.editing
    }

    pub fn selected_traffic(&self) -> Option<&TrafficEntry> {
        let id = match self.nav {
            NavSection::Proxy => self.proxy_selected,
            NavSection::History => self.history_selected,
            _ => None,
        }?;
        self.traffic.iter().find(|entry| entry.id == id)
    }

    pub fn current_layout(&self) -> AppLayout {
        compute(self.last_area, &self.layout, self.nav.uses_context())
    }

    pub fn context_visible(&self) -> bool {
        self.nav.uses_context() && self.current_layout().context.is_some()
    }

    pub fn overlay_open(&self) -> bool {
        self.palette.is_some()
            || self.context_menu.is_some()
            || self.help_open
            || self.confirm.is_some()
    }

    pub(crate) fn notify(&mut self, notice: Notice) {
        self.notices.push(Toast {
            notice,
            expires_at: Instant::now() + TOAST_LIFETIME,
        });
        if self.notices.len() > MAX_TOASTS {
            self.notices.remove(0);
        }
    }

    pub(crate) fn notify_info(&mut self, message: impl Into<String>) {
        self.notify(Notice::info(message));
    }

    pub(crate) fn notify_warning(&mut self, message: impl Into<String>) {
        self.notify(Notice::warning(message));
    }

    pub(crate) fn notify_error(&mut self, message: impl Into<String>) {
        self.notify(Notice::error(message));
    }

    pub(crate) fn notify_success(&mut self, message: impl Into<String>) {
        self.notify(Notice::success(message));
    }

    /// Drains pending application events through the same handler used by the
    /// terminal loop. Useful for embedding and integration tests.
    pub fn drain_events(&mut self) -> usize {
        let mut drained = 0;
        while let Some(event) = self.events.poll() {
            self.handle_event(event);
            drained += 1;
        }
        drained
    }

    pub fn handle_event(&mut self, event: AppEvent) {
        match event {
            AppEvent::TrafficCaptured(entry) => {
                let entry = *entry;
                let label = format!(
                    "Captured {} {} from {}",
                    entry.request.method, entry.request.target, entry.request.host
                );
                self.upsert_traffic(entry);
                self.notify_info(label);
            }
            AppEvent::TrafficUpdated(entry) => {
                self.upsert_traffic(*entry);
            }
            AppEvent::InterceptionPaused(entry) => {
                let entry = *entry;
                let id = entry.id;
                let label = format!(
                    "Paused request #{} for review ({} {})",
                    entry.id, entry.request.method, entry.request.target
                );
                self.upsert_traffic(entry);
                self.sync_interception_selection();
                if self.interception.selected.is_none() {
                    self.select_interception(id);
                } else if self.interception.selected == Some(id) {
                    self.load_interception_editor();
                }
                self.notify_warning(label);
            }
            AppEvent::InterceptionQueueChanged { pending, capacity } => {
                self.interception.queue_pending = pending;
                self.interception.queue_capacity = capacity;
                if pending >= capacity && capacity > 0 {
                    self.notify_warning(format!(
                        "Interception queue full ({pending}/{capacity}). New matching requests may be rejected or delayed."
                    ));
                }
            }
            AppEvent::ProxyStateChanged(state) => {
                self.proxy_state = state;
                if matches!(
                    state,
                    ProxyState::Stopped | ProxyState::Starting | ProxyState::Failed
                ) {
                    self.proxy_address = None;
                }
                let message = format!("Proxy state: {}", state.label());
                if state == ProxyState::Failed {
                    self.notify_error(message);
                } else {
                    self.notify_info(message);
                }
            }
            AppEvent::ProxyBound(address) => {
                self.proxy_address = Some(address);
            }
            AppEvent::TlsStateChanged(status) => {
                self.config.proxy.tls_interception_enabled = status.enabled;
                if let Some(error) = &status.error {
                    self.notify_error(format!("TLS interception: {error}"));
                } else if status.enabled {
                    self.notify_warning(
                        "HTTPS TLS interception is ON: authorized CONNECT sessions are decrypted and visible.",
                    );
                }
                self.tls_status = status;
            }
            AppEvent::Repeater(event) => self.handle_repeater_event(event),
            AppEvent::Notice(notice) => self.notify(notice),
            AppEvent::Storage(event) => self.handle_storage_event(event),
            AppEvent::Shutdown => self.should_quit = true,
        }
    }

    fn handle_repeater_event(&mut self, event: RepeaterEvent) {
        match event {
            RepeaterEvent::Phase {
                tab,
                execution,
                phase,
            } => {
                if let Some(tab) = self.repeater.active_tab_by_id(tab) {
                    tab.set_phase(execution, phase);
                }
            }
            RepeaterEvent::Completed {
                tab,
                execution,
                phase,
                result,
                entry,
            } => {
                let mut applied = false;
                if let Some(tab) = self.repeater.active_tab_by_id(tab) {
                    applied = tab.complete(execution, phase.clone(), (*result).clone());
                }
                if applied {
                    match phase {
                        RepeaterExecutionPhase::Completed => {
                            let status = result
                                .response
                                .as_ref()
                                .map(|response| response.status.to_string())
                                .unwrap_or_else(|| "no response".into());
                            self.notify_success(format!(
                                "Repeater {} · {} · {} B · {} ms",
                                status,
                                result.request.host,
                                result.response_bytes,
                                result.timings.total_ms
                            ));
                            if !result.warnings.is_empty() {
                                self.notify_warning(result.warnings.join("; "));
                            }
                        }
                        RepeaterExecutionPhase::Cancelled => {
                            self.notify_info("Repeater execution cancelled.")
                        }
                        RepeaterExecutionPhase::Blocked => self.notify_warning(format!(
                            "Repeater blocked: {}",
                            result.error.as_deref().unwrap_or("blocked by policy")
                        )),
                        _ => self.notify_error(format!(
                            "Repeater execution failed: {}",
                            result.error.as_deref().unwrap_or("unknown error")
                        )),
                    }
                    // Persistence and History see the completed transaction as
                    // REPEATER provenance; it never enters the Proxy workspace.
                    self.upsert_traffic(*entry);
                }
            }
        }
    }

    fn handle_storage_event(&mut self, event: StorageEvent) {
        match event {
            StorageEvent::Status(status) => {
                let previous = self.storage.clone();
                if status.enabled
                    && let Some(path) = &status.database_path
                {
                    self.config.storage.database_path = path.clone();
                }
                self.config.storage.persist_bodies = status.policy.persist_bodies;
                self.config.storage.persist_sensitive_headers =
                    status.policy.persist_sensitive_headers;
                if status.error != previous.error
                    && let Some(error) = &status.error
                {
                    self.notify_error(format!(
                        "Persistence disabled: {error}. The proxy keeps running; captured traffic is no longer stored."
                    ));
                }
                if status.dropped > previous.dropped {
                    self.notify_warning(format!(
                        "{} captures were dropped instead of stored: the database writer is slower than traffic.",
                        status.dropped - previous.dropped
                    ));
                }
                self.storage = status;
            }
            StorageEvent::Sessions(list) => {
                let count = list.len();
                self.sessions = list;
                self.sessions_loading = false;
                self.sessions_selected = self.sessions_selected.min(count.saturating_sub(1));
                if self.sessions_open {
                    self.notify_info(format!("Loaded {count} stored sessions."));
                }
            }
            StorageEvent::SessionLoaded {
                session_id,
                entries,
                truncated,
            } => {
                let name = self
                    .sessions
                    .iter()
                    .find(|session| session.id == session_id)
                    .map(|session| session.name.clone())
                    .unwrap_or_else(|| session_id.0.clone());
                let count = entries.len();
                let last = entries.last().map(|entry| entry.id);
                for entry in entries {
                    self.upsert_traffic(entry);
                }
                if let Some(id) = last {
                    self.history_selected = Some(id);
                }
                self.restored_session = Some((session_id, name.clone()));
                self.sessions_open = false;
                self.nav = NavSection::History;
                self.focus = Focus::Content;
                self.notify_success(format!(
                    "Restored {count} transactions from {name} as read-only history."
                ));
                if truncated {
                    self.notify_warning(
                        "The stored session is larger than the restore limit; older transactions were not loaded.",
                    );
                }
            }
            StorageEvent::Exported {
                session_id,
                path,
                records,
                redacted_headers,
                bodies_omitted,
            } => {
                self.notify_success(format!(
                    "Exported {records} records from {session_id} to {} ({redacted_headers} header values redacted, {bodies_omitted} records without stored bodies).",
                    path.display()
                ));
            }
            StorageEvent::Failed(error) => self.notify_error(format!("Storage: {error}")),
        }
    }

    fn upsert_traffic(&mut self, entry: TrafficEntry) {
        if let Some(existing) = self
            .traffic
            .iter_mut()
            .find(|existing| existing.id == entry.id)
        {
            *existing = entry;
        } else {
            self.traffic.push(entry);
            self.traffic.sort_by_key(|entry| entry.id);
        }
        self.ensure_selections();
        self.sync_interception_selection();
    }

    pub fn tick(&mut self) {
        if self.decoder.poll() {
            if let Some(error) = &self.decoder.error {
                self.notify_error(format!("Decoder {}: {}", error.label(), error.message));
            } else {
                self.notify_success(format!(
                    "Decoder completed: {} bytes → {} bytes",
                    self.decoder.input_bytes.len(),
                    self.decoder.displayed_bytes.len()
                ));
            }
        }
        let now = Instant::now();
        self.notices.retain(|toast| toast.expires_at > now);
        if self
            .last_click
            .as_ref()
            .is_some_and(|(at, _, _)| now.duration_since(*at) > Duration::from_secs(1))
        {
            self.last_click = None;
        }
    }

    pub(crate) fn ensure_selections(&mut self) {
        let proxy_ids: Vec<TrafficId> = self.proxy_entries().iter().map(|entry| entry.id).collect();
        if self
            .proxy_selected
            .is_none_or(|selected| !proxy_ids.contains(&selected))
        {
            self.proxy_selected = self
                .proxy_entries()
                .iter()
                .find(|entry| entry.state.is_awaiting_decision())
                .map(|entry| entry.id)
                .or_else(|| proxy_ids.first().copied());
        }

        let history: Vec<TrafficId> = self
            .traffic
            .iter()
            .filter(|entry| self.history_filter.matches(entry))
            .map(|entry| entry.id)
            .collect();
        if self
            .history_selected
            .is_none_or(|selected| !history.contains(&selected))
        {
            self.history_selected = history.last().copied();
        }
    }

    pub fn navigate(&mut self, section: NavSection) {
        self.nav = section;
        self.focus = Focus::Content;
        self.search.active = false;
        self.settings.edit = None;
        self.repeater.editing = false;
        self.decoder.editing = false;
        self.decoder.history_open = false;
        self.inspector.reset();
    }

    pub(crate) fn selected_id(&self) -> Option<TrafficId> {
        match self.nav {
            NavSection::Proxy => self.proxy_selected,
            NavSection::History => self.history_selected,
            _ => None,
        }
    }

    pub(crate) fn start_search(&mut self) {
        self.nav = NavSection::History;
        self.focus = Focus::Content;
        self.search.active = true;
    }

    pub(crate) fn clear_filters(&mut self) {
        self.history_filter.clear();
        self.search.active = false;
        self.ensure_selections();
    }

    pub(crate) fn cycle_method_filter(&mut self) {
        let mut options: Vec<Option<String>> = vec![None];
        let methods: BTreeSet<String> = self
            .traffic
            .iter()
            .map(|entry| entry.request.method.clone())
            .collect();
        options.extend(methods.into_iter().map(Some));

        let current = options
            .iter()
            .position(|option| *option == self.history_filter.method)
            .unwrap_or(0);
        self.history_filter.method = options[(current + 1) % options.len()].clone();
        self.ensure_selections();
    }

    pub(crate) fn cycle_status_filter(&mut self) {
        self.history_filter.status = self.history_filter.status.next();
        self.ensure_selections();
    }

    pub(crate) fn cycle_host_filter(&mut self) {
        let mut options: Vec<Option<String>> = vec![None];
        options.extend(self.history_hosts().into_iter().map(Some));

        let current = options
            .iter()
            .position(|option| *option == self.history_filter.host)
            .unwrap_or(0);
        self.history_filter.host = options[(current + 1) % options.len()].clone();
        self.ensure_selections();
    }

    pub(crate) fn move_selection(&mut self, delta: i32) {
        match self.nav {
            NavSection::Proxy => {
                let ids: Vec<TrafficId> =
                    self.proxy_entries().iter().map(|entry| entry.id).collect();
                self.proxy_selected = step_selection(&ids, self.proxy_selected, delta);
                self.inspector.reset();
            }
            NavSection::History => {
                let ids: Vec<TrafficId> = self
                    .history_entries()
                    .iter()
                    .map(|entry| entry.id)
                    .collect();
                self.history_selected = step_selection(&ids, self.history_selected, delta);
                self.inspector.reset();
            }
            NavSection::Settings => {
                if delta < 0 {
                    for _ in 0..delta.unsigned_abs() {
                        self.settings.select_previous();
                    }
                } else {
                    for _ in 0..delta {
                        self.settings.select_next();
                    }
                }
            }
            _ => {}
        }
    }

    pub(crate) fn select_edge(&mut self, last: bool) {
        match self.nav {
            NavSection::Proxy => {
                let ids: Vec<TrafficId> =
                    self.proxy_entries().iter().map(|entry| entry.id).collect();
                self.proxy_selected = if last { ids.last() } else { ids.first() }.copied();
            }
            NavSection::History => {
                let ids: Vec<TrafficId> = self
                    .history_entries()
                    .iter()
                    .map(|entry| entry.id)
                    .collect();
                self.history_selected = if last { ids.last() } else { ids.first() }.copied();
            }
            NavSection::Settings => {
                self.settings.selected = if last { SettingId::ALL.len() - 1 } else { 0 };
            }
            _ => {}
        }
    }

    pub(crate) fn inspect_selected(&mut self) {
        let blocked = self
            .selected_traffic()
            .is_some_and(lifecycle::is_scope_or_policy_block);
        if self.selected_traffic().is_some() {
            self.layout.context_open = true;
            // A policy block has no upstream response to inspect; open the
            // response explanation so the operator immediately sees the reason
            // and the route to scope settings.
            self.inspector.side = if blocked {
                MessageSide::Response
            } else {
                MessageSide::Request
            };
            self.inspector.scroll = 0;
            self.focus = Focus::Context;
        } else {
            self.notify_warning("No request is selected.");
        }
    }

    pub(crate) fn toggle_inspector(&mut self) {
        self.layout.context_open = !self.layout.context_open;
        if !self.context_visible() && self.focus == Focus::Context {
            self.focus = Focus::Content;
        }
        if self.layout.context_open && self.nav.uses_context() && !self.context_visible() {
            self.notify_warning(
                "Inspector hidden at this width. Widen the terminal or resize panes to show it.",
            );
        }
    }

    pub(crate) fn toggle_tls_interception(&mut self) {
        let enabled = !self.tls_status.enabled;
        if enabled {
            self.notify_warning(
                "Enabling HTTPS TLS interception decrypts authorized CONNECT traffic. Clients must explicitly trust the exported local CA. The private key is never exported.",
            );
        }
        self.dispatch_command(AppCommand::SetTlsInterception { enabled });
    }

    pub(crate) fn toggle_interception(&mut self) {
        self.dispatch_command(AppCommand::SetInterception {
            enabled: !self.config.proxy.interception_enabled,
        });
    }

    /// Routes a command through the application boundary. Proxy and storage
    /// workers will subscribe to this command channel in later milestones; in
    /// this foundation the locally owned parts are applied here.
    pub(crate) fn dispatch_command(&mut self, command: AppCommand) {
        match command {
            AppCommand::StartProxy(_) | AppCommand::StopProxy => {
                let Some(sender) = &self.proxy_sender else {
                    self.notify_warning(
                        "Proxy worker is not attached. Run the packaged RAWFRAME binary to start the engine.",
                    );
                    return;
                };
                let start = matches!(&command, AppCommand::StartProxy(_));
                match sender.try_send(command) {
                    Ok(()) => {
                        self.proxy_state = if start {
                            ProxyState::Starting
                        } else {
                            ProxyState::Stopping
                        };
                        if start {
                            self.proxy_address = None;
                            self.notify_info("Starting proxy engine…");
                        } else {
                            self.notify_info("Stopping proxy engine…");
                        }
                    }
                    Err(_) => self.notify_error("Proxy command queue is unavailable."),
                }
            }
            AppCommand::SetInterception { enabled } => {
                self.set_interception(enabled);
                if let Some(sender) = &self.proxy_sender {
                    let _ = sender.try_send(AppCommand::SetInterception { enabled });
                }
            }
            AppCommand::SetTlsInterception { enabled } => {
                if let Some(sender) = &self.proxy_sender {
                    match sender.try_send(AppCommand::SetTlsInterception { enabled }) {
                        Ok(()) => {
                            self.notify_info(if enabled {
                                "Enabling HTTPS TLS interception…"
                            } else {
                                "Disabling HTTPS TLS interception…"
                            });
                        }
                        Err(_) => self.notify_error("Proxy command queue is unavailable."),
                    }
                } else {
                    self.notify_warning("Proxy worker is not attached.");
                }
            }
            AppCommand::UpdateScope(scope) => {
                let mut delivered = false;
                if let Some(sender) = &self.proxy_sender {
                    delivered |= sender
                        .try_send(AppCommand::UpdateScope(scope.clone()))
                        .is_ok();
                }
                // Repeater keeps its own live scope snapshot so an edit is
                // enforced even when the proxy listener is stopped.
                if let Some(sender) = &self.repeater_sender {
                    delivered |= sender.try_send(RepeaterCommand::UpdateScope(scope)).is_ok();
                }
                if delivered {
                    self.notify_success(
                        "Scope updated: new proxy and Repeater requests use the edited allowlist immediately.",
                    );
                } else {
                    self.notify_warning(
                        "Scope updated for this session, but no running engine accepted it.",
                    );
                }
            }
            AppCommand::ForwardRequest(id) => {
                if self.is_live_pending_interception(id) {
                    if let Some(sender) = &self.proxy_sender {
                        if sender.try_send(AppCommand::ForwardRequest(id)).is_ok() {
                            self.notify_info(format!("Forward decision sent for request #{id}."));
                        } else {
                            self.notify_error("Proxy command queue is unavailable.");
                        }
                    } else {
                        self.notify_warning("Proxy worker is not attached.");
                    }
                } else {
                    self.forward_request(id);
                }
            }
            AppCommand::DropRequest(id) => {
                if self.is_live_pending_interception(id) {
                    if let Some(sender) = &self.proxy_sender {
                        if sender.try_send(AppCommand::DropRequest(id)).is_ok() {
                            self.notify_info(format!("Drop decision sent for request #{id}."));
                        } else {
                            self.notify_error("Proxy command queue is unavailable.");
                        }
                    } else {
                        self.notify_warning("Proxy worker is not attached.");
                    }
                } else {
                    self.drop_request(id);
                }
            }
            AppCommand::ForwardModified { id, request } => {
                if self.is_live_pending_interception(id) {
                    if let Some(sender) = &self.proxy_sender {
                        if sender
                            .try_send(AppCommand::ForwardModified { id, request })
                            .is_ok()
                        {
                            self.notify_info(format!(
                                "Forward-modified decision sent for request #{id}."
                            ));
                        } else {
                            self.notify_error("Proxy command queue is unavailable.");
                        }
                    } else {
                        self.notify_warning("Proxy worker is not attached.");
                    }
                } else {
                    self.notify_warning(format!(
                        "Request #{id} is not a live paused interception."
                    ));
                }
            }
        }
    }

    fn is_live_pending_interception(&self, id: rawframe_core::models::traffic::TrafficId) -> bool {
        self.traffic.iter().any(|entry| {
            entry.id == id
                && entry.is_live_capture()
                && matches!(
                    entry.state,
                    rawframe_core::models::traffic::TrafficState::Paused
                        | rawframe_core::models::traffic::TrafficState::Modified
                )
        })
    }

    pub(crate) fn start_proxy(&mut self) {
        if !self.engine_available() {
            self.notify_warning(
                "Proxy worker is not attached. Run the packaged RAWFRAME binary to start the engine.",
            );
            return;
        }
        if self.proxy_state.is_active() {
            self.notify_info("The proxy is already active.");
            return;
        }
        let config = self.config.clone();
        self.dispatch_command(AppCommand::StartProxy(Box::new(config)));
    }

    pub(crate) fn stop_proxy(&mut self) {
        if !self.proxy_state.is_active() {
            self.notify_info("The proxy is already stopped.");
            return;
        }
        self.dispatch_command(AppCommand::StopProxy);
    }

    pub(crate) fn toggle_proxy(&mut self) {
        if self.proxy_state.is_active() {
            self.stop_proxy();
        } else {
            self.start_proxy();
        }
    }

    fn set_interception(&mut self, enabled: bool) {
        self.config.proxy.interception_enabled = enabled;
        if enabled {
            self.notify_warning(
                "Interception enabled. Matching HTTP requests will pause before reaching the upstream server.",
            );
        } else {
            self.notify_info("Interception disabled.");
        }
    }

    pub(crate) fn toggle_redaction(&mut self) {
        self.config.appearance.redact_sensitive_headers =
            !self.config.appearance.redact_sensitive_headers;
        let message = if self.config.appearance.redact_sensitive_headers {
            "Sensitive-header redaction enabled."
        } else {
            "Sensitive-header redaction disabled. Authorization, Cookie and Set-Cookie values are now visible."
        };
        self.notify_warning(message);
    }

    pub(crate) fn cycle_accent(&mut self) {
        self.config.appearance.accent = self.config.appearance.accent.next();
        self.theme = Theme::from_preset(self.config.appearance.accent);
        self.notify_info(format!("Accent: {}", self.config.appearance.accent.label()));
    }

    pub(crate) fn toggle_mouse(&mut self) {
        self.config.appearance.mouse_enabled = !self.config.appearance.mouse_enabled;
        let message = if self.config.appearance.mouse_enabled {
            "Mouse support enabled."
        } else {
            "Mouse support disabled. Use the keyboard."
        };
        self.notify_info(message);
    }

    pub(crate) fn open_palette(&mut self) {
        self.palette = Some(PaletteState::new());
        self.context_menu = None;
    }

    pub(crate) fn close_palette(&mut self) {
        self.palette = None;
    }

    pub(crate) fn execute_command(&mut self, command: CommandId) {
        match command {
            CommandId::GoProxy => self.navigate(NavSection::Proxy),
            CommandId::GoHistory => self.navigate(NavSection::History),
            CommandId::GoRepeater => self.navigate(NavSection::Repeater),
            CommandId::GoIntruder => self.navigate(NavSection::Intruder),
            CommandId::GoDecoder => self.navigate(NavSection::Decoder),
            CommandId::GoSettings => self.navigate(NavSection::Settings),
            CommandId::DecoderExecute => {
                self.navigate(NavSection::Decoder);
                self.execute_decoder();
            }
            CommandId::DecoderAddStep => {
                self.navigate(NavSection::Decoder);
                self.add_decoder_step();
            }
            CommandId::DecoderCopy => {
                self.navigate(NavSection::Decoder);
                self.copy_decoder_output();
            }
            CommandId::DecoderHistory => {
                self.navigate(NavSection::Decoder);
                self.toggle_decoder_history();
            }
            CommandId::DecoderSendToRepeater => {
                self.navigate(NavSection::Decoder);
                self.send_decoder_output_to_repeater();
            }
            CommandId::ToggleProxy => self.toggle_proxy(),
            CommandId::ToggleInterception => self.toggle_interception(),
            CommandId::ToggleRedaction => self.toggle_redaction(),
            CommandId::ToggleInspector => self.toggle_inspector(),
            CommandId::CycleAccent => self.cycle_accent(),
            CommandId::ForwardRequest => self.forward_selected_request(),
            CommandId::DropRequest => self.drop_selected_request(),
            CommandId::ReplayRequest => {
                if let Some(id) = self.selected_id() {
                    self.open_in_repeater(id, false);
                } else {
                    self.notify_warning("Select a request in Proxy or HTTP History first.");
                }
            }
            CommandId::EditRequest => {
                if let Some(id) = self.selected_id() {
                    self.open_in_repeater(id, true);
                } else {
                    self.notify_warning("Select a request in Proxy or HTTP History first.");
                }
            }
            CommandId::NewRepeaterTab => {
                self.navigate(NavSection::Repeater);
                self.repeater.new_blank();
                self.repeater.editing = true;
                self.notify_info(
                    "New Repeater tab. Enter a URL, then send to a scoped destination.",
                );
            }
            CommandId::CloseRepeaterTab => self.request_close_repeater_tab(),
            CommandId::DuplicateRepeaterTab => self.duplicate_repeater_tab(),
            CommandId::SendRepeaterRequest => self.send_repeater_request(),
            CommandId::CancelRepeaterRequest => self.cancel_repeater_request(),
            CommandId::ResetRepeaterEdits => self.reset_repeater_edits(),
            CommandId::ClearRepeaterResponse => self.clear_repeater_response(),
            CommandId::ToggleRepeaterRedirects => self.toggle_repeater_redirects(),
            CommandId::SearchHistory => self.start_search(),
            CommandId::ClearHistoryFilters => self.clear_filters(),
            CommandId::ToggleMouse => self.toggle_mouse(),
            CommandId::ShowHelp => self.help_open = true,
            CommandId::OpenStoredSessions => self.open_sessions(),
            CommandId::ExportStoredSession => self.export_current_session(),
            CommandId::Quit => self.request_quit(),
        }
        self.close_palette();
    }

    pub(crate) fn dispatch_action(&mut self, action: ActionId) {
        match action {
            ActionId::ForwardRequest => {
                if self.nav == NavSection::Proxy && !self.pending_interceptions().is_empty() {
                    self.forward_interception_unchanged();
                } else {
                    self.forward_selected_request();
                }
            }
            ActionId::DropRequest => {
                if self.nav == NavSection::Proxy && !self.pending_interceptions().is_empty() {
                    self.drop_interception();
                } else {
                    self.drop_selected_request();
                }
            }
            ActionId::ForwardModified => self.forward_interception_modified(),
            ActionId::InspectRequest => {
                if self.nav == NavSection::Proxy && self.interception_selected().is_some() {
                    self.focus = Focus::Content;
                    self.interception.editing = false;
                } else {
                    self.inspect_selected();
                }
            }
            ActionId::ReplayRequest => {
                if let Some(id) = self.selected_id() {
                    self.open_in_repeater(id, false);
                }
            }
            ActionId::EditRequest => {
                if self.nav == NavSection::Proxy && self.interception_selected().is_some() {
                    self.interception.editing = true;
                    self.focus = Focus::Content;
                    self.load_interception_editor();
                } else if let Some(id) = self.selected_id() {
                    self.open_in_repeater(id, true);
                }
            }
            ActionId::ToggleProxy => self.toggle_proxy(),
            ActionId::ToggleInterception => self.toggle_interception(),
            ActionId::ToggleInspector => self.toggle_inspector(),
            ActionId::ToggleRedaction => self.toggle_redaction(),
            ActionId::NewRepeaterTab => {
                self.navigate(NavSection::Repeater);
                self.repeater.new_blank();
                self.repeater.editing = true;
            }
            ActionId::CloseRepeaterTab => self.request_close_repeater_tab(),
            ActionId::DuplicateRepeaterTab => self.duplicate_repeater_tab(),
            ActionId::SendRepeater => self.send_repeater_request(),
            ActionId::CancelRepeater => self.cancel_repeater_request(),
            ActionId::ResetRepeater => self.reset_repeater_edits(),
            ActionId::ClearRepeaterResponse => self.clear_repeater_response(),
            ActionId::ToggleRepeaterRedirects => self.toggle_repeater_redirects(),
            ActionId::ClearFilters => self.clear_filters(),
            ActionId::Search => self.start_search(),
            ActionId::CycleMethod => {
                self.navigate(NavSection::History);
                self.cycle_method_filter();
            }
            ActionId::CycleStatus => {
                self.navigate(NavSection::History);
                self.cycle_status_filter();
            }
            ActionId::CycleHost => {
                self.navigate(NavSection::History);
                self.cycle_host_filter();
            }
            ActionId::DecoderExecute => self.execute_decoder(),
            ActionId::DecoderAddStep => self.add_decoder_step(),
            ActionId::DecoderRemoveStep => self.remove_decoder_step(),
            ActionId::DecoderMoveStepUp => self.move_decoder_step(-1),
            ActionId::DecoderMoveStepDown => self.move_decoder_step(1),
            ActionId::DecoderSwap => self.swap_decoder_input_output(),
            ActionId::DecoderClear => self.clear_decoder(),
            ActionId::DecoderCopy => self.copy_decoder_output(),
            ActionId::DecoderSendToRepeater => self.send_decoder_output_to_repeater(),
            ActionId::DecoderTransformPrev => self.decoder.select_transform(-1),
            ActionId::DecoderTransformNext => self.decoder.select_transform(1),
            ActionId::DecoderToggleDirection => self.toggle_decoder_direction(),
            ActionId::DecoderHistory => self.toggle_decoder_history(),
            ActionId::DecoderPreview => self.preview_decoder_step(),
            ActionId::SendRepeaterRequestToDecoder => self.send_repeater_request_body_to_decoder(),
            ActionId::SendRepeaterResponseToDecoder => {
                self.send_repeater_response_body_to_decoder()
            }
        }
    }

    pub(crate) fn forward_selected_request(&mut self) {
        let Some(id) = self.selected_id() else {
            self.notify_warning("Select a request in Proxy or HTTP History first.");
            return;
        };
        self.dispatch_command(AppCommand::ForwardRequest(id));
    }

    fn forward_request(&mut self, id: TrafficId) {
        let outcome = {
            let Some(entry) = self.traffic.iter_mut().find(|entry| entry.id == id) else {
                return;
            };
            if !entry.source.is_simulated() {
                Err(
                    "This live request is not awaiting an interception decision, so no forward command was sent."
                        .to_string(),
                )
            } else {
                match entry.state {
                    TrafficState::Captured | TrafficState::Paused | TrafficState::Modified => {
                        if entry.forward().is_ok() {
                            Ok(format!(
                                "Simulated request #{} marked forwarded. No network traffic was sent.",
                                id
                            ))
                        } else {
                            Err(format!("Request #{} cannot be forwarded.", id))
                        }
                    }
                    TrafficState::Forwarded => {
                        Err(format!("Request #{} is already awaiting a response.", id))
                    }
                    _ => Err(format!("Request #{} can no longer be forwarded.", id)),
                }
            }
        };

        match outcome {
            Ok(message) => self.notify_success(message),
            Err(message) => self.notify_warning(message),
        }
        self.ensure_selections();
    }

    pub(crate) fn drop_selected_request(&mut self) {
        let Some(id) = self.selected_id() else {
            self.notify_warning("Select a request in Proxy or HTTP History first.");
            return;
        };
        self.dispatch_command(AppCommand::DropRequest(id));
    }

    fn drop_request(&mut self, id: TrafficId) {
        let outcome = {
            let Some(entry) = self.traffic.iter_mut().find(|entry| entry.id == id) else {
                return;
            };
            if !entry.source.is_simulated() {
                Err("This live request is not awaiting an interception decision, so no drop command was sent."
                    .to_string())
            } else if entry.state.is_awaiting_decision() {
                if entry.drop_request().is_ok() {
                    Ok(format!(
                        "Simulated request #{} dropped locally. Nothing was transmitted.",
                        id
                    ))
                } else {
                    Err(format!("Request #{} cannot be dropped.", id))
                }
            } else {
                Err(format!("Request #{} is not awaiting a decision.", id))
            }
        };

        match outcome {
            Ok(message) => self.notify_success(message),
            Err(message) => self.notify_warning(message),
        }
        self.ensure_selections();
    }

    pub(crate) fn open_in_repeater(&mut self, id: TrafficId, edit: bool) {
        let Some(entry) = self.traffic.iter().find(|entry| entry.id == id).cloned() else {
            self.notify_warning("That request is no longer available.");
            return;
        };
        let origin = if entry.source.is_simulated() {
            RepeaterOrigin::Simulated(entry.id)
        } else {
            RepeaterOrigin::Captured(entry.id)
        };
        self.repeater.add_request(
            entry.request.clone(),
            origin,
            self.config.appearance.redact_sensitive_headers,
        );
        self.nav = NavSection::Repeater;
        self.focus = Focus::Content;
        self.repeater.editing = edit;
        if entry.source.is_simulated() {
            self.notify_info(format!(
                "Opened simulated request #{} in Repeater. Nothing will be transmitted.",
                entry.id
            ));
        } else {
            self.notify_info(format!(
                "Opened captured request #{} in Repeater.",
                entry.id
            ));
        }
    }

    pub(crate) fn send_repeater_request(&mut self) {
        if self.repeater_sender.is_none() {
            self.notify_warning(
                "Repeater engine is not attached. Run the packaged RAWFRAME binary to transmit.",
            );
            return;
        }
        let Some(tab) = self.repeater.active_tab() else {
            self.notify_warning("There is no Repeater tab to send.");
            return;
        };
        if tab.is_busy() {
            self.notify_warning(
                "This tab already has an execution in flight. Cancel it before sending again.",
            );
            return;
        }
        if let Some(error) = &tab.parse_error {
            self.notify_error(format!("Cannot transmit an invalid request: {error}"));
            self.repeater.editing = true;
            return;
        }
        let request = tab.execution_request();
        if let Err(error) = validate_request(&request, self.config.proxy.max_body_bytes) {
            self.notify_error(format!("Request validation failed: {error}"));
            self.repeater.editing = true;
            return;
        }
        let tab_id = tab.document.id;
        let follow_redirects = tab.follow_redirects;
        let origin = match tab.origin {
            RepeaterOrigin::Captured(id) | RepeaterOrigin::Simulated(id) => Some(id),
            RepeaterOrigin::Blank => None,
        };
        let origin_request = tab.original_request.clone().map(Box::new);
        let execution = self.repeater.next_execution_id();
        let Some(tab) = self.repeater.active_tab_mut() else {
            return;
        };
        tab.active_execution = Some(execution);
        tab.execution = RepeaterExecutionPhase::Validating;
        let Some(sender) = &self.repeater_sender else {
            if let Some(tab) = self.repeater.active_tab_mut() {
                tab.active_execution = None;
                tab.execution = RepeaterExecutionPhase::Failed;
            }
            self.notify_error("Repeater engine is unavailable; nothing was sent.");
            return;
        };
        match sender.try_send(RepeaterCommand::Execute {
            tab: tab_id,
            execution,
            request,
            follow_redirects,
            origin,
            origin_request,
        }) {
            Ok(()) => self.notify_info(format!(
                "Repeater execution started{}",
                if follow_redirects {
                    " (safe redirects on)"
                } else {
                    ""
                }
            )),
            Err(_) => {
                if let Some(tab) = self.repeater.active_tab_by_id(tab_id) {
                    tab.active_execution = None;
                    tab.execution = RepeaterExecutionPhase::Failed;
                }
                self.notify_error("Repeater command queue is unavailable.");
            }
        }
    }

    pub(crate) fn cancel_repeater_request(&mut self) {
        let Some(tab) = self.repeater.active_tab() else {
            return;
        };
        let Some(execution) = tab.active_execution else {
            self.notify_info("No Repeater execution is in flight.");
            return;
        };
        if let Some(sender) = &self.repeater_sender {
            if sender
                .try_send(RepeaterCommand::Cancel { execution })
                .is_ok()
            {
                self.notify_info("Cancelling Repeater execution…");
            } else {
                self.notify_error("Repeater command queue is unavailable.");
            }
        }
    }

    pub(crate) fn duplicate_repeater_tab(&mut self) {
        if self.repeater.duplicate_active().is_some() {
            self.notify_info("Repeater tab duplicated with an independent response state.");
        }
    }

    pub fn decoder_state(&self) -> &DecoderState {
        &self.decoder
    }

    pub(crate) fn execute_decoder(&mut self) {
        match self.decoder.execute() {
            Ok(()) => self.notify_info(format!(
                "Decoder running {} step(s)…",
                self.decoder.pipeline.len()
            )),
            Err(error) => self.notify_error(error),
        }
    }

    pub(crate) fn add_decoder_step(&mut self) {
        match self.decoder.add_step() {
            Ok(()) => self.notify_info(format!(
                "Added {} to the pipeline.",
                self.decoder.selected_transform().label()
            )),
            Err(error) => self.notify_warning(error),
        }
    }

    pub(crate) fn remove_decoder_step(&mut self) {
        if self.decoder.pipeline.is_empty() {
            self.notify_warning("The Decoder pipeline is empty.");
            return;
        }
        self.decoder.remove_step();
    }

    pub(crate) fn move_decoder_step(&mut self, delta: i32) {
        self.decoder.move_step(delta);
    }

    pub(crate) fn toggle_decoder_direction(&mut self) {
        self.decoder.toggle_direction();
        self.notify_info(format!(
            "Transform: {}",
            self.decoder.selected_transform().label()
        ));
    }

    pub(crate) fn clear_decoder(&mut self) {
        self.decoder.clear_input_output();
        self.notify_info("Decoder input and output cleared; pipeline retained.");
    }

    pub(crate) fn swap_decoder_input_output(&mut self) {
        if self.decoder.output.is_none() {
            self.notify_warning("Run a transformation before swapping input and output.");
            return;
        }
        self.decoder.swap_input_output();
        self.notify_info("Swapped Decoder input and output.");
    }

    pub(crate) fn copy_decoder_output(&mut self) {
        if !self.decoder.copy_displayed() {
            self.notify_warning("There is no Decoder output to copy.");
            return;
        }
        self.notify_success("Decoder output copied via the terminal clipboard (OSC 52).");
    }

    pub(crate) fn preview_decoder_step(&mut self) {
        if self.decoder.steps.is_empty() {
            self.notify_warning("Run the pipeline before inspecting intermediate results.");
            return;
        }
        self.decoder.preview_selected_step();
    }

    pub(crate) fn show_decoder_final_output(&mut self) {
        self.decoder.show_final_output();
    }

    pub(crate) fn toggle_decoder_history(&mut self) {
        self.decoder.history_open = !self.decoder.history_open;
        self.decoder.history_scroll = 0;
    }

    pub(crate) fn send_repeater_request_body_to_decoder(&mut self) {
        let Some(tab) = self.repeater.active_tab() else {
            self.notify_warning("Open a Repeater tab first.");
            return;
        };
        let body = tab.execution_request().body;
        let label = format!("REPEATER REQUEST · {}", tab.title());
        self.decoder.load_input(body, label);
        self.navigate(NavSection::Decoder);
        self.focus = Focus::Content;
        self.notify_info("Loaded Repeater request body into Decoder.");
    }

    pub(crate) fn send_repeater_response_body_to_decoder(&mut self) {
        let Some(tab) = self.repeater.active_tab() else {
            self.notify_warning("Open a Repeater tab first.");
            return;
        };
        let Some(body) = tab
            .response
            .as_ref()
            .and_then(|result| result.response.as_ref())
            .map(|response| response.body.clone())
        else {
            self.notify_warning("The active Repeater tab has no response body.");
            return;
        };
        let label = format!("REPEATER RESPONSE · {}", tab.title());
        self.decoder.load_input(body, label);
        self.navigate(NavSection::Decoder);
        self.focus = Focus::Content;
        self.notify_info("Loaded Repeater response body into Decoder.");
    }

    pub(crate) fn send_decoder_output_to_repeater(&mut self) {
        if self.decoder.output.is_none() && self.decoder.view_step.is_none() {
            self.notify_warning("Run a transformation before sending output to Repeater.");
            return;
        }
        let Some(tab) = self.repeater.active_tab_mut() else {
            self.notify_warning("Open a Repeater tab first.");
            return;
        };
        let bytes = self.decoder.displayed_bytes.clone();
        tab.replace_body(bytes);
        let len = tab.source_body.len();
        self.navigate(NavSection::Repeater);
        self.focus = Focus::Content;
        self.notify_success(format!(
            "Inserted {len} transformed bytes into the Repeater request body; the original capture is unchanged."
        ));
    }

    pub fn take_clipboard_request(&mut self) -> Option<String> {
        self.decoder.take_clipboard_request()
    }

    pub(crate) fn reset_repeater_edits(&mut self) {
        let Some(tab) = self.repeater.active_tab_mut() else {
            return;
        };
        if tab.original_request.is_none() {
            self.notify_info("This authored tab has no captured original to reset to.");
            return;
        }
        if tab.active_execution.is_some() {
            self.notify_warning("Cancel the in-flight execution before resetting edits.");
            return;
        }
        tab.reset_edits();
        self.notify_info("Repeater edits reset to the original captured request.");
    }

    pub(crate) fn clear_repeater_response(&mut self) {
        let Some(tab) = self.repeater.active_tab_mut() else {
            return;
        };
        if tab.response.is_none() {
            self.notify_info("There is no Repeater response to clear.");
            return;
        }
        tab.clear_response();
        self.repeater.response_scroll = 0;
        self.notify_info("Repeater response cleared; request draft is unchanged.");
    }

    pub(crate) fn toggle_repeater_redirects(&mut self) {
        let Some(tab) = self.repeater.active_tab_mut() else {
            return;
        };
        tab.follow_redirects = !tab.follow_redirects;
        let enabled = tab.follow_redirects;
        if enabled {
            self.notify_warning(
                "Redirects ON: up to 5 hops, each revalidated against scope; credentials are stripped cross-origin.",
            );
        } else {
            self.notify_info(
                "Redirects OFF: a 3xx response is shown and never followed automatically.",
            );
        }
    }

    pub(crate) fn request_close_repeater_tab(&mut self) {
        let Some(tab) = self.repeater.active_tab() else {
            return;
        };
        let dirty = tab.dirty;
        let active = tab.active_execution;
        if let Some(execution) = active {
            if let Some(sender) = &self.repeater_sender {
                let _ = sender.try_send(RepeaterCommand::Cancel { execution });
            }
            self.repeater.close_active();
            self.notify_info("Cancelled the in-flight execution and closed the Repeater tab.");
            return;
        }
        if dirty {
            self.confirm = Some(ConfirmState {
                title: "Close edited tab?".into(),
                body: "This Repeater document has unsaved edits. Closing it discards them.".into(),
                confirm_label: "Close tab",
                action: ConfirmAction::CloseRepeaterTab(self.repeater.active),
            });
        } else {
            self.repeater.close_active();
            self.notify_info("Repeater tab closed.");
        }
    }

    pub(crate) fn request_quit(&mut self) {
        let live_paused = self
            .traffic
            .iter()
            .any(|entry| entry.is_paused() && !entry.source.is_simulated());
        let repeater_busy = self
            .repeater
            .tabs
            .iter()
            .any(|tab| tab.active_execution.is_some());
        if self.repeater.has_unsaved_changes() || live_paused || repeater_busy {
            let reason = if repeater_busy {
                "A Repeater execution is in flight and will be cancelled."
            } else if self.repeater.has_unsaved_changes() {
                "Repeater documents with unsaved edits will be lost."
            } else {
                "Requests are paused and would be abandoned."
            };
            self.confirm = Some(ConfirmState {
                title: "Leave RAWFRAME?".into(),
                body: reason.into(),
                confirm_label: "Quit",
                action: ConfirmAction::Quit,
            });
        } else {
            self.should_quit = true;
        }
    }

    pub(crate) fn confirm_yes(&mut self) {
        let Some(confirm) = self.confirm.take() else {
            return;
        };
        match confirm.action {
            ConfirmAction::Quit => self.should_quit = true,
            ConfirmAction::CloseRepeaterTab(index) => {
                self.repeater.select(index);
                self.repeater.close_active();
                self.notify_info("Repeater tab closed.");
            }
        }
    }

    pub(crate) fn confirm_no(&mut self) {
        self.confirm = None;
        self.focus = Focus::Content;
    }

    pub(crate) fn activate_setting(&mut self) {
        let id = self.settings.selected_id();
        if id == SettingId::Scope {
            self.open_scope_editor();
            return;
        }
        if id.is_editable() {
            let buffer = self.setting_edit_value(id);
            self.settings.edit = Some(SettingEdit { id, buffer });
        } else if id.is_toggle() {
            self.toggle_setting(id);
        } else {
            self.setting_read_only_notice(id);
        }
    }

    fn setting_edit_value(&self, id: SettingId) -> String {
        match id {
            SettingId::BindAddress => self.config.proxy.bind_address.to_string(),
            SettingId::Port => self.config.proxy.port.to_string(),
            SettingId::MaxBody => (self.config.proxy.max_body_bytes / (1024 * 1024)).to_string(),
            SettingId::MaxResponse => {
                (self.config.proxy.max_response_bytes / (1024 * 1024)).to_string()
            }
            SettingId::MaxConnections => self.config.proxy.max_connections.to_string(),
            SettingId::ConnectTimeout => self.config.proxy.connect_timeout_secs.to_string(),
            SettingId::UpstreamTimeout => self.config.proxy.upstream_timeout_secs.to_string(),
            SettingId::IdleTimeout => self.config.proxy.idle_timeout_secs.to_string(),
            SettingId::InterceptTimeout => self.config.proxy.intercept_timeout_secs.to_string(),
            _ => String::new(),
        }
    }

    pub(crate) fn commit_setting_edit(&mut self) {
        let Some(edit) = self.settings.edit.take() else {
            return;
        };
        match self.apply_setting_value(edit.id, &edit.buffer) {
            Ok(()) => {
                self.notify_success(format!("{} updated for this session.", edit.id.label()));
            }
            Err(message) => {
                self.notify_error(message);
                self.settings.edit = Some(edit);
            }
        }
    }

    fn apply_setting_value(&mut self, id: SettingId, value: &str) -> Result<(), String> {
        match id {
            SettingId::BindAddress => {
                let address: IpAddr = value
                    .trim()
                    .parse()
                    .map_err(|_| format!("'{value}' is not a valid IP address."))?;
                if !address.is_loopback() {
                    return Err(
                        "Settings only permit loopback binding. Restart with --bind ADDR --allow-remote-bind to authorize a remote listener."
                            .into(),
                    );
                }
                self.config.proxy.bind_address = address;
            }
            SettingId::Port => {
                let port: u16 = value
                    .trim()
                    .parse()
                    .map_err(|_| format!("'{value}' is not a valid port."))?;
                if port == 0 {
                    return Err("Port must be between 1 and 65535.".into());
                }
                self.config.proxy.port = port;
            }
            SettingId::MaxBody | SettingId::MaxResponse => {
                let mib: usize = value
                    .trim()
                    .parse()
                    .map_err(|_| format!("'{value}' is not a whole number of MiB."))?;
                if !(1..=64).contains(&mib) {
                    return Err("Body limits must be between 1 and 64 MiB.".into());
                }
                if id == SettingId::MaxBody {
                    self.config.proxy.max_body_bytes = mib * 1024 * 1024;
                } else {
                    self.config.proxy.max_response_bytes = mib * 1024 * 1024;
                }
            }
            SettingId::MaxConnections => {
                let limit: usize = value
                    .trim()
                    .parse()
                    .map_err(|_| format!("'{value}' is not a whole number."))?;
                if !(1..=4096).contains(&limit) {
                    return Err("Concurrent connections must be between 1 and 4096.".into());
                }
                self.config.proxy.max_connections = limit;
            }
            SettingId::ConnectTimeout
            | SettingId::UpstreamTimeout
            | SettingId::IdleTimeout
            | SettingId::InterceptTimeout => {
                let seconds: u64 = value
                    .trim()
                    .parse()
                    .map_err(|_| format!("'{value}' is not a whole number of seconds."))?;
                if !(1..=86_400).contains(&seconds) {
                    return Err("Timeouts must be between 1 and 86400 seconds.".into());
                }
                match id {
                    SettingId::ConnectTimeout => self.config.proxy.connect_timeout_secs = seconds,
                    SettingId::UpstreamTimeout => self.config.proxy.upstream_timeout_secs = seconds,
                    SettingId::IdleTimeout => self.config.proxy.idle_timeout_secs = seconds,
                    SettingId::InterceptTimeout => {
                        self.config.proxy.intercept_timeout_secs = seconds
                    }
                    _ => {}
                }
            }
            _ => return Err("This setting is not editable.".into()),
        }
        self.config.validate().map_err(|error| error.to_string())
    }

    pub(crate) fn toggle_setting(&mut self, id: SettingId) {
        match id {
            SettingId::Interception => self.toggle_interception(),
            SettingId::AllowPrivateUpstreams => {
                self.config.proxy.allow_private_upstreams =
                    !self.config.proxy.allow_private_upstreams;
                if self.config.proxy.allow_private_upstreams {
                    self.notify_warning(
                        "Private and loopback upstreams enabled for this session. Scope rules still apply; restart the proxy to apply.",
                    );
                } else {
                    self.notify_info(
                        "Private and loopback upstreams blocked. Restart the proxy to apply.",
                    );
                }
            }
            SettingId::TlsInterception => self.toggle_tls_interception(),
            SettingId::VerifyTls => self.notify_warning(
                "Upstream TLS verification cannot be disabled in this build. Certificate validation is mandatory.",
            ),
            SettingId::Redaction => self.toggle_redaction(),
            SettingId::Accent => self.cycle_accent(),
            SettingId::Mouse => self.toggle_mouse(),
            SettingId::PersistBodies => {
                let next = StoragePolicy {
                    persist_bodies: !self.config.storage.persist_bodies,
                    persist_sensitive_headers: self.config.storage.persist_sensitive_headers,
                };
                self.apply_storage_policy(next);
                if next.persist_bodies {
                    self.notify_warning(
                        "Body persistence enabled: bodies of new captures are written to the session database.",
                    );
                } else {
                    self.notify_info(
                        "Body persistence disabled. Existing stored bodies are left untouched.",
                    );
                }
            }
            SettingId::PersistSensitive => {
                let next = StoragePolicy {
                    persist_bodies: self.config.storage.persist_bodies,
                    persist_sensitive_headers: !self.config.storage.persist_sensitive_headers,
                };
                self.apply_storage_policy(next);
                if next.persist_sensitive_headers {
                    self.notify_error(
                        "Sensitive-header persistence enabled: Authorization, Cookie and API-key values will be stored in plain form for new captures.",
                    );
                } else {
                    self.notify_info("Sensitive-header persistence disabled.");
                }
            }
            _ => self.setting_read_only_notice(id),
        }
    }

    fn setting_read_only_notice(&mut self, id: SettingId) {
        match id {
            SettingId::Scope => {
                self.notify_info(format!(
                    "Scope: {}. Press Enter to edit rules.",
                    self.config.proxy.scope.summary()
                ));
            }
            SettingId::CertificateAuthority => match &self.tls_status.ca_fingerprint {
                Some(fingerprint) => self.notify_info(format!(
                    "CA certificate: {} · {}",
                    self.tls_status
                        .ca_cert_path
                        .as_deref()
                        .unwrap_or("(unknown path)"),
                    fingerprint
                )),
                None => self.notify_warning(
                    "No local CA is active. Enable HTTPS TLS interception to generate or load the local CA explicitly.",
                ),
            },
            SettingId::CaFingerprint => match &self.tls_status.ca_fingerprint {
                Some(fingerprint) => self.notify_info(format!("CA fingerprint: {fingerprint}")),
                None => self.notify_warning(
                    "No local CA fingerprint is available. Enable HTTPS TLS interception or run --tls-ca-fingerprint.",
                ),
            },
            SettingId::DatabasePath => {
                if self.storage.enabled {
                    self.notify_info(format!(
                        "SQLite session database: {} · {} transactions stored · session {}",
                        self.storage
                            .database_path
                            .as_ref()
                            .map(|path| path.display().to_string())
                            .unwrap_or_else(|| self.config.storage.database_path.display().to_string()),
                        self.storage.persisted,
                        self.storage
                            .session_id
                            .as_ref()
                            .map(|id| id.0.clone())
                            .unwrap_or_else(|| "(unknown)".into()),
                    ));
                } else if let Some(error) = &self.storage.error {
                    self.notify_error(format!("Persistence is disabled: {error}"));
                } else {
                    self.notify_warning(
                        "Persistence is not attached in this process. Run the packaged binary without --no-persist to store sessions.",
                    );
                }
            }
            _ => {}
        }
    }

    pub(crate) fn setting_value(&self, id: SettingId) -> String {
        match id {
            SettingId::BindAddress => self.config.proxy.bind_address.to_string(),
            SettingId::Port => self.config.proxy.port.to_string(),
            SettingId::Interception => on_off(self.config.proxy.interception_enabled),
            SettingId::TlsInterception => on_off(self.tls_status.enabled),
            SettingId::VerifyTls => "ON (locked)".to_string(),
            SettingId::MaxBody => {
                format!("{} MiB", self.config.proxy.max_body_bytes / (1024 * 1024))
            }
            SettingId::MaxResponse => {
                format!(
                    "{} MiB",
                    self.config.proxy.max_response_bytes / (1024 * 1024)
                )
            }
            SettingId::MaxConnections => self.config.proxy.max_connections.to_string(),
            SettingId::ConnectTimeout => format!("{} s", self.config.proxy.connect_timeout_secs),
            SettingId::UpstreamTimeout => {
                format!("{} s", self.config.proxy.upstream_timeout_secs)
            }
            SettingId::IdleTimeout => format!("{} s", self.config.proxy.idle_timeout_secs),
            SettingId::InterceptTimeout => {
                format!("{} s", self.config.proxy.intercept_timeout_secs)
            }
            SettingId::AllowPrivateUpstreams => on_off(self.config.proxy.allow_private_upstreams),
            SettingId::Redaction => on_off(self.config.appearance.redact_sensitive_headers),
            SettingId::Accent => self.config.appearance.accent.label().to_string(),
            SettingId::Mouse => on_off(self.config.appearance.mouse_enabled),
            SettingId::PersistBodies => on_off(self.config.storage.persist_bodies),
            SettingId::PersistSensitive => on_off(self.config.storage.persist_sensitive_headers),
            SettingId::Scope => self.config.proxy.scope.summary(),
            SettingId::CertificateAuthority => self
                .tls_status
                .ca_cert_path
                .clone()
                .unwrap_or_else(|| "not initialised".to_string()),
            SettingId::CaFingerprint => self
                .tls_status
                .ca_fingerprint
                .clone()
                .unwrap_or_else(|| "not initialised".to_string()),
            SettingId::DatabasePath => {
                let path = self
                    .storage
                    .database_path
                    .clone()
                    .unwrap_or_else(|| self.config.storage.database_path.clone());
                let state = if self.storage.enabled {
                    format!("ON · {} stored", self.storage.persisted)
                } else if self.storage.error.is_some() {
                    "ERROR".to_string()
                } else {
                    "OFF".to_string()
                };
                format!("{} · {state}", path.display())
            }
        }
    }

    pub(crate) fn setting_is_on(&self, id: SettingId) -> bool {
        match id {
            SettingId::Interception => self.config.proxy.interception_enabled,
            SettingId::TlsInterception => self.tls_status.enabled,
            SettingId::VerifyTls => true,
            SettingId::AllowPrivateUpstreams => self.config.proxy.allow_private_upstreams,
            SettingId::Redaction => self.config.appearance.redact_sensitive_headers,
            SettingId::Mouse => self.config.appearance.mouse_enabled,
            SettingId::PersistBodies => self.config.storage.persist_bodies,
            SettingId::PersistSensitive => self.config.storage.persist_sensitive_headers,
            _ => false,
        }
    }

    fn apply_storage_policy(&mut self, policy: StoragePolicy) {
        policy.apply_to_config(&mut self.config.storage);
        if let Some(sender) = &self.storage_sender {
            let _ = sender.try_send(StorageCommand::SetPolicy(policy));
        } else {
            self.storage.policy = policy;
            self.notify_warning(
                "Persistence is not attached: this policy applies to the next launch only.",
            );
        }
    }

    // --- Stored sessions ---

    pub(crate) fn open_sessions(&mut self) {
        if self.storage_sender.is_none() {
            if let Some(error) = &self.storage.error {
                self.notify_error(format!("Persistence is unavailable: {error}"));
            } else {
                self.notify_warning(
                    "Persistence is not attached in this process. Run the packaged binary without --no-persist to browse stored sessions.",
                );
            }
            return;
        }
        self.sessions_open = true;
        self.sessions_loading = true;
        self.refresh_sessions();
    }

    pub(crate) fn close_sessions(&mut self) {
        self.sessions_open = false;
        self.sessions_loading = false;
    }

    pub(crate) fn refresh_sessions(&mut self) {
        let Some(sender) = &self.storage_sender else {
            self.notify_warning("Persistence is not attached.");
            return;
        };
        self.sessions_loading = true;
        match sender.try_send(StorageCommand::ListSessions) {
            Ok(()) => {}
            Err(_) => {
                self.sessions_loading = false;
                self.notify_error("Storage command queue is unavailable.");
            }
        }
    }

    pub(crate) fn move_sessions_selection(&mut self, delta: i32) {
        if self.sessions.is_empty() {
            self.sessions_selected = 0;
            return;
        }
        let next = (self.sessions_selected as i64 + i64::from(delta))
            .clamp(0, self.sessions.len() as i64 - 1);
        self.sessions_selected = next as usize;
    }

    pub(crate) fn select_session_edge(&mut self, last: bool) {
        self.sessions_selected = if last {
            self.sessions.len().saturating_sub(1)
        } else {
            0
        };
    }

    pub(crate) fn restore_selected_session(&mut self) {
        let Some(summary) = self.sessions.get(self.sessions_selected).cloned() else {
            self.notify_warning("No stored session is selected.");
            return;
        };
        let Some(sender) = &self.storage_sender else {
            self.notify_warning("Persistence is not attached.");
            return;
        };
        match sender.try_send(StorageCommand::LoadSession {
            session_id: summary.id.clone(),
            limit: 5_000,
        }) {
            Ok(()) => self.notify_info(format!(
                "Restoring {} transactions from {}…",
                summary.records, summary.name
            )),
            Err(_) => self.notify_error("Storage command queue is unavailable."),
        }
    }

    pub(crate) fn export_selected_session(&mut self) {
        let Some(summary) = self.sessions.get(self.sessions_selected).cloned() else {
            self.notify_warning("No stored session is selected.");
            return;
        };
        self.export_session(summary.id, &summary.name);
    }

    pub(crate) fn export_current_session(&mut self) {
        let Some(session_id) = self.storage.session_id.clone() else {
            self.notify_warning("No persisted session is active.");
            return;
        };
        let name = self.session.name.clone();
        self.export_session(session_id, &name);
    }

    fn export_session(&mut self, session_id: SessionId, name: &str) {
        let Some(sender) = &self.storage_sender else {
            self.notify_warning("Persistence is not attached.");
            return;
        };
        let path = self.export_path(name);
        match sender.try_send(StorageCommand::ExportSession {
            session_id,
            path: path.clone(),
        }) {
            Ok(()) => {
                self.notify_info(format!("Exporting redacted history to {}…", path.display()))
            }
            Err(_) => self.notify_error("Storage command queue is unavailable."),
        }
    }

    fn export_path(&self, name: &str) -> PathBuf {
        let directory = self
            .storage
            .database_path
            .as_ref()
            .or(Some(&self.config.storage.database_path))
            .and_then(|path| path.parent().map(|parent| parent.join("exports")))
            .unwrap_or_else(|| PathBuf::from("exports"));
        let safe: String = name
            .chars()
            .map(|ch| {
                if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_') {
                    ch
                } else {
                    '-'
                }
            })
            .collect();
        directory.join(format!(
            "{safe}-{}.jsonl",
            Utc::now().format("%Y%m%dT%H%M%SZ")
        ))
    }

    // --- Live scope editing ---

    pub(crate) fn open_scope_editor(&mut self) {
        self.scope_editor = Some(ScopeEditorState::default());
    }

    pub(crate) fn close_scope_editor(&mut self) {
        self.scope_editor = None;
    }

    pub(crate) fn move_scope_selection(&mut self, delta: i32) {
        let len = self.config.proxy.scope.allowlist.len();
        if let Some(editor) = &mut self.scope_editor {
            editor.move_selection(delta, len);
        }
    }

    pub(crate) fn select_scope_edge(&mut self, last: bool) {
        let len = self.config.proxy.scope.allowlist.len();
        if let Some(editor) = &mut self.scope_editor {
            editor.selected = if last { len.saturating_sub(1) } else { 0 };
        }
    }

    pub(crate) fn scope_input_push(&mut self, ch: char) {
        if let Some(editor) = &mut self.scope_editor {
            if editor.input.chars().count() < 128 {
                editor.input.push(ch);
            }
            editor.error = None;
        }
    }

    pub(crate) fn scope_input_backspace(&mut self) {
        if let Some(editor) = &mut self.scope_editor {
            editor.input.pop();
            editor.error = None;
        }
    }

    /// Parses the typed rule with the shared grammar and adds it to the live
    /// allowlist. Invalid input is reported instead of being guessed at.
    pub(crate) fn commit_scope_rule(&mut self) {
        let Some(editor) = &mut self.scope_editor else {
            return;
        };
        let text = editor.input.trim().to_string();
        if text.is_empty() {
            editor.error =
                Some("Enter a rule such as api.example.test:443 or *.example.test.".into());
            return;
        }
        match ScopeRule::parse(&text) {
            Ok(rule) => {
                if self.config.proxy.scope.allowlist.contains(&rule) {
                    editor.error = Some("That rule is already in the allowlist.".into());
                    return;
                }
                self.config.proxy.scope.allowlist.push(rule);
                editor.input.clear();
                editor.error = None;
                self.apply_scope_change();
            }
            Err(error) => editor.error = Some(error.to_string()),
        }
    }

    pub(crate) fn remove_selected_scope_rule(&mut self) {
        let Some(editor) = &self.scope_editor else {
            return;
        };
        if self.config.proxy.scope.allowlist.is_empty() {
            return;
        }
        let index = editor
            .selected
            .min(self.config.proxy.scope.allowlist.len() - 1);
        self.config.proxy.scope.allowlist.remove(index);
        let len = self.config.proxy.scope.allowlist.len();
        if let Some(editor) = &mut self.scope_editor {
            editor.selected = editor.selected.min(len.saturating_sub(1));
            editor.error = None;
        }
        self.apply_scope_change();
    }

    pub(crate) fn toggle_scope_block_unlisted(&mut self) {
        self.config.proxy.scope.block_unlisted = !self.config.proxy.scope.block_unlisted;
        if let Some(editor) = &mut self.scope_editor {
            editor.error = if self.config.proxy.scope.allowlist.is_empty()
                && self.config.proxy.scope.block_unlisted
            {
                Some("The allowlist is empty: every upstream request will be denied.".into())
            } else {
                None
            };
        }
        self.apply_scope_change();
    }

    fn apply_scope_change(&mut self) {
        let scope = self.config.proxy.scope.clone();
        if self.proxy_sender.is_some() {
            self.dispatch_command(AppCommand::UpdateScope(scope));
        } else {
            self.notify_info(format!(
                "Scope updated for this session: {}. It applies when the proxy starts.",
                self.config.proxy.scope.summary()
            ));
        }
    }

    pub(crate) fn open_context_menu(&mut self, x: u16, y: u16, target: HitTarget) {
        let items = match target {
            HitTarget::ProxyRow(id) | HitTarget::HistoryRow(id) => {
                let entry = self.traffic.iter().find(|entry| entry.id == id);
                let mut items = vec![
                    MenuItem {
                        label: "Inspect request",
                        action: MenuAction::Inspect(id),
                        danger: false,
                    },
                    MenuItem {
                        label: "Replay in Repeater",
                        action: MenuAction::Replay(id),
                        danger: false,
                    },
                    MenuItem {
                        label: "Edit in Repeater",
                        action: MenuAction::Edit(id),
                        danger: false,
                    },
                ];
                if let Some(entry) = entry
                    && entry.state.is_awaiting_decision()
                {
                    items.push(MenuItem {
                        label: "Forward request",
                        action: MenuAction::Forward(id),
                        danger: false,
                    });
                    items.push(MenuItem {
                        label: "Drop request",
                        action: MenuAction::Drop(id),
                        danger: true,
                    });
                }
                items
            }
            HitTarget::RepeaterTab(index) => vec![MenuItem {
                label: "Close tab",
                action: MenuAction::CloseRepeaterTab(index),
                danger: true,
            }],
            HitTarget::RepeaterEditor
            | HitTarget::InspectorSide(_)
            | HitTarget::InspectorView(_) => {
                vec![
                    MenuItem {
                        label: "Toggle redaction",
                        action: MenuAction::ToggleRedaction,
                        danger: false,
                    },
                    MenuItem {
                        label: "Command palette",
                        action: MenuAction::OpenPalette,
                        danger: false,
                    },
                ]
            }
            _ => vec![
                MenuItem {
                    label: "Command palette",
                    action: MenuAction::OpenPalette,
                    danger: false,
                },
                MenuItem {
                    label: "Keyboard help",
                    action: MenuAction::OpenHelp,
                    danger: false,
                },
            ],
        };
        self.context_menu = Some(ContextMenuState::new(x, y, items));
    }

    pub(crate) fn execute_menu_action(&mut self, action: MenuAction) {
        self.context_menu = None;
        match action {
            MenuAction::Inspect(id) => {
                self.focus_traffic(id);
                self.layout.context_open = true;
                self.inspector.side = MessageSide::Request;
                self.inspector.scroll = 0;
                self.focus = Focus::Context;
            }
            MenuAction::Replay(id) => {
                self.focus_traffic(id);
                self.open_in_repeater(id, false);
            }
            MenuAction::Edit(id) => {
                self.focus_traffic(id);
                self.open_in_repeater(id, true);
            }
            MenuAction::Forward(id) => {
                self.focus_traffic(id);
                self.forward_selected_request();
            }
            MenuAction::Drop(id) => {
                self.focus_traffic(id);
                self.drop_selected_request();
            }
            MenuAction::CloseRepeaterTab(index) => {
                self.nav = NavSection::Repeater;
                self.focus = Focus::Content;
                self.repeater.select(index);
                self.request_close_repeater_tab();
            }
            MenuAction::ToggleRedaction => self.toggle_redaction(),
            MenuAction::OpenPalette => self.open_palette(),
            MenuAction::OpenHelp => self.help_open = true,
        }
    }

    fn focus_traffic(&mut self, id: TrafficId) {
        if let Some(entry) = self.traffic.iter().find(|entry| entry.id == id)
            && entry.state.is_pending()
        {
            self.proxy_selected = Some(id);
        }
        self.history_selected = Some(id);
    }

    pub(crate) fn apply_render(&mut self, mut output: crate::interaction::RenderOutput) {
        if output.area.width > 0 && output.area.height > 0 {
            self.last_area = output.area;
        }
        output.area = self.last_area;
        self.render = output;
        if let Some(position) = self.pointer {
            self.hover = self.render.hit_at(position.x, position.y).cloned();
        }
    }

    pub(crate) fn set_editor_cursor_from_mouse(&mut self, x: u16, y: u16) {
        let Some(origin) = self.render.editor_origin else {
            return;
        };
        let gutter = self.render.editor_gutter;
        let Some(tab) = self.repeater.active_tab_mut() else {
            return;
        };
        let row = y.saturating_sub(origin.y) as usize + usize::from(tab.editor.scroll());
        let col = x.saturating_sub(origin.x).saturating_sub(gutter) as usize
            + usize::from(tab.editor.hscroll());
        tab.editor.set_cursor(row, col);
        let rows = self.render.repeater_rows;
        let cols = self.render.repeater_cols;
        if let Some(tab) = self.repeater.active_tab_mut() {
            tab.editor.ensure_visible(rows, cols);
        }
        self.repeater.editing = true;
    }

    pub(crate) fn set_decoder_editor_cursor_from_mouse(&mut self, x: u16, y: u16) {
        let Some(origin) = self.render.editor_origin else {
            return;
        };
        let gutter = self.render.editor_gutter;
        let row = y.saturating_sub(origin.y) as usize + usize::from(self.decoder.input.scroll());
        let col = x.saturating_sub(origin.x).saturating_sub(gutter) as usize
            + usize::from(self.decoder.input.hscroll());
        self.decoder.input.set_cursor(row, col);
        self.decoder
            .input
            .ensure_visible(self.render.repeater_rows, self.render.repeater_cols);
        self.decoder.editing = true;
    }

    pub(crate) fn move_interception_selection(&mut self, delta: i32) {
        let ids: Vec<TrafficId> = self.pending_interceptions().iter().map(|e| e.id).collect();
        self.interception.selected = step_selection(&ids, self.interception.selected, delta);
        self.proxy_selected = self.interception.selected;
        self.interception.editing = false;
        self.load_interception_editor();
    }

    pub(crate) fn select_interception_edge(&mut self, last: bool) {
        let ids: Vec<TrafficId> = self.pending_interceptions().iter().map(|e| e.id).collect();
        self.interception.selected = if last { ids.last() } else { ids.first() }.copied();
        self.proxy_selected = self.interception.selected;
        self.interception.editing = false;
        self.load_interception_editor();
    }

    pub(crate) fn pending_interceptions(&self) -> Vec<&TrafficEntry> {
        let mut entries: Vec<&TrafficEntry> = self
            .traffic
            .iter()
            .filter(|entry| entry.is_live_capture() && entry.state.is_awaiting_decision())
            .collect();
        entries.sort_by_key(|entry| entry.id);
        entries
    }

    pub(crate) fn sync_interception_selection(&mut self) {
        let pending: Vec<TrafficId> = self.pending_interceptions().iter().map(|e| e.id).collect();
        if self
            .interception
            .selected
            .is_none_or(|id| !pending.contains(&id))
        {
            self.interception.selected = pending.first().copied();
            self.proxy_selected = self.interception.selected;
            self.interception.dirty = false;
            self.interception.editing = false;
            self.load_interception_editor();
        } else {
            self.proxy_selected = self.interception.selected;
        }
        if self.interception.queue_pending != pending.len() {
            self.interception.queue_pending = pending.len();
        }
    }

    pub(crate) fn load_interception_editor(&mut self) {
        let Some(id) = self.interception.selected else {
            self.interception.editor = TextBuffer::from_text("");
            self.interception.original = None;
            self.interception.parse_error = None;
            self.interception.validation_error = None;
            self.interception.dirty = false;
            return;
        };
        let Some(entry) = self.traffic.iter().find(|e| e.id == id).cloned() else {
            self.interception.selected = None;
            self.interception.editor = TextBuffer::from_text("");
            self.interception.original = None;
            self.interception.parse_error = None;
            self.interception.validation_error = None;
            self.interception.dirty = false;
            return;
        };
        if !entry.state.is_awaiting_decision() || !entry.is_live_capture() {
            self.interception.selected = None;
            self.interception.editor = TextBuffer::from_text("");
            self.interception.original = None;
            self.interception.parse_error = None;
            self.interception.validation_error = None;
            self.interception.dirty = false;
            return;
        }
        // Preserve in-progress edits for the same selected request.
        if self.interception.original.is_some() && self.interception.dirty {
            // keep current editor as-is
        } else {
            let req = entry
                .original_request
                .clone()
                .unwrap_or_else(|| entry.request.clone());
            self.interception.editor = TextBuffer::from_text(&req.to_display_text(false));
            self.interception.original = Some(req);
            self.interception.parse_error = None;
            self.interception.validation_error = None;
            self.interception.dirty = false;
        }
    }

    pub(crate) fn select_interception(&mut self, id: TrafficId) {
        if self.pending_interceptions().iter().any(|e| e.id == id) {
            self.interception.selected = Some(id);
            self.proxy_selected = Some(id);
            self.interception.dirty = false;
            self.interception.editing = false;
            self.load_interception_editor();
        }
    }

    #[allow(dead_code)]
    pub(crate) fn interception_editable_request(
        &mut self,
    ) -> Result<rawframe_core::models::EditableHttpRequest, String> {
        let text = self.interception.editor.text();
        // Parse using request scheme from original if available, else http.
        let scheme = self
            .interception
            .original
            .as_ref()
            .map(|r| r.scheme)
            .unwrap_or(rawframe_core::models::message::Scheme::Http);
        let parsed = rawframe_http::parse_request(&text, scheme).map_err(|e| e.to_string())?;
        self.interception.parse_error = None;
        // Build editable request for proxy; proxy currently requires absolute http(s) target.
        let abs_target = parsed.url();
        if !(abs_target.starts_with("http://") || abs_target.starts_with("https://")) {
            return Err(
                "target must resolve to an absolute http:// or https:// URL for forwarding"
                    .to_string(),
            );
        }
        let body_len = parsed.body.len();
        if body_len > self.config.proxy.max_body_bytes {
            return Err(format!(
                "request body exceeds configured limit ({} bytes)",
                self.config.proxy.max_body_bytes
            ));
        }
        Ok(rawframe_core::models::EditableHttpRequest {
            method: parsed.method,
            target: abs_target,
            version: parsed.version,
            host: parsed.host,
            port: parsed.port,
            scheme: parsed.scheme,
            headers: parsed.headers,
            body: parsed.body,
        })
    }

    #[allow(dead_code)]
    pub(crate) fn forward_interception_unchanged(&mut self) {
        let Some(id) = self.interception.selected else {
            self.notify_warning("No pending interception selected.");
            return;
        };
        if !self.is_live_pending_interception(id) {
            self.notify_warning(format!("Request #{id} is not awaiting a decision."));
            self.sync_interception_selection();
            return;
        }
        self.dispatch_command(AppCommand::ForwardRequest(id));
        self.interception.last_decision = Some(format!("Forward requested for #{id}"));
    }

    #[allow(dead_code)]
    pub(crate) fn drop_interception(&mut self) {
        let Some(id) = self.interception.selected else {
            self.notify_warning("No pending interception selected.");
            return;
        };
        if !self.is_live_pending_interception(id) {
            self.notify_warning(format!("Request #{id} is not awaiting a decision."));
            self.sync_interception_selection();
            return;
        }
        self.dispatch_command(AppCommand::DropRequest(id));
        self.interception.last_decision = Some(format!("Drop requested for #{id}"));
    }

    #[allow(dead_code)]
    pub(crate) fn forward_interception_modified(&mut self) {
        let Some(id) = self.interception.selected else {
            self.notify_warning("No pending interception selected.");
            return;
        };
        if !self.is_live_pending_interception(id) {
            self.notify_warning(format!("Request #{id} is not awaiting a decision."));
            self.sync_interception_selection();
            return;
        }
        match self.interception_editable_request() {
            Ok(request) => {
                self.interception.validation_error = None;
                self.dispatch_command(AppCommand::ForwardModified { id, request });
                self.interception.last_decision =
                    Some(format!("Forward-modified requested for #{id}"));
            }
            Err(err) => {
                self.interception.parse_error = Some(err.clone());
                self.interception.validation_error = Some(err.clone());
                self.notify_error(format!("Cannot forward modified request: {err}"));
            }
        }
    }

    // --- Public helpers for integration tests / embedding ---

    /// Number of live paused interceptions currently tracked by the UI.
    pub fn interception_pending_count(&self) -> usize {
        self.pending_interceptions().len()
    }

    /// Selected interception request id, if any.
    pub fn interception_selected(&self) -> Option<TrafficId> {
        self.interception.selected
    }

    /// Replace interception editor contents (as if pasted/edited) for the selected request.
    /// Does not dispatch a decision.
    pub fn set_interception_editor_text(&mut self, text: &str) {
        self.interception.editor = TextBuffer::from_text(text);
        self.interception.dirty = true;
        self.interception.parse_error = None;
        self.interception.validation_error = None;
    }

    /// Current interception editor text.
    pub fn interception_editor_text(&self) -> String {
        self.interception.editor.text()
    }

    /// Dispatch a forward-unchanged decision for the selected live interception.
    pub fn interception_forward_unchanged_action(&mut self) {
        self.forward_interception_unchanged();
    }

    /// Dispatch a drop decision for the selected live interception.
    pub fn interception_drop_action(&mut self) {
        self.drop_interception();
    }

    /// Dispatch a forward-modified decision for the selected live interception using current editor contents.
    pub fn interception_forward_modified_action(&mut self) {
        self.forward_interception_modified();
    }

    /// Dispatch an application command through the UI boundary (public wrapper for integration).
    pub fn dispatch_app_command(&mut self, command: AppCommand) {
        self.dispatch_command(command);
    }
}

impl Default for App {
    fn default() -> Self {
        Self::demo()
    }
}

fn step_selection(ids: &[TrafficId], current: Option<TrafficId>, delta: i32) -> Option<TrafficId> {
    if ids.is_empty() {
        return None;
    }
    let Some(index) = current.and_then(|current| ids.iter().position(|id| *id == current)) else {
        return if delta >= 0 { ids.first() } else { ids.last() }.copied();
    };
    let next = (index as i64 + i64::from(delta)).clamp(0, ids.len() as i64 - 1) as usize;
    ids.get(next).copied()
}

fn on_off(value: bool) -> String {
    if value { "ON" } else { "OFF" }.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rawframe_core::models::config::Scope;
    use rawframe_core::models::message::{HttpRequest, Scheme};
    use rawframe_core::models::traffic::TrafficSource;
    use rawframe_core::{AppEvent, NoticeLevel};

    fn entry(id: u64) -> TrafficEntry {
        TrafficEntry::new(
            TrafficId(id),
            HttpRequest::new("GET", Scheme::Https, "probe.rawframe.test", 443, "/fresh"),
        )
    }

    #[test]
    fn startup_selects_history_and_leaves_the_live_proxy_empty() {
        let app = App::demo();
        // Fixtures live in HTTP History; the live Proxy workspace starts empty.
        assert!(app.proxy_entries().is_empty());
        assert!(app.proxy_selected.is_none());
        assert!(app.history_selected.is_some());
        assert_eq!(app.pending_entries().len(), 4);
        assert_eq!(app.history_entries().len(), 17);
        assert_eq!(app.nav, NavSection::Proxy);
    }

    #[test]
    fn events_are_upserted_and_trigger_notices() {
        let mut app = App::demo();
        let before = app.traffic.len();
        app.handle_event(AppEvent::TrafficCaptured(Box::new(entry(99))));

        assert_eq!(app.traffic.len(), before + 1);
        assert!(
            app.notices
                .last()
                .unwrap()
                .notice
                .message
                .contains("Captured")
        );

        let mut updated = entry(99);
        updated.pause().unwrap();
        app.handle_event(AppEvent::TrafficUpdated(Box::new(updated.clone())));
        assert_eq!(app.traffic.len(), before + 1);
        assert_eq!(
            app.traffic
                .iter()
                .find(|entry| entry.id == TrafficId(99))
                .unwrap()
                .state,
            TrafficState::Paused
        );
    }

    #[test]
    fn event_sender_can_drive_the_application() {
        let mut app = App::demo();
        app.event_sender()
            .send(AppEvent::Notice(Notice::error("engine offline")))
            .unwrap();
        let event = app.events.poll().unwrap();
        app.handle_event(event);
        assert_eq!(app.notices.last().unwrap().notice.level, NoticeLevel::Error);
    }

    #[test]
    fn forwarding_and_dropping_simulated_requests_is_local_only() {
        let mut app = App::demo();
        let id = app
            .pending_entries()
            .iter()
            .find(|entry| {
                matches!(
                    entry.state,
                    TrafficState::Captured | TrafficState::Paused | TrafficState::Modified
                )
            })
            .map(|entry| entry.id)
            .unwrap();
        app.proxy_selected = Some(id);
        app.forward_selected_request();
        let entry = app.traffic.iter().find(|entry| entry.id == id).unwrap();
        assert_eq!(entry.state, TrafficState::Forwarded);
        assert!(
            app.notices
                .iter()
                .any(|toast| toast.notice.message.contains("No network traffic")),
            "{:?}",
            app.notices
                .iter()
                .map(|toast| &toast.notice.message)
                .collect::<Vec<_>>()
        );

        let id = app
            .pending_entries()
            .iter()
            .find(|entry| {
                matches!(
                    entry.state,
                    TrafficState::Captured | TrafficState::Paused | TrafficState::Modified
                )
            })
            .map(|entry| entry.id)
            .unwrap();
        app.proxy_selected = Some(id);
        app.drop_selected_request();
        let entry = app.traffic.iter().find(|entry| entry.id == id).unwrap();
        assert!(entry.state.is_terminal() || entry.state == TrafficState::Forwarded);
    }

    #[test]
    fn live_requests_are_never_faked_when_forwarding() {
        let mut app = App::demo();
        app.handle_event(AppEvent::TrafficCaptured(Box::new(entry(100))));
        app.proxy_selected = Some(TrafficId(100));
        app.nav = NavSection::Proxy;
        app.forward_selected_request();

        let live = app
            .traffic
            .iter()
            .find(|entry| entry.id == TrafficId(100))
            .unwrap();
        assert_eq!(live.source, TrafficSource::Intercepted);
        assert_eq!(live.state, TrafficState::Captured);
        assert!(
            app.notices
                .last()
                .unwrap()
                .notice
                .message
                .contains("not awaiting an interception decision")
        );
    }

    #[test]
    fn settings_validation_refuses_remote_binds() {
        let mut app = App::demo();
        let result = app.apply_setting_value(SettingId::BindAddress, "0.0.0.0");
        assert!(result.is_err());
        assert_eq!(app.config.proxy.bind_address.to_string(), "127.0.0.1");

        app.apply_setting_value(SettingId::BindAddress, "::1")
            .unwrap();
        assert!(app.config.proxy.bind_address.is_loopback());
    }

    #[test]
    fn filters_reduce_history_and_keep_selection_valid() {
        let mut app = App::demo();
        app.navigate(NavSection::History);
        app.history_filter.method = Some("POST".into());
        app.ensure_selections();

        assert!(
            app.history_entries()
                .iter()
                .all(|entry| entry.request.method == "POST")
        );
        assert!(app.history_selected.is_none() || app.selected_traffic().is_some());

        app.clear_filters();
        assert_eq!(app.history_entries().len(), 17);
    }

    #[test]
    fn search_navigation_scopes_to_history() {
        let mut app = App::demo();
        app.start_search();
        assert_eq!(app.nav, NavSection::History);
        assert!(app.search.active);
    }

    #[test]
    fn commands_flow_through_the_application_boundary() {
        let mut app = App::demo();
        app.dispatch_command(AppCommand::SetInterception { enabled: true });
        assert!(app.config.proxy.interception_enabled);

        let id = app.pending_entries().first().map(|entry| entry.id).unwrap();
        app.proxy_selected = Some(id);
        app.dispatch_command(AppCommand::ForwardRequest(id));
        assert_eq!(
            app.traffic
                .iter()
                .find(|entry| entry.id == id)
                .unwrap()
                .state,
            TrafficState::Forwarded
        );

        let id = app.pending_entries().last().map(|entry| entry.id).unwrap();
        app.proxy_selected = Some(id);
        app.dispatch_command(AppCommand::DropRequest(id));
        assert!(!app.notices.is_empty());
    }

    #[test]
    fn accent_cycle_updates_theme() {
        let mut app = App::demo();
        let before = app.theme.accent;
        app.cycle_accent();
        assert_ne!(app.theme.accent, before);
        assert_eq!(app.config.appearance.accent, app.theme.accent);
    }

    #[test]
    fn persistence_status_is_visible_and_policy_changes_are_forwarded() {
        let mut app = App::demo();
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        app.attach_storage_commands(tx);

        app.handle_event(AppEvent::Storage(StorageEvent::Status(
            StorageStatus::enabled(
                "/tmp/rawframe-test.db",
                SessionId("sess-1".into()),
                StoragePolicy::metadata_only(),
            ),
        )));
        assert!(app.storage_status().enabled);
        assert!(app.setting_value(SettingId::DatabasePath).contains("ON"));

        app.toggle_setting(SettingId::PersistBodies);
        assert!(app.config.storage.persist_bodies);
        match rx.try_recv().expect("policy command") {
            StorageCommand::SetPolicy(policy) => {
                assert!(policy.persist_bodies);
                assert!(!policy.persist_sensitive_headers);
            }
            other => panic!("unexpected command: {other:?}"),
        }

        app.handle_event(AppEvent::Storage(StorageEvent::Failed("disk full".into())));
        assert!(
            app.notices
                .last()
                .unwrap()
                .notice
                .message
                .contains("disk full")
        );
    }

    #[test]
    fn restored_history_is_marked_read_only_and_never_live() {
        let mut app = App::demo();
        let mut entry = TrafficEntry::new(
            TrafficId(1_000_001),
            HttpRequest::new("GET", Scheme::Https, "api.rawframe.test", 443, "/stored"),
        );
        entry.source = TrafficSource::Restored;
        entry.body_omitted = true;
        entry.note = Some("restored from database".into());

        app.handle_event(AppEvent::Storage(StorageEvent::SessionLoaded {
            session_id: SessionId("sess-previous".into()),
            entries: vec![entry],
            truncated: false,
        }));

        assert_eq!(app.nav, NavSection::History);
        assert_eq!(app.restored_entry_count(), 1);
        assert_eq!(app.restored_session_label(), Some("sess-previous"));
        assert!(app.proxy_entries().iter().all(|entry| !entry.is_restored()));
        let selected = app.selected_traffic().unwrap();
        assert!(selected.is_restored());
        assert!(selected.body_omitted);

        // Persisted history uses the same search/filter path. Searching for
        // provenance finds restored rows; a non-matching host hides them.
        app.history_filter.query = "restored".into();
        app.ensure_selections();
        assert_eq!(app.history_entries().len(), 1);
        app.history_filter.query.clear();
        app.history_filter.host = Some("other.test".into());
        app.ensure_selections();
        assert!(app.history_entries().is_empty());
        app.clear_filters();
        assert!(
            app.notices
                .last()
                .unwrap()
                .notice
                .message
                .contains("Restored 1 transactions")
        );
    }

    #[test]
    fn stored_session_browser_renders_real_state_and_requests_restore() {
        use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

        let mut app = App::demo();
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        app.attach_storage_commands(tx);
        app.handle_event(AppEvent::Storage(StorageEvent::Sessions(vec![
            SessionSummary {
                id: SessionId("sess-previous".into()),
                name: "previous".into(),
                project_id: rawframe_core::models::ProjectId::default_project(),
                project_name: "default".into(),
                created_at: Utc::now(),
                records: 3,
                incomplete: 1,
                last_activity_at: None,
                recovered: true,
            },
        ])));
        app.open_sessions();
        assert!(app.sessions_open());
        assert!(matches!(rx.try_recv(), Ok(StorageCommand::ListSessions)));

        let buffer = crate::testing::render_frame(&mut app, 120, 36);
        let text = crate::testing::text(&buffer);
        assert!(text.contains("STORED SESSIONS"), "{text}");
        assert!(text.contains("default/previous"), "{text}");
        assert!(text.contains("3 rec"), "{text}");
        assert!(text.contains("1 incomplete"), "{text}");
        assert!(text.contains("recovered"), "{text}");

        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(matches!(
            rx.try_recv(),
            Ok(StorageCommand::LoadSession { session_id, .. }) if session_id.0 == "sess-previous"
        ));
    }

    #[test]
    fn scope_editor_renders_rules_and_default_deny_state() {
        let mut app = App::demo();
        app.open_scope_editor();
        for ch in "api.example.test".chars() {
            app.scope_input_push(ch);
        }
        app.commit_scope_rule();

        let buffer = crate::testing::render_frame(&mut app, 120, 36);
        let text = crate::testing::text(&buffer);
        assert!(text.contains("TARGET SCOPE"), "{text}");
        assert!(text.contains("Default: DENY"), "{text}");
        assert!(text.contains("api.example.test"), "{text}");
    }

    #[test]
    fn scope_editor_uses_the_shared_parser_and_updates_the_live_rules() {
        let mut app = App::demo();
        app.open_scope_editor();
        for ch in "https://api.example.test:443".chars() {
            app.scope_input_push(ch);
        }
        app.commit_scope_rule();

        assert_eq!(app.scope_rules().len(), 1);
        assert_eq!(app.scope_rules()[0].spec(), "https://api.example.test:443");
        assert!(
            app.setting_value(SettingId::Scope)
                .contains("1 allowlist rule")
        );

        for ch in "not/a/host".chars() {
            app.scope_input_push(ch);
        }
        app.commit_scope_rule();
        assert!(app.scope_editor().unwrap().error.is_some());
        assert_eq!(app.scope_rules().len(), 1);

        app.remove_selected_scope_rule();
        assert!(app.scope_rules().is_empty());
        assert!(
            app.scope_editor().is_some(),
            "editor stays open to add another rule"
        );
    }

    fn wait_for_decoder(app: &mut App) {
        for _ in 0..200 {
            app.tick();
            if !app.decoder.running {
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        panic!("Decoder did not finish");
    }

    #[test]
    fn decoder_runs_real_pipeline_and_supports_swap_clear_copy_and_history() {
        use rawframe_core::decoder::Transform;

        let mut app = App::demo();
        app.navigate(NavSection::Decoder);
        app.decoder.load_input(b"aGVsbG8=".to_vec(), "TEST");
        app.decoder.pipeline.push(Transform::Base64Decode);
        app.execute_decoder();
        wait_for_decoder(&mut app);

        assert!(app.decoder.error.is_none());
        assert_eq!(app.decoder.displayed_bytes, b"hello");
        assert_eq!(
            app.decoder.displayed_format,
            rawframe_core::OutputFormat::Text
        );
        assert_eq!(app.decoder.history.len(), 1);
        assert!(app.decoder.history[0].result.contains("OK"));

        app.copy_decoder_output();
        assert_eq!(app.take_clipboard_request().as_deref(), Some("hello"));

        app.swap_decoder_input_output();
        assert_eq!(app.decoder.input_bytes, b"hello");
        assert_eq!(app.decoder.output.as_ref().unwrap().bytes, b"aGVsbG8=");

        app.clear_decoder();
        assert!(app.decoder.input_bytes.is_empty());
        assert!(app.decoder.output.is_none());
        assert_eq!(app.decoder.pipeline, [Transform::Base64Decode]);
    }

    #[test]
    fn decoder_pipeline_editing_reorders_fails_and_preserves_failure_step() {
        use rawframe_core::decoder::Transform;

        let mut app = App::demo();
        app.navigate(NavSection::Decoder);
        app.decoder.load_input(b"aGVsbG8=".to_vec(), "TEST");
        app.decoder.pipeline = vec![Transform::JsonPretty, Transform::Base64Decode];
        app.decoder.selected_step = 1;
        app.move_decoder_step(-1);
        assert_eq!(
            app.decoder.pipeline,
            [Transform::Base64Decode, Transform::JsonPretty]
        );

        app.execute_decoder();
        wait_for_decoder(&mut app);
        let error = app.decoder.error.as_ref().unwrap();
        assert_eq!(error.step_index, 1);
        assert_eq!(error.transform, Some(Transform::JsonPretty));
        assert!(app.decoder.output.is_none());
        assert_eq!(app.decoder.steps.len(), 1);
        assert_eq!(app.decoder.steps[0].output, b"hello");
        app.decoder.selected_step = 0;
        app.preview_decoder_step();
        assert_eq!(app.decoder.displayed_bytes, b"hello");
        assert_eq!(app.decoder.view_step, Some(0));
        app.show_decoder_final_output();
        assert!(app.decoder.view_step.is_none());

        app.decoder.remove_step();
        assert_eq!(app.decoder.pipeline.len(), 1);
    }

    #[test]
    fn decoder_and_repeater_body_transfers_are_explicit_and_preserve_captures() {
        use rawframe_core::decoder::Transform;

        let mut app = App::demo();
        let tab = app.repeater.active_tab().unwrap();
        let original_body = tab.execution_request().body;
        let original_request = tab.original_request.clone();
        let capture_bodies: Vec<Vec<u8>> = app
            .traffic
            .iter()
            .map(|entry| entry.request.body.clone())
            .collect();

        app.send_repeater_request_body_to_decoder();
        assert_eq!(app.nav, NavSection::Decoder);
        assert_eq!(app.decoder.input_bytes, original_body);

        app.decoder.pipeline.push(Transform::JsonPretty);
        app.execute_decoder();
        wait_for_decoder(&mut app);
        assert!(app.decoder.error.is_none());
        assert_eq!(
            app.decoder.displayed_format,
            rawframe_core::OutputFormat::Json
        );
        app.send_decoder_output_to_repeater();
        assert_eq!(app.nav, NavSection::Repeater);
        let tab = app.repeater.active_tab().unwrap();
        assert_eq!(tab.original_request, original_request);
        assert_ne!(tab.execution_request().body, original_body);
        assert!(tab.editor.text().contains("Content-Length:"));
        assert!(
            app.traffic
                .iter()
                .map(|entry| entry.request.body.clone())
                .eq(capture_bodies),
            "loading Decoder and returning output must not mutate stored captures"
        );

        let mut result = repeater_result(200);
        result.response.as_mut().unwrap().body = b"{\"response\":true}".to_vec();
        app.repeater.active_tab_mut().unwrap().response = Some(result);
        app.send_repeater_response_body_to_decoder();
        assert_eq!(app.nav, NavSection::Decoder);
        assert_eq!(app.decoder.input_bytes, b"{\"response\":true}");
    }

    fn repeater_result(status: u16) -> rawframe_core::RepeaterResult {
        rawframe_core::RepeaterResult {
            request: HttpRequest::new(
                "POST",
                Scheme::Https,
                "api.rawframe.test",
                443,
                "/v1/orders",
            ),
            response: Some(rawframe_core::HttpResponse::with_body(
                status,
                "application/json",
                "{\"ok\":true}",
            )),
            timings: rawframe_core::RepeaterTimings {
                total_ms: 17,
                ..rawframe_core::RepeaterTimings::default()
            },
            redirects: Vec::new(),
            truncated: false,
            response_bytes: 11,
            error: None,
            warnings: Vec::new(),
            sent_at: Utc::now(),
        }
    }

    #[test]
    fn repeater_send_dispatches_a_real_execution_and_cancel_uses_its_id() {
        let mut app = App::demo();
        app.navigate(NavSection::Repeater);
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        app.attach_repeater_commands(tx);
        let tab_id = app.repeater.active_tab().unwrap().document.id;

        app.send_repeater_request();
        let command = rx.try_recv().expect("execution command");
        let RepeaterCommand::Execute {
            tab,
            execution,
            request,
            follow_redirects,
            ..
        } = command
        else {
            panic!("expected Execute");
        };
        assert_eq!(tab, tab_id);
        assert!(!follow_redirects);
        assert_eq!(
            request.method,
            app.repeater.active_tab().unwrap().document.request.method
        );
        assert_eq!(
            app.repeater.active_tab().unwrap().active_execution,
            Some(execution)
        );
        assert_eq!(
            app.repeater.active_tab().unwrap().execution,
            RepeaterExecutionPhase::Validating
        );

        app.cancel_repeater_request();
        assert!(matches!(
            rx.try_recv().expect("cancel command"),
            RepeaterCommand::Cancel { execution: id } if id == execution
        ));
    }

    #[test]
    fn repeater_completion_updates_only_the_owning_tab_and_history() {
        let mut app = App::demo();
        app.navigate(NavSection::Repeater);
        let tab_id = app.repeater.active_tab().unwrap().document.id;
        app.repeater.active_tab_mut().unwrap().active_execution = Some(3);
        let other_before = app.repeater.tabs[1].response.clone();

        let result = repeater_result(201);
        let mut completed_entry = TrafficEntry::new(
            TrafficId(rawframe_core::repeater::REPEATER_ID_BASE + 1),
            result.request.clone(),
        );
        completed_entry.source = TrafficSource::Repeater;
        completed_entry.repeater_origin = Some(TrafficId(14));
        completed_entry.response = result.response.clone();
        completed_entry.state = TrafficState::Completed;

        app.handle_event(AppEvent::Repeater(RepeaterEvent::Completed {
            tab: tab_id,
            execution: 3,
            phase: RepeaterExecutionPhase::Completed,
            result: Box::new(result),
            entry: Box::new(completed_entry.clone()),
        }));

        let tab = app.repeater.active_tab().unwrap();
        assert_eq!(tab.execution, RepeaterExecutionPhase::Completed);
        assert_eq!(tab.response.as_ref().unwrap().status(), Some(201));
        assert!(tab.active_execution.is_none());
        assert_eq!(app.repeater.tabs[1].response, other_before);
        assert!(
            app.traffic
                .iter()
                .any(|entry| entry.id == completed_entry.id && entry.is_repeater())
        );
        assert!(
            app.proxy_entries().iter().all(|entry| !entry.is_repeater()),
            "Repeater results must never appear as live proxy traffic"
        );
    }

    #[test]
    fn stale_repeater_completion_cannot_overwrite_a_newer_tab_state() {
        let mut app = App::demo();
        app.navigate(NavSection::Repeater);
        let tab_id = app.repeater.active_tab().unwrap().document.id;
        app.repeater.active_tab_mut().unwrap().active_execution = Some(9);
        app.handle_event(AppEvent::Repeater(RepeaterEvent::Completed {
            tab: tab_id,
            execution: 8,
            phase: RepeaterExecutionPhase::Completed,
            result: Box::new(repeater_result(200)),
            entry: Box::new(entry(2_000_009)),
        }));
        assert!(app.repeater.active_tab().unwrap().response.is_none());
        assert_eq!(app.repeater.active_tab().unwrap().active_execution, Some(9));
    }

    #[test]
    fn a_storage_failure_does_not_block_repeater_results() {
        let mut app = App::demo();
        app.navigate(NavSection::Repeater);
        app.report_storage_failure(Some("/tmp/rawframe.db".into()), "disk full".into());
        let tab_id = app.repeater.active_tab().unwrap().document.id;
        app.repeater.active_tab_mut().unwrap().active_execution = Some(5);
        app.handle_event(AppEvent::Repeater(RepeaterEvent::Completed {
            tab: tab_id,
            execution: 5,
            phase: RepeaterExecutionPhase::Completed,
            result: Box::new(repeater_result(200)),
            entry: Box::new(entry(2_000_010)),
        }));

        assert_eq!(
            app.repeater
                .active_tab()
                .unwrap()
                .response
                .as_ref()
                .unwrap()
                .response
                .as_ref()
                .unwrap()
                .status,
            200
        );
        assert!(
            app.storage_status()
                .error
                .as_deref()
                .unwrap()
                .contains("disk full")
        );
        assert!(
            !app.storage_status().enabled,
            "the failure is surfaced without claiming persistence"
        );
    }

    #[test]
    fn scope_updates_reach_both_the_proxy_and_repeater() {
        let mut app = App::demo();
        let (proxy_tx, mut proxy_rx) = tokio::sync::mpsc::channel(4);
        let (repeater_tx, mut repeater_rx) = tokio::sync::mpsc::channel(4);
        app.attach_proxy_commands(proxy_tx);
        app.attach_repeater_commands(repeater_tx);
        let scope = ScopeRule::parse("https://api.rawframe.test").unwrap();
        app.dispatch_app_command(AppCommand::UpdateScope(Scope::allow(scope.clone())));

        assert!(matches!(
            proxy_rx.try_recv().unwrap(),
            AppCommand::UpdateScope(scope) if scope.allowlist == vec![scope_rule()]
        ));
        assert!(matches!(
            repeater_rx.try_recv().unwrap(),
            RepeaterCommand::UpdateScope(scope) if scope.allowlist == vec![scope_rule()]
        ));
    }

    fn scope_rule() -> ScopeRule {
        ScopeRule::parse("https://api.rawframe.test").unwrap()
    }

    #[test]
    fn selection_steps_are_clamped() {
        let ids = vec![TrafficId(1), TrafficId(2), TrafficId(3)];
        assert_eq!(step_selection(&ids, None, 1), Some(TrafficId(1)));
        assert_eq!(step_selection(&ids, None, -1), Some(TrafficId(3)));
        assert_eq!(
            step_selection(&ids, Some(TrafficId(3)), 1),
            Some(TrafficId(3))
        );
        assert_eq!(
            step_selection(&ids, Some(TrafficId(1)), -1),
            Some(TrafficId(1))
        );
    }
}
