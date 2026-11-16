//! Application controller for the terminal shell.
//!
//! The controller owns presentation state and consumes [`AppEvent`]s from the
//! event bus. Networking and storage services are absent in this milestone; the
//! UI keeps their boundary explicit instead of faking live behaviour.

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use ratatui::layout::{Position, Rect};
use rawframe_core::models::traffic::{TrafficEntry, TrafficId, TrafficState};
use rawframe_core::models::{AppConfig, Session};
use rawframe_core::{
    AppCommand, AppEvent, CommandSender, EventBus, EventSender, HistoryFilter, Notice, ProxyState,
};

use crate::commands::{CommandId, CommandSpec, filter_commands};
use crate::components::lifecycle;
use crate::interaction::{ActionId, Focus, HitTarget, MessageSide, NavSection, SettingId};
use crate::layout::{AppLayout, DragTarget, LayoutState, compute};
use crate::state::{
    ConfirmAction, ConfirmState, ContextMenuState, InspectorState, MenuAction, MenuItem,
    PaletteState, RepeaterOrigin, RepeaterState, RepeaterTab, SearchState, SettingEdit,
    SettingsState, Toast,
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
    pub(crate) traffic: Vec<TrafficEntry>,
    pub(crate) proxy_selected: Option<TrafficId>,
    pub(crate) history_selected: Option<TrafficId>,
    pub(crate) history_filter: HistoryFilter,
    pub(crate) search: SearchState,
    pub(crate) inspector: InspectorState,
    pub(crate) repeater: RepeaterState,
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
            traffic,
            proxy_selected: None,
            history_selected: None,
            history_filter: HistoryFilter::default(),
            search: SearchState::default(),
            inspector: InspectorState::default(),
            repeater,
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
            AppEvent::Notice(notice) => self.notify(notice),
            AppEvent::Shutdown => self.should_quit = true,
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
                self.notify_info("New Repeater tab. Transmission is unavailable in this build.");
            }
            CommandId::CloseRepeaterTab => self.request_close_repeater_tab(),
            CommandId::SendRepeaterRequest => self.send_repeater_request(),
            CommandId::SearchHistory => self.start_search(),
            CommandId::ClearHistoryFilters => self.clear_filters(),
            CommandId::ToggleMouse => self.toggle_mouse(),
            CommandId::ShowHelp => self.help_open = true,
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
            ActionId::SendRepeater => self.send_repeater_request(),
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
                    "Live forwarding is unavailable here: the proxy forwards automatically and operator pause/forward arrives with interception in Milestone 4."
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
                Err("Live HTTP requests were already forwarded by the proxy; drop-on-pause arrives with interception in Milestone 4."
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
        let Some(tab) = self.repeater.active_tab() else {
            self.notify_warning("There is no Repeater tab to send.");
            return;
        };
        let parse_error = tab.parse_error.clone();
        if let Some(error) = parse_error {
            self.notify_error(format!("Cannot transmit an invalid request: {error}"));
            return;
        }
        self.notify_warning(
            "Transmission unavailable: Repeater delivery is not implemented in this build. Nothing was sent.",
        );
    }

    pub(crate) fn request_close_repeater_tab(&mut self) {
        let Some(tab) = self.repeater.active_tab() else {
            return;
        };
        let dirty = tab.dirty;
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
        if self.repeater.has_unsaved_changes() || live_paused {
            let reason = if self.repeater.has_unsaved_changes() {
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
            SettingId::VerifyTls => self.notify_warning(
                "Upstream TLS verification cannot be disabled in this build. Certificate validation is mandatory.",
            ),
            SettingId::Redaction => self.toggle_redaction(),
            SettingId::Accent => self.cycle_accent(),
            SettingId::Mouse => self.toggle_mouse(),
            SettingId::PersistBodies => {
                self.config.storage.persist_bodies = !self.config.storage.persist_bodies;
                if self.config.storage.persist_bodies {
                    self.notify_warning(
                        "Body persistence enabled for this session. SQLite storage is not active yet; captured bodies can contain credentials.",
                    );
                } else {
                    self.notify_info("Body persistence disabled.");
                }
            }
            SettingId::PersistSensitive => {
                self.config.storage.persist_sensitive_headers =
                    !self.config.storage.persist_sensitive_headers;
                if self.config.storage.persist_sensitive_headers {
                    self.notify_error(
                        "Sensitive-header persistence enabled. This is a deliberate confidentiality risk and storage is not active yet.",
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
            SettingId::Scope => self.notify_warning(format!(
                "Scope: {}. Edit scope with --scope when launching; upstream traffic is denied by default.",
                self.config.proxy.scope.summary()
            )),
            SettingId::CertificateAuthority => self.notify_warning(
                "No local CA has been generated. TLS interception is Milestone 3 and requires explicit client trust.",
            ),
            SettingId::DatabasePath => self.notify_warning(
                "SQLite persistence is Milestone 4. No database file has been created.",
            ),
            _ => {}
        }
    }

    pub(crate) fn setting_value(&self, id: SettingId) -> String {
        match id {
            SettingId::BindAddress => self.config.proxy.bind_address.to_string(),
            SettingId::Port => self.config.proxy.port.to_string(),
            SettingId::Interception => on_off(self.config.proxy.interception_enabled),
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
            SettingId::CertificateAuthority => "not initialised".to_string(),
            SettingId::DatabasePath => self.config.storage.database_path.display().to_string(),
        }
    }

    pub(crate) fn setting_is_on(&self, id: SettingId) -> bool {
        match id {
            SettingId::Interception => self.config.proxy.interception_enabled,
            SettingId::VerifyTls => true,
            SettingId::AllowPrivateUpstreams => self.config.proxy.allow_private_upstreams,
            SettingId::Redaction => self.config.appearance.redact_sensitive_headers,
            SettingId::Mouse => self.config.appearance.mouse_enabled,
            SettingId::PersistBodies => self.config.storage.persist_bodies,
            SettingId::PersistSensitive => self.config.storage.persist_sensitive_headers,
            _ => false,
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
                .contains("unavailable")
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
