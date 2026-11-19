//! Interaction vocabulary shared by rendering and input handling.
//!
//! Rendering records hit rectangles into [`RenderOutput`]; input resolves the
//! pointer against those rectangles. Nothing in the UI uses fixed coordinates.

use ratatui::layout::Rect;
use rawframe_core::models::traffic::TrafficId;
use rawframe_core::models::websocket::{WebSocketConnectionId, WebSocketFrameId};

use crate::layout::DragTarget;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NavSection {
    Proxy,
    History,
    WebSocket,
    Repeater,
    Settings,
    Intruder,
    Decoder,
}

impl NavSection {
    /// Primary workspaces.
    pub const PRIMARY: [Self; 7] = [
        Self::Proxy,
        Self::History,
        Self::WebSocket,
        Self::Repeater,
        Self::Intruder,
        Self::Decoder,
        Self::Settings,
    ];

    /// All sections including clearly planned modules.
    pub const ALL: [Self; 7] = [
        Self::Proxy,
        Self::History,
        Self::WebSocket,
        Self::Repeater,
        Self::Settings,
        Self::Intruder,
        Self::Decoder,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Proxy => "Proxy",
            Self::History => "HTTP History",
            Self::WebSocket => "WebSocket",
            Self::Repeater => "Repeater",
            Self::Settings => "Settings",
            Self::Intruder => "Intruder",
            Self::Decoder => "Decoder",
        }
    }

    pub const fn short_label(self) -> &'static str {
        match self {
            Self::Proxy => "Proxy",
            Self::History => "History",
            Self::WebSocket => "WebSocket",
            Self::Repeater => "Repeater",
            Self::Settings => "Settings",
            Self::Intruder => "Intruder",
            Self::Decoder => "Decoder",
        }
    }

    pub const fn shortcut(self) -> &'static str {
        match self {
            Self::Proxy => "^1",
            Self::History => "^2",
            Self::WebSocket => "^7",
            Self::Repeater => "^3",
            Self::Settings => "^4",
            Self::Intruder => "^5",
            Self::Decoder => "^6",
        }
    }

    pub const fn uses_context(self) -> bool {
        // Repeater and Intruder render their own response inspectors, so the
        // shared context pane would duplicate it and waste width.
        matches!(self, Self::Proxy | Self::History)
    }

    pub const fn is_primary(self) -> bool {
        matches!(
            self,
            Self::Proxy
                | Self::History
                | Self::WebSocket
                | Self::Repeater
                | Self::Intruder
                | Self::Decoder
                | Self::Settings
        )
    }

    pub const fn next(self) -> Self {
        match self {
            Self::Proxy => Self::History,
            Self::History => Self::WebSocket,
            Self::WebSocket => Self::Repeater,
            Self::Repeater => Self::Settings,
            Self::Settings => Self::Intruder,
            Self::Intruder => Self::Decoder,
            Self::Decoder => Self::Proxy,
        }
    }

    pub const fn previous(self) -> Self {
        match self {
            Self::Proxy => Self::Decoder,
            Self::History => Self::Proxy,
            Self::WebSocket => Self::History,
            Self::Repeater => Self::WebSocket,
            Self::Settings => Self::Repeater,
            Self::Intruder => Self::Settings,
            Self::Decoder => Self::Intruder,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    Nav,
    Content,
    Context,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageSide {
    Request,
    Response,
}

impl MessageSide {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Request => "Request",
            Self::Response => "Response",
        }
    }

    pub const fn toggled(self) -> Self {
        match self {
            Self::Request => Self::Response,
            Self::Response => Self::Request,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InspectorView {
    Raw,
    Headers,
    Body,
}

impl InspectorView {
    pub const ALL: [Self; 3] = [Self::Raw, Self::Headers, Self::Body];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Raw => "Raw",
            Self::Headers => "Headers",
            Self::Body => "Body",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionId {
    ForwardRequest,
    DropRequest,
    ForwardModified,
    InspectRequest,
    ReplayRequest,
    EditRequest,
    ToggleProxy,
    ToggleInterception,
    ToggleInspector,
    ToggleRedaction,
    NewRepeaterTab,
    CloseRepeaterTab,
    DuplicateRepeaterTab,
    SendRepeater,
    CancelRepeater,
    ResetRepeater,
    ClearRepeaterResponse,
    ToggleRepeaterRedirects,
    ClearFilters,
    Search,
    CycleMethod,
    CycleStatus,
    CycleHost,
    DecoderExecute,
    DecoderAddStep,
    DecoderRemoveStep,
    DecoderMoveStepUp,
    DecoderMoveStepDown,
    DecoderSwap,
    DecoderClear,
    DecoderCopy,
    DecoderSendToRepeater,
    DecoderTransformPrev,
    DecoderTransformNext,
    DecoderToggleDirection,
    DecoderHistory,
    DecoderPreview,
    SendRepeaterRequestToDecoder,
    SendRepeaterResponseToDecoder,
    IntruderViewToggle,
    IntruderEditRequest,
    IntruderMarkPosition,
    IntruderClearPositions,
    IntruderTogglePosition,
    IntruderNextSet,
    IntruderAddList,
    IntruderRenameList,
    IntruderDeleteList,
    IntruderImportWordlist,
    IntruderStrategy,
    IntruderStart,
    IntruderPause,
    IntruderCancel,
    IntruderBaseline,
    IntruderCycleSort,
    IntruderSendToRepeater,
    WebSocketForward,
    WebSocketDrop,
    WebSocketModify,
    WebSocketNextPaused,
    WebSocketClear,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingId {
    BindAddress,
    Port,
    Interception,
    TlsInterception,
    VerifyTls,
    MaxBody,
    MaxResponse,
    MaxConnections,
    ConnectTimeout,
    UpstreamTimeout,
    IdleTimeout,
    InterceptTimeout,
    AllowPrivateUpstreams,
    Redaction,
    Accent,
    Mouse,
    PersistBodies,
    PersistSensitive,
    Scope,
    CertificateAuthority,
    CaFingerprint,
    DatabasePath,
}

impl SettingId {
    pub const ALL: [Self; 22] = [
        Self::BindAddress,
        Self::Port,
        Self::Interception,
        Self::TlsInterception,
        Self::VerifyTls,
        Self::MaxBody,
        Self::MaxResponse,
        Self::MaxConnections,
        Self::ConnectTimeout,
        Self::UpstreamTimeout,
        Self::IdleTimeout,
        Self::InterceptTimeout,
        Self::AllowPrivateUpstreams,
        Self::Redaction,
        Self::Accent,
        Self::Mouse,
        Self::PersistBodies,
        Self::PersistSensitive,
        Self::Scope,
        Self::CertificateAuthority,
        Self::CaFingerprint,
        Self::DatabasePath,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::BindAddress => "Bind address",
            Self::Port => "Listen port",
            Self::Interception => "HTTP interception",
            Self::TlsInterception => "HTTPS TLS interception",
            Self::VerifyTls => "Upstream TLS verification",
            Self::MaxBody => "Request body limit",
            Self::MaxResponse => "Response body limit",
            Self::MaxConnections => "Concurrent connections",
            Self::ConnectTimeout => "Connect timeout",
            Self::UpstreamTimeout => "Upstream response timeout",
            Self::IdleTimeout => "Idle timeout",
            Self::InterceptTimeout => "Interception timeout",
            Self::AllowPrivateUpstreams => "Private upstreams",
            Self::Redaction => "Redact sensitive headers",
            Self::Accent => "Accent",
            Self::Mouse => "Mouse support",
            Self::PersistBodies => "Persist bodies",
            Self::PersistSensitive => "Persist sensitive headers",
            Self::Scope => "Target scope",
            Self::CertificateAuthority => "Local certificate authority",
            Self::CaFingerprint => "CA fingerprint",
            Self::DatabasePath => "Database",
        }
    }

    pub const fn section(self) -> &'static str {
        match self {
            Self::BindAddress
            | Self::Port
            | Self::Interception
            | Self::TlsInterception
            | Self::VerifyTls
            | Self::MaxBody
            | Self::MaxResponse
            | Self::MaxConnections
            | Self::ConnectTimeout
            | Self::UpstreamTimeout
            | Self::IdleTimeout
            | Self::InterceptTimeout
            | Self::AllowPrivateUpstreams => "PROXY",
            Self::Redaction | Self::Accent | Self::Mouse => "INTERFACE & PRIVACY",
            Self::PersistBodies | Self::PersistSensitive | Self::Scope => "STORAGE & SCOPE",
            Self::CertificateAuthority | Self::CaFingerprint | Self::DatabasePath => {
                "SECURITY & STORAGE"
            }
        }
    }

    pub const fn is_editable(self) -> bool {
        matches!(
            self,
            Self::BindAddress
                | Self::Port
                | Self::MaxBody
                | Self::MaxResponse
                | Self::MaxConnections
                | Self::ConnectTimeout
                | Self::UpstreamTimeout
                | Self::IdleTimeout
                | Self::InterceptTimeout
        )
    }

    pub const fn is_toggle(self) -> bool {
        matches!(
            self,
            Self::Interception
                | Self::TlsInterception
                | Self::VerifyTls
                | Self::AllowPrivateUpstreams
                | Self::Redaction
                | Self::Accent
                | Self::Mouse
                | Self::PersistBodies
                | Self::PersistSensitive
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HitTarget {
    Nav(NavSection),
    ProxyRow(TrafficId),
    InterceptionRow(TrafficId),
    HistoryRow(TrafficId),
    Action(ActionId),
    InspectorSide(MessageSide),
    InspectorView(InspectorView),
    RepeaterView(crate::state::RepeaterView),
    InspectorClose,
    RepeaterTab(usize),
    RepeaterEditor,
    DecoderEditor,
    DecoderHistoryRow(usize),
    IntruderCandidate(usize),
    IntruderPositionRow(usize),
    IntruderResultRow(usize),
    IntruderEditor,
    WebSocketConnection(WebSocketConnectionId),
    WebSocketFrame(WebSocketFrameId),
    InterceptionEditor,
    Setting(SettingId),
    SessionRow(usize),
    ScopeRuleRow(usize),
    PaletteRow(usize),
    MenuItem(usize),
    Splitter(DragTarget),
    SearchField,
    DismissOverlay,
    OverlaySurface,
    Confirm(bool),
}

#[derive(Debug, Clone)]
pub struct Hit {
    pub rect: Rect,
    pub target: HitTarget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScrollRegion {
    ProxyList,
    InterceptionQueue,
    HistoryList,
    Inspector,
    RepeaterEditor,
    DecoderEditor,
    IntruderRequest,
    IntruderResults,
    IntruderInspector,
    IntruderPreview,
    DecoderOutput,
    DecoderPipeline,
    DecoderHistory,
    InterceptionEditor,
    WebSocketConnections,
    WebSocketFrames,
    WebSocketInspector,
    Settings,
    Palette,
    Menu,
}

#[derive(Debug, Clone, Copy)]
pub struct ScrollZone {
    pub rect: Rect,
    pub region: ScrollRegion,
}

#[derive(Debug, Default)]
pub struct RenderOutput {
    pub hits: Vec<Hit>,
    pub zones: Vec<ScrollZone>,
    pub area: Rect,
    pub repeater_rows: u16,
    pub repeater_cols: u16,
    pub editor_origin: Option<ratatui::layout::Position>,
    pub editor_gutter: u16,
}

impl RenderOutput {
    pub fn hit(&mut self, rect: Rect, target: HitTarget) {
        if rect.width > 0 && rect.height > 0 {
            self.hits.push(Hit { rect, target });
        }
    }

    pub fn zone(&mut self, rect: Rect, region: ScrollRegion) {
        if rect.width > 0 && rect.height > 0 {
            self.zones.push(ScrollZone { rect, region });
        }
    }

    pub fn hit_at(&self, x: u16, y: u16) -> Option<&HitTarget> {
        let position = ratatui::layout::Position::new(x, y);
        self.hits
            .iter()
            .rev()
            .find(|hit| hit.rect.contains(position))
            .map(|hit| &hit.target)
    }

    pub fn zone_at(&self, x: u16, y: u16) -> Option<ScrollRegion> {
        let position = ratatui::layout::Position::new(x, y);
        self.zones
            .iter()
            .rev()
            .find(|zone| zone.rect.contains(position))
            .map(|zone| zone.region)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn navigation_order_wraps() {
        assert_eq!(NavSection::Proxy.previous(), NavSection::Decoder);
        assert_eq!(NavSection::Settings.next(), NavSection::Intruder);
        assert_eq!(NavSection::Decoder.next(), NavSection::Proxy);
        assert_eq!(NavSection::History.next(), NavSection::WebSocket);
        assert_eq!(NavSection::WebSocket.previous(), NavSection::History);
        assert_eq!(NavSection::WebSocket.shortcut(), "^7");
        assert!(NavSection::History.uses_context());
        assert!(!NavSection::Repeater.uses_context());
        assert!(!NavSection::Settings.uses_context());
        // Intruder renders its own inspector, so it does not take the shared
        // context pane.
        assert!(!NavSection::Intruder.uses_context());
        assert!(NavSection::Proxy.is_primary());
        assert!(NavSection::Decoder.is_primary());
        assert!(NavSection::Intruder.is_primary());
        assert!(NavSection::WebSocket.is_primary());
        assert!(!NavSection::WebSocket.uses_context());
        assert_eq!(NavSection::PRIMARY.len(), NavSection::ALL.len());
    }

    #[test]
    fn hit_testing_prefers_the_most_recent_registration() {
        let mut output = RenderOutput::default();
        output.hit(
            Rect::new(0, 0, 10, 10),
            HitTarget::Action(ActionId::ForwardRequest),
        );
        output.hit(
            Rect::new(2, 2, 3, 3),
            HitTarget::Action(ActionId::DropRequest),
        );

        assert_eq!(
            output.hit_at(3, 3),
            Some(&HitTarget::Action(ActionId::DropRequest))
        );
        assert_eq!(
            output.hit_at(8, 8),
            Some(&HitTarget::Action(ActionId::ForwardRequest))
        );
        assert!(output.hit_at(50, 50).is_none());
    }

    #[test]
    fn settings_have_distinct_editable_and_toggle_fields() {
        assert!(SettingId::Port.is_editable());
        assert!(SettingId::Redaction.is_toggle());
        assert!(!SettingId::Scope.is_editable());
        assert!(!SettingId::Scope.is_toggle());
        assert_eq!(SettingId::ALL.len(), 22);
    }
}
