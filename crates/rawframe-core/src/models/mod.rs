//! Shared domain models. Nothing in this module performs I/O.

pub mod certificate;
pub mod config;
pub mod headers;
pub mod message;
pub mod session;
pub mod traffic;
pub mod websocket;

pub use certificate::CertificateMetadata;
pub use config::{
    AccentPreset, AppConfig, AppearanceConfiguration, ConfigError, InterceptionAction,
    InterceptionRule, ProxyConfiguration, Scope, ScopeError, ScopeParseError, ScopeRule,
    StorageConfiguration,
};
pub use headers::{Header, Headers, SENSITIVE_HEADERS};
pub use message::{HttpRequest, HttpResponse, Scheme, StatusClass};
pub use session::{
    Project, ProjectId, RepeaterId, RepeaterRequest, Session, SessionId, SessionSummary,
};
pub use traffic::{
    EditableHttpRequest, InterceptionMetadata, TrafficEntry, TrafficId, TrafficKind, TrafficSource,
    TrafficState, TrafficTimings, TransitionError, TunnelMetadata, TunnelOutcome,
};
pub use websocket::{
    WebSocketConnection, WebSocketConnectionId, WebSocketConnectionState, WebSocketDirection,
    WebSocketFrame, WebSocketFrameDecision, WebSocketFrameId, WebSocketInterceptionOutcome,
    WebSocketMessage, WebSocketMessageId, WebSocketOpcode,
};
