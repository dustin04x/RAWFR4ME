//! Core domain types and application contracts for RAWFRAME.
//!
//! This crate is deliberately free of terminal, networking, and database
//! dependencies. It defines:
//!
//! * the shared request/response/traffic models ([`models`]),
//! * the event and command boundary between services and the UI ([`events`]),
//! * history filtering ([`filter`]),
//! * terminal-safety primitives for hostile captured data ([`security`]),
//! * clearly labelled simulated traffic used by the demo shell ([`fixtures`]).
//!
//! Confidentiality of captured secrets is preserved by default: sensitive
//! header values are only masked at render time, and bodies are never persisted
//! unless the operator opts in.

pub mod events;
pub mod filter;
pub mod fixtures;
pub mod models;
pub mod security;

pub use events::{
    AppCommand, AppEvent, CommandSender, EventBus, EventReceiver, EventSendError, EventSender,
    Notice, NoticeLevel, ProxyState,
};
pub use filter::{HistoryFilter, StatusFilter};
pub use models::{
    AccentPreset, AppConfig, CertificateMetadata, EditableHttpRequest, Header, Headers,
    HttpRequest, HttpResponse, InterceptionMetadata, InterceptionRule, ProxyConfiguration,
    RepeaterRequest, Scheme, Scope, Session, StatusClass, StorageConfiguration, TrafficEntry,
    TrafficId, TrafficKind, TrafficSource, TrafficState, TunnelMetadata, TunnelOutcome,
};
