//! Core domain types and application contracts for RAWFRAME.
//!
//! This crate is deliberately free of terminal, networking, and database
//! dependencies. It defines:
//!
//! * the shared request/response/traffic models ([`models`]),
//! * the event and command boundary between services and the UI ([`events`]),
//! * history filtering ([`filter`]),
//! * persistence command/event contracts ([`storage`]),
//! * Repeater execution contracts and request validation ([`repeater`]),
//! * terminal-safety primitives for hostile captured data ([`security`]),
//! * clearly labelled simulated traffic used by the demo shell ([`fixtures`]).
//!
//! Confidentiality of captured secrets is preserved by default: sensitive
//! header values are only masked at render time, and bodies are never persisted
//! unless the operator opts in.

pub mod decoder;
pub mod events;
pub mod filter;
pub mod fixtures;
pub mod h2;
pub mod intruder;
pub mod models;
pub mod repeater;
pub mod security;
pub mod storage;

pub use decoder::{
    DECODER_DEFAULT_MAX_INPUT, DECODER_DEFAULT_MAX_OUTPUT, Direction, OutputFormat,
    PipelineFailure, PipelineRun, PipelineStep, Transform, TransformError, TransformLimits,
    TransformOutput, execute_pipeline, transform,
};
pub use events::{
    AppCommand, AppEvent, CommandSender, EventBus, EventReceiver, EventSendError, EventSender,
    Notice, NoticeLevel, ProxyState, TlsStatus,
};
pub use filter::{HistoryFilter, StatusFilter};
pub use h2::{HTTP2_VERSION, is_http2_version, protocol_label};
pub use intruder::{
    AttackPlan, DEFAULT_CONCURRENCY, DEFAULT_MAX_DURATION_SECS, DEFAULT_RATE_PER_SECOND,
    INTRUDER_ID_BASE, IntruderCommand, IntruderCommandSender, IntruderEvent, IntruderLaunch,
    IntruderOutcome, IntruderPhase, IntruderResult, IntruderStopReason, IntruderSummary,
    IntruderTemplate, MARKER, MAX_CONCURRENCY, MAX_DURATION_SECS, MAX_GENERATED_REQUESTS,
    MAX_PAYLOAD_BYTES, MAX_PAYLOAD_SETS, MAX_PAYLOADS_PER_SET, MAX_POSITIONS, MAX_RATE_PER_SECOND,
    MAX_WORDLIST_BYTES, MAX_WORDLIST_LINE_BYTES, PayloadError, PayloadSet, PayloadSource,
    PlanError, Position, PositionArea, PositionId, ResultFilter, ResultSort, Strategy,
    TemplateAnalysis, TemplateError, WordlistOutcome, build_plan, intruder_entry, plan_count,
    sorted_indices,
};
pub use models::{
    AccentPreset, AppConfig, CertificateMetadata, EditableHttpRequest, Header, Headers,
    HttpRequest, HttpResponse, InterceptionMetadata, InterceptionRule, Project, ProjectId,
    ProxyConfiguration, RepeaterRequest, Scheme, Scope, Session, SessionId, SessionSummary,
    StatusClass, StorageConfiguration, TrafficEntry, TrafficId, TrafficKind, TrafficSource,
    TrafficState, TunnelMetadata, TunnelOutcome,
};
pub use repeater::{
    ExecutionComparison, HeaderDifference, RedirectHop, RepeaterCommand, RepeaterCommandSender,
    RepeaterEvent, RepeaterExecutionPhase, RepeaterResult, RepeaterTimings, RequestValidationError,
    compare_executions, validate_request,
};
pub use storage::{
    STORAGE_COMMAND_QUEUE, StorageCommand, StorageCommandReceiver, StorageCommandSender,
    StorageEvent, StoragePolicy, StorageStatus,
};
