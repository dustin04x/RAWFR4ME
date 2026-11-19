//! SQLite-backed persistence for RAWFRAME sessions and captured traffic.
//!
//! The crate is deliberately isolated: `rawframe-core` defines the command and
//! event contracts, this crate implements them, and only the CLI links both. The
//! proxy and the TUI never depend on SQLite.
//!
//! Guarantees:
//! - redaction happens before values reach SQL, on the storage policy's terms;
//! - bodies are stored as `NULL` unless the operator opted in;
//! - one writer thread owns the connection, so the proxy never blocks on disk;
//! - schema changes are versioned migrations, applied transactionally;
//! - a corrupt, full, or unavailable database disables persistence with an
//!   explicit error instead of crashing the proxy or deleting data.

pub mod error;
pub mod record;
pub mod schema;
pub mod store;
pub mod websocket;
pub mod worker;

pub use error::StoreError;
pub use record::{RESTORED_ID_BASE, TrafficRecord, restored_traffic_id};
pub use schema::SCHEMA_VERSION;
pub use store::{DEFAULT_MAX_BYTES, ExportSummary, Store, default_database_path};
pub use websocket::WebSocketRecording;
pub use worker::{
    RECORD_QUEUE_CAPACITY, StorageHandle, StorageOptions, StorageService, spawn_capture_pump,
};
