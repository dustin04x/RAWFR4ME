//! Independent request execution for RAWFRAME's Repeater.
//!
//! The proxy and Repeater share the request model, scope parser, address policy,
//! and verified upstream TLS configuration, but they have separate connection
//! paths. Repeater never uses the CONNECT tunnel, the local MITM CA, or the
//! interception queue.

mod engine;
mod service;
pub mod websocket;

pub use engine::{
    ExecutionFailure, ExecutionOutcome, RepeaterConfig, RepeaterEngine, entry_from_outcome,
};
pub use service::run_service;
pub use websocket::{WebSocketRepeaterConfig, run_websocket_service};
