//! Bounded Intruder execution for RAWFRAME.
//!
//! The Intruder does not have its own HTTP stack. Every generated request goes
//! through the Repeater engine, which resolves the destination once, validates
//! every resolved address, enforces the live scope, and verifies upstream TLS.
//! This crate adds the attack-specific concerns: deterministic plans, a
//! conservative request rate, bounded concurrency, pause/resume, cancellation, a
//! total duration ceiling, and bounded response capture.

mod engine;
mod service;
mod wordlist;

pub use engine::{
    IntruderEngine, MAX_CAPTURED_RESPONSE_BYTES, MAX_GENERATED_REQUEST_BODY, RateGate,
    combination_slots, intruder_config, planned_id, run_attack,
};
pub use service::{run_service, wordlist_command};
pub use wordlist::load_wordlist;
