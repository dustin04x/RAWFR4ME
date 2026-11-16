//! HTTP/1.x document parsing for RAWFRAME.
//!
//! This crate parses the text an operator sees in the Repeater and in tests. It
//! is intentionally not a wire protocol implementation: message framing,
//! chunked transfer decoding, connection reuse, and TLS belong to the proxy
//! engine in a later milestone.

mod error;
mod parsing;

pub use error::ParseError;
pub use parsing::{parse_request, parse_response};
