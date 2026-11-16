use thiserror::Error;

/// Errors produced while parsing an authored HTTP document.
///
/// This parser is for Repeater documents and test fixtures, not for forwarding
/// wire traffic: bodies are treated as UTF-8 text and framing headers are not
/// enforced. Wire parsing and framing validation belong to the proxy engine.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("message is empty")]
    Empty,
    #[error("message has no complete start line or headers")]
    Incomplete,
    #[error("malformed HTTP message: {0}")]
    Malformed(String),
    #[error("message has too many header fields")]
    TooManyHeaders,
    #[error("request has no Host field and no absolute target authority")]
    MissingHost,
    #[error("invalid authority: {0}")]
    InvalidAuthority(String),
    #[error("invalid port: {0}")]
    InvalidPort(String),
    #[error("header value is not valid UTF-8")]
    InvalidHeaderValue,
    #[error("invalid request target")]
    InvalidTarget,
    #[error("response has no valid status code")]
    InvalidStatus,
}
