//! Typed proxy errors.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("failed to bind proxy listener: {0}")]
    Bind(#[source] std::io::Error),
    #[error("proxy I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid proxy configuration: {0}")]
    Configuration(String),
    #[error("upstream connection failed: {0}")]
    Upstream(String),
}
