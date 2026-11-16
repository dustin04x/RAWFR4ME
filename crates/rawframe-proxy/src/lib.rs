//! RAWFRAME's HTTP/1.1 forwarding and opaque CONNECT proxy engine.
//!
//! The proxy is intentionally independent of the terminal interface. It
//! publishes captures and lifecycle changes through [`rawframe_core::AppEvent`]
//! and is controlled through [`rawframe_core::AppCommand`]. HTTPS CONNECT is an
//! opaque tunnel; no TLS is terminated or inspected in this milestone.

mod body;
mod destination;
pub mod error;
mod interception;
mod server;
mod service;
mod tunnel;

pub use error::ProxyError;
pub use server::{ProxyHandle, run_service, start_proxy};

#[doc(hidden)]
pub use destination::address_allowed;
