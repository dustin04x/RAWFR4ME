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
mod tls;
mod tunnel;

pub use error::ProxyError;
pub use interception::InterceptDecision;
pub use server::{ProxyHandle, run_service, start_proxy};
pub mod tls_api {
    pub use crate::tls::{CaInfo, CaManager, CaPaths, CaStatus};
}

#[doc(hidden)]
pub use destination::address_allowed;
