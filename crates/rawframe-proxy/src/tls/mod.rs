//! TLS interception: local CA, leaf issuance, and TLS session helpers.
//!
//! This module is intentionally isolated from request routing. It never disables
//! upstream certificate verification, never exposes private key material, and
//! only supports explicitly enabled interception for HTTP/1.1 inside TLS.

use std::path::PathBuf;
use std::sync::Arc;

use rawframe_core::TlsStatus;
use rustls::ClientConfig;
use tokio::sync::{Mutex, RwLock};

pub mod ca;
pub mod intercept;
pub mod leaf;

pub use ca::{CaInfo, CaManager, CaPaths, CaStatus};
pub use leaf::LeafIssuer;

#[derive(Clone)]
pub struct TlsRuntime {
    pub ca: Arc<CaManager>,
    pub leaf_issuer: LeafIssuer,
    pub upstream_config: Arc<ClientConfig>,
}

/// Session-scoped TLS interception controller. Startup config decides the
/// initial state; the TUI may explicitly enable/disable it. Enabling loads or
/// creates the local CA and keeps signing material in memory only.
pub struct TlsController {
    ca_dir: PathBuf,
    upstream_trust_file: Option<PathBuf>,
    runtime: RwLock<Option<TlsRuntime>>,
    /// Serializes enable/disable transitions so a late enable cannot resurrect
    /// interception after an explicit disable.
    transition: Mutex<()>,
}

impl TlsController {
    pub fn new(ca_dir: PathBuf, upstream_trust_file: Option<PathBuf>) -> Self {
        Self {
            ca_dir,
            upstream_trust_file,
            runtime: RwLock::new(None),
            transition: Mutex::new(()),
        }
    }

    pub async fn is_enabled(&self) -> bool {
        self.runtime.read().await.is_some()
    }

    /// Returns a snapshot of the current interception runtime. A session that
    /// obtains this snapshot keeps it until it closes, even if interception is
    /// disabled meanwhile; new CONNECTs after disable use the opaque path.
    pub async fn runtime(&self) -> Option<TlsRuntime> {
        self.runtime.read().await.clone()
    }

    /// Explicitly enables interception. Returns the public CA status on success.
    /// Never replaces existing CA material silently.
    pub async fn enable(&self) -> Result<TlsStatus, String> {
        let _transition = self.transition.lock().await;
        if let Some(runtime) = self.runtime().await {
            return Ok(TlsStatus::enabled(
                runtime.ca.cert_path().display().to_string(),
                runtime.ca.fingerprint_sha256().to_string(),
            ));
        }
        let paths = CaPaths::new(self.ca_dir.clone());
        let loaded = tokio::task::spawn_blocking(move || {
            let ca = CaManager::load_or_generate(&paths)?;
            Ok::<_, crate::error::ProxyError>(Arc::new(ca))
        })
        .await
        .map_err(|_| "CA initialization task failed".to_string())?
        .map_err(|error| error.to_string())?;
        let upstream = crate::tls::intercept::build_upstream_tls_config_with_trust_file(
            self.upstream_trust_file.as_deref(),
        )
        .map_err(|error| error.to_string())?;
        let runtime = TlsRuntime {
            ca: loaded.clone(),
            leaf_issuer: LeafIssuer::new(loaded),
            upstream_config: Arc::new(upstream),
        };
        let status = TlsStatus::enabled(
            runtime.ca.cert_path().display().to_string(),
            runtime.ca.fingerprint_sha256().to_string(),
        );
        *self.runtime.write().await = Some(runtime);
        Ok(status)
    }

    /// Disabling drops the in-memory CA/leaf signing material. CONNECT returns
    /// to the opaque tunnel path immediately.
    pub async fn disable(&self) {
        let _transition = self.transition.lock().await;
        *self.runtime.write().await = None;
    }
}
