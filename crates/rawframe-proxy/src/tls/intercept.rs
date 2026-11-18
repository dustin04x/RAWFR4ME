//! TLS interception session helpers.
//!
//! Security invariants:
//! - Upstream TLS verification is always enabled (trusted roots, hostname/SNI verified).
//! - Both legs advertise `h2` then `http/1.1`; the negotiated value is read back
//!   after each handshake and h2 is used only on an exact `h2` match.
//! - Client-facing and upstream TLS sessions negotiate independently.

use std::sync::Arc;

use rawframe_core::h2;
use rustls::pki_types::ServerName;
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::error::ProxyError;
use crate::tls::leaf::{LeafIssuer, LeafMaterial};

/// Builds a client TLS config that always verifies upstream certificates and
/// hostnames using trusted roots. No insecure mode is provided.
/// Builds the upstream client config. `trust_file` is an explicit PEM bundle for
/// lab deployments; the platform store is used when absent. Verification and
/// hostname checks are never disabled.
pub fn build_upstream_tls_config_with_trust_file(
    trust_file: Option<&std::path::Path>,
) -> Result<ClientConfig, ProxyError> {
    let mut roots = RootCertStore::empty();
    let mut added = 0usize;
    match trust_file {
        Some(path) => {
            let pem = std::fs::read(path).map_err(|error| {
                ProxyError::Configuration(format!(
                    "failed to read upstream trust bundle {}: {error}",
                    path.display()
                ))
            })?;
            let mut cursor = std::io::Cursor::new(pem);
            for item in rustls_pemfile::certs(&mut cursor) {
                let cert = item.map_err(|error| {
                    ProxyError::Configuration(format!(
                        "invalid certificate in upstream trust bundle: {error}"
                    ))
                })?;
                if roots.add(cert).is_ok() {
                    added += 1;
                }
            }
        }
        None => {
            let native = rustls_native_certs::load_native_certs();
            for cert in native.certs {
                if roots.add(cert).is_ok() {
                    added += 1;
                }
            }
        }
    }
    if added == 0 {
        return Err(ProxyError::Configuration(
            "no trusted root certificates available for upstream TLS verification".into(),
        ));
    }
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    // Prefer HTTP/2 but keep HTTP/1.1 as a first-class fallback. The proxy reads
    // the negotiated protocol; advertising is not a claim of negotiation.
    config.alpn_protocols = vec![h2::ALPN_H2.to_vec(), h2::ALPN_HTTP11.to_vec()];
    Ok(config)
}

pub fn upstream_connector(config: Arc<ClientConfig>) -> TlsConnector {
    TlsConnector::from(config)
}

pub fn upstream_server_name(host: &str) -> Result<ServerName<'static>, ProxyError> {
    ServerName::try_from(host.to_string())
        .map_err(|_| ProxyError::Configuration("invalid upstream TLS server name".into()))
}

fn certified_key_from_material(material: LeafMaterial) -> Result<Arc<CertifiedKey>, ProxyError> {
    let key = material.key()?;
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|_| ProxyError::Configuration("failed to load issued leaf signing key".into()))?;
    Ok(Arc::new(CertifiedKey::new(
        material.cert_chain,
        signing_key,
    )))
}

/// Builds a per-destination server acceptor that presents a leaf certificate for
/// the validated CONNECT destination and advertises HTTP/2 with an HTTP/1.1
/// fallback via ALPN.
/// SNI, when provided by the client, must match the CONNECT authority host.
pub async fn server_acceptor_for_destination(
    issuer: LeafIssuer,
    destination_host: &str,
) -> Result<TlsAcceptor, ProxyError> {
    let destination = crate::tls::leaf::normalize_identity(destination_host)
        .ok_or_else(|| ProxyError::Configuration("invalid TLS interception destination".into()))?;
    let material = issuer.leaf_for_host(&destination).await?;
    let certified = certified_key_from_material(material)?;
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(FixedResolver {
            certified,
            destination,
        }));
    config.alpn_protocols = vec![h2::ALPN_H2.to_vec(), h2::ALPN_HTTP11.to_vec()];
    Ok(TlsAcceptor::from(Arc::new(config)))
}

#[derive(Debug)]
struct FixedResolver {
    certified: Arc<CertifiedKey>,
    destination: String,
}

impl ResolvesServerCert for FixedResolver {
    fn resolve(&self, client_hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if let Some(sni) = client_hello.server_name()
            && sni.to_ascii_lowercase() != self.destination
        {
            return None;
        }
        Some(self.certified.clone())
    }
}
