use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, KeyPair, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::sync::Mutex;

use crate::error::ProxyError;
use crate::tls::ca::CaManager;

#[allow(dead_code)]
const DEFAULT_CACHE_CAPACITY: usize = 256;

/// A cached leaf certificate chain and key for a validated destination identity.
#[derive(Clone)]
pub struct LeafMaterial {
    pub cert_chain: Vec<CertificateDer<'static>>,
    key_der: Vec<u8>,
}

impl LeafMaterial {
    pub fn key(&self) -> Result<PrivateKeyDer<'static>, ProxyError> {
        Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            self.key_der.clone(),
        )))
    }
}

type PublishedLeaf = Result<LeafMaterial, String>;
type IssuanceSlot = Arc<Mutex<Option<PublishedLeaf>>>;

#[derive(Clone)]
pub struct LeafIssuer {
    ca: Arc<CaManager>,
    cache: Arc<Mutex<LeafCache>>,
}

struct LeafCache {
    entries: HashMap<String, LeafMaterial>,
    order: Vec<String>,
    capacity: usize,
    in_flight: HashMap<String, IssuanceSlot>,
}

#[allow(dead_code)]
impl LeafIssuer {
    pub fn new(ca: Arc<CaManager>) -> Self {
        Self::with_capacity(ca, DEFAULT_CACHE_CAPACITY)
    }

    pub fn with_capacity(ca: Arc<CaManager>, capacity: usize) -> Self {
        Self {
            ca,
            cache: Arc::new(Mutex::new(LeafCache {
                entries: HashMap::new(),
                order: Vec::new(),
                capacity: capacity.max(1),
                in_flight: HashMap::new(),
            })),
        }
    }

    /// Issues or returns a cached leaf for a validated host (DNS name or IP).
    /// The host must already be validated by destination/scope policy.
    pub async fn leaf_for_host(&self, host: &str) -> Result<LeafMaterial, ProxyError> {
        let identity = normalize_identity(host).ok_or_else(|| {
            ProxyError::Configuration("refusing to issue leaf for invalid hostname".into())
        })?;
        // Per-host issuance is serialized by a mutex stored in the cache. A
        // Notify-based handshake can lose a wakeup if the issuing task finishes
        // between lookup and `notified().await`; the mutex also publishes the
        // result, so waiters either reuse the certificate or a deterministic
        // error instead of hanging.
        let slot = {
            let mut cache = self.cache.lock().await;
            if let Some(existing) = cache.entries.get(&identity) {
                return Ok(existing.clone());
            }
            cache
                .in_flight
                .entry(identity.clone())
                .or_insert_with(|| Arc::new(Mutex::new(None)))
                .clone()
        };
        let mut slot_guard = slot.lock().await;
        if let Some(result) = slot_guard.as_ref() {
            return result.clone().map_err(ProxyError::Configuration);
        }
        // Another waiter may have populated the cache before this task got the
        // per-host lock.
        {
            let cache = self.cache.lock().await;
            if let Some(existing) = cache.entries.get(&identity) {
                *slot_guard = Some(Ok(existing.clone()));
                return Ok(existing.clone());
            }
        }

        let result = self.issue(&identity).await;
        let published = result
            .as_ref()
            .map(|material| material.clone())
            .map_err(ToString::to_string);
        {
            let mut cache = self.cache.lock().await;
            if let Ok(material) = &published {
                cache.insert(identity.clone(), material.clone());
            }
            if cache
                .in_flight
                .get(&identity)
                .is_some_and(|current| Arc::ptr_eq(current, &slot))
            {
                cache.in_flight.remove(&identity);
            }
        }
        *slot_guard = Some(published.clone());
        published.map_err(ProxyError::Configuration)
    }

    async fn issue(&self, identity: &str) -> Result<LeafMaterial, ProxyError> {
        let ca = self.ca.clone();
        let identity = identity.to_string();
        tokio::task::spawn_blocking(move || issue_leaf_blocking(&ca, &identity))
            .await
            .map_err(|_| {
                ProxyError::Configuration("leaf certificate issuance task failed".into())
            })?
    }

    #[cfg(test)]
    pub async fn cache_len(&self) -> usize {
        self.cache.lock().await.entries.len()
    }
}

impl LeafCache {
    fn insert(&mut self, key: String, value: LeafMaterial) {
        if let std::collections::hash_map::Entry::Occupied(mut e) = self.entries.entry(key.clone())
        {
            e.insert(value);
            return;
        }
        if self.entries.len() >= self.capacity
            && let Some(oldest) = self.order.first().cloned()
        {
            self.order.remove(0);
            self.entries.remove(&oldest);
        }
        self.order.push(key.clone());
        self.entries.insert(key, value);
    }
}

fn issue_leaf_blocking(ca: &CaManager, identity: &str) -> Result<LeafMaterial, ProxyError> {
    let mut params = CertificateParams::new(vec![identity.to_string()]).map_err(|_| {
        ProxyError::Configuration("refusing to issue leaf for invalid subject name".into())
    })?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, identity);
    params.distinguished_name = dn;
    if let Ok(ip) = identity.parse::<IpAddr>() {
        params.subject_alt_names = vec![SanType::IpAddress(ip)];
    } else {
        params.subject_alt_names = vec![SanType::DnsName(identity.try_into().map_err(|_| {
            ProxyError::Configuration("refusing to issue leaf for invalid DNS name".into())
        })?)];
    }
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.use_authority_key_identifier_extension = true;
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::hours(1);
    params.not_after = now + time::Duration::days(825);

    let leaf_key = KeyPair::generate()
        .map_err(|e| ProxyError::Configuration(format!("failed to generate leaf key pair: {e}")))?;
    let leaf_cert = params
        .signed_by(&leaf_key, ca.cert(), ca.key_pair())
        .map_err(|e| ProxyError::Configuration(format!("failed to sign leaf certificate: {e}")))?;
    let cert_der = leaf_cert.der().to_vec();
    let key_der = leaf_key.serialize_der();
    let chain = vec![CertificateDer::from(cert_der), ca_cert_der(ca)?];
    Ok(LeafMaterial {
        cert_chain: chain,
        key_der,
    })
}

fn ca_cert_der(ca: &CaManager) -> Result<CertificateDer<'static>, ProxyError> {
    let der = pem_first_der(ca.cert_pem())
        .map_err(|_| ProxyError::Configuration("failed to parse CA certificate DER".into()))?;
    Ok(CertificateDer::from(der))
}

fn pem_first_der(pem: &str) -> Result<Vec<u8>, ()> {
    use rustls_pemfile::Item;
    let mut cursor = std::io::Cursor::new(pem.as_bytes());
    for item in rustls_pemfile::read_all(&mut cursor) {
        match item.map_err(|_| ())? {
            Item::X509Certificate(der) => return Ok(der.to_vec()),
            _ => continue,
        }
    }
    Err(())
}

pub fn normalize_identity(host: &str) -> Option<String> {
    let host = host.trim().trim_end_matches('.');
    if host.is_empty() {
        return None;
    }
    if host
        .chars()
        .any(|c| c.is_control() || c.is_whitespace() || matches!(c, '/' | '\\' | '@' | '\0'))
    {
        return None;
    }
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        return None;
    }
    if host.parse::<IpAddr>().is_ok() {
        return Some(host.to_string());
    }
    let lower = host.to_ascii_lowercase();
    if lower.len() > 253 || lower.starts_with('.') || lower.contains("..") {
        return None;
    }
    Some(lower)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::ca::CaPaths;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "rawframe-leaf-{name}-{nanos}-{}",
            std::process::id()
        ))
    }

    #[tokio::test]
    async fn issues_and_caches_leaf() {
        let dir = temp_dir("cache");
        let paths = CaPaths::new(&dir);
        let ca = Arc::new(CaManager::load_or_generate(&paths).unwrap());
        let issuer = LeafIssuer::with_capacity(ca, 8);
        let a = issuer.leaf_for_host("example.test").await.unwrap();
        let b = issuer.leaf_for_host("example.test").await.unwrap();
        assert_eq!(a.cert_chain.len(), b.cert_chain.len());
        assert!(!a.cert_chain.is_empty());
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn leaf_has_a_bounded_validity_period() {
        use x509_parser::prelude::FromDer;

        let dir = temp_dir("validity");
        let paths = CaPaths::new(&dir);
        let ca = Arc::new(CaManager::load_or_generate(&paths).unwrap());
        let issuer = LeafIssuer::new(ca);
        let leaf = issuer.leaf_for_host("validity.test").await.unwrap();
        let (_, cert) =
            x509_parser::certificate::X509Certificate::from_der(leaf.cert_chain[0].as_ref())
                .unwrap();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let not_before = cert.validity().not_before.timestamp();
        let not_after = cert.validity().not_after.timestamp();
        assert!(not_before <= now, "leaf must already be valid");
        assert!(not_after > now, "leaf must not be expired");
        assert!(
            not_after - not_before <= 900 * 24 * 60 * 60,
            "leaf validity must stay bounded"
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn regeneration_invalidates_previously_issued_leaf_trust() {
        use x509_parser::prelude::FromDer;

        let dir = temp_dir("regen-trust");
        let paths = CaPaths::new(&dir);
        let old_ca = Arc::new(CaManager::load_or_generate(&paths).unwrap());
        let old_ca_cert = old_ca.cert_pem().to_string();
        let issuer = LeafIssuer::new(old_ca);
        let leaf = issuer.leaf_for_host("regen.test").await.unwrap();

        let new_ca = CaManager::regenerate(&paths).unwrap();
        let new_ca_cert = new_ca.cert_pem().to_string();
        assert_ne!(old_ca_cert, new_ca_cert);

        let old_der = pem_first_der(&old_ca_cert).unwrap();
        let new_der = pem_first_der(&new_ca_cert).unwrap();
        let (_, old_x509) = x509_parser::certificate::X509Certificate::from_der(&old_der).unwrap();
        let (_, new_x509) = x509_parser::certificate::X509Certificate::from_der(&new_der).unwrap();
        let (_, leaf_x509) =
            x509_parser::certificate::X509Certificate::from_der(leaf.cert_chain[0].as_ref())
                .unwrap();

        assert!(
            leaf_x509
                .verify_signature(Some(old_x509.public_key()))
                .is_ok(),
            "leaf must verify against the issuing CA"
        );
        assert!(
            leaf_x509
                .verify_signature(Some(new_x509.public_key()))
                .is_err(),
            "regenerated CA must not validate leaves from the old CA"
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn dns_leaf_has_dns_san_and_server_auth_eku() {
        use x509_parser::prelude::{FromDer, GeneralName};

        let dir = temp_dir("san");
        let paths = CaPaths::new(&dir);
        let ca = Arc::new(CaManager::load_or_generate(&paths).unwrap());
        let issuer = LeafIssuer::new(ca);
        let leaf = issuer.leaf_for_host("Example.Test").await.unwrap();
        let (_, cert) =
            x509_parser::certificate::X509Certificate::from_der(leaf.cert_chain[0].as_ref())
                .unwrap();
        let san = cert.subject_alternative_name().unwrap().unwrap();
        assert!(
            san.value
                .general_names
                .iter()
                .any(|name| matches!(name, GeneralName::DNSName("example.test")))
        );
        let eku = cert.extended_key_usage().unwrap().unwrap();
        assert!(eku.value.server_auth);
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn ip_leaf_has_ip_san() {
        use x509_parser::prelude::{FromDer, GeneralName};

        let dir = temp_dir("ip-san");
        let paths = CaPaths::new(&dir);
        let ca = Arc::new(CaManager::load_or_generate(&paths).unwrap());
        let issuer = LeafIssuer::new(ca);
        let leaf = issuer.leaf_for_host("127.0.0.1").await.unwrap();
        let (_, cert) =
            x509_parser::certificate::X509Certificate::from_der(leaf.cert_chain[0].as_ref())
                .unwrap();
        let san = cert.subject_alternative_name().unwrap().unwrap();
        assert!(matches!(
            san.value.general_names.first(),
            Some(GeneralName::IPAddress(_))
        ));
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn issues_ip_san_leaf() {
        let dir = temp_dir("ip");
        let paths = CaPaths::new(&dir);
        let ca = Arc::new(CaManager::load_or_generate(&paths).unwrap());
        let issuer = LeafIssuer::new(ca);
        let a = issuer.leaf_for_host("127.0.0.1").await.unwrap();
        assert!(!a.cert_chain.is_empty());
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_requests_for_same_host_all_complete() {
        use std::sync::Arc as StdArc;

        let dir = temp_dir("concurrent");
        let paths = CaPaths::new(&dir);
        let ca = Arc::new(CaManager::load_or_generate(&paths).unwrap());
        let issuer = StdArc::new(LeafIssuer::with_capacity(ca, 8));

        let mut tasks = Vec::new();
        for _ in 0..32 {
            let issuer = StdArc::clone(&issuer);
            tasks.push(tokio::spawn(async move {
                tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    issuer.leaf_for_host("concurrent.test"),
                )
                .await
                .expect("concurrent leaf issuance timed out")
                .expect("concurrent leaf issuance failed")
            }));
        }
        for task in tasks {
            let leaf = task.await.expect("leaf issuance task panicked");
            assert!(!leaf.cert_chain.is_empty());
        }
        assert_eq!(issuer.cache_len().await, 1, "one leaf per identity");
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn rejects_invalid_hostname() {
        let dir = temp_dir("bad");
        let paths = CaPaths::new(&dir);
        let ca = Arc::new(CaManager::load_or_generate(&paths).unwrap());
        let issuer = LeafIssuer::new(ca);
        assert!(issuer.leaf_for_host("bad host").await.is_err());
        assert!(issuer.leaf_for_host("").await.is_err());
        assert!(issuer.leaf_for_host("../evil").await.is_err());
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn cache_is_bounded() {
        let dir = temp_dir("bound");
        let paths = CaPaths::new(&dir);
        let ca = Arc::new(CaManager::load_or_generate(&paths).unwrap());
        let issuer = LeafIssuer::with_capacity(ca, 2);
        for i in 0..5 {
            let _ = issuer.leaf_for_host(&format!("h{i}.test")).await.unwrap();
        }
        assert!(issuer.cache_len().await <= 2);
        let _ = fs::remove_dir_all(dir);
    }
}
