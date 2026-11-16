use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use base64::Engine;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
    KeyUsagePurpose,
};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};
use x509_parser::prelude::FromDer;

use crate::error::ProxyError;

const CERT_FILE: &str = "rawframe-ca.crt.pem";
const KEY_FILE: &str = "rawframe-ca.key.pem";

#[derive(Debug, Clone)]
pub struct CaPaths {
    pub dir: PathBuf,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

impl CaPaths {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        let dir = dir.into();
        Self {
            cert_path: dir.join(CERT_FILE),
            key_path: dir.join(KEY_FILE),
            dir,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaStatus {
    Missing,
    Ready,
}

#[derive(Debug, Clone)]
pub struct CaInfo {
    pub status: CaStatus,
    pub cert_path: PathBuf,
    pub fingerprint_sha256: Option<String>,
}

/// Local interception CA. Holds signing material in memory only; callers must
/// never log or expose the private key.
pub struct CaManager {
    paths: CaPaths,
    cert: Certificate,
    key_pair: KeyPair,
    cert_pem: String,
    fingerprint_sha256: String,
}

impl CaManager {
    pub fn paths(dir: impl Into<PathBuf>) -> CaPaths {
        CaPaths::new(dir)
    }

    /// Loads an existing valid CA. Never generates or replaces material.
    pub fn load(paths: &CaPaths) -> Result<Self, ProxyError> {
        if !paths.cert_path.exists() || !paths.key_path.exists() {
            return Err(ProxyError::Configuration(
                "local CA material is missing; generate or initialize it explicitly".into(),
            ));
        }
        let cert_pem = fs::read_to_string(&paths.cert_path).map_err(|e| {
            ProxyError::Configuration(format!("failed to read CA certificate: {e}"))
        })?;
        let key_pem = fs::read_to_string(&paths.key_path).map_err(|e| {
            ProxyError::Configuration(format!("failed to read CA private key: {e}"))
        })?;
        Self::from_pem(paths.clone(), cert_pem, key_pem)
    }

    /// Loads an existing CA or generates one if missing. Never replaces an
    /// existing CA (even if invalid) — invalid existing material is reported.
    pub fn load_or_generate(paths: &CaPaths) -> Result<Self, ProxyError> {
        if paths.cert_path.exists() || paths.key_path.exists() {
            if !(paths.cert_path.exists() && paths.key_path.exists()) {
                return Err(ProxyError::Configuration(
                    "CA material is incomplete (certificate or key missing); refusing to replace it automatically"
                        .into(),
                ));
            }
            return Self::load(paths);
        }
        Self::generate(paths)
    }

    /// Explicitly regenerates CA material. This invalidates prior client trust
    /// and must only be invoked by an explicit operator action.
    pub fn regenerate(paths: &CaPaths) -> Result<Self, ProxyError> {
        if paths.cert_path.exists() {
            fs::remove_file(&paths.cert_path).map_err(ProxyError::Io)?;
        }
        if paths.key_path.exists() {
            fs::remove_file(&paths.key_path).map_err(ProxyError::Io)?;
        }
        Self::generate(paths)
    }

    fn generate(paths: &CaPaths) -> Result<Self, ProxyError> {
        ensure_ca_dir(&paths.dir)?;
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "RAWFRAME Local Interception CA");
        dn.push(DnType::OrganizationName, "RAWFRAME");
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::days(1);
        params.not_after = now + Duration::days(3650);

        let key_pair = KeyPair::generate().map_err(|e| {
            ProxyError::Configuration(format!("failed to generate CA key pair: {e}"))
        })?;
        let cert = params.self_signed(&key_pair).map_err(|e| {
            ProxyError::Configuration(format!("failed to generate CA certificate: {e}"))
        })?;
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        write_atomic(&paths.cert_path, cert_pem.as_bytes(), 0o644)?;
        write_private_atomic(&paths.key_path, key_pem.as_bytes())?;
        Self::from_pem(paths.clone(), cert_pem, key_pem)
    }

    fn from_pem(paths: CaPaths, cert_pem: String, key_pem: String) -> Result<Self, ProxyError> {
        validate_ca_material(&cert_pem, &key_pem)?;
        let fingerprint_sha256 = fingerprint_sha256_pem(&cert_pem)?;
        let key_pair = KeyPair::from_pem(&key_pem).map_err(|_| {
            ProxyError::Configuration(
                "CA private key is invalid or does not match supported format".into(),
            )
        })?;
        let der = pem_first_der(&cert_pem).map_err(|_| {
            ProxyError::Configuration("CA certificate PEM could not be parsed".into())
        })?;
        let (_, x509) =
            x509_parser::certificate::X509Certificate::from_der(&der).map_err(|_| {
                ProxyError::Configuration("CA certificate is not a valid X.509 certificate".into())
            })?;
        if x509.public_key().raw != key_pair.public_key_der().as_slice() {
            return Err(ProxyError::Configuration(
                "CA certificate and private key do not match".into(),
            ));
        }
        let params = CertificateParams::from_ca_cert_pem(&cert_pem).map_err(|_| {
            ProxyError::Configuration(
                "CA certificate is invalid or cannot be used for signing".into(),
            )
        })?;
        let cert = params.self_signed(&key_pair).map_err(|_| {
            ProxyError::Configuration(
                "CA certificate/key are inconsistent or cannot be used for signing".into(),
            )
        })?;
        Ok(Self {
            paths,
            cert,
            key_pair,
            cert_pem,
            fingerprint_sha256,
        })
    }

    pub fn info(&self) -> CaInfo {
        CaInfo {
            status: CaStatus::Ready,
            cert_path: self.paths.cert_path.clone(),
            fingerprint_sha256: Some(self.fingerprint_sha256.clone()),
        }
    }

    pub fn cert_path(&self) -> &Path {
        &self.paths.cert_path
    }

    pub fn fingerprint_sha256(&self) -> &str {
        &self.fingerprint_sha256
    }

    /// Public CA certificate PEM (safe to export/share). Never returns key material.
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    pub(crate) fn cert(&self) -> &Certificate {
        &self.cert
    }

    pub(crate) fn key_pair(&self) -> &KeyPair {
        &self.key_pair
    }

    /// Returns non-sensitive status for a CA directory without generating material.
    pub fn inspect(paths: &CaPaths) -> CaInfo {
        if !(paths.cert_path.exists() && paths.key_path.exists()) {
            return CaInfo {
                status: CaStatus::Missing,
                cert_path: paths.cert_path.clone(),
                fingerprint_sha256: None,
            };
        }
        match fs::read_to_string(&paths.cert_path)
            .ok()
            .and_then(|pem| fingerprint_sha256_pem(&pem).ok())
        {
            Some(fp) => CaInfo {
                status: CaStatus::Ready,
                cert_path: paths.cert_path.clone(),
                fingerprint_sha256: Some(fp),
            },
            None => CaInfo {
                status: CaStatus::Missing,
                cert_path: paths.cert_path.clone(),
                fingerprint_sha256: None,
            },
        }
    }
}

fn validate_ca_material(cert_pem: &str, key_pem: &str) -> Result<(), ProxyError> {
    if !cert_pem.contains("BEGIN CERTIFICATE") {
        return Err(ProxyError::Configuration(
            "CA certificate file is not a valid PEM certificate".into(),
        ));
    }
    if !(key_pem.contains("BEGIN PRIVATE KEY")
        || key_pem.contains("BEGIN RSA PRIVATE KEY")
        || key_pem.contains("BEGIN EC PRIVATE KEY"))
    {
        return Err(ProxyError::Configuration(
            "CA key file is not a valid PEM private key".into(),
        ));
    }
    let der = pem_first_der(cert_pem)
        .map_err(|_| ProxyError::Configuration("CA certificate PEM could not be parsed".into()))?;
    let (_, x509) = x509_parser::certificate::X509Certificate::from_der(&der).map_err(|_| {
        ProxyError::Configuration("CA certificate is not a valid X.509 certificate".into())
    })?;
    if let Ok(Some(bc)) = x509.basic_constraints()
        && !bc.value.ca
    {
        return Err(ProxyError::Configuration(
            "CA certificate is not marked as a CA".into(),
        ));
    }
    Ok(())
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

fn fingerprint_sha256_pem(cert_pem: &str) -> Result<String, ProxyError> {
    let der = pem_first_der(cert_pem).map_err(|_| {
        ProxyError::Configuration("failed to parse CA certificate for fingerprint".into())
    })?;
    let mut hasher = Sha256::new();
    hasher.update(&der);
    let digest = hasher.finalize();
    Ok(format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD.encode(digest)
    ))
}

fn ensure_ca_dir(dir: &Path) -> Result<(), ProxyError> {
    fs::create_dir_all(dir).map_err(ProxyError::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

fn write_atomic(path: &Path, contents: &[u8], mode: u32) -> Result<(), ProxyError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(ProxyError::Io)?;
    }
    let tmp = path.with_extension("tmp");
    let mut file = fs::File::create(&tmp).map_err(ProxyError::Io)?;
    file.write_all(contents).map_err(ProxyError::Io)?;
    file.sync_all().map_err(ProxyError::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(mode));
    }
    fs::rename(&tmp, path).map_err(ProxyError::Io)?;
    Ok(())
}

fn write_private_atomic(path: &Path, contents: &[u8]) -> Result<(), ProxyError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let tmp = path.with_extension("tmp");
        let mut opts = fs::OpenOptions::new();
        opts.create(true).write(true).truncate(true).mode(0o600);
        let mut file = opts.open(&tmp).map_err(ProxyError::Io)?;
        file.write_all(contents).map_err(ProxyError::Io)?;
        file.sync_all().map_err(ProxyError::Io)?;
        let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600));
        fs::rename(&tmp, path).map_err(ProxyError::Io)?;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = mode_unused(contents);
        write_atomic(path, contents, 0o600)
    }
}

#[cfg(not(unix))]
fn mode_unused(_contents: &[u8]) {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("rawframe-ca-{name}-{nanos}-{}", std::process::id()))
    }

    #[test]
    fn generates_persists_and_reloads_ca() {
        let dir = temp_dir("gen");
        let paths = CaPaths::new(&dir);
        let ca = CaManager::load_or_generate(&paths).unwrap();
        assert!(paths.cert_path.exists());
        assert!(paths.key_path.exists());
        let fp = ca.fingerprint_sha256().to_string();
        assert!(fp.starts_with("SHA256:"));
        let ca2 = CaManager::load(&paths).unwrap();
        assert_eq!(ca2.fingerprint_sha256(), fp);
        assert!(ca2.cert_pem().contains("BEGIN CERTIFICATE"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn missing_material_is_reported() {
        let dir = temp_dir("missing");
        let paths = CaPaths::new(&dir);
        assert!(CaManager::load(&paths).is_err());
        let info = CaManager::inspect(&paths);
        assert_eq!(info.status, CaStatus::Missing);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn invalid_material_is_rejected() {
        let dir = temp_dir("invalid");
        fs::create_dir_all(&dir).unwrap();
        let paths = CaPaths::new(&dir);
        fs::write(&paths.cert_path, "not a cert").unwrap();
        fs::write(&paths.key_path, "not a key").unwrap();
        assert!(CaManager::load(&paths).is_err());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn incomplete_material_is_not_auto_replaced() {
        let dir = temp_dir("incomplete");
        fs::create_dir_all(&dir).unwrap();
        let paths = CaPaths::new(&dir);
        fs::write(&paths.cert_path, "orphan").unwrap();
        assert!(CaManager::load_or_generate(&paths).is_err());
        assert_eq!(fs::read_to_string(&paths.cert_path).unwrap(), "orphan");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn explicit_regeneration_replaces_material() {
        let dir = temp_dir("regen");
        let paths = CaPaths::new(&dir);
        let ca = CaManager::load_or_generate(&paths).unwrap();
        let fp = ca.fingerprint_sha256().to_string();
        let ca2 = CaManager::regenerate(&paths).unwrap();
        assert_ne!(fp, ca2.fingerprint_sha256());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn ca_certificate_has_signing_constraints() {
        use x509_parser::prelude::FromDer;

        let dir = temp_dir("constraints");
        let paths = CaPaths::new(&dir);
        let ca = CaManager::load_or_generate(&paths).unwrap();
        let der = pem_first_der(ca.cert_pem()).unwrap();
        let (_, cert) = x509_parser::certificate::X509Certificate::from_der(&der).unwrap();
        let bc = cert.basic_constraints().unwrap().unwrap();
        assert!(bc.value.ca, "CA certificate must set basicConstraints CA");
        let ku = cert.key_usage().unwrap().unwrap();
        assert!(
            ku.value.key_cert_sign(),
            "CA must be allowed to sign certificates"
        );
        assert!(ku.value.crl_sign(), "CA must be allowed to sign CRLs");

        let reloaded = CaManager::load(&paths).unwrap();
        assert_eq!(ca.fingerprint_sha256(), reloaded.fingerprint_sha256());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn certificate_and_key_mismatch_is_rejected() {
        let first = temp_dir("match-a");
        let second = temp_dir("match-b");
        let a = CaManager::load_or_generate(&CaPaths::new(&first)).unwrap();
        let _b = CaManager::load_or_generate(&CaPaths::new(&second)).unwrap();
        let foreign_key = fs::read_to_string(CaPaths::new(&second).key_path).unwrap();
        fs::write(CaPaths::new(&first).key_path, foreign_key).unwrap();
        let error = match CaManager::load(&CaPaths::new(&first)) {
            Ok(_) => panic!("mismatched CA key must be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("do not match"));
        assert_eq!(
            CaManager::inspect(&CaPaths::new(&first)).status,
            CaStatus::Ready,
            "inspect must not leak or mutate material"
        );
        let _ = a;
        let _ = fs::remove_dir_all(first);
        let _ = fs::remove_dir_all(second);
    }

    #[cfg(unix)]
    #[test]
    fn private_key_permissions_are_restrictive() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("perms");
        let paths = CaPaths::new(&dir);
        let _ = CaManager::load_or_generate(&paths).unwrap();
        let mode = fs::metadata(&paths.key_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let _ = fs::remove_dir_all(dir);
    }
}
