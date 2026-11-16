//! Metadata for certificates issued by the local RAWFRAME certificate authority.
//!
//! Private key material is deliberately absent from this model. Keys will live
//! in a dedicated, permission-restricted store (Milestone 3); serialising them
//! with traffic or UI state is not acceptable.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateMetadata {
    pub common_name: String,
    pub subject_alt_names: Vec<String>,
    /// SHA-256 fingerprint as lowercase hex, colon-separated for display.
    pub fingerprint_sha256: String,
    pub issuer: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub is_ca: bool,
}

impl CertificateMetadata {
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now >= self.not_after || now < self.not_before
    }

    pub fn covers_hostname(&self, hostname: &str) -> bool {
        let hostname = hostname.to_ascii_lowercase();
        if self.common_name.eq_ignore_ascii_case(&hostname) {
            return true;
        }
        self.subject_alt_names.iter().any(|name| {
            let name = name.to_ascii_lowercase();
            if let Some(suffix) = name.strip_prefix("*.") {
                hostname
                    .strip_suffix(suffix)
                    .is_some_and(|prefix| prefix.ends_with('.') && prefix.len() > 1)
            } else {
                name == hostname
            }
        })
    }

    pub fn is_usable_for(&self, hostname: &str, now: DateTime<Utc>) -> bool {
        !self.is_expired(now) && self.covers_hostname(hostname)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeDelta;

    fn certificate() -> CertificateMetadata {
        let now = Utc::now();
        CertificateMetadata {
            common_name: "rawframe local CA".into(),
            subject_alt_names: vec!["*.rawframe.test".into(), "rawframe.test".into()],
            fingerprint_sha256: "ab:cd".into(),
            issuer: "rawframe local CA".into(),
            not_before: now - TimeDelta::days(1),
            not_after: now + TimeDelta::days(30),
            is_ca: true,
        }
    }

    #[test]
    fn wildcard_sans_cover_one_or_more_labels() {
        let certificate = certificate();
        assert!(certificate.covers_hostname("api.rawframe.test"));
        assert!(certificate.covers_hostname("deep.api.rawframe.test"));
        assert!(certificate.covers_hostname("rawframe.test"));
        assert!(!certificate.covers_hostname("rawframe.test.evil"));
        assert!(!certificate.covers_hostname("other.test"));
    }

    #[test]
    fn expiry_is_evaluated_at_the_supplied_time() {
        let certificate = certificate();
        let now = Utc::now();
        assert!(certificate.is_usable_for("api.rawframe.test", now));
        assert!(certificate.is_expired(certificate.not_after + TimeDelta::seconds(1)));
        assert!(certificate.is_expired(certificate.not_before - TimeDelta::seconds(1)));
    }
}
