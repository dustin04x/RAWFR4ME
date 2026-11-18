//! HTTP/2 representation boundaries.
//!
//! RAWFRAME does not model HTTP/2 frames. An HTTP/2 message is represented by
//! the same structured [`HttpRequest`]/[`HttpResponse`] contracts as HTTP/1.1,
//! with the negotiated protocol recorded in `version`:
//!
//! - `:method`, `:scheme`, `:authority`, and `:path` map to `method`, `scheme`,
//!   `host`/`port`, and `target`. They are never stored as ordinary headers and
//!   never written back into the header list, so an HTTP/1.1 consumer cannot
//!   mistake a pseudo-header for a real field.
//! - Regular headers keep their order and duplicates, lower-cased only where the
//!   wire requires it (the HTTP/2 encoder does that, not this module).
//! - Bodies stay raw bytes; HTTP/2 has no chunked transfer coding.
//!
//! This module is the single conversion boundary used by the proxy and the
//! Repeater, so both produce identical requests for the same model.

use crate::models::{Headers, HttpRequest, Scheme};

/// ALPN identifier for HTTP/2.
pub const ALPN_H2: &[u8] = b"h2";
/// ALPN identifier for HTTP/1.1.
pub const ALPN_HTTP11: &[u8] = b"http/1.1";

/// Header fields that are meaningful on one HTTP/2 connection but must never be
/// forwarded as regular fields. They are connection-specific in HTTP/1.1 and
/// forbidden by RFC 9113.
const CONNECTION_SPECIFIC: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
    "te",
];

/// Returns true when a recorded `version` string denotes HTTP/2.
pub fn is_http2_version(version: &str) -> bool {
    matches!(
        version.trim().to_ascii_lowercase().as_str(),
        "http/2" | "http/2.0" | "h2"
    )
}

/// Short, stable label for a recorded protocol version.
///
/// Only versions RAWFRAME actually records get a protocol name. Anything else
/// (including HTTP/3, which RAWFRAME never negotiates) is reported as
/// `unknown` rather than being silently folded into HTTP/1.1.
pub fn protocol_label(version: &str) -> &'static str {
    let version = version.trim();
    if is_http2_version(version) {
        "HTTP/2"
    } else if version.eq_ignore_ascii_case("http/1.1") {
        "HTTP/1.1"
    } else if version.eq_ignore_ascii_case("http/1.0") {
        "HTTP/1.0"
    } else if version.eq_ignore_ascii_case("http/0.9") {
        "HTTP/0.9"
    } else {
        "unknown"
    }
}

/// Canonical version string for a completed HTTP/2 exchange.
pub const HTTP2_VERSION: &str = "HTTP/2.0";

/// True for fields that HTTP/2 forbids or that only make sense per connection.
pub fn is_connection_specific(name: &str) -> bool {
    CONNECTION_SPECIFIC
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(name))
        // `TE: trailers` is the one allowed TE value, but RAWFRAME never sends
        // request trailers, so keeping TE out of generated requests is safe.
        || name.eq_ignore_ascii_case("host")
}

/// Removes HTTP/1.1 connection-specific fields from a header set before it is
/// encoded for HTTP/2. The `Host` field is dropped because the authority is
/// carried by `:authority`; keeping both would give the peer two sources of
/// truth.
pub fn sanitize_headers_for_h2(headers: &Headers) -> Headers {
    let mut sanitized = Headers::new();
    for header in headers.iter() {
        if is_connection_specific(&header.name) {
            continue;
        }
        sanitized.append(header.name.clone(), header.value.clone());
    }
    sanitized
}

/// Absolute URI for an HTTP/2 request: `scheme://authority/path?query`.
///
/// hyper derives `:scheme`, `:authority`, and `:path` from this URI, so it must
/// be absolute even when the authored document uses an origin-form target.
pub fn absolute_uri(request: &HttpRequest) -> String {
    let target = origin_form(&request.target);
    let target = if target.starts_with('/') || target == "*" {
        target
    } else {
        format!("/{target}")
    };
    format!(
        "{}://{}{}",
        scheme_label(request.scheme),
        request.authority(),
        target
    )
}

/// Reduces a target to origin-form. An authored absolute target keeps only its
/// path and query: the scheme and authority always come from the validated
/// request fields, so a target string can never redirect an h2 request.
fn origin_form(target: &str) -> String {
    let target = target.trim();
    if target.is_empty() {
        return "/".to_string();
    }
    let rest = target
        .strip_prefix("https://")
        .or_else(|| target.strip_prefix("http://"));
    if let Some(rest) = rest {
        return match rest.find('/') {
            Some(index) => rest[index..].to_string(),
            None => "/".to_string(),
        };
    }
    target.to_string()
}

fn scheme_label(scheme: Scheme) -> &'static str {
    match scheme {
        Scheme::Http => "http",
        Scheme::Https => "https",
    }
}

/// True when a negotiated ALPN value is HTTP/2. Any other value (including a
/// missing negotiation) means HTTP/1.1 was selected.
pub fn alpn_is_h2(negotiated: Option<&[u8]>) -> bool {
    negotiated == Some(ALPN_H2)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> HttpRequest {
        let mut request =
            HttpRequest::new("GET", Scheme::Https, "lab.rawframe.test", 8443, "/a?b=1");
        request.headers.append("accept", "*/*");
        request
    }

    #[test]
    fn versions_are_classified_without_guessing() {
        assert!(is_http2_version("HTTP/2.0"));
        assert!(is_http2_version("HTTP/2"));
        assert!(is_http2_version("h2"));
        assert!(!is_http2_version("HTTP/1.1"));
        assert!(!is_http2_version(""));
        assert_eq!(protocol_label("HTTP/2.0"), "HTTP/2");
        assert_eq!(protocol_label("HTTP/1.1"), "HTTP/1.1");
        assert_eq!(protocol_label("HTTP/1.0"), "HTTP/1.0");
        assert_eq!(protocol_label(""), "unknown");
        // Never claim a protocol RAWFRAME did not negotiate.
        assert_eq!(protocol_label("HTTP/3.0"), "unknown");
        assert_eq!(protocol_label("gopher/1"), "unknown");
        assert_eq!(protocol_label(" http/1.1 "), "HTTP/1.1");
    }

    #[test]
    fn alpn_only_selects_h2_on_an_exact_match() {
        assert!(alpn_is_h2(Some(b"h2")));
        assert!(!alpn_is_h2(Some(b"http/1.1")));
        assert!(!alpn_is_h2(None));
        assert!(!alpn_is_h2(Some(b"h2c")));
    }

    #[test]
    fn connection_specific_fields_are_removed_for_h2() {
        let mut request = request();
        request.headers.append("Connection", "keep-alive");
        request.headers.append("Transfer-Encoding", "chunked");
        request.headers.append("Upgrade", "h2c");
        request.headers.append("X-Kept", "yes");
        let sanitized = sanitize_headers_for_h2(&request.headers);
        assert!(!sanitized.contains("connection"));
        assert!(!sanitized.contains("transfer-encoding"));
        assert!(!sanitized.contains("upgrade"));
        assert!(!sanitized.contains("host"));
        assert_eq!(sanitized.get("x-kept"), Some("yes"));
        assert_eq!(sanitized.get("accept"), Some("*/*"));
        // The original model is untouched: conversion never mutates captures.
        assert!(request.headers.contains("connection"));
    }

    #[test]
    fn absolute_uri_carries_scheme_authority_and_path() {
        assert_eq!(
            absolute_uri(&request()),
            "https://lab.rawframe.test:8443/a?b=1"
        );
        let mut root = HttpRequest::new("GET", Scheme::Http, "lab.rawframe.test", 80, "");
        root.target = String::new();
        assert_eq!(absolute_uri(&root), "http://lab.rawframe.test/");

        // An absolute authored target cannot override the validated authority.
        let mut absolute = request();
        absolute.target = "https://elsewhere.invalid/x?y=2".into();
        assert_eq!(
            absolute_uri(&absolute),
            "https://lab.rawframe.test:8443/x?y=2"
        );
        absolute.target = "http://elsewhere.invalid".into();
        assert_eq!(absolute_uri(&absolute), "https://lab.rawframe.test:8443/");
    }
}
