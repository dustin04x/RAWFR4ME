//! HTTP request and response data models shared across the workbench.

use serde::{Deserialize, Serialize};

use super::headers::Headers;
use crate::security::{display_bytes, sanitize_for_display};

/// Upper bound used when turning a body into display text. This is intentionally
/// smaller than the proxy's configurable capture limit: inspection must stay
/// responsive even when a body is large.
pub const DISPLAY_BODY_LIMIT: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scheme {
    Http,
    Https,
}

impl Scheme {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }

    pub const fn default_port(self) -> u16 {
        match self {
            Self::Http => 80,
            Self::Https => 443,
        }
    }
}

impl std::fmt::Display for Scheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatusClass {
    Informational,
    Success,
    Redirection,
    ClientError,
    ServerError,
    Unknown,
}

impl StatusClass {
    pub fn from_code(status: u16) -> Self {
        match status {
            100..=199 => Self::Informational,
            200..=299 => Self::Success,
            300..=399 => Self::Redirection,
            400..=499 => Self::ClientError,
            500..=599 => Self::ServerError,
            _ => Self::Unknown,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Informational => "1xx",
            Self::Success => "2xx",
            Self::Redirection => "3xx",
            Self::ClientError => "4xx",
            Self::ServerError => "5xx",
            Self::Unknown => "other",
        }
    }

    pub const fn is_error(self) -> bool {
        matches!(self, Self::ClientError | Self::ServerError)
    }
}

/// A single HTTP request as captured or authored in the Repeater.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpRequest {
    pub method: String,
    pub scheme: Scheme,
    pub host: String,
    pub port: u16,
    /// Origin-form target ("/path?query"), or "*" for OPTIONS.
    pub target: String,
    pub version: String,
    pub headers: Headers,
    pub body: Vec<u8>,
}

impl HttpRequest {
    /// Builds a request and ensures a `Host` field is present.
    pub fn new(
        method: impl Into<String>,
        scheme: Scheme,
        host: impl Into<String>,
        port: u16,
        target: impl Into<String>,
    ) -> Self {
        let host = host.into();
        let mut headers = Headers::new();
        let authority = authority_for(&host, scheme, port);
        headers.append("Host", authority);
        Self {
            method: method.into().to_ascii_uppercase(),
            scheme,
            host,
            port,
            target: target.into(),
            version: "HTTP/1.1".to_string(),
            headers,
            body: Vec::new(),
        }
    }

    pub fn authority(&self) -> String {
        authority_for(&self.host, self.scheme, self.port)
    }

    pub fn url(&self) -> String {
        format!("{}://{}{}", self.scheme, self.authority(), self.target)
    }

    pub fn content_length(&self) -> usize {
        self.body.len()
    }

    pub fn body_text(&self) -> String {
        display_bytes(&self.body, DISPLAY_BODY_LIMIT).text
    }

    /// Raw HTTP/1.1 serialization using CRLF line endings. Used for wire-shaped
    /// output and round-trip tests; not for terminal display.
    pub fn to_http_string(&self, redact: bool) -> String {
        let mut output = format!("{} {} {}\r\n", self.method, self.target, self.version);
        for line in self.headers.lines(redact) {
            output.push_str(&line);
            output.push_str("\r\n");
        }
        output.push_str("\r\n");
        output.push_str(&String::from_utf8_lossy(&self.body));
        output
    }

    /// Terminal-safe, LF-normalized text suitable for the inspector or editor.
    /// Control sequences are escaped; binary bodies are shown lossily.
    pub fn to_display_text(&self, redact: bool) -> String {
        let mut output = format!(
            "{} {} {}\n",
            sanitize_for_display(&self.method),
            sanitize_for_display(&self.target),
            sanitize_for_display(&self.version)
        );
        for line in self.headers.display_lines(redact) {
            output.push_str(&line);
            output.push('\n');
        }
        output.push('\n');
        output.push_str(&self.body_text());
        output
    }
}

/// A single HTTP response as captured or authored in the Repeater.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpResponse {
    pub status: u16,
    pub reason: String,
    pub version: String,
    pub headers: Headers,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn new(status: u16) -> Self {
        Self {
            status,
            reason: reason_phrase(status).to_string(),
            version: "HTTP/1.1".to_string(),
            headers: Headers::new(),
            body: Vec::new(),
        }
    }

    pub fn with_body(status: u16, content_type: &str, body: impl Into<Vec<u8>>) -> Self {
        let body = body.into();
        let mut response = Self::new(status);
        response
            .headers
            .append("Content-Type", content_type.to_string());
        response
            .headers
            .append("Content-Length", body.len().to_string());
        response.body = body;
        response
    }

    pub fn status_class(&self) -> StatusClass {
        StatusClass::from_code(self.status)
    }

    pub fn status_line(&self) -> String {
        if self.reason.is_empty() {
            format!("{} {}", self.version, self.status)
        } else {
            format!("{} {} {}", self.version, self.status, self.reason)
        }
    }

    pub fn content_length(&self) -> usize {
        self.body.len()
    }

    pub fn content_type(&self) -> Option<&str> {
        self.headers.get("content-type")
    }

    pub fn body_text(&self) -> String {
        display_bytes(&self.body, DISPLAY_BODY_LIMIT).text
    }

    pub fn to_http_string(&self, redact: bool) -> String {
        let mut output = format!("{}\r\n", self.status_line());
        for line in self.headers.lines(redact) {
            output.push_str(&line);
            output.push_str("\r\n");
        }
        output.push_str("\r\n");
        output.push_str(&String::from_utf8_lossy(&self.body));
        output
    }

    pub fn to_display_text(&self, redact: bool) -> String {
        let mut output = format!(
            "{} {} {}\n",
            sanitize_for_display(&self.version),
            self.status,
            sanitize_for_display(&self.reason)
        );
        for line in self.headers.display_lines(redact) {
            output.push_str(&line);
            output.push('\n');
        }
        output.push('\n');
        output.push_str(&self.body_text());
        output
    }
}

/// Formats an authority for the `Host` field, omitting default ports and
/// bracketing IPv6 literals.
pub fn authority_for(host: &str, scheme: Scheme, port: u16) -> String {
    let display_host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };

    if port == scheme.default_port() {
        display_host
    } else {
        format!("{display_host}:{port}")
    }
}

/// Canonical reason phrases for common status codes. Unknown codes keep an empty
/// reason, which is legal in HTTP and avoids inventing information.
pub fn reason_phrase(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        101 => "Switching Protocols",
        102 => "Processing",
        103 => "Early Hints",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        413 => "Content Too Large",
        415 => "Unsupported Media Type",
        418 => "I'm a teapot",
        422 => "Unprocessable Content",
        426 => "Upgrade Required",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        451 => "Unavailable For Legal Reasons",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_url_omits_default_ports_and_brackets_ipv6() {
        let mut request =
            HttpRequest::new("get", Scheme::Https, "api.rawframe.test", 443, "/v1/users");
        assert_eq!(request.method, "GET");
        assert_eq!(request.headers.get("host"), Some("api.rawframe.test"));
        assert_eq!(request.url(), "https://api.rawframe.test/v1/users");

        request.port = 8443;
        assert_eq!(request.authority(), "api.rawframe.test:8443");

        let request = HttpRequest::new("GET", Scheme::Http, "::1", 80, "/");
        assert_eq!(request.authority(), "[::1]");
        assert_eq!(request.url(), "http://[::1]/");
    }

    #[test]
    fn request_serialization_contains_crlf_and_body() {
        let mut request =
            HttpRequest::new("POST", Scheme::Https, "shop.rawframe.test", 443, "/cart");
        request.body = b"{\"sku\":\"LAMP-01\"}".to_vec();
        request.headers.append("Content-Type", "application/json");

        let raw = request.to_http_string(false);
        assert!(raw.starts_with("POST /cart HTTP/1.1\r\n"));
        assert!(raw.contains("Host: shop.rawframe.test\r\n"));
        assert!(raw.ends_with("\r\n\r\n{\"sku\":\"LAMP-01\"}"));
    }

    #[test]
    fn display_text_escapes_control_sequences() {
        let mut request = HttpRequest::new("GET", Scheme::Https, "api.rawframe.test", 443, "/");
        request.body = b"\x1b[31mdanger".to_vec();
        let display = request.to_display_text(false);

        assert!(!display.contains('\u{1b}'));
        assert!(display.contains("^[[31mdanger"));
        assert!(!display.contains('\r'));
    }

    #[test]
    fn redaction_applies_to_serialization() {
        let mut request = HttpRequest::new("GET", Scheme::Https, "api.rawframe.test", 443, "/");
        request.headers.append("Authorization", "Bearer token");
        let display = request.to_display_text(true);

        assert!(display.contains("Authorization: <redacted>"));
        assert!(!display.contains("Bearer token"));
    }

    #[test]
    fn response_status_line_handles_unknown_and_empty_reasons() {
        let response = HttpResponse::new(200);
        assert_eq!(response.status_line(), "HTTP/1.1 200 OK");
        assert_eq!(response.status_class(), StatusClass::Success);

        let mut unusual = HttpResponse::new(599);
        assert_eq!(unusual.status_line(), "HTTP/1.1 599");
        unusual.reason = "Upstream exploded".into();
        assert_eq!(unusual.status_line(), "HTTP/1.1 599 Upstream exploded");
    }

    #[test]
    fn response_with_body_sets_framing_headers() {
        let response = HttpResponse::with_body(404, "application/json", "{}");
        assert_eq!(
            response.headers.get("content-type"),
            Some("application/json")
        );
        assert_eq!(response.headers.get("content-length"), Some("2"));
        assert_eq!(response.content_length(), 2);
        assert_eq!(response.status_class(), StatusClass::ClientError);
        assert!(response.status_class().is_error());
    }

    #[test]
    fn status_classes_cover_all_defined_ranges() {
        assert_eq!(StatusClass::from_code(103), StatusClass::Informational);
        assert_eq!(StatusClass::from_code(302), StatusClass::Redirection);
        assert_eq!(StatusClass::from_code(500), StatusClass::ServerError);
        assert_eq!(StatusClass::from_code(700), StatusClass::Unknown);
    }
}
