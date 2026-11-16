//! Destination parsing, scope checks, and safe upstream name resolution.
//!
//! A hostname is authorized by scope before resolution. It is then resolved
//! exactly once and every returned address is checked against the address
//! policy. The connection uses the already-resolved socket addresses, so a
//! second DNS answer cannot redirect an authorized name into a protected
//! network after validation.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use hyper::Request;
use hyper::header::{HOST, HeaderMap};
use hyper::http::uri::Authority;
use rawframe_core::models::message::{Scheme, authority_for};
use rawframe_core::models::{HttpRequest, Scope};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone)]
pub struct Destination {
    pub scheme: Scheme,
    pub host: String,
    pub port: u16,
    pub target: String,
    pub authority: String,
}

#[derive(Debug, Clone)]
pub struct Rejection {
    pub status: hyper::StatusCode,
    pub message: String,
}

impl Rejection {
    pub fn new(status: hyper::StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(hyper::StatusCode::BAD_REQUEST, message)
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(hyper::StatusCode::FORBIDDEN, message)
    }

    pub fn bad_gateway(message: impl Into<String>) -> Self {
        Self::new(hyper::StatusCode::BAD_GATEWAY, message)
    }
}

impl Destination {
    /// Parses an absolute-form HTTP proxy request.
    pub fn from_http_request<B>(request: &Request<B>) -> Result<Self, Rejection> {
        let uri = request.uri();
        let scheme = match uri.scheme_str() {
            Some("http") => Scheme::Http,
            Some("https") => {
                return Err(Rejection::bad_request(
                    "HTTPS requests must use CONNECT; this proxy does not terminate TLS.",
                ));
            }
            Some(other) => {
                return Err(Rejection::bad_request(format!(
                    "unsupported proxy URI scheme: {other}"
                )));
            }
            None => {
                return Err(Rejection::bad_request(
                    "proxy requests must use absolute-form targets",
                ));
            }
        };
        let authority = uri.authority().ok_or_else(|| {
            Rejection::bad_request("absolute-form target is missing an authority")
        })?;
        let destination = Self::from_authority(scheme, authority, uri.path_and_query())?;

        check_host_header(request.headers(), &destination)?;
        Ok(destination)
    }

    /// Parses authority-form CONNECT targets.
    pub fn from_connect_request<B>(request: &Request<B>) -> Result<Self, Rejection> {
        let authority_text = request
            .uri()
            .authority()
            .map(|authority| authority.as_str().to_string())
            .or_else(|| {
                let text = request.uri().to_string();
                let trimmed = text.trim_start_matches("//");
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                }
            })
            .ok_or_else(|| Rejection::bad_request("CONNECT target is missing an authority"))?;
        let authority: Authority = authority_text
            .parse()
            .map_err(|_| Rejection::bad_request("CONNECT target has an invalid authority"))?;
        Self::from_authority(Scheme::Https, &authority, None)
    }

    pub fn is_permitted(&self, scope: &Scope) -> bool {
        scope.permits(self.scheme, &self.host, self.port)
    }

    pub fn scope_rejection(&self) -> Rejection {
        Rejection::forbidden(format!(
            "destination {}:{} is outside the configured scope",
            self.host, self.port
        ))
    }

    fn from_authority(
        scheme: Scheme,
        authority: &Authority,
        path_and_query: Option<&hyper::http::uri::PathAndQuery>,
    ) -> Result<Self, Rejection> {
        let raw_host = authority.host();
        let host = normalize_host(raw_host).ok_or_else(|| {
            Rejection::bad_request("destination authority contains an invalid host")
        })?;
        let port = authority
            .port_u16()
            .unwrap_or_else(|| scheme.default_port());
        if port == 0 {
            return Err(Rejection::bad_request("destination port must not be zero"));
        }
        let target = path_and_query
            .map(|path| path.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());
        if !target.starts_with('/') && target != "*" {
            return Err(Rejection::bad_request(
                "proxy request target must be origin-form",
            ));
        }
        Ok(Self {
            scheme,
            authority: authority_for(&host, scheme, port),
            host,
            port,
            target,
        })
    }

    pub fn capture_request<B>(&self, request: &Request<B>) -> HttpRequest {
        let mut captured = HttpRequest::new(
            request.method().as_str(),
            self.scheme,
            self.host.clone(),
            self.port,
            self.target.clone(),
        );
        captured.version = format!("{:?}", request.version());
        captured.headers = capture_headers(request.headers());
        captured
            .headers
            .insert("Host", authority_for(&self.host, self.scheme, self.port));
        captured
    }

    pub fn capture_connect_request<B>(&self, request: &Request<B>) -> HttpRequest {
        let mut captured = HttpRequest::new(
            "CONNECT",
            Scheme::Https,
            self.host.clone(),
            self.port,
            self.authority.clone(),
        );
        captured.version = format!("{:?}", request.version());
        captured.headers = capture_headers(request.headers());
        captured
    }
}

pub fn capture_headers(headers: &HeaderMap) -> rawframe_core::models::Headers {
    let mut captured = rawframe_core::models::Headers::new();
    for (name, value) in headers {
        captured.append(
            name.as_str(),
            String::from_utf8_lossy(value.as_bytes()).into_owned(),
        );
    }
    captured
}

fn check_host_header(headers: &HeaderMap, destination: &Destination) -> Result<(), Rejection> {
    let mut values = headers.get_all(HOST).iter();
    let Some(value) = values.next() else {
        return Ok(());
    };
    if values.next().is_some() {
        return Err(Rejection::bad_request(
            "multiple Host headers are not allowed",
        ));
    }
    let authority: Authority = value
        .to_str()
        .map_err(|_| Rejection::bad_request("Host header is not valid ASCII"))?
        .parse()
        .map_err(|_| Rejection::bad_request("Host header has an invalid authority"))?;
    let host = normalize_host(authority.host())
        .ok_or_else(|| Rejection::bad_request("Host header has an invalid host"))?;
    let port = authority
        .port_u16()
        .unwrap_or_else(|| destination.scheme.default_port());
    if host != destination.host || port != destination.port {
        return Err(Rejection::bad_request(
            "Host header does not match the absolute-form target",
        ));
    }
    Ok(())
}

pub fn normalize_host(host: &str) -> Option<String> {
    let host = host.trim().trim_start_matches('[').trim_end_matches(']');
    let host = host.trim_end_matches('.');
    if host.is_empty()
        || host
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace() || matches!(ch, '/' | '@' | '\\'))
    {
        return None;
    }
    Some(host.to_ascii_lowercase())
}

/// Resolves once and returns only addresses permitted by the address policy.
/// The caller connects to these exact addresses.
pub async fn resolve_destination(
    destination: &Destination,
    allow_private: bool,
    connect_timeout: Duration,
) -> Result<Vec<SocketAddr>, Rejection> {
    let addresses = timeout(
        connect_timeout,
        resolve_addresses(&destination.host, destination.port),
    )
    .await
    .map_err(|_| Rejection::bad_gateway("upstream name resolution timed out"))?
    .map_err(|error| Rejection::bad_gateway(format!("upstream resolution failed: {error}")))?;

    if addresses.is_empty() {
        return Err(Rejection::bad_gateway(
            "upstream hostname resolved to no addresses",
        ));
    }
    if let Some(blocked) = addresses
        .iter()
        .find(|address| !address_allowed(address.ip(), allow_private))
    {
        return Err(Rejection::forbidden(format!(
            "resolved upstream address {} is not permitted by the address policy",
            blocked.ip()
        )));
    }
    Ok(addresses)
}

async fn resolve_addresses(host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let mut addresses: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await?.collect();
    addresses.sort_unstable();
    addresses.dedup();
    Ok(addresses)
}

/// Address policy for resolved upstreams. Link-local, unspecified, multicast,
/// and reserved/non-global ranges are always rejected. Loopback and private
/// ranges require an explicit `allow_private` opt-in for local lab testing.
pub fn address_allowed(ip: IpAddr, allow_private: bool) -> bool {
    match ip {
        IpAddr::V4(address) => {
            if address.is_loopback() || address.is_private() {
                return allow_private;
            }
            is_public_v4(address)
        }
        IpAddr::V6(address) => {
            let first = address.segments()[0];
            let unique_local = first & 0xfe00 == 0xfc00;
            let link_local = first & 0xffc0 == 0xfe80;
            if link_local || address.is_multicast() || address.is_unspecified() {
                return false;
            }
            if address.is_loopback() || unique_local {
                return allow_private;
            }
            let global_unicast = first & 0xe000 == 0x2000;
            let documentation = first == 0x2001 && address.segments()[1] == 0x0db8;
            global_unicast && !documentation
        }
    }
}

fn is_public_v4(address: std::net::Ipv4Addr) -> bool {
    let octets = address.octets();
    let first = octets[0];
    let second = octets[1];
    let third = octets[2];
    if first == 0
        || first == 10
        || first == 127
        || first >= 224
        || (first == 100 && (64..=127).contains(&second))
        || (first == 169 && second == 254)
        || (first == 172 && (16..=31).contains(&second))
        || (first == 192 && second == 168)
        || (first == 192 && second == 0 && matches!(third, 0 | 2))
        || (first == 198 && matches!(second, 18 | 19))
        || (first == 198 && second == 51 && third == 100)
        || (first == 203 && second == 0 && third == 113)
    {
        return false;
    }
    true
}

pub async fn connect_upstream(
    destination: &Destination,
    allow_private: bool,
    connect_timeout: Duration,
) -> Result<TcpStream, Rejection> {
    let addresses = resolve_destination(destination, allow_private, connect_timeout).await?;
    timeout(connect_timeout, TcpStream::connect(&addresses[..]))
        .await
        .map_err(|_| Rejection::bad_gateway("upstream connection timed out"))?
        .map_err(|error| Rejection::bad_gateway(format!("upstream connection failed: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::Request;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    fn request(uri: &str) -> Request<()> {
        Request::builder().method("GET").uri(uri).body(()).unwrap()
    }

    #[test]
    fn absolute_form_targets_are_parsed_with_default_ports() {
        let request = request("http://example.test/path?q=1");
        let destination = Destination::from_http_request(&request).unwrap();
        assert_eq!(destination.host, "example.test");
        assert_eq!(destination.port, 80);
        assert_eq!(destination.target, "/path?q=1");
        assert_eq!(destination.authority, "example.test");
    }

    #[test]
    fn host_header_must_match_the_absolute_target() {
        let request = Request::builder()
            .method("GET")
            .uri("http://example.test/")
            .header(HOST, "evil.test")
            .body(())
            .unwrap();
        let rejection = Destination::from_http_request(&request).unwrap_err();
        assert_eq!(rejection.status, hyper::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn scope_rejects_unlisted_destinations() {
        let scope = Scope::allow(rawframe_core::models::ScopeRule::host("allowed.test"));
        let request = request("http://blocked.test/");
        let destination = Destination::from_http_request(&request).unwrap();
        assert!(!destination.is_permitted(&scope));
        assert_eq!(
            destination.scope_rejection().status,
            hyper::StatusCode::FORBIDDEN
        );
    }

    #[test]
    fn scope_supports_wildcards_scheme_and_port() {
        let scope = Scope::allow(rawframe_core::models::ScopeRule {
            host_pattern: "*.example.test".into(),
            scheme: Some(Scheme::Http),
            port: Some(8081),
        });
        let allowed = request("http://api.example.test:8081/");
        let destination = Destination::from_http_request(&allowed).unwrap();
        assert_eq!(destination.host, "api.example.test");
        assert!(destination.is_permitted(&scope));

        let wrong_port = request("http://api.example.test:8080/");
        let destination = Destination::from_http_request(&wrong_port).unwrap();
        assert!(!destination.is_permitted(&scope));

        let https = request("https://api.example.test:8081/");
        assert!(Destination::from_http_request(&https).is_err());
    }

    #[test]
    fn ipv6_authorities_are_normalized() {
        let scope = Scope::allow(rawframe_core::models::ScopeRule::host("::1"));
        let request = request("http://[::1]:8080/path");
        let destination = Destination::from_http_request(&request).unwrap();
        assert!(destination.is_permitted(&scope));
        assert_eq!(destination.host, "::1");
        assert_eq!(destination.port, 8080);
        assert_eq!(destination.authority, "[::1]:8080");
    }

    #[test]
    fn private_addresses_require_an_explicit_opt_in() {
        assert!(address_allowed(IpAddr::V4(Ipv4Addr::LOCALHOST), true));
        assert!(!address_allowed(IpAddr::V4(Ipv4Addr::LOCALHOST), false));
        assert!(address_allowed(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            true
        ));
        assert!(!address_allowed(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            false
        ));
        assert!(address_allowed(IpAddr::V6(Ipv6Addr::LOCALHOST), true));
        assert!(!address_allowed(IpAddr::V6(Ipv6Addr::LOCALHOST), false));
        assert!(!address_allowed(
            IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
            true
        ));
        assert!(address_allowed(
            IpAddr::V4(Ipv4Addr::from_str("93.184.216.34").unwrap()),
            false
        ));
        assert!(!address_allowed("2001:db8::1".parse().unwrap(), false));
    }
}
