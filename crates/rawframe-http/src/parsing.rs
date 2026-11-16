//! Parsing of authored HTTP/1.x documents.

use httparse::{EMPTY_HEADER, Request, Response, Status};
use rawframe_core::models::Headers;
use rawframe_core::models::message::{HttpRequest, HttpResponse, Scheme};

use crate::error::ParseError;

const MAX_HEADERS: usize = 128;

/// Parses an HTTP request document. `default_scheme` is used for origin-form
/// targets, which carry no scheme; it should reflect the connection context the
/// document is being edited for.
pub fn parse_request(raw: &str, default_scheme: Scheme) -> Result<HttpRequest, ParseError> {
    if raw.trim().is_empty() {
        return Err(ParseError::Empty);
    }

    let (head, body) = split_head_body(raw);
    let normalized = normalize_head(head);
    let mut parsed_headers = [EMPTY_HEADER; MAX_HEADERS];
    let (method, target, version) = {
        let mut parsed = Request::new(&mut parsed_headers);
        match parsed.parse(normalized.as_bytes()) {
            Ok(Status::Complete(_)) => {}
            Ok(Status::Partial) => return Err(ParseError::Incomplete),
            Err(httparse::Error::TooManyHeaders) => return Err(ParseError::TooManyHeaders),
            Err(error) => return Err(ParseError::Malformed(error.to_string())),
        }

        let method = parsed
            .method
            .ok_or(ParseError::Malformed("missing request method".into()))?
            .to_ascii_uppercase();
        if method.is_empty() {
            return Err(ParseError::Malformed("empty request method".into()));
        }
        let target = parsed
            .path
            .ok_or(ParseError::Malformed("missing request target".into()))?
            .to_string();
        if target.is_empty() {
            return Err(ParseError::InvalidTarget);
        }
        let version = version_string(parsed.version);
        (method, target, version)
    };

    let headers = collect_headers(&parsed_headers)?;

    let (scheme, host, port, target) =
        if let Some((scheme, host, port, target)) = parse_absolute_target(&target)? {
            (scheme, host, port, target)
        } else {
            let host_header = headers.get("host").ok_or(ParseError::MissingHost)?;
            let (host, port) = parse_authority(host_header, default_scheme.default_port())?;
            (default_scheme, host, port, target)
        };
    let mut request = HttpRequest::new(method, scheme, host, port, target);
    if !headers.contains("host") {
        let authority = request.authority();
        request.headers = headers;
        request.headers.insert("Host", authority);
    } else {
        request.headers = headers;
    }
    request.version = version;
    request.body = body.as_bytes().to_vec();

    Ok(request)
}

/// Parses an HTTP response document.
pub fn parse_response(raw: &str) -> Result<HttpResponse, ParseError> {
    if raw.trim().is_empty() {
        return Err(ParseError::Empty);
    }

    let (head, body) = split_head_body(raw);
    let normalized = normalize_head(head);
    let mut parsed_headers = [EMPTY_HEADER; MAX_HEADERS];
    let (status, reason, version) = {
        let mut parsed = Response::new(&mut parsed_headers);
        match parsed.parse(normalized.as_bytes()) {
            Ok(Status::Complete(_)) => {}
            Ok(Status::Partial) => return Err(ParseError::Incomplete),
            Err(httparse::Error::TooManyHeaders) => return Err(ParseError::TooManyHeaders),
            Err(error) => return Err(ParseError::Malformed(error.to_string())),
        }

        let status = parsed.code.ok_or(ParseError::InvalidStatus)?;
        if !(100..=999).contains(&status) {
            return Err(ParseError::InvalidStatus);
        }
        let reason = parsed.reason.unwrap_or_default().to_string();
        let version = version_string(parsed.version);
        (status, reason, version)
    };

    let headers = collect_headers(&parsed_headers)?;

    let mut response = HttpResponse::new(status);
    response.reason = reason;
    response.version = version;
    response.headers = headers;
    response.body = body.as_bytes().to_vec();
    Ok(response)
}

fn split_head_body(raw: &str) -> (&str, &str) {
    if let Some(index) = raw.find("\r\n\r\n") {
        (&raw[..index], &raw[index + 4..])
    } else if let Some(index) = raw.find("\n\n") {
        (&raw[..index], &raw[index + 2..])
    } else {
        (raw, "")
    }
}

/// Normalizes line endings so `httparse` sees canonical CRLF separators. A
/// trailing blank line is supplied when the editor omits it.
fn normalize_head(head: &str) -> String {
    let mut normalized = String::with_capacity(head.len() + 4);
    for line in head.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        normalized.push_str(line);
        normalized.push_str("\r\n");
    }
    normalized.push_str("\r\n");
    normalized
}

fn collect_headers(headers: &[httparse::Header<'_>; MAX_HEADERS]) -> Result<Headers, ParseError> {
    let mut collected = Headers::new();
    for header in headers.iter() {
        if header.name.is_empty() {
            break;
        }
        let value = std::str::from_utf8(header.value)
            .map_err(|_| ParseError::InvalidHeaderValue)?
            .trim()
            .to_string();
        collected.append(header.name.to_string(), value);
    }
    Ok(collected)
}

fn version_string(version: Option<u8>) -> String {
    match version {
        Some(0) => "HTTP/1.0".to_string(),
        _ => "HTTP/1.1".to_string(),
    }
}

/// Returns the parsed absolute target when the request line contains one.
fn parse_absolute_target(
    target: &str,
) -> Result<Option<(Scheme, String, u16, String)>, ParseError> {
    let lower = target.to_ascii_lowercase();
    let (scheme, prefix_len) = if lower.starts_with("https://") {
        (Scheme::Https, "https://".len())
    } else if lower.starts_with("http://") {
        (Scheme::Http, "http://".len())
    } else {
        return Ok(None);
    };

    let remainder = &target[prefix_len..];
    let boundary = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
    let authority = &remainder[..boundary];
    if authority.is_empty() {
        return Err(ParseError::InvalidAuthority(authority.to_string()));
    }

    let (host, port) = parse_authority(authority, scheme.default_port())?;
    let mut path = &remainder[boundary..];
    if path.is_empty() {
        path = "/";
    } else if !path.starts_with('/') {
        return Err(ParseError::InvalidTarget);
    }

    Ok(Some((scheme, host, port, path.to_string())))
}

fn parse_authority(authority: &str, default_port: u16) -> Result<(String, u16), ParseError> {
    let authority = authority.trim();
    if authority.is_empty()
        || authority.contains('@')
        || authority.contains(char::is_whitespace)
        || authority.contains('/')
        || authority.contains('?')
        || authority.contains('#')
    {
        return Err(ParseError::InvalidAuthority(authority.to_string()));
    }

    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let closing = rest
            .find(']')
            .ok_or_else(|| ParseError::InvalidAuthority(authority.to_string()))?;
        let host = &rest[..closing];
        let after = &rest[closing + 1..];
        if host.is_empty() {
            return Err(ParseError::InvalidAuthority(authority.to_string()));
        }
        let port = if after.is_empty() {
            default_port
        } else {
            let port = after
                .strip_prefix(':')
                .ok_or_else(|| ParseError::InvalidAuthority(authority.to_string()))?;
            parse_port(port)?
        };
        (host.to_string(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => {
                if port.is_empty() {
                    return Err(ParseError::InvalidPort(port.to_string()));
                }
                (host.to_string(), parse_port(port)?)
            }
            Some(_) => return Err(ParseError::InvalidAuthority(authority.to_string())),
            None => (authority.to_string(), default_port),
        }
    };

    if host.is_empty() {
        return Err(ParseError::InvalidAuthority(authority.to_string()));
    }

    Ok((host.to_ascii_lowercase(), port))
}

fn parse_port(port: &str) -> Result<u16, ParseError> {
    let parsed = port
        .parse::<u16>()
        .map_err(|_| ParseError::InvalidPort(port.to_string()))?;
    if parsed == 0 {
        return Err(ParseError::InvalidPort(port.to_string()));
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_origin_form_request_with_headers_and_body() {
        let raw = "POST /v1/orders?dry_run=true HTTP/1.1\r\n\
                   Host: api.rawframe.test\r\n\
                   Authorization: Bearer fixture\r\n\
                   Content-Type: application/json\r\n\
                   \r\n\
                   {\"sku\":\"LAMP-01\"}";

        let request = parse_request(raw, Scheme::Https).unwrap();
        assert_eq!(request.method, "POST");
        assert_eq!(request.scheme, Scheme::Https);
        assert_eq!(request.host, "api.rawframe.test");
        assert_eq!(request.port, 443);
        assert_eq!(request.target, "/v1/orders?dry_run=true");
        assert_eq!(request.body, br#"{"sku":"LAMP-01"}"#);
        assert_eq!(request.headers.get("authorization"), Some("Bearer fixture"));
    }

    #[test]
    fn parses_absolute_form_and_overrides_scheme() {
        let raw = "GET http://legacy.rawframe.test:8081/status?full=1 HTTP/1.1\r\n\
                   Host: ignored.example\r\n\r\n";
        let request = parse_request(raw, Scheme::Https).unwrap();

        assert_eq!(request.scheme, Scheme::Http);
        assert_eq!(request.host, "legacy.rawframe.test");
        assert_eq!(request.port, 8081);
        assert_eq!(request.target, "/status?full=1");
        // The authored Host field is preserved, even when it differs.
        assert_eq!(request.headers.get("host"), Some("ignored.example"));
    }

    #[test]
    fn absolute_target_without_path_gets_root() {
        let request =
            parse_request("GET https://api.rawframe.test HTTP/1.1\n\n", Scheme::Http).unwrap();
        assert_eq!(request.target, "/");
        assert_eq!(request.url(), "https://api.rawframe.test/");
    }

    #[test]
    fn lf_only_documents_are_accepted() {
        let raw = "GET /healthz HTTP/1.1\nHost: internal.rawframe.test\nAccept: */*\n\nok";
        let request = parse_request(raw, Scheme::Https).unwrap();
        assert_eq!(request.headers.len(), 2);
        assert_eq!(request.body, b"ok");
    }

    #[test]
    fn duplicate_headers_are_preserved_in_order() {
        let raw = "GET / HTTP/1.1\r\nHost: a.test\r\nX-Trace: one\r\nX-Trace: two\r\n\r\n";
        let request = parse_request(raw, Scheme::Https).unwrap();
        assert_eq!(
            request.headers.get_all("x-trace").collect::<Vec<_>>(),
            ["one", "two"]
        );
    }

    #[test]
    fn missing_host_is_an_error_for_origin_form() {
        let error =
            parse_request("GET / HTTP/1.1\r\nAccept: */*\r\n\r\n", Scheme::Https).unwrap_err();
        assert_eq!(error, ParseError::MissingHost);
    }

    #[test]
    fn malformed_start_line_is_rejected() {
        assert!(parse_request("not a request\r\n\r\n", Scheme::Https).is_err());
        assert_eq!(
            parse_request("   \n", Scheme::Https).unwrap_err(),
            ParseError::Empty
        );
    }

    #[test]
    fn ipv6_authorities_are_supported() {
        let raw = "GET / HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n";
        let request = parse_request(raw, Scheme::Http).unwrap();
        assert_eq!(request.host, "::1");
        assert_eq!(request.port, 8080);
        assert_eq!(request.authority(), "[::1]:8080");
    }

    #[test]
    fn invalid_authorities_are_rejected() {
        let raw = "GET / HTTP/1.1\r\nHost: user@api.rawframe.test\r\n\r\n";
        assert!(matches!(
            parse_request(raw, Scheme::Https),
            Err(ParseError::InvalidAuthority(_))
        ));

        let raw = "GET / HTTP/1.1\r\nHost: api.rawframe.test:0\r\n\r\n";
        assert!(matches!(
            parse_request(raw, Scheme::Https),
            Err(ParseError::InvalidPort(_))
        ));
    }

    #[test]
    fn options_asterisk_target_is_preserved() {
        let request = parse_request(
            "OPTIONS * HTTP/1.1\r\nHost: api.rawframe.test\r\n\r\n",
            Scheme::Https,
        )
        .unwrap();
        assert_eq!(request.target, "*");
    }

    #[test]
    fn parses_response_with_unknown_reason() {
        let raw = "HTTP/1.1 599 Upstream exploded\r\nContent-Type: text/plain\r\n\r\nboom";
        let response = parse_response(raw).unwrap();
        assert_eq!(response.status, 599);
        assert_eq!(response.reason, "Upstream exploded");
        assert_eq!(response.body, b"boom");
    }

    #[test]
    fn parses_response_without_reason_phrase() {
        let response = parse_response("HTTP/1.0 204\r\n\r\n").unwrap();
        assert_eq!(response.version, "HTTP/1.0");
        assert_eq!(response.status, 204);
        assert_eq!(response.reason, "");
        assert_eq!(response.status_line(), "HTTP/1.0 204");
    }

    #[test]
    fn round_trips_a_request_document() {
        let raw = "PUT /v1/profile HTTP/1.1\nHost: api.rawframe.test\nCookie: a=b\n\n{\"ok\":true}";
        let request = parse_request(raw, Scheme::Https).unwrap();
        let rendered = request.to_http_string(false);

        let reparsed = parse_request(&rendered, Scheme::Https).unwrap();
        assert_eq!(reparsed, request);
    }

    #[test]
    fn empty_response_is_rejected() {
        assert_eq!(parse_response("").unwrap_err(), ParseError::Empty);
    }
}
