//! Application configuration with secure defaults.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::message::{HttpRequest, Scheme};

pub const MAX_BODY_LIMIT_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_CONCURRENT_CONNECTIONS: usize = 4096;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub proxy: ProxyConfiguration,
    pub appearance: AppearanceConfiguration,
    pub storage: StorageConfiguration,
    pub interception_rules: Vec<InterceptionRule>,
}

impl AppConfig {
    /// Checks values that would make the proxy unsafe or non-functional.
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.proxy.validate()?;
        for rule in &self.interception_rules {
            rule.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ProxyConfiguration {
    pub bind_address: IpAddr,
    pub port: u16,
    /// Interception is opt-in. Even when enabled, only rules that match a
    /// request pause it.
    pub interception_enabled: bool,
    /// Upstream certificate verification. Enabled by default and surfaced as a
    /// security-critical setting rather than a casual toggle.
    pub verify_upstream_tls: bool,
    /// Explicit opt-in HTTPS interception (client-side TLS termination for
    /// authorized CONNECT destinations). Disabled by default; opaque tunnelling
    /// remains the default behavior.
    pub tls_interception_enabled: bool,
    /// Directory containing the local interception CA material (cert/key). When
    /// empty/unset, a default under RAWFRAME's data directory is used.
    pub tls_ca_dir: PathBuf,
    /// Optional explicit upstream trust bundle for lab/test deployments. When
    /// unset, the platform trust store is used. Verification and hostname checks
    /// remain mandatory regardless.
    pub tls_upstream_trust_file: Option<PathBuf>,
    pub max_body_bytes: usize,
    pub max_response_bytes: usize,
    pub max_connections: usize,
    pub connect_timeout_secs: u64,
    pub upstream_timeout_secs: u64,
    pub idle_timeout_secs: u64,
    pub intercept_timeout_secs: u64,
    pub intercept_queue_capacity: usize,
    /// Largest single RFC 6455 frame the WebSocket relay accepts.
    pub websocket_max_frame_bytes: usize,
    /// Largest reassembled WebSocket message kept for inspection.
    pub websocket_max_message_bytes: usize,
    /// Independent ceiling on concurrently relayed WebSocket connections.
    pub websocket_max_connections: usize,
    /// Per-frame/per-message payload bytes copied into the event bus and store.
    /// Larger payloads are still relayed; only capture is truncated.
    pub websocket_capture_bytes: usize,
    /// Idle ceiling for a WebSocket connection with no frames in either
    /// direction.
    pub websocket_idle_timeout_secs: u64,
    /// Lab deployments may target loopback/private upstreams. This is off by
    /// default so hostname scope cannot be rebound into a private network.
    pub allow_private_upstreams: bool,
    pub scope: Scope,
}

impl Default for ProxyConfiguration {
    fn default() -> Self {
        Self {
            // Binding to loopback prevents accidental exposure on a network.
            bind_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 8080,
            interception_enabled: false,
            verify_upstream_tls: true,
            tls_interception_enabled: false,
            tls_ca_dir: PathBuf::new(),
            tls_upstream_trust_file: None,
            max_body_bytes: 2 * 1024 * 1024,
            max_response_bytes: 2 * 1024 * 1024,
            max_connections: 128,
            connect_timeout_secs: 10,
            upstream_timeout_secs: 30,
            idle_timeout_secs: 60,
            intercept_timeout_secs: 120,
            intercept_queue_capacity: 32,
            websocket_max_frame_bytes: 2 * 1024 * 1024,
            websocket_max_message_bytes: 8 * 1024 * 1024,
            websocket_max_connections: 64,
            websocket_capture_bytes: 64 * 1024,
            websocket_idle_timeout_secs: 300,
            allow_private_upstreams: false,
            scope: Scope::default(),
        }
    }
}

impl ProxyConfiguration {
    pub fn listen_addr(&self) -> SocketAddr {
        SocketAddr::new(self.bind_address, self.port)
    }

    pub fn is_loopback_bind(&self) -> bool {
        self.bind_address.is_loopback()
    }

    pub fn tls_ca_dir_resolved(&self) -> PathBuf {
        if self.tls_ca_dir.as_os_str().is_empty() {
            data_directory().join("ca")
        } else {
            self.tls_ca_dir.clone()
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.port == 0 {
            return Err(ConfigError::InvalidPort(self.port));
        }
        if self.max_body_bytes == 0 {
            return Err(ConfigError::InvalidBodyLimit(self.max_body_bytes));
        }
        if self.max_body_bytes > MAX_BODY_LIMIT_BYTES {
            return Err(ConfigError::BodyLimitTooLarge {
                limit: self.max_body_bytes,
                max: MAX_BODY_LIMIT_BYTES,
            });
        }
        if self.max_response_bytes == 0 {
            return Err(ConfigError::InvalidResponseLimit(self.max_response_bytes));
        }
        if self.max_response_bytes > MAX_BODY_LIMIT_BYTES {
            return Err(ConfigError::ResponseLimitTooLarge {
                limit: self.max_response_bytes,
                max: MAX_BODY_LIMIT_BYTES,
            });
        }
        if self.max_connections == 0 || self.max_connections > MAX_CONCURRENT_CONNECTIONS {
            return Err(ConfigError::InvalidConnectionLimit {
                limit: self.max_connections,
                max: MAX_CONCURRENT_CONNECTIONS,
            });
        }
        if self.intercept_queue_capacity == 0 || self.intercept_queue_capacity > 4096 {
            return Err(ConfigError::InvalidInterceptQueue {
                limit: self.intercept_queue_capacity,
                max: 4096,
            });
        }
        if self.connect_timeout_secs == 0
            || self.upstream_timeout_secs == 0
            || self.idle_timeout_secs == 0
            || self.intercept_timeout_secs == 0
            || self.websocket_idle_timeout_secs == 0
        {
            return Err(ConfigError::InvalidTimeout {
                connect: self.connect_timeout_secs,
                intercept: self.intercept_timeout_secs,
            });
        }
        if self.websocket_max_frame_bytes == 0
            || self.websocket_max_frame_bytes > MAX_BODY_LIMIT_BYTES
        {
            return Err(ConfigError::InvalidWebSocketLimit {
                field: "frame",
                limit: self.websocket_max_frame_bytes,
                max: MAX_BODY_LIMIT_BYTES,
            });
        }
        if self.websocket_max_message_bytes == 0
            || self.websocket_max_message_bytes > MAX_BODY_LIMIT_BYTES
        {
            return Err(ConfigError::InvalidWebSocketLimit {
                field: "message",
                limit: self.websocket_max_message_bytes,
                max: MAX_BODY_LIMIT_BYTES,
            });
        }
        if self.websocket_capture_bytes == 0 || self.websocket_capture_bytes > MAX_BODY_LIMIT_BYTES
        {
            return Err(ConfigError::InvalidWebSocketLimit {
                field: "capture",
                limit: self.websocket_capture_bytes,
                max: MAX_BODY_LIMIT_BYTES,
            });
        }
        if self.websocket_max_connections == 0
            || self.websocket_max_connections > MAX_CONCURRENT_CONNECTIONS
        {
            return Err(ConfigError::InvalidWebSocketLimit {
                field: "connection",
                limit: self.websocket_max_connections,
                max: MAX_CONCURRENT_CONNECTIONS,
            });
        }
        self.scope.validate()?;
        if !self.verify_upstream_tls {
            return Err(ConfigError::InsecureTlsVerification);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AccentPreset {
    #[default]
    Violet,
    Indigo,
    Teal,
}

impl AccentPreset {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Violet => "Violet",
            Self::Indigo => "Indigo",
            Self::Teal => "Teal",
        }
    }

    pub const fn next(self) -> Self {
        match self {
            Self::Violet => Self::Indigo,
            Self::Indigo => Self::Teal,
            Self::Teal => Self::Violet,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AppearanceConfiguration {
    pub accent: AccentPreset,
    pub mouse_enabled: bool,
    /// Redacts Authorization, Cookie, Set-Cookie and API-key style fields in all
    /// inspectors and logs. Turning this off is an explicit operator action.
    pub redact_sensitive_headers: bool,
}

impl Default for AppearanceConfiguration {
    fn default() -> Self {
        Self {
            accent: AccentPreset::Violet,
            mouse_enabled: true,
            redact_sensitive_headers: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct StorageConfiguration {
    pub database_path: PathBuf,
    /// Bodies are not persisted unless the operator opts in.
    pub persist_bodies: bool,
    /// Sensitive headers are not persisted unless the operator opts in.
    pub persist_sensitive_headers: bool,
}

impl Default for StorageConfiguration {
    fn default() -> Self {
        Self {
            database_path: data_directory().join("rawframe.db"),
            persist_bodies: false,
            persist_sensitive_headers: false,
        }
    }
}

/// Platform data directory for RAWFRAME state. Falls back to a local directory
/// when the environment provides no home path.
pub fn data_directory() -> PathBuf {
    if let Some(xdg) = std::env::var_os("XDG_DATA_HOME").filter(|value| !value.is_empty()) {
        return PathBuf::from(xdg).join("rawframe");
    }
    if let Some(home) = std::env::var_os("HOME").filter(|value| !value.is_empty()) {
        return PathBuf::from(home).join(".local/share/rawframe");
    }
    PathBuf::from(".rawframe")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Scope {
    pub allowlist: Vec<ScopeRule>,
    /// Default-deny: with no rules, upstream traffic is refused. This prevents a
    /// freshly started proxy from becoming an open relay.
    pub block_unlisted: bool,
}

impl Default for Scope {
    fn default() -> Self {
        Self {
            allowlist: Vec::new(),
            block_unlisted: true,
        }
    }
}

impl Scope {
    pub fn allow(rule: ScopeRule) -> Self {
        Self {
            allowlist: vec![rule],
            block_unlisted: true,
        }
    }

    pub fn permits(&self, scheme: Scheme, host: &str, port: u16) -> bool {
        if !self.block_unlisted {
            return true;
        }
        self.allowlist
            .iter()
            .any(|rule| rule.matches(scheme, host, port))
    }

    pub fn validate(&self) -> Result<(), ScopeError> {
        for rule in &self.allowlist {
            rule.validate()?;
        }
        Ok(())
    }

    pub fn summary(&self) -> String {
        if !self.block_unlisted {
            return "open (block_unlisted = false)".to_string();
        }
        match self.allowlist.len() {
            0 => "deny all (no allowlist rules)".to_string(),
            1 => "1 allowlist rule".to_string(),
            count => format!("{count} allowlist rules"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeRule {
    /// Lower-case host or leading-wildcard host (`*.example.test`).
    pub host_pattern: String,
    pub scheme: Option<Scheme>,
    pub port: Option<u16>,
}

impl ScopeRule {
    pub fn host(pattern: impl Into<String>) -> Self {
        Self {
            host_pattern: pattern.into().to_ascii_lowercase(),
            scheme: None,
            port: None,
        }
    }

    pub fn matches(&self, scheme: Scheme, host: &str, port: u16) -> bool {
        if self.scheme.is_some_and(|allowed| allowed != scheme) {
            return false;
        }
        if self.port.is_some_and(|allowed| allowed != port) {
            return false;
        }
        host_matches(&self.host_pattern, host)
    }

    pub fn validate(&self) -> Result<(), ScopeError> {
        validate_host_pattern(&self.host_pattern)
    }

    /// Parses `host`, `host:port`, `http://host[:port]`, `https://host[:port]`,
    /// `[::1]:port`, and leading wildcard hosts. Shared by the CLI flag parser
    /// and the Settings scope editor so both accept exactly the same syntax.
    pub fn parse(spec: &str) -> Result<Self, ScopeParseError> {
        let spec = spec.trim();
        if spec.is_empty() {
            return Err(ScopeParseError::Empty);
        }
        let (scheme, authority) = if let Some((scheme, rest)) = spec.split_once("://") {
            let scheme = match scheme.to_ascii_lowercase().as_str() {
                "http" => Scheme::Http,
                "https" => Scheme::Https,
                other => return Err(ScopeParseError::UnsupportedScheme(other.to_string())),
            };
            (Some(scheme), rest)
        } else {
            (None, spec)
        };

        let (host, port) = parse_scope_authority(authority)?;
        let rule = Self {
            host_pattern: host.to_ascii_lowercase(),
            scheme,
            port,
        };
        rule.validate()?;
        Ok(rule)
    }

    /// Human-readable form that round-trips through [`ScopeRule::parse`].
    pub fn spec(&self) -> String {
        let mut spec = String::new();
        if let Some(scheme) = self.scheme {
            spec.push_str(scheme.as_str());
            spec.push_str("://");
        }
        if self.host_pattern.contains(':') && !self.host_pattern.starts_with('[') {
            spec.push('[');
            spec.push_str(&self.host_pattern);
            spec.push(']');
        } else {
            spec.push_str(&self.host_pattern);
        }
        if let Some(port) = self.port {
            spec.push(':');
            spec.push_str(&port.to_string());
        }
        spec
    }
}

fn parse_scope_authority(authority: &str) -> Result<(String, Option<u16>), ScopeParseError> {
    if authority.is_empty() || authority.contains('/') || authority.contains('@') {
        return Err(ScopeParseError::InvalidAuthority);
    }
    if let Some(bracketed) = authority.strip_prefix('[') {
        let end = bracketed
            .find(']')
            .ok_or(ScopeParseError::InvalidAuthority)?;
        let host = &bracketed[..end];
        let suffix = &bracketed[end + 1..];
        let port = if suffix.is_empty() {
            None
        } else if let Some(port) = suffix.strip_prefix(':') {
            Some(parse_scope_port(port)?)
        } else {
            return Err(ScopeParseError::InvalidAuthority);
        };
        if host.is_empty() {
            return Err(ScopeParseError::InvalidAuthority);
        }
        return Ok((host.to_string(), port));
    }

    if authority.matches(':').count() == 1 {
        let (host, port) = authority.rsplit_once(':').unwrap_or((authority, ""));
        if host.is_empty() {
            return Err(ScopeParseError::InvalidAuthority);
        }
        return Ok((host.to_string(), Some(parse_scope_port(port)?)));
    }
    Ok((authority.to_string(), None))
}

fn parse_scope_port(port: &str) -> Result<u16, ScopeParseError> {
    let port: u16 = port
        .parse()
        .map_err(|_| ScopeParseError::InvalidPort(port.to_string()))?;
    if port == 0 {
        return Err(ScopeParseError::InvalidPort(port.to_string()));
    }
    Ok(port)
}

fn host_matches(pattern: &str, host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    let host = host.trim_end_matches('.');

    if let Some(suffix) = pattern.strip_prefix("*.") {
        host == suffix || host.ends_with(&format!(".{suffix}"))
    } else {
        host == pattern
    }
}

fn validate_host_pattern(pattern: &str) -> Result<(), ScopeError> {
    if pattern.is_empty() {
        return Err(ScopeError::EmptyHostPattern);
    }
    let remainder = pattern.strip_prefix("*.").unwrap_or(pattern);
    if remainder.is_empty() || remainder.contains('*') {
        return Err(ScopeError::InvalidHostPattern(pattern.to_string()));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterceptionAction {
    Intercept,
    Forward,
}

impl InterceptionAction {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Intercept => "INTERCEPT",
            Self::Forward => "FORWARD",
        }
    }
}

/// A scope-aware interception rule. Rules are evaluated in order; the first
/// match wins. No rules means nothing is paused, even when interception is armed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterceptionRule {
    pub name: String,
    pub enabled: bool,
    pub method: Option<String>,
    pub host_pattern: Option<String>,
    pub path_contains: Option<String>,
    pub action: InterceptionAction,
}

impl InterceptionRule {
    pub fn matches(&self, request: &HttpRequest) -> bool {
        if !self.enabled {
            return false;
        }
        if let Some(method) = &self.method
            && !request.method.eq_ignore_ascii_case(method)
        {
            return false;
        }
        if let Some(pattern) = &self.host_pattern
            && !host_matches(&pattern.to_ascii_lowercase(), &request.host)
        {
            return false;
        }
        if let Some(path) = &self.path_contains
            && !request.target.contains(path)
        {
            return false;
        }
        true
    }

    pub fn validate(&self) -> Result<(), ScopeError> {
        if self.name.trim().is_empty() {
            return Err(ScopeError::EmptyRuleName);
        }
        if let Some(pattern) = &self.host_pattern {
            validate_host_pattern(&pattern.to_ascii_lowercase())?;
        }
        Ok(())
    }

    pub fn matches_any<'a>(rules: &'a [Self], request: &HttpRequest) -> Option<&'a Self> {
        rules.iter().find(|rule| rule.matches(request))
    }
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("port must be between 1 and 65535, got {0}")]
    InvalidPort(u16),
    #[error("max_body_bytes must be greater than zero")]
    InvalidBodyLimit(usize),
    #[error("body limit {limit} exceeds the supported maximum of {max} bytes")]
    BodyLimitTooLarge { limit: usize, max: usize },
    #[error("max_response_bytes must be greater than zero")]
    InvalidResponseLimit(usize),
    #[error("response limit {limit} exceeds the supported maximum of {max} bytes")]
    ResponseLimitTooLarge { limit: usize, max: usize },
    #[error("max_connections must be between 1 and {max}, got {limit}")]
    InvalidConnectionLimit { limit: usize, max: usize },
    #[error("intercept queue capacity must be between 1 and {max}, got {limit}")]
    InvalidInterceptQueue { limit: usize, max: usize },
    #[error("websocket {field} limit {limit} must be between 1 and {max}")]
    InvalidWebSocketLimit {
        field: &'static str,
        limit: usize,
        max: usize,
    },
    #[error("timeouts must be greater than zero (connect={connect}s, intercept={intercept}s)")]
    InvalidTimeout { connect: u64, intercept: u64 },
    #[error("upstream TLS verification cannot be disabled")]
    InsecureTlsVerification,
    #[error(transparent)]
    Scope(#[from] ScopeError),
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ScopeError {
    #[error("scope host pattern must not be empty")]
    EmptyHostPattern,
    #[error("invalid scope host pattern: {0}")]
    InvalidHostPattern(String),
    #[error("interception rule name must not be empty")]
    EmptyRuleName,
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ScopeParseError {
    #[error("scope rule must not be empty")]
    Empty,
    #[error("unsupported scope scheme '{0}' (use http or https)")]
    UnsupportedScheme(String),
    #[error("scope authority must be a host with an optional port")]
    InvalidAuthority,
    #[error("invalid scope port '{0}'")]
    InvalidPort(String),
    #[error(transparent)]
    Invalid(#[from] ScopeError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_local_and_deny_by_default() {
        let config = AppConfig::default();
        assert_eq!(config.proxy.bind_address, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(config.proxy.port, 8080);
        assert!(config.proxy.is_loopback_bind());
        assert!(!config.proxy.interception_enabled);
        assert!(config.proxy.verify_upstream_tls);
        assert!(!config.proxy.tls_interception_enabled);
        assert!(!config.storage.persist_bodies);
        assert!(!config.storage.persist_sensitive_headers);
        assert!(config.appearance.redact_sensitive_headers);
        assert!(
            !config
                .proxy
                .scope
                .permits(Scheme::Https, "api.rawframe.test", 443)
        );
        config.validate().unwrap();
    }

    #[test]
    fn scope_wildcards_match_apex_and_subdomains() {
        let scope = Scope::allow(ScopeRule::host("*.rawframe.test"));
        assert!(scope.permits(Scheme::Https, "api.rawframe.test", 443));
        assert!(scope.permits(Scheme::Https, "rawframe.test", 443));
        assert!(scope.permits(Scheme::Https, "DEEP.API.RAWFRAme.TEST.", 443));
        assert!(!scope.permits(Scheme::Https, "rawframe.test.evil", 443));
        assert!(scope.permits(Scheme::Http, "api.rawframe.test", 80));
    }

    #[test]
    fn scope_scheme_and_port_are_enforced() {
        let rule = ScopeRule {
            host_pattern: "api.rawframe.test".into(),
            scheme: Some(Scheme::Https),
            port: Some(8443),
        };
        let scope = Scope::allow(rule);
        assert!(scope.permits(Scheme::Https, "api.rawframe.test", 8443));
        assert!(!scope.permits(Scheme::Http, "api.rawframe.test", 8443));
        assert!(!scope.permits(Scheme::Https, "api.rawframe.test", 443));
    }

    #[test]
    fn invalid_scope_patterns_are_rejected() {
        let scope = Scope::allow(ScopeRule::host("api.*.test"));
        assert!(scope.validate().is_err());

        let scope = Scope::allow(ScopeRule::host(""));
        assert!(scope.validate().is_err());
    }

    #[test]
    fn interception_rules_match_first_in_order() {
        let request = HttpRequest::new(
            "POST",
            Scheme::Https,
            "api.rawframe.test",
            443,
            "/v1/orders",
        );
        let rules = vec![
            InterceptionRule {
                name: "ignore health".into(),
                enabled: true,
                method: None,
                host_pattern: Some("api.rawframe.test".into()),
                path_contains: Some("/health".into()),
                action: InterceptionAction::Intercept,
            },
            InterceptionRule {
                name: "pause orders".into(),
                enabled: true,
                method: Some("POST".into()),
                host_pattern: Some("*.rawframe.test".into()),
                path_contains: Some("/orders".into()),
                action: InterceptionAction::Intercept,
            },
        ];

        let matched = InterceptionRule::matches_any(&rules, &request).unwrap();
        assert_eq!(matched.name, "pause orders");
    }

    #[test]
    fn disabled_rules_never_match() {
        let request = HttpRequest::new("GET", Scheme::Https, "a.test", 443, "/");
        let rule = InterceptionRule {
            name: "off".into(),
            enabled: false,
            method: None,
            host_pattern: None,
            path_contains: None,
            action: InterceptionAction::Intercept,
        };
        assert!(!rule.matches(&request));
    }

    #[test]
    fn validation_rejects_unusable_limits() {
        let mut config = AppConfig::default();
        config.proxy.port = 0;
        assert_eq!(config.validate(), Err(ConfigError::InvalidPort(0)));

        config.proxy.port = 8080;
        config.proxy.max_body_bytes = 0;
        assert!(config.validate().is_err());

        config.proxy.max_body_bytes = MAX_BODY_LIMIT_BYTES + 1;
        assert!(config.validate().is_err());

        config.proxy.max_body_bytes = 1024;
        config.proxy.connect_timeout_secs = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn scope_rule_parsing_round_trips() {
        for spec in [
            "api.example.test",
            "https://api.example.test:8443",
            "http://127.0.0.1:8081",
            "*.rawframe.test",
            "https://[::1]:8443",
        ] {
            let rule = ScopeRule::parse(spec).unwrap();
            assert_eq!(rule.spec(), spec);
            rule.validate().unwrap();
        }
    }

    #[test]
    fn scope_rule_parsing_rejects_invalid_input() {
        for spec in [
            "",
            "ftp://host",
            "host:not-a-port",
            "host/path",
            "[::1",
            "host:0",
        ] {
            assert!(ScopeRule::parse(spec).is_err(), "accepted: {spec}");
        }
    }

    #[test]
    fn accent_presets_cycle() {
        assert_eq!(AccentPreset::Violet.next(), AccentPreset::Indigo);
        assert_eq!(AccentPreset::Indigo.next(), AccentPreset::Teal);
        assert_eq!(AccentPreset::Teal.next(), AccentPreset::Violet);
    }
}
