//! Command-line arguments and validation.

use std::net::IpAddr;
use std::path::PathBuf;

use anyhow::{Result, bail};
use clap::Parser;
use rawframe_core::AppConfig;
use rawframe_core::models::{Scheme, ScopeRule};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaAction {
    Show,
    Export(PathBuf),
    Fingerprint,
    Regenerate,
}

#[derive(Debug, Clone, Parser, PartialEq, Eq)]
#[command(
    name = "rawframe",
    version,
    about = "RAWFRAME — terminal-native HTTP interception & security testing workbench",
    long_about = "RAWFRAME is a terminal-native interception and security testing workbench.\n\
                  This build forwards HTTP/1.1 and relays opaque HTTPS CONNECT tunnels by default. \
                  HTTPS TLS interception is opt-in and requires explicit CA trust. Repeater transmission is not implemented.",
    after_help = "Only test systems for which you have explicit authorization."
)]
pub struct Cli {
    /// Address for the proxy listener. Defaults to loopback.
    #[arg(long, value_name = "ADDR", default_value = "127.0.0.1")]
    pub bind: IpAddr,

    /// Port for the proxy listener.
    #[arg(long, value_name = "PORT", default_value_t = 8080)]
    pub port: u16,

    /// Permit a non-loopback bind address.
    #[arg(long)]
    pub allow_remote_bind: bool,

    /// Add an upstream scope rule: [http|https://]host[:port] or a wildcard host.
    /// Repeat the flag for multiple destinations. Without rules, all upstreams
    /// are denied by default.
    #[arg(long = "scope", value_name = "RULE", action = clap::ArgAction::Append)]
    pub scope: Vec<String>,

    /// Permit loopback/private upstream addresses for local lab targets. Off by
    /// default to prevent hostname scope from being rebound into private networks.
    #[arg(long)]
    pub allow_private_upstreams: bool,

    /// Disable mouse capture and mouse interaction for this run.
    #[arg(long)]
    pub no_mouse: bool,

    /// Disable sensitive-header redaction. This exposes captured credentials on screen.
    #[arg(long)]
    pub no_redact: bool,

    /// Write diagnostics to this file instead of the default local log path.
    #[arg(long, value_name = "FILE")]
    pub log_file: Option<PathBuf>,

    /// Explicitly enable HTTPS TLS interception for authorized scoped CONNECT
    /// targets (disabled by default; opaque tunnelling remains default).
    #[arg(long)]
    pub tls_intercept: bool,

    /// Directory for local interception CA material (certificate/key).
    #[arg(long, value_name = "DIR")]
    pub tls_ca_dir: Option<PathBuf>,

    /// Verify upstream TLS against this PEM bundle instead of the platform trust
    /// store (lab use only; chain and hostname verification remain mandatory).
    #[arg(long, value_name = "FILE")]
    pub tls_upstream_ca: Option<PathBuf>,

    /// Print local CA certificate path/status and exit.
    #[arg(long)]
    pub tls_ca_show: bool,

    /// Export the public CA certificate PEM to a file and exit.
    #[arg(long, value_name = "FILE")]
    pub tls_ca_export: Option<PathBuf>,

    /// Print the local CA certificate SHA-256 fingerprint and exit.
    #[arg(long)]
    pub tls_ca_fingerprint: bool,

    /// Explicitly regenerate the local interception CA and exit (invalidates prior trust).
    #[arg(long)]
    pub tls_ca_regenerate: bool,
}

impl Cli {
    /// Applies CLI overrides and enforces the local-binding safety rule.
    pub fn apply(&self, mut config: AppConfig) -> Result<AppConfig> {
        if !self.bind.is_loopback() && !self.allow_remote_bind {
            bail!(
                "refusing non-loopback bind address {} without --allow-remote-bind",
                self.bind
            );
        }
        config.proxy.bind_address = self.bind;
        config.proxy.port = self.port;
        config.proxy.allow_private_upstreams = self.allow_private_upstreams;
        config.proxy.tls_interception_enabled = self.tls_intercept;
        if let Some(dir) = &self.tls_ca_dir {
            config.proxy.tls_ca_dir = dir.clone();
        }
        config.proxy.tls_upstream_trust_file = self.tls_upstream_ca.clone();
        config.proxy.scope.allowlist = self
            .scope
            .iter()
            .map(|rule| parse_scope_rule(rule))
            .collect::<Result<Vec<_>>>()?;
        config.proxy.scope.block_unlisted = true;
        config.appearance.mouse_enabled = !self.no_mouse;
        config.appearance.redact_sensitive_headers = !self.no_redact;
        config
            .validate()
            .map_err(|error| anyhow::anyhow!("invalid configuration: {error}"))?;
        Ok(config)
    }

    pub fn log_path(&self) -> Option<&PathBuf> {
        self.log_file.as_ref()
    }

    pub fn ca_action(&self) -> Option<CaAction> {
        if self.tls_ca_show {
            Some(CaAction::Show)
        } else if let Some(path) = &self.tls_ca_export {
            Some(CaAction::Export(path.clone()))
        } else if self.tls_ca_fingerprint {
            Some(CaAction::Fingerprint)
        } else if self.tls_ca_regenerate {
            Some(CaAction::Regenerate)
        } else {
            None
        }
    }
}

fn parse_scope_rule(spec: &str) -> Result<ScopeRule> {
    let spec = spec.trim();
    if spec.is_empty() {
        bail!("--scope requires a non-empty host rule");
    }
    let (scheme, authority) = if let Some((scheme, rest)) = spec.split_once("://") {
        let scheme = match scheme.to_ascii_lowercase().as_str() {
            "http" => Scheme::Http,
            "https" => Scheme::Https,
            other => bail!("unsupported scope scheme '{other}' (use http or https)"),
        };
        (Some(scheme), rest)
    } else {
        (None, spec)
    };

    let (host, port) = parse_scope_authority(authority)?;
    let rule = ScopeRule {
        host_pattern: host.to_ascii_lowercase(),
        scheme,
        port,
    };
    rule.validate()
        .map_err(|error| anyhow::anyhow!("invalid --scope '{spec}': {error}"))?;
    Ok(rule)
}

fn parse_scope_authority(authority: &str) -> Result<(String, Option<u16>)> {
    if authority.is_empty() || authority.contains('/') || authority.contains('@') {
        bail!("--scope authority must be a host with an optional port");
    }
    if let Some(bracketed) = authority.strip_prefix('[') {
        let end = bracketed
            .find(']')
            .ok_or_else(|| anyhow::anyhow!("unterminated IPv6 literal in --scope"))?;
        let host = &bracketed[..end];
        let suffix = &bracketed[end + 1..];
        let port = if suffix.is_empty() {
            None
        } else if let Some(port) = suffix.strip_prefix(':') {
            Some(parse_port(port)?)
        } else {
            bail!("invalid IPv6 scope authority '{authority}'");
        };
        if host.is_empty() {
            bail!("--scope host must not be empty");
        }
        return Ok((host.to_string(), port));
    }

    if authority.matches(':').count() == 1 {
        let (host, port) = authority.rsplit_once(':').unwrap_or((authority, ""));
        if host.is_empty() {
            bail!("--scope host must not be empty");
        }
        return Ok((host.to_string(), Some(parse_port(port)?)));
    }
    Ok((authority.to_string(), None))
}

fn parse_port(port: &str) -> Result<u16> {
    let port: u16 = port
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid scope port '{port}'"))?;
    if port == 0 {
        bail!("scope port must be between 1 and 65535");
    }
    Ok(port)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(args).expect("valid arguments")
    }

    #[test]
    fn defaults_are_local_and_safe() {
        let cli = parse(&["rawframe"]);
        assert!(cli.bind.is_loopback());
        assert_eq!(cli.port, 8080);
        assert!(!cli.no_mouse);
        assert!(!cli.no_redact);
        assert!(!cli.allow_remote_bind);
        assert!(cli.scope.is_empty());
        assert!(!cli.allow_private_upstreams);

        let config = cli.apply(AppConfig::default()).unwrap();
        assert!(config.proxy.is_loopback_bind());
        assert!(config.appearance.mouse_enabled);
        assert!(config.appearance.redact_sensitive_headers);
        assert!(config.proxy.scope.allowlist.is_empty());
        assert!(!config.proxy.allow_private_upstreams);
    }

    #[test]
    fn scope_rules_support_schemes_ports_and_wildcards() {
        let cli = parse(&[
            "rawframe",
            "--scope",
            "http://127.0.0.1:8081",
            "--scope",
            "*.example.test",
            "--scope",
            "https://[::1]:8443",
        ]);
        let config = cli.apply(AppConfig::default()).unwrap();
        assert_eq!(config.proxy.scope.allowlist.len(), 3);
        assert!(config.proxy.scope.permits(Scheme::Http, "127.0.0.1", 8081));
        assert!(!config.proxy.scope.permits(Scheme::Https, "127.0.0.1", 8081));
        assert!(
            config
                .proxy
                .scope
                .permits(Scheme::Http, "api.example.test", 80)
        );
        assert!(config.proxy.scope.permits(Scheme::Https, "::1", 8443));
    }

    #[test]
    fn invalid_scope_rules_are_rejected() {
        for rule in ["http://host:not-a-port", "ftp://host", "host/path", "[::1"] {
            let cli = parse(&["rawframe", "--scope", rule]);
            assert!(cli.apply(AppConfig::default()).is_err(), "rule: {rule}");
        }
    }

    #[test]
    fn private_upstreams_require_the_explicit_flag() {
        let cli = parse(&["rawframe", "--allow-private-upstreams"]);
        let config = cli.apply(AppConfig::default()).unwrap();
        assert!(config.proxy.allow_private_upstreams);
    }

    #[test]
    fn non_loopback_binds_require_an_explicit_flag() {
        let cli = parse(&["rawframe", "--bind", "0.0.0.0"]);
        let error = cli.apply(AppConfig::default()).unwrap_err();
        assert!(error.to_string().contains("--allow-remote-bind"));

        let cli = parse(&["rawframe", "--bind", "0.0.0.0", "--allow-remote-bind"]);
        let config = cli.apply(AppConfig::default()).unwrap();
        assert_eq!(config.proxy.bind_address.to_string(), "0.0.0.0");
    }

    #[test]
    fn interaction_and_redaction_flags_are_applied() {
        let cli = parse(&["rawframe", "--no-mouse", "--no-redact"]);
        let config = cli.apply(AppConfig::default()).unwrap();
        assert!(!config.appearance.mouse_enabled);
        assert!(!config.appearance.redact_sensitive_headers);
    }

    #[test]
    fn invalid_ports_are_rejected() {
        let cli = parse(&["rawframe", "--port", "0"]);
        assert!(cli.apply(AppConfig::default()).is_err());
    }

    #[test]
    fn help_text_states_the_authorization_boundary() {
        let result = Cli::try_parse_from(["rawframe", "--help"]);
        assert!(result.is_err());
        let error = result.unwrap_err().to_string();
        assert!(error.contains("authorization"));
    }
}
