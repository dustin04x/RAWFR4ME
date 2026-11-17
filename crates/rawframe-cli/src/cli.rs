//! Command-line arguments and validation.

use std::net::IpAddr;
use std::path::PathBuf;

use anyhow::{Result, bail};
use clap::Parser;
use rawframe_core::AppConfig;
use rawframe_core::models::{ScopeRule, Session};

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

    /// SQLite database for captured history (defaults to the platform data dir).
    #[arg(long, value_name = "FILE")]
    pub db: Option<PathBuf>,

    /// Run without persistence. Captured traffic stays in memory only.
    #[arg(long)]
    pub no_persist: bool,

    /// Store captured request and response bodies (off by default).
    #[arg(long)]
    pub persist_bodies: bool,

    /// Store sensitive header values instead of <redacted> (off by default).
    #[arg(long)]
    pub persist_sensitive_headers: bool,

    /// Name for this capture session (recorded in the database).
    #[arg(long, value_name = "NAME")]
    pub session_name: Option<String>,

    /// Name for the project that owns this session.
    #[arg(long, value_name = "NAME")]
    pub project: Option<String>,

    /// Export stored history as redacted JSON Lines to FILE and exit.
    #[arg(long, value_name = "FILE")]
    pub export_history: Option<PathBuf>,

    /// Session id to export with --export-history (defaults to the newest session).
    #[arg(long, value_name = "ID")]
    pub export_session: Option<String>,

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
        if let Some(path) = &self.db {
            config.storage.database_path = path.clone();
        }
        config.storage.persist_bodies = self.persist_bodies;
        config.storage.persist_sensitive_headers = self.persist_sensitive_headers;
        config
            .validate()
            .map_err(|error| anyhow::anyhow!("invalid configuration: {error}"))?;
        Ok(config)
    }

    /// The capture session for this run, owned by the named project (if any).
    pub fn session_and_project(&self) -> (Session, rawframe_core::models::Project) {
        let project = match &self.project {
            Some(name) => {
                // Stable identifier so repeated runs with the same project name
                // group their sessions instead of creating a new project each time.
                let slug: String = name
                    .trim()
                    .to_ascii_lowercase()
                    .chars()
                    .map(|ch| {
                        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_') {
                            ch
                        } else {
                            '-'
                        }
                    })
                    .collect();
                let mut project = rawframe_core::models::Project::new(name.clone());
                if !slug.is_empty() {
                    project.id = rawframe_core::models::ProjectId(format!("proj-{slug}"));
                }
                project
            }
            None => rawframe_core::models::Project::default_project(),
        };
        let mut session = Session::new(
            self.session_name
                .clone()
                .unwrap_or_else(|| "capture".to_string()),
        );
        session.project_id = project.id.clone();
        (session, project)
    }

    pub fn persistence_enabled(&self) -> bool {
        !self.no_persist
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
    ScopeRule::parse(spec).map_err(|error| anyhow::anyhow!("invalid --scope '{spec}': {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use rawframe_core::models::Scheme;

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
    fn persistence_flags_shape_the_database_and_policy() {
        let cli = parse(&[
            "rawframe",
            "--db",
            "/tmp/rawframe-test.db",
            "--persist-bodies",
            "--persist-sensitive-headers",
            "--session-name",
            "engagement",
            "--project",
            "acme",
        ]);
        assert!(cli.persistence_enabled());
        let config = cli.apply(AppConfig::default()).unwrap();
        assert_eq!(
            config.storage.database_path,
            PathBuf::from("/tmp/rawframe-test.db")
        );
        assert!(config.storage.persist_bodies);
        assert!(config.storage.persist_sensitive_headers);

        let (session, project) = cli.session_and_project();
        assert_eq!(session.name, "engagement");
        assert_eq!(project.name, "acme");
        assert_eq!(project.id.0, "proj-acme", "stable project id");
        assert_eq!(session.project_id, project.id);

        // Repeated runs with the same project name land in the same project.
        let (_, second) = parse(&["rawframe", "--project", "acme"]).session_and_project();
        assert_eq!(second.id, project.id);
    }

    #[test]
    fn no_persist_leaves_the_default_policy_off() {
        let cli = parse(&["rawframe", "--no-persist"]);
        assert!(!cli.persistence_enabled());
        let config = cli.apply(AppConfig::default()).unwrap();
        assert!(!config.storage.persist_bodies);
        assert!(!config.storage.persist_sensitive_headers);
    }

    #[test]
    fn help_text_states_the_authorization_boundary() {
        let result = Cli::try_parse_from(["rawframe", "--help"]);
        assert!(result.is_err());
        let error = result.unwrap_err().to_string();
        assert!(error.contains("authorization"));
    }
}
