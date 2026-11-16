use std::fs;
use std::io::Write;

use anyhow::{Context, Result};
use clap::Parser;
use rawframe_cli::cli::{CaAction, Cli};
use rawframe_core::AppConfig;

fn handle_ca_action(action: &CaAction, config: &AppConfig) -> Result<()> {
    use rawframe_proxy::tls_api::{CaManager, CaPaths, CaStatus};
    let dir = config.proxy.tls_ca_dir_resolved();
    let paths = CaPaths::new(&dir);
    match action {
        CaAction::Show => {
            let info = CaManager::inspect(&paths);
            println!("CA directory: {}", paths.dir.display());
            println!("CA certificate: {}", paths.cert_path.display());
            println!("CA key: {}", paths.key_path.display());
            match info.status {
                CaStatus::Ready => println!("Status: ready"),
                CaStatus::Missing => println!("Status: missing or invalid (not ready)"),
            }
            if let Some(fp) = info.fingerprint_sha256 {
                println!("Fingerprint: {fp}");
            }
            println!(
                "Trust: install/trust the public CA certificate explicitly in your client/system; never trust private keys."
            );
            println!(
                "Disable interception: run without --tls-intercept (default is opaque CONNECT tunnelling)."
            );
        }
        CaAction::Fingerprint => {
            let ca = CaManager::load(&paths).context("loading local CA (generate it by enabling TLS interception or using --tls-ca-regenerate)")?;
            println!("{}", ca.fingerprint_sha256());
        }
        CaAction::Export(out) => {
            let ca = CaManager::load(&paths).context("loading local CA for export")?;
            if let Some(parent) = out.parent()
                && !parent.as_os_str().is_empty()
            {
                fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
            let mut file =
                fs::File::create(out).with_context(|| format!("writing {}", out.display()))?;
            file.write_all(ca.cert_pem().as_bytes())?;
            println!("Exported public CA certificate to {}", out.display());
            println!("Fingerprint: {}", ca.fingerprint_sha256());
            println!("Note: this exports only the public certificate, never the private key.");
        }
        CaAction::Regenerate => {
            let ca = CaManager::regenerate(&paths).context("regenerating local CA")?;
            println!("Regenerated local interception CA.");
            println!("CA certificate: {}", ca.cert_path().display());
            println!("Fingerprint: {}", ca.fingerprint_sha256());
            println!(
                "WARNING: regeneration invalidates any previously trusted RAWFRAME CA; re-trust the new public certificate explicitly if needed."
            );
            println!(
                "Private key material is stored locally with restricted permissions and is never exported."
            );
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = cli.apply(AppConfig::default())?;
    if let Some(action) = cli.ca_action() {
        // CA management actions do not start the TUI/proxy runtime.
        return handle_ca_action(&action, &config);
    }
    let log_path = rawframe_cli::logging::init(cli.log_path().map(std::path::PathBuf::as_path))
        .context("initializing diagnostics")?;

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        bind = %config.proxy.bind_address,
        port = config.proxy.port,
        live_proxy = true,
        log = %log_path.display(),
        "starting RAWFRAME"
    );
    if !config.appearance.redact_sensitive_headers {
        tracing::warn!("sensitive-header redaction disabled by operator");
    }
    if !config.proxy.is_loopback_bind() {
        tracing::warn!(
            bind = %config.proxy.bind_address,
            "remote proxy binding explicitly authorized"
        );
    }
    if config.proxy.allow_private_upstreams {
        tracing::warn!("private/loopback upstream addresses explicitly authorized");
    }
    tracing::info!(
        scope_rules = config.proxy.scope.allowlist.len(),
        "proxy scope configured (default deny when zero rules)"
    );

    let mut app = rawframe_tui::App::new(config);
    let events = app.event_sender();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("rawframe-proxy")
        .build()
        .context("creating proxy runtime")?;
    let (command_tx, command_rx) = tokio::sync::mpsc::channel(32);
    let proxy_service = runtime.spawn(rawframe_proxy::run_service(command_rx, events));
    app.attach_proxy_commands(command_tx);

    let ui_result = rawframe_tui::run(app).context("terminal session failed");
    runtime.block_on(async {
        if let Err(error) = proxy_service.await {
            tracing::error!(%error, "proxy worker task failed");
        }
    });
    runtime.shutdown_timeout(std::time::Duration::from_secs(2));
    tracing::info!("RAWFRAME stopped");
    ui_result
}
