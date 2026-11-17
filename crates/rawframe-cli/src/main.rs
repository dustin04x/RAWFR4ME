use std::fs;
use std::io::Write;
use std::sync::{Arc, RwLock};

use anyhow::{Context, Result, bail};
use clap::Parser;
use rawframe_cli::cli::{CaAction, Cli};
use rawframe_core::AppConfig;
use rawframe_core::models::SessionId;
use rawframe_core::storage::StoragePolicy;
use rawframe_store::{StorageOptions, StorageService, Store, spawn_capture_pump};

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

fn export_history(cli: &Cli, config: &AppConfig) -> Result<()> {
    let Some(output) = &cli.export_history else {
        return Ok(());
    };
    let store = Store::open_existing(
        &config.storage.database_path,
        StoragePolicy::from_config(&config.storage),
    )
    .with_context(|| {
        format!(
            "opening {} for export (capture some traffic first, or pass --db)",
            config.storage.database_path.display()
        )
    })?;
    let sessions = store.list_sessions()?;
    let session_id = match &cli.export_session {
        Some(id) => SessionId(id.clone()),
        None => sessions
            .first()
            .map(|session| session.id.clone())
            .ok_or_else(|| anyhow::anyhow!("the database contains no sessions to export"))?,
    };
    let summary = store.export_session(&session_id, output)?;
    println!(
        "Exported {} records from {} to {}",
        summary.records,
        session_id,
        output.display()
    );
    println!(
        "Redacted header values: {} · records without stored bodies: {}",
        summary.redacted_headers, summary.bodies_omitted
    );
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = cli.apply(AppConfig::default())?;
    if let Some(action) = cli.ca_action() {
        // CA management actions do not start the TUI/proxy runtime.
        return handle_ca_action(&action, &config);
    }
    if cli.export_history.is_some() {
        // Export is a headless action; it never starts the listener or UI.
        return export_history(&cli, &config);
    }
    if cli.export_session.is_some() {
        bail!("--export-session requires --export-history FILE");
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

    let persistence_enabled = cli.persistence_enabled();
    let database_path = config.storage.database_path.clone();
    let repeater_config = rawframe_repeater::RepeaterConfig::from_proxy(&config.proxy);
    let repeater_scope = Arc::new(RwLock::new(config.proxy.scope.clone()));
    let mut app = rawframe_tui::App::new(config);
    let events = app.event_sender();

    // Storage is created before the UI loop so failures are reported in the
    // interface instead of being discovered on the first write.
    let mut storage: Option<(StorageService, std::thread::JoinHandle<()>)> = None;
    if persistence_enabled {
        let (session, project) = cli.session_and_project();
        let mut options = StorageOptions::new(
            database_path.clone(),
            session,
            StoragePolicy::from_config(&app.config().storage),
        );
        options.project = project;
        let pump_events = app.subscribe_events();
        match StorageService::spawn(options, events.clone()) {
            Ok(service) => {
                app.attach_storage_commands(service.handle().command_sender());
                let pump = spawn_capture_pump(pump_events, service.handle())
                    .context("starting capture pump")?;
                storage = Some((service, pump));
                tracing::info!(database = %database_path.display(), "session persistence enabled");
            }
            Err(error) => {
                tracing::error!(%error, database = %database_path.display(), "persistence unavailable");
                app.report_storage_failure(Some(database_path.clone()), error.to_string());
            }
        }
    } else {
        tracing::warn!("persistence disabled by --no-persist");
        app.report_storage_disabled();
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("rawframe-proxy")
        .build()
        .context("creating proxy runtime")?;
    let (command_tx, command_rx) = tokio::sync::mpsc::channel(32);
    let proxy_service = runtime.spawn(rawframe_proxy::run_service(command_rx, events.clone()));
    app.attach_proxy_commands(command_tx);

    // Repeater has an independent connection path and its own command channel,
    // but shares the scope policy and verified TLS configuration.
    let (repeater_tx, repeater_rx) = tokio::sync::mpsc::channel(16);
    let repeater_service = runtime.spawn(rawframe_repeater::run_service(
        repeater_rx,
        repeater_config,
        events,
        repeater_scope,
    ));
    app.attach_repeater_commands(repeater_tx);

    let ui_result = rawframe_tui::run(app).context("terminal session failed");
    runtime.block_on(async {
        if let Err(error) = proxy_service.await {
            tracing::error!(%error, "proxy worker task failed");
        }
        if let Err(error) = repeater_service.await {
            tracing::error!(%error, "Repeater service task failed");
        }
    });
    runtime.shutdown_timeout(std::time::Duration::from_secs(2));
    if let Some((service, pump)) = storage {
        service.shutdown();
        let _ = pump.join();
    }
    tracing::info!("RAWFRAME stopped");
    ui_result
}
