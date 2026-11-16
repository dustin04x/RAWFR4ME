use anyhow::{Context, Result};
use clap::Parser;
use rawframe_cli::cli::Cli;
use rawframe_core::AppConfig;

fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = cli.apply(AppConfig::default())?;
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
