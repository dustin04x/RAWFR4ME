//! Proxy listener, lifecycle service, and connection acceptance.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use rawframe_core::models::AppConfig;
use rawframe_core::models::config::Scope;
use rawframe_core::{AppCommand, AppEvent, EventSender, Notice, ProxyState};
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, mpsc, watch};
use tokio::time::timeout;
use tokio_util::task::TaskTracker;

use crate::error::ProxyError;
use crate::interception::{InterceptDecision, InterceptionManager};
use crate::service::{ServiceContext, handle_request};
use crate::tls::TlsController;

const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
const FIRST_LIVE_TRAFFIC_ID: u64 = 1_000;
const MAX_HEADERS: usize = 128;
const MAX_HEADER_BYTES: usize = 64 * 1024;

pub struct ProxyHandle {
    local_addr: SocketAddr,
    shutdown: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
    interception: InterceptionManager,
    tls: Arc<TlsController>,
    scope: Arc<RwLock<Scope>>,
}

impl ProxyHandle {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Resolves a pending interception decision. Used by embedding tests and the
    /// command service; decisions are runtime-local.
    pub async fn resolve_interception(
        &self,
        id: rawframe_core::models::TrafficId,
        decision: InterceptDecision,
    ) {
        let _ = self.interception.resolve(id, decision).await;
    }

    /// Replaces the live scope allowlist. Requests admitted after this call use
    /// the new rules immediately; already-forwarded requests are untouched.
    pub fn update_scope(&self, scope: Scope) {
        *self
            .scope
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = scope;
    }

    pub async fn shutdown(mut self) {
        let _ = self.shutdown.send(true);
        if timeout(SHUTDOWN_GRACE + Duration::from_secs(3), &mut self.task)
            .await
            .is_err()
        {
            self.task.abort();
            let _ = self.task.await;
        }
    }
}

/// Binds and starts a proxy listener. The caller owns the handle and can await
/// its shutdown.
pub async fn start_proxy(
    config: AppConfig,
    events: EventSender,
    ids: Arc<AtomicU64>,
) -> Result<ProxyHandle, ProxyError> {
    config
        .validate()
        .map_err(|error| ProxyError::Configuration(error.to_string()))?;
    if !config.proxy.verify_upstream_tls {
        return Err(ProxyError::Configuration(
            "upstream TLS verification cannot be disabled".into(),
        ));
    }

    let listener = TcpListener::bind(config.proxy.listen_addr())
        .await
        .map_err(ProxyError::Bind)?;
    let local_addr = listener.local_addr()?;
    let config = Arc::new(config);
    let (shutdown, shutdown_rx) = watch::channel(false);
    let tracker = TaskTracker::new();
    let connections = Arc::new(Semaphore::new(config.proxy.max_connections));
    let tunnels = Arc::new(Semaphore::new(config.proxy.max_connections));
    let interception = InterceptionManager::new(
        config.proxy.interception_enabled,
        config.proxy.intercept_timeout_secs,
        config.proxy.intercept_queue_capacity,
        config.interception_rules.clone(),
        events.clone(),
        shutdown_rx.clone(),
    );
    let tls = Arc::new(TlsController::new(
        config.proxy.tls_ca_dir_resolved(),
        config.proxy.tls_upstream_trust_file.clone(),
    ));
    let initial_tls_status = if config.proxy.tls_interception_enabled {
        match tls.enable().await {
            Ok(status) => status,
            Err(error) => {
                return Err(ProxyError::Configuration(format!(
                    "failed to enable TLS interception: {error}"
                )));
            }
        }
    } else {
        rawframe_core::TlsStatus::disabled()
    };
    let live_scope = Arc::new(RwLock::new(config.proxy.scope.clone()));
    let context_tls = tls.clone();
    let context = ServiceContext {
        config: config.clone(),
        scope: live_scope.clone(),
        events,
        ids,
        tracker: tracker.clone(),
        tunnels,
        shutdown: shutdown_rx.clone(),
        interception: interception.clone(),
        tls,
    };

    let initial_events = context.events.clone();
    let _ = initial_events
        .send_async(AppEvent::TlsStateChanged(initial_tls_status))
        .await;
    let task = tokio::spawn(run_listener(
        listener,
        context,
        connections,
        tracker,
        shutdown_rx,
    ));
    Ok(ProxyHandle {
        local_addr,
        shutdown,
        task,
        interception,
        tls: context_tls,
        scope: live_scope,
    })
}

/// Owns the proxy lifecycle in response to application commands. The worker is
/// intentionally independent of the TUI; `rawframe-cli` runs it on its runtime.
pub async fn run_service(mut commands: mpsc::Receiver<AppCommand>, events: EventSender) {
    let ids = Arc::new(AtomicU64::new(FIRST_LIVE_TRAFFIC_ID));
    let mut handle: Option<ProxyHandle> = None;

    while let Some(command) = commands.recv().await {
        match command {
            AppCommand::StartProxy(config) => {
                let scope_empty =
                    config.proxy.scope.block_unlisted && config.proxy.scope.allowlist.is_empty();
                if handle.is_some() {
                    let _ = events
                        .send_async(AppEvent::Notice(Notice::warning(
                            "The proxy is already running.",
                        )))
                        .await;
                    continue;
                }
                let _ = events
                    .send_async(AppEvent::ProxyStateChanged(ProxyState::Starting))
                    .await;
                match start_proxy(*config, events.clone(), ids.clone()).await {
                    Ok(started) => {
                        let _ = events
                            .send_async(AppEvent::ProxyBound(started.local_addr()))
                            .await;
                        let _ = events
                            .send_async(AppEvent::ProxyStateChanged(ProxyState::Listening))
                            .await;
                        let _ = events
                            .send_async(AppEvent::Notice(Notice::success(format!(
                                "Proxy listening on {}",
                                started.local_addr()
                            ))))
                            .await;
                        if scope_empty {
                            let _ = events
                                .send_async(AppEvent::Notice(Notice::warning(
                                    "Scope is empty: every upstream request and CONNECT will be denied. Restart with --scope RULE to authorize targets.",
                                )))
                                .await;
                        }
                        handle = Some(started);
                    }
                    Err(error) => {
                        let _ = events
                            .send_async(AppEvent::ProxyStateChanged(ProxyState::Failed))
                            .await;
                        let _ = events
                            .send_async(AppEvent::Notice(Notice::error(format!(
                                "Proxy failed to start: {error}"
                            ))))
                            .await;
                    }
                }
            }
            AppCommand::UpdateScope(scope) => {
                if let Some(active) = handle.as_ref() {
                    active.update_scope(scope);
                    let _ = events
                        .send_async(AppEvent::Notice(Notice::success(
                            "Scope updated: new requests use the edited allowlist.",
                        )))
                        .await;
                }
                // When the proxy is stopped the next StartProxy config already
                // carries the edited scope; nothing else to apply.
            }
            AppCommand::StopProxy => {
                if let Some(started) = handle.take() {
                    let _ = events
                        .send_async(AppEvent::ProxyStateChanged(ProxyState::Stopping))
                        .await;
                    let _ = started.interception.cancel_all("proxy stopped").await;
                    started.shutdown().await;
                    let _ = events
                        .send_async(AppEvent::ProxyStateChanged(ProxyState::Stopped))
                        .await;
                    let _ = events
                        .send_async(AppEvent::Notice(Notice::info("Proxy stopped.")))
                        .await;
                }
            }
            AppCommand::SetInterception { enabled } => {
                if let Some(active) = handle.as_ref() {
                    active.interception.set_enabled(enabled);
                    if !enabled {
                        let _ = active
                            .interception
                            .cancel_all("interception disabled")
                            .await;
                    }
                }
                let _ = events
                    .send_async(AppEvent::Notice(Notice::info(if enabled {
                        "Interception enabled."
                    } else {
                        "Interception disabled."
                    })))
                    .await;
            }
            AppCommand::SetTlsInterception { enabled } => {
                if let Some(active) = handle.as_ref() {
                    if enabled {
                        match active.tls.enable().await {
                            Ok(status) => {
                                let _ = events.send_async(AppEvent::TlsStateChanged(status)).await;
                                let _ = events
                                    .send_async(AppEvent::Notice(Notice::warning(
                                        "HTTPS TLS interception enabled: authorized CONNECT sessions will be decrypted and visible.",
                                    )))
                                    .await;
                            }
                            Err(error) => {
                                let _ = events
                                    .send_async(AppEvent::TlsStateChanged(
                                        rawframe_core::TlsStatus {
                                            enabled: false,
                                            ca_cert_path: None,
                                            ca_fingerprint: None,
                                            error: Some(error.clone()),
                                        },
                                    ))
                                    .await;
                                let _ = events
                                    .send_async(AppEvent::Notice(Notice::error(format!(
                                        "TLS interception could not be enabled: {error}"
                                    ))))
                                    .await;
                            }
                        }
                    } else {
                        active.tls.disable().await;
                        let _ = events
                            .send_async(AppEvent::TlsStateChanged(
                                rawframe_core::TlsStatus::disabled(),
                            ))
                            .await;
                        let _ = events
                            .send_async(AppEvent::Notice(Notice::info(
                                "TLS interception disabled: CONNECT is opaque again.",
                            )))
                            .await;
                    }
                } else {
                    let _ = events
                        .send_async(AppEvent::Notice(Notice::warning(
                            "Start the proxy before changing TLS interception.",
                        )))
                        .await;
                }
            }
            AppCommand::ForwardRequest(id) => {
                if let Some(active) = handle.as_ref() {
                    let _ = active
                        .interception
                        .resolve(id, InterceptDecision::ForwardUnchanged)
                        .await;
                }
            }
            AppCommand::DropRequest(id) => {
                if let Some(active) = handle.as_ref() {
                    let _ = active
                        .interception
                        .resolve(id, InterceptDecision::Drop)
                        .await;
                }
            }
            AppCommand::ForwardModified { id, request } => {
                if let Some(active) = handle.as_ref() {
                    let _ = active
                        .interception
                        .resolve(id, InterceptDecision::ForwardModified(request))
                        .await;
                }
            }
        }
    }

    if let Some(started) = handle {
        let _ = events
            .send_async(AppEvent::ProxyStateChanged(ProxyState::Stopping))
            .await;
        let _ = started
            .interception
            .cancel_all("proxy service shutting down")
            .await;
        started.shutdown().await;
        let _ = events
            .send_async(AppEvent::ProxyStateChanged(ProxyState::Stopped))
            .await;
    }
}

async fn run_listener(
    listener: TcpListener,
    context: ServiceContext,
    connections: Arc<Semaphore>,
    tracker: TaskTracker,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let Ok((stream, _peer)) = accepted else {
                    continue;
                };
                let Ok(permit) = connections.clone().try_acquire_owned() else {
                    drop(stream);
                    continue;
                };
                let context = context.clone();
                let connection_shutdown = shutdown.clone();
                tracker.spawn(async move {
                    serve_connection(stream, context, connection_shutdown).await;
                    drop(permit);
                });
            }
        }
    }

    drop(listener);
    tracker.close();
    if timeout(SHUTDOWN_GRACE, tracker.wait()).await.is_err() {
        tracing::warn!("proxy shutdown grace period elapsed; remaining tasks will be dropped");
    }
}

async fn serve_connection(
    stream: tokio::net::TcpStream,
    context: ServiceContext,
    mut shutdown: watch::Receiver<bool>,
) {
    let builder = {
        let mut builder = http1::Builder::new();
        builder
            .timer(TokioTimer::new())
            .keep_alive(true)
            .half_close(true)
            .max_headers(MAX_HEADERS)
            .max_buf_size(MAX_HEADER_BYTES)
            .header_read_timeout(Some(Duration::from_secs(
                context.config.proxy.idle_timeout_secs,
            )));
        builder
    };
    let service_context = context.clone();
    let service = service_fn(move |request| {
        let context = service_context.clone();
        async move { Ok::<_, Infallible>(handle_request(request, context).await) }
    });

    let connection = builder
        .serve_connection(TokioIo::new(stream), service)
        .with_upgrades();
    tokio::pin!(connection);

    tokio::select! {
        result = connection.as_mut() => {
            if let Err(error) = result {
                tracing::debug!(%error, "client connection ended with an error");
            }
        }
        _ = wait_for_shutdown(&mut shutdown) => {
            connection.as_mut().graceful_shutdown();
            let _ = timeout(SHUTDOWN_GRACE, connection.as_mut()).await;
        }
    }
}

pub(crate) async fn wait_for_shutdown(shutdown: &mut watch::Receiver<bool>) {
    if *shutdown.borrow() {
        return;
    }
    while shutdown.changed().await.is_ok() {
        if *shutdown.borrow() {
            return;
        }
    }
}

pub(crate) fn next_id(ids: &AtomicU64) -> u64 {
    ids.fetch_add(1, Ordering::Relaxed)
}
