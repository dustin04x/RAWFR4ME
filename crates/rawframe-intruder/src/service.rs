//! Long-running Intruder service.
//!
//! The service owns the engine and exactly one active attack. It publishes
//! progress and results on the application event bus, so the interface never
//! touches a socket and the storage worker persists results from the same event
//! stream. Starting a second attack while one is running is refused instead of
//! being queued or silently merged.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use rawframe_core::models::config::Scope;
use rawframe_core::{
    AppEvent, EventSender, IntruderCommand, IntruderEvent, IntruderPhase, IntruderSummary,
};
use rawframe_repeater::RepeaterConfig;
use tokio::sync::{Notify, mpsc};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::engine::{IntruderEngine, intruder_config, run_attack};
use crate::wordlist::load_wordlist;

struct ActiveRun {
    run: u64,
    cancel: CancellationToken,
    paused: Arc<AtomicBool>,
    notify: Arc<Notify>,
    handle: JoinHandle<IntruderSummary>,
}

/// Runs until [`IntruderCommand::Shutdown`] or the command channel closes.
pub async fn run_service(
    mut commands: mpsc::Receiver<IntruderCommand>,
    base_config: RepeaterConfig,
    events: EventSender,
    scope: Arc<std::sync::RwLock<Scope>>,
) {
    let engine = Arc::new(IntruderEngine::new(intruder_config(&base_config), scope));
    let mut active: Option<ActiveRun> = None;

    loop {
        let command = commands.recv().await;
        let Some(command) = command else {
            if let Some(attack) = active.take() {
                attack.cancel.cancel();
                let _ =
                    tokio::time::timeout(std::time::Duration::from_secs(2), attack.handle).await;
            }
            break;
        };

        // Reap a finished attack before deciding whether a new one may start.
        if active
            .as_ref()
            .is_some_and(|attack| attack.handle.is_finished())
            && let Some(attack) = active.take()
            && let Err(error) = attack.handle.await
        {
            tracing::error!(%error, "Intruder run task failed");
        }

        match command {
            IntruderCommand::LoadWordlist { request, path } => {
                let events = events.clone();
                tokio::spawn(async move {
                    let outcome = load_wordlist(request, &path).await;
                    let _ = events
                        .send_async(AppEvent::Intruder(IntruderEvent::Wordlist(outcome)))
                        .await;
                });
            }
            IntruderCommand::Start { run, launch } => {
                if let Some(attack) = &active {
                    let _ = events
                        .send_async(AppEvent::Intruder(IntruderEvent::Failed {
                            run,
                            error: format!(
                                "run {} is still active; finish or cancel it before starting another attack",
                                attack.run
                            ),
                        }))
                        .await;
                    continue;
                }
                if let Err(error) = launch.validate() {
                    let _ = events
                        .send_async(AppEvent::Intruder(IntruderEvent::Failed {
                            run,
                            error: format!("invalid attack configuration: {error}"),
                        }))
                        .await;
                    continue;
                }

                let cancel = CancellationToken::new();
                let paused = Arc::new(AtomicBool::new(false));
                let notify = Arc::new(Notify::new());
                let handle = tokio::spawn(run_attack(
                    engine.clone(),
                    events.clone(),
                    run,
                    *launch,
                    cancel.clone(),
                    paused.clone(),
                    notify.clone(),
                ));
                active = Some(ActiveRun {
                    run,
                    cancel,
                    paused,
                    notify,
                    handle,
                });
            }
            IntruderCommand::Pause { run } => {
                if let Some(attack) = &active
                    && attack.run == run
                {
                    attack.paused.store(true, Ordering::Relaxed);
                    let _ = events
                        .send_async(AppEvent::Intruder(IntruderEvent::Phase {
                            run,
                            phase: IntruderPhase::Paused,
                        }))
                        .await;
                }
            }
            IntruderCommand::Resume { run } => {
                if let Some(attack) = &active
                    && attack.run == run
                {
                    attack.paused.store(false, Ordering::Relaxed);
                    attack.notify.notify_waiters();
                    let _ = events
                        .send_async(AppEvent::Intruder(IntruderEvent::Phase {
                            run,
                            phase: IntruderPhase::Running,
                        }))
                        .await;
                }
            }
            IntruderCommand::Cancel { run } => {
                if let Some(attack) = &active
                    && attack.run == run
                {
                    let _ = events
                        .send_async(AppEvent::Intruder(IntruderEvent::Phase {
                            run,
                            phase: IntruderPhase::Cancelling,
                        }))
                        .await;
                    attack.paused.store(false, Ordering::Relaxed);
                    attack.notify.notify_waiters();
                    attack.cancel.cancel();
                }
            }
            IntruderCommand::Shutdown => {
                if let Some(attack) = active.take() {
                    attack.paused.store(false, Ordering::Relaxed);
                    attack.notify.notify_waiters();
                    attack.cancel.cancel();
                    // Give in-flight results a moment to arrive so they can still
                    // be displayed and persisted during exit.
                    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), attack.handle)
                        .await;
                }
                break;
            }
        }
    }
}

/// Convenience wrapper used by tests and callers that only need to request a
/// wordlist read without constructing a command by hand.
pub fn wordlist_command(request: u64, path: impl Into<PathBuf>) -> IntruderCommand {
    IntruderCommand::LoadWordlist {
        request,
        path: path.into(),
    }
}
