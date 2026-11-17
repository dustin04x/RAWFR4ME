//! Long-running Repeater service.
//!
//! The service owns the engine, cancellation tokens, and the concurrency limit.
//! It publishes phase changes and completed transactions on the application
//! event bus; the TUI never touches a socket and the storage worker persists
//! completed entries from the same event stream.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::RwLock;

use rawframe_core::AppEvent;
use rawframe_core::EventSender;
use rawframe_core::models::config::Scope;
use rawframe_core::models::traffic::TrafficId;
use rawframe_core::repeater::{
    REPEATER_ID_BASE, RepeaterCommand, RepeaterEvent, RepeaterExecutionPhase,
};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::engine::{RepeaterConfig, RepeaterEngine, entry_from_outcome};

/// Runs until [`RepeaterCommand::Shutdown`] or the command channel closes.
/// Cancellation does not abort the task: the engine returns a Cancelled result,
/// which is displayed and persisted like any other terminal outcome.
pub async fn run_service(
    mut commands: mpsc::Receiver<RepeaterCommand>,
    config: RepeaterConfig,
    events: EventSender,
    scope: Arc<RwLock<Scope>>,
) {
    let engine = Arc::new(RepeaterEngine::new(config, scope));
    let cancellations: Arc<std::sync::Mutex<HashMap<u64, CancellationToken>>> =
        Arc::new(std::sync::Mutex::new(HashMap::new()));
    let mut tasks: JoinSet<()> = JoinSet::new();
    let mut next_id = REPEATER_ID_BASE + 1;

    loop {
        tokio::select! {
            command = commands.recv() => {
                match command {
                    Some(RepeaterCommand::Execute {
                        tab,
                        execution,
                        request,
                        follow_redirects,
                        origin,
                        origin_request,
                    }) => {
                        let cancel = CancellationToken::new();
                        cancellations
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .insert(execution, cancel.clone());
                        let _ = events.send(AppEvent::Repeater(RepeaterEvent::Phase {
                            tab,
                            execution,
                            phase: RepeaterExecutionPhase::Validating,
                        }));
                        let engine = engine.clone();
                        let task_events = events.clone();
                        let task_cancellations = cancellations.clone();
                        let entry_id = TrafficId(next_id);
                        next_id += 1;
                        tasks.spawn(async move {
                            let progress_events = task_events.clone();
                            let outcome = engine
                                .execute(&request, follow_redirects, cancel, move |phase| {
                                    let _ = progress_events.send(AppEvent::Repeater(
                                        RepeaterEvent::Phase {
                                            tab,
                                            execution,
                                            phase,
                                        },
                                    ));
                                })
                                .await;
                            let entry = entry_from_outcome(
                                entry_id,
                                &outcome,
                                origin,
                                origin_request.map(|request| *request),
                            );
                            let _ = task_events.send(AppEvent::Repeater(
                                RepeaterEvent::Completed {
                                    tab,
                                    execution,
                                    phase: outcome.phase,
                                    result: Box::new(outcome.result),
                                    entry: Box::new(entry),
                                },
                            ));
                            task_cancellations
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner())
                                .remove(&execution);
                        });
                    }
                    Some(RepeaterCommand::Cancel { execution }) => {
                        if let Some(token) = cancellations
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .get(&execution)
                        {
                            token.cancel();
                        }
                    }
                    Some(RepeaterCommand::UpdateScope(scope)) => engine.update_scope(scope),
                    Some(RepeaterCommand::Shutdown) | None => {
                        for token in cancellations
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .values()
                        {
                            token.cancel();
                        }
                        // Give cancellation a moment to produce terminal results
                        // so they can still be displayed/persisted during exit.
                        let drain = tokio::time::timeout(std::time::Duration::from_secs(2), async {
                            while tasks.join_next().await.is_some() {}
                        });
                        let _ = drain.await;
                        break;
                    }
                }
            }
            joined = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(Err(error)) = joined {
                    tracing::error!(%error, "Repeater execution task failed");
                }
            }
        }
    }

    tasks.abort_all();
}
