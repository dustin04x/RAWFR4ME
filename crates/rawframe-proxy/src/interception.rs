//! In-process interception queue and decision routing.
//!
//! Decision channels are runtime-local and never leave the proxy crate.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use chrono::Utc;
use rawframe_core::models::InterceptionAction;
use rawframe_core::models::traffic::{
    EditableHttpRequest, InterceptionMetadata, TrafficEntry, TrafficId, TrafficState,
};
use rawframe_core::{AppEvent, EventSender, InterceptionRule, Notice};
use tokio::sync::{Mutex, oneshot, watch};
use tokio::time::timeout;

#[derive(Debug, Clone)]
pub enum InterceptDecision {
    ForwardUnchanged,
    ForwardModified(EditableHttpRequest),
    Drop,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PauseOutcome {
    ForwardedUnchanged,
    ForwardedModified(EditableHttpRequest),
    Dropped,
    TimedOut,
    Cancelled(String),
    Rejected(String),
}

struct Pending {
    tx: oneshot::Sender<InterceptDecision>,
    // kept so we can mark/notify if needed; entry state is published by caller.
    _id: TrafficId,
}

/// Removes a pending interception if the waiting request future is dropped
/// (for example, the client disconnected while paused). Normal decisions remove
/// the entry first, so this guard is a no-op on the normal path.
struct PendingGuard {
    inner: Arc<Mutex<State>>,
    id: u64,
    events: EventSender,
    entry: TrafficEntry,
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let inner = self.inner.clone();
        let events = self.events.clone();
        let id = self.id;
        let entry = self.entry.clone();
        handle.spawn(async move {
            let (removed, pending, capacity) = {
                let mut state = inner.lock().await;
                let removed = state.pending.remove(&id).is_some();
                (removed, state.pending.len(), state.capacity)
            };
            if !removed {
                return;
            }
            let mut entry = entry;
            let _ = entry.cancel_interception("client disconnected before interception decision");
            let _ = events
                .send_async(AppEvent::TrafficUpdated(Box::new(entry)))
                .await;
            let _ = events
                .send_async(AppEvent::InterceptionQueueChanged { pending, capacity })
                .await;
        });
    }
}

struct State {
    pending: HashMap<u64, Pending>,
    capacity: usize,
}

#[derive(Clone)]
pub struct InterceptionManager {
    inner: Arc<Mutex<State>>,
    enabled: Arc<AtomicBool>,
    timeout_secs: Arc<std::sync::atomic::AtomicU64>,
    rules: Arc<Mutex<Vec<InterceptionRule>>>,
    events: EventSender,
    shutdown: watch::Receiver<bool>,
}

impl InterceptionManager {
    pub fn new(
        enabled: bool,
        timeout_secs: u64,
        capacity: usize,
        rules: Vec<InterceptionRule>,
        events: EventSender,
        shutdown: watch::Receiver<bool>,
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(State {
                pending: HashMap::new(),
                capacity: capacity.max(1),
            })),
            enabled: Arc::new(AtomicBool::new(enabled)),
            timeout_secs: Arc::new(std::sync::atomic::AtomicU64::new(timeout_secs.max(1))),
            rules: Arc::new(Mutex::new(rules)),
            events,
            shutdown,
        }
    }

    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    pub async fn should_pause(&self, request: &rawframe_core::models::HttpRequest) -> bool {
        if !self.is_enabled() {
            return false;
        }
        let rules = self.rules.lock().await;
        match InterceptionRule::matches_any(&rules, request) {
            Some(rule) => matches!(rule.action, InterceptionAction::Intercept),
            // No matching/explicit rules: when interception is armed, pause by default
            // so the workbench is usable without preconfigured rules.
            None => rules.is_empty() || !rules.iter().any(|r| r.enabled),
        }
    }

    /// Registers a pending interception and waits for a decision or terminal condition.
    /// The caller is responsible for publishing the paused entry/event before/with registration
    /// as appropriate; this function focuses on queueing and awaiting.
    pub async fn pause(
        &self,
        id: TrafficId,
        mut paused_entry: TrafficEntry,
        client_meta: Option<String>,
    ) -> PauseOutcome {
        let (tx, rx) = oneshot::channel();
        let mut shutdown = self.shutdown.clone();
        let capacity;
        let pending_count;
        {
            let mut state = self.inner.lock().await;
            capacity = state.capacity;
            if state.pending.len() >= state.capacity {
                let _ = self
                    .events
                    .send_async(AppEvent::Notice(Notice::warning(format!(
                        "Interception queue full ({}/{}); request #{} was not paused.",
                        state.pending.len(),
                        state.capacity,
                        id
                    ))))
                    .await;
                return PauseOutcome::Rejected("interception queue is full".to_string());
            }
            let pos = state.pending.len() + 1;
            paused_entry.interception = InterceptionMetadata {
                intercepted: true,
                modified: false,
                queue_position: Some(pos),
                client_addr: client_meta,
                arrival_at: Some(Utc::now()),
            };
            if paused_entry.state != TrafficState::Paused {
                let _ = paused_entry.pause();
            }
            state.pending.insert(id.0, Pending { tx, _id: id });
            pending_count = state.pending.len();
        }

        let guard_entry = paused_entry.clone();
        let _ = self
            .events
            .send_async(AppEvent::InterceptionPaused(Box::new(paused_entry)))
            .await;
        let _ = self
            .events
            .send_async(AppEvent::InterceptionQueueChanged {
                pending: pending_count,
                capacity,
            })
            .await;

        let _pending_guard = PendingGuard {
            inner: self.inner.clone(),
            id: id.0,
            events: self.events.clone(),
            entry: guard_entry,
        };

        let timeout_secs = self.timeout_secs.load(Ordering::Relaxed);
        let wait = timeout(Duration::from_secs(timeout_secs), async {
            tokio::select! {
                decision = rx => decision.map_err(|_| ()),
                changed = shutdown.changed() => {
                    if changed.is_ok() && *shutdown.borrow() {
                        Err(())
                    } else {
                        // spurious or sender closed; treat as cancelled/closed
                        Err(())
                    }
                }
            }
        });

        let outcome = match wait.await {
            Ok(Ok(InterceptDecision::ForwardUnchanged)) => PauseOutcome::ForwardedUnchanged,
            Ok(Ok(InterceptDecision::ForwardModified(req))) => PauseOutcome::ForwardedModified(req),
            Ok(Ok(InterceptDecision::Drop)) => PauseOutcome::Dropped,
            Ok(Err(())) => {
                // sender dropped (disconnect/shutdown/disable path may remove it)
                if *shutdown.borrow() {
                    PauseOutcome::Cancelled("proxy shutting down".to_string())
                } else {
                    PauseOutcome::Cancelled("interception cancelled".to_string())
                }
            }
            Err(_) => PauseOutcome::TimedOut,
        };

        // remove from queue if still present and publish queue size
        let (pending, cap) = {
            let mut state = self.inner.lock().await;
            state.pending.remove(&id.0);
            (state.pending.len(), state.capacity)
        };
        let _ = self
            .events
            .send_async(AppEvent::InterceptionQueueChanged {
                pending,
                capacity: cap,
            })
            .await;
        outcome
    }

    pub async fn resolve(&self, id: TrafficId, decision: InterceptDecision) -> bool {
        let tx = {
            let mut state = self.inner.lock().await;
            state.pending.remove(&id.0).map(|p| p.tx)
        };
        if let Some(tx) = tx {
            let _ = tx.send(decision);
            let (pending, cap) = {
                let state = self.inner.lock().await;
                (state.pending.len(), state.capacity)
            };
            let _ = self
                .events
                .send_async(AppEvent::InterceptionQueueChanged {
                    pending,
                    capacity: cap,
                })
                .await;
            true
        } else {
            false
        }
    }

    /// Cancels all pending interceptions (shutdown/disable). Dropping senders unblocks waiters.
    pub async fn cancel_all(&self, reason: &str) -> Vec<TrafficId> {
        let pending = {
            let mut state = self.inner.lock().await;
            let ids: Vec<TrafficId> = state.pending.keys().copied().map(TrafficId).collect();
            state.pending.clear();
            ids
        };
        if !pending.is_empty() {
            let cap = self.inner.lock().await.capacity;
            let _ = self
                .events
                .send_async(AppEvent::InterceptionQueueChanged {
                    pending: 0,
                    capacity: cap,
                })
                .await;
            let _ = self
                .events
                .send_async(AppEvent::Notice(Notice::warning(format!(
                    "{} pending interception(s) cancelled: {reason}",
                    pending.len()
                ))))
                .await;
        }
        pending
    }
}
