//! Frame-level WebSocket interception.
//!
//! Each paused frame is registered under its globally unique frame id and the
//! relay waits for an operator decision with a hard timeout. The pending table
//! is bounded by the configured interception queue capacity, so a flood of
//! frames cannot grow memory without limit; when the queue is full the frame is
//! forwarded unchanged and the operator is warned instead of stalling traffic
//! silently.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use rawframe_core::AppEvent;
use rawframe_core::EventSender;
use rawframe_core::models::websocket::{
    WebSocketFrame, WebSocketFrameDecision, WebSocketFrameId, WebSocketInterceptionOutcome,
};
use tokio::sync::{Mutex, oneshot, watch};

/// What the relay should do with a frame after the pause resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PauseOutcome {
    pub decision: WebSocketFrameDecision,
    pub outcome: WebSocketInterceptionOutcome,
    /// True when the connection cannot continue (cancel or timeout).
    pub terminal: bool,
}

impl PauseOutcome {
    fn forward() -> Self {
        Self {
            decision: WebSocketFrameDecision::Forward,
            outcome: WebSocketInterceptionOutcome::Forwarded,
            terminal: false,
        }
    }
}

struct Inner {
    enabled: AtomicBool,
    capacity: usize,
    timeout: Duration,
    events: EventSender,
    pending: Mutex<HashMap<WebSocketFrameId, oneshot::Sender<WebSocketFrameDecision>>>,
    shutdown: watch::Receiver<bool>,
}

#[derive(Clone)]
pub struct WebSocketInterceptor {
    inner: Arc<Inner>,
}

impl WebSocketInterceptor {
    pub fn new(
        enabled: bool,
        timeout_secs: u64,
        capacity: usize,
        events: EventSender,
        shutdown: watch::Receiver<bool>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                enabled: AtomicBool::new(enabled),
                capacity: capacity.max(1),
                timeout: Duration::from_secs(timeout_secs.max(1)),
                events,
                pending: Mutex::new(HashMap::new()),
                shutdown,
            }),
        }
    }

    pub fn set_enabled(&self, enabled: bool) {
        self.inner.enabled.store(enabled, Ordering::Relaxed);
    }

    pub fn is_enabled(&self) -> bool {
        self.inner.enabled.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub async fn pending_count(&self) -> usize {
        self.inner.pending.lock().await.len()
    }

    /// Delivers an operator decision. Returns false when the frame already
    /// resolved (timeout, cancellation, or a stale interface action).
    pub async fn resolve(&self, frame: WebSocketFrameId, decision: WebSocketFrameDecision) -> bool {
        let sender = self.inner.pending.lock().await.remove(&frame);
        match sender {
            Some(sender) => sender.send(decision).is_ok(),
            None => false,
        }
    }

    /// Cancels every pending frame. Paused relays observe the cancellation and
    /// close their connections rather than forwarding a frame nobody reviewed.
    pub async fn cancel_all(&self) {
        let mut pending = self.inner.pending.lock().await;
        pending.clear();
    }

    /// Registers `frame` for review and waits for a decision, a timeout, or a
    /// global shutdown. Frames are forwarded unchanged when interception is
    /// disabled or the bounded queue is full.
    pub async fn pause(&self, frame: &WebSocketFrame) -> PauseOutcome {
        if !self.is_enabled() {
            return PauseOutcome::forward();
        }

        let mut pending = self.inner.pending.lock().await;
        if pending.len() >= self.inner.capacity {
            drop(pending);
            let _ = self
                .inner
                .events
                .send_async(AppEvent::Notice(rawframe_core::Notice::warning(
                    "WebSocket interception queue is full: the frame was forwarded unchanged.",
                )))
                .await;
            return PauseOutcome::forward();
        }

        let (sender, receiver) = oneshot::channel();
        pending.insert(frame.id, sender);
        drop(pending);

        let _ = self
            .inner
            .events
            .send_async(AppEvent::WebSocketFramePaused(Box::new(frame.clone())))
            .await;

        let mut shutdown = self.inner.shutdown.clone();
        let timeout = tokio::time::sleep(self.inner.timeout);
        tokio::pin!(timeout);

        let outcome = tokio::select! {
            decision = receiver => match decision {
                Ok(WebSocketFrameDecision::Forward) => PauseOutcome {
                    decision: WebSocketFrameDecision::Forward,
                    outcome: WebSocketInterceptionOutcome::Forwarded,
                    terminal: false,
                },
                Ok(WebSocketFrameDecision::ForwardModified { payload }) => PauseOutcome {
                    decision: WebSocketFrameDecision::ForwardModified { payload },
                    outcome: WebSocketInterceptionOutcome::Modified,
                    terminal: false,
                },
                Ok(WebSocketFrameDecision::Drop) => PauseOutcome {
                    decision: WebSocketFrameDecision::Drop,
                    outcome: WebSocketInterceptionOutcome::Dropped,
                    terminal: false,
                },
                Err(_) => PauseOutcome {
                    decision: WebSocketFrameDecision::Drop,
                    outcome: WebSocketInterceptionOutcome::Cancelled,
                    terminal: true,
                },
            },
            _ = &mut timeout => {
                self.inner.pending.lock().await.remove(&frame.id);
                PauseOutcome {
                    decision: WebSocketFrameDecision::Drop,
                    outcome: WebSocketInterceptionOutcome::TimedOut,
                    terminal: true,
                }
            }
            _ = shutdown.changed() => {
                self.inner.pending.lock().await.remove(&frame.id);
                PauseOutcome {
                    decision: WebSocketFrameDecision::Drop,
                    outcome: WebSocketInterceptionOutcome::Cancelled,
                    terminal: true,
                }
            }
        };

        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rawframe_core::EventBus;
    use rawframe_core::models::websocket::{
        WebSocketConnectionId, WebSocketDirection, WebSocketOpcode,
    };

    fn frame(id: u64) -> WebSocketFrame {
        WebSocketFrame::new(
            WebSocketFrameId(id),
            WebSocketConnectionId(1),
            WebSocketDirection::ClientToServer,
            WebSocketOpcode::Text,
            true,
            true,
            b"hello".to_vec(),
            false,
        )
    }

    #[tokio::test]
    async fn decisions_are_delivered_to_the_waiting_relay() {
        let bus = EventBus::new();
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let interceptor = WebSocketInterceptor::new(true, 5, 8, bus.sender(), shutdown_rx);
        let paused = frame(10);
        let waiting = {
            let interceptor = interceptor.clone();
            let paused = paused.clone();
            tokio::spawn(async move { interceptor.pause(&paused).await })
        };
        tokio::task::yield_now().await;
        assert!(
            interceptor
                .resolve(
                    paused.id,
                    WebSocketFrameDecision::ForwardModified {
                        payload: b"changed".to_vec()
                    }
                )
                .await
        );
        let outcome = waiting.await.unwrap();
        assert_eq!(outcome.outcome, WebSocketInterceptionOutcome::Modified);
        assert!(!outcome.terminal);
    }

    #[tokio::test]
    async fn cancel_all_closes_pending_frames() {
        let bus = EventBus::new();
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let interceptor = WebSocketInterceptor::new(true, 30, 8, bus.sender(), shutdown_rx);
        let paused = frame(11);
        let waiting = {
            let interceptor = interceptor.clone();
            let paused = paused.clone();
            tokio::spawn(async move { interceptor.pause(&paused).await })
        };
        tokio::task::yield_now().await;
        interceptor.cancel_all().await;
        let outcome = waiting.await.unwrap();
        assert_eq!(outcome.outcome, WebSocketInterceptionOutcome::Cancelled);
        assert!(outcome.terminal);
    }

    #[tokio::test]
    async fn full_queue_forwards_without_pausing() {
        let bus = EventBus::new();
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let interceptor = WebSocketInterceptor::new(true, 30, 1, bus.sender(), shutdown_rx);
        let first = frame(12);
        let first_wait = {
            let interceptor = interceptor.clone();
            let first = first.clone();
            tokio::spawn(async move { interceptor.pause(&first).await })
        };
        tokio::task::yield_now().await;
        let second = interceptor.pause(&frame(13)).await;
        assert_eq!(second.outcome, WebSocketInterceptionOutcome::Forwarded);
        assert!(!second.terminal);
        interceptor.cancel_all().await;
        let _ = first_wait.await;
    }

    #[tokio::test]
    async fn disabled_interception_never_pauses() {
        let bus = EventBus::new();
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let interceptor = WebSocketInterceptor::new(false, 30, 8, bus.sender(), shutdown_rx);
        let outcome = interceptor.pause(&frame(14)).await;
        assert_eq!(outcome.outcome, WebSocketInterceptionOutcome::Forwarded);
        assert_eq!(interceptor.pending_count().await, 0);
    }
}
