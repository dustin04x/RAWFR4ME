//! Application event and command contracts.
//!
//! The proxy worker publishes [`AppEvent`] values through the channel owned by
//! the application shell. The TUI only reacts to events; it never reaches into
//! the proxy. Commands flow the other way through [`AppCommand`].

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use thiserror::Error;
use tokio::sync::mpsc::{self, Receiver, Sender};

use crate::models::AppConfig;
use crate::models::config::Scope;
use crate::models::traffic::{TrafficEntry, TrafficId};
use crate::storage::StorageEvent;

/// Events are bounded so a fast proxy cannot grow the UI queue without limit.
/// Producers that run asynchronously use [`EventSender::send_async`] and receive
/// backpressure; synchronous tests may use [`EventSender::send`].
pub const EVENT_QUEUE_CAPACITY: usize = 4096;

#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[error("application event queue is closed or full")]
pub struct EventSendError;

/// Fan-out sender. Every subscriber created through [`EventBus::subscribe`]
/// receives each event, so background services (persistence) can observe
/// captures without the interface relaying them.
#[derive(Debug, Clone)]
pub struct EventSender {
    sinks: Arc<Mutex<Vec<Sender<AppEvent>>>>,
}

impl EventSender {
    fn new(sinks: Arc<Mutex<Vec<Sender<AppEvent>>>>) -> Self {
        Self { sinks }
    }

    /// Non-blocking send for synchronous callers and tests. The event is offered
    /// to every subscriber; it succeeds if at least one queue accepted it.
    pub fn send(&self, event: AppEvent) -> Result<(), EventSendError> {
        let sinks = self
            .sinks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut delivered = false;
        for sink in sinks.iter() {
            if sink.try_send(event.clone()).is_ok() {
                delivered = true;
            }
        }
        if delivered {
            Ok(())
        } else {
            Err(EventSendError)
        }
    }

    /// Async send used by proxy tasks. This applies backpressure when a
    /// subscriber is temporarily unable to drain captures.
    pub async fn send_async(&self, event: AppEvent) -> Result<(), EventSendError> {
        let sinks: Vec<Sender<AppEvent>> = {
            let sinks = self
                .sinks
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            sinks.clone()
        };
        if sinks.is_empty() {
            return Err(EventSendError);
        }
        // A subscriber that has been dropped must never stall or abort the
        // proxy; skip closed sinks and succeed if at least one queue accepted
        // the event.
        let mut delivered = false;
        for sink in sinks {
            if sink.send(event.clone()).await.is_ok() {
                delivered = true;
            }
        }
        if delivered {
            Ok(())
        } else {
            Err(EventSendError)
        }
    }

    pub fn subscriber_count(&self) -> usize {
        self.sinks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }
}

pub type EventReceiver = Receiver<AppEvent>;
pub type CommandSender = Sender<AppCommand>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NoticeLevel {
    #[default]
    Info,
    Success,
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    pub level: NoticeLevel,
    pub message: String,
}

impl Notice {
    pub fn info(message: impl Into<String>) -> Self {
        Self {
            level: NoticeLevel::Info,
            message: message.into(),
        }
    }

    pub fn success(message: impl Into<String>) -> Self {
        Self {
            level: NoticeLevel::Success,
            message: message.into(),
        }
    }

    pub fn warning(message: impl Into<String>) -> Self {
        Self {
            level: NoticeLevel::Warning,
            message: message.into(),
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self {
            level: NoticeLevel::Error,
            message: message.into(),
        }
    }
}

/// Runtime HTTPS interception status exposed to the UI. The CA private key is
/// never part of this value; only the public certificate path and fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TlsStatus {
    pub enabled: bool,
    pub ca_cert_path: Option<String>,
    pub ca_fingerprint: Option<String>,
    /// Set when enabling/disabling failed. Interception is off when present.
    pub error: Option<String>,
}

impl TlsStatus {
    pub fn disabled() -> Self {
        Self::default()
    }

    pub fn enabled(ca_cert_path: impl Into<String>, ca_fingerprint: impl Into<String>) -> Self {
        Self {
            enabled: true,
            ca_cert_path: Some(ca_cert_path.into()),
            ca_fingerprint: Some(ca_fingerprint.into()),
            error: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProxyState {
    #[default]
    Stopped,
    Starting,
    Listening,
    Stopping,
    Failed,
}

impl ProxyState {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Stopped => "STOPPED",
            Self::Starting => "STARTING",
            Self::Listening => "LISTENING",
            Self::Stopping => "STOPPING",
            Self::Failed => "FAILED",
        }
    }

    pub const fn is_active(self) -> bool {
        !matches!(self, Self::Stopped | Self::Failed)
    }
}

/// Events emitted by application services towards the UI shell.
#[derive(Debug, Clone)]
pub enum AppEvent {
    TrafficCaptured(Box<TrafficEntry>),
    TrafficUpdated(Box<TrafficEntry>),
    InterceptionPaused(Box<TrafficEntry>),
    InterceptionQueueChanged {
        pending: usize,
        capacity: usize,
    },
    ProxyStateChanged(ProxyState),
    /// The actual bound address, which may differ from configuration when port 0
    /// is used in tests.
    ProxyBound(SocketAddr),
    TlsStateChanged(TlsStatus),
    /// Persistence status, query results, exports, and storage failures.
    Storage(StorageEvent),
    /// Repeater phase changes and completed real executions.
    Repeater(crate::repeater::RepeaterEvent),
    /// Intruder run progress, generated results, and wordlist outcomes.
    Intruder(crate::intruder::IntruderEvent),
    Notice(Notice),
    Shutdown,
}

/// Outbound intents for state owned by application services. The UI routes
/// these through the controller instead of mutating service internals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppCommand {
    StartProxy(Box<AppConfig>),
    StopProxy,
    SetInterception {
        enabled: bool,
    },
    /// Explicitly enable/disable HTTPS TLS interception for this session.
    /// Enabling initializes the local CA; disabling destroys the in-memory
    /// signing material and returns CONNECT to opaque tunnelling.
    SetTlsInterception {
        enabled: bool,
    },
    ForwardRequest(TrafficId),
    DropRequest(TrafficId),
    ForwardModified {
        id: TrafficId,
        request: crate::models::traffic::EditableHttpRequest,
    },
    /// Replace the live target-scope allowlist. New requests and CONNECT
    /// sessions use the updated rules immediately; established connections keep
    /// the rules they were admitted under.
    UpdateScope(Scope),
}

/// Event bus retained by the application shell. The shell owns the primary
/// receiver; background services may take additional receivers.
pub struct EventBus {
    sender: EventSender,
    sinks: Arc<Mutex<Vec<Sender<AppEvent>>>>,
    receiver: EventReceiver,
    capacity: usize,
}

impl EventBus {
    pub fn new() -> Self {
        Self::with_capacity(EVENT_QUEUE_CAPACITY)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        let sinks = Arc::new(Mutex::new(Vec::new()));
        let (sender, receiver) = mpsc::channel(capacity);
        sinks.lock().unwrap().push(sender);
        Self {
            sender: EventSender::new(sinks.clone()),
            sinks,
            receiver,
            capacity,
        }
    }

    /// A clone of the sender for proxy, storage, or other workers.
    pub fn sender(&self) -> EventSender {
        self.sender.clone()
    }

    /// Registers an additional receiver. Events already queued before the
    /// subscription are not replayed.
    pub fn subscribe(&mut self) -> EventReceiver {
        let (sender, receiver) = mpsc::channel(self.capacity);
        self.sinks.lock().unwrap().push(sender);
        receiver
    }

    /// Non-blocking poll used by the terminal event loop.
    pub fn poll(&mut self) -> Option<AppEvent> {
        self.receiver.try_recv().ok()
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::message::{HttpRequest, Scheme};
    use crate::models::traffic::TrafficSource;

    #[test]
    fn events_travel_through_the_bus() {
        let mut bus = EventBus::new();
        let sender = bus.sender();

        let request = HttpRequest::new("GET", Scheme::Https, "api.rawframe.test", 443, "/");
        let entry = TrafficEntry::new(TrafficId(7), request);
        sender
            .send(AppEvent::TrafficCaptured(Box::new(entry)))
            .unwrap();

        match bus.poll().unwrap() {
            AppEvent::TrafficCaptured(entry) => {
                assert_eq!(entry.id, TrafficId(7));
                assert_eq!(entry.source, TrafficSource::Intercepted);
            }
            other => panic!("unexpected event: {other:?}"),
        }
        assert!(bus.poll().is_none());
    }

    #[test]
    fn subscribers_receive_every_event() {
        let mut bus = EventBus::new();
        let sender = bus.sender();
        let mut storage = bus.subscribe();

        sender
            .send(AppEvent::Notice(Notice::info("hello")))
            .unwrap();

        assert!(matches!(bus.poll(), Some(AppEvent::Notice(_))));
        assert!(matches!(storage.try_recv(), Ok(AppEvent::Notice(_))));
        assert_eq!(sender.subscriber_count(), 2);
    }

    #[test]
    fn notices_have_levels() {
        assert_eq!(Notice::info("x").level, NoticeLevel::Info);
        assert_eq!(Notice::success("x").level, NoticeLevel::Success);
        assert_eq!(Notice::warning("x").level, NoticeLevel::Warning);
        assert_eq!(Notice::error("x").level, NoticeLevel::Error);
    }

    #[test]
    fn proxy_state_exposes_activity() {
        assert!(!ProxyState::Stopped.is_active());
        assert!(!ProxyState::Failed.is_active());
        assert!(ProxyState::Listening.is_active());
        assert_eq!(ProxyState::Listening.label(), "LISTENING");
    }
}
