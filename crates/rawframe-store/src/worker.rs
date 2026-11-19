//! The storage worker.
//!
//! A dedicated OS thread owns the [`Store`] and its single SQLite connection.
//! Captures arrive on a bounded synchronous channel with `try_send`, so the
//! proxy request path can never block on disk I/O; if the writer falls behind,
//! captures are dropped and *counted* rather than stalling live traffic.
//! Commands and results travel asynchronously over the application event bus.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError};
use std::time::Duration;

use rawframe_core::events::{AppEvent, EventReceiver, EventSender};
use rawframe_core::models::session::{Project, Session, SessionId};
use rawframe_core::models::traffic::{TrafficEntry, TrafficSource};
use rawframe_core::models::websocket::{WebSocketConnection, WebSocketFrame, WebSocketMessage};
use rawframe_core::storage::{
    STORAGE_COMMAND_QUEUE, StorageCommand, StorageCommandReceiver, StorageCommandSender,
    StorageEvent, StoragePolicy, StorageStatus,
};

use crate::error::StoreError;
use crate::store::{DEFAULT_MAX_BYTES, Store};

/// Captures that may wait for the writer before backpressure drops them.
pub const RECORD_QUEUE_CAPACITY: usize = 1024;
const BATCH_LIMIT: usize = 64;
const POLL_INTERVAL: Duration = Duration::from_millis(20);

#[derive(Debug, Clone)]
pub struct StorageOptions {
    pub path: PathBuf,
    pub project: Project,
    pub session: Session,
    pub policy: StoragePolicy,
    pub max_bytes: u64,
}

impl StorageOptions {
    pub fn new(path: impl Into<PathBuf>, session: Session, policy: StoragePolicy) -> Self {
        let project = Project::default_project();
        Self {
            path: path.into(),
            project,
            session,
            policy,
            max_bytes: DEFAULT_MAX_BYTES,
        }
    }
}

/// One item handed to the storage worker. WebSocket recordings share the same
/// bounded queue as HTTP traffic, so a burst of frames cannot bypass the write
/// limit or grow memory without bound.
enum Capture {
    Traffic(Box<TrafficEntry>),
    Connection(Box<WebSocketConnection>),
    Frame(Box<WebSocketFrame>),
    Message(Box<WebSocketMessage>),
}

/// Cheap, cloneable handle used by the capture pump and the interface.
#[derive(Debug, Clone)]
pub struct StorageHandle {
    records: SyncSender<Capture>,
    commands: StorageCommandSender,
    dropped: Arc<AtomicU64>,
}

impl StorageHandle {
    /// Non-blocking capture submission. Never blocks the caller.
    pub fn try_record(&self, entry: TrafficEntry) -> bool {
        self.offer(Capture::Traffic(Box::new(entry)))
    }

    pub fn try_record_connection(&self, connection: WebSocketConnection) -> bool {
        self.offer(Capture::Connection(Box::new(connection)))
    }

    pub fn try_record_frame(&self, frame: WebSocketFrame) -> bool {
        self.offer(Capture::Frame(Box::new(frame)))
    }

    pub fn try_record_message(&self, message: WebSocketMessage) -> bool {
        self.offer(Capture::Message(Box::new(message)))
    }

    fn offer(&self, capture: Capture) -> bool {
        match self.records.try_send(capture) {
            Ok(()) => true,
            Err(_) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    pub fn command_sender(&self) -> StorageCommandSender {
        self.commands.clone()
    }

    /// Best-effort async command submission; false when the worker is gone.
    pub fn try_command(&self, command: StorageCommand) -> bool {
        self.commands.try_send(command).is_ok()
    }

    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// Owns the worker thread. Dropping the service shuts the worker down cleanly.
pub struct StorageService {
    handle: StorageHandle,
    join: Option<std::thread::JoinHandle<()>>,
    events: EventSender,
    session_id: SessionId,
    path: PathBuf,
}

impl StorageService {
    /// Opens the database on the calling thread (so failures are reported to the
    /// caller immediately), then moves it to the worker thread.
    pub fn spawn(options: StorageOptions, events: EventSender) -> Result<Self, StoreError> {
        let mut store = Store::open(
            &options.path,
            &options.project,
            &options.session,
            options.policy,
            options.max_bytes,
        )?;
        let session_id = store.session().id.clone();
        let path = store.path().to_path_buf();

        let (record_tx, record_rx) = mpsc::sync_channel(RECORD_QUEUE_CAPACITY);
        let (command_tx, command_rx) = tokio::sync::mpsc::channel(STORAGE_COMMAND_QUEUE);
        let dropped = Arc::new(AtomicU64::new(0));
        let handle = StorageHandle {
            records: record_tx,
            commands: command_tx,
            dropped: dropped.clone(),
        };

        let initial = StorageStatus::enabled(path.clone(), session_id.clone(), store.policy());
        let worker_events = events.clone();
        let thread_events = events.clone();
        let thread_name = format!("rawframe-store-{}", session_id.0);
        let failure_session = session_id.clone();
        let failure_path = path.clone();
        let join = std::thread::Builder::new()
            .name(thread_name)
            .spawn(move || {
                if let Err(error) =
                    run_worker(&mut store, record_rx, command_rx, &thread_events, &dropped)
                {
                    tracing::error!(%error, "storage worker stopped with an error");
                    let _ = thread_events
                        .send(AppEvent::Storage(StorageEvent::Failed(error.to_string())));
                    let mut failed = StorageStatus::failed(Some(failure_path), error.to_string());
                    failed.persisted = store.count_records(&failure_session).unwrap_or(0) as u64;
                    let _ = thread_events.send(AppEvent::Storage(StorageEvent::Status(failed)));
                }
            })?;

        let _ = worker_events.send(AppEvent::Storage(StorageEvent::Status(initial)));
        Ok(Self {
            handle,
            join: Some(join),
            events,
            session_id,
            path,
        })
    }

    pub fn handle(&self) -> StorageHandle {
        self.handle.clone()
    }

    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Signals the worker to checkpoint and close the session, then waits for it.
    pub fn shutdown(mut self) {
        let _ = self.handle.commands.try_send(StorageCommand::Shutdown);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
        tracing::debug!(session = %self.session_id, "storage worker stopped");
    }

    /// Sends a status event reflecting an external decision (for example the
    /// operator disabling persistence), so the interface stays truthful.
    pub fn emit(&self, event: StorageEvent) {
        let _ = self.events.send(AppEvent::Storage(event));
    }
}

impl Drop for StorageService {
    fn drop(&mut self) {
        let _ = self.handle.commands.try_send(StorageCommand::Shutdown);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

/// Forwards live captures from the application event bus to the storage worker.
///
/// This is the production bridge: the proxy never talks to the store directly.
/// Genuinely intercepted traffic and completed Repeater executions are stored;
/// simulated fixtures and unexecuted Repeater drafts are not history.
pub fn spawn_capture_pump(
    mut events: EventReceiver,
    handle: StorageHandle,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("rawframe-capture-pump".into())
        .spawn(move || {
            while let Some(event) = events.blocking_recv() {
                match event {
                    AppEvent::TrafficCaptured(entry) | AppEvent::TrafficUpdated(entry) => {
                        let entry = *entry;
                        if entry.source == TrafficSource::Intercepted {
                            handle.try_record(entry);
                        }
                    }
                    AppEvent::Repeater(rawframe_core::RepeaterEvent::Completed {
                        entry, ..
                    }) => {
                        if entry.source == TrafficSource::Repeater {
                            handle.try_record(*entry);
                        }
                    }
                    AppEvent::Intruder(rawframe_core::IntruderEvent::Completed {
                        entry, ..
                    }) => {
                        if entry.source == TrafficSource::Intruder {
                            handle.try_record(*entry);
                        }
                    }
                    AppEvent::WebSocketConnection(connection) => {
                        if matches!(
                            connection.source,
                            TrafficSource::Intercepted | TrafficSource::Repeater
                        ) {
                            handle.try_record_connection(*connection);
                        }
                    }
                    AppEvent::WebSocketFrame(frame) => {
                        handle.try_record_frame(*frame);
                    }
                    AppEvent::WebSocketMessage(message) => {
                        handle.try_record_message(*message);
                    }
                    AppEvent::Shutdown => break,
                    _ => {}
                }
            }
        })
}

fn run_worker(
    store: &mut Store,
    records: Receiver<Capture>,
    mut commands: StorageCommandReceiver,
    events: &EventSender,
    dropped: &AtomicU64,
) -> Result<(), StoreError> {
    let mut status = StorageStatus::enabled(
        store.path().to_path_buf(),
        store.session().id.clone(),
        store.policy(),
    );
    status.dropped = dropped.load(Ordering::Relaxed);
    let mut reported_dropped = status.dropped;
    let _ = events.send(AppEvent::Storage(StorageEvent::Status(status.clone())));

    loop {
        while let Ok(command) = commands.try_recv() {
            if handle_command(store, command, &mut status, events)? {
                let _ = store.close("shutdown");
                status.enabled = false;
                status.dropped = dropped.load(Ordering::Relaxed);
                let _ = events.send(AppEvent::Storage(StorageEvent::Status(status)));
                return Ok(());
            }
        }
        if !status.enabled {
            // Disk budget exhausted or the database failed: keep serving
            // queries, but drain and count captures instead of silently
            // accepting them into a queue nothing will write.
            while records.try_recv().is_ok() {
                dropped.fetch_add(1, Ordering::Relaxed);
            }
            let now_dropped = dropped.load(Ordering::Relaxed);
            if now_dropped != reported_dropped {
                reported_dropped = now_dropped;
                status.dropped = now_dropped;
                let _ = events.send(AppEvent::Storage(StorageEvent::Status(status.clone())));
            }
            std::thread::sleep(POLL_INTERVAL);
            continue;
        }

        match records.recv_timeout(POLL_INTERVAL) {
            Ok(first) => {
                let mut batch = Vec::with_capacity(BATCH_LIMIT);
                batch.push(first);
                while batch.len() < BATCH_LIMIT {
                    match records.try_recv() {
                        Ok(entry) => batch.push(entry),
                        Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
                    }
                }
                let count = batch.len();
                let mut traffic = Vec::new();
                let mut connections = Vec::new();
                let mut frames = Vec::new();
                let mut messages = Vec::new();
                for capture in batch {
                    match capture {
                        Capture::Traffic(entry) => traffic.push(*entry),
                        Capture::Connection(connection) => connections.push(*connection),
                        Capture::Frame(frame) => frames.push(*frame),
                        Capture::Message(message) => messages.push(*message),
                    }
                }
                let written = traffic.len() + connections.len() + frames.len() + messages.len();
                let result = (|| -> Result<(), StoreError> {
                    if !traffic.is_empty() {
                        store.write_batch(&traffic)?;
                    }
                    if !connections.is_empty() || !frames.is_empty() || !messages.is_empty() {
                        store.write_websocket(&connections, &frames, &messages)?;
                    }
                    Ok(())
                })();
                match result {
                    Ok(()) => {
                        status.persisted += written as u64;
                        status.dropped = dropped.load(Ordering::Relaxed);
                        let _ =
                            events.send(AppEvent::Storage(StorageEvent::Status(status.clone())));
                    }
                    Err(error) => {
                        let fatal = error.is_fatal();
                        tracing::error!(%error, "failed to persist captured traffic");
                        let _ = events.send(AppEvent::Storage(StorageEvent::Failed(format!(
                            "could not persist captured traffic: {error}"
                        ))));
                        // The writer refused this batch: count it either way so
                        // the UI never implies it was stored.
                        dropped.fetch_add(count as u64, Ordering::Relaxed);
                        status.dropped = dropped.load(Ordering::Relaxed);
                        reported_dropped = status.dropped;
                        if fatal {
                            status.enabled = false;
                            status.error = Some(error.to_string());
                        }
                        let _ =
                            events.send(AppEvent::Storage(StorageEvent::Status(status.clone())));
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                let _ = store.close("shutdown");
                return Ok(());
            }
        }
    }
}

fn handle_command(
    store: &mut Store,
    command: StorageCommand,
    status: &mut StorageStatus,
    events: &EventSender,
) -> Result<bool, StoreError> {
    match command {
        StorageCommand::Shutdown => return Ok(true),
        StorageCommand::ListSessions => match store.list_sessions() {
            Ok(sessions) => {
                let _ = events.send(AppEvent::Storage(StorageEvent::Sessions(sessions)));
            }
            Err(error) => {
                let _ = events.send(AppEvent::Storage(StorageEvent::Failed(format!(
                    "could not list stored sessions: {error}"
                ))));
            }
        },
        StorageCommand::LoadSession { session_id, limit } => {
            match store.load_session(&session_id, limit) {
                Ok((entries, truncated)) => {
                    let _ = events.send(AppEvent::Storage(StorageEvent::SessionLoaded {
                        session_id,
                        entries,
                        truncated,
                    }));
                }
                Err(error) => {
                    let _ = events.send(AppEvent::Storage(StorageEvent::Failed(format!(
                        "could not restore session {session_id}: {error}"
                    ))));
                }
            }
        }
        StorageCommand::ExportSession { session_id, path } => {
            match store.export_session(&session_id, &path) {
                Ok(summary) => {
                    let _ = events.send(AppEvent::Storage(StorageEvent::Exported {
                        session_id,
                        path,
                        records: summary.records,
                        redacted_headers: summary.redacted_headers,
                        bodies_omitted: summary.bodies_omitted,
                    }));
                }
                Err(error) => {
                    let _ = events.send(AppEvent::Storage(StorageEvent::Failed(format!(
                        "could not export session {session_id}: {error}"
                    ))));
                }
            }
        }
        StorageCommand::SetPolicy(policy) => {
            store.set_policy(policy);
            status.policy = policy;
            let _ = events.send(AppEvent::Storage(StorageEvent::Status(status.clone())));
        }
    }
    Ok(false)
}
