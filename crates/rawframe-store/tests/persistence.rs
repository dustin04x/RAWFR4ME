//! Integration tests for the real SQLite store: no mocks, isolated temp DBs.

use std::fs;
use std::time::{Duration, Instant};

use chrono::Utc;
use rawframe_core::events::{AppEvent, EventBus};
use rawframe_core::models::headers::Headers;
use rawframe_core::models::message::{HttpRequest, HttpResponse, Scheme};
use rawframe_core::models::session::{Project, Session, SessionId};
use rawframe_core::models::traffic::{
    TrafficEntry, TrafficId, TrafficSource, TrafficState, TunnelMetadata, TunnelOutcome,
};
use rawframe_core::repeater::{
    REPEATER_ID_BASE, RepeaterEvent, RepeaterExecutionPhase, RepeaterResult, RepeaterTimings,
};
use rawframe_core::storage::{StorageCommand, StorageEvent, StoragePolicy};
use rawframe_store::store::{DEFAULT_MAX_BYTES, parse_timestamp};
use rawframe_store::{StorageOptions, StorageService, Store, StoreError, spawn_capture_pump};
use tempfile::TempDir;

fn project() -> Project {
    Project::default_project()
}

fn policy() -> StoragePolicy {
    StoragePolicy::metadata_only()
}

fn open(dir: &TempDir, session: &Session, policy: StoragePolicy) -> Store {
    Store::open(
        dir.path().join("sessions.db"),
        &project(),
        session,
        policy,
        DEFAULT_MAX_BYTES,
    )
    .expect("store opens")
}

fn sample_entry(id: u64) -> TrafficEntry {
    let mut request = HttpRequest::new("GET", Scheme::Https, "api.rawframe.test", 443, "/v1/items");
    request
        .headers
        .append("Authorization", "Bearer super-secret");
    request.headers.append("Accept", "application/json");
    request.body = br#"{"query":1}"#.to_vec();

    let mut entry = TrafficEntry::new(TrafficId(id), request);
    entry.forward().unwrap();
    let mut response = HttpResponse::with_body(200, "application/json", br#"{"ok":true}"#.to_vec());
    response.headers.append("Set-Cookie", "first=1");
    response.headers.append("Set-Cookie", "second=2");
    response.headers.append("X-Api-Key", "response-secret");
    entry.complete(response, 12).unwrap();
    entry.note = Some("operator note".into());
    entry
}

#[test]
fn metadata_only_policy_redacts_headers_and_omits_bodies() {
    let dir = TempDir::new().unwrap();
    let session = Session::new("metadata-only");
    let mut store = open(&dir, &session, policy());
    store.write_entry(&sample_entry(1)).unwrap();

    let (entries, truncated) = store.load_session(&session.id, 100).unwrap();
    assert!(!truncated);
    assert_eq!(entries.len(), 1);
    let entry = &entries[0];

    assert_eq!(entry.source, TrafficSource::Restored);
    assert!(entry.is_restored());
    assert!(entry.body_omitted, "policy withheld bodies");
    assert_eq!(entry.request.body, Vec::<u8>::new());
    assert_eq!(entry.response.as_ref().unwrap().body, Vec::<u8>::new());
    assert_eq!(
        entry.request.headers.get("authorization"),
        Some("<redacted>")
    );
    assert_eq!(
        entry.response.as_ref().unwrap().headers.get("x-api-key"),
        Some("<redacted>")
    );
    assert_eq!(
        entry.request.headers.get("accept"),
        Some("application/json")
    );
    assert!(entry.redacted_headers >= 2, "masked values are counted");
    assert_eq!(entry.response.as_ref().unwrap().status, 200);
    assert_eq!(entry.state, TrafficState::Completed);
    assert_eq!(entry.note.as_deref(), Some("operator note"));

    // The raw row stores SQL NULL, not an empty blob.
    let conn = rusqlite::Connection::open(store.path()).unwrap();
    let (request_body, response_body): (Option<Vec<u8>>, Option<Vec<u8>>) = conn
        .query_row(
            "SELECT request_body, response_body FROM traffic",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(request_body, None);
    assert_eq!(response_body, None);
}

#[test]
fn opting_in_persists_bodies_and_sensitive_values() {
    let dir = TempDir::new().unwrap();
    let session = Session::new("full-fidelity");
    let policy = StoragePolicy {
        persist_bodies: true,
        persist_sensitive_headers: true,
    };
    let mut store = open(&dir, &session, policy);
    store.write_entry(&sample_entry(1)).unwrap();

    let (entries, _) = store.load_session(&session.id, 10).unwrap();
    let entry = &entries[0];
    assert!(!entry.body_omitted);
    assert_eq!(entry.request.body, br#"{"query":1}"#.to_vec());
    assert_eq!(
        entry.response.as_ref().unwrap().body,
        br#"{"ok":true}"#.to_vec()
    );
    assert_eq!(
        entry.request.headers.get("authorization"),
        Some("Bearer super-secret")
    );
    assert_eq!(
        entry.response.as_ref().unwrap().headers.get("x-api-key"),
        Some("response-secret")
    );
}

#[test]
fn duplicate_headers_keep_order_and_count() {
    let dir = TempDir::new().unwrap();
    let session = Session::new("duplicates");
    let mut store = open(
        &dir,
        &session,
        StoragePolicy {
            persist_bodies: false,
            persist_sensitive_headers: true,
        },
    );
    store.write_entry(&sample_entry(1)).unwrap();

    let (entries, _) = store.load_session(&session.id, 10).unwrap();
    let set_cookies: Vec<&str> = entries[0]
        .response
        .as_ref()
        .unwrap()
        .headers
        .get_all("set-cookie")
        .collect();
    assert_eq!(set_cookies, ["first=1", "second=2"]);
    assert_eq!(entries[0].response.as_ref().unwrap().headers.len(), 5);
}

#[test]
fn binary_bodies_round_trip_bytes_exactly() {
    let dir = TempDir::new().unwrap();
    let session = Session::new("binary");
    let policy = StoragePolicy {
        persist_bodies: true,
        persist_sensitive_headers: false,
    };
    let mut store = open(&dir, &session, policy);

    let binary: Vec<u8> = (0..=255u8).collect();
    let mut request = HttpRequest::new("POST", Scheme::Http, "upload.test", 80, "/bin");
    request.body = binary.clone();
    let mut entry = TrafficEntry::new(TrafficId(1), request);
    entry.forward().unwrap();
    let mut response = HttpResponse::new(204);
    response.body = binary.clone();
    entry.complete(response, 1).unwrap();
    store.write_entry(&entry).unwrap();

    let (entries, _) = store.load_session(&session.id, 10).unwrap();
    assert_eq!(entries[0].request.body, binary);
    assert_eq!(entries[0].response.as_ref().unwrap().body, binary);
}

#[test]
fn tunnel_metadata_and_modified_requests_round_trip() {
    let dir = TempDir::new().unwrap();
    let session = Session::new("tunnel");
    let mut store = open(
        &dir,
        &session,
        StoragePolicy {
            persist_bodies: true,
            persist_sensitive_headers: false,
        },
    );

    let request = HttpRequest::new("CONNECT", Scheme::Https, "secure.test", 443, "/");
    let metadata = TunnelMetadata {
        client_to_upstream_bytes: 1234,
        upstream_to_client_bytes: 4321,
        outcome: TunnelOutcome::Closed,
    };
    let mut entry =
        TrafficEntry::tunnel(TrafficId(3), request.clone(), metadata.clone(), Utc::now());
    let mut original = request.clone();
    original.body = b"original-body".to_vec();
    let mut edited = request;
    edited.target = "/changed".into();
    edited.body = b"edited-body".to_vec();
    entry.original_request = Some(original);
    entry.final_request = Some(edited);
    entry.forward().unwrap();
    entry.complete(HttpResponse::new(200), 4).unwrap();
    store.write_entry(&entry).unwrap();

    let (entries, _) = store.load_session(&session.id, 10).unwrap();
    let loaded = &entries[0];
    assert!(loaded.is_tunnel());
    assert_eq!(loaded.tunnel.as_ref(), Some(&metadata));
    assert_eq!(
        loaded.original_request.as_ref().unwrap().body,
        b"original-body".to_vec()
    );
    assert_eq!(
        loaded.final_request.as_ref().unwrap().target,
        "/changed".to_string()
    );
    assert_eq!(
        loaded.final_request.as_ref().unwrap().body,
        b"edited-body".to_vec()
    );
}

#[test]
fn repeater_transactions_keep_provenance_and_are_redacted() {
    let dir = TempDir::new().unwrap();
    let session = Session::new("repeater");
    let mut store = open(&dir, &session, policy());
    let mut entry = sample_entry(REPEATER_ID_BASE + 1);
    entry.source = TrafficSource::Repeater;
    entry.repeater_origin = Some(TrafficId(14));
    entry.original_request = Some(sample_entry(1).request);
    store.write_entry(&entry).unwrap();

    let (entries, _) = store.load_session(&session.id, 10).unwrap();
    let restored = &entries[0];
    assert_eq!(restored.source, TrafficSource::Restored);
    assert_eq!(restored.repeater_origin, Some(TrafficId(14)));
    assert_eq!(
        restored.request.headers.get("authorization"),
        Some("<redacted>")
    );
    assert_eq!(
        restored.response.as_ref().unwrap().headers.get("x-api-key"),
        Some("<redacted>")
    );
    assert!(restored.body_omitted);
    assert!(restored.response.as_ref().unwrap().body.is_empty());

    let export = dir.path().join("repeater.jsonl");
    store.export_session(&session.id, &export).unwrap();
    let line: serde_json::Value =
        serde_json::from_str(fs::read_to_string(&export).unwrap().lines().next().unwrap()).unwrap();
    assert_eq!(line["stored_source"], "repeater");
    assert_eq!(line["repeater_origin"], 14);
    assert_eq!(line["request_body"]["omitted"], true);
}

#[test]
fn capture_pump_persists_completed_repeater_executions() {
    let dir = TempDir::new().unwrap();
    let session = Session::new("repeater-pump");
    let mut bus = EventBus::new();
    let mut observer = bus.subscribe();
    let service = StorageService::spawn(
        StorageOptions::new(dir.path().join("sessions.db"), session.clone(), policy()),
        bus.sender(),
    )
    .unwrap();
    let pump = spawn_capture_pump(bus.subscribe(), service.handle()).unwrap();

    let mut entry = sample_entry(REPEATER_ID_BASE + 2);
    entry.source = TrafficSource::Repeater;
    entry.repeater_origin = Some(TrafficId(22));
    let result = RepeaterResult {
        request: entry.request.clone(),
        response: entry.response.clone(),
        timings: RepeaterTimings {
            total_ms: 9,
            ..RepeaterTimings::default()
        },
        redirects: Vec::new(),
        truncated: false,
        response_bytes: 11,
        error: None,
        warnings: Vec::new(),
        sent_at: Utc::now(),
    };
    bus.sender()
        .send(AppEvent::Repeater(RepeaterEvent::Completed {
            tab: rawframe_core::models::session::RepeaterId(1),
            execution: 1,
            phase: RepeaterExecutionPhase::Completed,
            result: Box::new(result),
            entry: Box::new(entry),
        }))
        .unwrap();
    wait_status(&mut observer, |status| status.persisted >= 1);
    bus.sender().send(AppEvent::Shutdown).unwrap();
    pump.join().unwrap();

    service
        .handle()
        .command_sender()
        .try_send(StorageCommand::LoadSession {
            session_id: session.id.clone(),
            limit: 10,
        })
        .expect("load accepted");
    let loaded = wait_for(&mut observer, |event| match event {
        StorageEvent::SessionLoaded { entries, .. } if !entries.is_empty() => Some(entries),
        _ => None,
    });
    assert_eq!(loaded[0].repeater_origin, Some(TrafficId(22)));

    service.shutdown();
}

#[test]
fn lifecycle_updates_upsert_the_same_row() {
    let dir = TempDir::new().unwrap();
    let session = Session::new("lifecycle");
    let mut store = open(&dir, &session, policy());

    let mut entry = sample_entry(7);
    entry.response = None;
    entry.state = TrafficState::Forwarded;
    store.write_entry(&entry).unwrap();
    assert_eq!(store.count_records(&session.id).unwrap(), 1);

    entry
        .complete(
            HttpResponse::with_body(201, "text/plain", b"created".to_vec()),
            5,
        )
        .unwrap();
    store.write_entry(&entry).unwrap();
    assert_eq!(store.count_records(&session.id).unwrap(), 1);

    let (entries, _) = store.load_session(&session.id, 10).unwrap();
    assert_eq!(entries[0].state, TrafficState::Completed);
    assert_eq!(entries[0].response.as_ref().unwrap().status, 201);
}

#[test]
fn sessions_are_isolated_and_listed_with_counts() {
    let dir = TempDir::new().unwrap();
    let first = Session::new("first");
    let second = Session::new("second");

    let mut store = open(&dir, &first, policy());
    store.write_entry(&sample_entry(1)).unwrap();
    store.close("shutdown").unwrap();
    drop(store);

    let mut other = open(&dir, &second, policy());
    other.write_entry(&sample_entry(1)).unwrap();
    other.write_entry(&sample_entry(2)).unwrap();

    let (first_entries, _) = other.load_session(&first.id, 10).unwrap();
    assert_eq!(first_entries.len(), 1);
    let (second_entries, _) = other.load_session(&second.id, 10).unwrap();
    assert_eq!(second_entries.len(), 2);

    let sessions = other.list_sessions().unwrap();
    assert_eq!(sessions.len(), 2);
    let first_summary = sessions.iter().find(|s| s.id == first.id).unwrap();
    let second_summary = sessions.iter().find(|s| s.id == second.id).unwrap();
    assert_eq!(first_summary.records, 1);
    assert_eq!(second_summary.records, 2);
    assert!(!first_summary.recovered);
    assert!(!second_summary.recovered);
}

#[test]
fn reopening_preserves_history_and_reports_truncation() {
    let dir = TempDir::new().unwrap();
    let session = Session::new("restart");
    {
        let mut store = open(&dir, &session, policy());
        store.write_entry(&sample_entry(1)).unwrap();
        store.write_entry(&sample_entry(2)).unwrap();
        store.close("shutdown").unwrap();
    }
    let store = open(&dir, &session, policy());
    assert_eq!(store.count_records(&session.id).unwrap(), 2);

    let (entries, truncated) = store.load_session(&session.id, 1).unwrap();
    assert_eq!(entries.len(), 1);
    assert!(truncated);

    let summary = store
        .list_sessions()
        .unwrap()
        .into_iter()
        .find(|s| s.id == session.id)
        .unwrap();
    assert!(summary.last_activity_at.is_some());
}

#[test]
fn interrupted_runs_are_recovered_and_marked_incomplete() {
    let dir = TempDir::new().unwrap();
    let crashed = Session::new("interrupted");
    {
        let mut store = open(&dir, &crashed, policy());
        let mut pending = sample_entry(1);
        pending.response = None;
        pending.state = TrafficState::Forwarded;
        store.write_entry(&pending).unwrap();
        // No close(): simulate a crash.
    }

    // The next run opens a new session; the crashed one is recovered.
    let store = open(&dir, &Session::new("next-run"), policy());
    let summaries = store.list_sessions().unwrap();
    let summary = summaries.iter().find(|s| s.id == crashed.id).unwrap();
    assert_eq!(summary.incomplete, 1, "pending row stays pending");
    assert!(summary.recovered, "unclean shutdown is flagged");

    let (entries, _) = store.load_session(&crashed.id, 10).unwrap();
    assert_eq!(entries[0].state, TrafficState::Forwarded);
    assert!(entries[0].state.is_pending());
}

#[test]
fn unknown_sessions_are_reported_not_silently_empty() {
    let dir = TempDir::new().unwrap();
    let store = open(&dir, &Session::new("known"), policy());
    let err = store
        .load_session(&SessionId("missing".into()), 10)
        .unwrap_err();
    assert!(matches!(err, StoreError::UnknownSession(id) if id == "missing"));
}

#[test]
fn corrupt_database_is_refused_without_deleting_it() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("sessions.db");
    fs::write(
        &path,
        b"this is not a sqlite database at all, not even close",
    )
    .unwrap();

    let result = Store::open(
        &path,
        &project(),
        &Session::new("corrupt"),
        policy(),
        DEFAULT_MAX_BYTES,
    );
    match result {
        Err(StoreError::Corrupt(_)) | Err(StoreError::Sqlite(_)) => {}
        Err(other) => panic!("unexpected error: {other}"),
        Ok(_) => panic!("corrupt file must not open"),
    }
    // The operator's file is still there to inspect or recover.
    assert_eq!(
        fs::read(&path).unwrap(),
        b"this is not a sqlite database at all, not even close"
    );
}

#[test]
fn unwritable_location_fails_cleanly() {
    let dir = TempDir::new().unwrap();
    let blocker = dir.path().join("blocker");
    fs::write(&blocker, b"file").unwrap();
    let result = Store::open(
        blocker.join("sessions.db"),
        &project(),
        &Session::new("unwritable"),
        policy(),
        DEFAULT_MAX_BYTES,
    );
    assert!(result.is_err(), "a file cannot be used as a directory");
}

#[test]
fn failed_batch_rolls_back_every_row() {
    let dir = TempDir::new().unwrap();
    let session = Session::new("atomic");
    let mut store = open(&dir, &session, policy());

    // A trigger that aborts one specific host makes the second insert fail
    // inside the transaction, proving the first row is rolled back too.
    {
        let conn = rusqlite::Connection::open(store.path()).unwrap();
        conn.execute_batch(
            "CREATE TRIGGER refuse_host BEFORE INSERT ON traffic
             WHEN NEW.host = 'blocked.test'
             BEGIN SELECT RAISE(ABORT, 'refused'); END;",
        )
        .unwrap();
    }

    let mut blocked = sample_entry(2);
    blocked.request.host = "blocked.test".into();
    let error = store
        .write_batch(&[sample_entry(1), blocked])
        .expect_err("trigger aborts the batch");
    assert!(matches!(error, StoreError::Sqlite(_)), "got {error:?}");
    assert_eq!(store.count_records(&session.id).unwrap(), 0);
}

#[test]
fn export_is_redacted_json_lines() {
    let dir = TempDir::new().unwrap();
    let session = Session::new("export");
    let mut store = open(&dir, &session, policy());
    store.write_entry(&sample_entry(1)).unwrap();

    let export = dir.path().join("history.jsonl");
    let summary = store.export_session(&session.id, &export).unwrap();
    assert_eq!(summary.records, 1);
    assert!(summary.redacted_headers >= 2);
    assert_eq!(summary.bodies_omitted, 1);

    let text = fs::read_to_string(&export).unwrap();
    let line: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
    assert_eq!(line["format"], "rawframe.history.v1");
    assert_eq!(line["host"], "api.rawframe.test");
    assert_eq!(line["request_body"]["omitted"], true);
    assert_eq!(line["request_headers"][0]["value"], "api.rawframe.test");
    let authorization = line["request_headers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|header| header["name"] == "Authorization")
        .unwrap();
    assert_eq!(authorization["value"], "<redacted>");
    assert!(
        !text.contains("super-secret") && !text.contains("response-secret"),
        "JSONL export must not leak sensitive values"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&export).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "exports are owner-only");
    }
}

#[test]
fn timestamps_survive_a_round_trip() {
    let dir = TempDir::new().unwrap();
    let session = Session::new("timestamps");
    let mut store = open(&dir, &session, policy());
    let entry = sample_entry(1);
    let started = entry.timings.started_at;
    store.write_entry(&entry).unwrap();

    let (entries, _) = store.load_session(&session.id, 10).unwrap();
    assert!(
        (entries[0].timings.started_at - started)
            .num_milliseconds()
            .abs()
            <= 1
    );
    assert_eq!(entries[0].timings.duration_ms, Some(12));
    assert!(entries[0].timings.completed_at.is_some());
    assert!(parse_timestamp(&Utc::now().to_rfc3339()).is_some());
}

#[test]
fn headers_helper_redacts_without_losing_duplicates() {
    // Guards the contract the store relies on, in the same test binary.
    let headers = Headers::from_pairs([("Cookie", "a=1"), ("Cookie", "b=2")]);
    let (redacted, count) = headers.redacted();
    assert_eq!(count, 2);
    assert_eq!(
        redacted.get_all("cookie").collect::<Vec<_>>(),
        ["<redacted>", "<redacted>"]
    );
}

#[test]
fn worker_persists_captures_and_answers_queries() {
    let dir = TempDir::new().unwrap();
    let session = Session::new("worker");
    let mut bus = EventBus::new();
    let mut observer = bus.subscribe();
    let service = StorageService::spawn(
        StorageOptions::new(dir.path().join("sessions.db"), session.clone(), policy()),
        bus.sender(),
    )
    .expect("worker starts");

    let handle = service.handle();
    assert!(handle.try_record(sample_entry(1)));

    wait_status(&mut observer, |status| status.persisted >= 1);

    let commands = handle.command_sender();
    commands
        .try_send(StorageCommand::ListSessions)
        .expect("command accepted");
    let sessions = wait_for(&mut observer, |event| match event {
        StorageEvent::Sessions(list) if !list.is_empty() => Some(list.clone()),
        _ => None,
    });
    assert_eq!(sessions[0].records, 1);

    commands
        .try_send(StorageCommand::LoadSession {
            session_id: session.id.clone(),
            limit: 10,
        })
        .expect("load accepted");
    let loaded = wait_for(&mut observer, |event| match event {
        StorageEvent::SessionLoaded { entries, .. } if !entries.is_empty() => Some(entries.clone()),
        _ => None,
    });
    assert_eq!(loaded[0].source, TrafficSource::Restored);

    service.shutdown();
}

#[test]
fn capture_pump_forwards_only_live_captures() {
    let dir = TempDir::new().unwrap();
    let session = Session::new("pump");
    let mut bus = EventBus::new();
    let mut observer = bus.subscribe();
    let service = StorageService::spawn(
        StorageOptions::new(dir.path().join("sessions.db"), session.clone(), policy()),
        bus.sender(),
    )
    .unwrap();
    let pump = spawn_capture_pump(bus.subscribe(), service.handle()).unwrap();

    let sender = bus.sender();
    sender
        .send(AppEvent::TrafficCaptured(Box::new(sample_entry(1))))
        .unwrap();
    wait_status(&mut observer, |status| status.persisted >= 1);

    // Simulated fixtures and authored drafts are not history.
    let mut simulated = sample_entry(2);
    simulated.source = TrafficSource::Simulated;
    sender
        .send(AppEvent::TrafficCaptured(Box::new(simulated)))
        .unwrap();
    sender.send(AppEvent::Shutdown).unwrap();
    pump.join().unwrap();

    let commands = service.handle().command_sender();
    commands.try_send(StorageCommand::ListSessions).unwrap();
    let sessions = wait_for(&mut observer, |event| match event {
        StorageEvent::Sessions(list) => Some(list),
        _ => None,
    });
    let summary = sessions.iter().find(|s| s.id == session.id).unwrap();
    assert_eq!(summary.records, 1, "simulated traffic was not stored");

    service.shutdown();
}

#[test]
fn worker_accepts_concurrent_capture_producers() {
    let dir = TempDir::new().unwrap();
    let session = Session::new("concurrent");
    let mut bus = EventBus::new();
    let mut observer = bus.subscribe();
    let service = StorageService::spawn(
        StorageOptions::new(dir.path().join("sessions.db"), session.clone(), policy()),
        bus.sender(),
    )
    .unwrap();

    let mut producers = Vec::new();
    for producer in 0..4u64 {
        let handle = service.handle();
        producers.push(std::thread::spawn(move || {
            for offset in 0..25u64 {
                assert!(handle.try_record(sample_entry(producer * 25 + offset + 1)));
            }
        }));
    }
    for producer in producers {
        producer.join().unwrap();
    }

    wait_status(&mut observer, |status| status.persisted >= 100);
    let commands = service.handle().command_sender();
    commands.try_send(StorageCommand::ListSessions).unwrap();
    let sessions = wait_for(&mut observer, |event| match event {
        StorageEvent::Sessions(list) => Some(list),
        _ => None,
    });
    let summary = sessions.iter().find(|s| s.id == session.id).unwrap();
    assert_eq!(summary.records, 100, "every producer's capture is durable");

    service.shutdown();
}

#[test]
fn worker_stops_accepting_captures_after_shutdown() {
    let dir = TempDir::new().unwrap();
    let bus = EventBus::new();
    let service = StorageService::spawn(
        StorageOptions::new(
            dir.path().join("sessions.db"),
            Session::new("stopped"),
            policy(),
        ),
        bus.sender(),
    )
    .unwrap();
    let handle = service.handle();
    service.shutdown();

    assert!(!handle.try_record(sample_entry(1)));
    // The drop is counted rather than silently ignored.
    assert!(handle.dropped() >= 1);
}

type AppEvents = tokio::sync::mpsc::Receiver<rawframe_core::events::AppEvent>;

/// Polls the storage subscriber until `predicate` returns a value or two
/// seconds pass. Real events are required: no test-only injection path exists.
fn wait_for<T>(
    receiver: &mut AppEvents,
    mut predicate: impl FnMut(StorageEvent) -> Option<T>,
) -> T {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if Instant::now() > deadline {
            panic!("timed out waiting for storage event");
        }
        match receiver.try_recv() {
            Ok(rawframe_core::events::AppEvent::Storage(event)) => {
                if let Some(value) = predicate(event) {
                    return value;
                }
            }
            Ok(_) => {}
            Err(_) => std::thread::sleep(Duration::from_millis(5)),
        }
    }
}

fn wait_status(
    receiver: &mut AppEvents,
    mut predicate: impl FnMut(&rawframe_core::storage::StorageStatus) -> bool,
) -> rawframe_core::storage::StorageStatus {
    wait_for(receiver, |event| match event {
        StorageEvent::Status(status) if predicate(&status) => Some(status),
        _ => None,
    })
}

#[test]
fn intruder_rows_keep_payload_metadata_and_stay_redacted() {
    use rawframe_core::INTRUDER_ID_BASE;

    let dir = TempDir::new().unwrap();
    let session = Session::new("intruder");
    let mut store = open(&dir, &session, policy());
    let mut entry = sample_entry(INTRUDER_ID_BASE + 3);
    entry.source = TrafficSource::Intruder;
    entry.intruder_origin = Some(TrafficId(7));
    // One text payload and one binary payload: the combination must survive
    // byte-exactly, including invalid UTF-8.
    entry.intruder_payloads = Some(vec![b"alice".to_vec(), vec![0x00, 0xff, 0xfe]]);
    store.write_entry(&entry).unwrap();

    let (entries, _) = store.load_session(&session.id, 10).unwrap();
    let restored = &entries[0];
    assert_eq!(restored.source, TrafficSource::Restored);
    assert_eq!(restored.intruder_origin, Some(TrafficId(7)));
    assert_eq!(
        restored.intruder_payloads,
        Some(vec![b"alice".to_vec(), vec![0x00, 0xff, 0xfe]])
    );
    // Provenance does not weaken the redaction policy.
    assert_eq!(
        restored.request.headers.get("authorization"),
        Some("<redacted>")
    );
    assert_eq!(
        restored.response.as_ref().unwrap().headers.get("x-api-key"),
        Some("<redacted>")
    );
    assert!(restored.body_omitted);
    assert!(restored.response.as_ref().unwrap().body.is_empty());

    let export = dir.path().join("intruder.jsonl");
    store.export_session(&session.id, &export).unwrap();
    let line: serde_json::Value =
        serde_json::from_str(fs::read_to_string(&export).unwrap().lines().next().unwrap()).unwrap();
    assert_eq!(line["stored_source"], "intruder");
    assert_eq!(line["intruder_origin"], 7);
    assert_eq!(line["intruder_payloads"][0], "YWxpY2U=");
    assert_eq!(line["intruder_payloads"][1], "AP/+");
    assert_eq!(line["request_body"]["omitted"], true);
}

#[test]
fn capture_pump_persists_completed_intruder_executions() {
    use rawframe_core::INTRUDER_ID_BASE;
    use rawframe_core::{IntruderEvent, IntruderResult};

    let dir = TempDir::new().unwrap();
    let session = Session::new("intruder-pump");
    let mut bus = EventBus::new();
    let mut observer = bus.subscribe();
    let service = StorageService::spawn(
        StorageOptions::new(dir.path().join("sessions.db"), session.clone(), policy()),
        bus.sender(),
    )
    .unwrap();
    let pump = spawn_capture_pump(bus.subscribe(), service.handle()).unwrap();

    let mut entry = sample_entry(INTRUDER_ID_BASE + 1);
    entry.source = TrafficSource::Intruder;
    entry.intruder_payloads = Some(vec![b"probe".to_vec()]);
    entry.intruder_origin = Some(TrafficId(31));
    let result = IntruderResult {
        id: entry.id,
        run: 1,
        index: 0,
        payloads: vec![b"probe".to_vec()],
        positions: vec![rawframe_core::PositionId(1)],
        phase: RepeaterExecutionPhase::Completed,
        result: RepeaterResult {
            request: entry.request.clone(),
            response: entry.response.clone(),
            timings: RepeaterTimings {
                total_ms: 4,
                ..RepeaterTimings::default()
            },
            redirects: Vec::new(),
            truncated: false,
            response_bytes: 11,
            error: None,
            warnings: Vec::new(),
            sent_at: Utc::now(),
        },
    };
    bus.sender()
        .send(AppEvent::Intruder(IntruderEvent::Completed {
            run: 1,
            result: Box::new(result),
            entry: Box::new(entry),
        }))
        .unwrap();
    wait_status(&mut observer, |status| status.persisted >= 1);
    bus.sender().send(AppEvent::Shutdown).unwrap();
    pump.join().unwrap();

    service
        .handle()
        .command_sender()
        .try_send(StorageCommand::LoadSession {
            session_id: session.id.clone(),
            limit: 10,
        })
        .expect("load accepted");
    let loaded = wait_for(&mut observer, |event| match event {
        StorageEvent::SessionLoaded { entries, .. } if !entries.is_empty() => Some(entries),
        _ => None,
    });
    assert_eq!(loaded[0].intruder_origin, Some(TrafficId(31)));
    assert_eq!(loaded[0].intruder_payloads, Some(vec![b"probe".to_vec()]));

    service.shutdown();
}
