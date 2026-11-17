//! End-to-end tests for headless history export: a real SQLite database, the
//! real binary, and real redaction.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use rawframe_core::models::message::{HttpRequest, HttpResponse, Scheme};
use rawframe_core::models::session::{Project, Session};
use rawframe_core::models::traffic::{TrafficEntry, TrafficId};
use rawframe_core::storage::StoragePolicy;
use rawframe_store::{DEFAULT_MAX_BYTES, Store};

fn temp_dir(label: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "rawframe-export-{label}-{}-{unique}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rawframe"))
        .args(args)
        .output()
        .expect("failed to run rawframe")
}

fn seed_database(dir: &Path) -> PathBuf {
    let path = dir.join("sessions.db");
    let session = Session::new("export-fixture");
    let mut store = Store::open(
        &path,
        &Project::default_project(),
        &session,
        StoragePolicy::metadata_only(),
        DEFAULT_MAX_BYTES,
    )
    .unwrap();

    let mut request = HttpRequest::new("GET", Scheme::Https, "api.example.test", 443, "/v1/items");
    request
        .headers
        .append("Authorization", "Bearer super-secret");
    request.body = br#"{"secret":"payload"}"#.to_vec();
    let mut entry = TrafficEntry::new(TrafficId(7), request);
    entry.forward().unwrap();
    entry
        .complete(
            HttpResponse::with_body(200, "application/json", b"{}".to_vec()),
            9,
        )
        .unwrap();
    store.write_entry(&entry).unwrap();
    store.close("shutdown").unwrap();
    path
}

#[test]
fn export_history_writes_redacted_jsonl_without_starting_the_ui() {
    let dir = temp_dir("success");
    let database = seed_database(&dir);
    let output_path = dir.join("history.jsonl");

    let output = run(&[
        "--db",
        database.to_str().unwrap(),
        "--export-history",
        output_path.to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Exported 1 records"), "{stdout}");

    let text = fs::read_to_string(&output_path).expect("export file");
    let line: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
    assert_eq!(line["format"], "rawframe.history.v1");
    assert_eq!(line["host"], "api.example.test");
    assert_eq!(line["request_body"]["omitted"], true);
    let authorization = line["request_headers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|header| header["name"] == "Authorization")
        .expect("authorization header present");
    assert_eq!(authorization["value"], "<redacted>");
    assert!(!text.contains("super-secret"));
    assert!(!text.contains("payload"));

    // The exporting process must not create a phantom session in the database.
    let reopened = Store::open_existing(&database, StoragePolicy::metadata_only()).unwrap();
    assert_eq!(reopened.list_sessions().unwrap().len(), 1);

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn export_missing_database_is_a_clear_error() {
    let dir = temp_dir("missing");
    let missing = dir.join("absent.db");
    let output = run(&[
        "--db",
        missing.to_str().unwrap(),
        "--export-history",
        dir.join("out.jsonl").to_str().unwrap(),
    ]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("does not exist"), "{stderr}");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn export_unknown_session_is_reported() {
    let dir = temp_dir("unknown");
    let database = seed_database(&dir);
    let output = run(&[
        "--db",
        database.to_str().unwrap(),
        "--export-session",
        "sess-missing",
        "--export-history",
        dir.join("out.jsonl").to_str().unwrap(),
    ]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("sess-missing"), "{stderr}");
    let _ = fs::remove_dir_all(dir);
}
