//! End-to-end tests for the CA management commands. Each test uses its own
//! temporary directory and the real `rawframe` binary with an isolated CA path.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_dir(label: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "rawframe-ca-cli-{label}-{}-{unique}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn run(dir: &Path, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rawframe"));
    command.arg("--tls-ca-dir").arg(dir);
    command.args(args);
    command.output().expect("failed to run rawframe")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn fingerprint_line(output: &Output) -> String {
    stdout(output)
        .lines()
        .find_map(|line| line.strip_prefix("Fingerprint: "))
        .expect("missing fingerprint output")
        .trim()
        .to_string()
}

#[test]
fn show_missing_material_does_not_create_a_ca() {
    let dir = temp_dir("missing");
    let output = run(&dir, &["--tls-ca-show"]);
    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("Status: missing or invalid"));
    assert!(text.contains("never trust private keys"));
    assert!(!dir.join("rawframe-ca.crt.pem").exists());
    assert!(!dir.join("rawframe-ca.key.pem").exists());
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn regenerate_show_fingerprint_and_export_are_consistent() {
    let dir = temp_dir("lifecycle");
    let regen = run(&dir, &["--tls-ca-regenerate"]);
    assert!(regen.status.success(), "{}", stderr(&regen));
    let regen_fp = fingerprint_line(&regen);

    let show = run(&dir, &["--tls-ca-show"]);
    assert!(show.status.success(), "{}", stderr(&show));
    let show_text = stdout(&show);
    assert!(show_text.contains("Status: ready"));
    assert!(show_text.contains(&regen_fp));
    assert!(show_text.contains("rawframe-ca.crt.pem"));

    let fingerprint = run(&dir, &["--tls-ca-fingerprint"]);
    assert!(fingerprint.status.success(), "{}", stderr(&fingerprint));
    assert_eq!(stdout(&fingerprint).trim(), regen_fp);

    let export_path = dir.join("public").join("rawframe-ca.pem");
    let export = run(&dir, &["--tls-ca-export", export_path.to_str().unwrap()]);
    assert!(export.status.success(), "{}", stderr(&export));
    let export_text = stdout(&export);
    assert!(export_text.contains("only the public certificate"));
    assert_eq!(fingerprint_line(&export), regen_fp);

    let exported = fs::read_to_string(&export_path).unwrap();
    let stored = fs::read_to_string(dir.join("rawframe-ca.crt.pem")).unwrap();
    assert_eq!(exported, stored);
    assert!(exported.contains("BEGIN CERTIFICATE"));
    assert!(!exported.contains("PRIVATE KEY"));
    assert!(!stdout(&export).contains("PRIVATE KEY"));

    let key = fs::read_to_string(dir.join("rawframe-ca.key.pem")).unwrap();
    assert!(key.contains("BEGIN PRIVATE KEY"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(dir.join("rawframe-ca.key.pem"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "CA private key must be owner-only");
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn invalid_material_is_reported_and_not_silently_replaced() {
    let dir = temp_dir("invalid");
    let cert = dir.join("rawframe-ca.crt.pem");
    let key = dir.join("rawframe-ca.key.pem");
    fs::write(&cert, "not-a-certificate\n").unwrap();
    fs::write(&key, "not-a-private-key\n").unwrap();

    let fingerprint = run(&dir, &["--tls-ca-fingerprint"]);
    assert!(!fingerprint.status.success());
    let error = stderr(&fingerprint);
    assert!(error.contains("loading local CA"), "{error}");
    assert!(!error.contains("not-a-private-key"), "{error}");

    let export_path = dir.join("must-not-exist.pem");
    let export = run(&dir, &["--tls-ca-export", export_path.to_str().unwrap()]);
    assert!(!export.status.success());
    assert!(!export_path.exists());
    assert!(!stderr(&export).contains("not-a-private-key"));

    let show = run(&dir, &["--tls-ca-show"]);
    assert!(show.status.success(), "{}", stderr(&show));
    let show_text = stdout(&show);
    assert!(show_text.contains("Status: missing or invalid"));
    assert!(!show_text.contains("not-a-private-key"));
    assert_eq!(fs::read_to_string(&cert).unwrap(), "not-a-certificate\n");
    assert_eq!(fs::read_to_string(&key).unwrap(), "not-a-private-key\n");

    // Replacement happens only through the explicit regeneration operation.
    let regen = run(&dir, &["--tls-ca-regenerate"]);
    assert!(regen.status.success(), "{}", stderr(&regen));
    let replaced = fs::read_to_string(&cert).unwrap();
    assert!(replaced.contains("BEGIN CERTIFICATE"));
    assert_ne!(replaced, "not-a-certificate\n");

    let _ = fs::remove_dir_all(dir);
}
