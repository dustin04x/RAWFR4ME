//! Real PTY regression for the TUI TLS interception lifecycle.
//!
//! The heavy lifting lives in `scripts/tui_tls_pty.py`: it launches this
//! crate's binary in a pseudo-terminal, drives the actual Settings controls,
//! and sends real CONNECT/TLS traffic to a local HTTPS origin. The test is
//! skipped only when the local Python cryptography/PTY runtime is unavailable.

use std::path::PathBuf;
use std::process::Command;

#[test]
fn tui_tls_enable_disable_through_real_pty() {
    let python_ok = Command::new("python3")
        .args(["-c", "import cryptography, pty, ssl"])
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    if !python_ok {
        eprintln!("SKIP: python3 with cryptography/pty is required for the PTY TLS test");
        return;
    }

    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scripts/tui_tls_pty.py");
    assert!(
        script.exists(),
        "PTY harness missing at {}",
        script.display()
    );
    let output = Command::new("python3")
        .arg(&script)
        .args([
            "--binary",
            env!("CARGO_BIN_EXE_rawframe"),
            "--sizes",
            "100x30",
            "--captures-dir",
            "",
            "--no-png",
        ])
        .output()
        .expect("run PTY TLS harness");
    assert!(
        output.status.success(),
        "PTY TLS harness failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("ALL PASS"),
        "harness did not report success:\n{stdout}"
    );
    assert!(stdout.contains("decrypted request appears"), "{stdout}");
    assert!(
        stdout.contains("new post-disable CONNECT is not decrypted"),
        "{stdout}"
    );
}
