//! Local-only diagnostic logging.
//!
//! Logs never include captured headers or bodies. The file is created with
//! owner-only permissions on Unix and stays inside RAWFRAME's data directory
//! unless the operator provides an explicit path.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use rawframe_core::models::config::data_directory;

/// Initializes file logging and returns the path in use. The TUI owns stdout,
/// so diagnostics are never written to stderr while the alternate screen is
/// active.
pub fn init(path: Option<&Path>) -> Result<PathBuf> {
    let path = path.map_or_else(
        || data_directory().join("logs").join("rawframe.log"),
        Path::to_path_buf,
    );
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating log directory {}", parent.display()))?;
    }

    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(&path)
        .with_context(|| format!("opening log file {}", path.display()))?;

    let writer = Mutex::new(file);
    // A global subscriber may already be installed in tests; failing to install
    // another one is not fatal to the application.
    let _ = tracing_subscriber::fmt()
        .with_writer(writer)
        .with_ansi(false)
        .with_target(false)
        .try_init();

    Ok(path)
}

/// Ensures a log directory exists and is writable without installing a
/// subscriber. Used by tests.
pub fn prepare(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    file.write_all(b"")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepares_a_log_file_in_a_temporary_directory() {
        let directory =
            std::env::temp_dir().join(format!("rawframe-log-test-{}", std::process::id()));
        let path = directory.join("rawframe.log");
        prepare(&path).unwrap();

        assert!(path.exists());
        let _ = std::fs::remove_dir_all(directory);
    }
}
