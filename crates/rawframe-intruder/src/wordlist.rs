//! Bounded local wordlist import.
//!
//! Files are streamed line by line and are never executed, never sent, and never
//! loaded wholesale into memory. Four limits are enforced: total bytes read,
//! bytes per line, payloads accepted, and per-payload size. A file that exceeds
//! a limit is reported as truncated rather than silently cut short, and lines
//! that are not valid UTF-8 are skipped and counted instead of being
//! reinterpreted.

use std::path::Path;

use rawframe_core::{
    MAX_PAYLOAD_BYTES, MAX_PAYLOADS_PER_SET, MAX_WORDLIST_BYTES, MAX_WORDLIST_LINE_BYTES,
    WordlistOutcome,
};
use tokio::io::{AsyncBufReadExt, BufReader};

/// Reads a local wordlist under the Intruder limits. Errors are reported in the
/// returned value so the interface never shows an empty list without a reason.
pub async fn load_wordlist(request: u64, path: &Path) -> WordlistOutcome {
    let mut outcome = WordlistOutcome {
        request,
        path: path.display().to_string(),
        payloads: Vec::new(),
        skipped: 0,
        invalid_utf8: 0,
        truncated: false,
        error: None,
    };

    let file = match tokio::fs::File::open(path).await {
        Ok(file) => file,
        Err(error) => {
            outcome.error = Some(format!("could not open the wordlist: {error}"));
            return outcome;
        }
    };

    let mut reader = BufReader::new(file);
    let mut line: Vec<u8> = Vec::new();
    let mut total_bytes: u64 = 0;

    loop {
        line.clear();
        match reader.read_until(b'\n', &mut line).await {
            Ok(0) => break,
            Ok(read) => {
                total_bytes = total_bytes.saturating_add(read as u64);
                if total_bytes > MAX_WORDLIST_BYTES {
                    outcome.truncated = true;
                    outcome.error = Some(format!(
                        "file exceeds the {MAX_WORDLIST_BYTES}-byte wordlist limit; only the first {} payloads were read",
                        outcome.payloads.len()
                    ));
                    break;
                }
            }
            Err(error) => {
                outcome.error = Some(format!("could not read the wordlist: {error}"));
                break;
            }
        }

        let trimmed = line.strip_suffix(b"\n").unwrap_or(&line);
        let trimmed = trimmed.strip_suffix(b"\r").unwrap_or(trimmed);
        if trimmed.is_empty() {
            outcome.skipped += 1;
            continue;
        }
        if trimmed.len() > MAX_WORDLIST_LINE_BYTES {
            // A line this long is almost never an intentional payload.
            outcome.skipped += 1;
            continue;
        }
        if trimmed.len() > MAX_PAYLOAD_BYTES {
            outcome.skipped += 1;
            continue;
        }
        if std::str::from_utf8(trimmed).is_err() {
            outcome.invalid_utf8 += 1;
            continue;
        }
        if outcome.payloads.len() >= MAX_PAYLOADS_PER_SET {
            outcome.truncated = true;
            outcome.error = Some(format!(
                "file contains more than the {MAX_PAYLOADS_PER_SET}-payload limit; extra lines were not read"
            ));
            break;
        }
        outcome.payloads.push(trimmed.to_vec());
    }

    if outcome.payloads.is_empty() && outcome.error.is_none() {
        outcome.error = Some("the selected file contained no usable payloads".into());
    }

    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp_file(contents: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("wordlist.txt");
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(contents).unwrap();
        file.flush().unwrap();
        (dir, path)
    }

    #[tokio::test]
    async fn loads_one_payload_per_line() {
        let (_dir, path) = temp_file(b"alpha\nbeta\ngamma\n");
        let outcome = load_wordlist(7, &path).await;
        assert!(outcome.error.is_none());
        assert_eq!(outcome.payloads.len(), 3);
        assert_eq!(outcome.payloads[1], b"beta".to_vec());
        assert_eq!(outcome.request, 7);
        assert!(!outcome.truncated);
    }

    #[tokio::test]
    async fn handles_crlf_and_skips_blank_lines() {
        let (_dir, path) = temp_file(b"a\r\n\r\nb\r\n");
        let outcome = load_wordlist(1, &path).await;
        assert_eq!(outcome.payloads, vec![b"a".to_vec(), b"b".to_vec()]);
        assert_eq!(outcome.skipped, 1);
    }

    #[tokio::test]
    async fn invalid_utf8_lines_are_counted_not_reinterpreted() {
        let (_dir, path) = temp_file(b"ok\n\xff\xfe\nfine\n");
        let outcome = load_wordlist(1, &path).await;
        assert_eq!(outcome.payloads, vec![b"ok".to_vec(), b"fine".to_vec()]);
        assert_eq!(outcome.invalid_utf8, 1);
    }

    #[tokio::test]
    async fn payload_ceiling_truncates_with_a_reason() {
        let mut contents = Vec::new();
        for index in 0..(MAX_PAYLOADS_PER_SET + 10) {
            contents.extend_from_slice(format!("value{index}\n").as_bytes());
        }
        let (_dir, path) = temp_file(&contents);
        let outcome = load_wordlist(1, &path).await;
        assert_eq!(outcome.payloads.len(), MAX_PAYLOADS_PER_SET);
        assert!(outcome.truncated);
        assert!(outcome.error.is_some());
    }

    #[tokio::test]
    async fn missing_file_reports_the_reason() {
        let outcome = load_wordlist(1, Path::new("/nonexistent/rawframe-wordlist")).await;
        assert!(outcome.payloads.is_empty());
        assert!(outcome.error.unwrap().contains("could not open"));
    }

    #[tokio::test]
    async fn empty_file_is_explained() {
        let (_dir, path) = temp_file(b"\n\n");
        let outcome = load_wordlist(1, &path).await;
        assert!(outcome.payloads.is_empty());
        assert!(outcome.error.unwrap().contains("no usable payloads"));
    }
}
