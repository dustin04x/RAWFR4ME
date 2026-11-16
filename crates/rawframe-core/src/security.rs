//! Terminal-safe rendering of captured, potentially hostile data.
//!
//! Captured HTTP data is attacker-controlled. A terminal emulator may interpret
//! escape sequences, alter the reader's directionality, or hide content. Every
//! byte that reaches the UI or a log line passes through this module first.

/// Result of converting an HTTP body into terminal-safe display text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisplayBytes {
    pub text: String,
    pub truncated: bool,
    pub lossy: bool,
}

/// Escapes control characters, terminal escape sequences, and Unicode bidi
/// controls while preserving line breaks for readable display.
///
/// * `\n` is preserved.
/// * `\r\n` is collapsed to `\n`; a lone `\r` is shown as `^M`.
/// * `\t` becomes four spaces.
/// * Other C0 controls become caret notation (`^[`, `^?`, ...).
/// * C1 controls and bidi overrides become `\u{...}` escapes.
pub fn sanitize_for_display(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '\n' => output.push('\n'),
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                    output.push('\n');
                } else {
                    output.push_str("^M");
                }
            }
            '\t' => output.push_str("    "),
            ch if ch.is_ascii_control() => {
                if ch == '\u{7f}' {
                    output.push_str("^?");
                } else {
                    let caret = (ch as u8 + 0x40) as char;
                    output.push('^');
                    output.push(caret);
                }
            }
            ch if is_unsafe_control(ch) => {
                output.push_str(&format!("\\u{{{:04x}}}", ch as u32));
            }
            ch => output.push(ch),
        }
    }

    output
}

/// Converts up to `limit` bytes of a body to display text, flagging truncation
/// and invalid UTF-8. Truncation respects UTF-8 character boundaries.
pub fn display_bytes(bytes: &[u8], limit: usize) -> DisplayBytes {
    let truncated = bytes.len() > limit;
    let mut end = limit.min(bytes.len());
    while end > 0 && (bytes[end - 1] & 0xC0) == 0x80 {
        end -= 1;
    }
    let slice = &bytes[..end];
    let lossy = std::str::from_utf8(slice).is_err();
    let text = String::from_utf8_lossy(slice);

    DisplayBytes {
        text: sanitize_for_display(&text),
        truncated,
        lossy,
    }
}

fn is_unsafe_control(ch: char) -> bool {
    matches!(
        ch,
        '\u{0080}'..='\u{009f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}'
            | '\u{200e}'..='\u{200f}'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_sequences_are_rendered_as_text() {
        let output = sanitize_for_display("safe\u{1b}[2Junsafe");
        assert_eq!(output, "safe^[[2Junsafe");
        assert!(!output.contains('\u{1b}'));
    }

    #[test]
    fn newlines_survive_and_tabs_expand() {
        assert_eq!(sanitize_for_display("a\nb"), "a\nb");
        assert_eq!(sanitize_for_display("a\r\nb"), "a\nb");
        assert_eq!(sanitize_for_display("a\tb"), "a    b");
        assert_eq!(sanitize_for_display("a\rb"), "a^Mb");
        assert_eq!(sanitize_for_display("\0\u{7f}"), "^@^?");
    }

    #[test]
    fn bidi_overrides_are_escaped() {
        let output = sanitize_for_display("invoice\u{202e}fdp.exe");
        assert_eq!(output, "invoice\\u{202e}fdp.exe");
    }

    #[test]
    fn c1_controls_are_escaped() {
        assert_eq!(sanitize_for_display("\u{009b}31m"), "\\u{009b}31m");
    }

    #[test]
    fn body_truncation_is_reported_and_safe() {
        let display = display_bytes(b"0123456789", 4);
        assert_eq!(display.text, "0123");
        assert!(display.truncated);
        assert!(!display.lossy);

        let display = display_bytes(b"short", 100);
        assert_eq!(display.text, "short");
        assert!(!display.truncated);
    }

    #[test]
    fn invalid_utf8_is_marked_lossy() {
        let display = display_bytes(&[0xff, 0xfe, b'o', b'k'], 64);
        assert!(display.lossy);
        assert!(display.text.contains("ok"));
    }

    #[test]
    fn limit_zero_never_panics() {
        let display = display_bytes(b"body", 0);
        assert_eq!(display.text, "");
        assert!(display.truncated);
    }
}
