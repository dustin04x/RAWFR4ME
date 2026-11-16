//! Ordered, duplicate-preserving HTTP header collections.
//!
//! Header order is preserved because byte-level fidelity matters to a proxy and
//! to a security tester comparing captures. Lookup and redaction are
//! case-insensitive as required by RFC 9110.

use serde::{Deserialize, Serialize};

use crate::security::sanitize_for_display;

/// Headers whose values must never be rendered verbatim in the UI or logs by
/// default. Names are compared case-insensitively.
pub const SENSITIVE_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
];

/// A header name/value pair. Values may contain sensitive material; redaction
/// is a presentation concern and never mutates captured data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    pub name: String,
    pub value: String,
}

impl Header {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}

/// An ordered header list that keeps duplicate fields (for example multiple
/// `Set-Cookie` fields) instead of collapsing them into a map.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Headers {
    entries: Vec<Header>,
}

impl Headers {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_pairs<I, K, V>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        let mut headers = Self::new();
        for (name, value) in pairs {
            headers.append(name, value);
        }
        headers
    }

    /// Appends a field, preserving any existing fields with the same name.
    pub fn append(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.entries.push(Header::new(name, value));
    }

    /// Replaces all existing fields with the given name.
    pub fn insert(&mut self, name: impl Into<String>, value: impl Into<String>) {
        let name = name.into();
        self.remove_all(&name);
        self.entries.push(Header::new(name, value));
    }

    pub fn remove_all(&mut self, name: &str) {
        self.entries
            .retain(|header| !eq_ignore_ascii_case(&header.name, name));
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|header| eq_ignore_ascii_case(&header.name, name))
            .map(|header| header.value.as_str())
    }

    pub fn get_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.entries
            .iter()
            .filter(move |header| eq_ignore_ascii_case(&header.name, name))
            .map(|header| header.value.as_str())
    }

    pub fn contains(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Header> {
        self.entries.iter()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn is_sensitive(name: &str) -> bool {
        SENSITIVE_HEADERS
            .iter()
            .any(|sensitive| eq_ignore_ascii_case(sensitive, name))
    }

    /// Returns a copy with sensitive values replaced. The returned count is the
    /// number of fields that were masked so the UI can surface it.
    pub fn redacted(&self) -> (Self, usize) {
        let mut redacted = Self::new();
        let mut count = 0;
        for header in &self.entries {
            if Self::is_sensitive(&header.name) {
                redacted.append(header.name.clone(), "<redacted>");
                count += 1;
            } else {
                redacted.entries.push(header.clone());
            }
        }
        (redacted, count)
    }

    /// Wire-oriented lines. Values are not sanitized; callers must use
    /// [`Headers::display_lines`] before writing to a terminal.
    pub fn lines(&self, redact: bool) -> Vec<String> {
        let (redacted, _) = if redact {
            self.redacted()
        } else {
            (self.clone(), 0)
        };
        redacted
            .entries
            .iter()
            .map(|header| format!("{}: {}", header.name, header.value))
            .collect()
    }

    /// Terminal-safe lines. Control characters and bidi overrides in captured
    /// values are escaped so they cannot manipulate the terminal or the reader.
    pub fn display_lines(&self, redact: bool) -> Vec<String> {
        self.lines(redact)
            .into_iter()
            .map(|line| sanitize_for_display(&line))
            .collect()
    }
}

fn eq_ignore_ascii_case(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_is_case_insensitive_and_preserves_order() {
        let headers = Headers::from_pairs([
            ("Host", "api.rawframe.test"),
            ("X-Trace", "one"),
            ("x-trace", "two"),
            ("content-type", "application/json"),
        ]);

        assert_eq!(headers.get("HOST"), Some("api.rawframe.test"));
        assert_eq!(
            headers.get_all("X-TRACE").collect::<Vec<_>>(),
            ["one", "two"]
        );
        assert_eq!(headers.len(), 4);
        assert_eq!(headers.iter().next().unwrap().name, "Host");
    }

    #[test]
    fn insert_replaces_all_duplicates() {
        let mut headers =
            Headers::from_pairs([("Accept", "text/html"), ("accept", "application/json")]);
        headers.insert("Accept", "text/plain");

        assert_eq!(
            headers.get_all("accept").collect::<Vec<_>>(),
            ["text/plain"]
        );
    }

    #[test]
    fn sensitive_headers_are_redacted_without_dropping_them() {
        let headers = Headers::from_pairs([
            ("Authorization", "Bearer super-secret"),
            ("Cookie", "session=abc"),
            ("Host", "api.rawframe.test"),
            ("X-Api-Key", "key-123"),
        ]);

        let (redacted, count) = headers.redacted();
        assert_eq!(count, 3);
        assert_eq!(redacted.get("authorization"), Some("<redacted>"));
        assert_eq!(redacted.get("cookie"), Some("<redacted>"));
        assert_eq!(redacted.get("x-api-key"), Some("<redacted>"));
        assert_eq!(redacted.get("host"), Some("api.rawframe.test"));
        assert_eq!(headers.get("authorization"), Some("Bearer super-secret"));
    }

    #[test]
    fn display_lines_neutralize_control_sequences() {
        let headers = Headers::from_pairs([("X-Note", "ok\u{1b}[31mred\u{1b}[0m")]);
        let lines = headers.display_lines(false);

        assert_eq!(lines.len(), 1);
        assert!(!lines[0].contains('\u{1b}'));
        assert!(lines[0].contains("^["));
    }

    #[test]
    fn missing_headers_return_none() {
        let headers = Headers::new();
        assert!(headers.is_empty());
        assert_eq!(headers.get("host"), None);
        assert!(!headers.contains("host"));
    }
}
