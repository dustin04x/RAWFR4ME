//! Shared request lifecycle terminology.
//!
//! Traffic tables, the interception editor and the inspector all describe the
//! same lifecycle, so the wording and colours live in one place. In particular,
//! a request rejected by scope/security policy is *blocked*, never "dropped".

use ratatui::style::{Modifier, Style};
use rawframe_core::models::traffic::{TrafficEntry, TrafficKind, TrafficState};

use crate::theme::Theme;

/// True when the entry failed because scope or another policy refused it,
/// rather than because forwarding/transport failed.
///
/// The proxy records a scope rejection as a failed entry whose error (and note)
/// names the configured scope, together with a locally generated error
/// response. That response must not be presented as an upstream response.
pub fn is_scope_or_policy_block(entry: &TrafficEntry) -> bool {
    if entry.state != TrafficState::Failed {
        return false;
    }
    let error = entry.error.as_deref().unwrap_or("").to_ascii_lowercase();
    let note = entry.note.as_deref().unwrap_or("").to_ascii_lowercase();
    error.contains("outside the configured scope")
        || error.contains("scope")
        || note.contains("scope")
        || (error.contains("denied")
            && entry
                .response
                .as_ref()
                .is_some_and(|response| response.status == 403))
}

/// Whether a real upstream response exists that can be inspected.
pub fn has_upstream_response(entry: &TrafficEntry) -> bool {
    entry.response.is_some() && !is_scope_or_policy_block(entry)
}

/// Full lifecycle description for the active interception editor / inspector.
pub fn label(entry: &TrafficEntry) -> String {
    if entry.kind == TrafficKind::ConnectTunnel {
        return entry
            .tunnel
            .as_ref()
            .map(|tunnel| format!("Tunnel {}", tunnel.outcome.label().to_ascii_lowercase()))
            .unwrap_or_else(|| "Tunnel".to_string());
    }
    match entry.state {
        TrafficState::Paused => "Paused — awaiting decision".to_string(),
        TrafficState::Modified => "Paused — modified, awaiting decision".to_string(),
        TrafficState::Forwarded => {
            if entry.interception.modified {
                "Modified — forwarded".to_string()
            } else if entry.interception.intercepted {
                "Forwarded — unchanged".to_string()
            } else {
                "Forwarded".to_string()
            }
        }
        TrafficState::Completed => {
            if entry.interception.modified {
                "Modified — forwarded".to_string()
            } else if entry.interception.intercepted {
                "Forwarded — unchanged".to_string()
            } else if let Some(response) = &entry.response {
                format!("Response {}", response.status)
            } else {
                "Completed".to_string()
            }
        }
        TrafficState::Dropped => "Dropped — by user".to_string(),
        TrafficState::TimedOut => "Timed out".to_string(),
        TrafficState::Cancelled => "Cancelled".to_string(),
        TrafficState::Failed => {
            if is_scope_or_policy_block(entry) {
                "Blocked — scope/policy".to_string()
            } else {
                "Failed — transport/processing".to_string()
            }
        }
        TrafficState::Captured => "Captured".to_string(),
    }
}

/// Compact lifecycle label for dense traffic tables.
pub fn short_label(entry: &TrafficEntry) -> String {
    if entry.kind == TrafficKind::ConnectTunnel {
        return entry
            .tunnel
            .as_ref()
            .map(|tunnel| format!("TUNNEL {}", tunnel.outcome.label()))
            .unwrap_or_else(|| "TUNNEL".to_string());
    }
    match entry.state {
        TrafficState::Paused => "PAUSED".to_string(),
        TrafficState::Modified => "PAUSED (MOD)".to_string(),
        TrafficState::Forwarded | TrafficState::Completed => {
            if entry.interception.modified {
                "FWD (MODIFIED)".to_string()
            } else if entry.interception.intercepted {
                "FWD (UNCHANGED)".to_string()
            } else if let Some(response) = &entry.response {
                response.status.to_string()
            } else {
                "FORWARDED".to_string()
            }
        }
        TrafficState::Dropped => "DROPPED (USER)".to_string(),
        TrafficState::TimedOut => "TIMED OUT".to_string(),
        TrafficState::Cancelled => "CANCELLED".to_string(),
        TrafficState::Failed => {
            if is_scope_or_policy_block(entry) {
                "BLOCKED (SCOPE)".to_string()
            } else {
                "FAILED".to_string()
            }
        }
        TrafficState::Captured => "CAPTURED".to_string(),
    }
}

pub fn style(theme: &Theme, entry: &TrafficEntry) -> Style {
    if entry.kind == TrafficKind::ConnectTunnel {
        return theme.accent();
    }
    match entry.state {
        TrafficState::Paused | TrafficState::Modified => {
            theme.warning().add_modifier(Modifier::BOLD)
        }
        TrafficState::Dropped | TrafficState::TimedOut | TrafficState::Cancelled => {
            theme.danger().add_modifier(Modifier::BOLD)
        }
        TrafficState::Failed => {
            if is_scope_or_policy_block(entry) {
                theme.warning().add_modifier(Modifier::BOLD)
            } else {
                theme.danger().add_modifier(Modifier::BOLD)
            }
        }
        TrafficState::Forwarded | TrafficState::Completed => theme.success(),
        TrafficState::Captured => theme.muted(),
    }
}

#[cfg(test)]
mod tests {
    use rawframe_core::fixtures;
    use rawframe_core::models::HttpRequest;
    use rawframe_core::models::message::Scheme;
    use rawframe_core::models::traffic::{TrafficEntry, TrafficId};

    use super::*;

    fn entry(method: &str) -> TrafficEntry {
        TrafficEntry::new(
            TrafficId(7),
            HttpRequest::new(method, Scheme::Http, "example.test", 80, "/admin"),
        )
    }

    #[test]
    fn scope_rejection_is_blocked_not_dropped() {
        let mut blocked = entry("GET");
        blocked
            .fail("destination example.test:80 is outside the configured scope")
            .unwrap();
        assert!(is_scope_or_policy_block(&blocked));
        assert_eq!(short_label(&blocked), "BLOCKED (SCOPE)");
        assert_eq!(label(&blocked), "Blocked — scope/policy");
        assert!(!short_label(&blocked).contains("DROPPED"));
    }

    #[test]
    fn failures_and_drops_keep_distinct_terminology() {
        let mut failed = entry("GET");
        failed.fail("connection refused by upstream").unwrap();
        assert!(!is_scope_or_policy_block(&failed));
        assert_eq!(short_label(&failed), "FAILED");

        let mut dropped = entry("POST");
        dropped.drop_request().unwrap();
        assert!(!is_scope_or_policy_block(&dropped));
        assert_eq!(short_label(&dropped), "DROPPED (USER)");
        assert_eq!(label(&dropped), "Dropped — by user");
    }

    #[test]
    fn modified_forwarding_is_labelled_as_modified() {
        let mut entry = entry("PUT");
        entry.interception.intercepted = true;
        entry.interception.modified = true;
        entry.forward().unwrap();
        assert_eq!(short_label(&entry), "FWD (MODIFIED)");
        assert_eq!(label(&entry), "Modified — forwarded");
    }

    #[test]
    fn simulated_fixtures_report_consistent_labels() {
        for entry in fixtures::simulated_traffic() {
            assert!(!short_label(&entry).is_empty());
            assert!(!label(&entry).is_empty());
        }
    }
}
