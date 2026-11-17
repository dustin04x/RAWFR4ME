//! Command palette catalogue and fuzzy matching.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandId {
    GoProxy,
    GoHistory,
    GoRepeater,
    GoIntruder,
    GoDecoder,
    GoSettings,
    ToggleProxy,
    ToggleInterception,
    ToggleRedaction,
    ToggleInspector,
    CycleAccent,
    ForwardRequest,
    DropRequest,
    ReplayRequest,
    EditRequest,
    NewRepeaterTab,
    CloseRepeaterTab,
    DuplicateRepeaterTab,
    SendRepeaterRequest,
    CancelRepeaterRequest,
    ResetRepeaterEdits,
    ClearRepeaterResponse,
    ToggleRepeaterRedirects,
    DecoderExecute,
    DecoderAddStep,
    DecoderCopy,
    DecoderHistory,
    DecoderSendToRepeater,
    SearchHistory,
    ClearHistoryFilters,
    ToggleMouse,
    ShowHelp,
    OpenStoredSessions,
    ExportStoredSession,
    Quit,
}

#[derive(Debug, Clone, Copy)]
pub struct CommandSpec {
    pub id: CommandId,
    pub title: &'static str,
    pub group: &'static str,
    pub shortcut: Option<&'static str>,
    pub keywords: &'static str,
}

pub const COMMANDS: &[CommandSpec] = &[
    CommandSpec {
        id: CommandId::GoProxy,
        title: "Go to Proxy",
        group: "Navigate",
        shortcut: Some("^1"),
        keywords: "intercept traffic in flight",
    },
    CommandSpec {
        id: CommandId::GoHistory,
        title: "Go to HTTP History",
        group: "Navigate",
        shortcut: Some("^2"),
        keywords: "captured requests search table",
    },
    CommandSpec {
        id: CommandId::GoRepeater,
        title: "Go to Repeater",
        group: "Navigate",
        shortcut: Some("^3"),
        keywords: "edit resend request",
    },
    CommandSpec {
        id: CommandId::GoIntruder,
        title: "Go to Intruder",
        group: "Navigate",
        shortcut: Some("^5"),
        keywords: "planned module placeholder",
    },
    CommandSpec {
        id: CommandId::GoDecoder,
        title: "Go to Decoder",
        group: "Navigate",
        shortcut: Some("^6"),
        keywords: "transform encode decode pipeline base64 hex url gzip hash jwt json",
    },
    CommandSpec {
        id: CommandId::DecoderExecute,
        title: "Run Decoder pipeline",
        group: "Decoder",
        shortcut: Some("^↵"),
        keywords: "transform encode decode execute",
    },
    CommandSpec {
        id: CommandId::DecoderAddStep,
        title: "Add Decoder transformation",
        group: "Decoder",
        shortcut: Some("A"),
        keywords: "pipeline step append transform",
    },
    CommandSpec {
        id: CommandId::DecoderCopy,
        title: "Copy Decoder output",
        group: "Decoder",
        shortcut: Some("Y"),
        keywords: "clipboard copy result",
    },
    CommandSpec {
        id: CommandId::DecoderHistory,
        title: "Show Decoder history",
        group: "Decoder",
        shortcut: Some("H"),
        keywords: "session runs history",
    },
    CommandSpec {
        id: CommandId::DecoderSendToRepeater,
        title: "Send Decoder output to Repeater body",
        group: "Decoder",
        shortcut: None,
        keywords: "repeater insert body transfer",
    },
    CommandSpec {
        id: CommandId::GoSettings,
        title: "Go to Settings",
        group: "Navigate",
        shortcut: Some("^4"),
        keywords: "configuration preferences",
    },
    CommandSpec {
        id: CommandId::ToggleProxy,
        title: "Start or stop the proxy engine",
        group: "Proxy",
        shortcut: Some("P"),
        keywords: "listen stop start network capture forward connect listener",
    },
    CommandSpec {
        id: CommandId::ToggleInterception,
        title: "Toggle interception",
        group: "Proxy",
        shortcut: Some("Space"),
        keywords: "pause arm rules capture",
    },
    CommandSpec {
        id: CommandId::ToggleInspector,
        title: "Toggle inspector panel",
        group: "Layout",
        shortcut: Some("I"),
        keywords: "context panel details",
    },
    CommandSpec {
        id: CommandId::ToggleRedaction,
        title: "Toggle sensitive-header redaction",
        group: "Privacy",
        shortcut: None,
        keywords: "authorization cookie secret mask",
    },
    CommandSpec {
        id: CommandId::CycleAccent,
        title: "Cycle accent color",
        group: "Appearance",
        shortcut: None,
        keywords: "theme violet indigo teal",
    },
    CommandSpec {
        id: CommandId::ForwardRequest,
        title: "Forward selected request",
        group: "Proxy",
        shortcut: Some("F"),
        keywords: "release pause continue",
    },
    CommandSpec {
        id: CommandId::DropRequest,
        title: "Drop selected request",
        group: "Proxy",
        shortcut: Some("D"),
        keywords: "discard cancel intercept",
    },
    CommandSpec {
        id: CommandId::ReplayRequest,
        title: "Replay selected request",
        group: "Repeater",
        shortcut: Some("R"),
        keywords: "open copy send",
    },
    CommandSpec {
        id: CommandId::EditRequest,
        title: "Edit selected request",
        group: "Repeater",
        shortcut: Some("E"),
        keywords: "open modify request",
    },
    CommandSpec {
        id: CommandId::NewRepeaterTab,
        title: "New Repeater tab",
        group: "Repeater",
        shortcut: Some("^N"),
        keywords: "add create blank",
    },
    CommandSpec {
        id: CommandId::CloseRepeaterTab,
        title: "Close Repeater tab",
        group: "Repeater",
        shortcut: Some("^W"),
        keywords: "remove tab",
    },
    CommandSpec {
        id: CommandId::DuplicateRepeaterTab,
        title: "Duplicate Repeater tab",
        group: "Repeater",
        shortcut: Some("D"),
        keywords: "copy clone independent request",
    },
    CommandSpec {
        id: CommandId::SendRepeaterRequest,
        title: "Send Repeater request",
        group: "Repeater",
        shortcut: Some("^Enter"),
        keywords: "transmit dispatch execute http https",
    },
    CommandSpec {
        id: CommandId::CancelRepeaterRequest,
        title: "Cancel Repeater execution",
        group: "Repeater",
        shortcut: Some("C"),
        keywords: "abort stop in flight",
    },
    CommandSpec {
        id: CommandId::ResetRepeaterEdits,
        title: "Reset Repeater edits to original",
        group: "Repeater",
        shortcut: Some("R"),
        keywords: "revert captured draft",
    },
    CommandSpec {
        id: CommandId::ClearRepeaterResponse,
        title: "Clear Repeater response",
        group: "Repeater",
        shortcut: Some("X"),
        keywords: "remove inspector result",
    },
    CommandSpec {
        id: CommandId::ToggleRepeaterRedirects,
        title: "Toggle Repeater redirect following",
        group: "Repeater",
        shortcut: Some("F"),
        keywords: "302 scope strip credentials redirects",
    },
    CommandSpec {
        id: CommandId::SearchHistory,
        title: "Search HTTP history",
        group: "History",
        shortcut: Some("^F"),
        keywords: "filter find",
    },
    CommandSpec {
        id: CommandId::ClearHistoryFilters,
        title: "Clear traffic filters",
        group: "History",
        shortcut: None,
        keywords: "history reset search method status host",
    },
    CommandSpec {
        id: CommandId::ToggleMouse,
        title: "Toggle mouse support",
        group: "Interface",
        shortcut: None,
        keywords: "pointer click drag",
    },
    CommandSpec {
        id: CommandId::ShowHelp,
        title: "Show keyboard help",
        group: "Help",
        shortcut: Some("?"),
        keywords: "shortcuts keys documentation",
    },
    CommandSpec {
        id: CommandId::OpenStoredSessions,
        title: "Browse stored sessions",
        group: "Storage",
        shortcut: Some("B"),
        keywords: "history database restore saved project session sqlite",
    },
    CommandSpec {
        id: CommandId::ExportStoredSession,
        title: "Export current session to JSONL",
        group: "Storage",
        shortcut: None,
        keywords: "download redacted save database jsonl",
    },
    CommandSpec {
        id: CommandId::Quit,
        title: "Quit RAWFRAME",
        group: "Application",
        shortcut: Some("Q"),
        keywords: "exit close",
    },
];

/// Filters and ranks commands for the palette. Every query token must match as
/// a subsequence of the command text; contiguous and word-initial matches rank
/// higher. With an empty query, the catalogue order is preserved.
pub fn filter_commands(query: &str) -> Vec<&'static CommandSpec> {
    let query = query.trim().to_ascii_lowercase();
    if query.is_empty() {
        return COMMANDS.iter().collect();
    }

    let tokens: Vec<&str> = query.split_whitespace().collect();
    let mut scored: Vec<(i32, &'static CommandSpec)> = COMMANDS
        .iter()
        .filter_map(|command| {
            let haystack = format!(
                "{} {} {} {}",
                command.title,
                command.group,
                command.keywords,
                command.shortcut.unwrap_or_default()
            )
            .to_ascii_lowercase();

            let mut total = 0;
            for token in &tokens {
                total += subsequence_score(token, &haystack)?;
            }
            let title_lower = command.title.to_ascii_lowercase();
            if title_lower.starts_with(&query) {
                total += 80;
            }
            for token in &tokens {
                if title_lower
                    .split(|ch: char| !ch.is_alphanumeric())
                    .any(|word| word.starts_with(token))
                {
                    total += 40;
                }
            }
            Some((total, command))
        })
        .collect();

    scored.sort_by(|(left_score, left), (right_score, right)| {
        right_score
            .cmp(left_score)
            .then_with(|| left.title.cmp(right.title))
    });
    scored.into_iter().map(|(_, command)| command).collect()
}

fn subsequence_score(needle: &str, haystack: &str) -> Option<i32> {
    if needle.is_empty() {
        return Some(0);
    }

    let mut matched = 0;
    let mut score = 0;
    let mut previous_match: Option<usize> = None;
    let mut previous_char = ' ';
    let needle_chars: Vec<char> = needle.chars().collect();

    for (index, ch) in haystack.chars().enumerate() {
        if matched >= needle_chars.len() {
            break;
        }
        if ch == needle_chars[matched] {
            score += 4;
            if previous_match == Some(index.saturating_sub(1)) {
                score += 8;
            }
            if index == 0 || matches!(previous_char, ' ' | '-' | '_' | '^') {
                score += 6;
            }
            previous_match = Some(index);
            matched += 1;
        }
        previous_char = ch;
    }

    if matched == needle_chars.len() {
        Some(score - (haystack.chars().count() as i32 / 8))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_query_lists_every_command() {
        assert_eq!(filter_commands("").len(), COMMANDS.len());
        assert_eq!(filter_commands("   ").len(), COMMANDS.len());
    }

    #[test]
    fn prefixes_rank_the_intended_navigation_first() {
        let results = filter_commands("hist");
        assert_eq!(results[0].id, CommandId::GoHistory);

        let results = filter_commands("rep");
        assert!(matches!(
            results[0].id,
            CommandId::GoRepeater
                | CommandId::NewRepeaterTab
                | CommandId::CloseRepeaterTab
                | CommandId::DuplicateRepeaterTab
                | CommandId::SendRepeaterRequest
                | CommandId::ReplayRequest
        ));
    }

    #[test]
    fn keywords_match_commands() {
        let results = filter_commands("redact");
        assert_eq!(results[0].id, CommandId::ToggleRedaction);

        let results = filter_commands("violet");
        assert_eq!(results[0].id, CommandId::CycleAccent);
    }

    #[test]
    fn multiple_tokens_are_all_required() {
        let results = filter_commands("toggle inspector");
        assert!(!results.is_empty());
        assert_eq!(results[0].id, CommandId::ToggleInspector);

        assert!(filter_commands("inspector zzz").is_empty());
    }

    #[test]
    fn unmatched_queries_return_nothing() {
        assert!(filter_commands("qqqqzzz").is_empty());
    }

    #[test]
    fn shortcuts_are_searchable() {
        let results = filter_commands("^enter");
        assert_eq!(results[0].id, CommandId::SendRepeaterRequest);
    }
}
