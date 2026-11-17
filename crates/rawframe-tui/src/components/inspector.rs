//! Request/response inspector used by the Proxy and HTTP History screens.

use chrono::Utc;
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use rawframe_core::models::traffic::{TrafficEntry, TrafficKind, TrafficState};
use rawframe_core::models::{Headers, HttpRequest, HttpResponse};
use rawframe_core::security::{DisplayBytes, display_bytes, sanitize_for_display};

use crate::components::lifecycle;
use crate::components::{
    empty_state, focused_panel, format_age, format_bytes, raw_message, source_badge, status_style,
    truncate,
};
use crate::interaction::{HitTarget, InspectorView, MessageSide, RenderOutput, ScrollRegion};
use crate::state::InspectorState;
use crate::theme::Theme;

const MAX_BODY_DISPLAY: usize = 128 * 1024;

#[derive(Debug, Clone, Copy)]
pub struct InspectorContext<'a> {
    pub entry: Option<&'a TrafficEntry>,
    pub inspector: &'a InspectorState,
    pub redact: bool,
    pub focused: bool,
}

pub fn render_inspector(
    frame: &mut Frame,
    area: Rect,
    theme: &Theme,
    context: InspectorContext<'_>,
    output: &mut RenderOutput,
) {
    let InspectorContext {
        entry,
        inspector,
        redact,
        focused,
    } = context;
    let block = focused_panel(theme, "INSPECTOR", focused);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.width == 0 || inner.height == 0 {
        return;
    }

    if entry.is_none() {
        empty_state(
            frame,
            inner,
            theme,
            "No request selected",
            &[
                "Select a traffic or history entry to inspect protocol details.",
                "The main workspace stays focused on the queue and active interception work.",
            ],
            Some("Enter inspect  ·  I toggle inspector  ·  Ctrl+4 Settings"),
        );
        return;
    }
    let entry = entry.unwrap();

    let close_width = 3.min(inner.width);
    let close_rect = Rect::new(
        inner.right().saturating_sub(close_width),
        inner.y,
        close_width,
        1,
    );
    frame.render_widget(
        Paragraph::new(Span::styled(
            " × ",
            if focused {
                theme.accent()
            } else {
                theme.muted()
            },
        )),
        close_rect,
    );
    output.hit(close_rect, HitTarget::InspectorClose);

    render_tabs(frame, inner, entry, inspector, redact, theme, output);
    if inner.height < 5 {
        return;
    }

    render_meta(frame, inner, entry, theme);
    // Tabs occupy two rows, lifecycle metadata two more, then a separator.
    let content_y = inner.y + 5;
    if content_y >= inner.bottom() {
        return;
    }
    // subtle separator
    frame.render_widget(
        Paragraph::new(Span::styled(
            "─".repeat(inner.width as usize),
            theme.border(),
        )),
        Rect::new(inner.x, content_y - 1, inner.width, 1),
    );
    let content = Rect::new(
        inner.x,
        content_y,
        inner.width,
        inner.bottom().saturating_sub(content_y),
    );
    output.zone(content, ScrollRegion::Inspector);

    if entry.is_tunnel() && inspector.view == InspectorView::Body {
        render_tunnel_metadata(frame, content, theme, entry, inspector.scroll);
        return;
    }

    if entry.body_omitted && inspector.view == InspectorView::Body {
        empty_state(
            frame,
            content,
            theme,
            "Body not stored",
            &[
                "This restored entry was written while body persistence was OFF.",
                "The body was never placed in the database, so it cannot be shown.",
            ],
            Some("Enable Persist bodies in Settings to store bodies of new captures."),
        );
        return;
    }

    match inspector.side {
        MessageSide::Request => {
            render_request_inspection(frame, content, theme, entry, inspector, redact);
        }
        MessageSide::Response => {
            render_response_inspection(frame, content, theme, entry, inspector, redact);
        }
    }
}

fn render_tabs(
    frame: &mut Frame,
    inner: Rect,
    entry: &TrafficEntry,
    inspector: &InspectorState,
    redact: bool,
    theme: &Theme,
    output: &mut RenderOutput,
) {
    // Primary request/response tabs.
    let mut x = inner.x;
    for side in [MessageSide::Request, MessageSide::Response] {
        let unavailable = side == MessageSide::Response
            && !lifecycle::has_upstream_response(entry)
            && !lifecycle::is_scope_or_policy_block(entry);
        let width = (side.label().chars().count() as u16 + 3).min(inner.right().saturating_sub(x));
        if width == 0 {
            break;
        }
        let active = inspector.side == side;
        let style = if active {
            theme.selected_accent().add_modifier(Modifier::BOLD)
        } else if unavailable {
            theme.faint()
        } else {
            theme.muted()
        };
        let bg = if active {
            theme.palette.surface_elevated
        } else {
            theme.palette.surface
        };
        let rect = Rect::new(x, inner.y, width, 1);
        frame.render_widget(
            Paragraph::new(Span::styled(format!(" {} ", side.label()), style))
                .style(Style::new().bg(bg)),
            rect,
        );
        output.hit(rect, HitTarget::InspectorSide(side));
        x += width;
    }

    if inner.height > 1 {
        let mut view_x = inner.x;
        for view in InspectorView::ALL {
            let width =
                (view.label().chars().count() as u16 + 2).min(inner.right().saturating_sub(view_x));
            if width == 0 {
                break;
            }
            let active = inspector.view == view;
            let style = if active {
                theme
                    .accent()
                    .add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
            } else {
                theme.faint()
            };
            let rect = Rect::new(view_x, inner.y + 1, width, 1);
            frame.render_widget(
                Paragraph::new(Span::styled(format!(" {} ", view.label()), style)),
                rect,
            );
            output.hit(rect, HitTarget::InspectorView(view));
            view_x += width;
        }
        if view_x + 10 < inner.right() {
            let (label, style) = if redact {
                ("REDACTED", theme.faint())
            } else {
                ("VISIBLE", theme.warning())
            };
            frame.render_widget(
                Paragraph::new(Span::styled(label, style)),
                Rect::new(inner.right().saturating_sub(10), inner.y + 1, 10, 1),
            );
        }
    }
}

fn render_meta(frame: &mut Frame, inner: Rect, entry: &TrafficEntry, theme: &Theme) {
    let meta_y = inner.y + 2;
    if meta_y >= inner.bottom() {
        return;
    }
    let target = if entry.is_tunnel() {
        format!("{}:{}", entry.request.host, entry.request.port)
    } else {
        entry.request.url()
    };
    let line1 = Line::from(vec![
        Span::styled(format!("#{:04}  ", entry.id.0), theme.faint()),
        Span::styled(
            entry.request.method.clone(),
            theme
                .method(&entry.request.method)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(
            truncate(&target, inner.width.saturating_sub(24) as usize),
            theme.text(),
        ),
    ]);
    frame.render_widget(
        Paragraph::new(line1),
        Rect::new(inner.x, meta_y, inner.width, 1),
    );

    if meta_y + 1 >= inner.bottom() {
        return;
    }
    // Keep the lifecycle readable in a narrow inspector: the remaining
    // metadata only appears when it actually fits next to the lifecycle.
    let mut spans = vec![Span::styled(
        lifecycle::label(entry),
        lifecycle::style(theme, entry),
    )];
    if inner.width >= 34 {
        spans.push(Span::raw("  "));
        spans.push(source_badge(theme, entry.source));
    }
    if entry.body_omitted && inner.width >= 60 {
        spans.push(Span::raw("  "));
        spans.push(Span::styled("BODY NOT STORED", theme.warning()));
    }
    if inner.width >= 44 {
        spans.push(Span::raw("  "));
        spans.push(Span::styled(
            format_age(entry.timings.started_at, Utc::now()),
            theme.faint(),
        ));
        if let Some(duration) = entry.duration_ms() {
            spans.push(Span::styled(format!("  {duration} ms"), theme.faint()));
        }
    }
    frame.render_widget(
        Paragraph::new(Line::from(spans)),
        Rect::new(inner.x, meta_y + 1, inner.width, 1),
    );
}

fn render_request_inspection(
    frame: &mut Frame,
    area: Rect,
    theme: &Theme,
    entry: &TrafficEntry,
    inspector: &InspectorState,
    redact: bool,
) {
    let original = entry.original_request.as_ref();
    let final_req = entry.final_request.as_ref();
    let show_both = original.is_some() && final_req.is_some() && original != final_req;

    if !show_both {
        let request = final_req.or(original).unwrap_or(&entry.request);
        render_request_side(frame, area, theme, request, inspector, redact);
        return;
    }

    // Keep modified interception inspectable: show original and final clearly separated.
    if area.height < 6 {
        let request = final_req.unwrap_or(&entry.request);
        render_request_side(frame, area, theme, request, inspector, redact);
        return;
    }
    let (left, right) = if area.width >= 84 {
        let chunks = ratatui::layout::Layout::default()
            .direction(ratatui::layout::Direction::Horizontal)
            .constraints([
                ratatui::layout::Constraint::Percentage(50),
                ratatui::layout::Constraint::Percentage(50),
            ])
            .split(area);
        (chunks[0], chunks[1])
    } else {
        let top_h = (area.height / 2).max(3);
        let chunks = ratatui::layout::Layout::default()
            .direction(ratatui::layout::Direction::Vertical)
            .constraints([
                ratatui::layout::Constraint::Length(top_h),
                ratatui::layout::Constraint::Min(3),
            ])
            .split(area);
        (chunks[0], chunks[1])
    };

    render_labeled_request(
        frame,
        left,
        "ORIGINAL",
        original.unwrap(),
        theme,
        inspector,
        redact,
    );
    render_labeled_request(
        frame,
        right,
        "FINAL (SENT/EDITED)",
        final_req.unwrap(),
        theme,
        inspector,
        redact,
    );
}

fn render_labeled_request(
    frame: &mut Frame,
    rect: Rect,
    label: &str,
    req: &HttpRequest,
    theme: &Theme,
    inspector: &InspectorState,
    redact: bool,
) {
    if rect.height == 0 || rect.width == 0 {
        return;
    }
    frame.render_widget(
        Paragraph::new(Span::styled(label, theme.label())),
        Rect::new(rect.x, rect.y, rect.width, 1),
    );
    let inner = Rect::new(
        rect.x,
        rect.y + 1,
        rect.width,
        rect.height.saturating_sub(1),
    );
    if inner.height > 0 {
        render_request_side(frame, inner, theme, req, inspector, redact);
    }
}

fn render_response_inspection(
    frame: &mut Frame,
    area: Rect,
    theme: &Theme,
    entry: &TrafficEntry,
    inspector: &InspectorState,
    redact: bool,
) {
    // A scope/policy rejection is recorded as a failed entry with a locally
    // generated error response. Never present that as an upstream response.
    if lifecycle::is_scope_or_policy_block(entry) {
        let reason = entry
            .error
            .as_deref()
            .or(entry.note.as_deref())
            .map(sanitize_for_display)
            .unwrap_or_else(|| "blocked by policy".to_string());
        empty_state(
            frame,
            area,
            theme,
            "Blocked before upstream (scope/policy)",
            &[
                "The request was rejected by the configured scope or security policy.",
                &format!("Reason: {reason}"),
                "No upstream response exists because the request was not forwarded.",
            ],
            Some("Review scope in Settings (Ctrl+4). Security policy was not weakened."),
        );
        return;
    }

    if let Some(response) = &entry.response {
        render_response_side(frame, area, theme, response, inspector, redact);
        return;
    }

    let (title, mut lines, hint): (&str, Vec<String>, Option<String>) = match entry.state {
        TrafficState::Dropped => (
            "No response (dropped by user)",
            vec![
                "The request was explicitly dropped during interception.".to_string(),
                "No request was forwarded upstream and no response was received.".to_string(),
            ],
            Some("Use Forward/Edit to send a request upstream.".to_string()),
        ),
        TrafficState::TimedOut => (
            "No response (timed out)",
            vec![
                "The request or interception timed out before completion.".to_string(),
                "No fabricated upstream response is shown.".to_string(),
            ],
            None,
        ),
        TrafficState::Cancelled => (
            "No response (cancelled)",
            vec![
                "The request was cancelled before completion.".to_string(),
                "No fabricated upstream response is shown.".to_string(),
            ],
            None,
        ),
        TrafficState::Failed => (
            "No response (transport/processing failure)",
            vec![
                "The request failed before producing an upstream response.".to_string(),
                format!(
                    "Reason: {}",
                    entry
                        .error
                        .as_deref()
                        .map(sanitize_for_display)
                        .unwrap_or_else(|| "unknown failure".to_string())
                ),
            ],
            None,
        ),
        TrafficState::Paused | TrafficState::Modified => (
            "No response yet (awaiting decision)",
            vec![
                "The request is paused in interception.".to_string(),
                "A response is only possible after you forward it upstream.".to_string(),
            ],
            Some("Forward, Forward modified, or Drop from the Proxy workspace.".to_string()),
        ),
        TrafficState::Forwarded => (
            "No response yet (forwarded)",
            vec!["The request was forwarded upstream and is awaiting a response.".to_string()],
            None,
        ),
        _ => (
            "No response available",
            vec!["No upstream response was captured for this request.".to_string()],
            None,
        ),
    };

    if entry.kind == TrafficKind::ConnectTunnel {
        lines = vec![
            "Opaque CONNECT tunnel — no HTTP response body or headers are captured.".to_string(),
            "This CONNECT entry is an opaque tunnel; payload is relayed, not inspected."
                .to_string(),
        ];
    }

    let line_refs: Vec<&str> = lines.iter().map(|s| s.as_str()).collect();
    empty_state(frame, area, theme, title, &line_refs, hint.as_deref());
}

fn render_request_side(
    frame: &mut Frame,
    area: Rect,
    theme: &Theme,
    request: &HttpRequest,
    inspector: &InspectorState,
    redact: bool,
) {
    match inspector.view {
        InspectorView::Raw => raw_message(
            frame,
            area,
            theme,
            &request.to_display_text(redact),
            inspector.scroll,
            theme.method(&request.method).add_modifier(Modifier::BOLD),
        ),
        InspectorView::Headers => render_headers(
            frame,
            area,
            theme,
            &request.headers,
            inspector.scroll,
            redact,
        ),
        InspectorView::Body => render_body(frame, area, theme, &request.body, inspector.scroll),
    }
}

fn render_response_side(
    frame: &mut Frame,
    area: Rect,
    theme: &Theme,
    response: &HttpResponse,
    inspector: &InspectorState,
    redact: bool,
) {
    match inspector.view {
        InspectorView::Raw => raw_message(
            frame,
            area,
            theme,
            &response.to_display_text(redact),
            inspector.scroll,
            status_style(theme, Some(response.status_class())),
        ),
        InspectorView::Headers => render_headers(
            frame,
            area,
            theme,
            &response.headers,
            inspector.scroll,
            redact,
        ),
        InspectorView::Body => render_body(frame, area, theme, &response.body, inspector.scroll),
    }
}

fn render_tunnel_metadata(
    frame: &mut Frame,
    area: Rect,
    theme: &Theme,
    entry: &TrafficEntry,
    scroll: u16,
) {
    let metadata = entry.tunnel.clone().unwrap_or_default();
    let mut lines = vec![
        Line::from(Span::styled("OPAQUE CONNECT TUNNEL", theme.title())),
        Line::from(Span::styled(
            "Payload bytes are relayed, not captured for this opaque CONNECT entry.",
            theme.muted(),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("Outcome: ", theme.label()),
            Span::styled(metadata.outcome.label(), theme.text()),
        ]),
        Line::from(vec![
            Span::styled("Client → upstream: ", theme.label()),
            Span::styled(
                format_bytes(metadata.client_to_upstream_bytes as usize),
                theme.text(),
            ),
        ]),
        Line::from(vec![
            Span::styled("Upstream → client: ", theme.label()),
            Span::styled(
                format_bytes(metadata.upstream_to_client_bytes as usize),
                theme.text(),
            ),
        ]),
    ];
    if let Some(duration) = entry.duration_ms() {
        lines.push(Line::from(vec![
            Span::styled("Duration: ", theme.label()),
            Span::styled(format!("{duration} ms"), theme.text()),
        ]));
    }
    if let Some(note) = &entry.note {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            sanitize_for_display(note),
            theme.faint(),
        )));
    }
    if let Some(err) = &entry.error {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("Reason: {}", sanitize_for_display(err)),
            if lifecycle::is_scope_or_policy_block(entry) {
                theme.warning()
            } else {
                theme.danger()
            },
        )));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .scroll((scroll, 0))
            .style(Style::new().bg(theme.palette.surface)),
        area,
    );
}

fn render_headers(
    frame: &mut Frame,
    area: Rect,
    theme: &Theme,
    headers: &Headers,
    scroll: u16,
    redact: bool,
) {
    let mut lines: Vec<Line<'static>> = Vec::new();
    let (_, masked) = if redact {
        headers.redacted()
    } else {
        (headers.clone(), 0)
    };
    for header in headers.iter() {
        let sensitive = redact && Headers::is_sensitive(&header.name);
        let value = if sensitive {
            "<redacted>".to_string()
        } else {
            sanitize_for_display(&header.value)
        };
        lines.push(Line::from(vec![
            Span::styled(
                format!("{}: ", sanitize_for_display(&header.name)),
                theme.accent().add_modifier(Modifier::DIM),
            ),
            Span::styled(
                value,
                if sensitive {
                    theme.faint()
                } else {
                    theme.text()
                },
            ),
        ]));
    }
    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            "(no header fields)",
            theme.faint(),
        )));
    }
    if masked > 0 {
        lines.push(Line::from(Span::styled(
            format!("{masked} sensitive field(s) masked"),
            theme.faint(),
        )));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .scroll((scroll, 0))
            .style(Style::new().bg(theme.palette.surface)),
        area,
    );
}

fn render_body(frame: &mut Frame, area: Rect, theme: &Theme, body: &[u8], scroll: u16) {
    let DisplayBytes {
        text,
        truncated,
        lossy,
    } = display_bytes(body, MAX_BODY_DISPLAY);

    if body.is_empty() {
        empty_state(
            frame,
            area,
            theme,
            "Empty body",
            &["No message body was captured."],
            None,
        );
        return;
    }

    let mut lines: Vec<Line<'static>> = Vec::new();
    if truncated || lossy {
        let mut badges = Vec::new();
        if truncated {
            badges.push(Span::styled("TRUNCATED ", theme.warning()));
        }
        if lossy {
            badges.push(Span::styled("INVALID UTF-8", theme.danger()));
        }
        lines.push(Line::from(badges));
    }
    for raw_line in text.split('\n') {
        lines.push(Line::from(Span::styled(raw_line.to_string(), theme.text())));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .scroll((scroll, 0))
            .style(Style::new().bg(theme.palette.surface)),
        area,
    );
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use rawframe_core::fixtures;
    use rawframe_core::models::message::Scheme;
    use rawframe_core::models::traffic::{TrafficEntry, TrafficId, TunnelMetadata, TunnelOutcome};
    use rawframe_core::models::{HttpRequest, HttpResponse};

    use super::*;
    use crate::theme::Theme;

    #[test]
    fn inspector_masks_secrets_and_records_interaction_targets() {
        let entry = fixtures::simulated_traffic()
            .into_iter()
            .find(|entry| entry.id == TrafficId(14))
            .unwrap();
        let theme = Theme::from_preset(rawframe_core::AccentPreset::Violet);
        let inspector = InspectorState::default();
        let backend = TestBackend::new(70, 26);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut output = RenderOutput::default();

        terminal
            .draw(|frame| {
                render_inspector(
                    frame,
                    Rect::new(0, 0, 70, 26),
                    &theme,
                    InspectorContext {
                        entry: Some(&entry),
                        inspector: &inspector,
                        redact: true,
                        focused: true,
                    },
                    &mut output,
                );
            })
            .unwrap();

        let buffer = terminal.backend().buffer();
        let mut text = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                text.push_str(buffer[(x, y)].symbol());
            }
            text.push('\n');
        }

        assert!(text.contains("<redacted>"));
        assert!(!text.contains("fixture-operator-token"));
        assert!(text.contains("INSPECTOR"));
        assert!(!output.hits.is_empty());
        assert!(
            output
                .zones
                .iter()
                .any(|zone| zone.region == ScrollRegion::Inspector)
        );
    }

    #[test]
    fn tunnel_inspector_shows_metadata_not_a_fabricated_body() {
        let request = HttpRequest::new(
            "CONNECT",
            Scheme::Https,
            "tunnel.example.test",
            443,
            "tunnel.example.test:443",
        );
        let mut entry = TrafficEntry::tunnel(
            TrafficId(1001),
            request,
            TunnelMetadata {
                client_to_upstream_bytes: 1536,
                upstream_to_client_bytes: 2048,
                outcome: TunnelOutcome::Closed,
            },
            Utc::now(),
        );
        entry.note = Some("Both directions closed".into());

        let theme = Theme::from_preset(rawframe_core::AccentPreset::Violet);
        let inspector = InspectorState {
            side: MessageSide::Request,
            view: InspectorView::Body,
            scroll: 0,
        };
        let backend = TestBackend::new(80, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut output = RenderOutput::default();

        terminal
            .draw(|frame| {
                render_inspector(
                    frame,
                    Rect::new(0, 0, 80, 30),
                    &theme,
                    InspectorContext {
                        entry: Some(&entry),
                        inspector: &inspector,
                        redact: true,
                        focused: true,
                    },
                    &mut output,
                );
            })
            .unwrap();

        let buffer = terminal.backend().buffer();
        let mut text = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                text.push_str(buffer[(x, y)].symbol());
            }
            text.push('\n');
        }

        assert!(text.contains("OPAQUE CONNECT TUNNEL"), "{text}");
        assert!(text.contains("CLOSED"), "{text}");
        assert!(text.contains("Payload bytes are relayed"), "{text}");
        assert!(!text.contains("Empty body"), "{text}");
    }

    fn render_text(entry: Option<&TrafficEntry>, inspector: &InspectorState) -> String {
        let theme = Theme::from_preset(rawframe_core::AccentPreset::Violet);
        let mut terminal = Terminal::new(TestBackend::new(80, 28)).unwrap();
        let mut output = RenderOutput::default();
        terminal
            .draw(|frame| {
                render_inspector(
                    frame,
                    Rect::new(0, 0, 80, 28),
                    &theme,
                    InspectorContext {
                        entry,
                        inspector,
                        redact: true,
                        focused: true,
                    },
                    &mut output,
                );
            })
            .unwrap();
        let buffer = terminal.backend().buffer();
        let mut text = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                text.push_str(buffer[(x, y)].symbol());
            }
            text.push('\n');
        }
        text
    }

    #[test]
    fn empty_inspector_explains_its_responsibility() {
        let text = render_text(None, &InspectorState::default());
        assert!(text.contains("NO REQUEST SELECTED"), "{text}");
        assert!(text.contains("inspect protocol details") || text.contains("protocol details"));
    }

    #[test]
    fn scope_blocked_request_is_not_shown_as_a_response() {
        let mut entry = TrafficEntry::new(
            TrafficId(41),
            HttpRequest::new("GET", Scheme::Http, "blocked.example.test", 80, "/admin"),
        );
        entry
            .fail("destination blocked.example.test:80 is outside the configured scope")
            .unwrap();
        // The proxy attaches a locally generated error response; it must never
        // be inspected as if upstream had answered.
        entry.response = Some(HttpResponse::with_body(
            403,
            "text/plain",
            "locally-generated-policy-body",
        ));

        let inspector = InspectorState {
            side: MessageSide::Response,
            view: InspectorView::Raw,
            scroll: 0,
        };
        let text = render_text(Some(&entry), &inspector);
        assert!(text.contains("BLOCKED BEFORE UPSTREAM"), "{text}");
        assert!(text.contains("outside the configured"), "{text}");
        assert!(text.contains("blocked.example.test"), "{text}");
        assert!(!text.contains("locally-generated-policy-body"), "{text}");
        assert!(text.contains("Settings"), "{text}");
    }

    #[test]
    fn dropped_request_reports_no_fabricated_response() {
        let mut entry = TrafficEntry::new(
            TrafficId(42),
            HttpRequest::new("POST", Scheme::Http, "drop.example.test", 80, "/submit"),
        );
        entry.drop_request().unwrap();
        let inspector = InspectorState {
            side: MessageSide::Response,
            view: InspectorView::Raw,
            scroll: 0,
        };
        let text = render_text(Some(&entry), &inspector);
        assert!(text.contains("DROPPED BY USER"), "{text}");
        assert!(!text.contains("HTTP/1.1"), "{text}");
    }
}
