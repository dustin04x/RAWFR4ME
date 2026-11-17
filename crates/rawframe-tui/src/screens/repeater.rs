//! Repeater workspace: independent request tabs, real execution, response
//! inspection, and execution comparison.

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use rawframe_core::models::StatusClass;
use rawframe_core::repeater::RepeaterExecutionPhase;
use rawframe_core::security::{display_bytes, sanitize_for_display};

use crate::app::App;
use crate::components::editor::render_editor;
use crate::components::{
    ButtonSpec, button_row, empty_state, focused_panel, format_bytes, truncate,
};
use crate::interaction::{ActionId, HitTarget, RenderOutput, ScrollRegion};
use crate::screens::render_heading;
use crate::state::{RepeaterTab, RepeaterView};
use crate::theme::Theme;

const MAX_BODY_DISPLAY: usize = 128 * 1024;
const MAX_HEX_DISPLAY: usize = 32 * 1024;

pub fn render(frame: &mut Frame, area: Rect, app: &App, theme: &Theme, output: &mut RenderOutput) {
    let engine_label = if app.repeater_engine_available() {
        "ENGINE READY"
    } else {
        "ENGINE OFFLINE"
    };
    render_heading(
        frame,
        Rect::new(area.x, area.y, area.width, 1),
        theme,
        "Repeater",
        "execute · inspect · compare",
        Some(engine_label),
        if app.repeater_engine_available() {
            theme.success()
        } else {
            theme.warning()
        },
    );

    if area.height < 8 {
        return;
    }

    let mut y = area.y + 1;
    render_tabs(
        frame,
        Rect::new(area.x, y, area.width, 1),
        app,
        theme,
        output,
    );
    y += 1;

    let Some(tab) = app.active_repeater_tab() else {
        empty_state(
            frame,
            Rect::new(area.x, y, area.width, area.bottom().saturating_sub(y)),
            theme,
            "No Repeater tab",
            &["Use ^N to create a request document."],
            None,
        );
        return;
    };

    let mut buttons = vec![
        ButtonSpec::new(
            "Send",
            ActionId::SendRepeater,
            !tab.is_busy() && app.repeater_engine_available(),
        )
        .primary()
        .key("^↵"),
        ButtonSpec::new("Cancel", ActionId::CancelRepeater, tab.is_busy()).key("C"),
        ButtonSpec::new("New", ActionId::NewRepeaterTab, true).key("^N"),
        ButtonSpec::new("Dup", ActionId::DuplicateRepeaterTab, true),
        ButtonSpec::new("Close", ActionId::CloseRepeaterTab, true).key("^W"),
    ];
    if area.width >= 100 {
        buttons.push(
            ButtonSpec::new(
                "Req→Dec",
                ActionId::SendRepeaterRequestToDecoder,
                !tab.execution_request().body.is_empty(),
            )
            .key("B"),
        );
        buttons.push(
            ButtonSpec::new(
                "Resp→Dec",
                ActionId::SendRepeaterResponseToDecoder,
                tab.response
                    .as_ref()
                    .and_then(|result| result.response.as_ref())
                    .is_some(),
            )
            .key("M"),
        );
    }
    let used = button_row(
        frame,
        Rect::new(area.x, y, area.width, 1),
        &buttons,
        theme,
        app.hover.as_ref(),
        output,
    );
    let redirect_width = area.width.saturating_sub(used + 2);
    if redirect_width >= 16 {
        let (label, style) = if tab.follow_redirects {
            ("REDIRECTS ON", theme.warning())
        } else {
            ("REDIRECTS OFF", theme.faint())
        };
        let rect = Rect::new(area.x + used + 2, y, redirect_width, 1);
        frame.render_widget(
            Paragraph::new(Span::styled(label, style.add_modifier(Modifier::BOLD)))
                .alignment(ratatui::layout::Alignment::Right),
            rect,
        );
        output.hit(rect, HitTarget::Action(ActionId::ToggleRepeaterRedirects));
    }
    y += 1;

    render_meta(frame, Rect::new(area.x, y, area.width, 1), app, tab, theme);
    y += 1;
    let body = Rect::new(area.x, y, area.width, area.bottom().saturating_sub(y));
    if body.height == 0 {
        return;
    }

    // Repeater owns both panes. Side-by-side when there is room, stacked
    // vertically below 84 columns so the editor and response stay usable.
    if area.width >= 84 {
        let split = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(58), Constraint::Percentage(42)])
            .split(body);
        render_editor_panel(frame, split[0], app, tab, theme, output);
        render_response_panel(frame, split[1], app, theme, output);
    } else {
        let split = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
            .split(body);
        render_editor_panel(frame, split[0], app, tab, theme, output);
        render_response_panel(frame, split[1], app, theme, output);
    }
}

fn render_editor_panel(
    frame: &mut Frame,
    area: Rect,
    app: &App,
    tab: &RepeaterTab,
    theme: &Theme,
    output: &mut RenderOutput,
) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let origin = match tab.origin {
        crate::state::RepeaterOrigin::Blank => "AUTHORED DRAFT",
        crate::state::RepeaterOrigin::Captured(_) => "FROM CAPTURED REQUEST",
        crate::state::RepeaterOrigin::Simulated(_) => "SIMULATED ORIGINAL",
    };
    let dirty = if tab.dirty { " · EDITED" } else { "" };
    let title = format!("REQUEST · {origin}{dirty}");
    let block = focused_panel(theme, &title, app.repeater.editing);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.width > 0 && inner.height > 0 {
        render_editor(
            frame,
            inner,
            theme,
            &tab.editor,
            app.repeater.editing,
            output,
        );
    }
}

fn render_tabs(frame: &mut Frame, area: Rect, app: &App, theme: &Theme, output: &mut RenderOutput) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let new_rect = Rect::new(area.right().saturating_sub(5), area.y, 3, 1);
    let max_tab_x = new_rect.x.saturating_sub(1);
    let tabs = &app.repeater.tabs;
    let labels: Vec<String> = tabs
        .iter()
        .map(|tab| {
            let state = if tab.is_busy() {
                format!(" {}", tab.execution.label())
            } else {
                String::new()
            };
            truncate(
                &format!("{} {}{state}", tab.origin.label(), tab.title()),
                if area.width < 80 { 18 } else { 26 },
            )
        })
        .collect();
    let widths: Vec<u16> = labels
        .iter()
        .map(|label| label.chars().count() as u16 + 2)
        .collect();

    let mut start = 0;
    while start < app.repeater.active {
        let needed: u16 = widths[start..=app.repeater.active]
            .iter()
            .copied()
            .sum::<u16>()
            + (app.repeater.active - start) as u16;
        if needed <= max_tab_x.saturating_sub(area.x) {
            break;
        }
        start += 1;
    }

    let mut x = area.x;
    for index in start..tabs.len() {
        let width = widths[index];
        if x + width > max_tab_x {
            break;
        }
        let active = index == app.repeater.active;
        let style = if active {
            theme.selected_accent().add_modifier(Modifier::UNDERLINED)
        } else {
            Style::new()
                .fg(theme.palette.muted)
                .bg(theme.palette.surface)
        };
        let rect = Rect::new(x, area.y, width, 1);
        frame.render_widget(
            Paragraph::new(Span::styled(format!(" {} ", labels[index]), style))
                .style(Style::new().bg(theme.palette.surface)),
            rect,
        );
        output.hit(rect, HitTarget::RepeaterTab(index));
        x += width + 1;
    }

    frame.render_widget(
        Paragraph::new(Span::styled(
            " + ",
            Style::new()
                .fg(theme.palette.accent)
                .bg(theme.palette.surface_elevated),
        ))
        .style(Style::new().bg(theme.palette.surface)),
        new_rect,
    );
    output.hit(new_rect, HitTarget::Action(ActionId::NewRepeaterTab));
}

fn render_meta(frame: &mut Frame, area: Rect, app: &App, tab: &RepeaterTab, theme: &Theme) {
    let state_style = match tab.execution {
        RepeaterExecutionPhase::Completed => theme.success(),
        RepeaterExecutionPhase::Failed | RepeaterExecutionPhase::Blocked => theme.danger(),
        RepeaterExecutionPhase::Cancelled | RepeaterExecutionPhase::TimedOut => theme.warning(),
        RepeaterExecutionPhase::Draft => theme.faint(),
        _ => theme.accent(),
    };
    let mut spans = vec![
        Span::styled(
            tab.execution.label(),
            state_style.add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(
            truncate(&tab.url(), area.width.saturating_sub(34) as usize),
            theme.muted(),
        ),
    ];
    if let Some(result) = &tab.response {
        if let Some(status) = result.status() {
            spans.push(Span::raw("  "));
            spans.push(Span::styled(
                format!("{status}"),
                theme.status_class(StatusClass::from_code(status)),
            ));
        }
        spans.push(Span::styled(
            format!("  {} ms", result.timings.total_ms),
            theme.faint(),
        ));
    }
    if tab.follow_redirects {
        spans.push(Span::styled("  FOLLOW", theme.warning()));
    }
    let retention = if app.config.storage.persist_bodies {
        "BODY PERSISTED"
    } else {
        "BODY NOT PERSISTED"
    };
    if area.width >= 96 {
        spans.push(Span::styled(format!("  {retention}"), theme.faint()));
    }
    frame.render_widget(
        Paragraph::new(Line::from(spans)).style(Style::new().bg(theme.palette.bg)),
        area,
    );
}

/// Right-hand response inspector. Draws only measured execution state and real
/// response bytes; a failure or scope block never renders as a successful
/// response.
pub fn render_response_panel(
    frame: &mut Frame,
    area: Rect,
    app: &App,
    theme: &Theme,
    output: &mut RenderOutput,
) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let focused = app.focus == crate::interaction::Focus::Context;
    let block = focused_panel(theme, "RESPONSE", focused);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.width == 0 || inner.height == 0 {
        return;
    }

    let close = Rect::new(inner.right().saturating_sub(3), inner.y, 3, 1);
    frame.render_widget(Paragraph::new(Span::styled("×", theme.muted())), close);
    output.hit(close, HitTarget::InspectorClose);

    let Some(tab) = app.active_repeater_tab() else {
        return;
    };

    // View strip is always visible, even while connecting.
    let mut view_x = inner.x;
    if inner.height > 1 {
        for view in RepeaterView::ALL {
            let width =
                (view.label().chars().count() as u16 + 2).min(inner.right().saturating_sub(view_x));
            if width == 0 {
                break;
            }
            let active = app.repeater.view == view;
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
            output.hit(rect, HitTarget::RepeaterView(view));
            view_x += width;
        }
    }

    let mut lines = Vec::new();
    lines.extend(execution_lines(app, tab, theme, inner.width as usize));
    if inner.height > 5 {
        lines.push(Line::from(""));
    }

    let content_y = inner.y + 3;
    if content_y >= inner.bottom() {
        return;
    }
    let content = Rect::new(
        inner.x,
        content_y,
        inner.width,
        inner.bottom().saturating_sub(content_y),
    );
    output.zone(content, ScrollRegion::Inspector);

    if let Some(error) = &tab
        .response
        .as_ref()
        .and_then(|result| result.error.as_ref())
    {
        lines.push(Line::from(Span::styled(
            format!("Error: {error}"),
            theme.danger(),
        )));
    } else if tab.execution == RepeaterExecutionPhase::Failed {
        lines.push(Line::from(Span::styled(
            "Execution failed before a response was available.",
            theme.danger(),
        )));
    }

    match app.repeater.view {
        RepeaterView::Compare => {
            lines.extend(comparison_lines(tab, theme));
        }
        view => {
            if let Some(result) = &tab.response {
                if let Some(response) = &result.response {
                    match view {
                        RepeaterView::Raw => {
                            let text = response
                                .to_display_text(app.config.appearance.redact_sensitive_headers);
                            lines.extend(text.lines().map(|line| {
                                Line::from(Span::styled(line.to_string(), theme.text()))
                            }));
                        }
                        RepeaterView::Headers => {
                            lines.extend(header_lines(
                                response,
                                app.config.appearance.redact_sensitive_headers,
                                theme,
                            ));
                        }
                        RepeaterView::Body => {
                            lines.extend(body_lines(&response.body, result.truncated, theme));
                        }
                        RepeaterView::Json => {
                            lines.extend(json_lines(&response.body, theme));
                        }
                        RepeaterView::Hex => {
                            lines.extend(hex_lines(&response.body, theme));
                        }
                        RepeaterView::Compare => {}
                    }
                } else if app.repeater.view == RepeaterView::Compare {
                    lines.extend(comparison_lines(tab, theme));
                }
            } else {
                lines.extend(waiting_lines(tab, theme));
            }
        }
    }

    frame.render_widget(
        Paragraph::new(lines)
            .scroll((app.repeater.response_scroll, 0))
            .style(Style::new().bg(theme.palette.surface)),
        inner,
    );
}

fn execution_lines(
    app: &App,
    tab: &RepeaterTab,
    theme: &Theme,
    width: usize,
) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    if let Some(result) = &tab.response {
        if let Some(response) = &result.response {
            let status_style = theme.status_class(StatusClass::from_code(response.status));
            lines.push(Line::from(vec![
                Span::styled(
                    truncate(&response.status_line(), width),
                    status_style.add_modifier(Modifier::BOLD),
                ),
                Span::raw("  "),
                Span::styled(format_bytes(result.response_bytes), theme.faint()),
            ]));
            lines.push(Line::from(vec![Span::styled(
                format!(
                    "dns {} · connect {} · tls {} · ttfb {} · total {} ms",
                    ms(result.timings.dns_ms),
                    ms(result.timings.connect_ms),
                    ms(result.timings.tls_ms),
                    ms(result.timings.ttfb_ms),
                    result.timings.total_ms
                ),
                theme.faint(),
            )]));
        } else {
            lines.push(Line::from(Span::styled(
                format!("{} · no response", tab.execution.label()),
                if tab.execution == RepeaterExecutionPhase::Blocked {
                    theme.warning()
                } else {
                    theme.danger()
                },
            )));
        }
        if !result.redirects.is_empty() {
            lines.push(Line::from(Span::styled(
                format!(
                    "{} redirect(s) followed · last {} → {}",
                    result.redirects.len(),
                    result.redirects.last().map(|hop| hop.status).unwrap_or(0),
                    truncate(
                        result
                            .redirects
                            .last()
                            .map(|hop| hop.to.as_str())
                            .unwrap_or(""),
                        width.saturating_sub(30)
                    )
                ),
                theme.faint(),
            )));
        }
        if result.truncated {
            lines.push(Line::from(Span::styled(
                "RESPONSE TRUNCATED AT CONFIGURED LIMIT",
                theme.warning(),
            )));
        }
        for warning in &result.warnings {
            lines.push(Line::from(Span::styled(
                format!("Warning: {warning}"),
                theme.warning(),
            )));
        }
    } else {
        lines.push(Line::from(Span::styled(waiting_title(tab), theme.faint())));
    }
    if width >= 54 {
        let retention = if app.config.storage.persist_bodies {
            "BODY PERSISTED"
        } else {
            "BODY NOT PERSISTED"
        };
        let sensitive = if app.config.appearance.redact_sensitive_headers {
            "HEADERS REDACTED"
        } else {
            "SENSITIVE HEADERS VISIBLE"
        };
        lines.push(Line::from(Span::styled(
            format!("{retention} · {sensitive}"),
            if app.config.storage.persist_bodies && !app.config.appearance.redact_sensitive_headers
            {
                theme.warning()
            } else {
                theme.faint()
            },
        )));
    }
    lines
}

fn waiting_title(tab: &RepeaterTab) -> String {
    match tab.execution {
        RepeaterExecutionPhase::Draft => "Draft not sent. Press Send or Ctrl+Enter.".into(),
        RepeaterExecutionPhase::Validating => "Validating request and destination…".into(),
        RepeaterExecutionPhase::Connecting => {
            "Resolving and connecting to validated address…".into()
        }
        RepeaterExecutionPhase::Sending => "Sending request…".into(),
        RepeaterExecutionPhase::Receiving => "Receiving response…".into(),
        RepeaterExecutionPhase::Cancelled => "Execution cancelled; no response.".into(),
        RepeaterExecutionPhase::TimedOut => "Execution timed out; no response.".into(),
        RepeaterExecutionPhase::Blocked => "Blocked by scope or destination policy.".into(),
        RepeaterExecutionPhase::Failed => "Execution failed; no response.".into(),
        RepeaterExecutionPhase::Completed => "Completed without a response.".into(),
    }
}

fn waiting_lines(tab: &RepeaterTab, theme: &Theme) -> Vec<Line<'static>> {
    vec![
        Line::from(Span::styled(waiting_title(tab), theme.muted())),
        Line::from(Span::styled(
            "RAWFRAME never fabricates a response.",
            theme.faint(),
        )),
    ]
}

fn header_lines(
    response: &rawframe_core::models::HttpResponse,
    redact: bool,
    theme: &Theme,
) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    for header in response.headers.iter() {
        let sensitive = redact && rawframe_core::models::Headers::is_sensitive(&header.name);
        lines.push(Line::from(vec![
            Span::styled(
                format!("{}: ", sanitize_for_display(&header.name)),
                theme.accent().add_modifier(Modifier::DIM),
            ),
            Span::styled(
                if sensitive {
                    "<redacted>".to_string()
                } else {
                    sanitize_for_display(&header.value)
                },
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
            "(no response headers)",
            theme.faint(),
        )));
    }
    lines
}

fn body_lines(body: &[u8], truncated: bool, theme: &Theme) -> Vec<Line<'static>> {
    if body.is_empty() {
        return vec![Line::from(Span::styled(
            "(empty response body)",
            theme.faint(),
        ))];
    }
    let display = display_bytes(body, MAX_BODY_DISPLAY);
    let mut lines = Vec::new();
    if display.truncated || truncated || display.lossy {
        let mut badges = Vec::new();
        if truncated {
            badges.push(Span::styled("TRUNCATED AT LIMIT ", theme.warning()));
        }
        if display.truncated {
            badges.push(Span::styled("DISPLAY TRUNCATED ", theme.warning()));
        }
        if display.lossy {
            badges.push(Span::styled("INVALID UTF-8 — use Hex", theme.danger()));
        }
        lines.push(Line::from(badges));
    }
    lines.extend(
        display
            .text
            .lines()
            .map(|line| Line::from(Span::styled(line.to_string(), theme.text()))),
    );
    lines
}

fn json_lines(body: &[u8], theme: &Theme) -> Vec<Line<'static>> {
    if body.is_empty() {
        return vec![Line::from(Span::styled("(empty body)", theme.faint()))];
    }
    match serde_json::from_slice::<serde_json::Value>(body) {
        Ok(value) => match serde_json::to_string_pretty(&value) {
            Ok(pretty) => pretty
                .lines()
                .map(|line| Line::from(Span::styled(line.to_string(), theme.text())))
                .collect(),
            Err(_) => vec![Line::from(Span::styled(
                "JSON parsed but could not be rendered.",
                theme.danger(),
            ))],
        },
        Err(error) => vec![
            Line::from(Span::styled(
                "Response body is not valid JSON.",
                theme.warning(),
            )),
            Line::from(Span::styled(
                format!("Parser: {error}. Use Raw or Hex to inspect the exact bytes."),
                theme.faint(),
            )),
        ],
    }
}

fn hex_lines(body: &[u8], theme: &Theme) -> Vec<Line<'static>> {
    if body.is_empty() {
        return vec![Line::from(Span::styled("(empty body)", theme.faint()))];
    }
    let shown = body.len().min(MAX_HEX_DISPLAY);
    let mut lines = Vec::new();
    if body.len() > shown {
        lines.push(Line::from(Span::styled(
            format!(
                "Showing first {} of {} bytes",
                format_bytes(shown),
                format_bytes(body.len())
            ),
            theme.warning(),
        )));
    }
    for (row, chunk) in body[..shown].chunks(16).enumerate() {
        let mut hex = String::new();
        let mut ascii = String::new();
        for index in 0..16 {
            if let Some(byte) = chunk.get(index) {
                hex.push_str(&format!("{byte:02x} "));
                ascii.push(if (0x20..=0x7e).contains(byte) {
                    *byte as char
                } else {
                    '.'
                });
            } else {
                hex.push_str("   ");
                ascii.push(' ');
            }
            if index == 7 {
                hex.push(' ');
            }
        }
        lines.push(Line::from(vec![
            Span::styled(format!("{:08x}  ", row * 16), theme.faint()),
            Span::styled(hex, theme.text()),
            Span::raw(" "),
            Span::styled(ascii, theme.muted()),
        ]));
    }
    lines
}

fn comparison_lines(tab: &RepeaterTab, theme: &Theme) -> Vec<Line<'static>> {
    let Some(comparison) = tab.comparison() else {
        return vec![
            Line::from(Span::styled("COMPARE NEEDS TWO EXECUTIONS", theme.title())),
            Line::from(Span::styled(
                "Send this request twice; the two most recent real responses are compared.",
                theme.muted(),
            )),
            Line::from(Span::styled(
                "Compared fields: status, headers, body, size, and duration.",
                theme.faint(),
            )),
        ];
    };
    let mut lines = vec![Line::from(Span::styled(
        "LAST TWO EXECUTIONS",
        theme.title(),
    ))];
    match comparison.status_changed {
        Some((before, after)) => lines.push(Line::from(vec![
            Span::styled("Status  ", theme.label()),
            Span::styled(
                format!("{before} → {after}"),
                theme.warning().add_modifier(Modifier::BOLD),
            ),
        ])),
        None => lines.push(Line::from(vec![
            Span::styled("Status  ", theme.label()),
            Span::styled("unchanged", theme.faint()),
        ])),
    }
    lines.push(Line::from(vec![
        Span::styled("Duration  ", theme.label()),
        Span::styled(
            format!("{:+} ms", comparison.duration_delta_ms),
            if comparison.duration_delta_ms == 0 {
                theme.faint()
            } else {
                theme.text()
            },
        ),
    ]));
    lines.push(Line::from(vec![
        Span::styled("Size  ", theme.label()),
        Span::styled(
            format!("{:+} bytes", comparison.size_delta),
            if comparison.size_delta == 0 {
                theme.faint()
            } else {
                theme.text()
            },
        ),
    ]));
    if comparison.header_changes.is_empty() {
        lines.push(Line::from(Span::styled(
            "Headers  unchanged",
            theme.faint(),
        )));
    } else {
        lines.push(Line::from(Span::styled(
            format!(
                "Headers  {} field(s) changed",
                comparison.header_changes.len()
            ),
            theme.text(),
        )));
        for change in comparison.header_changes.iter().take(12) {
            lines.push(Line::from(vec![
                Span::styled(format!("  {}  ", change.name), theme.accent()),
                Span::styled(
                    format!(
                        "{} → {}",
                        if change.previous.is_empty() {
                            "(absent)".to_string()
                        } else {
                            truncate(&change.previous.join(", "), 28)
                        },
                        if change.current.is_empty() {
                            "(absent)".to_string()
                        } else {
                            truncate(&change.current.join(", "), 28)
                        }
                    ),
                    theme.muted(),
                ),
            ]));
        }
    }
    if let Some(index) = comparison.first_body_difference {
        lines.push(Line::from(Span::styled(
            format!("Body  changed at byte {index}"),
            theme.warning(),
        )));
    } else {
        lines.push(Line::from(Span::styled("Body  unchanged", theme.faint())));
    }
    lines
}

fn ms(value: Option<u64>) -> String {
    value.map_or_else(|| "—".to_string(), |value| format!("{value}"))
}

#[cfg(test)]
mod tests {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use rawframe_core::models::message::{HttpRequest, HttpResponse, Scheme};
    use rawframe_core::repeater::{RepeaterResult, RepeaterTimings};

    use super::*;
    use crate::app::App;
    use crate::state::RepeaterOrigin;

    fn text_of(terminal: &Terminal<TestBackend>) -> String {
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

    fn result(status: u16, body: &[u8], duration: u64) -> RepeaterResult {
        let mut response = HttpResponse::with_body(status, "application/json", body);
        response.headers.append("X-Trace", "one");
        RepeaterResult {
            request: HttpRequest::new(
                "POST",
                Scheme::Https,
                "api.rawframe.test",
                443,
                "/v1/orders",
            ),
            response: Some(response),
            timings: RepeaterTimings {
                dns_ms: Some(2),
                connect_ms: Some(3),
                tls_ms: Some(4),
                ttfb_ms: Some(6),
                total_ms: duration,
                ..RepeaterTimings::default()
            },
            redirects: Vec::new(),
            truncated: false,
            response_bytes: body.len(),
            error: None,
            warnings: Vec::new(),
            sent_at: chrono::Utc::now(),
        }
    }

    fn app_with_result(status: u16, body: &[u8]) -> App {
        let mut app = App::demo();
        app.navigate(crate::interaction::NavSection::Repeater);
        let result = result(status, body, 12);
        let tab = app.repeater.active_tab_mut().unwrap();
        tab.response = Some(result);
        tab.execution = RepeaterExecutionPhase::Completed;
        app
    }

    #[test]
    fn full_shell_keeps_editor_and_response_usable_at_supported_sizes() {
        for (width, height) in [(140, 40), (100, 30), (80, 24)] {
            let app = app_with_result(200, b"{\"ok\":true}");
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            terminal
                .draw(|frame| {
                    crate::ui::render(frame, &app);
                })
                .unwrap();
            let text = text_of(&terminal);
            assert!(text.contains("REQUEST"), "{width}x{height}: editor missing");
            assert!(
                text.contains("RESPONSE") || text.contains("200 OK"),
                "{width}x{height}: response missing\n{text}"
            );
            assert!(text.contains("Send"), "{width}x{height}: send missing");
        }
    }

    #[test]
    fn repeater_renders_tabs_editor_and_execution_controls() {
        let app = App::demo();
        let theme = app.theme();
        let mut terminal = Terminal::new(TestBackend::new(110, 32)).unwrap();
        let mut output = RenderOutput::default();

        terminal
            .draw(|frame| {
                render(frame, Rect::new(0, 0, 110, 32), &app, &theme, &mut output);
            })
            .unwrap();

        let text = text_of(&terminal);
        assert!(text.contains("REPEATER"));
        assert!(text.contains("REQUEST"));
        assert!(text.contains("ENGINE OFFLINE"));
        assert!(text.contains("Send"));
        assert!(
            output
                .hits
                .iter()
                .any(|hit| hit.target == HitTarget::RepeaterEditor)
        );
    }

    #[test]
    fn response_panel_shows_real_status_timing_and_body_views() {
        let mut app = app_with_result(201, b"{\"ok\":true}");
        let theme = app.theme();
        let mut terminal = Terminal::new(TestBackend::new(70, 34)).unwrap();
        let mut output = RenderOutput::default();

        terminal
            .draw(|frame| {
                render_response_panel(frame, Rect::new(0, 0, 70, 34), &app, &theme, &mut output);
            })
            .unwrap();
        let text = text_of(&terminal);
        assert!(text.contains("201 Created"), "{text}");
        assert!(text.contains("total 12 ms"));
        assert!(text.contains("BODY NOT PERSISTED"));

        app.repeater.view = RepeaterView::Json;
        terminal
            .draw(|frame| {
                render_response_panel(frame, Rect::new(0, 0, 70, 34), &app, &theme, &mut output);
            })
            .unwrap();
        let text = text_of(&terminal);
        assert!(text.contains("\"ok\": true"), "{text}");
    }

    #[test]
    fn failure_and_blocked_states_never_render_a_successful_response() {
        let mut app = App::demo();
        app.navigate(crate::interaction::NavSection::Repeater);
        let tab = app.repeater.active_tab_mut().unwrap();
        tab.execution = RepeaterExecutionPhase::Blocked;
        tab.response = Some(RepeaterResult {
            request: HttpRequest::new("GET", Scheme::Http, "blocked.test", 80, "/"),
            response: None,
            timings: RepeaterTimings::default(),
            redirects: Vec::new(),
            truncated: false,
            response_bytes: 0,
            error: Some("destination blocked.test:80 is outside the configured scope".into()),
            warnings: Vec::new(),
            sent_at: chrono::Utc::now(),
        });
        let theme = app.theme();
        let mut terminal = Terminal::new(TestBackend::new(70, 30)).unwrap();
        let mut output = RenderOutput::default();
        terminal
            .draw(|frame| {
                render_response_panel(frame, Rect::new(0, 0, 70, 30), &app, &theme, &mut output);
            })
            .unwrap();
        let text = text_of(&terminal);
        assert!(text.contains("BLOCKED"));
        assert!(text.contains("outside the configured scope"));
        assert!(!text.contains("200 OK"));
    }

    #[test]
    fn small_repeater_layout_includes_editor_and_response() {
        let app = App::demo();
        let theme = app.theme();
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        let mut output = RenderOutput::default();
        terminal
            .draw(|frame| {
                render(frame, Rect::new(0, 0, 80, 24), &app, &theme, &mut output);
            })
            .unwrap();
        let text = text_of(&terminal);
        assert!(text.contains("REQUEST"));
        assert!(text.contains("RESPONSE"));
        assert!(text.contains("Draft not sent"));
    }

    #[test]
    fn compare_view_reports_actual_differences() {
        let mut app = App::demo();
        app.navigate(crate::interaction::NavSection::Repeater);
        let first = result(200, b"before", 10);
        let second = result(201, b"after", 20);
        let tab = app.repeater.active_tab_mut().unwrap();
        tab.executions = vec![first, second.clone()];
        tab.response = Some(second);
        app.repeater.view = RepeaterView::Compare;
        let theme = app.theme();
        let mut terminal = Terminal::new(TestBackend::new(70, 30)).unwrap();
        let mut output = RenderOutput::default();
        terminal
            .draw(|frame| {
                render_response_panel(frame, Rect::new(0, 0, 70, 30), &app, &theme, &mut output);
            })
            .unwrap();
        let text = text_of(&terminal);
        assert!(text.contains("200 → 201"), "{text}");
        assert!(text.contains("Body  changed at byte 0"), "{text}");
    }

    #[test]
    fn repeater_tabs_keep_independent_responses() {
        let mut app = App::demo();
        app.navigate(crate::interaction::NavSection::Repeater);
        let first = app.repeater.active_tab().unwrap().document.id;
        let tab = app.repeater.active_tab_mut().unwrap();
        tab.response = Some(result(200, b"first", 5));
        tab.execution = RepeaterExecutionPhase::Completed;
        app.repeater.duplicate_active();
        let second = app.repeater.active_tab().unwrap().document.id;
        assert_ne!(first, second);
        assert!(app.repeater.active_tab().unwrap().response.is_none());
        app.repeater.select(0);
        assert_eq!(
            app.repeater
                .active_tab()
                .unwrap()
                .response
                .as_ref()
                .unwrap()
                .status(),
            Some(200)
        );
        let _ = RepeaterOrigin::Captured(rawframe_core::models::traffic::TrafficId(1));
    }
}
