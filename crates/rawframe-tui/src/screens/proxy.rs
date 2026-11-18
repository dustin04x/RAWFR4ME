//! Proxy workspace: traffic queue, interception workflow, and contextual actions.

use chrono::Utc;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table};
use rawframe_core::models::Scheme;
use rawframe_core::models::traffic::{TrafficEntry, TrafficKind, TrafficState};

use crate::app::App;
use crate::components::editor::render_editor_with_target;
use crate::components::lifecycle;
use crate::components::{
    ButtonSpec, button_row, empty_state, focused_panel, format_age, protocol_tag, source_badge,
    truncate,
};
use crate::interaction::{ActionId, Focus, HitTarget, RenderOutput, ScrollRegion};
use crate::screens::window_start;
use crate::theme::Theme;

pub fn render(frame: &mut Frame, area: Rect, app: &App, theme: &Theme, output: &mut RenderOutput) {
    if area.height == 0 || area.width == 0 {
        return;
    }

    let pending = app.pending_interceptions();
    let body_area = area;

    if body_area.width < 30 || body_area.height < 5 {
        return;
    }

    match selected_pending_entry(app, &pending) {
        Some(entry) if body_area.height >= 12 => {
            // Prioritize active interception workflow: queue focus above, editor/decision below.
            let rows = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Percentage(46), Constraint::Percentage(54)])
                .split(body_area);
            render_traffic_area(frame, rows[0], app, theme, &pending, output);
            render_interception_workspace(frame, rows[1], app, theme, entry, output);
        }
        // Short terminals: the decision editor is the priority; the queue stays
        // reachable from the pending list once the terminal grows.
        Some(entry) => render_interception_workspace(frame, body_area, app, theme, entry, output),
        None => render_traffic_area(frame, body_area, app, theme, &pending, output),
    }
}

fn selected_pending_entry<'a>(
    app: &'a App,
    pending: &[&'a TrafficEntry],
) -> Option<&'a TrafficEntry> {
    if let Some(id) = app.interception.selected
        && let Some(entry) = pending.iter().copied().find(|e| e.id == id)
    {
        return Some(entry);
    }
    app.selected_traffic()
        .filter(|e| e.is_live_capture() && e.state.is_awaiting_decision())
}

fn render_traffic_area(
    frame: &mut Frame,
    area: Rect,
    app: &App,
    theme: &Theme,
    pending: &[&TrafficEntry],
    output: &mut RenderOutput,
) {
    if area.height == 0 || area.width == 0 {
        return;
    }

    let focused = app.focus == Focus::Content && !app.interception.editing;
    let show_pending_queue = !pending.is_empty();
    let title = if show_pending_queue {
        format!("PENDING INTERCEPTION QUEUE · {}", pending.len())
    } else if app.has_any_live_capture() {
        format!("TRAFFIC · {} live capture(s)", app.live_capture_count())
    } else {
        "TRAFFIC".to_string()
    };
    let decrypted_https = app.traffic().iter().any(|entry| {
        entry.is_live_capture()
            && entry.kind == TrafficKind::Http
            && entry.request.scheme == Scheme::Https
    });
    let title = if decrypted_https && app.tls_status.enabled {
        format!("{title} · TLS DECRYPTED")
    } else if decrypted_https {
        format!("{title} · DECRYPTED CAPTURE (TLS NOW OFF)")
    } else {
        title
    };
    let block = focused_panel(theme, &title, focused);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.height < 3 || inner.width < 20 {
        return;
    }

    let (actions_rect, list_rect) = (
        Rect::new(inner.x, inner.y, inner.width, 1),
        Rect::new(
            inner.x,
            inner.y + 1,
            inner.width,
            inner.height.saturating_sub(1),
        ),
    );
    render_contextual_actions(frame, actions_rect, app, theme, pending, output);
    if list_rect.height == 0 {
        return;
    }

    if show_pending_queue {
        render_pending_queue(frame, list_rect, app, theme, pending, output);
    } else {
        render_proxy_traffic_table(frame, list_rect, app, theme, output);
    }
}

fn render_contextual_actions(
    frame: &mut Frame,
    area: Rect,
    app: &App,
    theme: &Theme,
    pending: &[&TrafficEntry],
    output: &mut RenderOutput,
) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let selected_entry = app.selected_traffic();
    let selected_pending = app
        .interception
        .selected
        .and_then(|id| pending.iter().copied().find(|e| e.id == id))
        .or_else(|| {
            selected_entry.filter(|e| e.is_live_capture() && e.state.is_awaiting_decision())
        });
    let can_toggle_proxy = true;
    let can_toggle_interception = true;
    let can_inspect = selected_entry.is_some();
    let can_replay = selected_entry.is_some();
    let can_forward = selected_pending.is_some();
    let can_drop = selected_pending.is_some();
    let can_edit = selected_pending.is_some();

    let mut buttons: Vec<ButtonSpec<'_>> = Vec::new();
    buttons.push(
        ButtonSpec::new(
            if app.proxy_state.is_active() {
                "Stop proxy"
            } else {
                "Start proxy"
            },
            ActionId::ToggleProxy,
            can_toggle_proxy,
        )
        .key("P"),
    );
    buttons.push(
        ButtonSpec::new(
            if app.config.proxy.interception_enabled {
                "Interception on"
            } else {
                "Interception off"
            },
            ActionId::ToggleInterception,
            can_toggle_interception,
        )
        .key("I"),
    );

    if selected_pending.is_some() {
        if app.interception.dirty {
            let can_send_modified = app.interception.parse_error.is_none()
                && app.interception.validation_error.is_none();
            buttons.push(
                ButtonSpec::new(
                    "Send modified",
                    ActionId::ForwardModified,
                    can_send_modified,
                )
                .key("S")
                .primary(),
            );
            buttons
                .push(ButtonSpec::new("Forward original", ActionId::ForwardRequest, true).key("F"));
        } else {
            buttons.push(
                ButtonSpec::new("Forward", ActionId::ForwardRequest, can_forward)
                    .key("F")
                    .primary(),
            );
        }
        buttons.push(ButtonSpec::new("Edit", ActionId::EditRequest, can_edit).key("E"));
        buttons.push(
            ButtonSpec::new("Drop", ActionId::DropRequest, can_drop)
                .key("D")
                .danger(),
        );
    } else {
        buttons
            .push(ButtonSpec::new("Inspect", ActionId::InspectRequest, can_inspect).key("Enter"));
        buttons.push(ButtonSpec::new("Replay", ActionId::ReplayRequest, can_replay).key("R"));
    }
    button_row(frame, area, &buttons, theme, app.hover.as_ref(), output);
}

fn render_pending_queue(
    frame: &mut Frame,
    area: Rect,
    app: &App,
    theme: &Theme,
    pending: &[&TrafficEntry],
    output: &mut RenderOutput,
) {
    output.zone(area, ScrollRegion::InterceptionQueue);
    if pending.is_empty() {
        render_empty_for_state(frame, area, app, theme);
        return;
    }
    if area.height < 2 || area.width < 20 {
        return;
    }

    let selected_id = app
        .interception
        .selected
        .or(app.proxy_selected)
        .or_else(|| pending.first().map(|e| e.id));
    let selected_pos = pending
        .iter()
        .position(|e| Some(e.id) == selected_id)
        .unwrap_or(0);
    let body_h = area.height.saturating_sub(1) as usize;
    let start = window_start(selected_pos, pending.len(), body_h);
    let now = Utc::now();

    let show_path = area.width >= 58;
    let (widths, header_labels): (Vec<Constraint>, Vec<&str>) = if show_path {
        (
            vec![
                Constraint::Length(5),
                Constraint::Length(7),
                Constraint::Min(8),
                Constraint::Min(8),
                Constraint::Length(15),
                Constraint::Length(7),
                Constraint::Length(4),
            ],
            vec![
                "ID",
                "METHOD",
                "HOST",
                "PATH",
                "LIFECYCLE",
                "WAITING",
                "SRC",
            ],
        )
    } else {
        (
            vec![
                Constraint::Length(5),
                Constraint::Length(7),
                Constraint::Min(8),
                Constraint::Length(14),
                Constraint::Length(7),
                Constraint::Length(4),
            ],
            vec!["ID", "METHOD", "HOST", "LIFECYCLE", "WAIT", "SRC"],
        )
    };

    let header = Row::new(
        header_labels
            .into_iter()
            .map(|h| Cell::from(Span::styled(h, theme.label())))
            .collect::<Vec<_>>(),
    );

    let rows: Vec<Row<'_>> = pending
        .iter()
        .skip(start)
        .take(body_h)
        .map(|entry| {
            let selected = Some(entry.id) == selected_id;
            let marker = if selected { "▌" } else { " " };
            let waiting = format_age(entry.timings.started_at, now);
            let lifecycle = lifecycle::short_label(entry);
            let path = if entry.request.target.is_empty() {
                "/".to_string()
            } else {
                entry.request.target.clone()
            };
            let mut cells = vec![
                Cell::from(Line::from(vec![
                    Span::styled(
                        marker,
                        if selected {
                            theme.accent()
                        } else {
                            theme.faint()
                        },
                    ),
                    Span::styled(
                        format!("{:04}", entry.id.0),
                        if selected {
                            theme.accent_bold()
                        } else {
                            theme.faint()
                        },
                    ),
                ])),
                Cell::from(Span::styled(
                    entry.request.method.clone(),
                    theme
                        .method(&entry.request.method)
                        .add_modifier(Modifier::BOLD),
                )),
                Cell::from(Span::styled(entry.request.host.clone(), theme.text())),
            ];
            if show_path {
                cells.push(Cell::from(Span::styled(truncate(&path, 28), theme.muted())));
            }
            cells.push(Cell::from(Span::styled(
                truncate(&lifecycle, if show_path { 15 } else { 14 }),
                lifecycle::style(theme, entry),
            )));
            cells.push(Cell::from(Span::styled(waiting, theme.warning())));
            cells.push(Cell::from(source_badge(theme, entry.source)));
            row_style(Row::new(cells), selected, theme)
        })
        .collect();

    let table = Table::new(rows, widths).header(header).column_spacing(1);
    frame.render_widget(table, area);

    for (offset, entry) in pending.iter().enumerate().skip(start).take(body_h) {
        let row_rect = Rect::new(area.x, area.y + 1 + (offset - start) as u16, area.width, 1);
        output.hit(row_rect, HitTarget::InterceptionRow(entry.id));
        output.hit(row_rect, HitTarget::ProxyRow(entry.id));
    }
}

fn render_proxy_traffic_table(
    frame: &mut Frame,
    area: Rect,
    app: &App,
    theme: &Theme,
    output: &mut RenderOutput,
) {
    output.zone(area, ScrollRegion::ProxyList);
    let entries = app.proxy_entries();
    if entries.is_empty() {
        render_empty_for_state(frame, area, app, theme);
        return;
    }
    if area.height < 2 {
        return;
    }

    let selected_id = app.proxy_selected.or_else(|| app.selected_id());
    let selected_pos = entries
        .iter()
        .position(|e| Some(e.id) == selected_id)
        .unwrap_or(0);
    let body_h = area.height.saturating_sub(1) as usize;
    let start = window_start(selected_pos, entries.len(), body_h);
    let now = Utc::now();

    // Column priority: identity first, then destination, lifecycle and duration.
    // Widths are computed here so every cell can be truncated with an ellipsis
    // instead of being hard-clipped by the table widget.
    let show_path = area.width >= 58;
    let show_duration = area.width >= 58;
    let (widths, labels, host_width, path_width, status_width): (
        Vec<Constraint>,
        Vec<&str>,
        u16,
        u16,
        usize,
    ) = if area.width >= 70 {
        let flex = area.width.saturating_sub(48);
        let host = (flex * 56 / 100).max(10);
        let path = flex.saturating_sub(host).max(10);
        (
            vec![
                Constraint::Length(5),
                Constraint::Length(7),
                Constraint::Length(host),
                Constraint::Length(path),
                Constraint::Length(18),
                Constraint::Length(8),
                Constraint::Length(4),
            ],
            vec![
                "ID",
                "METHOD",
                "HOST",
                "PATH",
                "LIFECYCLE / STATUS",
                "DURATION",
                "SRC",
            ],
            host,
            path,
            18,
        )
    } else if show_path {
        let flex = area.width.saturating_sub(43);
        let host = (flex * 55 / 100).max(7);
        let path = flex.saturating_sub(host).max(7);
        (
            vec![
                Constraint::Length(5),
                Constraint::Length(7),
                Constraint::Length(host),
                Constraint::Length(path),
                Constraint::Length(15),
                Constraint::Length(6),
                Constraint::Length(4),
            ],
            vec!["ID", "METHOD", "HOST", "PATH", "STATUS", "DUR", "SRC"],
            host,
            path,
            15,
        )
    } else {
        let host = area.width.saturating_sub(33).max(8);
        (
            vec![
                Constraint::Length(5),
                Constraint::Length(7),
                Constraint::Length(host),
                Constraint::Length(13),
                Constraint::Length(4),
            ],
            vec!["ID", "METHOD", "HOST", "STATUS", "SRC"],
            host,
            0,
            13,
        )
    };

    let header = Row::new(
        labels
            .into_iter()
            .map(|h| Cell::from(Span::styled(h, theme.label())))
            .collect::<Vec<_>>(),
    );

    let rows: Vec<Row<'_>> = entries
        .iter()
        .skip(start)
        .take(body_h)
        .map(|entry| {
            let selected = Some(entry.id) == selected_id;
            let marker = if selected { "▌" } else { " " };
            let status = lifecycle::short_label(entry);
            let path = if entry.kind == TrafficKind::ConnectTunnel {
                "(CONNECT tunnel)".to_string()
            } else if entry.request.target.is_empty() {
                "/".to_string()
            } else {
                entry.request.target.clone()
            };
            // Protocol is part of the row at every width, so a narrow terminal
            // never loses the difference between HTTP/1.1 and HTTP/2. Without a
            // path column the tag lives beside the host instead.
            let host_cell = if show_path {
                entry.request.host.clone()
            } else {
                format!("{} {}", protocol_tag(entry), entry.request.host)
            };
            let path = if show_path {
                format!("{} {path}", protocol_tag(entry))
            } else {
                path
            };
            let duration = entry
                .duration_ms()
                .map(|ms| format!("{ms}ms"))
                .unwrap_or_else(|| format_age(entry.timings.started_at, now));
            let mut cells = vec![
                Cell::from(Line::from(vec![
                    Span::styled(
                        marker,
                        if selected {
                            theme.accent()
                        } else {
                            theme.faint()
                        },
                    ),
                    Span::styled(
                        format!("{:04}", entry.id.0),
                        if selected {
                            theme.accent_bold()
                        } else {
                            theme.faint()
                        },
                    ),
                ])),
                Cell::from(Span::styled(
                    entry.request.method.clone(),
                    theme
                        .method(&entry.request.method)
                        .add_modifier(Modifier::BOLD),
                )),
                Cell::from(Span::styled(
                    truncate(&host_cell, host_width as usize),
                    theme.text(),
                )),
            ];
            if show_path {
                cells.push(Cell::from(Span::styled(
                    truncate(&path, path_width as usize),
                    theme.muted(),
                )));
            }
            cells.push(Cell::from(Span::styled(
                truncate(&status, status_width),
                lifecycle::style(theme, entry),
            )));
            if show_duration {
                cells.push(Cell::from(Span::styled(duration, theme.faint())));
            }
            cells.push(Cell::from(source_badge(theme, entry.source)));
            row_style(Row::new(cells), selected, theme)
        })
        .collect();

    let table = Table::new(rows, widths).header(header).column_spacing(1);
    frame.render_widget(table, area);

    for (offset, entry) in entries.iter().skip(start).take(body_h).enumerate() {
        let row_rect = Rect::new(area.x, area.y + 1 + offset as u16, area.width, 1);
        output.hit(row_rect, HitTarget::ProxyRow(entry.id));
    }
}

fn row_style(row: Row<'static>, selected: bool, theme: &Theme) -> Row<'static> {
    row.style(Style::new().bg(if selected {
        theme.palette.selection
    } else {
        theme.palette.surface
    }))
}

fn render_empty_for_state(frame: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let fixtures = app
        .traffic
        .iter()
        .filter(|entry| entry.source == rawframe_core::models::traffic::TrafficSource::Simulated)
        .count();
    match app.proxy_state {
        rawframe_core::ProxyState::Stopped | rawframe_core::ProxyState::Failed => {
            let body = if fixtures > 0 {
                format!(
                    "The proxy engine is not running. {fixtures} simulated fixture(s) are listed in HTTP History, not live traffic."
                )
            } else {
                "The proxy engine is not running. No live traffic can be captured.".to_string()
            };
            empty_state(
                frame,
                area,
                theme,
                "Proxy stopped",
                &[
                    &body,
                    "Start the engine, then point a client at the listener.",
                ],
                Some("Press P to start the proxy  ·  Ctrl+4 reviews scope"),
            );
        }
        _ if app.config.proxy.interception_enabled => empty_state(
            frame,
            area,
            theme,
            "Interception enabled and waiting",
            &[
                "Matching HTTP requests will pause here before reaching the upstream server.",
                "Paused requests take over this workspace for a forward/edit/drop decision.",
            ],
            Some("Send traffic through the proxy  ·  I toggles interception"),
        ),
        _ => empty_state(
            frame,
            area,
            theme,
            "Listening with no traffic",
            &[
                "The proxy is active. Live requests and CONNECT tunnel metadata appear here.",
                "Simulated fixtures stay in HTTP History and are labelled SIM.",
            ],
            Some(if app.tls_status.enabled {
                "Configure your client and send a request  ·  scoped HTTPS CONNECT is decrypted"
            } else {
                "Configure your client and send a request  ·  HTTPS CONNECT remains opaque"
            }),
        ),
    }
}

fn render_interception_workspace(
    frame: &mut Frame,
    area: Rect,
    app: &App,
    theme: &Theme,
    entry: &TrafficEntry,
    output: &mut RenderOutput,
) {
    let modified = app.interception.dirty
        || entry.interception.modified
        || entry.state == TrafficState::Modified;
    let title = format!("ACTIVE INTERCEPTION · #{:04}", entry.id.0);
    let block = focused_panel(
        theme,
        &title,
        app.interception.editing || app.focus == Focus::Content,
    );
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.height < 6 || inner.width < 24 {
        return;
    }

    let now = Utc::now();
    let waiting = format_age(entry.timings.started_at, now);
    let validation = app
        .interception
        .parse_error
        .as_ref()
        .or(app.interception.validation_error.as_ref());
    let header_h = if validation.is_some() { 3 } else { 2 };
    let header_h = header_h.min(inner.height.saturating_sub(3));
    let info = Rect::new(inner.x, inner.y, inner.width, header_h);
    let rest = Rect::new(
        inner.x,
        inner.y + header_h,
        inner.width,
        inner.height.saturating_sub(header_h),
    );

    // Identity + lifecycle only: protocol detail belongs to the inspector.
    let mut meta = vec![
        Line::from(vec![
            Span::styled(
                format!("{} ", entry.request.method),
                theme
                    .method(&entry.request.method)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(entry.request.host.clone(), theme.text()),
            Span::raw("  "),
            Span::styled(truncate(&entry.request.target, 40), theme.muted()),
            Span::raw("  "),
            Span::styled(format!("waiting {waiting}"), theme.warning()),
        ]),
        Line::from(vec![
            Span::styled(lifecycle::label(entry), lifecycle::style(theme, entry)),
            Span::styled("  ·  ", theme.faint()),
            Span::styled(
                if modified { "modified" } else { "unmodified" },
                if modified {
                    theme.warning()
                } else {
                    theme.faint()
                },
            ),
            Span::styled("  ·  ", theme.faint()),
            Span::styled("no response yet", theme.faint()),
        ]),
    ];
    if let Some(err) = validation {
        meta.push(Line::from(Span::styled(
            format!("Validation: {err}"),
            theme.danger(),
        )));
    }
    frame.render_widget(
        Paragraph::new(meta).style(Style::new().bg(theme.palette.surface)),
        info,
    );

    if rest.height < 4 {
        return;
    }

    let (editor_area, status_area) = if rest.height >= 10 {
        let split = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(6), Constraint::Length(3)])
            .split(rest);
        (split[0], split[1])
    } else {
        (rest, Rect::new(rest.x, rest.bottom(), rest.width, 0))
    };

    render_interception_editor(frame, editor_area, app, theme, output);
    render_interception_status(frame, status_area, app, theme, entry);
}

fn render_interception_editor(
    frame: &mut Frame,
    area: Rect,
    app: &App,
    theme: &Theme,
    output: &mut RenderOutput,
) {
    if area.height == 0 {
        return;
    }
    let (label_rect, editor_rect) = (
        Rect::new(area.x, area.y, area.width, 1),
        Rect::new(
            area.x,
            area.y + 1,
            area.width,
            area.height.saturating_sub(1),
        ),
    );
    let label = if app.interception.editing {
        "Request editor (editing) — global shortcuts disabled while typing"
    } else if app.interception.dirty {
        "Request editor (edited, not forwarded)"
    } else {
        "Request editor (current editable request)"
    };
    let style =
        if app.interception.parse_error.is_some() || app.interception.validation_error.is_some() {
            theme.danger()
        } else if app.interception.editing || app.interception.dirty {
            theme.warning()
        } else {
            theme.label()
        };
    frame.render_widget(
        Paragraph::new(Span::styled(format!(" {label}"), style))
            .style(Style::new().bg(theme.palette.surface)),
        label_rect,
    );
    if editor_rect.height > 0 {
        render_editor_with_target(
            frame,
            editor_rect,
            theme,
            &app.interception.editor,
            app.interception.editing,
            output,
            HitTarget::InterceptionEditor,
            ScrollRegion::InterceptionEditor,
        );
    }
}

fn render_interception_status(
    frame: &mut Frame,
    area: Rect,
    _app: &App,
    theme: &Theme,
    entry: &TrafficEntry,
) {
    if area.height == 0 || area.width == 0 {
        return;
    }
    let mut lines = Vec::new();
    if let Some(err) = &entry.error {
        lines.push(Line::from(Span::styled(
            format!(
                "Reason: {}",
                truncate(err, area.width.saturating_sub(9) as usize)
            ),
            theme.danger(),
        )));
    }
    if area.height > 2 || lines.is_empty() {
        let hint = if area.width >= 90 {
            "F forward unchanged  ·  E edit  ·  S send modified (Ctrl+Enter)  ·  D drop"
        } else {
            "F forward  ·  E edit  ·  S modified  ·  D drop"
        };
        lines.push(Line::from(Span::styled(hint, theme.faint())));
    }
    if area.height > 3 {
        lines.push(Line::from(Span::styled(
            "Original request is preserved until you explicitly forward an edited version.",
            theme.faint(),
        )));
    }
    frame.render_widget(
        Paragraph::new(lines).style(Style::new().bg(theme.palette.surface)),
        area,
    );
}

#[cfg(test)]
mod tests {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use rawframe_core::models::HttpRequest;
    use rawframe_core::models::message::Scheme;
    use rawframe_core::models::traffic::TrafficId;
    use rawframe_core::{AppEvent, ProxyState};

    use super::*;
    use crate::app::App;

    fn render_text(app: &App, width: u16, height: u16) -> String {
        let theme = app.theme();
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        let mut output = RenderOutput::default();
        terminal
            .draw(|frame| {
                render(
                    frame,
                    Rect::new(0, 0, width, height),
                    app,
                    &theme,
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

    fn live_entry(id: u64, state: TrafficState) -> TrafficEntry {
        let mut entry = TrafficEntry::new(
            TrafficId(id),
            HttpRequest::new(
                "POST",
                Scheme::Http,
                "api.internal.test",
                8080,
                "/v1/session",
            ),
        );
        entry.state = state;
        entry
    }

    #[test]
    fn proxy_workspace_does_not_duplicate_request_details() {
        let mut app = App::demo();
        app.handle_event(AppEvent::TrafficCaptured(Box::new(live_entry(
            100,
            TrafficState::Completed,
        ))));
        let text = render_text(&app, 120, 36);

        assert!(text.contains("TRAFFIC"), "{text}");
        assert!(text.contains("1 live capture(s)"), "{text}");
        assert!(text.contains("SRC"), "{text}");
        // Protocol detail belongs to the inspector, not the traffic workspace.
        assert!(
            !text.to_ascii_uppercase().contains("REQUEST DETAILS"),
            "{text}"
        );
        assert!(!text.contains("HEADERS"), "{text}");
    }

    #[test]
    fn pending_interception_makes_the_queue_and_editor_primary() {
        let mut app = App::demo();
        app.handle_event(AppEvent::InterceptionPaused(Box::new(live_entry(
            900,
            TrafficState::Paused,
        ))));
        assert_eq!(app.interception_pending_count(), 1);

        let text = render_text(&app, 120, 40);
        assert!(text.contains("PENDING INTERCEPTION QUEUE"), "{text}");
        assert!(text.contains("ACTIVE INTERCEPTION"), "{text}");
        assert!(text.contains("Paused — awaiting decision"), "{text}");
        assert!(text.contains("Forward"), "{text}");
        assert!(text.contains("Drop"), "{text}");
        assert!(
            text.contains("Ctrl+Enter") && text.contains("S send modified"),
            "{text}"
        );
        assert!(!text.contains("DROPPED"), "{text}");
    }

    #[test]
    fn contextual_toolbar_hides_actions_that_cannot_apply() {
        // Finished live captures are inspectable but cannot be forwarded/dropped.
        let mut app = App::demo();
        app.handle_event(AppEvent::TrafficCaptured(Box::new(live_entry(
            101,
            TrafficState::Completed,
        ))));
        assert_eq!(app.interception_pending_count(), 0);
        let text = render_text(&app, 120, 36);

        assert!(text.contains("Inspect"), "{text}");
        assert!(text.contains("Replay"), "{text}");
        assert!(!text.contains("Forward"), "{text}");
        assert!(!text.contains("Drop"), "{text}");
    }

    #[test]
    fn empty_proxy_states_explain_the_next_action() {
        // Fixtures are history data; a stopped proxy with no live captures
        // explains the state instead of presenting fixtures as traffic.
        let app = App::demo();
        assert!(app.proxy_entries().is_empty());
        assert_eq!(app.proxy_state, ProxyState::Stopped);
        let text = render_text(&app, 100, 30);
        assert!(text.contains("PROXY STOPPED"), "{text}");
        assert!(text.contains("Press P"), "{text}");
        assert!(text.contains("HTTP History"), "{text}");
    }

    #[test]
    fn table_columns_keep_identity_and_status_when_narrow() {
        let mut app = App::demo();
        app.handle_event(AppEvent::TrafficCaptured(Box::new(live_entry(
            102,
            TrafficState::Completed,
        ))));
        let text = render_text(&app, 50, 20);
        assert!(text.contains("METHOD"), "{text}");
        assert!(text.contains("STATUS"), "{text}");
        assert!(text.contains("SRC"), "{text}");
    }
}
