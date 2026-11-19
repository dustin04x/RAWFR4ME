//! Intruder workspace: request positions, payload sources, strategy, exact
//! execution preview, live progress, results table, and response inspector.
//!
//! Everything drawn here comes from state the operator can see and change. The
//! preview is the plan the engine runs; the results are real responses.

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use rawframe_core::models::StatusClass;
use rawframe_core::security::{display_bytes, sanitize_for_display};
use rawframe_core::{IntruderOutcome, IntruderPhase, IntruderResult, MARKER};

use crate::app::App;
use crate::components::editor::render_editor_with_target;
use crate::components::{
    ButtonSpec, button_row, empty_state, format_bytes, panel, status_style, truncate,
};
use crate::interaction::{ActionId, HitTarget, RenderOutput, ScrollRegion};
use crate::intruder::{Candidate, IntruderView};
use crate::screens::render_heading;
use crate::theme::Theme;

const INSPECTOR_BODY_LIMIT: usize = 24 * 1024;

pub fn render(frame: &mut Frame, area: Rect, app: &App, theme: &Theme, output: &mut RenderOutput) {
    let engine = if app.intruder_engine_available() {
        "ENGINE READY"
    } else {
        "ENGINE OFFLINE"
    };
    render_heading(
        frame,
        Rect::new(area.x, area.y, area.width, 1),
        theme,
        "Intruder",
        "positions · payloads · bounded execution",
        Some(engine),
        if app.intruder_engine_available() {
            theme.success()
        } else {
            theme.warning()
        },
    );

    if area.height < 6 {
        return;
    }

    let mut y = area.y + 1;
    render_view_tabs(
        frame,
        Rect::new(area.x, y, area.width, 1),
        app,
        theme,
        output,
    );
    y += 1;
    render_actions(
        frame,
        Rect::new(area.x, y, area.width, 1),
        app,
        theme,
        output,
    );
    y += 1;

    let body = Rect::new(area.x, y, area.width, area.bottom().saturating_sub(y));
    if body.height == 0 {
        return;
    }

    if !app.intruder.has_template() {
        empty_state(
            frame,
            body,
            theme,
            "No request loaded",
            &[
                "Open a request from HTTP History (I) or send one from Repeater (I).",
                "Intruder works on a copy; the source request is never overwritten.",
            ],
            None,
        );
        return;
    }

    match app.intruder.view {
        IntruderView::Setup => render_setup(frame, body, app, theme, output),
        IntruderView::Results => render_results(frame, body, app, theme, output),
    }

    if let Some(prompt) = &app.intruder.prompt {
        render_prompt(frame, area, theme, prompt);
    }
}

fn render_view_tabs(
    frame: &mut Frame,
    area: Rect,
    app: &App,
    theme: &Theme,
    output: &mut RenderOutput,
) {
    let mut spans: Vec<Span<'static>> = Vec::new();
    let mut x = area.x;
    for view in [IntruderView::Setup, IntruderView::Results] {
        let active = app.intruder.view == view;
        let label = format!(" {} ", view.label());
        let width = label.chars().count() as u16;
        let rect = Rect::new(x, area.y, width.min(area.right().saturating_sub(x)), 1);
        if rect.width == 0 {
            break;
        }
        let style = if active {
            theme.accent_bold()
        } else {
            theme.faint()
        };
        frame.render_widget(
            Paragraph::new(Span::styled(label.clone(), style))
                .style(Style::new().bg(theme.palette.bg)),
            rect,
        );
        output.hit(rect, HitTarget::Action(ActionId::IntruderViewToggle));
        spans.push(Span::raw(""));
        x += width + 1;
    }

    let (phase_label, phase_style) = phase_badge(app, theme);
    let progress = app.intruder.progress();
    let right = if app.intruder.total > 0 {
        format!(
            "{} · {}/{} · {} ",
            phase_label,
            progress.0,
            progress.1,
            app.intruder.plan_status()
        )
    } else {
        format!("{phase_label} · {} ", app.intruder.plan_status())
    };
    let _ = spans;
    if right.chars().count() + 4 < area.width as usize {
        frame.render_widget(
            Paragraph::new(Span::styled(right, phase_style))
                .alignment(Alignment::Right)
                .style(Style::new().bg(theme.palette.bg)),
            area,
        );
    }
}

fn phase_badge(app: &App, theme: &Theme) -> (String, Style) {
    let label = app.intruder.phase.label().to_ascii_uppercase();
    let style = match app.intruder.phase {
        IntruderPhase::Running => theme.accent_bold(),
        IntruderPhase::Paused => theme.warning(),
        IntruderPhase::Cancelling => theme.danger(),
        IntruderPhase::Finished => theme.success(),
        IntruderPhase::Idle => theme.faint(),
    };
    (label, style)
}

fn render_actions(
    frame: &mut Frame,
    area: Rect,
    app: &App,
    theme: &Theme,
    output: &mut RenderOutput,
) {
    let plan_ready = app.intruder.build_launch().is_ok();
    let active = app.intruder.is_active();
    let buttons: Vec<ButtonSpec<'_>> = match app.intruder.view {
        IntruderView::Setup => {
            let mut buttons = vec![
                ButtonSpec::new(
                    "Start",
                    ActionId::IntruderStart,
                    plan_ready && !active && app.intruder_engine_available(),
                )
                .primary()
                .key("^⏎"),
                ButtonSpec::new("Edit req", ActionId::IntruderEditRequest, true).key("⏎"),
                ButtonSpec::new("Mark", ActionId::IntruderMarkPosition, true).key("M"),
                ButtonSpec::new("Strategy", ActionId::IntruderStrategy, true).key("S"),
                ButtonSpec::new("List", ActionId::IntruderAddList, true).key("A"),
            ];
            if area.width >= 96 {
                buttons.push(ButtonSpec::new(
                    "Rename list",
                    ActionId::IntruderRenameList,
                    app.intruder.active_set().is_some(),
                ));
                buttons.push(ButtonSpec::new(
                    "Import wordlist",
                    ActionId::IntruderImportWordlist,
                    true,
                ));
                buttons.push(ButtonSpec::new(
                    "Clear positions",
                    ActionId::IntruderClearPositions,
                    !app.intruder.position_rows().is_empty(),
                ));
            }
            buttons
        }
        IntruderView::Results => {
            let mut buttons = vec![
                ButtonSpec::new(
                    if app.intruder.phase == IntruderPhase::Paused {
                        "Resume"
                    } else {
                        "Pause"
                    },
                    ActionId::IntruderPause,
                    active,
                )
                .key("P"),
                ButtonSpec::new("Cancel", ActionId::IntruderCancel, active).key("X"),
                ButtonSpec::new(
                    "To Repeater",
                    ActionId::IntruderSendToRepeater,
                    app.intruder.selected_result().is_some(),
                )
                .key("T"),
                ButtonSpec::new("Baseline", ActionId::IntruderBaseline, true).key("B"),
                ButtonSpec::new("Sort", ActionId::IntruderCycleSort, true).key("S"),
            ];
            if area.width >= 96 {
                buttons.push(ButtonSpec::new("Setup", ActionId::IntruderViewToggle, true).key("G"));
            }
            buttons
        }
    };
    button_row(frame, area, &buttons, theme, app.hover.as_ref(), output);
}

fn render_setup(
    frame: &mut Frame,
    area: Rect,
    app: &App,
    theme: &Theme,
    output: &mut RenderOutput,
) {
    if area.width >= 100 {
        let columns = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(54), Constraint::Percentage(46)])
            .split(area);
        let left = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(46), Constraint::Percentage(54)])
            .split(columns[0]);
        let right = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Percentage(34),
                Constraint::Percentage(30),
                Constraint::Percentage(36),
            ])
            .split(columns[1]);
        render_request(frame, left[0], app, theme, output);
        render_positions(frame, left[1], app, theme, output);
        render_payloads(frame, right[0], app, theme, output);
        render_strategy(frame, right[1], app, theme);
        render_preview(frame, right[2], app, theme);
    } else {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(6),
                Constraint::Length(5),
                Constraint::Length(3),
                Constraint::Min(3),
            ])
            .split(area);
        render_request_compact(frame, rows[0], app, theme, output);
        render_positions_compact(frame, rows[1], app, theme, output);
        render_strategy_compact(frame, rows[2], app, theme);
        render_preview_compact(frame, rows[3], app, theme);
    }
}

fn render_request(
    frame: &mut Frame,
    area: Rect,
    app: &App,
    theme: &Theme,
    output: &mut RenderOutput,
) {
    let template = app.intruder.template.as_ref().expect("template");
    let title = format!(
        " REQUEST · {} {} ",
        template.method,
        truncate(&template.url(), area.width.saturating_sub(24) as usize)
    );
    let block = panel(theme, &title);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    render_request_inner(frame, inner, app, theme, output);
}

fn render_request_compact(
    frame: &mut Frame,
    area: Rect,
    app: &App,
    theme: &Theme,
    output: &mut RenderOutput,
) {
    if area.height == 0 {
        return;
    }
    let template = app.intruder.template.as_ref().expect("template");
    let header = Line::from(vec![
        Span::styled(" REQUEST ", theme.label()),
        Span::styled(
            format!("{} {}", template.method, truncate(&template.url(), 48)),
            theme.muted(),
        ),
    ]);
    frame.render_widget(
        Paragraph::new(header),
        Rect::new(area.x, area.y, area.width, 1),
    );
    let inner = Rect::new(
        area.x,
        area.y + 1,
        area.width,
        area.height.saturating_sub(1),
    );
    render_request_inner(frame, inner, app, theme, output);
}

fn render_request_inner(
    frame: &mut Frame,
    inner: Rect,
    app: &App,
    theme: &Theme,
    output: &mut RenderOutput,
) {
    if inner.height == 0 || inner.width == 0 {
        return;
    }
    let editing_head =
        app.intruder.editing && app.intruder.edit_target == crate::intruder::EditTarget::Head;
    let editing_body =
        app.intruder.editing && app.intruder.edit_target == crate::intruder::EditTarget::Body;

    if editing_head {
        render_editor_with_target(
            frame,
            inner,
            theme,
            &app.intruder.head,
            true,
            output,
            HitTarget::IntruderEditor,
            ScrollRegion::IntruderRequest,
        );
        return;
    }

    let mut lines: Vec<Line<'static>> = Vec::new();
    for (index, text) in app.intruder.head.text().lines().enumerate() {
        lines.push(marker_line(index, text, theme));
    }
    let body_height = if inner.height >= 6 { 3 } else { 1 };
    let head_area = Rect::new(
        inner.x,
        inner.y,
        inner.width,
        inner.height.saturating_sub(body_height),
    );
    frame.render_widget(Paragraph::new(lines), head_area);

    let body_area = Rect::new(
        inner.x,
        inner.y + head_area.height,
        inner.width,
        body_height,
    );
    if body_area.height == 0 {
        return;
    }
    if editing_body {
        render_editor_with_target(
            frame,
            body_area,
            theme,
            &app.intruder.body,
            true,
            output,
            HitTarget::IntruderEditor,
            ScrollRegion::IntruderRequest,
        );
        return;
    }
    let template = app.intruder.template.as_ref().expect("template");
    let label = if template.body.is_empty() {
        Line::from(Span::styled("BODY · empty", theme.faint()))
    } else if let Some(text) = template.body_text() {
        let mut line = vec![Span::styled("BODY · ", theme.label())];
        line.extend(marker_spans(text, theme));
        Line::from(line)
    } else {
        Line::from(vec![
            Span::styled("BODY · ", theme.label()),
            Span::styled(
                format!("{} binary bytes · markers supported", template.body.len()),
                theme.warning(),
            ),
        ])
    };
    frame.render_widget(Paragraph::new(label), body_area);
    let hint = if app.intruder.editing {
        "EDITING · Esc commits · Tab moves focus"
    } else {
        "Enter edits · 2 edits body · M marks a component"
    };
    if body_area.height > 1 {
        frame.render_widget(
            Paragraph::new(Span::styled(hint, theme.faint())),
            Rect::new(body_area.x, body_area.y + 1, body_area.width, 1),
        );
    }
}

fn marker_line(index: usize, text: &str, theme: &Theme) -> Line<'static> {
    let mut spans = vec![Span::styled(format!("{:>2} ", index + 1), theme.faint())];
    spans.extend(marker_spans(text, theme));
    Line::from(spans)
}

/// Renders `§value§` with the marker glyph in the accent colour so an active
/// position is identifiable in the request itself.
fn marker_spans(text: &str, theme: &Theme) -> Vec<Span<'static>> {
    let mut spans = Vec::new();
    let mut active = false;
    for (index, part) in text.split(MARKER).enumerate() {
        if index > 0 {
            spans.push(Span::styled(MARKER, theme.accent_bold()));
            active = !active;
        }
        if !part.is_empty() {
            spans.push(Span::styled(
                part.to_string(),
                if active { theme.accent() } else { theme.text() },
            ));
        }
    }
    spans
}

fn render_positions(
    frame: &mut Frame,
    area: Rect,
    app: &App,
    theme: &Theme,
    output: &mut RenderOutput,
) {
    let marked = app.intruder.position_rows().len();
    let title = format!(" POSITIONS · {marked} marked ");
    let block = panel(theme, &title);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    render_positions_inner(frame, inner, app, theme, output);
}

fn render_positions_compact(
    frame: &mut Frame,
    area: Rect,
    app: &App,
    theme: &Theme,
    output: &mut RenderOutput,
) {
    if area.height == 0 {
        return;
    }
    let marked = app.intruder.position_rows().len();
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(" POSITIONS ", theme.label()),
            Span::styled(
                format!("{marked} marked · M marks · Space enables"),
                theme.faint(),
            ),
        ])),
        Rect::new(area.x, area.y, area.width, 1),
    );
    let inner = Rect::new(
        area.x,
        area.y + 1,
        area.width,
        area.height.saturating_sub(1),
    );
    render_positions_inner(frame, inner, app, theme, output);
}

fn render_positions_inner(
    frame: &mut Frame,
    inner: Rect,
    app: &App,
    theme: &Theme,
    output: &mut RenderOutput,
) {
    if inner.height == 0 || inner.width == 0 {
        return;
    }
    let candidates = app.intruder.candidates();
    if candidates.is_empty() {
        frame.render_widget(
            Paragraph::new(Span::styled(
                "This request has no markable components.",
                theme.faint(),
            )),
            inner,
        );
        return;
    }
    let rows = inner.height as usize;
    let start = window_start(candidates.len(), app.intruder.selection, rows);
    let mut lines: Vec<Line<'static>> = Vec::new();
    for (offset, candidate) in candidates.iter().enumerate().skip(start).take(rows) {
        let selected = offset == app.intruder.selection;
        let style = if selected {
            theme.selected_accent()
        } else {
            theme.text()
        };
        let glyph = if candidate.marked {
            if position_enabled(app, candidate) {
                Span::styled("● ", theme.accent_bold())
            } else {
                Span::styled("○ ", theme.warning())
            }
        } else {
            Span::styled("· ", theme.faint())
        };
        let mut spans = vec![
            glyph,
            Span::styled(candidate.area_label().to_string(), style),
        ];
        if inner.width > 34 {
            spans.push(Span::raw(" "));
            let label_width = 16.min(inner.width as usize / 3);
            spans.push(Span::styled(
                format!("{:<label_width$}", truncate(&candidate.label, label_width)),
                theme.muted(),
            ));
            spans.push(Span::raw("  "));
            spans.push(Span::styled(
                truncate(&candidate.preview, inner.width.saturating_sub(40) as usize),
                if candidate.marked {
                    theme.accent()
                } else {
                    theme.faint()
                },
            ));
        }
        lines.push(Line::from(spans));
    }
    frame.render_widget(Paragraph::new(lines), inner);
    let base_y = inner.y;
    for row in 0..(inner.height as usize).min(candidates.len()) {
        output.hit(
            Rect::new(inner.x, base_y + row as u16, inner.width, 1),
            HitTarget::IntruderCandidate(start + row),
        );
    }
}

fn position_enabled(app: &App, candidate: &Candidate) -> bool {
    // The parsed analysis is the single source of truth: a component is enabled
    // when an enabled position with the same area exists.
    if !candidate.marked {
        return false;
    }
    let rows = app.intruder.position_rows();
    match candidate.area_label() {
        "PATH" => rows.iter().any(|row| row.area == "PATH" && row.enabled),
        "QUERY" => rows.iter().any(|row| row.area == "QUERY" && row.enabled),
        "BODY" => rows.iter().any(|row| row.area == "BODY" && row.enabled),
        _ => {
            let name = candidate.label.trim_start_matches("header · ");
            let area = format!("HDR {name}");
            rows.iter().any(|row| row.area == area && row.enabled)
        }
    }
}

fn render_payloads(
    frame: &mut Frame,
    area: Rect,
    app: &App,
    theme: &Theme,
    output: &mut RenderOutput,
) {
    let set_label = app
        .intruder
        .active_set()
        .map(|set| format!("{} · {} payloads", set.name, set.len()))
        .unwrap_or_else(|| "no payload list".into());
    let title = format!(
        " PAYLOADS · {} ",
        truncate(&set_label, area.width.saturating_sub(16) as usize)
    );
    let block = panel(theme, &title);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if app.intruder.editing && app.intruder.edit_target == crate::intruder::EditTarget::Payloads {
        render_editor_with_target(
            frame,
            inner,
            theme,
            &app.intruder.payload_text,
            true,
            output,
            HitTarget::IntruderEditor,
            ScrollRegion::IntruderRequest,
        );
        return;
    }
    if inner.height == 0 {
        return;
    }
    let mut lines: Vec<Line<'static>> = Vec::new();
    let lists: Vec<String> = app
        .intruder
        .sets
        .iter()
        .enumerate()
        .map(|(index, set)| {
            if index == app.intruder.active_set {
                format!("▸{}", truncate(&set.name, 12))
            } else {
                truncate(&set.name, 13)
            }
        })
        .collect();
    lines.push(Line::from(Span::styled(
        truncate(&lists.join("  "), inner.width as usize),
        theme.muted(),
    )));
    let payloads = app
        .intruder
        .active_set()
        .map(|set| set.payloads.clone())
        .unwrap_or_default();
    if payloads.is_empty() {
        lines.push(Line::from(Span::styled(
            "empty list · press ⏎ on this panel to type payloads",
            theme.warning(),
        )));
    } else {
        for (index, payload) in payloads
            .iter()
            .take(inner.height.saturating_sub(2) as usize)
            .enumerate()
        {
            let text = sanitize_for_display(&String::from_utf8_lossy(payload));
            lines.push(Line::from(vec![
                Span::styled(format!("{:>3} ", index + 1), theme.faint()),
                Span::styled(
                    truncate(&text, inner.width.saturating_sub(5) as usize),
                    theme.text(),
                ),
            ]));
        }
    }
    frame.render_widget(Paragraph::new(lines), inner);
}

fn render_strategy(frame: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let block = panel(theme, " STRATEGY ");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.height == 0 {
        return;
    }
    let strategy = app.intruder.strategy;
    let mut lines = vec![Line::from(vec![
        Span::styled(strategy.label().to_ascii_uppercase(), theme.accent_bold()),
        Span::raw("  "),
        Span::styled(
            truncate(
                strategy.description(),
                inner
                    .width
                    .saturating_sub(strategy.label().len() as u16 + 3) as usize,
            ),
            theme.muted(),
        ),
    ])];
    let positions = app.intruder.enabled_positions().len();
    lines.push(Line::from(vec![
        Span::styled(
            format!("{} POSITIONS", positions),
            if positions == 0 {
                theme.warning()
            } else {
                theme.text()
            },
        ),
        Span::styled(
            format!("  ·  {}", app.intruder.plan_status()),
            theme.muted(),
        ),
    ]));
    lines.push(Line::from(vec![
        Span::styled("CONCURRENCY ", theme.label()),
        Span::styled(format!("{} ", app.intruder.concurrency), theme.text()),
        Span::styled("RATE ", theme.label()),
        Span::styled(format!("{}/s ", app.intruder.rate), theme.text()),
        Span::styled("LIMIT ", theme.label()),
        Span::styled(format!("{}s", app.intruder.max_duration_secs), theme.text()),
    ]));
    lines.push(Line::from(vec![
        Span::styled("REDIRECTS ", theme.label()),
        Span::styled(
            if app.intruder.follow_redirects {
                "ON · each hop re-validated "
            } else {
                "OFF "
            },
            if app.intruder.follow_redirects {
                theme.warning()
            } else {
                theme.success()
            },
        ),
        Span::styled("TLS ", theme.label()),
        Span::styled(
            if app.intruder.template.as_ref().map(|t| t.scheme)
                == Some(rawframe_core::Scheme::Https)
            {
                "VERIFIED"
            } else {
                "n/a (HTTP)"
            },
            theme.muted(),
        ),
    ]));
    frame.render_widget(Paragraph::new(lines), inner);
}

fn render_strategy_compact(frame: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    if area.height == 0 {
        return;
    }
    let strategy = app.intruder.strategy;
    let line = Line::from(vec![
        Span::styled(" CONFIG ", theme.label()),
        Span::styled(strategy.label().to_ascii_uppercase(), theme.accent_bold()),
        Span::styled(
            format!(
                " · {} · conc {} · {}/s · {}s · redirects {} ",
                app.intruder.plan_status(),
                app.intruder.concurrency,
                app.intruder.rate,
                app.intruder.max_duration_secs,
                if app.intruder.follow_redirects {
                    "on"
                } else {
                    "off"
                }
            ),
            theme.muted(),
        ),
    ]);
    frame.render_widget(
        Paragraph::new(vec![
            line,
            Line::from(Span::styled(
                format!(
                    " set: {} · {} payloads",
                    app.intruder
                        .active_set()
                        .map(|set| set.name.clone())
                        .unwrap_or_default(),
                    app.intruder.active_set().map(|set| set.len()).unwrap_or(0)
                ),
                theme.faint(),
            )),
        ]),
        area,
    );
}

fn render_preview(frame: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let block = panel(theme, " PREVIEW · first combinations ");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    render_preview_inner(frame, inner, app, theme);
}

fn render_preview_compact(frame: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    if area.height == 0 {
        return;
    }
    frame.render_widget(
        Paragraph::new(Span::styled(" PREVIEW ", theme.label())),
        Rect::new(area.x, area.y, area.width, 1),
    );
    render_preview_inner(
        frame,
        Rect::new(
            area.x,
            area.y + 1,
            area.width,
            area.height.saturating_sub(1),
        ),
        app,
        theme,
    );
}

fn render_preview_inner(frame: &mut Frame, inner: Rect, app: &App, theme: &Theme) {
    if inner.height == 0 || inner.width == 0 {
        return;
    }
    if let Some(Err(error)) = &app.intruder.plan {
        let hint = match error {
            rawframe_core::PlanError::NoPositions => {
                "Mark at least one component (M) and enable it (Space)."
            }
            rawframe_core::PlanError::EmptyPayloadSet(_name) => {
                "The selected payload list has no payloads; add some with Enter."
            }
            _ => "Adjust positions, payload lists, or strategy to fit the limits.",
        };
        frame.render_widget(
            Paragraph::new(vec![
                Line::from(Span::styled(error.to_string(), theme.danger())),
                Line::from(Span::styled(hint, theme.faint())),
            ]),
            inner,
        );
        return;
    }

    let mut lines: Vec<Line<'static>> = Vec::new();
    for (index, request) in app.intruder.preview.iter().enumerate() {
        match request {
            Ok(request) => {
                lines.push(Line::from(vec![
                    Span::styled(format!("{:>2} ", index + 1), theme.faint()),
                    Span::styled(
                        truncate(&request.target, inner.width.saturating_sub(6) as usize),
                        theme.text(),
                    ),
                ]));
                // Show the payloads that differ from the literal, which is what
                // the operator is actually testing.
                let payloads = app
                    .intruder
                    .plan
                    .as_ref()
                    .and_then(|plan| plan.as_ref().ok())
                    .map(|plan| plan.combination_display(index))
                    .unwrap_or_default();
                if !payloads.is_empty() && lines.len() < inner.height as usize {
                    lines.push(Line::from(vec![
                        Span::styled("   ", theme.faint()),
                        Span::styled(
                            truncate(
                                &payloads.join(" · "),
                                inner.width.saturating_sub(4) as usize,
                            ),
                            theme.accent(),
                        ),
                    ]));
                }
            }
            Err(error) => lines.push(Line::from(Span::styled(
                format!("{:>2} {error}", index + 1),
                theme.danger(),
            ))),
        }
        if lines.len() >= inner.height as usize {
            break;
        }
    }
    let total = app
        .intruder
        .plan
        .as_ref()
        .and_then(|plan| plan.as_ref().ok())
        .map(|plan| plan.count)
        .unwrap_or(0);
    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            "No combinations yet.",
            theme.faint(),
        )));
    }
    if (lines.len() as u16) < inner.height && total > app.intruder.preview.len() as u64 {
        lines.push(Line::from(Span::styled(
            format!(
                "… {} more not shown · {total} total",
                total - app.intruder.preview.len() as u64
            ),
            theme.faint(),
        )));
    }
    frame.render_widget(Paragraph::new(lines), inner);
}

fn render_results(
    frame: &mut Frame,
    area: Rect,
    app: &App,
    theme: &Theme,
    output: &mut RenderOutput,
) {
    let mut rows = vec![Constraint::Length(1)];
    if app.intruder.total > 0 {
        rows.push(Constraint::Length(1));
    }
    let footer_height = 2.min(area.height.saturating_sub(3));
    rows.push(Constraint::Min(3));
    if footer_height > 0 {
        rows.push(Constraint::Length(footer_height));
    }
    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints(rows)
        .split(area);

    render_result_header(frame, sections[0], app, theme, output);
    let mut index = 1;
    if app.intruder.total > 0 {
        render_progress(frame, sections[index], app, theme);
        index += 1;
    }
    let table_area = sections[index];

    if area.width >= 104 {
        let columns = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
            .split(Rect::new(
                table_area.x,
                table_area.y,
                table_area.width,
                table_area.bottom().saturating_sub(table_area.y),
            ));
        render_table(frame, columns[0], app, theme, output);
        render_inspector(frame, columns[1], app, theme, output);
    } else {
        let stacked = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
            .split(table_area);
        render_table(frame, stacked[0], app, theme, output);
        render_inspector(frame, stacked[1], app, theme, output);
    }
}

fn render_result_header(
    frame: &mut Frame,
    area: Rect,
    app: &App,
    theme: &Theme,
    output: &mut RenderOutput,
) {
    let visible = app.intruder.filtered_results().len();
    let total = app.intruder.results.len();
    let filter = if app.intruder.filter.is_empty() {
        "no filter".to_string()
    } else {
        let mut parts = Vec::new();
        if !app.intruder.filter.query.trim().is_empty() {
            parts.push(format!("q:{}", truncate(&app.intruder.filter.query, 18)));
        }
        if let Some(class) = app.intruder.filter.status_class {
            parts.push(class.label().to_string());
        }
        if let Some(outcome) = app.intruder.filter.outcome {
            parts.push(outcome.label().to_string());
        }
        parts.join(" · ")
    };
    let sort = format!(
        "sort {}{}",
        app.intruder.sort.label(),
        if app.intruder.sort_descending {
            " ↓"
        } else {
            " ↑"
        }
    );
    let line = Line::from(vec![
        Span::styled(format!(" {visible}/{total} results "), theme.label()),
        Span::styled(format!("· {filter} "), theme.faint()),
        Span::styled(format!("· {sort} "), theme.faint()),
        Span::styled(
            format!("· {} ", app.intruder.baseline_label()),
            theme.muted(),
        ),
    ]);
    frame.render_widget(
        Paragraph::new(line).style(Style::new().bg(theme.palette.bg)),
        area,
    );
    if area.width > 60 {
        let right = " / filter · F status · O outcome · U clear ";
        frame.render_widget(
            Paragraph::new(Span::styled(right, theme.faint())).alignment(Alignment::Right),
            area,
        );
        output.hit(area, HitTarget::Action(ActionId::IntruderCycleSort));
    }
}

fn render_progress(frame: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let (done, total) = app.intruder.progress();
    let total = total.max(1);
    let width = area.width.saturating_sub(34).max(8) as usize;
    let filled = ((done as f64 / total as f64) * width as f64).round() as usize;
    let filled = filled.min(width);
    let bar = format!("{}{}", "█".repeat(filled), "░".repeat(width - filled));
    let style = match app.intruder.phase {
        IntruderPhase::Paused => theme.warning(),
        IntruderPhase::Cancelling => theme.danger(),
        IntruderPhase::Finished => theme.success(),
        _ => theme.accent(),
    };
    let line = Line::from(vec![
        Span::styled(format!(" {:>4}/{:<4} ", done, total), theme.text()),
        Span::styled(bar, style),
        Span::styled(
            format!(
                " {:>3}%  {} ",
                (done as f64 / total as f64 * 100.0).round() as u64,
                app.intruder.phase.label().to_ascii_uppercase()
            ),
            style.add_modifier(Modifier::BOLD),
        ),
    ]);
    frame.render_widget(
        Paragraph::new(line).style(Style::new().bg(theme.palette.bg)),
        area,
    );
}

fn render_table(
    frame: &mut Frame,
    area: Rect,
    app: &App,
    theme: &Theme,
    output: &mut RenderOutput,
) {
    let block = panel(theme, " RESULTS ");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.height == 0 || inner.width == 0 {
        return;
    }
    let wide = inner.width >= 70;
    let mut header = vec![
        Span::styled(format!("{:<5}", "  #"), theme.label()),
        Span::styled(format!("{:<5}", "STAT"), theme.label()),
        Span::styled(format!("{:<10}", "OUTCOME"), theme.label()),
        Span::styled(format!("{:>9}", "SIZE"), theme.label()),
    ];
    if wide {
        header.push(Span::styled(format!("{:>8}", "TIME"), theme.label()));
        header.push(Span::styled("  PAYLOADS", theme.label()));
    } else {
        header.push(Span::styled("  PAYLOADS", theme.label()));
    }
    frame.render_widget(
        Paragraph::new(Line::from(header)).style(theme.table_header()),
        Rect::new(inner.x, inner.y, inner.width, 1),
    );

    let indices = app.intruder.filtered_results();
    if indices.is_empty() {
        frame.render_widget(
            Paragraph::new(Span::styled(
                if app.intruder.results.is_empty() {
                    "No results yet. Confirm a plan on the Setup view to start a run."
                } else {
                    "No results match the current filter."
                },
                theme.faint(),
            )),
            Rect::new(
                inner.x,
                inner.y + 1,
                inner.width,
                inner.height.saturating_sub(1),
            ),
        );
        return;
    }

    let rows = inner.height.saturating_sub(1) as usize;
    let start = window_start(indices.len(), app.intruder.result_selection, rows);
    let mut lines: Vec<Line<'static>> = Vec::new();
    for (offset, result_index) in indices.iter().enumerate().skip(start).take(rows) {
        let Some(result) = app.intruder.results.get(*result_index) else {
            continue;
        };
        let selected = offset == app.intruder.result_selection;
        let base_style = if selected {
            theme.selected_row()
        } else {
            theme.row(offset, false)
        };
        let status = result
            .status()
            .map(|status| status.to_string())
            .unwrap_or_else(|| "---".into());
        let class = result.status().map(StatusClass::from_code);
        let outcome = result.outcome();
        let mut spans = vec![
            Span::styled(
                format!("{:<5}", format!("#{}", result.index + 1)),
                base_style.patch(theme.faint()),
            ),
            Span::styled(
                format!("{status:<5}"),
                base_style.patch(status_style(theme, class)),
            ),
            Span::styled(
                format!("{:<10}", truncate(outcome.label(), 10)),
                base_style.patch(outcome_style(theme, outcome)),
            ),
            Span::styled(
                format!("{:>9}", format_bytes(result.size())),
                base_style.patch(theme.muted()),
            ),
        ];
        if wide {
            spans.push(Span::styled(
                format!("{:>8}", format!("{} ms", result.duration_ms())),
                base_style.patch(theme.faint()),
            ));
        }
        spans.push(Span::styled(
            format!("  {}", truncate(&result.payload_display().join(" · "), 28)),
            base_style.patch(theme.accent()),
        ));
        if app.intruder.baseline == Some(result.index) {
            spans.push(Span::styled("  BASE", base_style.patch(theme.warning())));
        }
        lines.push(Line::from(spans));
    }
    frame.render_widget(
        Paragraph::new(lines),
        Rect::new(inner.x, inner.y + 1, inner.width, rows as u16),
    );
    for row in 0..rows.min(indices.len()) {
        output.hit(
            Rect::new(inner.x, inner.y + 1 + row as u16, inner.width, 1),
            HitTarget::IntruderResultRow(start + row),
        );
    }
    output.zone(
        Rect::new(inner.x, inner.y + 1, inner.width, rows as u16),
        ScrollRegion::IntruderResults,
    );
}

fn outcome_style(theme: &Theme, outcome: IntruderOutcome) -> Style {
    match outcome {
        IntruderOutcome::Response => theme.success(),
        IntruderOutcome::Blocked => theme.warning(),
        IntruderOutcome::TimedOut => theme.warning(),
        IntruderOutcome::Failed => theme.danger(),
        IntruderOutcome::Cancelled | IntruderOutcome::NotSent => theme.faint(),
    }
}

fn render_inspector(
    frame: &mut Frame,
    area: Rect,
    app: &App,
    theme: &Theme,
    _output: &mut RenderOutput,
) {
    let block = panel(theme, " INSPECT · V cycles view ");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.height == 0 || inner.width == 0 {
        return;
    }
    let tabs = Line::from(
        crate::intruder::IntruderResultView::ALL
            .iter()
            .map(|view| {
                let active = *view == app.intruder.inspector_view;
                Span::styled(
                    format!(" {} ", view.label()),
                    if active {
                        theme.accent_bold()
                    } else {
                        theme.faint()
                    },
                )
            })
            .collect::<Vec<_>>(),
    );
    frame.render_widget(
        Paragraph::new(tabs),
        Rect::new(inner.x, inner.y, inner.width, 1),
    );
    let body = Rect::new(
        inner.x,
        inner.y + 1,
        inner.width,
        inner.height.saturating_sub(1),
    );
    if body.height == 0 {
        return;
    }
    let Some(result) = app.intruder.selected_result() else {
        frame.render_widget(
            Paragraph::new(Span::styled(
                "Select a result to inspect it.",
                theme.faint(),
            )),
            body,
        );
        return;
    };

    let mut lines: Vec<Line<'static>> = Vec::new();
    match app.intruder.inspector_view {
        crate::intruder::IntruderResultView::Raw => {
            let request = &result.result.request;
            lines.push(Line::from(Span::styled(
                format!("{} {} {}", request.method, request.target, request.version),
                theme.accent_bold(),
            )));
            for header in request.headers.iter() {
                lines.push(Line::from(vec![
                    Span::styled(format!("{}: ", header.name), theme.label()),
                    Span::styled(sanitize_for_display(&header.value), theme.text()),
                ]));
            }
            if let Some(response) = &result.result.response {
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    format!(
                        "{} {} {}",
                        response.version,
                        response.status,
                        sanitize_for_display(&response.reason)
                    ),
                    status_style(theme, Some(StatusClass::from_code(response.status))),
                )));
                for header in response.headers.iter() {
                    lines.push(Line::from(vec![
                        Span::styled(format!("{}: ", header.name), theme.label()),
                        Span::styled(sanitize_for_display(&header.value), theme.text()),
                    ]));
                }
            }
        }
        crate::intruder::IntruderResultView::Headers => {
            if let Some(response) = &result.result.response {
                for header in response.headers.iter() {
                    lines.push(Line::from(vec![
                        Span::styled(format!("{}: ", header.name), theme.label()),
                        Span::styled(sanitize_for_display(&header.value), theme.text()),
                    ]));
                }
                if response.headers.iter().count() == 0 {
                    lines.push(Line::from(Span::styled(
                        "No response headers.",
                        theme.faint(),
                    )));
                }
            } else {
                lines.push(Line::from(Span::styled(
                    "This request has no response headers.",
                    theme.faint(),
                )));
            }
        }
        crate::intruder::IntruderResultView::Body => {
            let body = result
                .result
                .response
                .as_ref()
                .map(|response| response.body.as_slice())
                .unwrap_or(&[]);
            if body.is_empty() {
                lines.push(Line::from(Span::styled(
                    "No captured body (empty, above the capture limit, or withheld by policy).",
                    theme.faint(),
                )));
            } else {
                let display = display_bytes(body, INSPECTOR_BODY_LIMIT);
                for text in display.text.lines() {
                    lines.push(Line::from(Span::styled(
                        sanitize_for_display(text),
                        theme.text(),
                    )));
                }
                if display.truncated || display.lossy {
                    lines.push(Line::from(Span::styled(
                        format!(
                            "… displayed {} of {} bytes{}",
                            INSPECTOR_BODY_LIMIT.min(body.len()),
                            body.len(),
                            if display.lossy {
                                " (binary shown lossily)"
                            } else {
                                ""
                            }
                        ),
                        theme.faint(),
                    )));
                }
            }
        }
        crate::intruder::IntruderResultView::Payloads => {
            lines.push(Line::from(Span::styled(
                format!("request #{} · id {}", result.index + 1, result.id),
                theme.label(),
            )));
            let positions = result.positions.clone();
            for (index, payload) in result.payloads.iter().enumerate() {
                let position = positions
                    .get(index)
                    .map(|id| format!("P{id}"))
                    .unwrap_or_else(|| format!("P{}", index + 1));
                lines.push(Line::from(vec![
                    Span::styled(format!("{position:>4}  "), theme.muted()),
                    Span::styled(
                        truncate(&sanitize_for_display(&String::from_utf8_lossy(payload)), 60),
                        theme.accent(),
                    ),
                    Span::styled(format!("  {} B", payload.len()), theme.faint()),
                ]));
            }
            if result.payloads.is_empty() {
                lines.push(Line::from(Span::styled(
                    "No payloads recorded.",
                    theme.faint(),
                )));
            }
            if let Some(error) = result.error() {
                lines.push(Line::from(Span::styled(
                    format!("error: {error}"),
                    theme.danger(),
                )));
            }
        }
        crate::intruder::IntruderResultView::Compare => {
            lines.extend(compare_lines(app, result, theme));
        }
    }
    frame.render_widget(Paragraph::new(lines), body);
}

fn compare_lines(app: &App, result: &IntruderResult, theme: &Theme) -> Vec<Line<'static>> {
    let Some(baseline) = app.intruder.baseline_result() else {
        return vec![
            Line::from(Span::styled("No baseline selected.", theme.warning())),
            Line::from(Span::styled(
                "Press B on a result to use it as the comparison baseline.",
                theme.faint(),
            )),
            Line::from(Span::styled(
                "Differences are measurements, not findings: a different status, size, or duration is not by itself a vulnerability.",
                theme.faint(),
            )),
        ];
    };
    if baseline.index == result.index {
        return vec![Line::from(Span::styled(
            "This result is the baseline.",
            theme.faint(),
        ))];
    }
    let comparison = result.comparison(baseline);
    let mut lines = vec![
        Line::from(vec![
            Span::styled("BASELINE ", theme.label()),
            Span::styled(format!("#{}", baseline.index + 1), theme.muted()),
            Span::styled(
                format!(
                    "  status {} · {} · {} ms",
                    baseline
                        .status()
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "---".into()),
                    format_bytes(baseline.size()),
                    baseline.duration_ms()
                ),
                theme.faint(),
            ),
        ]),
        Line::from(vec![
            Span::styled("CURRENT  ", theme.label()),
            Span::styled(format!("#{}", result.index + 1), theme.muted()),
            Span::styled(
                format!(
                    "  status {} · {} · {} ms",
                    result
                        .status()
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "---".into()),
                    format_bytes(result.size()),
                    result.duration_ms()
                ),
                theme.faint(),
            ),
        ]),
        Line::from(""),
    ];
    match comparison.status_changed {
        Some((before, after)) => lines.push(Line::from(Span::styled(
            format!("status {before} → {after}"),
            theme.warning(),
        ))),
        None => lines.push(Line::from(Span::styled("status unchanged", theme.faint()))),
    }
    lines.push(Line::from(Span::styled(
        format!(
            "size {:+} B · duration {:+} ms · body {}",
            comparison.size_delta,
            comparison.duration_delta_ms,
            if comparison.body_changed {
                "differs"
            } else {
                "matches"
            }
        ),
        theme.muted(),
    )));
    for header in comparison.header_changes.iter().take(6) {
        lines.push(Line::from(vec![
            Span::styled(format!("{}: ", header.name), theme.label()),
            Span::styled(
                format!(
                    "{} → {}",
                    truncate(&sanitize_for_display(&header.previous.join(", ")), 24),
                    truncate(&sanitize_for_display(&header.current.join(", ")), 24)
                ),
                theme.muted(),
            ),
        ]));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Evidence only: this is not a vulnerability finding.",
        theme.faint(),
    )));
    lines
}

fn render_prompt(
    frame: &mut Frame,
    area: Rect,
    theme: &Theme,
    prompt: &crate::intruder::IntruderPrompt,
) {
    let width = area.width.saturating_sub(8).clamp(24, 88);
    let height = 5.min(area.height);
    let rect = Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    );
    let block = panel(theme, prompt.title());
    let inner = block.inner(rect);
    frame.render_widget(ratatui::widgets::Clear, rect);
    frame.render_widget(block, rect);
    let lines = vec![
        Line::from(vec![
            Span::styled("› ", theme.accent_bold()),
            Span::styled(
                truncate(&prompt.buffer, inner.width.saturating_sub(3) as usize),
                theme.text(),
            ),
        ]),
        Line::from(""),
        Line::from(Span::styled("Enter confirms · Esc cancels", theme.faint())),
    ];
    frame.render_widget(Paragraph::new(lines), inner);
}

/// Keeps a selected row inside a fixed-height window.
fn window_start(len: usize, selected: usize, rows: usize) -> usize {
    if rows == 0 || len <= rows {
        return 0;
    }
    let selected = selected.min(len - 1);
    if selected < rows {
        0
    } else {
        (selected + 1).saturating_sub(rows).min(len - rows)
    }
}

#[cfg(test)]
mod tests {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use rawframe_core::models::message::{HttpRequest, HttpResponse, Scheme};
    use rawframe_core::repeater::{RepeaterResult, RepeaterTimings};
    use rawframe_core::{AppEvent, IntruderEvent, IntruderResult, PositionId, TrafficId};

    use super::*;
    use crate::app::App;
    use crate::interaction::NavSection;

    fn frame_text(app: &App, width: u16, height: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("backend");
        terminal
            .draw(|frame| {
                let mut output = RenderOutput::default();
                crate::ui::render(frame, app);
                let _ = &mut output;
            })
            .expect("draw");
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

    fn app_with_intruder() -> App {
        let mut app = App::demo();
        let id = app.traffic()[0].id;
        app.open_in_intruder(id);
        app
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn result(index: u64, status: u16, size: usize) -> IntruderResult {
        let mut response = HttpResponse::with_body(status, "text/plain", vec![b'a'; size]);
        response.headers.append("X-Probe", "yes");
        IntruderResult {
            id: TrafficId(rawframe_core::INTRUDER_ID_BASE + index),
            run: 1,
            index,
            payloads: vec![format!("payload{index}").into_bytes()],
            positions: vec![PositionId(1)],
            phase: rawframe_core::RepeaterExecutionPhase::Completed,
            result: RepeaterResult {
                request: HttpRequest::new("GET", Scheme::Http, "lab.rawframe.test", 8080, "/probe"),
                response: Some(response),
                timings: RepeaterTimings {
                    total_ms: 12 + index,
                    ..RepeaterTimings::default()
                },
                redirects: Vec::new(),
                truncated: false,
                response_bytes: size,
                error: None,
                warnings: Vec::new(),
                sent_at: chrono::Utc::now(),
            },
        }
    }

    #[test]
    fn setup_renders_readably_at_every_supported_size() {
        let mut app = app_with_intruder();
        for (width, height) in [(140, 40), (100, 30), (80, 24)] {
            let text = frame_text(&app, width, height);
            assert!(
                text.contains("INTRUDER"),
                "{width}x{height} lost the heading"
            );
            assert!(
                text.contains("POSITIONS"),
                "{width}x{height} lost the position editor"
            );
            assert!(
                text.contains("PREVIEW"),
                "{width}x{height} lost the execution preview"
            );
            assert!(
                !text.contains("planned"),
                "{width}x{height} still shows Intruder as planned"
            );
        }
        // The empty state is explicit before positions are marked.
        let text = frame_text(&app, 100, 30);
        assert!(text.contains("Mark at least one component") || text.contains("NoPositions"));
        let _ = &mut app;
    }

    #[test]
    fn marking_a_component_updates_positions_and_the_exact_count() {
        let mut app = app_with_intruder();
        app.handle_key(key(KeyCode::Char('M')));
        assert_eq!(app.intruder.position_rows().len(), 1);
        let text = frame_text(&app, 140, 40);
        assert!(
            text.contains("1 marked"),
            "the position editor shows the mark"
        );
        assert!(
            text.contains("8 REQUESTS"),
            "the built-in list yields eight sniper requests"
        );
        // The preview shows the expanded request, not a mock row.
        assert!(text.contains("/"), "the preview lists generated targets");
    }

    #[test]
    fn starting_requires_confirmation_and_sends_the_previewed_plan() {
        let mut app = app_with_intruder();
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        app.attach_intruder_commands(tx);
        app.handle_key(key(KeyCode::Char('M')));

        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::CONTROL));
        let confirm = app.confirm.as_ref().expect("confirmation is required");
        assert!(confirm.title.contains("Start Intruder"));
        assert!(confirm.body.contains("8 requests"));
        assert!(confirm.body.contains("authorized"));
        assert!(
            rx.try_recv().is_err(),
            "nothing is sent before confirmation"
        );

        app.handle_key(key(KeyCode::Char('y')));
        let command = rx.try_recv().expect("start command after confirming");
        let rawframe_core::IntruderCommand::Start { run, launch } = command else {
            panic!("expected Start");
        };
        assert_eq!(run, 1);
        assert_eq!(launch.plan.count, 8);
        assert!(!launch.follow_redirects);
        assert!(app.intruder.is_active());

        // Cancelling a run is a real command, not a UI-only flag.
        app.handle_key(key(KeyCode::Char('X')));
        assert!(matches!(
            rx.try_recv(),
            Ok(rawframe_core::IntruderCommand::Cancel { run: 1 })
        ));
    }

    #[test]
    fn results_arrive_from_events_and_render_with_their_payloads() {
        let mut app = app_with_intruder();
        let (tx, _rx) = tokio::sync::mpsc::channel(4);
        app.attach_intruder_commands(tx);
        app.handle_key(key(KeyCode::Char('M')));
        app.handle_key(key(KeyCode::Char('g')));
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::CONTROL));
        app.handle_key(key(KeyCode::Char('y')));

        for (index, status) in [(0u64, 200u16), (1, 403), (2, 500)] {
            let entry = app.traffic()[0].clone();
            app.handle_event(AppEvent::Intruder(IntruderEvent::Completed {
                run: 1,
                result: Box::new(result(index, status, 100 + index as usize)),
                entry: Box::new(entry),
            }));
        }
        assert_eq!(app.intruder.results.len(), 3);
        let text = frame_text(&app, 140, 40);
        assert!(text.contains("payload0"));
        assert!(text.contains("403"));
        assert!(text.contains("RESPONSE"));

        // Status-class filtering narrows the table without hiding rows silently:
        // three presses select 4xx, matching the single 403.
        app.handle_key(key(KeyCode::Char('F')));
        app.handle_key(key(KeyCode::Char('F')));
        app.handle_key(key(KeyCode::Char('F')));
        assert_eq!(app.intruder.filtered_results().len(), 1);
        app.handle_key(key(KeyCode::Char('U')));
        assert_eq!(app.intruder.filtered_results().len(), 3);

        // Navigating to a result changes the inspector content.
        app.handle_key(key(KeyCode::Char('j')));
        assert_eq!(app.intruder.result_selection, 1);
        // Baseline comparison is measured, not asserted as a finding.
        app.handle_key(key(KeyCode::Char('B')));
        assert_eq!(app.intruder.baseline, Some(1));
        for _ in 0..4 {
            app.handle_key(key(KeyCode::Char('V')));
        }
        assert_eq!(
            app.intruder.inspector_view,
            crate::intruder::IntruderResultView::Compare
        );
        let text = frame_text(&app, 140, 40);
        assert!(text.contains("BASELINE"));
    }

    #[test]
    fn a_result_transfers_to_a_new_repeater_tab_without_touching_the_old_one() {
        let mut app = app_with_intruder();
        let (tx, _rx) = tokio::sync::mpsc::channel(4);
        app.attach_intruder_commands(tx);
        app.handle_key(key(KeyCode::Char('M')));
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::CONTROL));
        app.handle_key(key(KeyCode::Char('y')));
        let entry = app.traffic()[0].clone();
        app.handle_event(AppEvent::Intruder(IntruderEvent::Completed {
            run: 1,
            result: Box::new(result(0, 201, 42)),
            entry: Box::new(entry),
        }));
        let tabs_before = app.repeater.tabs.len();
        app.handle_key(key(KeyCode::Char('T')));
        assert_eq!(app.repeater.tabs.len(), tabs_before + 1);
        assert_eq!(app.nav, NavSection::Repeater);
        let tab = app.repeater.active_tab().expect("new tab");
        assert_eq!(
            tab.response.as_ref().and_then(|result| result.status()),
            Some(201)
        );
        assert!(tab.document.request.target.contains("/probe"));
    }

    #[test]
    fn s_cycles_the_sort_in_results_without_touching_the_strategy() {
        let mut app = app_with_intruder();
        let (tx, _rx) = tokio::sync::mpsc::channel(4);
        app.attach_intruder_commands(tx);
        app.handle_key(key(KeyCode::Char('M')));
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::CONTROL));
        app.handle_key(key(KeyCode::Char('y')));
        let entry = app.traffic()[0].clone();
        for index in 0..3 {
            app.handle_event(AppEvent::Intruder(IntruderEvent::Completed {
                run: 1,
                result: Box::new(result(index, 200 + index as u16, 8)),
                entry: Box::new(entry.clone()),
            }));
        }
        // Confirming the plan already switches to Results.
        assert_eq!(app.intruder.view, IntruderView::Results);

        let strategy = app.intruder.strategy;
        let sort = app.intruder.sort;
        app.handle_key(key(KeyCode::Char('S')));
        assert_eq!(
            app.intruder.strategy, strategy,
            "S must not change the attack"
        );
        assert_ne!(app.intruder.sort, sort, "S cycles the sort order");
    }

    #[test]
    fn payload_lists_are_created_and_renamed_through_prompts() {
        let mut app = app_with_intruder();
        let before = app.intruder.sets.len();

        // A opens the name prompt instead of creating a list behind the user.
        app.handle_key(key(KeyCode::Char('A')));
        assert_eq!(app.intruder.sets.len(), before);
        let prompt = app.intruder.prompt.clone().expect("new list prompt");
        assert_eq!(prompt.kind, crate::intruder::PromptKind::NewListName);
        for _ in 0..prompt.buffer.chars().count() {
            app.handle_key(key(KeyCode::Backspace));
        }
        for ch in "audit".chars() {
            app.handle_key(key(KeyCode::Char(ch)));
        }
        app.handle_key(key(KeyCode::Enter));
        assert!(app.intruder.prompt.is_none());
        assert_eq!(app.intruder.sets.len(), before + 1);
        assert_eq!(app.intruder.active_set().expect("new set").name, "audit");

        // L renames the active list, prefilled with its current name.
        app.handle_key(key(KeyCode::Char('L')));
        let prompt = app.intruder.prompt.clone().expect("rename prompt");
        assert_eq!(prompt.kind, crate::intruder::PromptKind::RenameList);
        assert_eq!(prompt.buffer, "audit");
        for _ in 0..prompt.buffer.chars().count() {
            app.handle_key(key(KeyCode::Backspace));
        }
        for ch in "audit-2".chars() {
            app.handle_key(key(KeyCode::Char(ch)));
        }
        app.handle_key(key(KeyCode::Enter));
        assert_eq!(
            app.intruder.active_set().expect("renamed set").name,
            "audit-2"
        );
    }

    #[test]
    fn navigation_reaches_intruder_without_a_planned_label() {
        let mut app = App::demo();
        app.navigate(NavSection::Intruder);
        let text = frame_text(&app, 100, 30);
        assert!(text.contains("NO REQUEST LOADED"));
        assert!(!text.contains("planned module"));
    }
}
