//! HTTP History workspace.

use chrono::Utc;
use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table};
use rawframe_core::models::traffic::{TrafficEntry, TrafficKind, TrafficSource};

use crate::app::App;
use crate::components::lifecycle;
use crate::components::{
    ButtonSpec, button_row, empty_state, focused_panel, format_age, format_bytes, source_badge,
};
use crate::interaction::{ActionId, HitTarget, RenderOutput, ScrollRegion};
use crate::screens::window_start;
use crate::theme::Theme;

pub fn render(frame: &mut Frame, area: Rect, app: &App, theme: &Theme, output: &mut RenderOutput) {
    if area.height == 0 || area.width == 0 {
        return;
    }
    let entries = app.history_entries();
    let total = app.traffic.len();

    let mut y = area.y;
    // Toolbar row: search + filters + clear
    let toolbar_h = if area.width < 90 { 2 } else { 1 };
    render_toolbar(
        frame,
        Rect::new(area.x, y, area.width, toolbar_h),
        app,
        theme,
        output,
    );
    y += toolbar_h;

    if y < area.bottom() {
        let live = app.live_capture_count();
        let sim = app
            .traffic
            .iter()
            .filter(|e| e.source == TrafficSource::Simulated)
            .count();
        let restored = app.restored_entry_count();
        let mut spans = vec![
            Span::styled(
                format!(" {} shown / {} total ", entries.len(), total),
                theme.muted(),
            ),
            Span::styled("·", theme.faint()),
            Span::styled(format!(" {live} live "), theme.success()),
            Span::styled("·", theme.faint()),
            Span::styled(format!(" {sim} simulated "), theme.warning()),
        ];
        if restored > 0 {
            spans.push(Span::styled("·", theme.faint()));
            spans.push(Span::styled(
                format!(" {restored} restored "),
                theme.accent(),
            ));
        }
        let note = match app.restored_session_label() {
            Some(label) => format!("  Read-only history from {label}."),
            None => "  Live, simulated and restored traffic are labeled in the table.".to_string(),
        };
        spans.push(Span::styled(note, theme.faint()));
        let hint = Line::from(spans);
        frame.render_widget(
            Paragraph::new(hint).style(Style::new().bg(theme.palette.bg)),
            Rect::new(area.x, y, area.width, 1),
        );
        y += 1;
    }

    let table_area = Rect::new(area.x, y, area.width, area.bottom().saturating_sub(y));
    render_history_table(frame, table_area, app, theme, entries, output);
}

fn render_toolbar(
    frame: &mut Frame,
    area: Rect,
    app: &App,
    theme: &Theme,
    output: &mut RenderOutput,
) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let compact = area.width < 90;
    let search_w = if compact {
        area.width
    } else {
        (area.width * 2 / 5)
            .clamp(24, 44)
            .min(area.width.saturating_sub(20))
    };

    render_search_field(
        frame,
        Rect::new(area.x, area.y, search_w, 1),
        app,
        theme,
        output,
    );

    let filters_area = if compact && area.height > 1 {
        Rect::new(area.x, area.y + 1, area.width, 1)
    } else {
        Rect::new(
            area.x + search_w + 1,
            area.y,
            area.right().saturating_sub(area.x + search_w + 1),
            1,
        )
    };
    render_filter_chips(frame, filters_area, app, theme, output);
}

fn render_search_field(
    frame: &mut Frame,
    area: Rect,
    app: &App,
    theme: &Theme,
    output: &mut RenderOutput,
) {
    if area.width == 0 {
        return;
    }
    let active = app.search.active;
    let style = if active {
        Style::new()
            .bg(theme.palette.selection)
            .fg(theme.palette.text)
    } else {
        Style::new()
            .bg(theme.palette.surface_elevated)
            .fg(theme.palette.text)
    };
    let mut spans = vec![Span::styled(" Search ", theme.accent())];
    if app.history_filter.query.is_empty() {
        spans.push(Span::styled(
            "method, host, path, status…  (/ or ^F)",
            theme.faint(),
        ));
        if active {
            spans.push(Span::styled("▏", theme.accent()));
        }
    } else {
        spans.push(Span::styled(app.history_filter.query.clone(), style));
        if active {
            spans.push(Span::styled("▏", theme.accent()));
        }
    }
    frame.render_widget(Paragraph::new(Line::from(spans)).style(style), area);
    output.hit(area, HitTarget::SearchField);
}

fn render_filter_chips(
    frame: &mut Frame,
    area: Rect,
    app: &App,
    theme: &Theme,
    output: &mut RenderOutput,
) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let method = app
        .history_filter
        .method
        .as_deref()
        .map(|m| format!("Method: {m}"))
        .unwrap_or_else(|| "Method: all".to_string());
    let status = format!("Status: {}", app.history_filter.status.label());
    let host = app
        .history_filter
        .host
        .as_deref()
        .map_or_else(|| "Host: any".to_string(), |host| format!("Host: {host}"));

    let mut buttons = vec![
        ButtonSpec::new(&method, ActionId::CycleMethod, true).key("M"),
        ButtonSpec::new(&status, ActionId::CycleStatus, true).key("S"),
        ButtonSpec::new(&host, ActionId::CycleHost, true).key("H"),
    ];
    if app.history_filter.is_active() {
        buttons.push(ButtonSpec::new("Clear", ActionId::ClearFilters, true).key("^U"));
    }
    button_row(frame, area, &buttons, theme, app.hover.as_ref(), output);
}

fn render_history_table(
    frame: &mut Frame,
    area: Rect,
    app: &App,
    theme: &Theme,
    entries: Vec<&TrafficEntry>,
    output: &mut RenderOutput,
) {
    if area.height == 0 {
        return;
    }
    let focused = app.focus == crate::interaction::Focus::Content;
    let block = focused_panel(theme, "HTTP HISTORY", focused);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.width == 0 || inner.height < 2 {
        return;
    }
    output.zone(inner, ScrollRegion::HistoryList);

    if entries.is_empty() {
        let (title, detail, hint) = if app.history_filter.is_active() {
            (
                "No matching history",
                "No entry matches the current search or filters.",
                "Clear filters with ^U  ·  Adjust M/S/H filters  ·  / to search",
            )
        } else if app.traffic.is_empty() {
            (
                "Empty history",
                "No traffic has been recorded yet.",
                "Start the proxy and send requests, or review fixtures if present.",
            )
        } else {
            (
                "No history to show",
                "Traffic exists but none is visible with current view settings.",
                "Adjust filters or search.",
            )
        };
        empty_state(frame, inner, theme, title, &[detail], Some(hint));
        return;
    }

    let columns = table_columns(inner.width);
    let widths = column_widths(&columns);
    let selected_position = entries
        .iter()
        .position(|entry| Some(entry.id) == app.history_selected)
        .unwrap_or(0);
    let body_height = inner.height.saturating_sub(1) as usize;
    let start = window_start(selected_position, entries.len(), body_height);
    let now = Utc::now();

    let rows: Vec<Row<'_>> = entries
        .iter()
        .skip(start)
        .take(body_height)
        .map(|entry| {
            build_row(
                theme,
                entry,
                Some(entry.id) == app.history_selected,
                &columns,
                now,
            )
        })
        .collect();

    let table = Table::new(rows, widths)
        .header(table_header(theme, &columns))
        .column_spacing(1)
        .style(Style::new().bg(theme.palette.surface));
    frame.render_widget(table, inner);

    for (offset, entry) in entries.iter().skip(start).take(body_height).enumerate() {
        let row_rect = Rect::new(inner.x, inner.y + 1 + offset as u16, inner.width, 1);
        output.hit(row_rect, HitTarget::HistoryRow(entry.id));
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Column {
    Id,
    Method,
    Host,
    Path,
    Status,
    Size,
    Duration,
    Age,
    Source,
}

fn table_columns(width: u16) -> Vec<Column> {
    use Column::*;
    if width >= 100 {
        vec![Id, Method, Host, Path, Status, Size, Duration, Age, Source]
    } else if width >= 76 {
        vec![Id, Method, Host, Path, Status, Duration, Age, Source]
    } else if width >= 56 {
        vec![Id, Method, Host, Status, Age, Source]
    } else {
        vec![Id, Method, Host, Status, Source]
    }
}

fn column_widths(columns: &[Column]) -> Vec<Constraint> {
    use Column::*;
    columns
        .iter()
        .map(|column| match column {
            Id => Constraint::Length(5),
            Method => Constraint::Length(7),
            Host | Path => Constraint::Min(10),
            Status => Constraint::Length(16),
            Size => Constraint::Length(8),
            Duration => Constraint::Length(8),
            Age => Constraint::Length(6),
            Source => Constraint::Length(5),
        })
        .collect()
}

fn table_header(theme: &Theme, columns: &[Column]) -> Row<'static> {
    use Column::*;
    let labels: Vec<&str> = columns
        .iter()
        .map(|column| match column {
            Id => "ID",
            Method => "METHOD",
            Host => "HOST",
            Path => "PATH",
            Status => "STATUS",
            Size => "SIZE",
            Duration => "TIME",
            Age => "AGE",
            Source => "SRC",
        })
        .collect();

    Row::new(
        labels
            .into_iter()
            .map(|label| Cell::from(Span::styled(label, theme.label())))
            .collect::<Vec<_>>(),
    )
    .style(Style::new().bg(theme.palette.surface))
}

fn build_row(
    theme: &Theme,
    entry: &TrafficEntry,
    selected: bool,
    columns: &[Column],
    now: chrono::DateTime<Utc>,
) -> Row<'static> {
    use Column::*;
    let marker = if selected { "▌" } else { " " };

    let mut cells = Vec::new();
    for column in columns {
        let cell = match column {
            Id => Cell::from(Line::from(vec![
                Span::styled(
                    marker,
                    if selected {
                        theme.accent()
                    } else {
                        theme.faint()
                    },
                ),
                Span::styled(format!("{:04}", entry.id.0), theme.faint()),
            ])),
            Method => Cell::from(Span::styled(
                entry.request.method.clone(),
                theme
                    .method(&entry.request.method)
                    .add_modifier(Modifier::BOLD),
            )),
            Host => Cell::from(Span::styled(entry.request.host.clone(), theme.text())),
            Path => Cell::from(Span::styled(
                if entry.kind == TrafficKind::ConnectTunnel {
                    "(CONNECT tunnel)".to_string()
                } else {
                    entry.request.target.clone()
                },
                theme.muted(),
            )),
            Status => Cell::from(Span::styled(
                lifecycle::short_label(entry),
                lifecycle::style(theme, entry),
            )),
            Size => Cell::from(Span::styled(
                format_bytes(entry.size_bytes()),
                theme.faint(),
            )),
            Duration => Cell::from(Span::styled(
                entry
                    .duration_ms()
                    .map_or_else(|| "—".to_string(), |ms| format!("{ms} ms")),
                theme.faint(),
            )),
            Age => Cell::from(Span::styled(
                format_age(entry.timings.started_at, now),
                theme.faint(),
            )),
            Source => Cell::from(source_badge(theme, entry.source)),
        };
        cells.push(cell);
    }

    Row::new(cells).style(Style::new().bg(if selected {
        theme.palette.selection
    } else {
        theme.palette.surface
    }))
}

#[cfg(test)]
mod tests {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use super::*;
    use crate::app::App;

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

    #[test]
    fn history_renders_filters_and_rows() {
        let app = App::demo();
        let theme = app.theme();
        let mut terminal = Terminal::new(TestBackend::new(120, 32)).unwrap();
        let mut output = RenderOutput::default();

        terminal
            .draw(|frame| {
                render(frame, Rect::new(0, 0, 120, 32), &app, &theme, &mut output);
            })
            .unwrap();

        let text = text_of(&terminal);
        assert!(text.contains("HTTP HISTORY"));
        assert!(text.contains("Method: all"));
        assert!(
            output
                .hits
                .iter()
                .any(|hit| matches!(hit.target, HitTarget::HistoryRow(_)))
        );
        assert!(
            output
                .hits
                .iter()
                .any(|hit| hit.target == HitTarget::SearchField)
        );
    }

    #[test]
    fn narrow_history_keeps_essential_columns() {
        assert_eq!(table_columns(50).len(), 5);
        assert_eq!(table_columns(70).len(), 6);
        assert_eq!(table_columns(110).len(), 9);
    }
}
