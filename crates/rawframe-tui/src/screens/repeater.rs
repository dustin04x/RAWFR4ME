//! Repeater workspace: editable request documents with multiple tabs.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::app::App;
use crate::components::editor::render_editor;
use crate::components::{ButtonSpec, button_row, empty_state, focused_panel, truncate};
use crate::interaction::{ActionId, HitTarget, RenderOutput, ScrollRegion};
use crate::screens::render_heading;
use crate::theme::Theme;

pub fn render(frame: &mut Frame, area: Rect, app: &App, theme: &Theme, output: &mut RenderOutput) {
    render_heading(
        frame,
        Rect::new(area.x, area.y, area.width, 1),
        theme,
        "Repeater",
        "compose · parse · inspect",
        Some("TRANSMISSION OFFLINE"),
        theme.warning(),
    );

    let mut y = area.y + 1;
    if area.height < 8 {
        return;
    }

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

    let used = button_row(
        frame,
        Rect::new(area.x, y, area.width, 1),
        &[
            ButtonSpec::new("Send", ActionId::SendRepeater, true).key("^⏎"),
            ButtonSpec::new("New", ActionId::NewRepeaterTab, true).key("^N"),
            ButtonSpec::new("Close", ActionId::CloseRepeaterTab, true).key("^W"),
        ],
        theme,
        app.hover.as_ref(),
        output,
    );
    y += 1;

    let status_width = area.width.saturating_sub(used + 2);
    if status_width > 12 {
        let (label, style) = match (&tab.parse_error, &tab.parse_summary) {
            (Some(_), _) => ("PARSE ERROR", theme.danger()),
            (None, Some(_)) => ("VALID REQUEST", theme.success()),
            _ => ("UNPARSED", theme.faint()),
        };
        frame.render_widget(
            Paragraph::new(Span::styled(label, style.add_modifier(Modifier::BOLD)))
                .alignment(ratatui::layout::Alignment::Right)
                .style(Style::new().bg(theme.palette.bg)),
            Rect::new(area.x + used + 2, y, status_width, 1),
        );
    }
    y += 2;

    let status_height = 1.min(area.bottom().saturating_sub(y));
    let editor_height = area
        .bottom()
        .saturating_sub(y)
        .saturating_sub(status_height);
    let editor_area = Rect::new(area.x, y, area.width, editor_height);

    let title = format!(
        "REQUEST DOCUMENT · {} · {}",
        tab.origin.label(),
        if tab.origin.is_simulated() {
            "SIMULATED"
        } else {
            "LOCAL DRAFT"
        }
    );
    let block = focused_panel(theme, &title, app.repeater.editing);
    let inner = block.inner(editor_area);
    frame.render_widget(block, editor_area);
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

    if status_height > 0 {
        render_status_line(
            frame,
            Rect::new(area.x, area.bottom().saturating_sub(1), area.width, 1),
            app,
            theme,
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
            truncate(
                &format!("{} {}", tab.origin.label(), tab.title()),
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

fn render_status_line(frame: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let Some(tab) = app.active_repeater_tab() else {
        return;
    };
    let left_style = if tab.parse_error.is_some() {
        theme.danger()
    } else {
        theme.faint()
    };
    let text = match (&tab.parse_error, &tab.parse_summary) {
        (Some(error), _) => format!("parse error · {error}"),
        (None, Some(summary)) => summary.clone(),
        _ => "unparsed document".to_string(),
    };
    let hint = if app.repeater.editing {
        "Esc · exit editing   ^↵ · send"
    } else {
        "Enter · edit document   ←/→ · switch tab"
    };

    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                truncate(&text, area.width.saturating_sub(24) as usize),
                left_style,
            ),
            Span::raw("  "),
            Span::styled(hint, theme.faint()),
            Span::raw(" "),
            Span::styled("TRANSMISSION OFFLINE", theme.warning()),
        ]))
        .style(Style::new().bg(theme.palette.bg)),
        area,
    );
}

/// Right-hand context panel for the Repeater. Deliberately shows no fabricated
/// response: transmission is not part of this milestone.
pub fn render_response_panel(
    frame: &mut Frame,
    area: Rect,
    app: &App,
    theme: &Theme,
    output: &mut RenderOutput,
) {
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

    let mut lines = vec![
        Line::from(Span::styled(
            truncate(&tab.url(), inner.width as usize),
            theme.muted(),
        )),
        Line::from(Span::styled(
            tab.origin.label().to_string(),
            if tab.is_simulated() {
                theme.warning()
            } else {
                theme.faint()
            },
        )),
        Line::from(""),
        Line::from(Span::styled("TRANSMISSION OFFLINE", theme.warning())),
        Line::from(""),
        Line::from(Span::styled(
            "Repeater delivery is not implemented in this build.",
            theme.muted(),
        )),
        Line::from(Span::styled(
            "RAWFRAME does not fabricate responses. Sending arrives with the proxy milestone.",
            theme.muted(),
        )),
    ];
    if let Some(error) = &tab.parse_error {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("Parse error: {error}"),
            theme.danger(),
        )));
    } else if let Some(summary) = &tab.parse_summary {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(summary.clone(), theme.faint())));
    }

    let content = Rect::new(
        inner.x,
        inner.y + 1,
        inner.width,
        inner.height.saturating_sub(1),
    );
    frame.render_widget(
        Paragraph::new(lines)
            .scroll((app.repeater.response_scroll, 0))
            .style(Style::new().bg(theme.palette.surface)),
        content,
    );
    output.zone(content, ScrollRegion::Inspector);
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
    fn repeater_renders_tabs_editor_and_offline_status() {
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
        assert!(text.contains("REQUEST DOCUMENT"));
        assert!(text.contains("TRANSMISSION OFFLINE"));
        assert!(
            output
                .hits
                .iter()
                .any(|hit| hit.target == HitTarget::RepeaterEditor)
        );
        assert!(
            output
                .hits
                .iter()
                .any(|hit| matches!(hit.target, HitTarget::RepeaterTab(_)))
        );
    }

    #[test]
    fn response_panel_states_that_no_response_is_fabricated() {
        let app = App::demo();
        let theme = app.theme();
        let mut terminal = Terminal::new(TestBackend::new(46, 24)).unwrap();
        let mut output = RenderOutput::default();

        terminal
            .draw(|frame| {
                render_response_panel(frame, Rect::new(0, 0, 46, 24), &app, &theme, &mut output);
            })
            .unwrap();

        let text = text_of(&terminal);
        assert!(text.contains("RESPONSE"));
        assert!(text.contains("does not fabricate"));
        assert!(
            output
                .zones
                .iter()
                .any(|zone| zone.region == ScrollRegion::Inspector)
        );
    }
}
