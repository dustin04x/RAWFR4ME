//! Multi-line document editor rendering with a line-number gutter.

use ratatui::Frame;
use ratatui::layout::{Position, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::interaction::{HitTarget, RenderOutput, ScrollRegion};
use crate::text::TextBuffer;
use crate::theme::Theme;

pub fn render_editor(
    frame: &mut Frame,
    area: Rect,
    theme: &Theme,
    buffer: &TextBuffer,
    focused: bool,
    output: &mut RenderOutput,
) {
    render_editor_with_target(
        frame,
        area,
        theme,
        buffer,
        focused,
        output,
        HitTarget::RepeaterEditor,
        ScrollRegion::RepeaterEditor,
    );
}

#[allow(clippy::too_many_arguments)]
pub fn render_editor_with_target(
    frame: &mut Frame,
    area: Rect,
    theme: &Theme,
    buffer: &TextBuffer,
    focused: bool,
    output: &mut RenderOutput,
    hit_target: HitTarget,
    scroll_region: ScrollRegion,
) {
    if area.width == 0 || area.height == 0 {
        return;
    }

    let digits = buffer.line_count().to_string().len().max(2) as u16;
    let gutter_width = digits + 3;
    let content_cols = area.width.saturating_sub(gutter_width);
    let rows = area.height as usize;
    let start = (buffer.scroll() as usize).min(buffer.line_count().saturating_sub(1));
    let end = (start + rows).min(buffer.line_count());

    let mut lines: Vec<Line<'static>> = Vec::with_capacity(end.saturating_sub(start));
    for index in start..end {
        let text = buffer.line(index).unwrap_or("");
        let visible: String = text
            .chars()
            .skip(buffer.hscroll() as usize)
            .take(content_cols as usize)
            .collect();
        let is_cursor_line = index == buffer.row() && focused;
        let line_style = if is_cursor_line {
            Style::new()
                .bg(theme.palette.surface_elevated)
                .fg(theme.palette.text)
        } else {
            Style::new().fg(theme.palette.text)
        };
        let number_style = if is_cursor_line {
            theme.accent_bold()
        } else {
            theme.faint()
        };

        lines.push(Line::from(vec![
            Span::styled(
                format!("{:>width$} ", index + 1, width = digits as usize),
                number_style,
            ),
            Span::styled("│ ", theme.border()),
            Span::styled(visible, line_style),
        ]));
    }

    frame.render_widget(
        Paragraph::new(lines).style(Style::new().bg(theme.palette.surface)),
        area,
    );

    if focused {
        let cursor_row = buffer.row().saturating_sub(start);
        let cursor_col = buffer.col().saturating_sub(buffer.hscroll() as usize);
        if cursor_row < rows
            && cursor_col < content_cols as usize
            && area.height > 0
            && area.width > gutter_width
        {
            let x = area.x + gutter_width + cursor_col as u16;
            let y = area.y + cursor_row as u16;
            if x < area.right() && y < area.bottom() {
                frame.render_widget(
                    Paragraph::new(Span::styled(
                        "▏",
                        Style::new()
                            .fg(theme.palette.accent_bright)
                            .bg(theme.palette.surface_elevated)
                            .add_modifier(Modifier::BOLD),
                    )),
                    Rect::new(x, y, 1, 1),
                );
            }
        }
    }

    output.hit(area, hit_target);
    output.zone(area, scroll_region);
    output.repeater_rows = area.height;
    output.repeater_cols = content_cols;
    output.editor_origin = Some(Position::new(area.x + gutter_width, area.y));
    output.editor_gutter = gutter_width;
}

#[cfg(test)]
mod tests {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use super::*;
    use crate::theme::Theme;

    #[test]
    fn editor_renders_gutter_and_records_geometry() {
        let backend = TestBackend::new(60, 8);
        let mut terminal = Terminal::new(backend).unwrap();
        let theme = Theme::from_preset(rawframe_core::AccentPreset::Violet);
        let buffer = TextBuffer::from_text("GET / HTTP/1.1\nHost: api.rawframe.test");
        let mut output = RenderOutput::default();

        terminal
            .draw(|frame| {
                render_editor(
                    frame,
                    Rect::new(0, 0, 60, 8),
                    &theme,
                    &buffer,
                    false,
                    &mut output,
                );
            })
            .unwrap();

        assert_eq!(output.repeater_rows, 8);
        assert!(output.editor_origin.is_some());
        assert!(output.editor_gutter >= 5);
        let text = buffer_text(&terminal);
        assert!(text.contains("GET / HTTP/1.1"));
        assert!(text.contains("Host: api.rawframe.test"));
    }

    fn buffer_text(terminal: &Terminal<TestBackend>) -> String {
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
}
