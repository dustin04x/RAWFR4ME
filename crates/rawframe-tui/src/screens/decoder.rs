//! Decoder workspace: bounded binary-safe transformations and a visible pipeline.

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Clear, Paragraph, Wrap};

use crate::app::App;
use crate::components::editor::render_editor_with_target;
use crate::components::{ButtonSpec, button_row, focused_panel, panel, truncate};
use crate::interaction::{ActionId, HitTarget, RenderOutput, ScrollRegion};
use crate::screens::render_heading;
use crate::state::{DecoderFocus, DecoderState};
use crate::theme::Theme;

pub fn render(frame: &mut Frame, area: Rect, app: &App, theme: &Theme, output: &mut RenderOutput) {
    let decoder = &app.decoder;
    render_heading(
        frame,
        Rect::new(area.x, area.y, area.width, 1),
        theme,
        "Decoder",
        "decode · transform · chain",
        Some(if decoder.running {
            "RUNNING"
        } else if decoder.error.is_some() {
            "ERROR"
        } else {
            "8 MiB BOUND"
        }),
        if decoder.error.is_some() {
            theme.danger()
        } else {
            theme.muted()
        },
    );
    if area.height < 8 {
        return;
    }

    let mut y = area.y + 1;
    let compact = area.width < 100;
    let buttons = if compact {
        vec![
            ButtonSpec::new("Run", ActionId::DecoderExecute, !decoder.running)
                .primary()
                .key("^↵"),
            ButtonSpec::new("Add", ActionId::DecoderAddStep, true).key("A"),
            ButtonSpec::new(
                "Del",
                ActionId::DecoderRemoveStep,
                !decoder.pipeline.is_empty(),
            ),
            ButtonSpec::new("Swap", ActionId::DecoderSwap, decoder.output.is_some()).key("S"),
            ButtonSpec::new(
                "Copy",
                ActionId::DecoderCopy,
                !decoder.displayed_bytes.is_empty(),
            )
            .key("Y"),
        ]
    } else {
        vec![
            ButtonSpec::new("Run", ActionId::DecoderExecute, !decoder.running)
                .primary()
                .key("^↵"),
            ButtonSpec::new("Add Step", ActionId::DecoderAddStep, true).key("A"),
            ButtonSpec::new(
                "Remove",
                ActionId::DecoderRemoveStep,
                !decoder.pipeline.is_empty(),
            ),
            ButtonSpec::new("Move ↑", ActionId::DecoderMoveStepUp, true),
            ButtonSpec::new("Move ↓", ActionId::DecoderMoveStepDown, true),
            ButtonSpec::new("Swap", ActionId::DecoderSwap, decoder.output.is_some()).key("S"),
            ButtonSpec::new("Clear", ActionId::DecoderClear, true).key("C"),
            ButtonSpec::new(
                "Copy",
                ActionId::DecoderCopy,
                !decoder.displayed_bytes.is_empty(),
            )
            .key("Y"),
            ButtonSpec::new(
                "To Repeater",
                ActionId::DecoderSendToRepeater,
                decoder.output.is_some(),
            ),
            ButtonSpec::new("History", ActionId::DecoderHistory, true).key("H"),
        ]
    };
    button_row(
        frame,
        Rect::new(area.x, y, area.width, 1),
        &buttons,
        theme,
        app.hover.as_ref(),
        output,
    );
    y += 1;

    render_selector(
        frame,
        Rect::new(area.x, y, area.width, 1),
        decoder,
        theme,
        output,
    );
    y += 1;

    let pipeline_height = if area.height >= 34 {
        5
    } else if area.height >= 24 {
        4
    } else {
        3
    };
    let remaining = area.bottom().saturating_sub(y + pipeline_height + 1);
    if remaining < 4 {
        return;
    }
    let split = if area.width >= 100 {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(Rect::new(area.x, y, area.width, remaining))
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(Rect::new(area.x, y, area.width, remaining))
    };
    render_input(frame, split[0], decoder, theme, output);
    render_output(frame, split[1], decoder, theme, output);
    y += remaining;

    render_pipeline(
        frame,
        Rect::new(area.x, y, area.width, pipeline_height),
        decoder,
        theme,
        output,
    );
    y += pipeline_height;
    render_meta(frame, Rect::new(area.x, y, area.width, 1), decoder, theme);

    if decoder.history_open {
        render_history(frame, area, decoder, theme, output);
    }
}

fn render_selector(
    frame: &mut Frame,
    area: Rect,
    decoder: &DecoderState,
    theme: &Theme,
    output: &mut RenderOutput,
) {
    if area.width == 0 {
        return;
    }
    let prev = Rect::new(area.x, area.y, 3, 1);
    let next = Rect::new(area.x + 3, area.y, 3, 1);
    let direction_width = 11;
    let add_width = 7;
    let label_start = area.x + 6;
    let label_width = area
        .width
        .saturating_sub(6 + 2 + direction_width + add_width)
        .max(8);
    let direction = Rect::new(label_start + label_width + 2, area.y, direction_width, 1);
    let add = Rect::new(
        direction.right().saturating_sub(add_width),
        area.y,
        add_width,
        1,
    );

    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(" ‹ ", theme.secondary_button()),
            Span::styled("› ", theme.secondary_button()),
            Span::styled("TRANSFORM  ", theme.label()),
            Span::styled(
                truncate(decoder.selected_transform().label(), label_width as usize),
                theme.accent_bold(),
            ),
            Span::styled(
                format!("  {} ", decoder.selected_transform().direction().label()),
                theme.muted(),
            ),
            Span::styled(" ADD ", theme.primary_button()),
        ]))
        .style(Style::new().bg(theme.palette.bg)),
        area,
    );
    output.hit(prev, HitTarget::Action(ActionId::DecoderTransformPrev));
    output.hit(next, HitTarget::Action(ActionId::DecoderTransformNext));
    output.hit(
        direction,
        HitTarget::Action(ActionId::DecoderToggleDirection),
    );
    output.hit(add, HitTarget::Action(ActionId::DecoderAddStep));
}

fn render_input(
    frame: &mut Frame,
    area: Rect,
    decoder: &DecoderState,
    theme: &Theme,
    output: &mut RenderOutput,
) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let format = if decoder.input_binary {
        "BINARY"
    } else {
        "TEXT"
    };
    let title = format!(
        "INPUT · {} · {} B · {format}",
        decoder.source_label,
        decoder.input_bytes.len()
    );
    let focused = decoder.focus == DecoderFocus::Input || decoder.editing;
    let block = focused_panel(theme, &truncate(&title, area.width as usize), focused);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.width > 0 && inner.height > 0 {
        render_editor_with_target(
            frame,
            inner,
            theme,
            &decoder.input,
            decoder.editing,
            output,
            HitTarget::DecoderEditor,
            ScrollRegion::DecoderEditor,
        );
    }
}

fn render_output(
    frame: &mut Frame,
    area: Rect,
    decoder: &DecoderState,
    theme: &Theme,
    output: &mut RenderOutput,
) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let title = format!(
        "{} · {} · {}",
        decoder.displayed_label,
        decoder.displayed_format.label(),
        format_bytes(decoder.displayed_bytes.len())
    );
    let focused = decoder.focus == DecoderFocus::Output;
    let block = focused_panel(theme, &truncate(&title, area.width as usize), focused);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.width == 0 || inner.height == 0 {
        return;
    }
    output.zone(inner, ScrollRegion::DecoderOutput);
    if decoder.output_display.is_empty() {
        let message = if decoder.running {
            "Transformation running…"
        } else if decoder.error.is_some() {
            "No output: the pipeline stopped at an error."
        } else {
            "No output yet. Run the pipeline with Ctrl+Enter."
        };
        frame.render_widget(
            Paragraph::new(message)
                .style(theme.muted())
                .wrap(Wrap { trim: true }),
            inner,
        );
        return;
    }
    let lines: Vec<Line<'static>> = decoder
        .output_display
        .lines()
        .map(|line| Line::from(Span::styled(line.to_string(), theme.text())))
        .collect();
    frame.render_widget(
        Paragraph::new(lines)
            .scroll((decoder.output_scroll, 0))
            .style(Style::new().bg(theme.palette.surface)),
        inner,
    );
}

fn render_pipeline(
    frame: &mut Frame,
    area: Rect,
    decoder: &DecoderState,
    theme: &Theme,
    output: &mut RenderOutput,
) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let focused = decoder.focus == DecoderFocus::Pipeline;
    let block = focused_panel(theme, "PIPELINE", focused);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.width == 0 || inner.height == 0 {
        return;
    }
    output.zone(inner, ScrollRegion::DecoderPipeline);
    let mut lines = Vec::new();
    if decoder.pipeline.is_empty() {
        lines.push(Line::from(vec![
            Span::styled(
                "No steps. Select a transform above and press ",
                theme.muted(),
            ),
            Span::styled("A", theme.accent_bold()),
            Span::styled(" to add one.", theme.muted()),
        ]));
    } else {
        let visible = inner.height as usize;
        let start =
            crate::screens::window_start(decoder.selected_step, decoder.pipeline.len(), visible);
        for index in start..(start + visible).min(decoder.pipeline.len()) {
            let step = decoder.pipeline[index];
            let result = decoder.steps.get(index);
            let detail = result
                .map(|step| {
                    format!(
                        "{}→{} B · {}",
                        step.input_bytes,
                        step.output_bytes,
                        step.format.label()
                    )
                })
                .unwrap_or_else(|| "not run".into());
            let selected = index == decoder.selected_step;
            let marker = if selected { "▸ " } else { "  " };
            let style = if selected {
                theme.selected_accent()
            } else {
                theme.text()
            };
            let previewed = decoder.view_step == Some(index);
            lines.push(Line::from(vec![
                Span::styled(marker, theme.accent_bold()),
                Span::styled(format!("{}. ", index + 1), theme.faint()),
                Span::styled(step.label().to_string(), style),
                Span::styled(format!("  {detail}"), theme.muted()),
                if previewed {
                    Span::styled("  VIEWING", theme.warning())
                } else {
                    Span::raw("")
                },
            ]));
            if let Some(error) = &decoder.error
                && error.step_index == index
            {
                lines.push(Line::from(vec![
                    Span::styled("     ✕ ", theme.danger()),
                    Span::styled(
                        truncate(&error.message, inner.width.saturating_sub(8) as usize),
                        theme.danger(),
                    ),
                ]));
            }
        }
    }
    frame.render_widget(
        Paragraph::new(lines).style(Style::new().bg(theme.palette.surface)),
        inner,
    );
}

fn render_meta(frame: &mut Frame, area: Rect, decoder: &DecoderState, theme: &Theme) {
    if area.width == 0 {
        return;
    }
    let status = if decoder.running {
        Span::styled("RUNNING", theme.warning())
    } else if let Some(error) = &decoder.error {
        Span::styled(format!("FAILED · {}", error.label()), theme.danger())
    } else if decoder.output.is_some() {
        Span::styled("COMPLETE", theme.success())
    } else {
        Span::styled("READY", theme.muted())
    };
    let note = decoder
        .displayed_note
        .as_deref()
        .map(|note| truncate(note, area.width.saturating_sub(52) as usize))
        .unwrap_or_default();
    let line = Line::from(vec![
        Span::styled(" IN ", theme.label()),
        Span::styled(format!("{} B", decoder.input_bytes.len()), theme.text()),
        Span::styled("   OUT ", theme.label()),
        Span::styled(format!("{} B", decoder.displayed_bytes.len()), theme.text()),
        Span::styled("   ", theme.faint()),
        status,
        Span::styled("   ", theme.faint()),
        Span::styled(
            truncate(&note, area.width.saturating_sub(48) as usize),
            theme.muted(),
        ),
        Span::styled("   H history", theme.faint()),
    ]);
    frame.render_widget(
        Paragraph::new(line).style(Style::new().bg(theme.palette.bg)),
        area,
    );
}

fn render_history(
    frame: &mut Frame,
    area: Rect,
    decoder: &DecoderState,
    theme: &Theme,
    output: &mut RenderOutput,
) {
    let width = area.width.saturating_sub(8).min(120);
    let height = area.height.saturating_sub(4).min(28);
    if width < 20 || height < 5 {
        return;
    }
    let rect = Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    );
    frame.render_widget(Clear, rect);
    let block = panel(theme, "DECODER HISTORY · CURRENT SESSION");
    let inner = block.inner(rect);
    frame.render_widget(block, rect);
    if inner.width == 0 || inner.height == 0 {
        return;
    }
    output.zone(inner, ScrollRegion::DecoderHistory);
    if decoder.history.is_empty() {
        frame.render_widget(
            Paragraph::new("No transformations have run in this session.")
                .style(theme.muted())
                .wrap(Wrap { trim: true }),
            inner,
        );
        return;
    }
    let visible = inner.height as usize;
    let start = crate::screens::window_start(
        decoder.history_scroll as usize,
        decoder.history.len(),
        visible,
    );
    let mut lines = Vec::new();
    for index in start..(start + visible).min(decoder.history.len()) {
        let entry = &decoder.history[index];
        let chain = if entry.steps.is_empty() {
            "passthrough".to_string()
        } else {
            entry
                .steps
                .iter()
                .map(|step| step.label())
                .collect::<Vec<_>>()
                .join(" → ")
        };
        let selected = index == decoder.history_scroll as usize;
        let style = if selected {
            theme.selected_accent()
        } else {
            theme.text()
        };
        lines.push(Line::from(vec![
            Span::styled(if selected { "▸ " } else { "  " }, theme.accent_bold()),
            Span::styled(format!("#{:<3} ", entry.sequence), theme.faint()),
            Span::styled(entry.at.clone(), theme.faint()),
            Span::styled("  ", theme.faint()),
            Span::styled(
                truncate(&chain, inner.width.saturating_sub(34) as usize),
                style,
            ),
        ]));
        lines.push(Line::from(vec![
            Span::styled("     ", theme.faint()),
            Span::styled(entry.result.clone(), theme.muted()),
            Span::styled(
                format!("  · {} → {} B", entry.input_bytes, entry.output_bytes),
                theme.faint(),
            ),
        ]));
        output.hit(
            Rect::new(inner.x, inner.y + (index - start) as u16, inner.width, 1),
            HitTarget::DecoderHistoryRow(index),
        );
    }
    frame.render_widget(
        Paragraph::new(lines).style(Style::new().bg(theme.palette.surface)),
        inner,
    );
    frame.render_widget(
        Paragraph::new(Span::styled("Esc/H close · ↑↓ select", theme.faint()))
            .alignment(ratatui::layout::Alignment::Right),
        Rect::new(rect.x, rect.bottom().saturating_sub(1), rect.width, 1),
    );
}

fn format_bytes(bytes: usize) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
    }
}

#[cfg(test)]
mod tests {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use super::*;

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
    fn decoder_renders_selector_pipeline_and_panels() {
        let mut app = App::demo();
        app.navigate(crate::interaction::NavSection::Decoder);
        app.decoder.load_input(b"aGVsbG8=".to_vec(), "TEST");
        app.decoder
            .pipeline
            .push(rawframe_core::decoder::Transform::Base64Decode);
        app.decoder.add_step().unwrap();
        let theme = app.theme();
        let mut terminal = Terminal::new(TestBackend::new(140, 40)).unwrap();
        let mut output = RenderOutput::default();
        terminal
            .draw(|frame| {
                render(frame, Rect::new(0, 0, 140, 40), &app, &theme, &mut output);
            })
            .unwrap();
        let text = text_of(&terminal);
        assert!(text.contains("DECODER"));
        assert!(text.contains("TRANSFORM"));
        assert!(text.contains("PIPELINE"));
        assert!(text.contains("INPUT"));
        assert!(text.contains("OUTPUT"));
        assert!(text.contains("Base64 decode"));
        assert!(text.contains("Run"));
    }

    #[test]
    fn decoder_renders_at_supported_sizes() {
        for (width, height) in [(140, 40), (100, 30), (80, 24)] {
            let mut app = App::demo();
            app.navigate(crate::interaction::NavSection::Decoder);
            app.decoder.load_input(b"{\"a\":1}".to_vec(), "TEST");
            let theme = app.theme();
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            let mut output = RenderOutput::default();
            terminal
                .draw(|frame| {
                    render(
                        frame,
                        Rect::new(0, 0, width, height),
                        &app,
                        &theme,
                        &mut output,
                    );
                })
                .unwrap();
            let text = text_of(&terminal);
            assert!(text.contains("DECODER"), "{width}x{height}");
            assert!(text.contains("PIPELINE"), "{width}x{height}");
            assert!(
                text.contains("INPUT") && text.contains("OUTPUT"),
                "{width}x{height}"
            );
        }
    }
}
