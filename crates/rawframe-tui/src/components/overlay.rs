//! Modal overlays: command palette, context menu, confirmation and help.

use ratatui::Frame;
use ratatui::layout::{Alignment, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Paragraph, Wrap};

use crate::commands::CommandSpec;
use crate::components::{panel, truncate};
use crate::interaction::{HitTarget, RenderOutput, ScrollRegion};
use crate::state::{ConfirmState, ContextMenuState, PaletteState};
use crate::theme::Theme;

fn overlay_frame(frame: &mut Frame, area: Rect, theme: &Theme, title: &str) -> Rect {
    let shadow = Rect::new(
        area.x
            .saturating_add(1)
            .min(frame.area().right().saturating_sub(area.width)),
        area.y
            .saturating_add(1)
            .min(frame.area().bottom().saturating_sub(area.height)),
        area.width,
        area.height,
    );
    frame.render_widget(
        Block::new().style(Style::new().bg(Color::Rgb(0, 0, 0))),
        shadow,
    );
    frame.render_widget(Clear, area);
    let block = panel(theme, title).border_style(theme.accent());
    let inner = block.inner(area);
    frame.render_widget(block, area);
    inner
}

fn clamp_rect(screen: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(screen.width.saturating_sub(2)).max(1);
    let height = height.min(screen.height.saturating_sub(2)).max(1);
    Rect::new(
        screen.x + screen.width.saturating_sub(width) / 2,
        screen.y + screen.height.saturating_sub(height) / 2,
        width,
        height,
    )
}

pub fn render_palette(
    frame: &mut Frame,
    screen: Rect,
    theme: &Theme,
    palette: &PaletteState,
    results: &[&CommandSpec],
    output: &mut RenderOutput,
) {
    output.hit(screen, HitTarget::DismissOverlay);

    let width = screen.width.saturating_sub(16).clamp(44, 78);
    let height = screen.height.saturating_sub(6).clamp(12, 22);
    let area = clamp_rect(screen, width, height);
    let inner = overlay_frame(frame, area, theme, "COMMAND PALETTE");
    output.hit(area, HitTarget::OverlaySurface);
    if inner.height < 4 || inner.width < 10 {
        return;
    }

    let query_line = if palette.query.is_empty() {
        Line::from(vec![
            Span::styled("❯ ", theme.accent_bold()),
            Span::styled("Type a command…", theme.faint()),
        ])
    } else {
        Line::from(vec![
            Span::styled("❯ ", theme.accent_bold()),
            Span::styled(palette.query.clone(), theme.text()),
            Span::styled("▏", theme.accent()),
        ])
    };
    frame.render_widget(
        Paragraph::new(query_line).style(Style::new().bg(theme.palette.surface)),
        Rect::new(inner.x, inner.y, inner.width, 1),
    );

    let divider = "─".repeat(inner.width as usize);
    frame.render_widget(
        Paragraph::new(Span::styled(divider, theme.border())),
        Rect::new(inner.x, inner.y + 1, inner.width, 1),
    );

    let list_top = inner.y + 2;
    let list_height = inner.height.saturating_sub(3) as usize;
    let selected = palette.selected.min(results.len().saturating_sub(1));
    let start = if results.len() <= list_height {
        0
    } else {
        selected
            .saturating_sub(list_height.saturating_sub(1))
            .min(results.len() - list_height)
    };

    if results.is_empty() {
        frame.render_widget(
            Paragraph::new(Span::styled("No matching commands.", theme.faint()))
                .style(Style::new().bg(theme.palette.surface)),
            Rect::new(inner.x, list_top, inner.width, 1),
        );
    }

    for (row, command) in results.iter().skip(start).take(list_height).enumerate() {
        let index = start + row;
        let is_selected = index == selected;
        let row_y = list_top + row as u16;
        let rect = Rect::new(inner.x, row_y, inner.width, 1);
        let base = if is_selected {
            theme.selected()
        } else {
            Style::new().bg(theme.palette.surface)
        };

        let title_style = if is_selected {
            theme.selected_accent()
        } else {
            theme.text()
        };
        let group_style = if is_selected {
            theme.selected()
        } else {
            theme.faint()
        };
        let shortcut = command.shortcut.unwrap_or_default();
        let used = command.title.chars().count()
            + command.group.chars().count()
            + 2
            + shortcut.chars().count();
        let gap = (inner.width as usize).saturating_sub(used + 1);

        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(format!(" {} ", truncate(command.title, 32)), title_style),
                Span::styled(command.group.to_string(), group_style),
                Span::raw(" ".repeat(gap)),
                Span::styled(shortcut.to_string(), group_style),
                Span::raw(" "),
            ]))
            .style(base),
            rect,
        );
        output.hit(rect, HitTarget::PaletteRow(index));
    }
    output.zone(
        Rect::new(
            inner.x,
            list_top,
            inner.width,
            list_height.min(u16::MAX as usize) as u16,
        ),
        ScrollRegion::Palette,
    );

    frame.render_widget(
        Paragraph::new(Span::styled("↑↓ move   ↵ run   esc close", theme.faint()))
            .alignment(Alignment::Right)
            .style(Style::new().bg(theme.palette.surface)),
        Rect::new(inner.x, inner.bottom().saturating_sub(1), inner.width, 1),
    );
}

pub fn render_menu(
    frame: &mut Frame,
    screen: Rect,
    theme: &Theme,
    menu: &ContextMenuState,
    output: &mut RenderOutput,
) {
    output.hit(screen, HitTarget::DismissOverlay);

    let width = 34.min(screen.width.saturating_sub(2));
    let height = (menu.items.len() as u16 + 2).min(screen.height.saturating_sub(2));
    let x = menu.x.min(screen.right().saturating_sub(width));
    let y = menu.y.min(screen.bottom().saturating_sub(height));
    let area = Rect::new(x.max(screen.x), y.max(screen.y), width, height);

    frame.render_widget(Clear, area);
    let block = panel(theme, "ACTIONS").border_style(theme.border_strong());
    let inner = block.inner(area);
    frame.render_widget(block, area);
    output.hit(area, HitTarget::OverlaySurface);
    if inner.height == 0 {
        return;
    }

    for (index, item) in menu.items.iter().take(inner.height as usize).enumerate() {
        let selected = index == menu.selected;
        let rect = Rect::new(inner.x, inner.y + index as u16, inner.width, 1);
        let style = if selected {
            if item.danger {
                Style::new()
                    .bg(theme.palette.danger)
                    .fg(theme.palette.bg)
                    .add_modifier(Modifier::BOLD)
            } else {
                theme.selected()
            }
        } else if item.danger {
            Style::new()
                .fg(theme.palette.danger)
                .bg(theme.palette.surface)
        } else {
            Style::new()
                .fg(theme.palette.text)
                .bg(theme.palette.surface)
        };
        let marker = if selected { "▸ " } else { "  " };
        frame.render_widget(
            Paragraph::new(Span::styled(format!("{marker}{}", item.label), style))
                .style(Style::new().bg(theme.palette.surface)),
            rect,
        );
        output.hit(rect, HitTarget::MenuItem(index));
    }
}

pub fn render_confirm(
    frame: &mut Frame,
    screen: Rect,
    theme: &Theme,
    confirm: &ConfirmState,
    output: &mut RenderOutput,
) {
    output.hit(screen, HitTarget::DismissOverlay);

    let area = clamp_rect(screen, 58, 10);
    let inner = overlay_frame(frame, area, theme, "CONFIRM");
    output.hit(area, HitTarget::OverlaySurface);
    if inner.height < 4 {
        return;
    }

    frame.render_widget(
        Paragraph::new(Span::styled(confirm.title.clone(), theme.title()))
            .style(Style::new().bg(theme.palette.surface)),
        Rect::new(inner.x, inner.y, inner.width, 1),
    );
    frame.render_widget(
        Paragraph::new(confirm.body.clone())
            .wrap(Wrap { trim: true })
            .style(
                Style::new()
                    .fg(theme.palette.muted)
                    .bg(theme.palette.surface),
            ),
        Rect::new(
            inner.x,
            inner.y + 2,
            inner.width,
            inner.height.saturating_sub(4),
        ),
    );

    let button_y = inner.bottom().saturating_sub(1);
    let cancel = Rect::new(inner.x, button_y, 12, 1);
    let confirm_button = Rect::new(inner.x + 13, button_y, 18, 1);
    frame.render_widget(
        Paragraph::new(Span::styled(" Cancel  esc", theme.secondary_button())),
        cancel,
    );
    frame.render_widget(
        Paragraph::new(Span::styled(
            format!(" {}  ↵", truncate(confirm.confirm_label, 10)),
            theme.on_danger(),
        )),
        confirm_button,
    );
    output.hit(cancel, HitTarget::Confirm(false));
    output.hit(confirm_button, HitTarget::Confirm(true));
}

pub fn render_help(frame: &mut Frame, screen: Rect, theme: &Theme, output: &mut RenderOutput) {
    output.hit(screen, HitTarget::DismissOverlay);

    let width = screen.width.saturating_sub(12).clamp(54, 92);
    let height = screen.height.saturating_sub(4).clamp(16, 30);
    let area = clamp_rect(screen, width, height);
    let inner = overlay_frame(frame, area, theme, "KEYBOARD & INTERACTION");
    output.hit(area, HitTarget::OverlaySurface);
    if inner.height < 4 {
        return;
    }

    let sections: &[(&str, &[(&str, &str)])] = &[
        (
            "GLOBAL",
            &[
                ("^K", "Command palette"),
                ("^1 … ^6", "Jump to a module"),
                ("Tab / ⇧Tab", "Cycle focus"),
                ("^F", "Search HTTP history"),
                ("I", "Toggle inspector"),
                ("R / E", "Replay / edit selected request"),
                ("Q", "Quit (Ctrl+C always exits)"),
            ],
        ),
        (
            "PROXY & HISTORY",
            &[
                ("↑ ↓", "Move selection"),
                ("Enter", "Inspect selected entry"),
                ("P", "Start/stop proxy"),
                ("I", "Toggle interception / inspector"),
                (
                    "F / E / S / D",
                    "Forward, edit, send modified, drop paused request",
                ),
                ("R", "Replay selected request"),
                ("M / S / H", "Cycle method, status, host filters"),
                ("Tab / ] [ / 1-3", "Focus and inspector views"),
            ],
        ),
        (
            "REPEATER",
            &[
                ("Ctrl+Enter", "Send request"),
                ("Enter", "Edit document"),
                ("← / →", "Previous / next tab"),
                ("^N / ^W", "New / close tab"),
                ("Esc", "Leave text editing"),
            ],
        ),
        (
            "MOUSE",
            &[
                ("Click", "Navigation, tabs, controls"),
                ("Double-click", "Open the inspector"),
                ("Right-click", "Context actions"),
                ("Drag divider", "Resize panels"),
                ("Wheel", "Scroll the panel under the pointer"),
            ],
        ),
    ];

    let mut lines: Vec<Line<'static>> = Vec::new();
    for (heading, entries) in sections {
        lines.push(Line::from(Span::styled(heading.to_string(), theme.label())));
        for (key, action) in *entries {
            lines.push(Line::from(vec![
                Span::styled(format!("  {key:<14}"), theme.accent()),
                Span::styled(action.to_string(), theme.text()),
            ]));
        }
        lines.push(Line::from(""));
    }
    frame.render_widget(
        Paragraph::new(lines).style(Style::new().bg(theme.palette.surface)),
        Rect::new(
            inner.x,
            inner.y,
            inner.width,
            inner.height.saturating_sub(1),
        ),
    );
    frame.render_widget(
        Paragraph::new(Span::styled("Esc or ? · close", theme.faint()))
            .alignment(Alignment::Right)
            .style(Style::new().bg(theme.palette.surface)),
        Rect::new(inner.x, inner.bottom().saturating_sub(1), inner.width, 1),
    );
}

#[cfg(test)]
mod tests {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use super::*;
    use crate::commands::COMMANDS;
    use crate::state::ConfirmAction;

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
    fn palette_renders_results_and_hits() {
        let theme = Theme::from_preset(rawframe_core::AccentPreset::Violet);
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
        let palette = PaletteState::new();
        let results: Vec<&CommandSpec> = COMMANDS.iter().take(6).collect();
        let mut output = RenderOutput::default();

        terminal
            .draw(|frame| {
                render_palette(
                    frame,
                    Rect::new(0, 0, 100, 30),
                    &theme,
                    &palette,
                    &results,
                    &mut output,
                );
            })
            .unwrap();

        let text = text_of(&terminal);
        assert!(text.contains("COMMAND PALETTE"));
        assert!(text.contains("Go to Proxy"));
        assert!(
            output
                .hits
                .iter()
                .any(|hit| matches!(hit.target, HitTarget::PaletteRow(0)))
        );
    }

    #[test]
    fn confirm_exposes_yes_and_no_targets() {
        let theme = Theme::from_preset(rawframe_core::AccentPreset::Violet);
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        let confirm = ConfirmState {
            title: "Quit?".into(),
            body: "Unsaved edits will be lost.".into(),
            confirm_label: "Quit",
            action: ConfirmAction::Quit,
        };
        let mut output = RenderOutput::default();

        terminal
            .draw(|frame| {
                render_confirm(
                    frame,
                    Rect::new(0, 0, 80, 24),
                    &theme,
                    &confirm,
                    &mut output,
                );
            })
            .unwrap();

        assert!(text_of(&terminal).contains("Leave") || text_of(&terminal).contains("Quit"));
        assert!(
            output
                .hits
                .iter()
                .any(|hit| hit.target == HitTarget::Confirm(true))
        );
        assert!(
            output
                .hits
                .iter()
                .any(|hit| hit.target == HitTarget::Confirm(false))
        );
    }
}
