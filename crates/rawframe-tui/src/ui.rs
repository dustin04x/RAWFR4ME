//! Composition of the persistent application shell.

use chrono::Local;
use ratatui::Frame;
use ratatui::layout::{Alignment, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::app::App;
use crate::components::inspector::{InspectorContext, render_inspector};
use crate::components::overlay::{
    render_confirm, render_help, render_menu, render_palette, render_scope_editor, render_sessions,
};
use crate::components::truncate;
use crate::interaction::{Focus, HitTarget, NavSection, RenderOutput};
use crate::layout::{DragTarget, compute};
use crate::screens;
use crate::theme::Theme;

pub fn render(frame: &mut Frame, app: &App) -> RenderOutput {
    let area = frame.area();
    let theme = app.theme();
    let mut output = RenderOutput {
        area,
        ..RenderOutput::default()
    };

    frame.render_widget(Block::new().style(theme.base()), area);

    if area.width == 0 || area.height == 0 {
        return output;
    }

    let layout = compute(area, &app.layout, app.nav.uses_context());
    if layout.too_small {
        render_too_small(frame, area, &theme);
        return output;
    }

    render_header(frame, layout.header, app, &theme);
    if let Some(sidebar) = layout.sidebar {
        render_sidebar(frame, sidebar, app, &theme, &mut output);
    }
    if let Some(divider) = layout.sidebar_divider {
        render_splitter(
            frame,
            divider,
            app,
            &theme,
            DragTarget::Sidebar,
            &mut output,
        );
    }

    render_workspace(frame, layout.workspace, app, &theme, &mut output);

    if let (Some(divider), Some(context)) = (layout.context_divider, layout.context) {
        render_splitter(
            frame,
            divider,
            app,
            &theme,
            DragTarget::Context,
            &mut output,
        );
        render_context(frame, context, app, &theme, &mut output);
    }

    render_footer(frame, layout.footer, app, &theme);

    if let Some(confirm) = &app.confirm {
        render_confirm(frame, area, &theme, confirm, &mut output);
    } else if let Some(palette) = &app.palette {
        let results = app.palette_results();
        render_palette(frame, area, &theme, palette, &results, &mut output);
    } else if let Some(menu) = &app.context_menu {
        render_menu(frame, area, &theme, menu, &mut output);
    } else if app.scope_editor().is_some() {
        render_scope_editor(frame, area, &theme, app, &mut output);
    } else if app.sessions_open() {
        render_sessions(frame, area, &theme, app, &mut output);
    } else if app.help_open {
        render_help(frame, area, &theme, &mut output);
    }

    output
}

fn render_workspace(
    frame: &mut Frame,
    area: Rect,
    app: &App,
    theme: &Theme,
    output: &mut RenderOutput,
) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    match app.nav {
        NavSection::Proxy => screens::proxy::render(frame, area, app, theme, output),
        NavSection::History => screens::history::render(frame, area, app, theme, output),
        NavSection::Repeater => screens::repeater::render(frame, area, app, theme, output),
        NavSection::Settings => screens::settings::render(frame, area, app, theme, output),
        NavSection::Intruder | NavSection::Decoder => {
            screens::placeholder::render(frame, area, app, theme, output)
        }
    }
}

fn render_context(
    frame: &mut Frame,
    area: Rect,
    app: &App,
    theme: &Theme,
    output: &mut RenderOutput,
) {
    match app.nav {
        NavSection::Proxy | NavSection::History => {
            let focused = app.focus == Focus::Context;
            render_inspector(
                frame,
                area,
                theme,
                InspectorContext {
                    entry: app.selected_traffic(),
                    inspector: &app.inspector,
                    redact: app.config.appearance.redact_sensitive_headers,
                    focused,
                },
                output,
            );
        }
        NavSection::Repeater => {
            screens::repeater::render_response_panel(frame, area, app, theme, output);
        }
        _ => {}
    }
}

fn render_header(frame: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let block = Block::new()
        .borders(Borders::BOTTOM)
        .border_style(theme.border())
        .style(Style::new().bg(theme.palette.bg));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.width == 0 || inner.height == 0 {
        return;
    }

    let workspace = app.nav.short_label();
    let left = format!(" RAWFRAME  |  {workspace} ");

    let listener = app
        .proxy_address()
        .map(|a| a.to_string())
        .unwrap_or_else(|| {
            format!(
                "{}:{}",
                app.config.proxy.bind_address, app.config.proxy.port
            )
        });
    let session = truncate(&app.session.name, 24);
    let center = if inner.width >= 110 {
        format!("{listener}  ·  {session}")
    } else {
        listener
    };

    let engine = match app.proxy_state {
        rawframe_core::ProxyState::Listening => "LISTENING",
        rawframe_core::ProxyState::Starting => "STARTING",
        rawframe_core::ProxyState::Stopping => "STOPPING",
        rawframe_core::ProxyState::Stopped => "STOPPED",
        rawframe_core::ProxyState::Failed => "FAILED",
    };
    let interception = if app.config.proxy.interception_enabled {
        "INTERCEPTION ON"
    } else {
        "INTERCEPTION OFF"
    };
    let scope = app.config.proxy.scope.summary();
    let pending = app.interception_pending_count();
    let mut right = format!("PROXY {engine}  |  {interception}  |  SCOPE {scope}");
    if pending > 0 {
        right.push_str(&format!("  |  PENDING {pending}"));
    }

    let left_w = left.chars().count();
    let center_w = center.chars().count();
    let right_w = right.chars().count();
    let total = inner.width as usize;

    let mut line1_spans: Vec<Span<'static>> = Vec::new();
    line1_spans.push(Span::styled(left, theme.accent_bold()));

    if total <= left_w + right_w + 2 || inner.height == 1 {
        // Compact: split left/right only.
        let compact_right = if total <= left_w + 18 {
            format!(
                " {engine} | {}",
                if app.config.proxy.interception_enabled {
                    "INT ON"
                } else {
                    "INT OFF"
                }
            )
        } else if total <= left_w + right_w + 2 {
            format!("PROXY {engine}  |  {interception}")
        } else {
            right.clone()
        };
        let gap = total.saturating_sub(left_w + compact_right.chars().count());
        line1_spans.push(Span::raw(" ".repeat(gap)));
        line1_spans.push(Span::styled(compact_right, header_right_style(app, theme)));
    } else {
        let gap1 = (total.saturating_sub(left_w + center_w + right_w)) / 2;
        let gap2 = total.saturating_sub(left_w + gap1 + center_w + right_w);
        line1_spans.push(Span::raw(" ".repeat(gap1.max(1))));
        line1_spans.push(Span::styled(center, theme.muted()));
        line1_spans.push(Span::raw(" ".repeat(gap2.max(1))));
        line1_spans.push(Span::styled(right, header_right_style(app, theme)));
    }

    frame.render_widget(
        Paragraph::new(Line::from(line1_spans)).style(Style::new().bg(theme.palette.bg)),
        Rect::new(inner.x, inner.y, inner.width, 1),
    );

    if inner.height > 1 {
        let l2_left = if app.has_any_live_capture() {
            format!(" Live traffic present  ·  {} entries", app.traffic.len())
        } else {
            " Simulated fixtures only (no traffic leaves this machine)".to_string()
        };
        let l2_right = format!(
            " {}  {} ",
            Local::now().format("%H:%M:%S"),
            if app.live_capture_count() > 0
                || app.proxy_state == rawframe_core::ProxyState::Listening
            {
                "●"
            } else {
                "○"
            }
        );
        let gap = total.saturating_sub(l2_left.chars().count() + l2_right.chars().count());
        let l2 = Line::from(vec![
            Span::styled(
                l2_left,
                if app.has_any_live_capture()
                    || app.proxy_state == rawframe_core::ProxyState::Listening
                {
                    theme.success()
                } else {
                    theme.warning()
                },
            ),
            Span::raw(" ".repeat(gap)),
            Span::styled(l2_right, theme.faint()),
        ]);
        frame.render_widget(
            Paragraph::new(l2).style(Style::new().bg(theme.palette.bg)),
            Rect::new(inner.x, inner.y + 1, inner.width, 1),
        );
    }
}

fn header_right_style(app: &App, theme: &Theme) -> Style {
    if app.proxy_state == rawframe_core::ProxyState::Failed {
        theme.danger()
    } else if app.interception_pending_count() > 0 {
        theme.warning().add_modifier(Modifier::BOLD)
    } else if app.proxy_state.is_active() {
        theme.muted()
    } else {
        theme.faint()
    }
}

fn render_sidebar(
    frame: &mut Frame,
    area: Rect,
    app: &App,
    theme: &Theme,
    output: &mut RenderOutput,
) {
    let focused = app.focus == Focus::Nav;
    let mut block = Block::new()
        .borders(Borders::RIGHT)
        .border_style(if focused {
            theme.accent()
        } else {
            theme.border()
        })
        .style(Style::new().bg(theme.palette.surface));
    block = block.title(Line::from(Span::styled(
        " WORKSPACES ",
        if focused {
            theme.accent_bold()
        } else {
            theme.label()
        },
    )));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.width < 4 || inner.height == 0 {
        return;
    }

    let mut y = inner.y;
    let groups: [(&str, &[NavSection]); 2] = [
        ("PRIMARY", &NavSection::PRIMARY),
        ("PLANNED", &[NavSection::Intruder, NavSection::Decoder]),
    ];
    for (heading, sections) in groups {
        if y >= inner.bottom() {
            break;
        }
        frame.render_widget(
            Paragraph::new(Span::styled(heading, theme.label()))
                .style(Style::new().bg(theme.palette.surface)),
            Rect::new(inner.x + 1, y, inner.width.saturating_sub(1), 1),
        );
        y += 1;
        for section in sections {
            if y >= inner.bottom() {
                break;
            }
            render_nav_item(frame, inner, y, *section, app, theme, output);
            y += 1;
        }
        y += 1;
    }

    if inner.height >= 10 {
        let pending = app.interception_pending_count();
        let info_y = inner.bottom().saturating_sub(5);
        if info_y > y {
            let lines = vec![
                Line::from(Span::styled("STATUS", theme.label())),
                Line::from(Span::styled(
                    if app.proxy_state.is_active() {
                        "Engine active"
                    } else {
                        "Engine stopped"
                    },
                    if app.proxy_state.is_active() {
                        theme.success()
                    } else {
                        theme.faint()
                    },
                )),
                Line::from(Span::styled(
                    if app.config.proxy.interception_enabled {
                        "Interception on"
                    } else {
                        "Interception off"
                    },
                    if app.config.proxy.interception_enabled {
                        theme.warning()
                    } else {
                        theme.faint()
                    },
                )),
                Line::from(Span::styled(
                    if pending > 0 {
                        format!("{pending} pending")
                    } else {
                        "No pending".to_string()
                    },
                    if pending > 0 {
                        theme.warning().add_modifier(Modifier::BOLD)
                    } else {
                        theme.faint()
                    },
                )),
            ];
            frame.render_widget(
                Paragraph::new(lines).style(Style::new().bg(theme.palette.surface)),
                Rect::new(inner.x + 1, info_y, inner.width.saturating_sub(1), 4),
            );
        }
    }
}

fn render_nav_item(
    frame: &mut Frame,
    inner: Rect,
    y: u16,
    section: NavSection,
    app: &App,
    theme: &Theme,
    output: &mut RenderOutput,
) {
    let active = app.nav == section;
    let hovered = app.hover == Some(HitTarget::Nav(section));
    let rect = Rect::new(inner.x, y, inner.width, 1);

    let bg = if active {
        theme.palette.selection
    } else if hovered {
        theme.palette.surface_elevated
    } else {
        theme.palette.surface
    };
    frame.render_widget(
        Paragraph::new(" ".repeat(inner.width as usize)).style(Style::new().bg(bg)),
        rect,
    );

    let marker = if active { "▌" } else { " " };
    let label = section.short_label();
    let mut spans = vec![
        Span::styled(
            marker,
            if active {
                theme.accent()
            } else {
                theme.faint()
            },
        ),
        Span::raw(" "),
        Span::styled(
            label,
            if active {
                theme.selected_accent()
            } else if section.is_planned() {
                theme.faint()
            } else {
                theme.muted()
            },
        ),
    ];
    let right = if section.is_planned() {
        "planned".to_string()
    } else {
        section.shortcut().to_string()
    };
    let used = 2 + label.chars().count();
    let gap = (inner.width as usize).saturating_sub(used + right.chars().count() + 1);
    spans.push(Span::raw(" ".repeat(gap)));
    spans.push(Span::styled(right, theme.faint()));
    spans.push(Span::raw(" "));

    frame.render_widget(
        Paragraph::new(Line::from(spans)).style(Style::new().bg(bg)),
        rect,
    );
    output.hit(rect, HitTarget::Nav(section));
}

fn render_splitter(
    frame: &mut Frame,
    area: Rect,
    app: &App,
    theme: &Theme,
    target: DragTarget,
    output: &mut RenderOutput,
) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let active = app.drag == Some(target) || app.hover == Some(HitTarget::Splitter(target));
    let style = if active {
        Style::new().fg(theme.palette.accent)
    } else {
        Style::new().fg(theme.palette.border)
    };
    let lines: Vec<Line<'static>> = (0..area.height)
        .map(|_| Line::from(Span::styled("│", style)))
        .collect();
    frame.render_widget(
        Paragraph::new(lines).style(Style::new().bg(theme.palette.bg)),
        area,
    );
    output.hit(area, HitTarget::Splitter(target));
}

fn render_footer(frame: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let block = Block::new()
        .borders(Borders::TOP)
        .border_style(theme.border())
        .style(Style::new().bg(theme.palette.surface));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.width == 0 || inner.height == 0 {
        return;
    }

    let (mode, mode_style) = current_mode(app, theme);
    let hints = context_hints(app);
    let right = " ^K commands  ? help  ^C quit ";
    let right_w = right.chars().count();
    let mode_w = mode.chars().count() + 2;

    let mut spans = vec![
        Span::styled(format!(" {mode} "), mode_style),
        Span::raw("  "),
    ];

    let left_budget = (inner.width as usize).saturating_sub(mode_w + right_w + 2);
    if left_budget > 8 {
        if let Some(toast) = app.notices.last() {
            let symbol = match toast.notice.level {
                rawframe_core::NoticeLevel::Info => "·",
                rawframe_core::NoticeLevel::Success => "✓",
                rawframe_core::NoticeLevel::Warning => "!",
                rawframe_core::NoticeLevel::Error => "×",
            };
            spans.push(Span::styled(
                format!("{symbol} "),
                theme.notice(toast.notice.level),
            ));
            spans.push(Span::styled(
                truncate(&toast.notice.message, left_budget.saturating_sub(2)),
                theme.muted(),
            ));
        } else {
            spans.push(Span::styled(truncate(hints, left_budget), theme.muted()));
        }
    }

    let used: usize = spans.iter().map(|s| s.content.chars().count()).sum();
    let gap = (inner.width as usize).saturating_sub(used + right_w);
    spans.push(Span::raw(" ".repeat(gap)));
    spans.push(Span::styled(right, theme.faint()));

    frame.render_widget(
        Paragraph::new(Line::from(spans)).style(Style::new().bg(theme.palette.surface)),
        Rect::new(inner.x, inner.y, inner.width, 1),
    );

    if inner.height > 1 {
        let storage = if app.storage_status().enabled {
            format!("  ·  DB ON ({} writes)", app.storage_status().persisted)
        } else if app.storage_status().error.is_some() {
            "  ·  DB ERROR".to_string()
        } else {
            "  ·  DB OFF".to_string()
        };
        let left = if app.live_capture_count() > 0 {
            format!(
                " Live captures: {}  ·  Simulated fixtures retained separately{storage}",
                app.live_capture_count()
            )
        } else if app.proxy_state == rawframe_core::ProxyState::Listening {
            let base = if app.tls_status.enabled {
                " Live engine listening  ·  No traffic yet  ·  TLS interception ON for scoped HTTPS"
            } else {
                " Live engine listening  ·  No traffic yet  ·  HTTPS CONNECT opaque (TLS interception off)"
            };
            format!("{base}{storage}")
        } else if app.tls_status.enabled {
            format!(
                " Simulated data only  ·  Start proxy for live capture  ·  TLS interception ON for scoped HTTPS{storage}"
            )
        } else {
            format!(
                " Simulated data only  ·  Start proxy for live HTTP capture  ·  HTTPS CONNECT opaque (TLS interception off){storage}"
            )
        };
        let left_style = if app.live_capture_count() > 0
            || app.proxy_state == rawframe_core::ProxyState::Listening
        {
            theme.success()
        } else {
            theme.faint()
        };
        let right = format!("RAWFRAME v{}", env!("CARGO_PKG_VERSION"));
        let gap =
            (inner.width as usize).saturating_sub(left.chars().count() + right.chars().count() + 1);
        let line = Line::from(vec![
            Span::styled(
                truncate(
                    &left,
                    (inner.width as usize).saturating_sub(right.chars().count() + 2),
                ),
                left_style,
            ),
            Span::raw(" ".repeat(gap.max(1))),
            Span::styled(right, theme.faint()),
        ]);
        frame.render_widget(
            Paragraph::new(line).style(Style::new().bg(theme.palette.surface)),
            Rect::new(inner.x, inner.y + 1, inner.width, 1),
        );
    }
}

fn current_mode(app: &App, theme: &Theme) -> (&'static str, Style) {
    if app.confirm.is_some() {
        ("CONFIRM", theme.on_danger())
    } else if app.palette.is_some() {
        ("COMMAND", theme.on_accent())
    } else if app.context_menu.is_some() {
        ("ACTIONS", theme.on_accent())
    } else if app.help_open {
        ("HELP", theme.on_accent())
    } else if app.search.active {
        ("SEARCH", theme.on_warning())
    } else if app.settings.edit.is_some() || app.repeater.editing || app.interception.editing {
        ("EDIT", theme.on_warning())
    } else {
        ("NORMAL", theme.on_accent())
    }
}

fn context_hints(app: &App) -> &'static str {
    if app.focus == Focus::Nav {
        return "↑↓ navigate  ·  Enter select  ·  Tab focus workspace";
    }
    match app.nav {
        NavSection::Proxy => {
            if app.interception.editing {
                "Typing in editor  ·  Ctrl+Enter forward modified  ·  Esc exit editor  ·  Tab focus"
            } else if app.interception_pending_count() > 0 {
                "↑↓ select paused  ·  F forward  ·  E edit  ·  D drop  ·  I interception  ·  Enter inspect"
            } else {
                "↑↓ select  ·  Enter inspect  ·  P start/stop  ·  I interception  ·  R replay"
            }
        }
        NavSection::History => {
            "↑↓ select  ·  Enter inspect  ·  / search  ·  M/S/H filters  ·  R replay  ·  B sessions"
        }
        NavSection::Repeater => {
            if app.repeater.editing {
                "Esc exit editing  ·  Ctrl+Enter send  ·  ^N new  ·  ^W close"
            } else {
                "Enter edit  ·  ←→ tabs  ·  ^N new  ·  ^W close  ·  Ctrl+Enter send"
            }
        }
        NavSection::Settings => "↑↓ select  ·  Enter edit/toggle  ·  Esc cancel edit",
        NavSection::Intruder | NavSection::Decoder => {
            "Planned module  ·  ^1 Proxy  ^2 History  ^3 Repeater  ^4 Settings"
        }
    }
}

fn render_too_small(frame: &mut Frame, area: Rect, theme: &Theme) {
    let width = area.width.saturating_sub(4).min(64);
    let height = 7.min(area.height);
    let rect = Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    );
    let lines = vec![
        Line::from(Span::styled("RAWFRAME", theme.accent_bold())),
        Line::from(""),
        Line::from(Span::styled("Terminal too small", theme.title())),
        Line::from(Span::styled(
            format!(
                "Minimum {}×{}  ·  current {}×{}",
                crate::layout::MIN_TERMINAL_WIDTH,
                crate::layout::MIN_TERMINAL_HEIGHT,
                area.width,
                area.height
            ),
            theme.muted(),
        )),
        Line::from(Span::styled(
            "Resize to continue. Ctrl+C quits.",
            theme.faint(),
        )),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .alignment(Alignment::Center)
            .style(Style::new().bg(theme.palette.bg)),
        rect,
    );
}

/// Test helper that renders one frame into an in-memory buffer.
#[doc(hidden)]
pub fn render_test_frame(app: &App, width: u16, height: u16) -> ratatui::buffer::Buffer {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("test backend");
    terminal
        .draw(|frame| {
            render(frame, app);
        })
        .expect("draw");
    terminal.backend().buffer().clone()
}

pub fn buffer_text(buffer: &ratatui::buffer::Buffer) -> String {
    let mut text = String::new();
    for y in 0..buffer.area.height {
        for x in 0..buffer.area.width {
            text.push_str(buffer[(x, y)].symbol());
        }
        text.push('\n');
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::App;

    #[test]
    fn shell_renders_brand_and_workspace() {
        let app = App::demo();
        let buffer = render_test_frame(&app, 130, 38);
        let text = buffer_text(&buffer);

        assert!(text.contains("RAWFRAME"));
        assert!(text.contains("Proxy"));
        assert!(text.contains("INTERCEPTION") || text.contains("Interception"));
    }

    #[test]
    fn tiny_terminals_get_a_clear_size_message() {
        let app = App::demo();
        let buffer = render_test_frame(&app, 50, 12);
        let text = buffer_text(&buffer);
        assert!(text.contains("too small") || text.contains("Minimum"));
    }
}
