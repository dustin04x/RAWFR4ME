//! Small, reusable presentation primitives.

pub mod editor;
pub mod inspector;
pub mod lifecycle;
pub mod overlay;

use chrono::{DateTime, Utc};
use ratatui::Frame;
use ratatui::layout::{Alignment, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Paragraph, Wrap};
use rawframe_core::models::traffic::{TrafficSource, TrafficState};
use rawframe_core::models::{HttpResponse, StatusClass};

use crate::interaction::{ActionId, HitTarget, RenderOutput};
use crate::theme::Theme;

pub fn panel(theme: &Theme, title: &str) -> Block<'static> {
    Block::new()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(theme.border())
        .style(theme.surface())
        .title_style(theme.label())
        .title(Line::from(format!(" {title} ")))
}

pub fn focused_panel(theme: &Theme, title: &str, focused: bool) -> Block<'static> {
    let block = panel(theme, title);
    if focused {
        block
            .border_style(theme.accent())
            .title_style(theme.accent_bold())
    } else {
        block
    }
}

pub fn section_label(theme: &Theme, text: &str) -> Line<'static> {
    Line::from(Span::styled(text.to_ascii_uppercase(), theme.label()))
}

pub fn muted_line(theme: &Theme, text: impl Into<String>) -> Line<'static> {
    Line::from(Span::styled(text.into(), theme.muted()))
}

pub fn dim_line(theme: &Theme, text: impl Into<String>) -> Line<'static> {
    Line::from(Span::styled(text.into(), theme.faint()))
}

pub fn key_hint(theme: &Theme, key: &str, label: &str) -> Vec<Span<'static>> {
    vec![
        Span::styled(
            format!(" {key} "),
            theme.faint().add_modifier(Modifier::BOLD),
        ),
        Span::styled(label.to_string(), theme.muted()),
    ]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ButtonKind {
    Primary,
    Secondary,
    Danger,
}

#[derive(Debug, Clone, Copy)]
pub struct ButtonSpec<'a> {
    pub label: &'a str,
    pub key: Option<&'a str>,
    pub action: ActionId,
    pub kind: ButtonKind,
    pub enabled: bool,
}

impl<'a> ButtonSpec<'a> {
    pub fn new(label: &'a str, action: ActionId, enabled: bool) -> Self {
        Self {
            label,
            key: None,
            action,
            kind: ButtonKind::Secondary,
            enabled,
        }
    }

    pub fn key(mut self, key: &'a str) -> Self {
        self.key = Some(key);
        self
    }

    pub fn primary(mut self) -> Self {
        self.kind = ButtonKind::Primary;
        self
    }

    pub fn danger(mut self) -> Self {
        self.kind = ButtonKind::Danger;
        self
    }
}

/// Renders a horizontal button strip and records hit targets. Returns the width
/// consumed so callers can place adjacent controls.
pub fn button_row(
    frame: &mut Frame,
    area: Rect,
    buttons: &[ButtonSpec<'_>],
    theme: &Theme,
    hovered: Option<&HitTarget>,
    output: &mut RenderOutput,
) -> u16 {
    let mut x = area.x;
    for button in buttons {
        if x >= area.right() {
            break;
        }
        let key = button.key.unwrap_or_default();
        let width = button.label.chars().count() as u16
            + 2
            + if key.is_empty() {
                0
            } else {
                key.chars().count() as u16 + 2
            };
        let width = width.min(area.right().saturating_sub(x));
        if width == 0 {
            continue;
        }

        let is_hovered = hovered == Some(&HitTarget::Action(button.action));
        let style = if !button.enabled {
            theme.disabled()
        } else {
            match button.kind {
                ButtonKind::Primary => {
                    let mut style = theme.primary_button();
                    if is_hovered {
                        style = style.bg(theme.palette.accent_bright);
                    }
                    style
                }
                ButtonKind::Secondary => {
                    let mut style = theme.secondary_button();
                    if is_hovered {
                        style = style.bg(theme.palette.border).fg(theme.palette.text);
                    }
                    style
                }
                ButtonKind::Danger => {
                    let mut style = theme.secondary_button().fg(theme.palette.danger);
                    if is_hovered {
                        style = style.bg(theme.palette.danger).fg(theme.palette.bg);
                    }
                    style
                }
            }
        };

        let mut spans = vec![Span::styled(format!(" {} ", button.label), style)];
        if !key.is_empty() {
            let key_style = if !button.enabled {
                theme.disabled()
            } else if is_hovered && button.kind != ButtonKind::Secondary {
                style
            } else {
                style.add_modifier(Modifier::DIM)
            };
            spans.push(Span::styled(key.to_string(), key_style));
            spans.push(Span::raw(" "));
        }

        let rect = Rect::new(x, area.y, width, 1);
        frame.render_widget(Paragraph::new(Line::from(spans)), rect);
        if button.enabled {
            output.hit(rect, HitTarget::Action(button.action));
        }
        x += width + 1;
    }
    x.saturating_sub(area.x)
}

pub fn empty_state(
    frame: &mut Frame,
    area: Rect,
    theme: &Theme,
    title: &str,
    body: &[&str],
    hint: Option<&str>,
) {
    if area.width < 12 || area.height < 3 {
        return;
    }
    let mut lines = vec![Line::from(Span::styled(
        title.to_ascii_uppercase(),
        theme.accent_bold(),
    ))];
    lines.push(Line::from(""));
    for paragraph in body {
        lines.push(Line::from(Span::styled(
            paragraph.to_string(),
            theme.muted(),
        )));
    }
    if let Some(hint) = hint {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(hint.to_string(), theme.faint())));
    }

    // Account for wrapped body/hint lines so the call to action is never
    // clipped when a message is long.
    let text_width = area.width.saturating_sub(4).max(1) as usize;
    let wrapped = |text: &str| text.chars().count().div_ceil(text_width).max(1);
    let mut height = wrapped(title) + 1 + body.iter().map(|line| wrapped(line)).sum::<usize>();
    if let Some(hint) = hint {
        height += 1 + wrapped(hint);
    }
    let height = (height as u16).min(area.height);
    let rect = Rect::new(
        area.x.saturating_add(2),
        area.y + area.height.saturating_sub(height) / 2,
        area.width.saturating_sub(4),
        height,
    );
    frame.render_widget(
        Paragraph::new(lines)
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true })
            .style(Style::new().bg(theme.palette.surface)),
        rect,
    );
}

pub fn source_badge(theme: &Theme, source: TrafficSource) -> Span<'static> {
    match source {
        TrafficSource::Simulated => Span::styled("SIM", theme.warning()),
        TrafficSource::Intercepted => Span::styled("LIVE", theme.muted()),
        TrafficSource::Authored => Span::styled("AUTH", theme.faint()),
        TrafficSource::Repeater => Span::styled("REPEATER", theme.success()),
        TrafficSource::Restored => Span::styled("RESTORED", theme.accent()),
    }
}

pub fn state_style(theme: &Theme, state: TrafficState) -> Style {
    theme.state(state).add_modifier(Modifier::BOLD)
}

pub fn status_style(theme: &Theme, class: Option<StatusClass>) -> Style {
    match class {
        Some(class) => theme.status_class(class).add_modifier(Modifier::BOLD),
        None => theme.muted(),
    }
}

pub fn response_status_style(theme: &Theme, response: &HttpResponse) -> Style {
    theme
        .status_class(response.status_class())
        .add_modifier(Modifier::BOLD)
}

pub fn format_bytes(bytes: usize) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
    }
}

pub fn format_age(started_at: DateTime<Utc>, now: DateTime<Utc>) -> String {
    let seconds = (now - started_at).num_seconds().max(0);
    if seconds < 60 {
        format!("{seconds}s")
    } else if seconds < 3600 {
        format!("{}m", seconds / 60)
    } else if seconds < 86_400 {
        format!("{}h", seconds / 3600)
    } else {
        format!("{}d", seconds / 86_400)
    }
}

pub fn truncate(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    if max_chars == 0 {
        return String::new();
    }
    let mut truncated: String = text.chars().take(max_chars.saturating_sub(1)).collect();
    truncated.push('…');
    truncated
}

pub fn truncate_left(text: &str, max_chars: usize) -> String {
    let count = text.chars().count();
    if count <= max_chars {
        return text.to_string();
    }
    if max_chars == 0 {
        return String::new();
    }
    let skip = count - max_chars.saturating_sub(1);
    format!("…{}", text.chars().skip(skip).collect::<String>())
}

pub fn request_target(entry: &rawframe_core::models::TrafficEntry, max_chars: usize) -> String {
    truncate(&entry.request.target, max_chars)
}

/// Renders a terminal-safe raw HTTP message with restrained syntax coloring.
pub fn raw_message(
    frame: &mut Frame,
    area: Rect,
    theme: &Theme,
    text: &str,
    scroll: u16,
    first_line_style: Style,
) {
    let mut lines: Vec<Line<'static>> = Vec::new();
    let mut in_headers = true;
    for (index, raw_line) in text.split('\n').enumerate() {
        if index == 0 {
            lines.push(Line::from(Span::styled(
                raw_line.to_string(),
                first_line_style,
            )));
            continue;
        }
        if raw_line.is_empty() {
            in_headers = false;
            lines.push(Line::from(""));
            continue;
        }
        if in_headers && let Some((name, value)) = raw_line.split_once(':') {
            lines.push(Line::from(vec![
                Span::styled(
                    format!("{name}:"),
                    theme.accent().add_modifier(Modifier::DIM),
                ),
                Span::styled(value.to_string(), theme.text()),
            ]));
            continue;
        }
        lines.push(Line::from(Span::styled(
            raw_line.to_string(),
            if in_headers {
                theme.text()
            } else {
                theme.surface()
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeDelta;

    #[test]
    fn bytes_are_scaled_for_people() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(2048), "2.0 KiB");
        assert_eq!(format_bytes(3 * 1024 * 1024), "3.0 MiB");
    }

    #[test]
    fn ages_are_relative_and_never_negative() {
        let now = Utc::now();
        assert_eq!(format_age(now, now), "0s");
        assert_eq!(format_age(now - TimeDelta::seconds(42), now), "42s");
        assert_eq!(format_age(now - TimeDelta::minutes(3), now), "3m");
        assert_eq!(format_age(now - TimeDelta::hours(5), now), "5h");
        assert_eq!(format_age(now + TimeDelta::seconds(3), now), "0s");
    }

    #[test]
    fn truncation_is_unicode_safe() {
        assert_eq!(truncate("abcdef", 10), "abcdef");
        assert_eq!(truncate("/v1/users?page=2", 8), "/v1/use…");
        assert_eq!(truncate("héllo wörld", 6), "héllo…");
        assert_eq!(truncate_left("/a/b/c/d", 4), "…c/d");
    }
}
