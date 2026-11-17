//! Screen renderers for the workspace area.

pub mod decoder;
pub mod history;
pub mod placeholder;
pub mod proxy;
pub mod repeater;
pub mod settings;

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::theme::Theme;

/// Renders the single-line screen heading with an optional right-aligned status.
pub fn render_heading(
    frame: &mut Frame,
    area: Rect,
    theme: &Theme,
    title: &str,
    subtitle: &str,
    right: Option<&str>,
    right_style: Style,
) {
    let left = Line::from(vec![
        Span::styled(title.to_ascii_uppercase(), theme.title()),
        Span::raw("  "),
        Span::styled(subtitle.to_string(), theme.faint()),
    ]);
    frame.render_widget(
        Paragraph::new(left).style(Style::new().bg(theme.palette.bg)),
        area,
    );
    if let Some(right) = right {
        let left_width = title.chars().count() + subtitle.chars().count() + 2;
        let right_width = right.chars().count();
        if left_width + right_width + 3 <= area.width as usize {
            frame.render_widget(
                Paragraph::new(Span::styled(right.to_string(), right_style))
                    .alignment(ratatui::layout::Alignment::Right)
                    .style(Style::new().bg(theme.palette.bg)),
                area,
            );
        }
    }
}

pub fn render_simulation_banner(frame: &mut Frame, area: Rect, theme: &Theme) {
    let line = Line::from(vec![
        Span::styled(" SIMULATED ", theme.on_warning()),
        Span::raw("  "),
        Span::styled(
            "Synthetic fixtures are shown until live traffic arrives. Press P to start the local HTTP proxy.",
            theme.warning(),
        ),
    ]);
    frame.render_widget(
        Paragraph::new(line).style(Style::new().bg(theme.palette.surface_elevated)),
        area,
    );
}

pub fn render_live_banner(frame: &mut Frame, area: Rect, theme: &Theme) {
    let line = Line::from(vec![
        Span::styled(" LIVE ENGINE ", theme.on_accent()),
        Span::raw("  "),
        Span::styled(
            "HTTP requests/responses are captured. HTTPS CONNECT is opaque by default; opt-in TLS interception decrypts HTTP/1.1 into the same workbench.",
            theme.success(),
        ),
    ]);
    frame.render_widget(
        Paragraph::new(line).style(Style::new().bg(theme.palette.surface_elevated)),
        area,
    );
}

pub fn window_start(selected: usize, len: usize, height: usize) -> usize {
    if len <= height || height == 0 {
        0
    } else {
        selected
            .saturating_sub(height.saturating_sub(1))
            .min(len - height)
    }
}
