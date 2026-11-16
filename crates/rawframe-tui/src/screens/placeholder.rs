//! Honest placeholders for modules planned after the proxy engine milestone.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};

use crate::app::App;
use crate::components::panel;
use crate::interaction::{NavSection, RenderOutput};
use crate::screens::render_heading;
use crate::theme::Theme;

pub fn render(frame: &mut Frame, area: Rect, app: &App, theme: &Theme, _output: &mut RenderOutput) {
    let (title, description, roadmap) = match app.nav {
        NavSection::Intruder => (
            "Intruder",
            "Automated request manipulation is planned but deliberately not implemented in the current build.",
            &[
                "Request templates with explicit payload positions",
                "Scope-checked attack configurations",
                "Bounded concurrency and rate controls",
                "Response analysis without fabricating findings",
            ][..],
        ),
        _ => (
            "Decoder",
            "Payload encoding and decoding workflows are planned but deliberately not implemented in the current build.",
            &[
                "Chained URL, Base64, and hex transforms",
                "Raw byte inspection with terminal-safe rendering",
                "Conversion history inside a session",
                "No automatic shell execution of decoded content",
            ][..],
        ),
    };

    render_heading(
        frame,
        Rect::new(area.x, area.y, area.width, 1),
        theme,
        title,
        "planned module",
        Some("NOT IMPLEMENTED"),
        theme.muted(),
    );

    let body_area = Rect::new(
        area.x,
        area.y + 2,
        area.width,
        area.bottom().saturating_sub(area.y + 2),
    );
    if body_area.height < 4 {
        return;
    }

    let block = panel(theme, "MODULE STATUS");
    let inner = block.inner(body_area);
    frame.render_widget(block, body_area);
    if inner.width < 20 || inner.height < 6 {
        return;
    }

    let mut lines = vec![
        Line::from(Span::styled(
            "FOUNDATION MILESTONE",
            theme.accent_bold().add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(description, theme.text())),
        Line::from(""),
        Line::from(Span::styled(
            "No simulated results or findings are shown for unimplemented features.",
            theme.muted(),
        )),
        Line::from(""),
        Line::from(Span::styled("PLANNED CAPABILITIES", theme.label())),
    ];
    for item in roadmap {
        lines.push(Line::from(vec![
            Span::styled("  · ", theme.faint()),
            Span::styled(item.to_string(), theme.muted()),
        ]));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Use ^1 · Proxy   ^2 · History   ^3 · Repeater   ^4 · Settings",
        theme.faint(),
    )));

    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: true })
            .style(Style::new().bg(theme.palette.surface)),
        Rect::new(
            inner.x,
            inner.y + 1,
            inner.width,
            inner.height.saturating_sub(1),
        ),
    );
}
