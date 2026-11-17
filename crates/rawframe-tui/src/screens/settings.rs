//! Settings workspace. Controls in this milestone are functional for the
//! current session; configuration persistence is intentionally absent.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};

use crate::app::App;
use crate::components::{focused_panel, panel, truncate};
use crate::interaction::{HitTarget, RenderOutput, ScrollRegion, SettingId};
use crate::screens::{render_heading, window_start};
use crate::theme::Theme;

#[derive(Debug, Clone, Copy)]
enum RowKind {
    Header(&'static str),
    Setting(SettingId),
}

pub fn render(frame: &mut Frame, area: Rect, app: &App, theme: &Theme, output: &mut RenderOutput) {
    render_heading(
        frame,
        Rect::new(area.x, area.y, area.width, 1),
        theme,
        "Settings",
        "proxy · privacy · storage",
        Some("SESSION-ONLY CONFIG"),
        theme.warning(),
    );

    let content = Rect::new(
        area.x,
        area.y + 2,
        area.width,
        area.bottom().saturating_sub(area.y + 2),
    );
    if content.height < 4 || content.width == 0 {
        return;
    }

    let show_details = content.width >= 96;
    if show_details {
        let columns = Layout::horizontal([Constraint::Percentage(63), Constraint::Min(30)])
            .horizontal_margin(0)
            .split(content);
        let gap = 1;
        let left = Rect::new(columns[0].x, content.y, columns[0].width, content.height);
        let right = Rect::new(
            columns[1].x + gap,
            content.y,
            columns[1].width.saturating_sub(gap),
            content.height,
        );
        render_list(frame, left, app, theme, output);
        render_details(frame, right, app, theme);
    } else {
        render_list(frame, content, app, theme, output);
    }
}

fn rows() -> Vec<RowKind> {
    let mut rows = Vec::new();
    let mut section = "";
    for id in SettingId::ALL {
        if id.section() != section {
            section = id.section();
            rows.push(RowKind::Header(section));
        }
        rows.push(RowKind::Setting(id));
    }
    rows
}

fn render_list(frame: &mut Frame, area: Rect, app: &App, theme: &Theme, output: &mut RenderOutput) {
    let title = "CONFIGURATION";
    let block = focused_panel(
        theme,
        title,
        app.focus == crate::interaction::Focus::Content,
    );
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.width == 0 || inner.height == 0 {
        return;
    }
    output.zone(inner, ScrollRegion::Settings);

    let rows = rows();
    let selected_id = app.settings.selected_id();
    let selected_row = rows
        .iter()
        .position(|row| matches!(row, RowKind::Setting(id) if *id == selected_id))
        .unwrap_or(0);
    let footer_height = 1.min(inner.height);
    let list_height = inner.height.saturating_sub(footer_height) as usize;
    let start = window_start(selected_row, rows.len(), list_height);

    for (offset, row) in rows.iter().skip(start).take(list_height).enumerate() {
        let y = inner.y + offset as u16;
        match row {
            RowKind::Header(section) => {
                frame.render_widget(
                    Paragraph::new(Span::styled(
                        format!(" {} ", section.to_ascii_uppercase()),
                        theme.label().add_modifier(Modifier::BOLD),
                    ))
                    .style(Style::new().bg(theme.palette.surface_elevated)),
                    Rect::new(inner.x, y, inner.width, 1),
                );
            }
            RowKind::Setting(id) => {
                render_setting_row(frame, inner, y, *id, app, theme, output);
            }
        }
    }

    frame.render_widget(
        Paragraph::new(Span::styled(
            "↑↓ select   Enter edit/toggle   Esc cancel edit",
            theme.faint(),
        ))
        .style(Style::new().bg(theme.palette.surface)),
        Rect::new(inner.x, inner.bottom().saturating_sub(1), inner.width, 1),
    );
}

fn render_setting_row(
    frame: &mut Frame,
    inner: Rect,
    y: u16,
    id: SettingId,
    app: &App,
    theme: &Theme,
    output: &mut RenderOutput,
) {
    let selected = app.settings.selected_id() == id;
    let rect = Rect::new(inner.x, y, inner.width, 1);
    if selected {
        frame.render_widget(
            Paragraph::new(" ".repeat(inner.width as usize))
                .style(Style::new().bg(theme.palette.selection)),
            rect,
        );
    }

    let editing = app.settings.edit.as_ref().is_some_and(|edit| edit.id == id);
    let mut value = if editing {
        let edit = app.settings.edit.as_ref().unwrap();
        format!("{}▏", edit.buffer)
    } else {
        app.setting_value(id)
    };

    let marker = Span::styled(
        if selected { "▌" } else { " " },
        if selected {
            theme.accent()
        } else {
            theme.faint()
        },
    );
    let label_style = if selected {
        theme.text()
    } else {
        theme.muted()
    };
    let value_style = if editing {
        theme.accent_bold()
    } else if id.is_toggle() {
        if app.setting_is_on(id) {
            theme.success()
        } else {
            theme.faint()
        }
    } else if id.is_editable() || id == SettingId::CaFingerprint {
        theme.text()
    } else {
        theme.faint()
    };

    if id.is_toggle() && !editing {
        let on = app.setting_is_on(id);
        value = format!(
            "{} {}",
            if on { "●" } else { "○" },
            if on { "ON" } else { "OFF" }
        );
    }
    if id == SettingId::VerifyTls {
        value = "● ON · locked".to_string();
    }

    let value_len = value.chars().count();
    let label_max = (inner.width as usize).saturating_sub(value_len + 4);
    if label_max < 4 {
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                marker,
                Span::styled(truncate(id.label(), inner.width as usize), label_style),
            ]))
            .style(Style::new().bg(if selected {
                theme.palette.selection
            } else {
                theme.palette.surface
            })),
            rect,
        );
    } else {
        let label = truncate(id.label(), label_max);
        let used = label.chars().count() + value_len + 2;
        let gap = (inner.width as usize).saturating_sub(used).max(1);
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                marker,
                Span::styled(format!(" {label}"), label_style),
                Span::raw(" ".repeat(gap)),
                Span::styled(value, value_style),
                Span::raw(" "),
            ]))
            .style(Style::new().bg(if selected {
                theme.palette.selection
            } else {
                theme.palette.surface
            })),
            rect,
        );
    }

    output.hit(rect, HitTarget::Setting(id));
}

fn render_details(frame: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let block = panel(theme, "DETAILS");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.width == 0 || inner.height < 2 {
        return;
    }

    let id = app.settings.selected_id();
    let (description, note) = describe(id);
    let mut lines = vec![
        Line::from(Span::styled(id.label().to_string(), theme.title())),
        Line::from(""),
        Line::from(Span::styled(
            format!("Value: {}", app.setting_value(id)),
            theme.muted(),
        )),
        Line::from(""),
        Line::from(Span::styled(description, theme.text())),
    ];
    if let Some(note) = note {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("SECURITY", theme.label())));
        lines.push(Line::from(Span::styled(note, theme.warning())));
    }
    if matches!(
        id,
        SettingId::TlsInterception | SettingId::CertificateAuthority | SettingId::CaFingerprint
    ) {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("LOCAL CA", theme.label())));
        if let Some(fingerprint) = &app.tls_status.ca_fingerprint {
            if let Some(path) = &app.tls_status.ca_cert_path {
                lines.push(Line::from(Span::styled(path.clone(), theme.muted())));
            }
            lines.push(Line::from(Span::styled(
                format!("Fingerprint {fingerprint}"),
                theme.text(),
            )));
        } else {
            lines.push(Line::from(Span::styled(
                "Not initialised. Enabling intercept generates a local CA on explicit operator action.",
                theme.warning(),
            )));
        }
        if let Some(error) = &app.tls_status.error {
            lines.push(Line::from(Span::styled(error.clone(), theme.danger())));
        }
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Changes apply to this session only. No configuration file is written.",
        theme.faint(),
    )));

    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: true })
            .style(Style::new().bg(theme.palette.surface)),
        inner,
    );
}

fn describe(id: SettingId) -> (&'static str, Option<&'static str>) {
    match id {
        SettingId::BindAddress => (
            "Local address the proxy will accept connections on. Loopback keeps the workbench private to this machine.",
            Some(
                "Settings refuse non-loopback binds; the CLI requires --bind ADDR with --allow-remote-bind.",
            ),
        ),
        SettingId::Port => (
            "TCP port for the HTTP proxy listener. Your testing client is configured to send traffic here.",
            None,
        ),
        SettingId::Interception => (
            "When armed, matching requests pause for review instead of being forwarded. Rules are scope-aware.",
            Some(
                "Captured HTTP (and decrypted HTTPS when enabled) pauses here for forward/edit/drop decisions. Scope and header rules decide what is captured.",
            ),
        ),
        SettingId::TlsInterception => (
            "Terminate authorized CONNECT sessions and inspect decrypted HTTP/1.1. Off by default; opaque tunnelling is preserved when disabled.",
            Some(
                "Enabling makes HTTPS content readable to RAWFRAME. Trust the exported CA certificate explicitly; the private key is never exported.",
            ),
        ),
        SettingId::VerifyTls => (
            "Upstream certificates are validated for intercepted HTTPS sessions. Hostname and chain checks are mandatory and cannot be disabled.",
            Some(
                "Opaque CONNECT tunnels are relayed without termination, so RAWFRAME cannot validate their end-to-end certificates. The setting stays locked on.",
            ),
        ),
        SettingId::MaxBody => (
            "Maximum request body the proxy will stream and capture. Larger bodies are rejected rather than accumulated without limit.",
            None,
        ),
        SettingId::MaxResponse => (
            "Maximum upstream response body the proxy will stream and capture. Declared oversize responses are rejected before streaming.",
            None,
        ),
        SettingId::MaxConnections => (
            "Maximum simultaneous client connections accepted by the proxy listener. Additional connections are closed.",
            None,
        ),
        SettingId::ConnectTimeout => (
            "How long DNS resolution, an upstream connection, and the HTTP handshake may take before they are abandoned.",
            None,
        ),
        SettingId::UpstreamTimeout => (
            "How long the proxy waits for upstream response headers before returning a gateway timeout.",
            None,
        ),
        SettingId::IdleTimeout => (
            "Maximum idle time for request/response body streaming, client connections, and opaque CONNECT tunnels.",
            None,
        ),
        SettingId::InterceptTimeout => (
            "How long a paused request may wait for an operator decision before it is released.",
            Some("Prevents stalled requests from consuming resources indefinitely."),
        ),
        SettingId::AllowPrivateUpstreams => (
            "Permits scope-authorized hostnames that resolve to loopback or private addresses, such as local lab servers.",
            Some("Off by default so a rebound hostname cannot reach private or loopback services."),
        ),
        SettingId::Redaction => (
            "Masks Authorization, Proxy-Authorization, Cookie, Set-Cookie, and API-key style fields in the UI and logs.",
            Some("Disabling redaction exposes captured credentials on screen."),
        ),
        SettingId::Accent => (
            "Selects the restrained accent used for focus, selection, and primary actions.",
            None,
        ),
        SettingId::Mouse => (
            "Enables click, drag, wheel, and context-menu interaction. Keyboard control always remains available.",
            None,
        ),
        SettingId::PersistBodies => (
            "When enabled, the bodies of new captures are written to the session database.",
            Some(
                "Off by default because bodies commonly contain credentials and personal data. Changing this never rewrites entries already stored.",
            ),
        ),
        SettingId::PersistSensitive => (
            "When enabled, sensitive header values are written instead of the placeholder <redacted>.",
            Some(
                "Off by default. Enabling this persists credentials in plain form and applies only to future writes.",
            ),
        ),
        SettingId::Scope => (
            "Live allowlist of hosts the proxy may contact. Edit rules without restarting the listener.",
            Some(
                "An empty allowlist denies all upstream traffic. Explicit target authorization is required before testing any system.",
            ),
        ),
        SettingId::CertificateAuthority => (
            "The local certificate authority used for HTTPS interception and per-host leaf certificates.",
            Some(
                "Generated on explicit enable or CLI action. The private key stays local with restrictive permissions and is never exported.",
            ),
        ),
        SettingId::CaFingerprint => (
            "SHA-256 fingerprint of the public CA certificate. Compare it before trusting the CA in a client.",
            Some(
                "The fingerprint identifies public certificate material only; it is not a secret and never reveals the private key.",
            ),
        ),
        SettingId::DatabasePath => (
            "Location of the SQLite session database holding captured history and schema migrations.",
            Some(
                "Bodies and sensitive header values follow the persistence toggles above. The database is created on first launch unless --no-persist is used.",
            ),
        ),
    }
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
    fn settings_render_groups_values_and_details() {
        let app = App::demo();
        let theme = app.theme();
        let mut terminal = Terminal::new(TestBackend::new(130, 36)).unwrap();
        let mut output = RenderOutput::default();

        terminal
            .draw(|frame| {
                render(frame, Rect::new(0, 0, 130, 36), &app, &theme, &mut output);
            })
            .unwrap();

        let text = text_of(&terminal);
        assert!(text.contains("SETTINGS"));
        assert!(text.contains("CONFIGURATION"));
        assert!(text.contains("Bind address"));
        assert!(text.contains("Upstream TLS verification"));
        assert!(text.contains("DETAILS"));
        assert!(text.contains("SESSION-ONLY CONFIG"));
        assert!(
            output
                .hits
                .iter()
                .any(|hit| hit.target == HitTarget::Setting(SettingId::BindAddress))
        );
    }

    #[test]
    fn every_setting_has_a_description() {
        for id in SettingId::ALL {
            let (description, _) = describe(id);
            assert!(
                !description.is_empty(),
                "missing description for {}",
                id.label()
            );
        }
    }
}
