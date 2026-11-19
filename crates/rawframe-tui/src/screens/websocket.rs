//! WebSocket workspace: connections, frame history, and a frame inspector.
//!
//! The layout adapts to the terminal: three panes on wide screens, and a
//! stacked inspector on narrower ones. Every row registers a hit target and a
//! scroll zone so mouse selection and wheel scrolling use the same state as the
//! keyboard.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};
use rawframe_core::models::websocket::{
    WebSocketConnection, WebSocketDirection, WebSocketFrame, WebSocketInterceptionOutcome,
    WebSocketOpcode,
};
use rawframe_core::security::sanitize_for_display;

use crate::app::App;
use crate::components::{
    ButtonSpec, button_row, empty_state, focused_panel, format_bytes, source_badge, truncate,
};
use crate::interaction::{ActionId, Focus, HitTarget, RenderOutput, ScrollRegion};
use crate::screens::{render_heading, window_start};
use crate::theme::Theme;
use crate::websocket::WebSocketState;

const HEX_PREVIEW_LINES: usize = 96;
const TEXT_PREVIEW_LINES: usize = 200;

pub fn render(frame: &mut Frame, area: Rect, app: &App, theme: &Theme, output: &mut RenderOutput) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let state = app.websocket();
    let enabled = app.websocket_interception();
    let focused = app.focus == Focus::Content;

    let rows = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Fill(1),
    ])
    .split(area);

    let subtitle = if state.received_live() {
        "HTTP/1.1 upgrade relay · frame-level capture"
    } else {
        "waiting for an HTTP/1.1 upgrade"
    };
    render_heading(
        frame,
        rows[0],
        theme,
        "WebSocket",
        subtitle,
        Some(if enabled {
            "INTERCEPTION ON"
        } else {
            "INTERCEPTION OFF"
        }),
        if enabled {
            theme.warning()
        } else {
            theme.faint()
        },
    );

    render_status(frame, rows[1], state, enabled, theme);
    render_actions(frame, rows[2], state, theme, app, output);

    let body = rows[3];
    if body.width == 0 || body.height == 0 {
        return;
    }

    if body.width >= 104 {
        let inspector = (body.width / 3).clamp(34, 48);
        let columns = Layout::horizontal([
            Constraint::Length(30),
            Constraint::Fill(1),
            Constraint::Length(inspector),
        ])
        .split(body);
        render_connections(frame, columns[0], state, focused, theme, output);
        render_frames(frame, columns[1], state, focused, theme, output);
        render_inspector(frame, columns[2], state, enabled, theme, app, output);
    } else if body.height >= 16 {
        let split = Layout::vertical([Constraint::Fill(1), Constraint::Length(9)]).split(body);
        let top = Layout::horizontal([Constraint::Length(22), Constraint::Fill(1)]).split(split[0]);
        render_connections(frame, top[0], state, focused, theme, output);
        render_frames(frame, top[1], state, focused, theme, output);
        render_inspector(frame, split[1], state, enabled, theme, app, output);
    } else {
        let top = if body.width >= 60 {
            Layout::horizontal([Constraint::Length(22), Constraint::Fill(1)]).split(body)
        } else {
            Layout::horizontal([Constraint::Fill(1)]).split(body)
        };
        if top.len() == 2 {
            render_connections(frame, top[0], state, focused, theme, output);
            render_frames(frame, top[1], state, focused, theme, output);
        } else {
            render_frames(frame, top[0], state, focused, theme, output);
        }
    }
}

fn render_status(
    frame: &mut Frame,
    area: Rect,
    state: &WebSocketState,
    enabled: bool,
    theme: &Theme,
) {
    if area.width == 0 {
        return;
    }
    let pending = state.pending_count();
    let mut spans = vec![
        Span::styled(
            format!(" {} connections ", state.connections().len()),
            theme.muted(),
        ),
        Span::styled("·", theme.faint()),
        Span::styled(format!(" {} frames ", state.frame_total()), theme.muted()),
        Span::styled("·", theme.faint()),
        Span::styled(
            format!(" {} messages ", state.messages().len()),
            theme.muted(),
        ),
        Span::styled("·", theme.faint()),
    ];
    if pending > 0 {
        spans.push(Span::styled(format!(" {pending} paused "), theme.warning()));
    } else {
        spans.push(Span::styled(
            if enabled { " armed " } else { " passive " },
            if enabled {
                theme.success()
            } else {
                theme.faint()
            },
        ));
    }
    if !state.filter().is_empty() {
        spans.push(Span::styled("·", theme.faint()));
        spans.push(Span::styled(
            format!(" filter \"{}\" ", sanitize_for_display(state.filter())),
            theme.accent(),
        ));
    }
    let hint = if state.received_live() {
        "  ↑↓ frames · ←→ connections · m modify · n next paused"
    } else {
        "  Frames appear when a client upgrades an in-scope HTTP/1.1 connection."
    };
    spans.push(Span::styled(hint, theme.faint()));
    frame.render_widget(
        Paragraph::new(Line::from(spans)).style(Style::new().bg(theme.palette.bg)),
        area,
    );
}

fn render_actions(
    frame: &mut Frame,
    area: Rect,
    state: &WebSocketState,
    theme: &Theme,
    app: &App,
    output: &mut RenderOutput,
) {
    if area.width == 0 {
        return;
    }
    let paused = state.selected_frame_paused();
    let buttons = [
        ButtonSpec::new("Forward", ActionId::WebSocketForward, paused)
            .key("f")
            .primary(),
        ButtonSpec::new("Drop", ActionId::WebSocketDrop, paused)
            .key("d")
            .danger(),
        ButtonSpec::new("Modify", ActionId::WebSocketModify, paused).key("m"),
        ButtonSpec::new(
            "Next paused",
            ActionId::WebSocketNextPaused,
            state.pending_count() > 0,
        )
        .key("n"),
        ButtonSpec::new(
            "Clear",
            ActionId::WebSocketClear,
            !state.connections().is_empty(),
        )
        .key("c"),
    ];
    let hovered = app.hover.as_ref();
    let used = button_row(frame, area, &buttons, theme, hovered, output);
    let rest = area.width.saturating_sub(used);
    if rest > 12 {
        let filter_area = Rect::new(area.x + used, area.y, rest, 1);
        render_filter(frame, filter_area, state, theme);
    }
}

fn render_filter(frame: &mut Frame, area: Rect, state: &WebSocketState, theme: &Theme) {
    let mut spans = vec![Span::styled(" Filter ", theme.accent())];
    if state.filter().is_empty() {
        spans.push(Span::styled(
            if state.searching {
                "type opcode, direction, id or payload"
            } else {
                "press / to filter frames"
            },
            theme.faint(),
        ));
    } else {
        spans.push(Span::styled(
            sanitize_for_display(state.filter()),
            theme.text(),
        ));
    }
    if state.searching {
        spans.push(Span::styled("▏", theme.accent()));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn render_connections(
    frame: &mut Frame,
    area: Rect,
    state: &WebSocketState,
    focused: bool,
    theme: &Theme,
    output: &mut RenderOutput,
) {
    let block = focused_panel(theme, "CONNECTIONS", focused);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    output.zone(inner, ScrollRegion::WebSocketConnections);
    if inner.height == 0 || inner.width == 0 {
        return;
    }
    if state.connections().is_empty() {
        frame.render_widget(
            Paragraph::new(Span::styled(" no connections", theme.faint())),
            inner,
        );
        return;
    }

    let selected = state
        .connections()
        .iter()
        .position(|connection| Some(connection.id) == state.selected_connection_id())
        .unwrap_or(0);
    let start = window_start(selected, state.connections().len(), inner.height as usize);
    for (offset, connection) in state
        .connections()
        .iter()
        .skip(start)
        .take(inner.height as usize)
        .enumerate()
    {
        let is_selected = Some(connection.id) == state.selected_connection_id();
        let y = inner.y + offset as u16;
        let spans = vec![
            Span::styled(
                if is_selected { "▸ " } else { "  " },
                if is_selected {
                    theme.accent()
                } else {
                    theme.faint()
                },
            ),
            Span::styled(truncate(&connection.host, 14), theme.text()),
            Span::styled(":", theme.faint()),
            Span::styled(connection.port.to_string(), theme.muted()),
        ];
        let line = Line::from(spans);
        let style = if is_selected {
            theme.selected()
        } else {
            Style::new().bg(theme.palette.surface)
        };
        frame.render_widget(
            Paragraph::new(line).style(style),
            Rect::new(inner.x, y, inner.width, 1),
        );
        output.hit(
            Rect::new(inner.x, y, inner.width, 1),
            HitTarget::WebSocketConnection(connection.id),
        );
    }
}

fn render_frames(
    frame: &mut Frame,
    area: Rect,
    state: &WebSocketState,
    focused: bool,
    theme: &Theme,
    output: &mut RenderOutput,
) {
    let title = match state.selected_connection() {
        Some(connection) => format!(
            "FRAMES · {} frames",
            state.frames_for(Some(connection.id)).len()
        ),
        None => "FRAMES".to_string(),
    };
    let block = focused_panel(theme, &title, focused);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    output.zone(inner, ScrollRegion::WebSocketFrames);
    if inner.height == 0 || inner.width == 0 {
        return;
    }

    let frames = state.visible_frames();
    if frames.is_empty() {
        let message = if state.connections().is_empty() {
            "None yet. Only HTTP/1.1 upgrade requests are relayed and captured."
        } else if state.filter().is_empty() {
            "This connection has no captured frames yet."
        } else {
            "No frames match the filter."
        };
        frame.render_widget(
            Paragraph::new(Span::styled(format!(" {message}"), theme.faint()))
                .wrap(Wrap { trim: true }),
            inner,
        );
        return;
    }

    let selected = frames
        .iter()
        .position(|frame| Some(frame.id) == state.selected_frame_id())
        .unwrap_or(frames.len() - 1);
    let start = window_start(selected, frames.len(), inner.height as usize);
    for (offset, entry) in frames
        .iter()
        .skip(start)
        .take(inner.height as usize)
        .enumerate()
    {
        let y = inner.y + offset as u16;
        let is_selected = Some(entry.id) == state.selected_frame_id();
        let marker = if state.is_paused(entry.id) {
            Span::styled("P", theme.warning())
        } else {
            Span::styled(
                outcome_marker(entry.interception),
                outcome_style(theme, entry.interception),
            )
        };
        let arrow = match entry.direction {
            WebSocketDirection::ClientToServer => "→",
            WebSocketDirection::ServerToClient => "←",
        };
        let mut spans = vec![
            Span::styled(
                if is_selected { "▸" } else { " " },
                if is_selected {
                    theme.accent()
                } else {
                    theme.faint()
                },
            ),
            marker,
            Span::raw(" "),
            Span::styled(format!("{arrow} "), theme.muted()),
            Span::styled(
                format!("{:<12}", entry.opcode.label()),
                opcode_style(theme, entry.opcode),
            ),
            Span::styled(format!("{:>6} B ", entry.payload_len), theme.muted()),
            Span::styled(
                truncate(
                    &frame_preview(entry),
                    inner.width.saturating_sub(32) as usize,
                ),
                theme.faint(),
            ),
        ];
        if !entry.fin {
            spans.push(Span::styled(" …", theme.warning()));
        }
        let line = Line::from(std::mem::take(&mut spans));
        let style = if is_selected {
            theme.selected()
        } else {
            Style::new().bg(theme.palette.surface)
        };
        frame.render_widget(
            Paragraph::new(line).style(style),
            Rect::new(inner.x, y, inner.width, 1),
        );
        output.hit(
            Rect::new(inner.x, y, inner.width, 1),
            HitTarget::WebSocketFrame(entry.id),
        );
    }
}

fn render_inspector(
    frame: &mut Frame,
    area: Rect,
    state: &WebSocketState,
    enabled: bool,
    theme: &Theme,
    app: &App,
    output: &mut RenderOutput,
) {
    let block = focused_panel(theme, "INSPECTOR", false);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.height == 0 || inner.width == 0 {
        return;
    }
    if state.editing() {
        output.zone(inner, ScrollRegion::WebSocketInspector);
        render_editor(frame, inner, state, theme);
        return;
    }
    output.zone(inner, ScrollRegion::WebSocketInspector);

    if state.connections().is_empty() {
        empty_state(
            frame,
            inner,
            theme,
            "No WebSocket traffic",
            &[
                "WebSocket frames are captured only through an HTTP/1.1 upgrade that the proxy relays.",
                "HTTP/2 extended CONNECT (RFC 8441) and HTTP/3 WebSockets are not supported.",
            ],
            Some(if app.engine_available() {
                "Start the proxy, then point a client at an in-scope ws:// or wss:// endpoint."
            } else {
                "Run the packaged RAWFRAME binary to attach the proxy engine."
            }),
        );
        return;
    }

    let mut lines: Vec<Line<'static>> = Vec::new();
    if let Some(connection) = state.selected_connection() {
        lines.extend(connection_lines(connection, theme));
    }
    if let Some(frame) = state.selected_frame() {
        lines.push(Line::from(""));
        lines.extend(frame_lines(frame, state, theme));
    }
    if let Some(message) = state.messages_for_selected().last() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("MESSAGE", theme.label())));
        lines.push(Line::from(vec![
            Span::styled(format!("#{} ", message.id.0), theme.accent_bold()),
            Span::styled(
                format!("{} · {} B", message.opcode.label(), message.payload_len),
                theme.muted(),
            ),
            Span::styled(
                format!(
                    " · {} · {} frames",
                    if message.complete {
                        "complete"
                    } else {
                        "incomplete"
                    },
                    message.frame_ids.len()
                ),
                theme.faint(),
            ),
        ]));
        lines.extend(payload_lines(
            &message.payload,
            message.payload_omitted,
            theme,
        ));
    }
    if !enabled {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Interception is off: frames are forwarded unchanged. Press i to arm it.",
            theme.faint(),
        )));
    }

    let scroll = state.inspector_scroll() as usize;
    let visible: Vec<Line<'static>> = lines.into_iter().skip(scroll).collect();
    frame.render_widget(
        Paragraph::new(visible)
            .style(Style::new().bg(theme.palette.surface))
            .wrap(Wrap { trim: false }),
        inner,
    );
}

fn connection_lines(connection: &WebSocketConnection, theme: &Theme) -> Vec<Line<'static>> {
    let scheme = if connection.tls { "wss" } else { "ws" };
    vec![
        Line::from(vec![
            Span::styled("CONNECTION ", theme.label()),
            Span::styled(format!("#{}", connection.id.0), theme.accent_bold()),
            Span::raw("  "),
            source_badge(theme, connection.source),
        ]),
        Line::from(Span::styled(
            format!(
                "{scheme}://{}:{}{}",
                connection.host, connection.port, connection.path
            ),
            theme.text(),
        )),
        Line::from(vec![
            Span::styled("state ", theme.faint()),
            Span::styled(
                format!("{:?}", connection.state).to_lowercase(),
                theme.muted(),
            ),
            Span::styled("  subprotocol ", theme.faint()),
            Span::styled(
                connection
                    .subprotocol
                    .clone()
                    .unwrap_or_else(|| "none".into()),
                theme.muted(),
            ),
        ]),
        Line::from(vec![
            Span::styled("frames ", theme.faint()),
            Span::styled(connection.frames.to_string(), theme.muted()),
            Span::styled("  messages ", theme.faint()),
            Span::styled(connection.messages.to_string(), theme.muted()),
            Span::styled("  bytes ↑ ", theme.faint()),
            Span::styled(
                format_bytes(connection.bytes_client_to_server as usize),
                theme.muted(),
            ),
            Span::styled(" ↓ ", theme.faint()),
            Span::styled(
                format_bytes(connection.bytes_server_to_client as usize),
                theme.muted(),
            ),
        ]),
        Line::from(vec![
            Span::styled("started ", theme.faint()),
            Span::styled(
                connection.started_at.format("%H:%M:%S").to_string(),
                theme.muted(),
            ),
            match connection.closed_at {
                Some(closed) => Span::styled(
                    format!("  closed {}", closed.format("%H:%M:%S")),
                    theme.faint(),
                ),
                None => Span::styled("  open", theme.success()),
            },
        ]),
    ]
    .into_iter()
    .chain(connection.error.as_ref().map(|error| {
        Line::from(Span::styled(
            format!("error: {}", sanitize_for_display(error)),
            theme.danger(),
        ))
    }))
    .collect()
}

fn frame_lines(
    frame: &WebSocketFrame,
    state: &WebSocketState,
    theme: &Theme,
) -> Vec<Line<'static>> {
    let direction = match frame.direction {
        WebSocketDirection::ClientToServer => "client → server",
        WebSocketDirection::ServerToClient => "server → client",
    };
    let mut lines = vec![
        Line::from(vec![
            Span::styled("FRAME ", theme.label()),
            Span::styled(format!("#{}", frame.id.0), theme.accent_bold()),
            Span::raw("  "),
            Span::styled(direction, theme.muted()),
            Span::raw("  "),
            Span::styled(
                frame.timestamp.format("%H:%M:%S%.3f").to_string(),
                theme.faint(),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                frame.opcode.label().to_string(),
                opcode_style(theme, frame.opcode),
            ),
            Span::styled(format!(" · {} B", frame.payload_len), theme.muted()),
            Span::styled(
                format!(
                    " · FIN {} · {} · {}",
                    if frame.fin { "yes" } else { "no" },
                    if frame.masked { "masked" } else { "unmasked" },
                    if state.is_paused(frame.id) {
                        "paused".to_string()
                    } else {
                        frame.interception.label().to_string()
                    }
                ),
                if state.is_paused(frame.id) {
                    theme.warning()
                } else {
                    theme.faint()
                },
            ),
        ]),
    ];
    if frame.truncated {
        lines.push(Line::from(Span::styled(
            format!("payload truncated to {} B for capture", frame.payload.len()),
            theme.warning(),
        )));
    }
    lines.extend(payload_lines(&frame.payload, frame.payload_omitted, theme));
    lines
}

fn render_editor(frame: &mut Frame, area: Rect, state: &WebSocketState, theme: &Theme) {
    let Some(editor) = state.editor() else {
        return;
    };
    let mut lines = vec![Line::from(vec![
        Span::styled(
            if state.composing() {
                "COMPOSE TEXT FRAME"
            } else {
                "MODIFY PAYLOAD"
            },
            theme.label(),
        ),
        Span::styled("  Enter newline · ^Enter send · Esc cancel", theme.faint()),
    ])];
    let scroll = editor.scroll() as usize;
    for line in editor
        .lines()
        .iter()
        .skip(scroll)
        .take(area.height.saturating_sub(2) as usize)
    {
        lines.push(Line::from(Span::styled(
            sanitize_for_display(line),
            theme.text(),
        )));
    }
    frame.render_widget(
        Paragraph::new(lines).style(Style::new().bg(theme.palette.surface)),
        area,
    );
}

fn payload_lines(payload: &[u8], omitted: bool, theme: &Theme) -> Vec<Line<'static>> {
    if omitted {
        return vec![Line::from(Span::styled(
            "payload withheld by the storage policy",
            theme.warning(),
        ))];
    }
    if payload.is_empty() {
        return vec![Line::from(Span::styled("empty payload", theme.faint()))];
    }
    match std::str::from_utf8(payload) {
        Ok(text) => sanitize_for_display(text)
            .lines()
            .take(TEXT_PREVIEW_LINES)
            .map(|line| Line::from(Span::styled(line.to_string(), theme.text())))
            .collect(),
        Err(_) => hex_lines(payload)
            .into_iter()
            .map(|line| Line::from(Span::styled(line, theme.muted())))
            .collect(),
    }
}

fn hex_lines(payload: &[u8]) -> Vec<String> {
    payload
        .chunks(16)
        .take(HEX_PREVIEW_LINES)
        .enumerate()
        .map(|(index, chunk)| {
            let hex = chunk
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<Vec<_>>()
                .join(" ");
            let ascii: String = chunk
                .iter()
                .map(|byte| {
                    if byte.is_ascii_graphic() || *byte == b' ' {
                        *byte as char
                    } else {
                        '.'
                    }
                })
                .collect();
            format!("{:04x}  {hex:<47}  {ascii}", index * 16)
        })
        .collect()
}

fn frame_preview(frame: &WebSocketFrame) -> String {
    if frame.payload_omitted {
        return "payload withheld".into();
    }
    if frame.payload.is_empty() {
        return String::new();
    }
    match std::str::from_utf8(&frame.payload) {
        Ok(text) => sanitize_for_display(text).replace(['\n', '\r'], " "),
        Err(_) => format!(
            "binary · {}",
            hex_lines(&frame.payload[..frame.payload.len().min(16)])[0]
        ),
    }
}

fn outcome_marker(outcome: WebSocketInterceptionOutcome) -> &'static str {
    match outcome {
        WebSocketInterceptionOutcome::Forwarded => " ",
        WebSocketInterceptionOutcome::Modified => "M",
        WebSocketInterceptionOutcome::Dropped => "D",
        WebSocketInterceptionOutcome::Cancelled => "C",
        WebSocketInterceptionOutcome::TimedOut => "T",
    }
}

fn outcome_style(theme: &Theme, outcome: WebSocketInterceptionOutcome) -> Style {
    match outcome {
        WebSocketInterceptionOutcome::Forwarded => theme.faint(),
        WebSocketInterceptionOutcome::Modified => theme.accent_bold(),
        WebSocketInterceptionOutcome::Dropped => theme.danger(),
        WebSocketInterceptionOutcome::Cancelled | WebSocketInterceptionOutcome::TimedOut => {
            theme.warning()
        }
    }
}

fn opcode_style(theme: &Theme, opcode: WebSocketOpcode) -> Style {
    if opcode.is_control() {
        theme.warning().add_modifier(Modifier::DIM)
    } else {
        theme.text()
    }
}
