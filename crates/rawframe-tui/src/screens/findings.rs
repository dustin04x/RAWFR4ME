//! Security Findings workspace.

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table, Wrap};
use rawframe_analysis::{Finding, FindingStatus, Severity};

use crate::app::App;
use crate::components::{ButtonSpec, button_row, focused_panel, panel};
use crate::interaction::{ActionId, HitTarget, RenderOutput, ScrollRegion};
use crate::screens::window_start;
use crate::theme::Theme;

pub fn render(frame: &mut Frame, area: Rect, app: &App, theme: &Theme, output: &mut RenderOutput) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Length(2),
            Constraint::Min(4),
            Constraint::Length(2),
        ])
        .split(area);
    render_heading(frame, rows[0], app, theme);
    render_overview(frame, rows[1], app, theme);
    let body = if area.width >= 120 {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(62), Constraint::Percentage(38)])
            .split(rows[2])
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(48), Constraint::Percentage(52)])
            .split(rows[2])
    };
    render_table(frame, body[0], app, theme, output);
    render_inspector(frame, body[1], app, theme);
    render_actions(frame, rows[3], app, theme, output);
}

fn render_heading(frame: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let progress = app
        .analysis_scheduler
        .as_ref()
        .map_or(0, |scheduler| scheduler.pending_jobs());
    let status = if let Some(progress) = app.project_analysis.as_ref() {
        format!("PROJECT · {} / {}", progress.next_offset, progress.total)
    } else if app.project_analysis_completed {
        "PROJECT ANALYSIS COMPLETE".to_string()
    } else if app.findings_loading {
        format!("ANALYZING · {progress} PENDING")
    } else if let Some(error) = &app.findings_error {
        error.clone()
    } else {
        "PASSIVE · NO REQUESTS SENT".to_string()
    };
    let line = format!(
        "◆ SECURITY FINDINGS{}{}",
        if app.findings_search.is_empty() {
            ""
        } else {
            "  ·  SEARCH: "
        },
        app.findings_search
    );
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(line, theme.accent_bold()),
            Span::raw("   "),
            Span::styled(
                format!(" {status} "),
                if app.findings_error.is_some() {
                    theme.danger().bg(theme.palette.surface)
                } else {
                    theme.faint().bg(theme.palette.surface)
                },
            ),
        ]))
        .style(Style::new().bg(theme.palette.surface_elevated)),
        area,
    );
}

fn render_overview(frame: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let findings: Vec<Finding> = app.analysis_findings.values().cloned().collect();
    let count = |severity| {
        findings
            .iter()
            .filter(|finding| finding.severity == severity)
            .count()
    };
    let chip = |label: &str, value: usize, style: Style| {
        Span::styled(
            format!(" {label} {value} "),
            style.bg(theme.palette.surface_elevated),
        )
    };
    let line = Line::from(vec![
        Span::styled(
            format!(" {} TOTAL ", findings.len()),
            theme.on_accent().add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        chip("CRIT", count(Severity::Critical), theme.danger()),
        Span::raw(" "),
        chip("HIGH", count(Severity::High), theme.danger()),
        Span::raw(" "),
        chip("MED", count(Severity::Medium), theme.warning()),
        Span::raw(" "),
        chip("LOW", count(Severity::Low), theme.warning()),
        Span::raw(" "),
        chip("INFO", count(Severity::Informational), theme.info()),
        Span::styled("    │    ", theme.border_strong()),
        chip(
            "NEW/OPEN",
            findings
                .iter()
                .filter(|f| {
                    matches!(
                        f.status,
                        FindingStatus::New | FindingStatus::Open | FindingStatus::Reopened
                    )
                })
                .count(),
            theme.text(),
        ),
        Span::raw(" "),
        chip(
            "ACK",
            count_status(&findings, FindingStatus::Acknowledged),
            theme.muted(),
        ),
        Span::raw(" "),
        chip(
            "DISMISSED",
            count_status(&findings, FindingStatus::Dismissed),
            theme.faint(),
        ),
        Span::raw(" "),
        chip(
            "RESOLVED",
            count_status(&findings, FindingStatus::Resolved),
            theme.success(),
        ),
    ]);
    frame.render_widget(
        Paragraph::new(line).style(Style::new().bg(theme.palette.surface)),
        area,
    );
}

fn render_table(
    frame: &mut Frame,
    area: Rect,
    app: &App,
    theme: &Theme,
    output: &mut RenderOutput,
) {
    let block = focused_panel(theme, "FINDINGS", true);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    output.zone(inner, ScrollRegion::Findings);
    let findings = app.visible_findings();
    if inner.width == 0 || inner.height == 0 {
        return;
    }
    if findings.is_empty() {
        let message = if app.findings_loading {
            "Loading findings…"
        } else if let Some(error) = &app.findings_error {
            error.as_str()
        } else if app.analysis_findings.is_empty() {
            "No findings yet. Captured HTTP/1.1 and HTTP/2 responses are analyzed passively."
        } else {
            "No findings match the current filters."
        };
        frame.render_widget(
            Paragraph::new(message)
                .style(theme.muted())
                .wrap(Wrap { trim: true }),
            inner,
        );
        return;
    }
    let widths = if inner.width >= 100 {
        vec![
            Constraint::Length(9),
            Constraint::Length(5),
            Constraint::Length(20),
            Constraint::Min(14),
            Constraint::Length(9),
            Constraint::Length(12),
        ]
    } else {
        vec![
            Constraint::Length(8),
            Constraint::Length(5),
            Constraint::Length(20),
            Constraint::Length(9),
            Constraint::Min(18),
        ]
    };
    let head = if inner.width >= 100 {
        Row::new([
            "SEVERITY",
            "CONF",
            "RULE",
            "TARGET / RESOURCE",
            "STATUS",
            "FIRST OBSERVED",
        ])
        .style(theme.table_header())
    } else {
        Row::new(["SEVERITY", "CONF", "RULE", "STATUS", "TARGET / FIRST"])
            .style(theme.table_header())
    };
    let height = inner.height.saturating_sub(1) as usize;
    let start = window_start(app.findings_selected, findings.len(), height);
    let visible = findings.iter().skip(start).take(height);
    let mut table_rows = Vec::new();
    for (offset, finding) in visible.enumerate() {
        let selected = start + offset == app.findings_selected;
        let base = if selected {
            theme.selected_row()
        } else {
            theme.row(offset, false)
        };
        let severity = Line::from(vec![
            Span::styled("● ", severity_style(finding.severity, theme)),
            Span::styled(
                severity_label(finding.severity),
                severity_style(finding.severity, theme).add_modifier(Modifier::BOLD),
            ),
        ]);
        let target = format!("{} {}", finding.origin, finding.resource);
        let cells = if inner.width >= 100 {
            vec![
                Cell::from(severity),
                Cell::from(Span::styled(confidence_label(finding), theme.muted())),
                Cell::from(Span::styled(
                    finding.rule_id.as_str(),
                    if selected {
                        theme.accent_bright()
                    } else {
                        theme.body()
                    },
                )),
                Cell::from(Span::styled(target, theme.text())),
                Cell::from(Span::styled(
                    status_label(finding.status),
                    status_style(finding.status, theme),
                )),
                Cell::from(Span::styled(
                    finding.first_observed.format("%m-%d %H:%M").to_string(),
                    theme.faint(),
                )),
            ]
        } else {
            vec![
                Cell::from(severity),
                Cell::from(Span::styled(confidence_label(finding), theme.muted())),
                Cell::from(Span::styled(
                    finding.rule_id.as_str(),
                    if selected {
                        theme.accent_bright()
                    } else {
                        theme.body()
                    },
                )),
                Cell::from(Span::styled(
                    status_label(finding.status),
                    status_style(finding.status, theme),
                )),
                Cell::from(Line::from(vec![
                    Span::styled(target, theme.text()),
                    Span::styled(
                        format!(" · {}", finding.first_observed.format("%m-%d %H:%M")),
                        theme.faint(),
                    ),
                ])),
            ]
        };
        table_rows.push(Row::new(cells).style(base));
    }
    frame.render_widget(
        Table::new(table_rows, widths)
            .header(head)
            .column_spacing(1)
            .style(theme.surface()),
        inner,
    );
    for (offset, finding) in findings.iter().skip(start).take(height).enumerate() {
        output.hit(
            Rect::new(inner.x, inner.y + 1 + offset as u16, inner.width, 1),
            HitTarget::FindingRow(start + offset),
        );
        let _ = finding;
    }
}

fn render_inspector(frame: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let block = panel(theme, "FINDING INSPECTOR");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let Some(finding) = app.selected_finding() else {
        frame.render_widget(
            Paragraph::new("Select a finding to inspect evidence and remediation.")
                .style(theme.muted())
                .wrap(Wrap { trim: true }),
            inner,
        );
        return;
    };
    let mut lines = vec![
        Line::from(vec![
            Span::styled("● ", severity_style(finding.severity, theme)),
            Span::styled(
                finding.title.clone(),
                severity_style(finding.severity, theme).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                format!(" {} ", severity_label(finding.severity)),
                severity_style(finding.severity, theme).bg(theme.palette.surface_elevated),
            ),
            Span::raw(" "),
            Span::styled(
                format!(" {} CONF ", confidence_label(&finding)),
                theme.muted().bg(theme.palette.surface_elevated),
            ),
            Span::raw(" "),
            Span::styled(
                format!(" {} ", status_word(finding.status)),
                status_style(finding.status, theme).bg(theme.palette.surface_elevated),
            ),
        ]),
        Line::from(vec![
            Span::styled("Rule ", theme.faint()),
            Span::styled(finding.rule_id.clone(), theme.accent()),
            Span::styled(format!(" v{}", finding.rule_version), theme.faint()),
            Span::styled(
                format!("  ·  {} occurrence(s)", finding.occurrence_count),
                theme.faint(),
            ),
        ]),
        Line::from(vec![
            Span::styled("First ", theme.faint()),
            Span::styled(
                finding.first_observed.format("%F %T UTC").to_string(),
                theme.muted(),
            ),
            Span::styled("  ·  Last ", theme.faint()),
            Span::styled(
                finding.last_observed.format("%F %T UTC").to_string(),
                theme.muted(),
            ),
        ]),
        Line::from(""),
        Line::from(Span::styled(finding.description.clone(), theme.body())),
        Line::from(Span::styled(
            finding.technical_explanation.clone(),
            theme.muted(),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "IMPACT",
            theme.warning().add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(finding.impact.clone(), theme.body())),
        Line::from(""),
        Line::from(Span::styled(
            "REMEDIATION",
            theme.success().add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(finding.remediation.clone(), theme.body())),
        Line::from(""),
        Line::from(Span::styled(
            "EVIDENCE",
            theme.accent().add_modifier(Modifier::BOLD),
        )),
    ];
    for evidence in finding.evidence.iter().take(8) {
        let value = if evidence.redacted {
            "<redacted>"
        } else {
            evidence.value.as_deref().unwrap_or("field absent")
        };
        lines.push(Line::from(vec![
            Span::styled(format!("▸ Traffic {}", evidence.traffic_id), theme.accent()),
            Span::styled(format!(" · {:?} · ", evidence.side), theme.faint()),
            Span::styled(evidence.field.clone(), theme.muted()),
            Span::styled(" = ", theme.faint()),
            Span::styled(value.to_string(), theme.text()),
            Span::styled(
                if evidence.truncated {
                    " · truncated"
                } else {
                    ""
                },
                theme.warning(),
            ),
        ]));
        lines.push(Line::from(Span::styled(
            format!("  {}", evidence.explanation),
            theme.faint(),
        )));
    }
    if finding.evidence.len() > 8 {
        lines.push(Line::from(Span::styled(
            "Evidence display capped at 8 references.",
            theme.faint(),
        )));
    }
    let related = finding
        .related_traffic
        .iter()
        .take(6)
        .map(|id| id.0.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    lines.push(Line::from(vec![
        Span::styled("RELATED TRAFFIC  ", theme.faint()),
        Span::styled(related, theme.info()),
    ]));
    frame.render_widget(
        Paragraph::new(lines)
            .style(theme.text())
            .wrap(Wrap { trim: true }),
        inner,
    );
}

fn render_actions(
    frame: &mut Frame,
    area: Rect,
    app: &App,
    theme: &Theme,
    output: &mut RenderOutput,
) {
    let enabled = app.selected_finding().is_some();
    let actions = [
        ButtonSpec::new("Acknowledge", ActionId::FindingAcknowledge, enabled).key("A"),
        ButtonSpec::new("Dismiss", ActionId::FindingDismiss, enabled)
            .danger()
            .key("D"),
        ButtonSpec::new("Resolve", ActionId::FindingResolve, enabled).key("X"),
        ButtonSpec::new("Reopen", ActionId::FindingReopen, enabled).key("O"),
        ButtonSpec::new("Reanalyze", ActionId::FindingReanalyze, enabled)
            .primary()
            .key("R"),
        ButtonSpec::new(
            "Export selected JSON",
            ActionId::FindingExportSelected,
            enabled,
        )
        .key("e"),
        ButtonSpec::new(
            "Export all JSON",
            ActionId::FindingExportAll,
            !app.analysis_findings.is_empty(),
        )
        .key("E"),
    ];
    button_row(frame, area, &actions, theme, None, output);
}

fn count_status(findings: &[Finding], status: FindingStatus) -> usize {
    findings
        .iter()
        .filter(|finding| finding.status == status)
        .count()
}
fn severity_label(value: Severity) -> &'static str {
    match value {
        Severity::Critical => "CRIT",
        Severity::High => "HIGH",
        Severity::Medium => "MED",
        Severity::Low => "LOW",
        Severity::Informational => "INFO",
    }
}
fn severity_style(value: Severity, theme: &Theme) -> Style {
    theme.severity(value)
}

fn status_style(status: FindingStatus, theme: &Theme) -> Style {
    match status {
        FindingStatus::New | FindingStatus::Open | FindingStatus::Reopened => theme.info(),
        FindingStatus::Acknowledged => theme.muted(),
        FindingStatus::Dismissed => theme.faint(),
        FindingStatus::Resolved => theme.success(),
    }
}
fn confidence_label(finding: &Finding) -> &'static str {
    match finding.confidence {
        rawframe_analysis::Confidence::Low => "LOW",
        rawframe_analysis::Confidence::Medium => "MED",
        rawframe_analysis::Confidence::High => "HIGH",
        rawframe_analysis::Confidence::Confirmed => "CONF",
    }
}
fn status_word(status: FindingStatus) -> &'static str {
    match status {
        FindingStatus::New => "New",
        FindingStatus::Open => "Open",
        FindingStatus::Acknowledged => "Acknowledged",
        FindingStatus::Dismissed => "Dismissed",
        FindingStatus::Resolved => "Resolved",
        FindingStatus::Reopened => "Reopened",
    }
}

fn status_label(status: FindingStatus) -> &'static str {
    match status {
        FindingStatus::New => "NEW",
        FindingStatus::Open => "OPEN",
        FindingStatus::Acknowledged => "ACK",
        FindingStatus::Dismissed => "DISMISSED",
        FindingStatus::Resolved => "RESOLVED",
        FindingStatus::Reopened => "REOPENED",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use rawframe_analysis::{Category, Confidence};
    use rawframe_core::models::AppConfig;

    fn finding() -> Finding {
        Finding {
            id: "fp".into(),
            rule_id: "http.missing_hsts".into(),
            rule_version: "1".into(),
            category: Category::Transport,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: "HTTPS response is missing Strict-Transport-Security".into(),
            description: "Captured header is missing.".into(),
            technical_explanation: "Header absent on captured HTTPS response.".into(),
            impact: "Plain HTTP may remain available.".into(),
            remediation: "Configure HSTS.".into(),
            evidence: vec![],
            origin: "https://example.test:443".into(),
            resource: "path-sha256:abc".into(),
            related_traffic: vec![],
            first_observed: Utc::now(),
            last_observed: Utc::now(),
            occurrence_count: 1,
            status: FindingStatus::New,
            fingerprint: "fp".into(),
            session_id: None,
        }
    }

    #[test]
    fn workspace_remains_renderable_at_supported_terminal_sizes() {
        let mut app = App::new(AppConfig::default());
        app.nav = crate::interaction::NavSection::Findings;
        let item = finding();
        app.analysis_findings.insert(item.fingerprint.clone(), item);
        for (width, height) in [(140, 40), (100, 30), (80, 24)] {
            let buffer = crate::ui::render_test_frame(&app, width, height);
            let text = buffer
                .content
                .iter()
                .map(|cell| cell.symbol())
                .collect::<String>();
            assert!(text.contains("SECURITY FINDINGS"), "{width}x{height}");
            assert!(text.contains("http.missing_hsts"), "{width}x{height}");
            if width == 140 {
                assert!(text.contains("REMEDIATION"), "{width}x{height}");
            }
        }
    }
}
