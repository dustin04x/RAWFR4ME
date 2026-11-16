//! In-memory rendering helpers for integration and snapshot tests.
//!
//! Rendering through [`render_frame`] applies hit-testing state to the app, which
//! lets tests drive real mouse and keyboard flows without a terminal.

use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::layout::Position;

use crate::app::App;
use crate::interaction::{HitTarget, RenderOutput};
use crate::ui;

/// Renders a frame, updates the application's hit map, and returns the buffer.
pub fn render_frame(app: &mut App, width: u16, height: u16) -> Buffer {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("test backend");
    let mut output = RenderOutput::default();
    terminal
        .draw(|frame| {
            output = ui::render(frame, app);
        })
        .expect("draw");
    app.apply_render(output);
    terminal.backend().buffer().clone()
}

/// Returns the centre of the first recorded hit rectangle for `target`.
pub fn position_for(app: &App, target: &HitTarget) -> Option<Position> {
    app.render
        .hits
        .iter()
        .find(|hit| &hit.target == target)
        .map(|hit| {
            Position::new(
                hit.rect.x + hit.rect.width / 2,
                hit.rect.y + hit.rect.height / 2,
            )
        })
}

pub fn text(buffer: &Buffer) -> String {
    ui::buffer_text(buffer)
}
