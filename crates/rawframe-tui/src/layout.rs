//! Shell geometry. Both rendering and mouse hit-testing use these rectangles so
//! no interaction depends on hard-coded screen coordinates.

use ratatui::layout::Rect;

pub const MIN_TERMINAL_WIDTH: u16 = 72;
pub const MIN_TERMINAL_HEIGHT: u16 = 20;
const HEADER_HEIGHT: u16 = 2;
const FOOTER_HEIGHT: u16 = 2;
const SIDEBAR_BREAKPOINT: u16 = 88;
const CONTEXT_BREAKPOINT: u16 = 116;
/// Below this width the inspector is not useful even with the navigation
/// collapsed, so it is hidden (the workspace keeps the full width).
const CONTEXT_MIN_TERMINAL_WIDTH: u16 = 84;
const SIDEBAR_MIN: u16 = 16;
const SIDEBAR_MAX: u16 = 24;
const CONTEXT_MIN: u16 = 30;
const CONTEXT_MAX: u16 = 56;
const WORKSPACE_MIN: u16 = 34;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DragTarget {
    Sidebar,
    Context,
}

#[derive(Debug, Clone)]
pub struct LayoutState {
    pub sidebar_width: u16,
    pub context_ratio: f32,
    pub context_open: bool,
}

impl Default for LayoutState {
    fn default() -> Self {
        Self {
            sidebar_width: 20,
            context_ratio: 0.30,
            context_open: true,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AppLayout {
    pub too_small: bool,
    pub header: Rect,
    pub body: Rect,
    pub sidebar: Option<Rect>,
    pub sidebar_divider: Option<Rect>,
    pub workspace: Rect,
    pub context_divider: Option<Rect>,
    pub context: Option<Rect>,
    pub footer: Rect,
}

/// Computes the persistent application shell.
///
/// At narrow widths the sidebar disappears (keyboard navigation remains
/// available). The inspector/context pane only appears when there is enough
/// room for a useful workspace and the operator has it enabled.
pub fn compute(area: Rect, state: &LayoutState, context_requested: bool) -> AppLayout {
    let too_small = area.width < MIN_TERMINAL_WIDTH || area.height < MIN_TERMINAL_HEIGHT;
    if area.width == 0 || area.height == 0 {
        return AppLayout {
            too_small: true,
            ..AppLayout::default()
        };
    }

    let header_height = HEADER_HEIGHT.min(area.height);
    let footer_height = FOOTER_HEIGHT.min(area.height.saturating_sub(header_height));
    let body = Rect {
        x: area.x,
        y: area.y + header_height,
        width: area.width,
        height: area.height.saturating_sub(header_height + footer_height),
    };
    let header = Rect {
        x: area.x,
        y: area.y,
        width: area.width,
        height: header_height,
    };
    let footer = Rect {
        x: area.x,
        y: area.bottom().saturating_sub(footer_height),
        width: area.width,
        height: footer_height,
    };

    if too_small || body.height == 0 {
        return AppLayout {
            too_small,
            header,
            body,
            workspace: body,
            footer,
            ..AppLayout::default()
        };
    }

    let context_requested = context_requested && state.context_open;
    let context_wanted = context_requested && area.width >= CONTEXT_MIN_TERMINAL_WIDTH;
    // Navigation is the first pane to collapse: below the wide breakpoint the
    // inspector and workspace take priority and navigation stays available on
    // the keyboard (Ctrl+1..6).
    let sidebar_allowed = if context_wanted {
        area.width >= CONTEXT_BREAKPOINT
    } else {
        area.width >= SIDEBAR_BREAKPOINT
    };
    let sidebar_width = state
        .sidebar_width
        .min(if context_wanted {
            // Keep navigation near 13-16% of a wide terminal so the inspector
            // and workspace keep their share at the breakpoint.
            ((u32::from(area.width) * 15 / 100) as u16).max(SIDEBAR_MIN)
        } else {
            SIDEBAR_MAX
        })
        .clamp(SIDEBAR_MIN, SIDEBAR_MAX)
        .min(area.width.saturating_sub(WORKSPACE_MIN + 1));
    let show_sidebar = sidebar_allowed && sidebar_width >= SIDEBAR_MIN;

    let mut x = body.x;
    let mut sidebar = None;
    let mut sidebar_divider = None;
    if show_sidebar {
        sidebar = Some(Rect::new(x, body.y, sidebar_width, body.height));
        x += sidebar_width;
        sidebar_divider = Some(Rect::new(x, body.y, 1, body.height));
        x += 1;
    }

    let mut context = None;
    let mut context_divider = None;
    if context_wanted {
        let reserved = x - body.x;
        let available = area.width.saturating_sub(reserved + 1 + WORKSPACE_MIN);
        if available >= CONTEXT_MIN {
            // Target inspector ~28-32% on wide terminals while remaining useful.
            let target_ratio = if area.width >= 120 {
                0.30
            } else if area.width >= 108 {
                0.32
            } else {
                0.34
            };
            let desired = (area.width as f32
                * state
                    .context_ratio
                    .clamp(0.26, 0.40)
                    .min(target_ratio + 0.04))
            .round() as u16;
            let mut context_width = desired.clamp(CONTEXT_MIN, CONTEXT_MAX).min(available);
            let min_ratio = if area.width >= 120 { 0.28 } else { 0.26 };
            let min_w = ((area.width as f32 * min_ratio).round() as u16)
                .clamp(CONTEXT_MIN, CONTEXT_MAX)
                .min(available);
            let max_w = ((area.width as f32 * 0.34).round() as u16)
                .clamp(CONTEXT_MIN, CONTEXT_MAX)
                .min(available);
            context_width = context_width.max(min_w).min(max_w.max(min_w));
            let context_x = area.right().saturating_sub(context_width);
            context = Some(Rect::new(context_x, body.y, context_width, body.height));
            context_divider = Some(Rect::new(
                context_x.saturating_sub(1),
                body.y,
                1,
                body.height,
            ));
        }
    }

    let workspace_width = area
        .right()
        .saturating_sub(x)
        .saturating_sub(context.map_or(0, |rect| rect.width + 1));

    AppLayout {
        too_small,
        header,
        body,
        sidebar,
        sidebar_divider,
        workspace: Rect::new(
            x,
            body.y,
            workspace_width.max(WORKSPACE_MIN.min(body.width)),
            body.height,
        ),
        context_divider,
        context,
        footer,
    }
}

impl LayoutState {
    pub fn resize_sidebar(&mut self, area: Rect, pointer_x: u16) {
        let width = pointer_x.saturating_sub(area.x);
        self.sidebar_width = width.clamp(SIDEBAR_MIN, SIDEBAR_MAX);
    }

    pub fn resize_context(&mut self, area: Rect, pointer_x: u16) {
        if area.width == 0 {
            return;
        }
        let width = u32::from(area.right().saturating_sub(pointer_x));
        let ratio = width as f32 / f32::from(area.width);
        self.context_ratio = ratio.clamp(0.24, 0.42);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wide() -> Rect {
        Rect::new(0, 0, 140, 40)
    }

    #[test]
    fn wide_layout_has_sidebar_and_context() {
        let layout = compute(wide(), &LayoutState::default(), true);
        assert!(!layout.too_small);
        assert!(layout.sidebar.is_some());
        assert!(layout.context.is_some());
        assert!(layout.workspace.width >= WORKSPACE_MIN);
        assert_eq!(layout.header.height, HEADER_HEIGHT);
        assert_eq!(layout.footer.height, FOOTER_HEIGHT);
    }

    #[test]
    fn context_is_hidden_when_requested_off_or_too_narrow() {
        let layout = compute(wide(), &LayoutState::default(), false);
        assert!(layout.context.is_none());

        let state = LayoutState {
            context_open: false,
            ..LayoutState::default()
        };
        let layout = compute(wide(), &state, true);
        assert!(layout.context.is_none());

        // Too narrow for a readable inspector: the workspace keeps the width.
        let tiny = compute(Rect::new(0, 0, 80, 24), &LayoutState::default(), true);
        assert!(tiny.context.is_none());
        assert_eq!(tiny.workspace.width, 80);
    }

    #[test]
    fn wide_workspace_proportions_stay_in_target_range() {
        let layout = compute(wide(), &LayoutState::default(), true);
        let sidebar = layout.sidebar.expect("sidebar on wide terminals").width;
        let context = layout.context.expect("inspector on wide terminals").width;
        let nav = f32::from(sidebar) / 140.0;
        let main = f32::from(layout.workspace.width) / 140.0;
        let inspector = f32::from(context) / 140.0;
        assert!((0.13..=0.16).contains(&nav), "nav {nav}");
        assert!((0.52..=0.58).contains(&main), "main {main}");
        assert!((0.28..=0.32).contains(&inspector), "inspector {inspector}");
    }

    #[test]
    fn narrow_inspector_collapses_navigation_instead_of_clipping() {
        for width in [84u16, 90, 96, 100, 110] {
            let layout = compute(Rect::new(0, 0, width, 30), &LayoutState::default(), true);
            assert!(
                layout.sidebar.is_none(),
                "sidebar should collapse at {width}"
            );
            let context = layout
                .context
                .unwrap_or_else(|| panic!("inspector missing at {width}"));
            assert!(layout.workspace.width >= 44, "workspace at {width}");
            assert!(context.width >= CONTEXT_MIN, "inspector at {width}");
        }
    }

    #[test]
    fn medium_layout_keeps_navigation_wide_enough_for_all_panes() {
        let layout = compute(Rect::new(0, 0, 120, 30), &LayoutState::default(), true);
        let sidebar = layout.sidebar.expect("sidebar at 120").width;
        let context = layout.context.expect("inspector at 120").width;
        assert!(sidebar <= 18, "navigation too wide: {sidebar}");
        assert!(layout.workspace.width >= 58, "workspace at 120");
        assert!((0.28..=0.34).contains(&(f32::from(context) / 120.0)));
    }

    #[test]
    fn narrow_layout_drops_sidebar_and_workspace_uses_full_width() {
        let layout = compute(Rect::new(0, 0, 80, 24), &LayoutState::default(), true);
        assert!(layout.sidebar.is_none());
        assert!(layout.context.is_none());
        assert_eq!(layout.workspace.x, 0);
        assert!(layout.workspace.width >= 34);
    }

    #[test]
    fn terminal_size_guard_reports_small_areas() {
        let layout = compute(Rect::new(0, 0, 71, 24), &LayoutState::default(), true);
        assert!(layout.too_small);

        let layout = compute(Rect::new(0, 0, 120, 19), &LayoutState::default(), true);
        assert!(layout.too_small);
    }

    #[test]
    fn sidebar_and_context_resizing_are_clamped() {
        let mut state = LayoutState::default();
        let area = wide();
        state.resize_sidebar(area, 1);
        assert_eq!(state.sidebar_width, SIDEBAR_MIN);
        state.resize_sidebar(area, 250);
        assert_eq!(state.sidebar_width, SIDEBAR_MAX);
        state.resize_context(area, 0);
        assert!((0.24..=0.42).contains(&state.context_ratio));
    }
}
