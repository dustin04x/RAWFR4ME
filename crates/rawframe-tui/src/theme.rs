//! The RAWFRAME visual system.
//!
//! Truecolor RGB values are used so the interface keeps its deep-charcoal
//! character on capable terminals. Semantic colors are reserved: green means
//! success, amber warning, red danger. The accent is applied sparingly to
//! focus, selection, and primary actions.

use ratatui::style::{Color, Modifier, Style};
use rawframe_core::models::message::StatusClass;
use rawframe_core::models::traffic::TrafficState;
use rawframe_core::{AccentPreset, NoticeLevel};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Palette {
    pub bg: Color,
    pub surface: Color,
    pub surface_elevated: Color,
    pub border: Color,
    pub border_strong: Color,
    pub text: Color,
    pub muted: Color,
    pub faint: Color,
    pub accent: Color,
    pub accent_bright: Color,
    pub selection: Color,
    pub success: Color,
    pub warning: Color,
    pub danger: Color,
}

const fn rgb(hex: u32) -> Color {
    Color::Rgb(
        ((hex >> 16) & 0xff) as u8,
        ((hex >> 8) & 0xff) as u8,
        (hex & 0xff) as u8,
    )
}

const VIOLET: Palette = Palette {
    bg: rgb(0x0b0b0f),
    surface: rgb(0x101016),
    surface_elevated: rgb(0x16161e),
    border: rgb(0x252530),
    border_strong: rgb(0x3a3a4a),
    text: rgb(0xd9d9e3),
    muted: rgb(0x8a8a9a),
    faint: rgb(0x5a5a69),
    accent: rgb(0xa78bfa),
    accent_bright: rgb(0xc4b5fd),
    selection: rgb(0x241e38),
    success: rgb(0x4ade80),
    warning: rgb(0xfbbf24),
    danger: rgb(0xf87171),
};

const INDIGO: Palette = Palette {
    bg: rgb(0x0a0b10),
    surface: rgb(0x0f1018),
    surface_elevated: rgb(0x151722),
    border: rgb(0x242636),
    border_strong: rgb(0x3a3d52),
    text: rgb(0xd9dae5),
    muted: rgb(0x898ca0),
    faint: rgb(0x595c6d),
    accent: rgb(0x818cf8),
    accent_bright: rgb(0xa5b4fc),
    selection: rgb(0x1e2440),
    success: rgb(0x4ade80),
    warning: rgb(0xfbbf24),
    danger: rgb(0xf87171),
};

const TEAL: Palette = Palette {
    bg: rgb(0x081011),
    surface: rgb(0x0d1618),
    surface_elevated: rgb(0x132024),
    border: rgb(0x213239),
    border_strong: rgb(0x385159),
    text: rgb(0xd8e3e4),
    muted: rgb(0x84989b),
    faint: rgb(0x566a6d),
    accent: rgb(0x5eead4),
    accent_bright: rgb(0x99f6e4),
    selection: rgb(0x14302e),
    success: rgb(0x4ade80),
    warning: rgb(0xfbbf24),
    danger: rgb(0xf87171),
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Theme {
    pub palette: Palette,
    pub accent: AccentPreset,
}

impl Theme {
    pub fn from_preset(accent: AccentPreset) -> Self {
        let palette = match accent {
            AccentPreset::Violet => VIOLET,
            AccentPreset::Indigo => INDIGO,
            AccentPreset::Teal => TEAL,
        };
        Self { palette, accent }
    }

    pub fn base(&self) -> Style {
        Style::new().fg(self.palette.text).bg(self.palette.bg)
    }

    pub fn surface(&self) -> Style {
        Style::new().fg(self.palette.text).bg(self.palette.surface)
    }

    pub fn text(&self) -> Style {
        Style::new().fg(self.palette.text)
    }

    pub fn muted(&self) -> Style {
        Style::new().fg(self.palette.muted)
    }

    pub fn faint(&self) -> Style {
        Style::new().fg(self.palette.faint)
    }

    pub fn accent(&self) -> Style {
        Style::new().fg(self.palette.accent)
    }

    pub fn accent_bold(&self) -> Style {
        Style::new()
            .fg(self.palette.accent)
            .add_modifier(Modifier::BOLD)
    }

    pub fn title(&self) -> Style {
        Style::new()
            .fg(self.palette.text)
            .add_modifier(Modifier::BOLD)
    }

    pub fn label(&self) -> Style {
        Style::new()
            .fg(self.palette.muted)
            .add_modifier(Modifier::BOLD)
    }

    pub fn border(&self) -> Style {
        Style::new().fg(self.palette.border)
    }

    pub fn border_focus(&self) -> Style {
        Style::new().fg(self.palette.border_strong)
    }

    pub fn border_strong(&self) -> Style {
        Style::new().fg(self.palette.border_strong)
    }

    pub fn selected(&self) -> Style {
        Style::new()
            .bg(self.palette.selection)
            .fg(self.palette.text)
    }

    pub fn selected_accent(&self) -> Style {
        Style::new()
            .bg(self.palette.selection)
            .fg(self.palette.accent_bright)
            .add_modifier(Modifier::BOLD)
    }

    pub fn primary_button(&self) -> Style {
        Style::new()
            .bg(self.palette.accent)
            .fg(self.palette.bg)
            .add_modifier(Modifier::BOLD)
    }

    pub fn secondary_button(&self) -> Style {
        Style::new()
            .bg(self.palette.surface_elevated)
            .fg(self.palette.text)
    }

    pub fn disabled(&self) -> Style {
        Style::new().fg(self.palette.faint)
    }

    pub fn on_accent(&self) -> Style {
        Style::new().bg(self.palette.accent).fg(self.palette.bg)
    }

    pub fn on_success(&self) -> Style {
        Style::new().bg(self.palette.success).fg(self.palette.bg)
    }

    pub fn on_warning(&self) -> Style {
        Style::new().bg(self.palette.warning).fg(self.palette.bg)
    }

    pub fn on_danger(&self) -> Style {
        Style::new().bg(self.palette.danger).fg(self.palette.bg)
    }

    pub fn success(&self) -> Style {
        Style::new().fg(self.palette.success)
    }

    pub fn warning(&self) -> Style {
        Style::new().fg(self.palette.warning)
    }

    pub fn danger(&self) -> Style {
        Style::new().fg(self.palette.danger)
    }

    pub fn status_class(&self, class: StatusClass) -> Style {
        match class {
            StatusClass::Success => self.success(),
            StatusClass::Redirection => Style::new().fg(self.palette.accent),
            StatusClass::ClientError => self.warning(),
            StatusClass::ServerError => self.danger(),
            StatusClass::Informational | StatusClass::Unknown => self.muted(),
        }
    }

    pub fn state(&self, state: TrafficState) -> Style {
        match state {
            TrafficState::Paused | TrafficState::Modified => self.warning(),
            TrafficState::Dropped | TrafficState::TimedOut | TrafficState::Cancelled => {
                self.danger()
            }
            TrafficState::Failed => self.danger(),
            TrafficState::Forwarded => self.accent(),
            TrafficState::Completed => self.success(),
            TrafficState::Captured => self.muted(),
        }
    }

    pub fn method(&self, method: &str) -> Style {
        match method {
            "GET" | "HEAD" => Style::new().fg(self.palette.text),
            "POST" => Style::new().fg(self.palette.accent),
            "PUT" | "PATCH" => Style::new().fg(self.palette.warning),
            "DELETE" => Style::new().fg(self.palette.danger),
            _ => self.muted(),
        }
    }

    pub fn notice(&self, level: NoticeLevel) -> Style {
        match level {
            NoticeLevel::Info => self.accent(),
            NoticeLevel::Success => self.success(),
            NoticeLevel::Warning => self.warning(),
            NoticeLevel::Error => self.danger(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_preset_has_a_distinct_accent() {
        let violet = Theme::from_preset(AccentPreset::Violet);
        let indigo = Theme::from_preset(AccentPreset::Indigo);
        let teal = Theme::from_preset(AccentPreset::Teal);

        assert_ne!(violet.palette.accent, indigo.palette.accent);
        assert_ne!(indigo.palette.accent, teal.palette.accent);
        assert_eq!(violet.palette.bg, rgb(0x0b0b0f));
    }

    #[test]
    fn semantic_styles_are_reserved() {
        let theme = Theme::from_preset(AccentPreset::Violet);
        assert_eq!(
            theme.status_class(StatusClass::Success).fg,
            Some(theme.palette.success)
        );
        assert_eq!(
            theme.status_class(StatusClass::ServerError).fg,
            Some(theme.palette.danger)
        );
        assert_eq!(
            theme.state(TrafficState::Paused).fg,
            Some(theme.palette.warning)
        );
        assert_eq!(
            theme.notice(NoticeLevel::Error).fg,
            Some(theme.palette.danger)
        );
    }
}
