//! The mint palette (DESIGN.md, CONTRACT §9) for terminals (CONTRACT §20.3): truecolor tokens
//! with 256- and 16-colour fallbacks, light and dark, `NO_COLOR`. `mo-tui` owns the details.

use ratatui::style::{Color, Modifier, Style};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Depth {
    TrueColor,
    Ansi256,
    Ansi16,
    NoColor,
}

#[derive(Clone, Copy, Debug)]
pub struct Theme {
    pub depth: Depth,
    pub dark: bool,
    pub ascii: bool,
}

impl Theme {
    /// Ink (navy) — text on light, background on dark.
    #[must_use]
    pub fn ink(&self) -> Color {
        self.pick((0x14, 0x21, 0x3D), 17, Color::Blue)
    }

    /// Mint — brand and calls to action.
    #[must_use]
    pub fn mint(&self) -> Color {
        self.pick((0x7D, 0xD3, 0xAE), 115, Color::Green)
    }

    /// Sky — base accent.
    #[must_use]
    pub fn sky(&self) -> Color {
        self.pick((0xA6, 0xCB, 0xEA), 153, Color::Cyan)
    }

    /// Butter — donated tokens (suns/coins).
    #[must_use]
    pub fn butter(&self) -> Color {
        self.pick((0xFF, 0xE0, 0x8A), 222, Color::Yellow)
    }

    /// Coral-soft — stop / error.
    #[must_use]
    pub fn coral(&self) -> Color {
        self.pick((0xFF, 0x9E, 0x94), 210, Color::Red)
    }

    #[must_use]
    pub fn text(&self) -> Style {
        Style::default()
    }

    #[must_use]
    pub fn accent(&self) -> Style {
        Style::default().fg(self.mint()).add_modifier(Modifier::BOLD)
    }

    fn pick(self, rgb: (u8, u8, u8), idx256: u8, ansi16: Color) -> Color {
        match self.depth {
            Depth::TrueColor => Color::Rgb(rgb.0, rgb.1, rgb.2),
            Depth::Ansi256 => Color::Indexed(idx256),
            Depth::Ansi16 => ansi16,
            Depth::NoColor => Color::Reset,
        }
    }
}
