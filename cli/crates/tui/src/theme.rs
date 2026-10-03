//! The mint palette (DESIGN.md, CONTRACT §9) for terminals (CONTRACT §20.3): truecolor tokens
//! with 256- and 16-colour fallbacks, light and dark, `NO_COLOR`, and an ASCII glyph set.
//!
//! We never paint the terminal's background: the user's own background shows through, and each
//! hue is picked per mode (the pastel "fill" on dark terminals, the "deep" variant on light ones,
//! DESIGN.md §2 contrast table). Meaning is never carried by colour alone: every status has a glyph
//! and a label ([`Glyph`]).

use ratatui::style::{Color, Modifier, Style};
use ratatui::symbols::border;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Depth {
    TrueColor,
    Ansi256,
    Ansi16,
    NoColor,
}

impl Depth {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Depth::TrueColor => "truecolor",
            Depth::Ansi256 => "256 colours",
            Depth::Ansi16 => "16 colours",
            Depth::NoColor => "no colour",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Theme {
    pub depth: Depth,
    pub dark: bool,
    pub ascii: bool,
}

impl Default for Theme {
    fn default() -> Self {
        Theme { depth: Depth::TrueColor, dark: true, ascii: false }
    }
}

/// Status glyphs, each with an ASCII fallback; always shown next to a label.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Glyph {
    Online,
    Offline,
    Connecting,
    Ok,
    Warn,
    Error,
    Paused,
    Pending,
    Stopped,
    Served,
    Used,
    Coin,
    Selected,
    Up,
    Down,
}

/// One environment reading, so detection is testable without touching the process env.
#[derive(Clone, Debug, Default)]
pub struct Env {
    pub no_color: Option<String>,
    pub colorterm: Option<String>,
    pub term: Option<String>,
    pub colorfgbg: Option<String>,
    pub moochy_theme: Option<String>,
}

impl Env {
    #[must_use]
    pub fn from_process() -> Env {
        let get = |k: &str| std::env::var(k).ok();
        Env {
            no_color: get("NO_COLOR"),
            colorterm: get("COLORTERM"),
            term: get("TERM"),
            colorfgbg: get("COLORFGBG"),
            moochy_theme: get("MOOCHY_THEME"),
        }
    }
}

impl Theme {
    /// Colour depth from `NO_COLOR` (non-empty wins, no-color.org), `COLORTERM`, `TERM`.
    /// Light/dark from the override (`--theme`, then `MOOCHY_THEME`), else `COLORFGBG`'s
    /// background index (7 or 15 = light), else dark.
    #[must_use]
    pub fn detect(env: &Env, theme: Option<&str>, ascii: bool) -> Theme {
        let term = env.term.as_deref().unwrap_or("");
        let ct = env.colorterm.as_deref().unwrap_or("");
        let depth = if env.no_color.as_deref().is_some_and(|v| !v.is_empty()) || term == "dumb" {
            Depth::NoColor
        } else if ct.eq_ignore_ascii_case("truecolor") || ct.eq_ignore_ascii_case("24bit") {
            Depth::TrueColor
        } else if term.contains("256") {
            Depth::Ansi256
        } else {
            Depth::Ansi16
        };
        let wanted = theme.or(env.moochy_theme.as_deref());
        let dark = match wanted {
            Some("light") => false,
            Some("dark") => true,
            _ => !env
                .colorfgbg
                .as_deref()
                .and_then(|v| v.rsplit(';').next())
                .is_some_and(|bg| bg == "7" || bg == "15"),
        };
        Theme { depth, dark, ascii: ascii || term == "linux" || term == "dumb" }
    }

    /// Ink (navy) — text on light, background on dark.
    #[must_use]
    pub fn ink(&self) -> Color {
        self.pick((0x14, 0x21, 0x3D), 17, Color::Blue)
    }

    /// Mint — brand and calls to action (Mint-deep on light terminals).
    #[must_use]
    pub fn mint(&self) -> Color {
        if self.dark {
            self.pick((0x7D, 0xD3, 0xAE), 115, Color::LightGreen)
        } else {
            self.pick((0x1A, 0x6B, 0x4A), 29, Color::Green)
        }
    }

    /// Sky — base accent, information.
    #[must_use]
    pub fn sky(&self) -> Color {
        if self.dark {
            self.pick((0xA6, 0xCB, 0xEA), 153, Color::LightCyan)
        } else {
            self.pick((0x1F, 0x4E, 0x79), 24, Color::Blue)
        }
    }

    /// Butter — donated tokens (suns/coins); Butter-deep (attention) on light terminals.
    #[must_use]
    pub fn butter(&self) -> Color {
        if self.dark {
            self.pick((0xFF, 0xE0, 0x8A), 222, Color::LightYellow)
        } else {
            self.pick((0x8A, 0x6A, 0x00), 136, Color::Yellow)
        }
    }

    /// Coral-soft — stop / error (Coral-deep on light terminals).
    #[must_use]
    pub fn coral(&self) -> Color {
        if self.dark {
            self.pick((0xFF, 0x9E, 0x94), 210, Color::LightRed)
        } else {
            self.pick((0xB4, 0x23, 0x18), 124, Color::Red)
        }
    }

    /// Blush — only the hamster's cheeks.
    #[must_use]
    pub fn blush(&self) -> Color {
        if self.dark {
            self.pick((0xF5, 0xB5, 0xC4), 218, Color::LightMagenta)
        } else {
            self.pick((0x9B, 0x2C, 0x4B), 125, Color::Magenta)
        }
    }

    /// Secondary text (labels, units, timestamps).
    #[must_use]
    pub fn muted(&self) -> Style {
        match self.depth {
            Depth::NoColor => Style::default().add_modifier(Modifier::DIM),
            _ if self.dark => Style::default().fg(self.pick((0x9A, 0xA6, 0xB8), 247, Color::Gray)),
            _ => Style::default().fg(self.pick((0x5B, 0x64, 0x75), 241, Color::DarkGray)),
        }
    }

    #[must_use]
    pub fn text(&self) -> Style {
        Style::default()
    }

    #[must_use]
    pub fn bold(&self) -> Style {
        Style::default().add_modifier(Modifier::BOLD)
    }

    #[must_use]
    pub fn accent(&self) -> Style {
        Style::default().fg(self.mint()).add_modifier(Modifier::BOLD)
    }

    #[must_use]
    pub fn ok(&self) -> Style {
        Style::default().fg(self.mint())
    }

    #[must_use]
    pub fn warn(&self) -> Style {
        Style::default().fg(self.butter())
    }

    #[must_use]
    pub fn err(&self) -> Style {
        Style::default().fg(self.coral())
    }

    #[must_use]
    pub fn info(&self) -> Style {
        Style::default().fg(self.sky())
    }

    /// Donated money: butter, the colour of tokens.
    #[must_use]
    pub fn money(&self) -> Style {
        Style::default().fg(self.butter())
    }

    /// The selected row / active tab: Ink on a Mint fill (9.0:1), reverse video without colour.
    #[must_use]
    pub fn selected(&self) -> Style {
        match self.depth {
            Depth::NoColor => Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD),
            _ => Style::default()
                .bg(self.pick((0x7D, 0xD3, 0xAE), 115, Color::Green))
                .fg(self.pick((0x14, 0x21, 0x3D), 17, Color::Black))
                .add_modifier(Modifier::BOLD),
        }
    }

    /// A key in the footer bar or help.
    #[must_use]
    pub fn key(&self) -> Style {
        self.accent()
    }

    #[must_use]
    pub fn border(&self) -> Style {
        self.muted().remove_modifier(Modifier::DIM)
    }

    #[must_use]
    pub fn border_focus(&self) -> Style {
        Style::default().fg(self.mint())
    }

    /// Rounded box drawing, or `+-|` with `--ascii`.
    #[must_use]
    pub fn border_set(&self) -> border::Set<'static> {
        if self.ascii {
            border::Set {
                top_left: "+",
                top_right: "+",
                bottom_left: "+",
                bottom_right: "+",
                vertical_left: "|",
                vertical_right: "|",
                horizontal_top: "-",
                horizontal_bottom: "-",
            }
        } else {
            border::ROUNDED
        }
    }

    #[must_use]
    pub fn glyph(&self, g: Glyph) -> &'static str {
        let (u, a) = match g {
            Glyph::Online => ("●", "*"),
            Glyph::Offline => ("○", "o"),
            Glyph::Connecting => ("◌", "."),
            Glyph::Ok => ("✔", "+"),
            Glyph::Warn => ("▲", "!"),
            Glyph::Error => ("✖", "x"),
            Glyph::Paused => ("‖", "="),
            Glyph::Pending => ("◆", "~"),
            Glyph::Stopped => ("■", "#"),
            Glyph::Served => ("↑", "^"),
            Glyph::Used => ("↓", "v"),
            Glyph::Coin => ("◉", "$"),
            Glyph::Selected => ("▶", ">"),
            Glyph::Up => ("▲", "^"),
            Glyph::Down => ("▼", "v"),
        };
        if self.ascii { a } else { u }
    }

    /// The style that goes with a glyph.
    #[must_use]
    pub fn glyph_style(&self, g: Glyph) -> Style {
        match g {
            Glyph::Online | Glyph::Ok | Glyph::Selected | Glyph::Used => self.ok(),
            Glyph::Warn | Glyph::Pending | Glyph::Paused => self.warn(),
            Glyph::Error | Glyph::Stopped => self.err(),
            Glyph::Coin | Glyph::Served => self.money(),
            Glyph::Offline | Glyph::Connecting | Glyph::Up | Glyph::Down => self.muted(),
        }
    }

    fn pick(&self, rgb: (u8, u8, u8), idx256: u8, ansi16: Color) -> Color {
        match self.depth {
            Depth::TrueColor => Color::Rgb(rgb.0, rgb.1, rgb.2),
            Depth::Ansi256 => Color::Indexed(idx256),
            Depth::Ansi16 => ansi16,
            Depth::NoColor => Color::Reset,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> Env {
        let mut e = Env::default();
        for (k, v) in pairs {
            let v = Some((*v).to_string());
            match *k {
                "NO_COLOR" => e.no_color = v,
                "COLORTERM" => e.colorterm = v,
                "TERM" => e.term = v,
                "COLORFGBG" => e.colorfgbg = v,
                _ => e.moochy_theme = v,
            }
        }
        e
    }

    #[test]
    fn detection() {
        let t = Theme::detect(&env(&[("COLORTERM", "truecolor"), ("TERM", "xterm-256color")]), None, false);
        assert_eq!((t.depth, t.dark, t.ascii), (Depth::TrueColor, true, false));
        assert_eq!(Theme::detect(&env(&[("TERM", "xterm-256color")]), None, false).depth, Depth::Ansi256);
        assert_eq!(Theme::detect(&env(&[("TERM", "xterm")]), None, false).depth, Depth::Ansi16);
        let t = Theme::detect(&env(&[("NO_COLOR", "1"), ("COLORTERM", "truecolor")]), None, false);
        assert_eq!(t.depth, Depth::NoColor);
        // An empty NO_COLOR does not count (no-color.org).
        assert_eq!(Theme::detect(&env(&[("NO_COLOR", ""), ("TERM", "xterm")]), None, false).depth, Depth::Ansi16);
        assert!(!Theme::detect(&env(&[("COLORFGBG", "0;15")]), None, false).dark);
        assert!(Theme::detect(&env(&[("COLORFGBG", "15;0")]), None, false).dark);
        assert!(Theme::detect(&env(&[("COLORFGBG", "0;15")]), Some("dark"), false).dark);
        assert!(!Theme::detect(&env(&[("MOOCHY_THEME", "light")]), None, false).dark);
        assert!(Theme::detect(&env(&[("TERM", "linux")]), None, false).ascii);
    }

    #[test]
    fn no_color_has_no_colours() {
        let t = Theme { depth: Depth::NoColor, dark: true, ascii: true };
        for s in [t.ok(), t.warn(), t.err(), t.accent(), t.selected(), t.muted()] {
            assert!(matches!(s.fg, None | Some(Color::Reset)), "{s:?}");
            assert!(matches!(s.bg, None | Some(Color::Reset)), "{s:?}");
        }
        assert!(t.glyph(Glyph::Online).is_ascii());
    }
}
