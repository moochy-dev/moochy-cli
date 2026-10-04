//! Terminal style for human lines (never JSON): ANSI colour only on a terminal, honouring
//! `NO_COLOR`, `CLICOLOR=0` and `FORCE_COLOR`; truecolor with `COLORTERM=truecolor|24bit`, else the
//! 16 basic colours. Palette: Mint (brand, success), Butter (highlights), Coral-soft (errors).
//! Callers sanitize server strings (`util::clean`) before painting them.

use std::io::IsTerminal as _;
use std::sync::LazyLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    Mint,
    Butter,
    Coral,
    Dim,
    Bold,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Painter {
    /// The stream is a terminal (human text and OSC 8 links are welcome).
    pub tty: bool,
    pub color: bool,
    rgb: bool,
}

/// Colour on? `NO_COLOR` (non-empty) wins, then `FORCE_COLOR` (non-empty, not `0`), then
/// `CLICOLOR=0`, then a terminal that is not `TERM=dumb`.
pub fn color_enabled(tty: bool, var: impl Fn(&str) -> Option<String>) -> bool {
    let set = |k: &str| var(k).is_some_and(|v| !v.is_empty());
    if set("NO_COLOR") {
        return false;
    }
    if set("FORCE_COLOR") && var("FORCE_COLOR").as_deref() != Some("0") {
        return true;
    }
    tty && var("CLICOLOR").as_deref() != Some("0") && var("TERM").as_deref() != Some("dumb")
}

fn env(k: &str) -> Option<String> {
    std::env::var(k).ok()
}

impl Painter {
    pub fn new(tty: bool, var: impl Fn(&str) -> Option<String>) -> Self {
        let color = color_enabled(tty, &var);
        let rgb = matches!(var("COLORTERM").as_deref(), Some("truecolor" | "24bit"));
        Self { tty, color, rgb }
    }

    pub fn paint(&self, tone: Tone, s: &str) -> String {
        if !self.color {
            return s.to_owned();
        }
        let code = match (tone, self.rgb) {
            (Tone::Mint, true) => "38;2;125;211;174",
            (Tone::Butter, true) => "38;2;255;224;138",
            (Tone::Coral, true) => "38;2;255;158;148",
            (Tone::Mint, false) => "32",
            (Tone::Butter, false) => "33",
            (Tone::Coral, false) => "31",
            (Tone::Dim, _) => "2",
            (Tone::Bold, _) => "1",
        };
        format!("\x1b[{code}m{s}\x1b[0m")
    }

    pub fn ok(&self, s: &str) -> String {
        self.paint(Tone::Mint, s)
    }
    pub fn hi(&self, s: &str) -> String {
        self.paint(Tone::Butter, s)
    }
    pub fn bad(&self, s: &str) -> String {
        self.paint(Tone::Coral, s)
    }
    pub fn dim(&self, s: &str) -> String {
        self.paint(Tone::Dim, s)
    }
    pub fn bold(&self, s: &str) -> String {
        self.paint(Tone::Bold, s)
    }

    /// A mint `●` / coral `×` marker when coloured, else nothing (plain output stays as it was).
    pub fn mark(&self, ok: bool) -> String {
        match (self.color, ok) {
            (false, _) => String::new(),
            (true, true) => self.ok("● "),
            (true, false) => self.bad("× "),
        }
    }

    /// `url` as an OSC 8 hyperlink on a terminal; its text is the URL itself, so it still copies
    /// as plain text anywhere. `url` must already be clean (no control characters).
    pub fn link(&self, url: &str) -> String {
        let text = self.ok(url);
        if self.tty { format!("\x1b]8;;{url}\x1b\\{text}\x1b]8;;\x1b\\") } else { text }
    }
}

static OUT: LazyLock<Painter> = LazyLock::new(|| Painter::new(std::io::stdout().is_terminal(), env));
static ERR: LazyLock<Painter> = LazyLock::new(|| Painter::new(std::io::stderr().is_terminal(), env));

/// Painter for stdout.
pub fn out() -> Painter {
    *OUT
}
/// Painter for stderr.
pub fn err() -> Painter {
    *ERR
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars<'a>(kv: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| kv.iter().find(|(n, _)| *n == k).map(|(_, v)| (*v).to_owned())
    }

    #[test]
    fn colour_gating() {
        assert!(color_enabled(true, vars(&[])));
        assert!(!color_enabled(false, vars(&[])), "not a terminal");
        assert!(!color_enabled(true, vars(&[("NO_COLOR", "1")])));
        assert!(color_enabled(true, vars(&[("NO_COLOR", "")])), "empty NO_COLOR is unset");
        assert!(!color_enabled(true, vars(&[("CLICOLOR", "0")])));
        assert!(!color_enabled(true, vars(&[("TERM", "dumb")])));
        assert!(color_enabled(false, vars(&[("FORCE_COLOR", "1")])));
        assert!(!color_enabled(false, vars(&[("FORCE_COLOR", "0")])));
        assert!(!color_enabled(false, vars(&[("FORCE_COLOR", "1"), ("NO_COLOR", "1")])), "NO_COLOR wins");
    }

    #[test]
    fn painting() {
        let plain = Painter::new(false, vars(&[]));
        assert_eq!(plain.ok("x"), "x");
        assert_eq!(plain.mark(true), "");
        assert_eq!(plain.link("https://a/b"), "https://a/b");
        let rgb = Painter::new(true, vars(&[("COLORTERM", "truecolor")]));
        assert_eq!(rgb.ok("x"), "\x1b[38;2;125;211;174mx\x1b[0m");
        let basic = Painter::new(true, vars(&[]));
        assert_eq!(basic.bad("x"), "\x1b[31mx\x1b[0m");
        assert!(basic.link("https://a/b").starts_with("\x1b]8;;https://a/b\x1b\\"));
        let no_color_tty = Painter::new(true, vars(&[("NO_COLOR", "1")]));
        assert_eq!(no_color_tty.link("u"), "\x1b]8;;u\x1b\\u\x1b]8;;\x1b\\", "a link without colour");
    }
}
