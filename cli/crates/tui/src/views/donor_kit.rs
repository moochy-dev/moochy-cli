//! Small helpers shared by the donor tabs (Donations, Served, Devices & keys, Activity).
//! Owner: mo-tui-donor. Candidates to move into `widgets/` once mo-tui's shared widgets land.

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::symbols::{bar, border};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph, TableState, Wrap};

use super::Input;
use crate::theme::Theme;

/// Width from which a list gets its detail pane on the side instead of below.
pub const WIDE: u16 = 110;

const ASCII_BORDER: border::Set = border::Set {
    top_left: "+",
    top_right: "+",
    bottom_left: "+",
    bottom_right: "+",
    vertical_left: "|",
    vertical_right: "|",
    horizontal_top: "-",
    horizontal_bottom: "-",
};

pub const ASCII_BARS: bar::Set = bar::Set {
    full: "#",
    seven_eighths: "#",
    three_quarters: "=",
    five_eighths: "=",
    half: "-",
    three_eighths: "-",
    one_quarter: ".",
    one_eighth: ".",
    empty: " ",
};

/// The glyph for the terminal: Unicode, or its ASCII fallback (`--ascii`).
#[must_use]
pub fn g(theme: &Theme, uni: &'static str, ascii: &'static str) -> &'static str {
    if theme.ascii { ascii } else { uni }
}

/// The separator between items on one line.
#[must_use]
pub fn dot(theme: &Theme) -> &'static str {
    g(theme, " · ", " - ")
}

#[must_use]
pub fn block<'a>(theme: &Theme, title: impl Into<Line<'a>>) -> Block<'a> {
    Block::bordered().border_set(if theme.ascii { ASCII_BORDER } else { border::ROUNDED }).title(title)
}

/// Meaning carried by a glyph and a label; the colour only repeats it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    Good,
    Warn,
    Bad,
    Info,
    Muted,
}

#[must_use]
pub fn tone(theme: &Theme, t: Tone) -> Style {
    let c = match t {
        Tone::Good => theme.mint(),
        Tone::Warn => theme.butter(),
        Tone::Bad => theme.coral(),
        Tone::Info => theme.sky(),
        Tone::Muted => return Style::default().add_modifier(Modifier::DIM),
    };
    // Pastel tokens are unreadable as text on a light background: there they become the fill.
    if theme.dark { Style::default().fg(c).add_modifier(Modifier::BOLD) } else { Style::default().fg(theme.ink()).bg(c) }
}

/// `● active` style label: glyph + word, toned.
#[must_use]
pub fn badge(theme: &Theme, t: Tone, glyph: &str, label: &str) -> Span<'static> {
    Span::styled(format!("{glyph} {label}"), tone(theme, t))
}

#[must_use]
pub fn dim(s: impl Into<String>) -> Span<'static> {
    Span::styled(s.into(), Style::default().add_modifier(Modifier::DIM))
}

#[must_use]
pub fn key(k: &str) -> Span<'static> {
    Span::styled(k.to_owned(), Style::default().add_modifier(Modifier::BOLD | Modifier::UNDERLINED))
}

/// The selected-row style: reversed (works without colour) with the selection arrow.
#[must_use]
pub fn selected(_theme: &Theme) -> Style {
    Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD)
}

#[must_use]
pub fn arrow(theme: &Theme) -> &'static str {
    g(theme, "▶ ", "> ")
}

/// Fuzzy `/` filter: every whitespace-separated term must appear, in order, in one of the fields
/// (case-insensitive subsequence). An empty filter matches everything.
#[must_use]
pub fn matches(filter: &str, fields: &[&str]) -> bool {
    filter.split_whitespace().all(|term| {
        let term = term.to_lowercase();
        fields.iter().any(|f| {
            let mut hay = f.chars().flat_map(char::to_lowercase);
            term.chars().all(|c| hay.any(|h| h == c))
        })
    })
}

/// `now`, `42s`, `5m`, `3h`, `2d` — how long ago.
#[must_use]
pub fn ago(now_ms: u64, at_ms: u64) -> String {
    let s = now_ms.saturating_sub(at_ms) / 1000;
    match s {
        0..=4 => "now".into(),
        5..=59 => format!("{s}s"),
        60..=3599 => format!("{}m", s / 60),
        3600..=86_399 => format!("{}h", s / 3600),
        _ => format!("{}d", s / 86_400),
    }
}

/// `in 5m`, `in 3h`, `expired`.
#[must_use]
pub fn until(now_ms: u64, at_ms: u64) -> String {
    if at_ms <= now_ms { "expired".into() } else { format!("in {}", ago(at_ms, now_ms)) }
}

/// `999`, `12.3k`, `4.5M`.
#[must_use]
pub fn count(n: u64) -> String {
    match n {
        0..=999 => n.to_string(),
        1000..=999_999 => format!("{}.{}k", n / 1000, n % 1000 / 100),
        _ => format!("{}.{}M", n / 1_000_000, n % 1_000_000 / 100_000),
    }
}

/// A request's cost: `$0.0123` below a dollar (cents hide small requests), else `$12.34`.
#[must_use]
pub fn cost(uusd: u64) -> String {
    if uusd < 1_000_000 { format!("$0.{:04}", uusd / 100) } else { crate::widgets::dollars(uusd) }
}

/// `820ms`, `1.2s`, `12s`.
#[must_use]
pub fn latency(ms: u64) -> String {
    match ms {
        0..=999 => format!("{ms}ms"),
        1000..=9999 => format!("{}.{}s", ms / 1000, ms % 1000 / 100),
        _ => format!("{}s", ms / 1000),
    }
}

/// `part` of `whole` in percent, rounded down; 0 when `whole` is 0.
#[must_use]
pub fn percent(part: u64, whole: u64) -> u64 {
    u128::from(part).checked_mul(100).and_then(|x| x.checked_div(u128::from(whole))).and_then(|x| u64::try_from(x).ok()).unwrap_or(0)
}

/// A text gauge `████░░░░ 42%` (`####---- 42%` in ASCII) toned by how full it is.
#[must_use]
pub fn gauge(theme: &Theme, part: u64, whole: u64, width: u16) -> Line<'static> {
    let pct = percent(part, whole);
    let w = u64::from(width);
    let filled = usize::try_from(w.saturating_mul(pct.min(100)) / 100).unwrap_or(0);
    let empty = usize::from(width).saturating_sub(filled);
    let t = match pct {
        0..=79 => Tone::Good,
        80..=99 => Tone::Warn,
        _ => Tone::Bad,
    };
    let (f, e) = if theme.ascii { ("#", "-") } else { ("█", "░") };
    Line::from(vec![
        Span::styled(f.repeat(filled), if theme.dark { tone(theme, t) } else { Style::default().fg(theme.ink()) }),
        dim(e.repeat(empty)),
        Span::raw(format!(" {pct:>3}%")),
    ])
}

/// List + detail pane: side by side when wide, stacked otherwise (the detail gets `detail_rows`,
/// at most half the height); no detail pane when there is no room for both.
#[must_use]
pub fn split(area: Rect, detail_rows: u16) -> (Rect, Option<Rect>) {
    if area.width >= WIDE {
        let [a, b] = Layout::horizontal([Constraint::Percentage(60), Constraint::Percentage(40)]).areas(area);
        (a, Some(b))
    } else if area.height >= 16 {
        let rows = detail_rows.min(area.height / 2);
        let [a, b] = Layout::vertical([Constraint::Min(0), Constraint::Length(rows)]).areas(area);
        (a, Some(b))
    } else {
        (area, None)
    }
}

/// An empty state: what is missing, and what to do next.
pub fn empty(f: &mut Frame, area: Rect, theme: &Theme, title: &str, lines: Vec<Line<'static>>) {
    let inner = block(theme, format!(" {title} "));
    let top = area.height.saturating_sub(2).saturating_sub(u16::try_from(lines.len()).unwrap_or(0)) / 2;
    let mut text = vec![Line::raw(""); usize::from(top)];
    text.extend(lines);
    f.render_widget(Paragraph::new(text).alignment(Alignment::Center).wrap(Wrap { trim: true }).block(inner), area);
}

/// A cursor over a table drawn inside a bordered block with one header row: keyboard, mouse
/// clicks and wheel, clamped to the number of rows.
#[derive(Default, Debug)]
pub struct Cursor {
    pub state: TableState,
    body: Rect,
    len: usize,
}

impl Cursor {
    /// Clamps the selection to `len` rows drawn in the bordered `area` (call before rendering).
    pub fn sync(&mut self, len: usize, area: Rect) {
        self.len = len;
        self.body = Rect {
            x: area.x.saturating_add(1),
            y: area.y.saturating_add(2),
            width: area.width.saturating_sub(2),
            height: area.height.saturating_sub(3),
        };
        let sel = if len == 0 { None } else { Some(self.state.selected().unwrap_or(0).min(len.saturating_sub(1))) };
        self.state.select(sel);
    }

    #[must_use]
    pub fn selected(&self) -> Option<usize> {
        self.state.selected().filter(|&i| i < self.len)
    }

    pub fn select(&mut self, i: usize) {
        if self.len > 0 {
            self.state.select(Some(i.min(self.len.saturating_sub(1))));
        }
    }

    /// Moves on navigation input; returns false for anything else.
    pub fn on_input(&mut self, input: &Input) -> bool {
        if self.len == 0 {
            return false;
        }
        let cur = self.state.selected().unwrap_or(0);
        let page = usize::from(self.body.height.max(1));
        let next = match input {
            Input::Up | Input::ScrollUp | Input::Char('k') => cur.saturating_sub(1),
            Input::Down | Input::ScrollDown | Input::Char('j') => cur.saturating_add(1),
            Input::PageUp => cur.saturating_sub(page),
            Input::PageDown => cur.saturating_add(page),
            Input::Home | Input::Char('g') => 0,
            Input::End | Input::Char('G') => self.len,
            Input::Click { col, row } => {
                let b = self.body;
                if *col < b.x || *col >= b.x.saturating_add(b.width) || *row < b.y || *row >= b.y.saturating_add(b.height) {
                    return false;
                }
                let i = self.state.offset().saturating_add(usize::from(row.saturating_sub(b.y)));
                if i >= self.len {
                    return false;
                }
                i
            }
            _ => return false,
        };
        self.select(next);
        true
    }
}

#[cfg(test)]
pub mod test_util {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use crate::model::Snapshot;
    use crate::theme::{Depth, Theme};
    use crate::views::{Ctx, View};

    pub const NOW: u64 = 1_790_000_000_000;

    pub fn themes() -> [Theme; 3] {
        [
            Theme { depth: Depth::TrueColor, dark: true, ascii: false },
            Theme { depth: Depth::TrueColor, dark: false, ascii: false },
            Theme { depth: Depth::NoColor, dark: false, ascii: true },
        ]
    }

    /// Renders `view` at w×h and returns the screen as text lines; asserts no control bytes.
    pub fn draw(view: &mut dyn View, snap: &Snapshot, theme: &Theme, filter: &str, w: u16, h: u16) -> String {
        let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
        let ctx = Ctx { snap, theme, filter, now_ms: NOW };
        t.draw(|f| view.render(f, f.area(), &ctx)).unwrap();
        let buf = t.backend().buffer().clone();
        let mut out = String::new();
        for y in 0..h {
            for x in 0..w {
                out.push_str(buf[(x, y)].symbol());
            }
            out.push('\n');
        }
        if std::env::var_os("TUI_DUMP").is_some() {
            eprintln!("{w}x{h} dark={} ascii={}\n{out}", theme.dark, theme.ascii);
        }
        assert!(!out.chars().any(|c| c.is_control() && c != '\n'), "control byte on screen:\n{out}");
        if theme.ascii {
            assert!(out.is_ascii() || out.contains('\u{FFFD}'), "non-ASCII in --ascii:\n{out}");
        }
        out
    }

    pub fn ctx<'a>(snap: &'a Snapshot, theme: &'a Theme) -> Ctx<'a> {
        Ctx { snap, theme, filter: "", now_ms: NOW }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fuzzy_terms() {
        assert!(matches("", &["x"]));
        assert!(matches("cld", &["claude-sonnet"]));
        assert!(matches("ACME son", &["github/acme/widget", "claude-sonnet"]));
        assert!(!matches("gpt", &["claude-sonnet"]));
        assert!(!matches("acme zz", &["acme"]));
    }

    #[test]
    fn formats() {
        assert_eq!(ago(100_000, 99_000), "now");
        assert_eq!(ago(100_000, 0), "1m");
        assert_eq!(ago(5, 10), "now");
        assert_eq!(until(0, 7_200_000), "in 2h");
        assert_eq!(until(10, 5), "expired");
        assert_eq!(count(12_345), "12.3k");
        assert_eq!(count(4_560_000), "4.5M");
        assert_eq!(cost(12_300), "$0.0123");
        assert_eq!(cost(12_345_678), "$12.34");
        assert_eq!(latency(820), "820ms");
        assert_eq!(latency(1250), "1.2s");
        assert_eq!(percent(3, 0), 0);
        assert_eq!(percent(u64::MAX, 1), 0); // overflowing u64 → 0, never a panic
        assert_eq!(percent(1, 3), 33);
    }

    #[test]
    fn cursor_clicks_and_bounds() {
        let mut c = Cursor::default();
        c.sync(5, Rect::new(0, 0, 40, 10));
        assert_eq!(c.selected(), Some(0));
        assert!(c.on_input(&Input::End));
        assert_eq!(c.selected(), Some(4));
        assert!(c.on_input(&Input::Down));
        assert_eq!(c.selected(), Some(4));
        assert!(c.on_input(&Input::Click { col: 3, row: 3 })); // body starts at row 2
        assert_eq!(c.selected(), Some(1));
        assert!(!c.on_input(&Input::Click { col: 3, row: 9 })); // past the last row
        assert!(!c.on_input(&Input::Click { col: 3, row: 1 })); // header
        c.sync(0, Rect::new(0, 0, 40, 10));
        assert_eq!(c.selected(), None);
        assert!(!c.on_input(&Input::Down));
    }
}
