//! Sparklines, meters and bars in the theme, with ASCII fallbacks (CONTRACT §20.3).

use ratatui::style::Style;
use ratatui::symbols::bar;
use ratatui::text::{Line, Span};
use ratatui::widgets::Sparkline;

use super::percent;
use crate::theme::Theme;

pub const ASCII_BARS: bar::Set<'static> = bar::Set {
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

/// A sparkline of per-day/minute values in `style` (butter for donated, mint for used).
#[must_use]
pub fn sparkline(t: Theme, data: &[u64], style: Style) -> Sparkline<'_> {
    let s = Sparkline::default().data(data).style(style);
    if t.ascii { s.bar_set(ASCII_BARS) } else { s }
}

/// Parts per thousand of `used` over `total` (0 when `total` is 0), capped at 1000.
#[must_use]
pub fn permille(used: u64, total: u64) -> u64 {
    u128::from(used).saturating_mul(1000).checked_div(u128::from(total)).unwrap_or(0).min(1000) as u64
}

fn cells(t: Theme, used: u64, total: u64, width: u16) -> (String, String) {
    let filled = (permille(used, total).saturating_mul(u64::from(width)) / 1000) as usize;
    let empty = usize::from(width).saturating_sub(filled);
    let (f, e) = if t.ascii { ("#", "-") } else { ("█", "░") };
    (f.repeat(filled), e.repeat(empty))
}

/// A gauge `██████░░░░  64%`: `width` cells of bar, then the percentage (always written). Mint
/// under 80 %, butter (attention) under 100 %, coral at the limit.
#[must_use]
pub fn meter(t: Theme, used: u64, total: u64, width: u16) -> Line<'static> {
    let pct = percent(used, total);
    let style = match pct {
        0..80 => t.ok(),
        80..100 => t.warn(),
        _ => t.err(),
    };
    let (f, e) = cells(t, used, total, width);
    Line::from(vec![Span::styled(f, style), Span::styled(e, t.muted()), Span::styled(format!(" {pct:>3}%"), style)])
}

/// A bar of `used` against `total` with no percentage (dollar caps, §19.5), in `style`.
#[must_use]
pub fn bar(t: Theme, used: u64, total: u64, width: u16, style: Style) -> Line<'static> {
    let (f, e) = cells(t, used, total, width);
    Line::from(vec![Span::styled(f, style), Span::styled(e, t.muted())])
}

/// A bar of `value` relative to `max` (at least one cell when non-zero), no track.
#[must_use]
pub fn hbar(t: Theme, value: u64, max: u64, width: u16, style: Style) -> Span<'static> {
    let n = (permille(value, max).saturating_mul(u64::from(width)) / 1000) as usize;
    let n = if value > 0 { n.max(1) } else { 0 };
    Span::styled(if t.ascii { "#" } else { "▇" }.repeat(n), style)
}

/// A one-row sparkline as text (fits inside a paragraph): the last `width` values, scaled to the
/// largest, `▁▂▃▄▅▆▇█` (`._-=#` in ASCII).
#[must_use]
pub fn spark_text(t: Theme, data: &[u64], width: usize, style: Style) -> Span<'static> {
    const U: [&str; 8] = ["▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"];
    const A: [&str; 8] = [".", ".", "_", "-", "-", "=", "#", "#"];
    let data = data.get(data.len().saturating_sub(width)..).unwrap_or_default();
    let max = data.iter().copied().max().unwrap_or(0);
    let set = if t.ascii { &A } else { &U };
    let s: String = data
        .iter()
        .map(|&v| if v == 0 { " " } else { set.get((permille(v, max).saturating_mul(7) / 1000) as usize).copied().unwrap_or("#") })
        .collect();
    Span::styled(s, style)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meter_writes_the_percentage() {
        let t = Theme { ascii: true, ..Theme::default() };
        assert_eq!(meter(t, 64, 100, 10).to_string(), "######----  64%");
        assert_eq!(bar(t, 3, 10, 10, Style::default()).to_string(), "###-------");
        assert_eq!(bar(t, 30, 10, 4, Style::default()).to_string(), "####");
        assert_eq!(bar(t, 3, 0, 4, Style::default()).to_string(), "----");
        assert_eq!(spark_text(t, &[0, 1, 2, 4, 8], 4, Style::default()).content, "..-#");
        assert_eq!(permille(5, 0), 0);
        assert_eq!(permille(500, 100), 1000);
    }
}
