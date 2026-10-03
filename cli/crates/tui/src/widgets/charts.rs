//! Sparklines, meters and bars in the theme, with ASCII fallbacks (CONTRACT §20.3).

use ratatui::style::Style;
use ratatui::symbols::bar;
use ratatui::text::{Line, Span};
use ratatui::widgets::Sparkline;

use crate::theme::Theme;

const ASCII_BARS: bar::Set<'static> = bar::Set {
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

/// A sparkline of per-day values in `style` (butter for donated, mint for used).
#[must_use]
pub fn sparkline<'a>(theme: &Theme, data: &'a [u64], style: Style) -> Sparkline<'a> {
    let s = Sparkline::default().data(data).style(style);
    if theme.ascii { s.bar_set(ASCII_BARS) } else { s }
}

/// Parts per thousand of `used` over `total` (0 when `total` is 0), capped at 1000.
#[must_use]
pub fn permille(used: u64, total: u64) -> u64 {
    if total == 0 {
        return 0;
    }
    u128::from(used).saturating_mul(1000).checked_div(u128::from(total)).unwrap_or(0).min(1000) as u64
}

/// A text meter: `██████░░░░ 64%` (`######.... 64%` in ASCII). Mint under 80 %, butter (attention)
/// under 100 %, coral at the limit — and the percentage is always written.
#[must_use]
pub fn meter<'a>(theme: &Theme, used: u64, total: u64, width: u16) -> Line<'a> {
    let pm = permille(used, total);
    let style = match pm {
        0..800 => theme.ok(),
        800..1000 => theme.warn(),
        _ => theme.err(),
    };
    let w = u64::from(width.saturating_sub(5));
    let filled = (pm.saturating_mul(w) / 1000) as usize;
    let empty = (w as usize).saturating_sub(filled);
    let (f, e) = if theme.ascii { ("#", ".") } else { ("█", "░") };
    Line::from(vec![
        Span::styled(f.repeat(filled), style),
        Span::styled(e.repeat(empty), theme.muted()),
        Span::styled(format!("{:>4}%", pm / 10), style),
    ])
}

/// A horizontal bar of `value` relative to `max`, `width` cells wide.
#[must_use]
pub fn hbar<'a>(theme: &Theme, value: u64, max: u64, width: u16, style: Style) -> Span<'a> {
    let n = (permille(value, max).saturating_mul(u64::from(width)) / 1000) as usize;
    let n = if value > 0 { n.max(1) } else { 0 };
    Span::styled(if theme.ascii { "#" } else { "▇" }.repeat(n), style)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meter_writes_the_percentage() {
        let t = Theme { ascii: true, ..Theme::default() };
        let l = meter(&t, 64, 100, 15);
        let s: String = l.spans.iter().map(|s| s.content.as_ref()).collect();
        assert_eq!(s, "######....  64%");
        assert_eq!(permille(5, 0), 0);
        assert_eq!(permille(500, 100), 1000);
    }
}
