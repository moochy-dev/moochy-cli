//! Shared widgets (CONTRACT §20.3): sortable/filterable tables ([`table`]), sparklines, meters and
//! bars ([`charts`]), fuzzy matching ([`fuzzy`]), status glyphs, money and time formatting.
//! Owner: mo-tui; view owners may add here in their own files and tell mo-tui.

use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};

use crate::sanitize::clean;
use crate::theme::{Glyph, Theme};

pub mod charts;
pub mod fuzzy;
pub mod table;

/// `$12.34` from µ$, rounded down to the cent.
#[must_use]
pub fn dollars(uusd: u64) -> String {
    let cents = uusd / 10_000;
    format!("${}.{:02}", cents / 100, cents % 100)
}

/// `950`, `12.3k`, `4.5M` tokens.
#[must_use]
pub fn tokens(n: u64) -> String {
    match n {
        0..1_000 => n.to_string(),
        1_000..1_000_000 => format!("{}.{}k", n / 1_000, n % 1_000 / 100),
        _ => format!("{}.{}M", n / 1_000_000, n % 1_000_000 / 100_000),
    }
}

/// `820ms`, `1.4s`, `12s`.
#[must_use]
pub fn latency(ms: u64) -> String {
    match ms {
        0..1_000 => format!("{ms}ms"),
        1_000..10_000 => format!("{}.{}s", ms / 1_000, ms % 1_000 / 100),
        _ => format!("{}s", ms / 1_000),
    }
}

/// How long ago, compact: `now`, `42s`, `5m`, `3h`, `2d`; `soon` for the future.
#[must_use]
pub fn ago(now_ms: u64, at_ms: u64) -> String {
    let Some(d) = now_ms.checked_sub(at_ms) else { return "soon".into() };
    let s = d / 1_000;
    match s {
        0..5 => "now".into(),
        5..60 => format!("{s}s"),
        60..3_600 => format!("{}m", s / 60),
        3_600..86_400 => format!("{}h", s / 3_600),
        _ => format!("{}d", s / 86_400),
    }
}

/// `2026-10-03` (UTC) from Unix ms.
#[must_use]
pub fn date(at_ms: u64) -> String {
    let (y, m, d) = civil(at_ms / 86_400_000);
    format!("{y:04}-{m:02}-{d:02}")
}

/// `2026-10-03 14:05` (UTC) from Unix ms.
#[must_use]
pub fn datetime(at_ms: u64) -> String {
    let secs = at_ms / 1_000 % 86_400;
    format!("{} {:02}:{:02}", date(at_ms), secs / 3_600, secs % 3_600 / 60)
}

/// Days since 1970-01-01 → (year, month, day), proleptic Gregorian (H. Hinnant's algorithm).
fn civil(days: u64) -> (u64, u64, u64) {
    let z = days.saturating_add(719_468);
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = doe.saturating_sub(doe / 1_460).saturating_add(doe / 36_524).saturating_sub(doe / 146_096) / 365;
    let doy = doe.saturating_sub(yoe.saturating_mul(365).saturating_add(yoe / 4).saturating_sub(yoe / 100));
    let mp = doy.saturating_mul(5).saturating_add(2) / 153;
    let d = doy.saturating_sub(mp.saturating_mul(153).saturating_add(2) / 5).saturating_add(1);
    let m = if mp < 10 { mp.saturating_add(3) } else { mp.saturating_sub(9) };
    let y = yoe.saturating_add(era.saturating_mul(400)).saturating_add(u64::from(m <= 2));
    (y, m, d)
}

/// The glyph for a status word the node reports (donation, request, device, decision…).
#[must_use]
pub fn status_glyph(status: &str) -> Glyph {
    match status.to_ascii_lowercase().as_str() {
        "active" | "online" | "ok" | "done" | "accepted" | "approved" | "served" | "verified" | "present" | "live" => Glyph::Ok,
        "paused" | "draining" => Glyph::Paused,
        "pending" | "waiting" | "requested" | "scheduled" => Glyph::Pending,
        "stopped" | "revoked" | "removed" | "expired" | "absent" => Glyph::Stopped,
        "refused" | "error" | "failed" | "denied" | "blocked" | "offline" => Glyph::Error,
        _ => Glyph::Warn,
    }
}

/// Glyph + label for a status (meaning never by colour alone, CONTRACT §20.3).
#[must_use]
pub fn status<'a>(theme: &Theme, status: &str) -> Line<'a> {
    let g = status_glyph(status);
    let st = theme.glyph_style(g);
    Line::from(vec![Span::styled(theme.glyph(g), st), Span::raw(" "), Span::styled(clean(status), st)])
}

/// `key` in the key style, ` what` muted — the footer/help idiom.
#[must_use]
pub fn key_hint<'a>(theme: &Theme, key: &'a str, what: &'a str) -> [Span<'a>; 2] {
    [Span::styled(key, theme.key()), Span::styled(format!(" {what}"), theme.muted())]
}

/// Splits a tab's area into a list and a detail pane: side by side when wide, stacked when tall,
/// list only when the terminal is small (the detail then opens with Enter, full-pane).
#[must_use]
pub fn master_detail(area: Rect) -> (Rect, Option<Rect>) {
    use ratatui::layout::{Constraint, Layout};
    if area.width >= 120 {
        let [l, r] = Layout::horizontal([Constraint::Percentage(60), Constraint::Percentage(40)]).areas(area);
        (l, Some(r))
    } else if area.height >= 26 {
        let [t, b] = Layout::vertical([Constraint::Percentage(60), Constraint::Percentage(40)]).areas(area);
        (t, Some(b))
    } else {
        (area, None)
    }
}

/// A `label  value` line for detail panes.
#[must_use]
pub fn field<'a>(theme: &Theme, label: &'a str, value: impl Into<String>, style: Style) -> Line<'a> {
    Line::from(vec![Span::styled(format!("{label:<12}"), theme.muted()), Span::styled(value.into(), style)])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dollars_from_uusd() {
        assert_eq!(dollars(12_345_678), "$12.34");
        assert_eq!(dollars(0), "$0.00");
    }

    #[test]
    fn formats() {
        assert_eq!(tokens(999), "999");
        assert_eq!(tokens(12_345), "12.3k");
        assert_eq!(tokens(4_560_000), "4.5M");
        assert_eq!(latency(820), "820ms");
        assert_eq!(latency(1_450), "1.4s");
        assert_eq!(ago(100_000, 99_000), "now");
        assert_eq!(ago(100_000, 58_000), "42s");
        assert_eq!(ago(10_000_000, 0), "2h");
        assert_eq!(ago(0, 5), "soon");
        assert_eq!(date(0), "1970-01-01");
        assert_eq!(date(951_782_400_000), "2000-02-29");
        assert_eq!(datetime(1_791_036_300_000), "2026-10-03 14:05");
    }

    #[test]
    fn statuses_have_distinct_glyphs() {
        assert_eq!(status_glyph("Active"), Glyph::Ok);
        assert_eq!(status_glyph("paused"), Glyph::Paused);
        assert_eq!(status_glyph("stopped"), Glyph::Stopped);
        assert_eq!(status_glyph("whatever"), Glyph::Warn);
    }
}
