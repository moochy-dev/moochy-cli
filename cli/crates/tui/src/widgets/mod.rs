//! The one toolkit every tab draws with (CONTRACT §20.3): panels (one border and title style),
//! empty states, status badges (glyph + label, colour only repeats it), truncation with `…`,
//! money/time/token formats, list cursors ([`list`]), charts ([`charts`]) and the fuzzy matcher
//! ([`fuzzy`]) behind every `/` filter. Theme-taking helpers take `Theme` by value (3-byte Copy).

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Padding, Paragraph, Wrap};

use crate::sanitize::clean;
use crate::theme::{Glyph, Theme};

pub mod charts;
pub mod fuzzy;
pub mod list;
#[cfg(test)]
pub mod test_util;

pub use fuzzy::matches;
pub use list::{TableCursor, TreeList, TreeRow};

/// Width from which a list gets its detail pane on the side instead of below.
pub const WIDE: u16 = 110;

// ---- panels ----

/// Every box in the app: rounded (or `+-|` with `--ascii`), muted border, ` Title ` in bold.
#[must_use]
pub fn block<'a>(t: Theme, title: impl Into<String>) -> Block<'a> {
    let title: String = title.into();
    let b = Block::default().borders(Borders::ALL).border_set(t.border_set()).border_style(t.border()).padding(Padding::horizontal(1));
    if title.is_empty() { b } else { b.title(Span::styled(format!(" {title} "), t.bold())) }
}

/// The focused panel (the list the keys move in): mint border and title.
#[must_use]
pub fn block_focus<'a>(t: Theme, title: impl Into<String>) -> Block<'a> {
    let title: String = title.into();
    let title = if title.is_empty() { String::new() } else { format!(" {title} ") };
    Block::default()
        .borders(Borders::ALL)
        .border_set(t.border_set())
        .border_style(t.border_focus())
        .padding(Padding::horizontal(1))
        .title(Span::styled(title, t.accent()))
}

/// A list title with its count: `Donations · 4`, or `Donations · 2/4` while filtered.
#[must_use]
pub fn counted(title: &str, shown: usize, total: usize) -> String {
    if shown == total { format!("{title} · {total}") } else { format!("{title} · {shown}/{total}") }
}

/// An empty state: what is missing and what to do next, centred in a panel.
pub fn empty(f: &mut Frame, area: Rect, t: Theme, title: &str, lines: Vec<Line<'static>>) {
    let b = block(t, title);
    let inner_h = area.height.saturating_sub(2);
    let top = inner_h.saturating_sub(u16::try_from(lines.len()).unwrap_or(u16::MAX)) / 2;
    let mut text = vec![Line::raw(""); usize::from(top)];
    text.extend(lines);
    f.render_widget(Paragraph::new(text).alignment(Alignment::Center).wrap(Wrap { trim: true }).block(b), area);
}

/// Pads `lines` to the widest one, so a centred group keeps its left edge (a block, not a ragged
/// stack).
#[must_use]
pub fn align_block(lines: Vec<Line<'static>>) -> Vec<Line<'static>> {
    let w = lines.iter().map(Line::width).max().unwrap_or(0);
    lines
        .into_iter()
        .map(|mut l| {
            let pad = w.saturating_sub(l.width());
            l.spans.push(Span::raw(" ".repeat(pad)));
            l
        })
        .collect()
}

/// "Nothing matches …" for a filter that hides every row.
#[must_use]
pub fn no_match(t: Theme, filter: &str) -> Vec<Line<'static>> {
    vec![
        Line::from(badge(t, Tone::Muted, t.glyph(Glyph::Offline), &format!("Nothing matches “{}”", trunc(&clean(filter), 40)))),
        Line::from(vec![key("Esc"), muted(t, " clears the filter")]),
    ]
}

/// List + detail: side by side when wide, stacked when tall (the detail gets `detail_rows`, at
/// most half), list only when there is no room for both.
#[must_use]
pub fn split(area: Rect, detail_rows: u16) -> (Rect, Option<Rect>) {
    if area.width >= WIDE {
        let [a, b] = Layout::horizontal([Constraint::Percentage(58), Constraint::Percentage(42)]).areas(area);
        (a, Some(b))
    } else if area.height >= 16 {
        let rows = detail_rows.min(area.height / 2);
        let [a, b] = Layout::vertical([Constraint::Min(0), Constraint::Length(rows)]).areas(area);
        (a, Some(b))
    } else {
        (area, None)
    }
}

// ---- text pieces ----

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
pub fn tone(t: Theme, tone: Tone) -> Style {
    match tone {
        Tone::Good => t.ok().add_modifier(Modifier::BOLD),
        Tone::Warn => t.warn().add_modifier(Modifier::BOLD),
        Tone::Bad => t.err().add_modifier(Modifier::BOLD),
        Tone::Info => t.info().add_modifier(Modifier::BOLD),
        Tone::Muted => t.muted(),
    }
}

/// `✔ active`: glyph + word in a tone. `label` must already be clean.
#[must_use]
pub fn badge(t: Theme, tn: Tone, glyph: &str, label: &str) -> Span<'static> {
    Span::styled(format!("{glyph} {label}"), tone(t, tn))
}

/// `span` padded (or cut with `…`) to exactly `width` cells: a column in a list of lines.
#[must_use]
pub fn col(span: &Span<'static>, width: usize) -> Span<'static> {
    let text = trunc(span.content.as_ref(), width);
    let pad = width.saturating_sub(Line::raw(text.as_str()).width());
    Span::styled(format!("{text}{:pad$}", ""), span.style)
}

#[must_use]
pub fn muted(t: Theme, s: impl Into<String>) -> Span<'static> {
    Span::styled(s.into(), t.muted())
}

#[must_use]
pub fn bold(s: impl Into<String>) -> Span<'static> {
    Span::styled(s.into(), Style::default().add_modifier(Modifier::BOLD))
}

/// A command or key the user can type.
#[must_use]
pub fn key(k: &str) -> Span<'static> {
    Span::styled(k.to_owned(), Style::default().add_modifier(Modifier::BOLD | Modifier::UNDERLINED))
}

/// `key` in the key style, ` what` muted — the footer/help idiom.
#[must_use]
pub fn key_hint<'a>(t: Theme, k: &'a str, what: &'a str) -> [Span<'a>; 2] {
    [Span::styled(k, t.key()), Span::styled(format!(" {what}"), t.muted())]
}

/// The separator between items on one line.
#[must_use]
pub fn dot(t: Theme) -> &'static str {
    if t.ascii { " - " } else { " · " }
}

/// `Label      value` for detail panes (label muted, 10 wide); `value` must already be clean.
#[must_use]
pub fn kv(t: Theme, label: &str, value: impl Into<String>) -> Line<'static> {
    Line::from(vec![Span::styled(format!("{label:<10} "), t.muted()), Span::raw(value.into())])
}

/// Like [`kv`] with a styled value.
#[must_use]
pub fn kv_span(t: Theme, label: &str, value: Span<'static>) -> Line<'static> {
    Line::from(vec![Span::styled(format!("{label:<10} "), t.muted()), value])
}

/// At most `n` characters, `…` at the end when cut (never a silent clip).
#[must_use]
pub fn trunc(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        return s.to_string();
    }
    let mut out: String = s.chars().take(n.saturating_sub(1)).collect();
    if n > 0 {
        out.push('…');
    }
    out
}

/// One rule per column and frame: when any slug overflows its room, every slug in the column
/// drops its forge prefix (never `owner/name` next to `github/owner/name`).
#[must_use]
pub fn hosts_dropped<'a>(cells: impl IntoIterator<Item = (&'a str, usize)>) -> bool {
    cells.into_iter().any(|(s, room)| s.chars().count() > room)
}

/// `github/owner/name` → `owner/name` when `drop_host` (see [`hosts_dropped`]).
#[must_use]
pub fn slug(s: &str, drop_host: bool) -> String {
    match s.split_once('/') {
        Some((_, rest)) if drop_host && rest.contains('/') => rest.to_string(),
        _ => s.to_string(),
    }
}

/// `github/owner/name` → `owner/name` when the full slug does not fit in `n`.
#[must_use]
pub fn short_slug(s: &str, n: usize) -> String {
    match s.split_once('/') {
        Some((_, rest)) if s.chars().count() > n && rest.contains('/') => rest.to_string(),
        _ => s.to_string(),
    }
}

/// The glyph for a status word the node reports (donation, request, device, decision…).
#[must_use]
pub fn status_glyph(status: &str) -> Glyph {
    match status.to_ascii_lowercase().as_str() {
        // Running now: ●. Done / checked: ✔.
        "active" | "online" | "live" => Glyph::Online,
        "ok" | "done" | "accepted" | "approved" | "served" | "verified" | "present" | "added" => Glyph::Ok,
        "paused" | "draining" => Glyph::Paused,
        "pending" | "waiting" | "requested" | "scheduled" | "running" => Glyph::Pending,
        "stopped" | "revoked" | "removed" | "expired" | "absent" | "ended" => Glyph::Stopped,
        "refused" | "error" | "failed" | "denied" | "blocked" | "offline" | "timeout" | "cancelled" | "rejected" | "limit" | "mismatch" => {
            Glyph::Error
        }
        _ => Glyph::Warn,
    }
}

/// Glyph + label for a status word (meaning never by colour alone, CONTRACT §20.3).
#[must_use]
pub fn status(t: Theme, status: &str) -> Span<'static> {
    let g = status_glyph(status);
    Span::styled(format!("{} {}", t.glyph(g), clean(status)), t.glyph_style(g).add_modifier(Modifier::BOLD))
}

// ---- formats ----

/// `$12.34` from µ$, rounded down to the cent; `<$0.01` for a non-zero amount under a cent.
#[must_use]
pub fn dollars(uusd: u64) -> String {
    if (1..10_000).contains(&uusd) {
        return "<$0.01".into();
    }
    let cents = uusd / 10_000;
    format!("${}.{:02}", cents / 100, cents % 100)
}

/// A single request's cost: four decimals under a dollar (`$0.0123`), else [`dollars`].
#[must_use]
pub fn cost(uusd: u64) -> String {
    match uusd {
        0 => "$0".into(),
        1..100 => "<$0.0001".into(),
        100..1_000_000 => format!("$0.{:04}", uusd / 100),
        _ => dollars(uusd),
    }
}

/// `999`, `12.3k`, `4.5M` (tokens, counts).
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

/// How long ago, compact (lists): `now`, `42s`, `5m`, `3h`, `2d`; the future reads `now`.
#[must_use]
pub fn ago(now_ms: u64, at_ms: u64) -> String {
    let s = now_ms.saturating_sub(at_ms) / 1_000;
    match s {
        0..5 => "now".into(),
        5..60 => format!("{s}s"),
        60..3_600 => format!("{}m", s / 60),
        3_600..86_400 => format!("{}h", s / 3_600),
        _ => format!("{}d", s / 86_400),
    }
}

/// How long ago, in words (detail panes): `just now`, `42s ago`, `5m ago`.
#[must_use]
pub fn ago_long(now_ms: u64, at_ms: u64) -> String {
    match ago(now_ms, at_ms).as_str() {
        "now" => "just now".into(),
        a => format!("{a} ago"),
    }
}

/// `in 5m`, `in 3h`, `expired`.
#[must_use]
pub fn until(now_ms: u64, at_ms: u64) -> String {
    if at_ms <= now_ms { "expired".into() } else { format!("in {}", ago(at_ms, now_ms)) }
}

/// `part` of `whole` in percent, rounded down; 0 when `whole` is 0 or the result overflows.
#[must_use]
pub fn percent(part: u64, whole: u64) -> u64 {
    u128::from(part).checked_mul(100).and_then(|x| x.checked_div(u128::from(whole))).and_then(|x| u64::try_from(x).ok()).unwrap_or(0)
}

/// `2026-10-03` (UTC) from Unix ms.
#[must_use]
pub fn date(at_ms: u64) -> String {
    let (y, m, d) = civil(at_ms / 86_400_000);
    format!("{y:04}-{m:02}-{d:02}")
}

/// `1 Nov` (UTC) from Unix ms.
#[must_use]
pub fn day_month(at_ms: u64) -> String {
    const M: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let (_, m, d) = civil(at_ms / 86_400_000);
    format!("{d} {}", M.get(usize::try_from(m.saturating_sub(1)).unwrap_or(0)).copied().unwrap_or("?"))
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

/// `--ascii` safety net, run on the finished frame: every non-ASCII symbol left by a view (`…`,
/// `·`, arrows, U+FFFD from sanitized text…) becomes its ASCII stand-in, so no glyph a plain
/// terminal cannot draw ever reaches it.
pub fn asciify(buf: &mut ratatui::buffer::Buffer) {
    for c in &mut buf.content {
        let s = c.symbol();
        if s.is_ascii() {
            continue;
        }
        let r = match s {
            "…" => "~",
            "·" | "•" | "–" | "—" | "─" | "━" => "-",
            "→" | "▶" | "›" | "≥" => ">",
            "←" | "‹" | "≤" => "<",
            "↑" | "▲" => "^",
            "↓" | "▼" => "v",
            "│" | "┃" | "‖" => "|",
            "“" | "”" => "\"",
            "‘" | "’" => "'",
            "×" => "x",
            "█" | "▇" | "▆" | "▅" => "#",
            "▄" | "▃" | "░" => "=",
            "▂" | "▁" => ".",
            _ => "?",
        };
        c.set_symbol(r);
    }
}

// ---- links ----

/// The public web origin (`Me.web`, CONTRACT §9), validated: `https://host[:port]` with no path or
/// odd bytes; anything else falls back to the canonical `https://moochy.dev`.
#[must_use]
pub fn web_origin(web: &str) -> String {
    let base = web.trim().trim_end_matches('/');
    let host = base.strip_prefix("https://").unwrap_or(base);
    let host = host.strip_suffix(":443").unwrap_or(host);
    let ok = !host.is_empty() && host.len() <= 253 && host.bytes().all(|c| c.is_ascii_alphanumeric() || b".-:[]".contains(&c));
    if ok { format!("https://{host}") } else { "https://moochy.dev".into() }
}

/// The passkey accept page for a request: the node's `decide_url` when it is on the web origin,
/// else `{web}/decide/{id}`; `None` for an id that is not a plain token.
#[must_use]
pub fn decide_url(web: &str, given: &str, id: &str) -> Option<String> {
    let origin = web_origin(web);
    let given = given.trim();
    if given.strip_prefix(origin.as_str()).and_then(|p| p.strip_prefix("/decide/")).is_some_and(id_ok) {
        return Some(given.to_string());
    }
    id_ok(id).then(|| format!("{origin}/decide/{id}"))
}

fn id_ok(id: &str) -> bool {
    (1..=64).contains(&id.len()) && id.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn money() {
        assert_eq!(dollars(12_345_678), "$12.34");
        assert_eq!(dollars(0), "$0.00");
        assert_eq!(dollars(4_000), "<$0.01");
        assert_eq!(dollars(10_000), "$0.01");
        assert_eq!(cost(12_300), "$0.0123");
        assert_eq!(cost(50), "<$0.0001");
        assert_eq!(cost(12_345_678), "$12.34");
        assert_eq!(percent(3, 0), 0);
        assert_eq!(percent(u64::MAX, 1), 0);
        assert_eq!(percent(1, 3), 33);
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
        assert_eq!(ago(0, 5), "now");
        assert_eq!(ago_long(100_000, 0), "1m ago");
        assert_eq!(ago_long(5, 10), "just now");
        assert_eq!(until(0, 7_200_000), "in 2h");
        assert_eq!(until(10, 5), "expired");
        assert_eq!(date(0), "1970-01-01");
        assert_eq!(date(951_782_400_000), "2000-02-29");
        assert_eq!(day_month(1_793_491_200_000), "1 Nov");
        assert_eq!(datetime(1_791_036_300_000), "2026-10-03 14:05");
        assert_eq!(trunc("abcdef", 4), "abc…");
        assert_eq!(trunc("abc", 4), "abc");
        assert_eq!(short_slug("github/acme/widgets", 10), "acme/widgets");
        assert_eq!(short_slug("github/acme/widgets", 40), "github/acme/widgets");
    }

    #[test]
    fn statuses_have_distinct_glyphs() {
        assert_eq!(status_glyph("Active"), Glyph::Online);
        assert_eq!(status_glyph("verified"), Glyph::Ok);
        assert_eq!(status_glyph("paused"), Glyph::Paused);
        assert_eq!(status_glyph("stopped"), Glyph::Stopped);
        assert_eq!(status_glyph("whatever"), Glyph::Warn);
    }

    #[test]
    fn links() {
        assert_eq!(web_origin("https://moochy.dev/"), "https://moochy.dev");
        assert_eq!(web_origin("moochy.dev:443"), "https://moochy.dev");
        assert_eq!(web_origin("https://web.test:8443"), "https://web.test:8443");
        assert_eq!(web_origin("https://evil.test/x?\u{1b}"), "https://moochy.dev");
        assert_eq!(web_origin(""), "https://moochy.dev");
        assert_eq!(decide_url("https://moochy.dev", "", "pl_01J").as_deref(), Some("https://moochy.dev/decide/pl_01J"));
        assert_eq!(decide_url("https://moochy.dev", "https://moochy.dev/decide/pl_9", "pl_01J").as_deref(), Some("https://moochy.dev/decide/pl_9"));
        // A decide_url pointing elsewhere is ignored: the link is rebuilt on the web origin.
        assert_eq!(decide_url("https://moochy.dev", "https://evil.test/decide/x", "pl_1").as_deref(), Some("https://moochy.dev/decide/pl_1"));
        assert_eq!(decide_url("https://moochy.dev", "", "../x"), None);
    }
}
