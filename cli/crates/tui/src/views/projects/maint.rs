//! Shared by the maintainer tabs (Projects, Organisations, Decisions; owner mo-tui-maint): a
//! single-cursor tree list with a detail pane, the accept/refuse confirmations, small formatters.
//! Every string from the snapshot goes through [`clean`] here or in the views before it is drawn.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Position, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::symbols::border;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};

use crate::model::Pending;
use crate::sanitize::clean;
use crate::source::Action;
use crate::theme::Theme;
use crate::views::{Input, Outcome};

/// `--ascii` borders (ratatui has no ASCII border set).
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

/// One line of a tree list; `key` says what the cursor points at.
pub struct Row<K> {
    pub depth: u8,
    pub line: Line<'static>,
    pub key: K,
}

/// Cursor, scroll and the list's last area (for mouse clicks).
#[derive(Default)]
pub struct Cursor {
    pub sel: usize,
    state: ListState,
    list: Rect,
}

impl Cursor {
    /// The selected row, clamped to the list.
    pub fn pick<'r, K>(&mut self, rows: &'r [Row<K>]) -> Option<&'r Row<K>> {
        self.sel = self.sel.min(rows.len().saturating_sub(1));
        rows.get(self.sel)
    }

    /// Moves on navigation input (keys, wheel, click); `true` if it was one.
    pub fn input(&mut self, input: &Input, len: usize) -> bool {
        let last = len.saturating_sub(1);
        let page = usize::from(self.list.height.saturating_sub(3)).max(1);
        let sel = match input {
            Input::Up | Input::ScrollUp | Input::Char('k') => self.sel.saturating_sub(1),
            Input::Down | Input::ScrollDown | Input::Char('j') => self.sel.saturating_add(1),
            Input::PageUp => self.sel.saturating_sub(page),
            Input::PageDown => self.sel.saturating_add(page),
            Input::Home | Input::Char('g') => 0,
            Input::End | Input::Char('G') => last,
            Input::Click { col, row } => {
                let inner = self.list.inner(ratatui::layout::Margin::new(1, 1));
                if !inner.contains(Position::new(*col, *row)) {
                    return false;
                }
                self.state.offset().saturating_add(usize::from(row.saturating_sub(inner.y)))
            }
            _ => return false,
        };
        self.sel = sel.min(last);
        true
    }

    /// The list (left, or top under 100 columns) and the detail of the selected row; `empty` when
    /// there is nothing to list.
    #[allow(clippy::too_many_arguments)]
    pub fn draw<K>(&mut self, f: &mut Frame, area: Rect, t: &Theme, title: &str, rows: &[Row<K>], detail: Vec<Line<'static>>, empty: &str) {
        if rows.is_empty() {
            self.list = Rect::default();
            f.render_widget(Paragraph::new(empty.to_owned()).wrap(Wrap { trim: false }).block(block(t, title)), area);
            return;
        }
        let [list_a, det_a] = if area.width >= 100 {
            Layout::horizontal([Constraint::Percentage(55), Constraint::Percentage(45)]).areas(area)
        } else {
            Layout::vertical([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(area)
        };
        self.list = list_a;
        self.sel = self.sel.min(rows.len().saturating_sub(1));
        self.state.select(Some(self.sel));
        let items = rows.iter().map(|r| {
            let mut spans = vec![Span::raw("  ".repeat(usize::from(r.depth)))];
            spans.extend(r.line.spans.iter().cloned());
            ListItem::new(Line::from(spans))
        });
        let list = List::new(items)
            .block(block(t, &format!("{title} · {}", rows.len())))
            .highlight_symbol(if t.ascii { "> " } else { "▶ " })
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
        f.render_stateful_widget(list, list_a, &mut self.state);
        f.render_widget(Paragraph::new(detail).wrap(Wrap { trim: false }).block(block(t, "Details")), det_a);
    }
}

#[must_use]
pub fn block(t: &Theme, title: &str) -> Block<'static> {
    let b = Block::default().borders(Borders::ALL).title(title.to_owned()).style(t.text());
    if t.ascii { b.border_set(ASCII_BORDER) } else { b }
}

/// Case-insensitive subsequence match for the `/` filter.
#[must_use]
pub fn fuzzy(hay: &str, needle: &str) -> bool {
    let mut h = hay.chars().flat_map(char::to_lowercase);
    needle.chars().flat_map(char::to_lowercase).all(|n| h.any(|c| c == n))
}

/// A glyph with its ASCII fallback.
#[must_use]
pub fn glyph(t: &Theme, uni: &'static str, ascii: &'static str) -> &'static str {
    if t.ascii { ascii } else { uni }
}

#[must_use]
pub fn bold(s: impl Into<String>) -> Span<'static> {
    Span::styled(s.into(), Style::default().add_modifier(Modifier::BOLD))
}

/// `label  value` for detail panes; `value` must already be clean.
#[must_use]
pub fn kv(label: &str, value: impl Into<String>) -> Line<'static> {
    Line::from(vec![bold(format!("{label:<11}")), Span::raw(value.into())])
}

/// `[#####-----]` of `used` against `total` (no percent: share caps are dollars, §19.5).
#[must_use]
pub fn bar(t: &Theme, used: u64, total: u64, width: u16) -> String {
    let w = u64::from(width);
    let filled = u128::from(used).saturating_mul(u128::from(w)).checked_div(u128::from(total)).map_or(0, |v| u64::try_from(v).unwrap_or(w).min(w));
    let (on, off) = if t.ascii { ("#", "-") } else { ("█", "░") };
    let filled = usize::try_from(filled).unwrap_or(0);
    let rest = usize::try_from(w).unwrap_or(0).saturating_sub(filled);
    format!("[{}{}]", on.repeat(filled), off.repeat(rest))
}

/// `just now`, `5m ago`, `3h ago`, `12d ago`.
#[must_use]
pub fn ago(now_ms: u64, at_ms: u64) -> String {
    let s = now_ms.saturating_sub(at_ms) / 1000;
    match s {
        0..60 => "just now".into(),
        60..3600 => format!("{}m ago", s / 60),
        3600..86_400 => format!("{}h ago", s / 3600),
        _ => format!("{}d ago", s / 86_400),
    }
}

/// The §19.2a status line of a claim (project or org).
#[must_use]
pub fn claim_status(t: &Theme, now_ms: u64, paused_since_ms: u64) -> Vec<Line<'static>> {
    if paused_since_ms == 0 {
        return vec![kv("Status", format!("{} active", glyph(t, "●", "*")))];
    }
    vec![
        Line::from(vec![bold(format!("{:<11}", "Status")), Span::styled(format!("{} PAUSED {}", glyph(t, "‖", "="), ago(now_ms, paused_since_ms)), Style::default().fg(t.coral()).add_modifier(Modifier::BOLD))]),
        Line::from("  No new task is routed to its donations until you sign in on the web to re-verify (claims pause after 30 days without a sign-in)."),
    ]
}

/// `https://…/decide/{id}` for passkey accepts, from the relay origin like `moochy decisions accept`.
#[must_use]
pub fn decide_url(relay: &str, id: &str) -> Option<String> {
    let ok = (1..=64).contains(&id.len()) && id.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-');
    let host_ok = |h: &str| !h.is_empty() && !h.starts_with("relay.moochy.dev") && h.bytes().all(|c| c.is_ascii_alphanumeric() || b".-:[]".contains(&c));
    let origin = match relay.trim_end_matches('/').strip_prefix("https://") {
        Some(h) if host_ok(h) => format!("https://{h}"),
        _ => "https://moochy.dev".into(),
    };
    ok.then(|| format!("{origin}/decide/{id}"))
}

/// A waiting request as a list row.
#[must_use]
pub fn pending_line(t: &Theme, p: &Pending) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{} waiting ", glyph(t, "◇", "?")), Style::default().fg(t.butter()).add_modifier(Modifier::BOLD)),
        Span::raw(format!("{}  {}", clean(&p.subject), clean(&p.summary))),
    ])
}

fn pending_fields(p: &Pending, now_ms: u64) -> Vec<Line<'static>> {
    vec![
        kv("Request", clean(&p.request_id)),
        kv("Kind", clean(&p.kind)),
        kv("For", clean(&p.target)),
        kv("From", clean(&p.subject)),
        kv("Terms", clean(&p.summary)),
        kv("Received", ago(now_ms, p.created_at_ms)),
    ]
}

#[must_use]
pub fn pending_detail(p: &Pending, relay: &str, now_ms: u64) -> Vec<Line<'static>> {
    let mut v = pending_fields(p, now_ms);
    v.push(Line::default());
    v.push(Line::from("a accept (signed with your owner key, checked with the server) · r refuse"));
    if let Some(u) = decide_url(relay, &p.request_id) {
        v.push(Line::from(format!("Or accept with your passkey: {u}")));
    }
    v
}

fn text(lines: &[Line<'static>]) -> String {
    lines.iter().map(ToString::to_string).collect::<Vec<_>>().join("\n")
}

/// `a`: every field the owner key will sign is shown; the node re-decodes the body and checks the
/// names with the server's Lookup before signing (A217/A218), exactly like `moochy accept`.
#[must_use]
pub fn confirm_accept(p: &Pending, relay: &str, now_ms: u64) -> Outcome {
    let mut v = pending_fields(p, now_ms);
    v.push(Line::default());
    v.push(Line::from("Your owner key signs this approval. Before signing, the node decodes the request and confirms every name with the server; if anything differs from what you see here, nothing is signed."));
    if let Some(u) = decide_url(relay, &p.request_id) {
        v.push(Line::from(format!("No owner key on this machine? Accept with your passkey: {u}")));
    }
    Outcome::Confirm { title: "Accept this request?".into(), body: text(&v), action: Action::Accept { request_id: p.request_id.clone() } }
}

/// `r`: refusing signs nothing; the requester is told.
#[must_use]
pub fn confirm_refuse(p: &Pending, now_ms: u64) -> Outcome {
    let mut v = pending_fields(p, now_ms);
    v.push(Line::default());
    v.push(Line::from("Refusing signs nothing; the requester is told."));
    Outcome::Confirm { title: "Refuse this request?".into(), body: text(&v), action: Action::Refuse { request_id: p.request_id.clone(), reason: String::new() } }
}

#[cfg(test)]
#[allow(clippy::must_use_candidate, clippy::missing_panics_doc, clippy::many_single_char_names)]
pub mod tests {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use super::*;
    use crate::model::{CoveredRepo, Decision, Me, Org, Project, Snapshot};
    use crate::theme::Depth;
    use crate::views::{Ctx, View};

    pub const NOW: u64 = 1_790_000_000_000;
    const DAY: u64 = 86_400_000;

    pub fn theme(ascii: bool) -> Theme {
        Theme { depth: Depth::TrueColor, dark: true, ascii }
    }

    pub fn fixture() -> Snapshot {
        Snapshot {
            me: Me { handle: "maya".into(), relay: "https://moochy.dev".into(), connected: true, ..Me::default() },
            projects: vec![
                Project { id: "r_1".into(), slug: "github/acme/widget".into(), donors: 3, pending: 1, month_uusd: 12_000_000, goal_uusd: 50_000_000, members: vec!["maya".into(), "bo".into()], funded_by: vec!["github/acme".into()], paused_since_ms: 0 },
                Project { id: "r_2".into(), slug: "github/acme/gadget".into(), donors: 0, pending: 0, month_uusd: 0, goal_uusd: 0, members: vec![], funded_by: vec![], paused_since_ms: NOW - 31 * DAY },
                Project { id: "r_3".into(), slug: "github/acme/\u{1b}]52;c;evil\u{7}tool".into(), ..Project::default() },
            ],
            orgs: vec![Org { id: "o_1".into(), path: "github/acme".into(), covered: vec![CoveredRepo { slug: "github/acme/widget".into(), used_uusd: 3_000_000, share_cap_uusd: 10_000_000 }], donors: 2, month_uusd: 3_000_000, paused_since_ms: 0 }],
            pending: vec![
                Pending { request_id: "pl_01J".into(), kind: "donor".into(), target: "github/acme/widget".into(), subject: "\u{1b}[31malice".into(), summary: "$20.00/month, ≤ $0.50/request, claude-sonnet".into(), created_at_ms: NOW - 3 * 3_600_000 },
                Pending { request_id: "pl_02K".into(), kind: "donor".into(), target: "github/acme".into(), subject: "carol".into(), summary: "$100.00/month".into(), created_at_ms: NOW - DAY },
            ],
            decisions: vec![
                Decision { at_ms: NOW - 2 * DAY, target: "github/acme/widget".into(), donor: "dave".into(), event: "accepted".into(), via: "passkey".into(), reason: String::new() },
                Decision { at_ms: NOW - DAY, target: "github/acme/widget".into(), donor: "eve".into(), event: "refused".into(), via: "cli".into(), reason: "not now".into() },
            ],
            ..Snapshot::default()
        }
    }

    pub fn ctx<'a>(snap: &'a Snapshot, t: &'a Theme, filter: &'a str) -> Ctx<'a> {
        Ctx { snap, theme: t, filter, now_ms: NOW }
    }

    /// The frame as plain text, one line per row.
    pub fn draw(v: &mut dyn View, w: u16, h: u16, c: &Ctx) -> String {
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| v.render(f, f.area(), c)).unwrap();
        let buf = term.backend().buffer();
        let s: Vec<String> = (0..h).map(|y| (0..w).map(|x| buf[(x, y)].symbol().to_owned()).collect()).collect();
        let s = s.join("\n");
        assert!(!s.chars().any(|c| c.is_control() && c != '\n'), "no control bytes reach the terminal: {s}");
        s
    }

    #[test]
    fn helpers() {
        assert!(fuzzy("github/acme/widget", "AcWid") && !fuzzy("github/acme", "zz"));
        assert_eq!(bar(&theme(true), 3, 10, 10), "[###-------]");
        assert_eq!(bar(&theme(true), 30, 10, 4), "[####]");
        assert_eq!(bar(&theme(true), 3, 0, 4), "[----]");
        assert_eq!(ago(NOW, NOW - 3 * 3_600_000), "3h ago");
        assert_eq!(ago(NOW, NOW + 5), "just now");
        assert_eq!(decide_url("https://moochy.dev/", "pl_01J").as_deref(), Some("https://moochy.dev/decide/pl_01J"));
        assert_eq!(decide_url("https://relay.test:8443", "pl_1").as_deref(), Some("https://relay.test:8443/decide/pl_1"));
        assert_eq!(decide_url("moochy.dev:443", "pl_1").as_deref(), Some("https://moochy.dev/decide/pl_1"));
        assert_eq!(decide_url("https://evil.test/x?\u{1b}", "pl_1").as_deref(), Some("https://moochy.dev/decide/pl_1"));
        assert_eq!(decide_url("https://relay.moochy.dev:443", "pl_1").as_deref(), Some("https://moochy.dev/decide/pl_1"));
        assert_eq!(decide_url("https://moochy.dev", "../x"), None);
    }

    #[test]
    fn confirmations_show_every_field() {
        let snap = fixture();
        let p = snap.pending.first().unwrap();
        let Outcome::Confirm { body, action, .. } = confirm_accept(p, &snap.me.relay, NOW) else { panic!() };
        assert_eq!(action, Action::Accept { request_id: "pl_01J".into() });
        for f in ["pl_01J", "donor", "github/acme/widget", "alice", "$20.00/month", "3h ago", "confirms every name with the server", "https://moochy.dev/decide/pl_01J"] {
            assert!(body.contains(f), "{f} missing from {body}");
        }
        assert!(!body.contains('\u{1b}'));
        let Outcome::Confirm { action, .. } = confirm_refuse(p, NOW) else { panic!() };
        assert_eq!(action, Action::Refuse { request_id: "pl_01J".into(), reason: String::new() });
    }
}
