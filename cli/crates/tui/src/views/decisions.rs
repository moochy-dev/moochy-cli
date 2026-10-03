//! The Decisions tab (CONTRACT §16, §20.2): requests waiting for me (accept with the owner key
//! through a confirmation, or with my passkey on the web via the /decide link; refuse) and the
//! history of accepts, refusals and revocations, newest first. Owner: mo-tui-maint.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};

use super::projects::maint::{Cursor, Row, ago, bold, confirm_accept, confirm_refuse, fuzzy, glyph, kv, pending_detail, pending_line};
use super::{Ctx, Input, Outcome, View};
use crate::model::Decision;
use crate::sanitize::clean;
use crate::theme::Theme;

#[derive(Default)]
pub struct DecisionsView {
    cur: Cursor,
}

#[derive(Clone, Copy)]
enum K {
    Waiting,
    History,
    Pending(usize),
    Decision(usize),
}

fn event_glyph(t: Theme, event: &str) -> &'static str {
    let e = event.to_ascii_lowercase();
    if e.contains("accept") || e.contains("approv") {
        glyph(&t, "✓", "+")
    } else if e.contains("refus") || e.contains("declin") || e.contains("revok") {
        glyph(&t, "✗", "x")
    } else {
        glyph(&t, "·", "-")
    }
}

fn rows(ctx: &Ctx) -> Vec<Row<K>> {
    let (snap, t, q) = (ctx.snap, ctx.theme, ctx.filter);
    let pending: Vec<_> = snap.pending.iter().enumerate().filter(|(_, p)| fuzzy(&clean(&format!("{} {} {}", p.subject, p.target, p.kind)), q)).collect();
    let mut history: Vec<_> = snap.decisions.iter().enumerate().filter(|(_, d)| fuzzy(&clean(&format!("{} {} {}", d.donor, d.target, d.event)), q)).collect();
    if pending.is_empty() && history.is_empty() {
        return Vec::new();
    }
    history.sort_by_key(|(_, d)| std::cmp::Reverse(d.at_ms));
    let mut out = vec![Row { depth: 0, line: Line::from(bold(format!("Waiting for you · {}", pending.len()))), key: K::Waiting }];
    out.extend(pending.into_iter().map(|(i, p)| Row { depth: 1, line: pending_line(t, p), key: K::Pending(i) }));
    out.push(Row { depth: 0, line: Line::from(bold(format!("History · {}", history.len()))), key: K::History });
    out.extend(history.into_iter().map(|(i, d)| Row { depth: 1, line: decision_line(*t, d, ctx.now_ms), key: K::Decision(i) }));
    out
}

fn decision_line(t: Theme, d: &Decision, now_ms: u64) -> Line<'static> {
    Line::from(vec![
        Span::raw(format!("{} ", event_glyph(t, &d.event))),
        bold(clean(&d.event)),
        Span::raw(format!("  {} → {}  {}", clean(&d.donor), clean(&d.target), ago(now_ms, d.at_ms))),
    ])
}

fn detail(ctx: &Ctx, key: K) -> Vec<Line<'static>> {
    let snap = ctx.snap;
    match key {
        K::Waiting => vec![
            Line::from(bold("Waiting for you")),
            Line::from(if snap.pending.is_empty() { "Nothing to decide right now." } else { "Donor requests for your projects and organisations." }),
            Line::default(),
            Line::from("a accept with your owner key (checked with the server first) · r refuse · or open the request's /decide link to accept with your passkey."),
        ],
        K::History => vec![Line::from(bold("History")), Line::from("Every accept, refusal and revocation, newest first: the same history as `moochy decisions`.")],
        K::Pending(i) => snap.pending.get(i).map(|p| pending_detail(p, &snap.me.relay, ctx.now_ms)).unwrap_or_default(),
        K::Decision(i) => {
            let Some(d) = snap.decisions.get(i) else { return Vec::new() };
            vec![
                Line::from(vec![Span::raw(format!("{} ", event_glyph(*ctx.theme, &d.event))), bold(clean(&d.event))]),
                kv("When", ago(ctx.now_ms, d.at_ms)),
                kv("For", clean(&d.target)),
                kv("Donor", clean(&d.donor)),
                kv("Via", clean(&d.via)),
                kv("Reason", if d.reason.is_empty() { "—".into() } else { clean(&d.reason) }),
            ]
        }
    }
}

impl View for DecisionsView {
    fn title(&self) -> &'static str {
        "Decisions"
    }

    fn hints(&self) -> &'static [(&'static str, &'static str)] {
        &[("↑↓", "move"), ("a", "accept"), ("r", "refuse"), ("/", "filter")]
    }

    fn render(&mut self, f: &mut Frame, area: Rect, ctx: &Ctx) {
        let rows = rows(ctx);
        let detail = self.cur.pick(&rows).map(|r| detail(ctx, r.key)).unwrap_or_default();
        let empty = if ctx.snap.pending.is_empty() && ctx.snap.decisions.is_empty() {
            "Nothing to decide and no history yet.\n\nWhen a donor asks to fund one of your projects or organisations, the request waits here: accept it with your owner key, or with your passkey on the web (the /decide link), or refuse it."
        } else {
            "Nothing matches the filter. Esc clears it."
        };
        self.cur.draw(f, area, ctx.theme, self.title(), &rows, detail, empty);
    }

    fn on_input(&mut self, input: &Input, ctx: &Ctx) -> Outcome {
        let rows = rows(ctx);
        if self.cur.input(input, rows.len()) {
            return Outcome::Redraw;
        }
        let Some(K::Pending(i)) = self.cur.pick(&rows).map(|r| r.key) else { return Outcome::Ignored };
        let Some(p) = ctx.snap.pending.get(i) else { return Outcome::Ignored };
        match input {
            Input::Char('a') => confirm_accept(p, &ctx.snap.me.relay, ctx.now_ms),
            Input::Char('r') => confirm_refuse(p, ctx.now_ms),
            _ => Outcome::Ignored,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::projects::maint::tests::{ctx, draw, fixture, theme};
    use super::*;
    use crate::model::Snapshot;
    use crate::source::Action;

    #[test]
    fn pending_then_history_newest_first() {
        let snap = fixture();
        let t = theme(false);
        let c = ctx(&snap, &t, "");
        let mut v = DecisionsView::default();
        for (w, h) in [(80, 24), (160, 48)] {
            let s = draw(&mut v, w, h, &c);
            assert!(s.contains("Waiting for you · 2") && s.contains("History · 2"), "{s}");
            let (eve, dave) = (s.find("refused").unwrap(), s.find("accepted").unwrap());
            assert!(eve < dave, "newest first: {s}");
            assert!(s.contains('✓') && s.contains('✗'), "{s}");
        }
        v.on_input(&Input::Down, &c);
        let s = draw(&mut v, 160, 48, &c);
        assert!(s.contains("https://moochy.dev/decide/pl_01J"), "the /decide link: {s}");
        let Outcome::Confirm { action, .. } = v.on_input(&Input::Char('a'), &c) else { panic!() };
        assert_eq!(action, Action::Accept { request_id: "pl_01J".into() });
        v.on_input(&Input::End, &c);
        assert_eq!(v.on_input(&Input::Char('a'), &c), Outcome::Ignored, "history is read-only");
        let s = draw(&mut v, 160, 48, &c);
        assert!(s.contains("Via        passkey"), "{s}");
    }

    #[test]
    fn filter_ascii_and_empty() {
        let snap = fixture();
        let t = theme(true);
        let mut v = DecisionsView::default();
        let s = draw(&mut v, 80, 24, &ctx(&snap, &t, "carol"));
        assert!(s.contains("Waiting for you · 1") && s.contains("History · 0") && !s.contains('✓'), "{s}");
        let empty = Snapshot::default();
        let s = draw(&mut v, 80, 24, &ctx(&empty, &t, ""));
        assert!(s.contains("Nothing to decide") && s.contains("/decide"), "{s}");
    }
}
