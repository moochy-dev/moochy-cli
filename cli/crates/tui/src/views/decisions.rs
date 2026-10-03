//! The Decisions tab (CONTRACT §16, §20.2): requests waiting for me (accept with the owner key
//! through a confirmation, or with my passkey on the web via the /decide link; refuse) and the
//! history of accepts, refusals and revocations, newest first.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};

use super::{Ctx, Input, Outcome, View, pending};
use crate::model::Decision;
use crate::sanitize::clean;
use crate::theme::{Glyph, Theme};
use crate::widgets::{self as w, TreeList, TreeRow};

#[derive(Default)]
pub struct DecisionsView {
    cur: TreeList,
}

#[derive(Clone, Copy)]
enum K {
    Waiting,
    History,
    Pending(usize),
    Decision(usize),
}

fn event_glyph(event: &str) -> Glyph {
    let e = event.to_ascii_lowercase();
    if e.contains("accept") || e.contains("approv") {
        Glyph::Ok
    } else if e.contains("refus") || e.contains("declin") || e.contains("revok") {
        Glyph::Error
    } else {
        Glyph::Warn
    }
}

fn event(t: Theme, d: &Decision) -> Span<'static> {
    let g = event_glyph(&d.event);
    Span::styled(format!("{} {}", t.glyph(g), clean(&d.event)), t.glyph_style(g).add_modifier(ratatui::style::Modifier::BOLD))
}

fn rows(ctx: &Ctx) -> Vec<TreeRow<K>> {
    let (snap, t, q) = (ctx.snap, *ctx.theme, ctx.filter);
    let pending: Vec<_> = snap.pending.iter().enumerate().filter(|(_, p)| w::matches(q, &[&clean(&p.subject), &clean(&p.target), &p.kind])).collect();
    let mut history: Vec<_> = snap.decisions.iter().enumerate().filter(|(_, d)| w::matches(q, &[&clean(&d.donor), &clean(&d.target), &d.event])).collect();
    if pending.is_empty() && history.is_empty() {
        return Vec::new();
    }
    history.sort_by_key(|(_, d)| std::cmp::Reverse(d.at_ms));
    let mut out = vec![TreeRow { depth: 0, line: Line::from(w::bold(format!("Waiting for you · {}", pending.len()))), key: K::Waiting }];
    out.extend(pending.into_iter().map(|(i, p)| TreeRow { depth: 1, line: pending::line(t, p), key: K::Pending(i) }));
    out.push(TreeRow { depth: 0, line: Line::from(w::bold(format!("History · {}", history.len()))), key: K::History });
    out.extend(history.into_iter().map(|(i, d)| TreeRow { depth: 1, line: decision_line(t, d, ctx.now_ms), key: K::Decision(i) }));
    out
}

fn decision_line(t: Theme, d: &Decision, now_ms: u64) -> Line<'static> {
    Line::from(vec![event(t, d), Span::raw(format!("  {} → {}  ", clean(&d.donor), clean(&d.target))), w::muted(t, w::ago(now_ms, d.at_ms))])
}

fn detail(ctx: &Ctx, key: K) -> (String, Vec<Line<'static>>) {
    let (snap, t) = (ctx.snap, *ctx.theme);
    match key {
        K::Waiting => (
            "Waiting for you".into(),
            vec![
                Line::from(if snap.pending.is_empty() { "Nothing to decide right now." } else { "Donor requests for your projects and organisations." }),
                Line::default(),
                Line::from(vec![w::key("a"), w::muted(t, " accept with your owner key (checked with the server first)")]),
                Line::from(vec![w::key("r"), w::muted(t, " refuse, with an optional reason")]),
                Line::from(w::muted(t, "or open the request's /decide link to accept with your passkey.")),
            ],
        ),
        K::History => ("History".into(), vec![Line::from("Every accept, refusal and revocation, newest first: the same history as `moochy decisions`.")]),
        K::Pending(i) => ("Request".into(), snap.pending.get(i).map(|p| pending::detail(t, p, &snap.me.web, ctx.now_ms)).unwrap_or_default()),
        K::Decision(i) => {
            let Some(d) = snap.decisions.get(i) else { return Default::default() };
            (
                "Decision".into(),
                vec![
                    w::kv_span(t, "Event", event(t, d)),
                    w::kv(t, "When", format!("{} ({} UTC)", w::ago_long(ctx.now_ms, d.at_ms), w::datetime(d.at_ms))),
                    w::kv(t, "For", clean(&d.target)),
                    w::kv(t, "Donor", clean(&d.donor)),
                    w::kv(t, "Via", clean(&d.via)),
                    w::kv(t, "Reason", if d.reason.is_empty() { "—".into() } else { clean(&d.reason) }),
                ],
            )
        }
    }
}

impl View for DecisionsView {
    fn title(&self) -> &'static str {
        "Decisions"
    }

    fn labels(&self) -> (&'static str, &'static str) {
        ("Decisions", "Decide")
    }

    fn hints(&self) -> &'static [(&'static str, &'static str)] {
        &[("a", "accept"), ("r", "refuse")]
    }

    fn render(&mut self, f: &mut Frame, area: Rect, ctx: &Ctx) {
        let t = *ctx.theme;
        let rows = rows(ctx);
        let detail = self.cur.pick(&rows).map(|r| detail(ctx, r.key)).unwrap_or_default();
        let empty = if ctx.snap.pending.is_empty() && ctx.snap.decisions.is_empty() {
            vec![
                Line::from(w::badge(t, w::Tone::Good, t.glyph(Glyph::Ok), "Nothing to decide and no history yet")),
                Line::raw(""),
                Line::raw("When a donor asks to fund one of your projects or organisations, the request waits here:"),
                Line::raw("accept it with your owner key, or with your passkey on the web (the /decide link), or refuse it."),
            ]
        } else {
            w::no_match(t, ctx.filter)
        };
        let total = ctx.snap.pending.len().saturating_add(ctx.snap.decisions.len()).saturating_add(2);
        self.cur.draw(f, area, t, self.title(), &rows, total.max(rows.len()), detail, empty);
    }

    fn on_input(&mut self, input: &Input, ctx: &Ctx) -> Outcome {
        let rows = rows(ctx);
        if self.cur.input(input, rows.len()) {
            return Outcome::Redraw;
        }
        let Some(K::Pending(i)) = self.cur.pick(&rows).map(|r| r.key) else { return Outcome::Ignored };
        let Some(p) = ctx.snap.pending.get(i) else { return Outcome::Ignored };
        match input {
            Input::Char('a') => pending::confirm_accept(*ctx.theme, p, &ctx.snap.me.web, ctx.now_ms),
            Input::Char('r') => pending::refuse(p),
            _ => Outcome::Ignored,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Snapshot;
    use crate::source::Action;
    use crate::widgets::test_util::{ctx, draw, maint_fixture as fixture, theme};

    #[test]
    fn pending_then_history_newest_first() {
        let snap = fixture();
        let t = theme(false);
        let c = ctx(&snap, &t, "");
        let mut v = DecisionsView::default();
        for (w, h) in [(80, 24), (160, 48)] {
            let s = draw(&mut v, &c, w, h);
            assert!(s.contains("Waiting for you · 2") && s.contains("History · 2"), "{s}");
            let (eve, dave) = (s.find("refused").unwrap(), s.find("accepted").unwrap());
            assert!(eve < dave, "newest first: {s}");
            assert!(s.contains('✔') && s.contains('✖'), "{s}");
        }
        v.on_input(&Input::Down, &c);
        let s = draw(&mut v, &c, 160, 48);
        assert!(s.contains("https://moochy.dev/decide/pl_01J"), "the /decide link: {s}");
        let Outcome::Confirm { action, .. } = v.on_input(&Input::Char('a'), &c) else { panic!() };
        assert_eq!(action, Action::Accept { request_id: "pl_01J".into() });
        v.on_input(&Input::End, &c);
        assert_eq!(v.on_input(&Input::Char('a'), &c), Outcome::Ignored, "history is read-only");
        let s = draw(&mut v, &c, 160, 48);
        assert!(s.contains("Via        passkey"), "{s}");
    }

    #[test]
    fn filter_ascii_and_empty() {
        let snap = fixture();
        let t = theme(true);
        let mut v = DecisionsView::default();
        let s = draw(&mut v, &ctx(&snap, &t, "carol"), 80, 24).replace(" - ", " · ");
        assert!(s.contains("Waiting for you · 1") && s.contains("History · 0") && !s.contains('✔'), "{s}");
        let empty = Snapshot::default();
        let s = draw(&mut v, &ctx(&empty, &t, ""), 80, 24);
        assert!(s.contains("Nothing to decide") && s.contains("/decide"), "{s}");
    }
}
