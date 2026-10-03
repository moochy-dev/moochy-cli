//! The Projects tab (CONTRACT §20.2): my claimed repos with their use against the goal, donors,
//! members, the orgs that also fund them, paused claims (§19.2a), and the requests waiting under
//! each, to accept (owner key, checked with the server, A217/A218) or refuse.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};

use super::{Ctx, Input, Outcome, View, pending};
use crate::sanitize::clean;
use crate::theme::Glyph;
use crate::widgets::{self as w, Tone, TreeList, TreeRow, charts};

#[derive(Default)]
pub struct ProjectsView {
    cur: TreeList,
}

#[derive(Clone, Copy)]
enum K {
    Project(usize),
    Pending(usize),
}

fn rows(ctx: &Ctx) -> Vec<TreeRow<K>> {
    let t = *ctx.theme;
    let mut out = Vec::new();
    // Columns: status, name (as wide as the longest, at most 34), money right-aligned.
    let name_w = ctx.snap.projects.iter().map(|p| clean(&p.slug).chars().count()).max().unwrap_or(0).clamp(12, 34);
    for (i, p) in ctx.snap.projects.iter().enumerate() {
        let slug = clean(&p.slug);
        let waiting: Vec<_> = ctx.snap.pending.iter().enumerate().filter(|(_, r)| r.target == p.slug || r.target == p.id).collect();
        if !w::matches(ctx.filter, &[&slug]) && !waiting.iter().any(|(_, r)| w::matches(ctx.filter, &[&clean(&r.subject)])) {
            continue;
        }
        let status = if p.paused_since_ms > 0 { w::badge(t, Tone::Bad, t.glyph(Glyph::Paused), "paused") } else { w::badge(t, Tone::Good, t.glyph(Glyph::Online), "active") };
        let mut spans = vec![w::col(&status, pending::STATUS_W.saturating_add(2)), w::col(&w::bold(slug), name_w)];
        spans.push(Span::styled(format!("{:>9}", w::dollars(p.month_uusd)), t.money()));
        if p.goal_uusd > 0 {
            spans.push(w::muted(t, format!(" of {}", w::dollars(p.goal_uusd))));
        }
        out.push(TreeRow { header: false, depth: 0, line: Line::from(spans), key: K::Project(i) });
        out.extend(waiting.into_iter().map(|(j, r)| TreeRow { header: false, depth: 1, line: pending::line(t, r, name_w), key: K::Pending(j) }));
    }
    out
}

fn list_or(t: crate::theme::Theme, label: &str, v: &[String], none: &str) -> Line<'static> {
    w::kv(t, label, if v.is_empty() { none.to_owned() } else { v.iter().map(|s| clean(s)).collect::<Vec<_>>().join(", ") })
}

fn detail(ctx: &Ctx, key: K) -> (String, Vec<Line<'static>>) {
    let (snap, t) = (ctx.snap, *ctx.theme);
    match key {
        K::Pending(j) => ("Request".into(), snap.pending.get(j).map(|p| pending::detail(t, p, &snap.me.web, ctx.now_ms)).unwrap_or_default()),
        K::Project(i) => {
            let Some(p) = snap.projects.get(i) else { return (String::new(), Vec::new()) };
            let mut v = vec![w::kv(t, "Id", clean(&p.id))];
            v.extend(pending::claim_status(t, ctx.now_ms, p.paused_since_ms));
            if p.goal_uusd > 0 {
                v.push(w::kv(t, "This month", format!("{} of {} goal", w::dollars(p.month_uusd), w::dollars(p.goal_uusd))));
                let mut l = vec![Span::raw(format!("{:<11}", ""))];
                l.extend(charts::meter(t, p.month_uusd, p.goal_uusd, 20).spans);
                v.push(Line::from(l));
            } else {
                v.push(w::kv(t, "This month", format!("{} used (no goal set)", w::dollars(p.month_uusd))));
            }
            v.push(w::kv(t, "Donors", format!("{} active{}{} waiting", p.donors, w::dot(t), p.pending)));
            v.push(list_or(t, "Members", &p.members, "only you"));
            v.push(list_or(t, "Funded by", &p.funded_by, "no organisation"));
            v.push(w::kv(t, "Page", format!("{}/p/{}", w::web_origin(&snap.me.web), clean(&p.slug))));
            if p.donors == 0 && p.pending == 0 {
                v.push(Line::default());
                v.push(Line::from(w::muted(t, "No donors yet: share the page above or its README button.")));
            }
            (clean(&p.slug), v)
        }
    }
}

impl View for ProjectsView {
    fn title(&self) -> &'static str {
        "Projects"
    }

    fn labels(&self) -> (&'static str, &'static str) {
        ("Projects", "Repos")
    }

    fn hints(&self) -> &'static [(&'static str, &'static str)] {
        &[("a", "accept"), ("r", "refuse")]
    }

    fn render(&mut self, f: &mut Frame, area: Rect, ctx: &Ctx) {
        let t = *ctx.theme;
        let rows = rows(ctx);
        let detail = self.cur.pick(&rows).map(|r| detail(ctx, r.key)).unwrap_or_default();
        let empty = if ctx.snap.projects.is_empty() {
            vec![
                Line::from(w::badge(t, Tone::Info, t.glyph(Glyph::Connecting), "No claimed projects yet")),
                Line::raw(""),
                Line::raw("Claim a repository you administer (or do it on the web):"),
                Line::from(w::key("moochy claim github/OWNER/NAME")),
                Line::raw(""),
                Line::from(w::muted(t, "Then share its page; donors and their requests show up here.")),
            ]
        } else {
            w::no_match(t, ctx.filter)
        };
        let total = ctx.snap.projects.len().saturating_add(ctx.snap.pending.iter().filter(|r| ctx.snap.projects.iter().any(|p| r.target == p.slug || r.target == p.id)).count());
        self.cur.draw(f, area, t, self.title(), &rows, total, detail, empty);
    }

    fn on_input(&mut self, input: &Input, ctx: &Ctx) -> Outcome {
        let rows = rows(ctx);
        if self.cur.input(input, &rows) {
            return Outcome::Redraw;
        }
        let Some(K::Pending(j)) = self.cur.pick(&rows).map(|r| r.key) else {
            return match input {
                Input::Char('a' | 'r') => Outcome::Toast("Select a waiting request first (◆ waiting)".into()),
                _ => Outcome::Ignored,
            };
        };
        let Some(p) = ctx.snap.pending.get(j) else { return Outcome::Ignored };
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
    fn lists_projects_with_waiting_requests_and_paused_claims() {
        let snap = fixture();
        let t = theme(false);
        let c = ctx(&snap, &t, "");
        let mut v = ProjectsView::default();
        for (w, h) in [(80, 24), (160, 48)] {
            let s = draw(&mut v, &c, w, h);
            assert!(s.contains("github/acme/widget") && s.contains("waiting") && s.contains("alice"), "{s}");
            assert!(s.contains("paused") && s.contains('‖'), "paused shown by word and glyph: {s}");
            assert!(s.contains("$12.00 of $50.00 goal") && s.contains("Funded by") && s.contains("github/acme"), "{s}");
        }
        // The paused project's detail says what to do.
        assert_eq!(v.on_input(&Input::End, &c), Outcome::Redraw);
        assert_eq!(v.on_input(&Input::Up, &c), Outcome::Redraw);
        let s = draw(&mut v, &c, 160, 48);
        assert!(s.contains("re-verify"), "{s}");
        let s = draw(&mut v, &ctx(&snap, &theme(true), ""), 80, 24);
        assert!(s.contains("+--") && s.contains("> ") && !s.contains('▶'), "ascii: {s}");
    }

    #[test]
    fn accept_and_refuse_go_through_confirm() {
        let snap = fixture();
        let t = theme(false);
        let c = ctx(&snap, &t, "");
        let mut v = ProjectsView::default();
        draw(&mut v, &c, 80, 24);
        assert!(matches!(v.on_input(&Input::Char('a'), &c), Outcome::Toast(_)), "a project row is not a request");
        v.on_input(&Input::Down, &c);
        let Outcome::Confirm { action, body, .. } = v.on_input(&Input::Char('a'), &c) else { panic!() };
        assert_eq!(action, Action::Accept { request_id: "pl_01J".into() });
        assert!(body.contains("alice") && body.contains("$20.00/month"));
        assert!(matches!(v.on_input(&Input::Char('r'), &c), Outcome::Prompt(_)));
    }

    #[test]
    fn mouse_filter_and_empty_states() {
        let snap = fixture();
        let t = theme(false);
        let mut v = ProjectsView::default();
        let c = ctx(&snap, &t, "tool");
        let s = draw(&mut v, &c, 80, 24);
        assert!(s.contains("evil") && s.contains("tool") && !s.contains('\u{1b}') && !s.contains("widget"), "{s}");
        let c = ctx(&snap, &t, "");
        draw(&mut v, &c, 80, 24);
        assert_eq!(v.on_input(&Input::Click { col: 5, row: 2 }, &c), Outcome::Redraw);
        assert!(matches!(v.on_input(&Input::Char('a'), &c), Outcome::Confirm { .. }), "clicked the request row");
        assert_eq!(v.on_input(&Input::Click { col: 5, row: 23 }, &c), Outcome::Ignored, "outside the list");
        let s = draw(&mut v, &ctx(&snap, &t, "zzz"), 80, 24);
        assert!(s.contains("Nothing matches"));
        let empty = Snapshot::default();
        let s = draw(&mut v, &ctx(&empty, &t, ""), 80, 24);
        assert!(s.contains("moochy claim"), "{s}");
    }
}
