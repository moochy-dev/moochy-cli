//! The Projects tab (CONTRACT §20.2): my claimed repos with their use against the goal, donors,
//! members, the orgs that also fund them, paused claims (§19.2a), and the requests waiting under
//! each, to accept (owner key, checked with the server, A217/A218) or refuse. Owner: mo-tui-maint.

pub mod maint;

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};

use self::maint::{Cursor, Row, bar, bold, claim_status, confirm_accept, confirm_refuse, fuzzy, glyph, kv, pending_detail, pending_line};
use super::{Ctx, Input, Outcome, View};
use crate::sanitize::clean;
use crate::widgets::dollars;

#[derive(Default)]
pub struct ProjectsView {
    cur: Cursor,
}

#[derive(Clone, Copy)]
enum K {
    Project(usize),
    Pending(usize),
}

fn rows(ctx: &Ctx) -> Vec<Row<K>> {
    let t = ctx.theme;
    let mut out = Vec::new();
    for (i, p) in ctx.snap.projects.iter().enumerate() {
        let slug = clean(&p.slug);
        let waiting: Vec<_> = ctx.snap.pending.iter().enumerate().filter(|(_, r)| r.target == p.slug || r.target == p.id).collect();
        if !fuzzy(&slug, ctx.filter) && !waiting.iter().any(|(_, r)| fuzzy(&clean(&r.subject), ctx.filter)) {
            continue;
        }
        let g = if p.paused_since_ms > 0 { glyph(t, "‖", "=") } else { glyph(t, "●", "*") };
        let mut spans = vec![Span::raw(format!("{g} ")), bold(slug), Span::raw(format!("  {}", dollars(p.month_uusd)))];
        if p.goal_uusd > 0 {
            spans.push(Span::raw(format!(" of {}", dollars(p.goal_uusd))));
        }
        if p.paused_since_ms > 0 {
            spans.push(Span::styled("  PAUSED", Style::default().fg(t.coral()).add_modifier(Modifier::BOLD)));
        }
        out.push(Row { depth: 0, line: Line::from(spans), key: K::Project(i) });
        out.extend(waiting.into_iter().map(|(j, r)| Row { depth: 1, line: pending_line(t, r), key: K::Pending(j) }));
    }
    out
}

fn list_or_none(label: &str, v: &[String], none: &str) -> Line<'static> {
    kv(label, if v.is_empty() { none.to_owned() } else { v.iter().map(|s| clean(s)).collect::<Vec<_>>().join(", ") })
}

fn detail(ctx: &Ctx, key: K) -> Vec<Line<'static>> {
    let (snap, t) = (ctx.snap, ctx.theme);
    match key {
        K::Pending(j) => snap.pending.get(j).map(|p| pending_detail(p, &snap.me.relay, ctx.now_ms)).unwrap_or_default(),
        K::Project(i) => {
            let Some(p) = snap.projects.get(i) else { return Vec::new() };
            let mut v = vec![Line::from(bold(clean(&p.slug))), kv("Id", clean(&p.id))];
            v.extend(claim_status(t, ctx.now_ms, p.paused_since_ms));
            if p.goal_uusd > 0 {
                v.push(kv("This month", format!("{} of {} goal", dollars(p.month_uusd), dollars(p.goal_uusd))));
                v.push(kv("", bar(t, p.month_uusd, p.goal_uusd, 20)));
            } else {
                v.push(kv("This month", format!("{} used (no goal set)", dollars(p.month_uusd))));
            }
            v.push(kv("Donors", format!("{} active · {} waiting", p.donors, p.pending)));
            v.push(list_or_none("Members", &p.members, "only you"));
            v.push(list_or_none("Funded by", &p.funded_by, "no organisation"));
            if p.donors == 0 && p.pending == 0 {
                v.push(Line::default());
                v.push(Line::from("No donors yet: share the project's donate link or README button (moochy.dev/p/…)."));
            }
            v
        }
    }
}

impl View for ProjectsView {
    fn title(&self) -> &'static str {
        "Projects"
    }

    fn hints(&self) -> &'static [(&'static str, &'static str)] {
        &[("↑↓", "move"), ("a", "accept"), ("r", "refuse"), ("/", "filter")]
    }

    fn render(&mut self, f: &mut Frame, area: Rect, ctx: &Ctx) {
        let rows = rows(ctx);
        let detail = self.cur.pick(&rows).map(|r| detail(ctx, r.key)).unwrap_or_default();
        let empty = if ctx.snap.projects.is_empty() {
            "No claimed projects yet.\n\nClaim a repository you administer with `moochy claim github/OWNER/NAME` (or on the web), then share its donate link. Donors and their requests show up here."
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
        let Some(K::Pending(j)) = self.cur.pick(&rows).map(|r| r.key) else { return Outcome::Ignored };
        let Some(p) = ctx.snap.pending.get(j) else { return Outcome::Ignored };
        match input {
            Input::Char('a') => confirm_accept(p, &ctx.snap.me.relay, ctx.now_ms),
            Input::Char('r') => confirm_refuse(p, ctx.now_ms),
            _ => Outcome::Ignored,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::maint::tests::{ctx, draw, fixture, theme};
    use super::*;
    use crate::model::Snapshot;
    use crate::source::Action;

    #[test]
    fn lists_projects_with_waiting_requests_and_paused_claims() {
        let snap = fixture();
        let t = theme(false);
        let c = ctx(&snap, &t, "");
        let mut v = ProjectsView::default();
        for (w, h) in [(80, 24), (160, 48)] {
            let s = draw(&mut v, w, h, &c);
            assert!(s.contains("github/acme/widget") && s.contains("waiting") && s.contains("alice"), "{s}");
            assert!(s.contains("PAUSED") && s.contains('‖'), "paused shown by word and glyph: {s}");
            assert!(s.contains("$12.00 of $50.00 goal") && s.contains("Funded by") && s.contains("github/acme"), "{s}");
        }
        // The paused project's detail says what to do.
        assert_eq!(v.on_input(&Input::End, &c), Outcome::Redraw);
        assert_eq!(v.on_input(&Input::Up, &c), Outcome::Redraw);
        let s = draw(&mut v, 160, 48, &c);
        assert!(s.contains("sign in on the web"), "{s}");
        let s = draw(&mut v, 80, 24, &ctx(&snap, &theme(true), ""));
        assert!(s.contains("+--") && s.contains("> ") && !s.contains('▶'), "ascii: {s}");
    }

    #[test]
    fn accept_and_refuse_go_through_confirm() {
        let snap = fixture();
        let t = theme(false);
        let c = ctx(&snap, &t, "");
        let mut v = ProjectsView::default();
        draw(&mut v, 80, 24, &c);
        assert_eq!(v.on_input(&Input::Char('a'), &c), Outcome::Ignored, "a project row is not a request");
        v.on_input(&Input::Down, &c);
        let Outcome::Confirm { action, body, .. } = v.on_input(&Input::Char('a'), &c) else { panic!() };
        assert_eq!(action, Action::Accept { request_id: "pl_01J".into() });
        assert!(body.contains("alice") && body.contains("$20.00/month"));
        assert!(matches!(v.on_input(&Input::Char('r'), &c), Outcome::Confirm { action: Action::Refuse { .. }, .. }));
    }

    #[test]
    fn mouse_filter_and_empty_states() {
        let snap = fixture();
        let t = theme(false);
        let mut v = ProjectsView::default();
        let c = ctx(&snap, &t, "tool");
        let s = draw(&mut v, 80, 24, &c);
        assert!(s.contains("evil") && !s.contains("widget"), "{s}");
        let c = ctx(&snap, &t, "");
        draw(&mut v, 80, 24, &c);
        assert_eq!(v.on_input(&Input::Click { col: 5, row: 2 }, &c), Outcome::Redraw);
        assert!(matches!(v.on_input(&Input::Char('a'), &c), Outcome::Confirm { .. }), "clicked the request row");
        assert_eq!(v.on_input(&Input::Click { col: 5, row: 23 }, &c), Outcome::Ignored, "outside the list");
        let s = draw(&mut v, 80, 24, &ctx(&snap, &t, "zzz"));
        assert!(s.contains("Nothing matches"));
        let empty = Snapshot::default();
        let s = draw(&mut v, 80, 24, &ctx(&empty, &t, ""));
        assert!(s.contains("moochy claim"), "{s}");
    }
}
