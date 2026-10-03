//! The Organisations tab (CONTRACT §19, §20.2): my claimed orgs with their donors, the repos they
//! cover (use against the per-repo share cap, in dollars, §19.5), my claimed repos of the org that
//! are not covered yet, and waiting requests. Adding or removing a repo signs `ORG_REPO_ADDED` /
//! `ORG_REPO_REMOVED` through a confirmation. Owner: mo-tui-maint.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};

use super::projects::maint::{Cursor, Row, bar, bold, claim_status, confirm_accept, confirm_refuse, fuzzy, glyph, kv, pending_detail, pending_line};
use super::{Ctx, Input, Outcome, View};
use crate::model::Org;
use crate::sanitize::clean;
use crate::source::Action;
use crate::widgets::dollars;

#[derive(Default)]
pub struct OrgsView {
    cur: Cursor,
}

#[derive(Clone, Copy)]
enum K {
    Org(usize),
    Covered(usize, usize),
    /// A repo I claimed under the org's path that it does not cover: (org, project).
    Candidate(usize, usize),
    Pending(usize),
}

fn cap_text(used: u64, cap: u64) -> String {
    if cap == 0 { format!("{} · no cap", dollars(used)) } else { format!("{} of {} cap", dollars(used), dollars(cap)) }
}

fn rows(ctx: &Ctx) -> Vec<Row<K>> {
    let (snap, t) = (ctx.snap, ctx.theme);
    let mut out = Vec::new();
    for (i, o) in snap.orgs.iter().enumerate() {
        let path = clean(&o.path);
        if !fuzzy(&path, ctx.filter) && !o.covered.iter().any(|c| fuzzy(&clean(&c.slug), ctx.filter)) {
            continue;
        }
        let g = if o.paused_since_ms > 0 { glyph(t, "‖", "=") } else { glyph(t, "●", "*") };
        let mut spans = vec![Span::raw(format!("{g} ")), bold(path), Span::raw(format!("  {} donors  {}", o.donors, dollars(o.month_uusd)))];
        if o.paused_since_ms > 0 {
            spans.push(Span::styled("  PAUSED", Style::default().fg(t.coral()).add_modifier(Modifier::BOLD)));
        }
        out.push(Row { depth: 0, line: Line::from(spans), key: K::Org(i) });
        for (j, c) in o.covered.iter().enumerate() {
            let line = Line::from(vec![Span::raw(format!("{} covered  ", glyph(t, "✓", "v"))), Span::raw(clean(&c.slug)), Span::raw(format!("  {}", cap_text(c.used_uusd, c.share_cap_uusd)))]);
            out.push(Row { depth: 1, line, key: K::Covered(i, j) });
        }
        for (j, p) in candidates(o, ctx) {
            let line = Line::from(vec![Span::styled("+ not covered  ", Style::default().fg(t.sky())), Span::raw(clean(&p))]);
            out.push(Row { depth: 1, line, key: K::Candidate(i, j) });
        }
        for (k, p) in snap.pending.iter().enumerate().filter(|(_, p)| p.target == o.path || p.target == o.id) {
            out.push(Row { depth: 1, line: pending_line(t, p), key: K::Pending(k) });
        }
    }
    out
}

/// My claimed projects under the org's path that it does not cover (the relay checks the
/// provider ownership when the add is signed, §19.3).
fn candidates<'a>(o: &'a Org, ctx: &'a Ctx) -> impl Iterator<Item = (usize, String)> + 'a {
    let prefix = format!("{}/", o.path);
    ctx.snap.projects.iter().enumerate().filter(move |(_, p)| p.slug.starts_with(&prefix) && !o.covered.iter().any(|c| c.slug == p.slug)).map(|(j, p)| (j, p.slug.clone()))
}

fn detail(ctx: &Ctx, key: K) -> Vec<Line<'static>> {
    let snap = ctx.snap;
    match key {
        K::Org(i) => {
            let Some(o) = snap.orgs.get(i) else { return Vec::new() };
            let mut out = vec![Line::from(bold(clean(&o.path))), kv("Id", clean(&o.id))];
            out.extend(claim_status(ctx.theme, ctx.now_ms, o.paused_since_ms));
            out.push(kv("Donors", format!("{} approved", o.donors)));
            out.push(kv("This month", format!("{} across {} covered repos", dollars(o.month_uusd), o.covered.len())));
            if o.covered.is_empty() {
                out.push(Line::default());
                out.push(Line::from(format!("No repo covered yet: select a “+ not covered” repo and press a, or run `moochy org add <repo> --org {}`.", clean(&o.path))));
            }
            if o.donors == 0 {
                out.push(Line::from("No donors yet: share the org page or its button (moochy.dev/org/…)."));
            }
            out
        }
        K::Covered(i, j) => {
            let Some((o, c)) = snap.orgs.get(i).and_then(|o| o.covered.get(j).map(|c| (o, c))) else { return Vec::new() };
            let mut out = vec![Line::from(bold(clean(&c.slug))), kv("Org", clean(&o.path)), kv("Used", format!("{} this month from the org's donations", dollars(c.used_uusd)))];
            if c.share_cap_uusd == 0 {
                out.push(kv("Share cap", "none: may draw from all of the org's donations"));
            } else {
                out.push(kv("Share cap", format!("{} per month", dollars(c.share_cap_uusd))));
                out.push(kv("", bar(ctx.theme, c.used_uusd, c.share_cap_uusd, 20)));
            }
            out.push(Line::default());
            out.push(Line::from("x remove from the org (signs ORG_REPO_REMOVED) · share caps are set in org settings on the web"));
            out
        }
        K::Candidate(i, j) => {
            let (Some(o), Some(p)) = (snap.orgs.get(i), snap.projects.get(j)) else { return Vec::new() };
            vec![
                Line::from(bold(clean(&p.slug))),
                kv("Org", clean(&o.path)),
                kv("Status", "claimed by you, not covered by the org"),
                Line::default(),
                Line::from("a add to the org (signs ORG_REPO_ADDED): the org's donations may then serve it."),
            ]
        }
        K::Pending(k) => snap.pending.get(k).map(|p| pending_detail(p, &snap.me.relay, ctx.now_ms)).unwrap_or_default(),
    }
}

fn confirm_org(org: &str, repo: &str, add: bool) -> Outcome {
    let (verb, entry, effect) = if add {
        ("Add", "ORG_REPO_ADDED", "The org's donations may then serve this repo. The relay checks that the repo belongs to the org at the provider.")
    } else {
        ("Remove", "ORG_REPO_REMOVED", "The org's donations stop serving this repo; its own donations are unaffected.")
    };
    let body = format!(
        "Organisation  {}\nProject       {}\n\nYour owner key signs {entry}. {effect} The node confirms both names with the server first; if anything differs from what you see here, nothing is signed.",
        clean(org),
        clean(repo)
    );
    let (org, repo) = (org.to_owned(), repo.to_owned());
    let action = if add { Action::OrgAdd { org, repo } } else { Action::OrgRemove { org, repo } };
    Outcome::Confirm { title: format!("{verb} this repo {} the organisation?", if add { "to" } else { "from" }), body, action }
}

impl View for OrgsView {
    fn title(&self) -> &'static str {
        "Organisations"
    }

    fn hints(&self) -> &'static [(&'static str, &'static str)] {
        &[("↑↓", "move"), ("a", "add/accept"), ("x", "remove"), ("r", "refuse"), ("/", "filter")]
    }

    fn render(&mut self, f: &mut Frame, area: Rect, ctx: &Ctx) {
        let rows = rows(ctx);
        let detail = self.cur.pick(&rows).map(|r| detail(ctx, r.key)).unwrap_or_default();
        let empty = if ctx.snap.orgs.is_empty() {
            "No organisations yet.\n\nIf you own a GitHub organisation or a GitLab group, claim it with `moochy claim --org github/ORG` (or on the web), then add the repos its donations may serve with `moochy org add`."
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
        let Some(key) = self.cur.pick(&rows).map(|r| r.key) else { return Outcome::Ignored };
        let snap = ctx.snap;
        match (key, input) {
            (K::Candidate(i, j), Input::Char('a')) => match (snap.orgs.get(i), snap.projects.get(j)) {
                (Some(o), Some(p)) => confirm_org(&o.path, &p.slug, true),
                _ => Outcome::Ignored,
            },
            (K::Covered(i, j), Input::Char('x')) => match snap.orgs.get(i).and_then(|o| o.covered.get(j).map(|c| (o, c))) {
                Some((o, c)) => confirm_org(&o.path, &c.slug, false),
                None => Outcome::Ignored,
            },
            (K::Pending(k), Input::Char('a')) => snap.pending.get(k).map_or(Outcome::Ignored, |p| confirm_accept(p, &snap.me.relay, ctx.now_ms)),
            (K::Pending(k), Input::Char('r')) => snap.pending.get(k).map_or(Outcome::Ignored, |p| confirm_refuse(p, ctx.now_ms)),
            _ => Outcome::Ignored,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::projects::maint::tests::{ctx, draw, fixture, theme};
    use super::*;
    use crate::model::Snapshot;

    #[test]
    fn covered_candidates_and_caps() {
        let snap = fixture();
        let t = theme(false);
        let c = ctx(&snap, &t, "");
        let mut v = OrgsView::default();
        for (w, h) in [(80, 24), (160, 48)] {
            let s = draw(&mut v, w, h, &c);
            assert!(s.contains("github/acme") && s.contains("2 donors"), "{s}");
            assert!(s.contains("covered  github/acme/widget  $3.00 of $10.00 cap"), "{s}");
            assert!(s.contains("+ not covered  github/acme/gadget") && s.contains("carol"), "{s}");
            assert!(!s.contains('%'), "share caps are dollars, never a percent");
        }
    }

    #[test]
    fn add_remove_go_through_confirm() {
        let snap = fixture();
        let t = theme(false);
        let c = ctx(&snap, &t, "");
        let mut v = OrgsView::default();
        draw(&mut v, 80, 24, &c);
        assert_eq!(v.on_input(&Input::Char('x'), &c), Outcome::Ignored, "the org row");
        v.on_input(&Input::Down, &c);
        let Outcome::Confirm { action, body, .. } = v.on_input(&Input::Char('x'), &c) else { panic!() };
        assert_eq!(action, Action::OrgRemove { org: "github/acme".into(), repo: "github/acme/widget".into() });
        assert!(body.contains("ORG_REPO_REMOVED") && body.contains("github/acme/widget"));
        assert_eq!(v.on_input(&Input::Char('a'), &c), Outcome::Ignored, "a covered repo is not added twice");
        v.on_input(&Input::Down, &c);
        let Outcome::Confirm { action, .. } = v.on_input(&Input::Char('a'), &c) else { panic!() };
        assert_eq!(action, Action::OrgAdd { org: "github/acme".into(), repo: "github/acme/gadget".into() });
        // The candidate with an escape in its slug is shown inert; the action carries the raw slug
        // for the node to check with the server.
        v.on_input(&Input::Down, &c);
        let s = draw(&mut v, 160, 48, &c);
        assert!(s.contains("evil") && !s.contains('\u{1b}'));
        v.on_input(&Input::Down, &c);
        assert!(matches!(v.on_input(&Input::Char('a'), &c), Outcome::Confirm { action: Action::Accept { .. }, .. }));
    }

    #[test]
    fn empty_state() {
        let snap = Snapshot::default();
        let t = theme(true);
        let s = draw(&mut OrgsView::default(), 80, 24, &ctx(&snap, &t, ""));
        assert!(s.contains("No organisations yet") && s.contains("--org github/ORG"), "{s}");
    }
}
