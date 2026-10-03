//! The Organisations tab (CONTRACT §19, §20.2): my claimed orgs with their donors, the repos they
//! cover (use against the per-repo share cap, in dollars, §19.5), my claimed repos of the org that
//! are not covered yet, and waiting requests. Adding or removing a repo signs `ORG_REPO_ADDED` /
//! `ORG_REPO_REMOVED` through a confirmation.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};

use super::{Ctx, Input, Outcome, View, pending};
use crate::model::Org;
use crate::sanitize::clean;
use crate::source::Action;
use crate::theme::{Glyph, Theme};
use crate::widgets::{self as w, Tone, TreeList, TreeRow, charts};

#[derive(Default)]
pub struct OrgsView {
    cur: TreeList,
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
    if cap == 0 { format!("{} · no cap", w::dollars(used)) } else { format!("{} of {} cap", w::dollars(used), w::dollars(cap)) }
}

fn rows(ctx: &Ctx) -> Vec<TreeRow<K>> {
    let (snap, t) = (ctx.snap, *ctx.theme);
    let mut out = Vec::new();
    let name_w = snap.orgs.iter().flat_map(|o| std::iter::once(o.path.as_str()).chain(o.covered.iter().map(|c| c.slug.as_str()))).map(|s| clean(s).chars().count()).max().unwrap_or(0).clamp(12, 34);
    for (i, o) in snap.orgs.iter().enumerate() {
        let path = clean(&o.path);
        if !w::matches(ctx.filter, &[&path]) && !o.covered.iter().any(|c| w::matches(ctx.filter, &[&clean(&c.slug)])) {
            continue;
        }
        let status = if o.paused_since_ms > 0 { w::badge(t, Tone::Bad, t.glyph(Glyph::Paused), "paused") } else { w::badge(t, Tone::Good, t.glyph(Glyph::Ok), "active") };
        let spans = vec![
            w::col(&status, pending::STATUS_W.saturating_add(2)),
            w::col(&w::bold(if o.person { format!("person {path}") } else { path }), name_w),
            Span::styled(format!("{:>9}", w::dollars(o.month_uusd)), t.money()),
            w::muted(t, format!("  {} donors", o.donors)),
        ];
        out.push(TreeRow { header: false, depth: 0, line: Line::from(spans), key: K::Org(i) });
        for (j, c) in o.covered.iter().enumerate() {
            let line = Line::from(vec![
                w::col(&w::badge(t, Tone::Good, t.glyph(Glyph::Ok), "covered"), pending::STATUS_W),
                w::col(&Span::raw(clean(&c.slug)), name_w),
                Span::styled(format!("{:>9}", w::dollars(c.used_uusd)), t.money()),
                w::muted(t, if c.share_cap_uusd == 0 { "  no cap".to_string() } else { format!(" of {} cap", w::dollars(c.share_cap_uusd)) }),
            ]);
            out.push(TreeRow { header: false, depth: 1, line, key: K::Covered(i, j) });
        }
        for (j, p) in candidates(o, ctx) {
            let line = Line::from(vec![w::col(&w::badge(t, Tone::Info, "+", "not covered"), pending::STATUS_W), Span::raw(clean(&p))]);
            out.push(TreeRow { header: false, depth: 1, line, key: K::Candidate(i, j) });
        }
        for (k, p) in snap.pending.iter().enumerate().filter(|(_, p)| p.target == o.path || p.target == o.id) {
            out.push(TreeRow { header: false, depth: 1, line: pending::line(t, p, name_w), key: K::Pending(k) });
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

/// The org at a glance: status, donors, the month's use with its 30-day trend, and every covered
/// repo as a bar against its share cap (or against the biggest user when uncapped).
fn org_detail(t: Theme, ctx: &Ctx, o: &Org) -> Vec<Line<'static>> {
    let mut out = vec![w::kv(t, "Id", clean(&o.id))];
    out.extend(pending::claim_status(t, ctx.now_ms, o.paused_since_ms));
    out.push(w::kv(t, "Donors", format!("{} approved", o.donors)));
    out.push(w::kv_span(t, "This month", Span::styled(format!("{} across {} covered repos", w::dollars(o.month_uusd), o.covered.len()), t.money())));
    if o.per_day_uusd.iter().any(|&v| v > 0) {
        out.push(Line::from(vec![w::muted(t, format!("{:<10} ", "30 days")), charts::spark_text(t, &o.per_day_uusd, 30, t.money())]));
    }
    out.push(w::kv(t, "Page", format!("{}/{}/{}", w::web_origin(&ctx.snap.me.web), if o.person { "people" } else { "org" }, clean(&o.path))));
    if o.covered.is_empty() {
        out.push(Line::default());
        out.push(Line::from(w::muted(t, format!("No repo covered yet: select a “+ not covered” repo and press a, or run `moochy org add <repo> --org {}`.", clean(&o.path)))));
    } else {
        out.push(Line::default());
        out.push(Line::from(w::bold("Covered repos")));
        let top = o.covered.iter().map(|c| c.share_cap_uusd.max(c.used_uusd)).max().unwrap_or(0);
        let name_w = o.covered.iter().map(|c| c.slug.chars().count()).max().unwrap_or(0).min(28);
        for c in &o.covered {
            let (of, style) = if c.share_cap_uusd == 0 { (top, t.ok()) } else { (c.share_cap_uusd, if c.used_uusd >= c.share_cap_uusd { t.err() } else { t.ok() }) };
            let mut l = vec![Span::raw(format!("  {:<name_w$} ", w::trunc(&w::short_slug(&clean(&c.slug), name_w), name_w)))];
            l.extend(charts::bar(t, c.used_uusd, of, 12, style).spans);
            l.push(w::muted(t, format!(" {}", cap_text(c.used_uusd, c.share_cap_uusd))));
            out.push(Line::from(l));
        }
    }
    if o.donors == 0 {
        out.push(Line::from(w::muted(t, "No donors yet: share the org page or its button.")));
    }
    out
}

fn detail(ctx: &Ctx, key: K) -> (String, Vec<Line<'static>>) {
    let (snap, t) = (ctx.snap, *ctx.theme);
    match key {
        K::Org(i) => snap.orgs.get(i).map(|o| (format!("{}{}", if o.person { "person " } else { "" }, clean(&o.path)), org_detail(t, ctx, o))).unwrap_or_default(),
        K::Covered(i, j) => {
            let Some((o, c)) = snap.orgs.get(i).and_then(|o| o.covered.get(j).map(|c| (o, c))) else { return Default::default() };
            let mut out = vec![w::kv(t, "Org", clean(&o.path)), w::kv(t, "Used", format!("{} this month from the org's donations", w::dollars(c.used_uusd)))];
            if c.share_cap_uusd == 0 {
                out.push(w::kv(t, "Share cap", "none: may draw from all of the org's donations"));
            } else {
                out.push(w::kv(t, "Share cap", format!("{} per month", w::dollars(c.share_cap_uusd))));
                let mut l = vec![Span::raw(format!("{:<11}", ""))];
                l.extend(charts::bar(t, c.used_uusd, c.share_cap_uusd, 20, t.ok()).spans);
                out.push(Line::from(l));
            }
            out.push(Line::default());
            out.push(Line::from(vec![w::key("x"), w::muted(t, " remove from the org (signs ORG_REPO_REMOVED); share caps are set in org settings on the web")]));
            (clean(&c.slug), out)
        }
        K::Candidate(i, j) => {
            let (Some(o), Some(p)) = (snap.orgs.get(i), snap.projects.get(j)) else { return Default::default() };
            (
                clean(&p.slug),
                vec![
                    w::kv(t, "Org", clean(&o.path)),
                    w::kv(t, "Status", "claimed by you, not covered by the org"),
                    Line::default(),
                    Line::from(vec![w::key("a"), w::muted(t, " add to the org (signs ORG_REPO_ADDED): the org's donations may then serve it.")]),
                ],
            )
        }
        K::Pending(k) => ("Request".into(), snap.pending.get(k).map(|p| pending::detail(t, p, &snap.me.web, ctx.now_ms)).unwrap_or_default()),
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

    // Also lists the user's person profiles (§24): sponsorship of a maintainer works like an org.

    fn labels(&self) -> (&'static str, &'static str) {
        ("Orgs", "Orgs")
    }

    fn hints(&self) -> &'static [(&'static str, &'static str)] {
        &[("a", "add/accept"), ("x", "remove"), ("r", "refuse")]
    }

    fn render(&mut self, f: &mut Frame, area: Rect, ctx: &Ctx) {
        let t = *ctx.theme;
        let rows = rows(ctx);
        let detail = self.cur.pick(&rows).map(|r| detail(ctx, r.key)).unwrap_or_default();
        let empty = if ctx.snap.orgs.is_empty() {
            vec![
                Line::from(w::badge(t, Tone::Info, t.glyph(Glyph::Connecting), "No organisations yet")),
                Line::raw(""),
                Line::raw("Own a GitHub organisation or a GitLab group? Claim it:"),
                Line::from(w::key("moochy claim --org github/ORG")),
                Line::raw("then add the repos its donations may serve:"),
                Line::from(w::key("moochy org add <repo> --org github/ORG")),
            ]
        } else {
            w::no_match(t, ctx.filter)
        };
        let total: usize = ctx.snap.orgs.iter().map(|o| o.covered.len().saturating_add(1)).sum();
        self.cur.draw(f, area, t, self.title(), &rows, total.max(rows.len()), detail, empty);
    }

    fn on_input(&mut self, input: &Input, ctx: &Ctx) -> Outcome {
        let rows = rows(ctx);
        if self.cur.input(input, &rows) {
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
            (K::Pending(k), Input::Char('a')) => snap.pending.get(k).map_or(Outcome::Ignored, |p| pending::confirm_accept(*ctx.theme, p, &snap.me.web, ctx.now_ms)),
            (K::Pending(k), Input::Char('r')) => snap.pending.get(k).map_or(Outcome::Ignored, pending::refuse),
            (_, Input::Char('a')) => Outcome::Toast("a adds a “not covered” repo or accepts a waiting request: select one first".into()),
            (_, Input::Char('x')) => Outcome::Toast("x removes a covered repo: select one first".into()),
            (_, Input::Char('r')) => Outcome::Toast("r refuses a waiting request: select one first".into()),
            _ => Outcome::Ignored,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Snapshot;
    use crate::widgets::test_util::{ctx, draw, maint_fixture as fixture, theme};

    #[test]
    fn covered_candidates_and_caps() {
        let snap = fixture();
        let t = theme(false);
        let c = ctx(&snap, &t, "");
        let mut v = OrgsView::default();
        for (w, h) in [(80, 24), (160, 48)] {
            let s = draw(&mut v, &c, w, h);
            assert!(s.contains("github/acme") && s.contains("2 donors"), "{s}");
            assert!(s.contains("covered") && s.contains("github/acme/widget") && s.contains("$3.00 of $10.00 cap"), "{s}");
            assert!(s.contains("not covered github/acme/gadget") && s.contains("carol"), "{s}");
            assert!(!s.contains('%'), "share caps are dollars, never a percent");
        }
        let s = draw(&mut v, &c, 160, 48);
        assert!(s.contains("Covered repos") && s.contains("https://moochy.dev/org/github/acme"), "{s}");
    }

    #[test]
    fn add_remove_go_through_confirm() {
        let snap = fixture();
        let t = theme(false);
        let c = ctx(&snap, &t, "");
        let mut v = OrgsView::default();
        draw(&mut v, &c, 80, 24);
        assert!(matches!(v.on_input(&Input::Char('x'), &c), Outcome::Toast(_)), "the org row");
        v.on_input(&Input::Down, &c);
        let Outcome::Confirm { action, body, .. } = v.on_input(&Input::Char('x'), &c) else { panic!() };
        assert_eq!(action, Action::OrgRemove { org: "github/acme".into(), repo: "github/acme/widget".into() });
        assert!(body.contains("ORG_REPO_REMOVED") && body.contains("github/acme/widget"));
        assert!(matches!(v.on_input(&Input::Char('a'), &c), Outcome::Toast(_)), "a covered repo is not added twice");
        v.on_input(&Input::Down, &c);
        let Outcome::Confirm { action, .. } = v.on_input(&Input::Char('a'), &c) else { panic!() };
        assert_eq!(action, Action::OrgAdd { org: "github/acme".into(), repo: "github/acme/gadget".into() });
        // The candidate with an escape in its slug is shown inert; the action carries the raw slug
        // for the node to check with the server.
        v.on_input(&Input::Down, &c);
        let s = draw(&mut v, &c, 160, 48);
        assert!(s.contains("acme/\u{FFFD}tool") && !s.contains("evil"), "{s}");
        v.on_input(&Input::Down, &c);
        assert!(matches!(v.on_input(&Input::Char('a'), &c), Outcome::Confirm { action: Action::Accept { .. }, .. }));
    }

    #[test]
    fn empty_state() {
        let snap = Snapshot::default();
        let t = theme(true);
        let s = draw(&mut OrgsView::default(), &ctx(&snap, &t, ""), 80, 24);
        assert!(s.contains("No organisations yet") && s.contains("--org github/ORG"), "{s}");
    }
}
