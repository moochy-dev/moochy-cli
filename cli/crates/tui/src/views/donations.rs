//! The Donations tab (CONTRACT §20.2): my donations with status, limit vs spent, schedule, models,
//! the 30-day trend and the next renewal; pause/resume, stop and lower the limit, each behind a
//! confirmation; per-project spend for organisation and person donations; the share link (§9).

use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table, Wrap};

use super::{Ctx, Input, Outcome, Prompt, Then, View};
use crate::model::Donation;
use crate::sanitize::clean;
use crate::source::Action;
use crate::theme::{Glyph, Theme};
use crate::widgets::{self as w, TableCursor, Tone, charts, list};

const CENT: u64 = 10_000;
/// Org donations: projects listed in the detail pane before "+N more".
const MAX_REPOS: usize = 8;

#[derive(Default)]
pub struct DonationsView {
    cur: TableCursor,
    note: Option<String>,
}

struct Status {
    tone: Tone,
    glyph: Glyph,
    label: String,
    why: &'static str,
}

fn status(d: &Donation) -> Status {
    let s = |tone, glyph, label: &str, why| Status { tone, glyph, label: label.to_owned(), why };
    match d.status.as_str() {
        "active" if d.budget_uusd > 0 && d.spent_uusd >= d.budget_uusd => {
            s(Tone::Warn, Glyph::Warn, "limit reached", "its monthly limit is used up; it starts again next month")
        }
        "active" => s(Tone::Good, Glyph::Online, "active", "your devices serve it, up to the limit"),
        "paused" => s(Tone::Warn, Glyph::Paused, "paused", "nothing is served until you resume it"),
        "pending" => s(Tone::Info, Glyph::Pending, "waiting", "the project owner has not accepted you yet"),
        "cancelled" | "stopped" | "revoked" | "ended" => s(Tone::Muted, Glyph::Stopped, "stopped", "stopped for good; donate again to restart"),
        "refused" => s(Tone::Bad, Glyph::Error, "refused", "the owner refused this donation"),
        other => Status { tone: Tone::Info, glyph: Glyph::Warn, label: clean(other), why: "" },
    }
}

fn badge(t: Theme, d: &Donation) -> Span<'static> {
    let st = status(d);
    w::badge(t, st.tone, t.glyph(st.glyph), &st.label)
}

fn live(d: &Donation) -> bool {
    matches!(d.status.as_str(), "active" | "paused" | "pending")
}

fn visible<'a>(ctx: &Ctx<'a>) -> Vec<&'a Donation> {
    ctx.snap.donations.iter().filter(|d| w::matches(ctx.filter, &[target(d), kind(d), &d.status, &d.schedule, &d.models.join(" ")])).collect()
}

/// What the donation funds: a project path, an org path or a person path (§24).
fn target(d: &Donation) -> &str {
    if d.target.is_empty() { &d.person } else { &d.target }
}

/// `project`, `org` or `person`: shown next to the target so the three never read alike.
fn kind(d: &Donation) -> &'static str {
    if !d.person.is_empty() {
        "person"
    } else if d.org {
        "org"
    } else {
        "project"
    }
}

/// The target's canonical public page (CONTRACT §9, §19.6, §24.6; §22.3 share link) on the public
/// web origin (`Me.web`): `/p/{provider}/{owner}/{name}`, `/org/{provider}/{path}`,
/// `/people/{provider}/{login}`. Display only. `None` when the path is not a plain slug of the
/// right shape (fail closed: never show a confusable link).
fn share_url(web: &str, d: &Donation) -> Option<String> {
    let seg = |x: &str| !x.is_empty() && x != "." && x != ".." && x.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    // m9: the relay names a GitHub project `owner/name` (CONTRACT §9, legacy form).
    let t = target(d);
    let legacy = kind(d) == "project" && t.split('/').count() == 2 && !t.starts_with("github/") && !t.starts_with("gitlab/");
    let path = if legacy { format!("github/{t}") } else { t.to_owned() };
    let parts: Vec<&str> = path.split('/').collect();
    let n = parts.len();
    let shape = match (parts.first().copied(), kind(d)) {
        (Some("github"), "project") => n == 3,
        (Some("gitlab"), "project") => n >= 3,
        (Some("github" | "gitlab"), "person") | (Some("github"), "org") => n == 2,
        (Some("gitlab"), "org") => n >= 2,
        _ => false,
    };
    if !shape || path.len() > 512 || !parts.iter().all(|x| seg(x)) {
        return None;
    }
    let prefix = match kind(d) {
        "person" => "people",
        "org" => "org",
        _ => "p",
    };
    Some(format!("{}/{prefix}/{path}", w::web_origin(web)))
}

/// `(today, this ISO week)` spend from a per-day series that ends today (UTC days, oldest first);
/// the week starts on Monday 00:00 UTC (1970-01-01 was a Thursday).
fn window_spent(per_day: &[u64], now_ms: u64) -> (u64, u64) {
    let since_monday = usize::try_from((now_ms / 86_400_000).saturating_add(3) % 7).unwrap_or(0);
    let today = per_day.last().copied().unwrap_or(0);
    let week = per_day.iter().rev().take(since_monday.saturating_add(1)).fold(0u64, |a, x| a.saturating_add(*x));
    (today, week)
}

impl DonationsView {
    fn detail(&self, t: Theme, d: &Donation, web: &str, now: u64, width: u16) -> Vec<Line<'static>> {
        let st = status(d);
        let mut v = vec![Line::from(vec![Span::styled(format!("{:<10} ", "Status"), t.muted()), badge(t, d), w::muted(t, format!("  {}", st.why))])];
        let mut limit = vec![Span::styled(format!("{:<10} ", "Limit"), t.muted()), Span::raw(format!("{} a month", w::dollars(d.budget_uusd)))];
        for (lim, per) in [(d.weekly_limit_uusd, "week"), (d.daily_limit_uusd, "day")] {
            if lim > 0 {
                limit.push(Span::raw(format!("{}{} a {per}", w::dot(t), w::dollars(lim))));
            }
        }
        if d.per_task_cap_uusd > 0 {
            limit.push(w::muted(t, format!("{}{} per task", w::dot(t), w::dollars(d.per_task_cap_uusd))));
        }
        v.push(Line::from(limit));
        let mut spent = vec![Span::styled(format!("{:<10} ", "Spent"), t.muted()), Span::styled(format!("{:<9}", w::dollars(d.spent_uusd)), t.money())];
        spent.extend(charts::meter(t, d.spent_uusd, d.budget_uusd, 16).spans);
        v.push(Line::from(spent));
        let mut left = w::dollars(d.budget_uusd.saturating_sub(d.spent_uusd));
        if d.weekly_limit_uusd > 0 || d.daily_limit_uusd > 0 {
            use std::fmt::Write as _;
            let (today, week) = window_spent(&d.per_day_uusd, now);
            left.push_str(" this month");
            for (lim, used, per) in [(d.weekly_limit_uusd, week, "this week"), (d.daily_limit_uusd, today, "today")] {
                if lim > 0 {
                    let _ = write!(left, "{}{} {per}", w::dot(t), w::dollars(lim.saturating_sub(used)));
                }
            }
        }
        v.push(w::kv(t, "Left", left));
        // The share link (§22.3) high up, so it is on screen at 80×24.
        if let Some(url) = share_url(web, d) {
            v.push(w::kv_span(t, "Share", Span::styled(url, t.info())));
        }
        if d.per_day_uusd.iter().any(|&x| x > 0) {
            let days = d.per_day_uusd.len().min(30);
            v.push(Line::from(vec![Span::styled(format!("{:<10} ", format!("{days} days")), t.muted()), charts::spark_text(t, &d.per_day_uusd, 30, t.money())]));
        }
        // One line for when it runs and when it starts again.
        let base = if d.schedule.is_empty() { "any time".to_owned() } else { clean(&d.schedule) };
        let sched = if d.renews_at_ms > 0 && live(d) {
            format!("{base}{}renews {} ({})", w::dot(t), w::day_month(d.renews_at_ms), w::until(now, d.renews_at_ms))
        } else {
            base
        };
        v.push(w::kv(t, "Schedule", sched));
        v.push(w::kv(t, "Models", if d.models.is_empty() { "any model you have a key for".to_owned() } else { d.models.iter().map(|m| clean(m)).collect::<Vec<_>>().join(", ") }));
        if d.org || !d.person.is_empty() {
            v.push(Line::default());
            v.push(Line::from(w::bold("Projects funded this month")));
            if d.per_repo_uusd.is_empty() {
                let who = if d.org { "the organisation's projects have" } else { "the repos this person covers have" };
                v.push(Line::from(w::muted(t, format!("  none yet: {who} not used it"))));
            }
            let mut repos: Vec<&(String, u64)> = d.per_repo_uusd.iter().collect();
            repos.sort_by_key(|r| std::cmp::Reverse(r.1));
            let top = repos.first().map_or(0, |r| r.1);
            let name_w = usize::from(width.saturating_sub(26)).clamp(8, 40);
            let drop = w::hosts_dropped(repos.iter().take(MAX_REPOS).map(|r| (r.0.as_str(), name_w)));
            for (name, used) in repos.iter().take(MAX_REPOS) {
                let n = w::trunc(&w::slug(&clean(name), drop), name_w);
                let mut l = vec![Span::styled(format!("  {:>8} ", w::dollars(*used)), t.money())];
                l.extend(charts::bar(t, *used, top, 10, t.money()).spans);
                l.push(Span::raw(format!(" {n}")));
                v.push(Line::from(l));
            }
            if repos.len() > MAX_REPOS {
                v.push(Line::from(w::muted(t, format!("  +{} more", repos.len().saturating_sub(MAX_REPOS)))));
            }
        }
        v.push(Line::raw(""));
        let mut keys = Vec::new();
        match d.status.as_str() {
            "active" => keys.extend([w::key("p"), w::muted(t, " pause  ")]),
            "paused" => keys.extend([w::key("p"), w::muted(t, " resume  ")]),
            _ => {}
        }
        if live(d) {
            keys.extend([w::key("-"), w::muted(t, " lower the limit  "), w::key("x"), w::muted(t, " stop")]);
        }
        if !keys.is_empty() {
            v.push(Line::from(keys));
        }
        if let Some(n) = &self.note {
            v.push(Line::from(w::badge(t, Tone::Warn, t.glyph(Glyph::Warn), n)));
        }
        v
    }
}

impl View for DonationsView {
    fn title(&self) -> &'static str {
        "Donations"
    }

    fn labels(&self) -> (&'static str, &'static str) {
        ("Donations", "Donated")
    }

    fn hints(&self) -> &'static [(&'static str, &'static str)] {
        &[("p", "pause/resume"), ("-", "lower limit"), ("x", "stop")]
    }

    fn render(&mut self, f: &mut Frame, area: Rect, ctx: &Ctx) {
        let t = *ctx.theme;
        if ctx.snap.donations.is_empty() {
            let lines = vec![
                Line::from(w::badge(t, Tone::Warn, t.glyph(Glyph::Coin), "No donations yet")),
                Line::raw(""),
                Line::raw("Donate tokens to a project you use, up to a monthly limit:"),
                Line::from(w::key("moochy donate --repo github/owner/name --cap $20")),
                Line::raw("or to an organisation:"),
                Line::from(w::key("moochy donate --org github/owner --cap $50")),
                Line::raw("or sponsor a maintainer's own tokens:"),
                Line::from(w::key("moochy donate --person github/login --cap $20")),
                Line::raw(""),
                Line::from(w::muted(t, "It starts once the project owner accepts you, and shows up here.")),
            ];
            return w::empty(f, area, t, self.title(), lines);
        }
        let rows = visible(ctx);
        let (list_a, detail) = if rows.is_empty() { (area, None) } else { w::split(area, 14) };
        self.cur.sync(rows.len(), list_a);
        // The month's total is always all donations, filtered or not.
        let total: u64 = ctx.snap.donations.iter().map(|d| d.spent_uusd).fold(0, u64::saturating_add);
        let title = format!("{}{}{} spent this month", w::counted("Donations", rows.len(), ctx.snap.donations.len()), w::dot(t), w::dollars(total));
        if rows.is_empty() {
            w::empty(f, list_a, t, &title, w::no_match(t, ctx.filter));
        } else {
            let wd = list_a.width;
            let mut widths = vec![Constraint::Length(15), Constraint::Min(16), Constraint::Length(17)];
            let mut header = vec!["Status", "Donating to", "Spent / limit"];
            if wd >= 80 {
                widths.push(Constraint::Length(15));
                header.push("Used");
            }
            if wd >= 110 {
                widths.push(Constraint::Length(10));
                header.push("30 days");
            }
            if wd >= 140 {
                widths.push(Constraint::Length(24));
                header.push("Schedule");
            }
            let cw = list::table_widths(list_a, &widths);
            let room = |d: &Donation| cw.get(1).copied().unwrap_or(0).saturating_sub(if kind(d) == "project" { 0 } else { 7 });
            let drop = w::hosts_dropped(rows.iter().map(|d| (target(d), room(d))));
            let body = rows.iter().map(|d| {
                let mut who = Vec::new();
                if kind(d) != "project" {
                    who.push(w::muted(t, format!("{} ", kind(d))));
                }
                who.push(Span::raw(w::slug(&clean(target(d)), drop)));
                let mut cells = vec![
                    Cell::from(badge(t, d)),
                    Cell::from(list::fit(Line::from(who), cw.get(1).copied().unwrap_or(0))),
                    Cell::from(Line::from(vec![Span::styled(w::dollars(d.spent_uusd), t.money()), w::muted(t, format!(" / {}", w::dollars(d.budget_uusd)))])),
                ];
                if wd >= 80 {
                    cells.push(Cell::from(charts::meter(t, d.spent_uusd, d.budget_uusd, 9)));
                }
                if wd >= 110 {
                    cells.push(Cell::from(charts::spark_text(t, &d.per_day_uusd, 10, t.money())));
                }
                if wd >= 140 {
                    let s = if d.schedule.is_empty() { "any time".to_owned() } else { clean(&d.schedule) };
                    cells.push(Cell::from(w::trunc(&s, cw.last().copied().unwrap_or(0))));
                }
                Row::new(cells)
            });
            let table = Table::new(body, widths)
                .header(Row::new(header).style(t.muted()))
                .row_highlight_style(t.selected())
                .highlight_symbol(list::marker(t))
                .block(w::block_focus(t, title));
            f.render_stateful_widget(table, list_a, &mut self.cur.state);
            self.cur.more(f, list_a, t);
        }
        if let (Some(area), Some(d)) = (detail, self.cur.selected().and_then(|i| rows.get(i))) {
            let title = format!("{} {}", kind(d), clean(target(d)));
            let lines = self.detail(t, d, &ctx.snap.me.web, ctx.now_ms, area.width.saturating_sub(2));
            f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }).block(w::block(t, title)), area);
        }
    }

    fn on_input(&mut self, input: &Input, ctx: &Ctx) -> Outcome {
        if self.cur.on_input(input) {
            self.note = None;
            return Outcome::Redraw;
        }
        let rows = visible(ctx);
        let Some(d) = self.cur.selected().and_then(|i| rows.get(i)) else { return Outcome::Ignored };
        if d.id.is_empty() {
            return Outcome::Ignored;
        }
        let name = clean(target(d));
        let id = clean(&d.id);
        let refuse = |me: &mut Self, why: &str| {
            me.note = Some(why.to_owned());
            Outcome::Redraw
        };
        match input {
            Input::Char('p') => match d.status.as_str() {
                "active" => Outcome::Confirm {
                    title: "Pause this donation".into(),
                    body: format!("Pause your donation to {name}? Nothing is served to it until you resume it. Same as `moochy donations pause {id}`."),
                    action: Action::PauseDonation(d.id.clone()),
                },
                "paused" => Outcome::Confirm {
                    title: "Resume this donation".into(),
                    body: format!("Resume your donation to {name}? Your devices serve it again, up to its limit. Same as `moochy donations resume {id}`."),
                    action: Action::ResumeDonation(d.id.clone()),
                },
                _ => refuse(self, "only an active or paused donation can be paused or resumed"),
            },
            Input::Char('x') if live(d) => Outcome::Confirm {
                title: "Stop this donation".into(),
                body: format!("Stop donating to {name} for good? This cannot be undone: donate again to restart. Same as `moochy donations stop {id}`."),
                action: Action::StopDonation(d.id.clone()),
            },
            Input::Char('-') if live(d) => {
                // Between what is already spent (rounded up to the cent) and just under the limit.
                let floor = d.spent_uusd.div_ceil(CENT).max(1).saturating_mul(CENT);
                let ceil = (d.budget_uusd.saturating_sub(1) / CENT).saturating_mul(CENT);
                if floor > ceil {
                    return refuse(self, "nothing left to lower: the limit is already spent; stop it instead (x)");
                }
                self.note = None;
                Outcome::Prompt(Prompt {
                    title: "Lower the limit".into(),
                    body: format!("{name}: {} a month, {} spent so far.", w::dollars(d.budget_uusd), w::dollars(d.spent_uusd)),
                    label: format!("New monthly limit in $ ({} to {})", w::dollars(floor), w::dollars(ceil)),
                    initial: String::new(),
                    max_len: 12,
                    then: Then::LowerLimit { id: d.id.clone(), target: name, budget_uusd: d.budget_uusd, spent_uusd: d.spent_uusd, floor_uusd: floor, ceil_uusd: ceil },
                })
            }
            Input::Char('x' | '-') => refuse(self, "this donation is not running"),
            _ => Outcome::Ignored,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Snapshot;
    use crate::widgets::test_util::{ctx, draw, themes};

    const DOLLAR: u64 = 1_000_000;

    fn snap() -> Snapshot {
        let d = |id: &str, target: &str, status: &str, budget, spent| Donation {
            id: id.into(),
            target: target.into(),
            status: status.into(),
            budget_uusd: budget,
            spent_uusd: spent,
            schedule: "nights".into(),
            models: vec!["claude-sonnet-4".into()],
            ..Donation::default()
        };
        let mut org = d("pl_org", "github/acme", "active", 50 * DOLLAR, 12 * DOLLAR);
        org.org = true;
        org.per_repo_uusd = vec![("github/acme/a".into(), 2 * DOLLAR), ("github/acme/\u{1b}[31mb".into(), 10 * DOLLAR)];
        let mut person = d("m_01J", "", "active", 20 * DOLLAR, 4 * DOLLAR);
        person.person = "github/octocat".into();
        person.per_repo_uusd = vec![("github/octocat/hello".into(), 3 * DOLLAR), ("github/other/lib".into(), DOLLAR)];
        let mut first = d("pl_1", "github/foo/bar", "active", 20 * DOLLAR, 3_100_000);
        first.per_day_uusd = vec![0, 100_000, 300_000, 200_000];
        first.renews_at_ms = crate::widgets::test_util::NOW + 3 * 86_400_000;
        Snapshot {
            me: crate::model::Me { web: "https://moochy.dev".into(), ..crate::model::Me::default() },
            donations: vec![first, d("pl_2", "gitlab/x/y", "paused", 10 * DOLLAR, 0), d("pl_3", "github/done/it", "cancelled", 5 * DOLLAR, 5 * DOLLAR), org, person],
            ..Snapshot::default()
        }
    }

    #[test]
    fn renders_every_size_and_theme() {
        let s = snap();
        for t in themes() {
            for (w, h) in [(80, 24), (160, 48)] {
                let mut v = DonationsView::default();
                let out = draw(&mut v, &ctx(&s, &t, ""), w, h);
                assert!(out.contains("foo/bar"), "{out}");
                assert!(out.contains("active") && out.contains("paused") && out.contains("stopped"), "{out}");
                assert!(out.contains("$3.10 / $20.00"), "{out}");
                assert!(out.contains("pause"), "{out}");
            }
        }
        let t = themes()[0];
        let out = draw(&mut DonationsView::default(), &ctx(&s, &t, ""), 160, 48);
        assert!(out.contains("renews") && out.contains("in 3d") && out.contains("4 days"), "{out}");
        let e = Snapshot::default();
        let out = draw(&mut DonationsView::default(), &ctx(&e, &t, ""), 80, 24);
        assert!(out.contains("No donations yet") && out.contains("moochy donate"), "{out}");
    }

    #[test]
    fn window_spent_today_and_iso_week() {
        const DAY: u64 = 86_400_000;
        let days = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let thu = 1_790_812_800_000; // Thursday 2026-10-01: the week began Monday 2026-09-28
        assert_eq!(window_spent(&days, thu), (10, 8 + 9 + 10 + 7));
        assert_eq!(window_spent(&days, thu + 4 * DAY), (10, 10), "Monday: a new week");
        assert_eq!(window_spent(&days, thu + 3 * DAY + DAY - 1), (10, 7 + 8 + 9 + 10 + 6 + 5 + 4), "Sunday 23:59: the whole week");
        assert_eq!(window_spent(&[], thu), (0, 0));
    }

    #[test]
    fn detail_shows_what_is_left_per_window() {
        let mut s = snap();
        s.donations[0].weekly_limit_uusd = DOLLAR;
        s.donations[0].daily_limit_uusd = DOLLAR / 2;
        let t = themes()[0];
        let out = draw(&mut DonationsView::default(), &ctx(&s, &t, ""), 160, 48);
        // NOW is a Monday: the week so far is today ($0.20).
        assert!(out.contains("$1.00 a week") && out.contains("$0.50 a day"), "{out}");
        assert!(out.contains("$16.90 this month") && out.contains("$0.80 this week") && out.contains("$0.30 today"), "{out}");
    }

    #[test]
    fn org_detail_lists_projects_sanitized() {
        let s = snap();
        let t = themes()[0];
        let mut v = DonationsView::default();
        let c = ctx(&s, &t, "");
        assert_eq!(v.on_input(&Input::End, &c), Outcome::Ignored, "cursor not synced yet");
        draw(&mut v, &c, 160, 48);
        v.cur.select(3);
        let out = draw(&mut v, &c, 160, 48);
        assert!(out.contains("Projects funded this month") && out.contains("acme/\u{FFFD}[31mb") && !out.contains('\u{1b}'), "{out}");
        let big = out.find("acme/\u{FFFD}[31mb").unwrap();
        assert!(big < out.find("acme/a\n").or_else(|| out.find("acme/a ")).unwrap_or(usize::MAX), "biggest spender first");
    }

    #[test]
    fn share_urls_are_canonical_or_absent() {
        let d = |target: &str, org: bool, person: &str| Donation { target: target.into(), org, person: person.into(), ..Donation::default() };
        let u = |web: &str, x: &Donation| share_url(web, x);
        assert_eq!(u("https://moochy.dev", &d("github/foo/bar", false, "")).as_deref(), Some("https://moochy.dev/p/github/foo/bar"));
        assert_eq!(u("https://moochy.dev", &d("foo/bar", false, "")).as_deref(), Some("https://moochy.dev/p/github/foo/bar"), "the relay's owner/name form");
        assert_eq!(u("https://moochy.dev/", &d("gitlab/g/sub/repo", false, "")).as_deref(), Some("https://moochy.dev/p/gitlab/g/sub/repo"));
        assert_eq!(u("moochy.dev:443", &d("github/acme", true, "")).as_deref(), Some("https://moochy.dev/org/github/acme"));
        assert_eq!(u("https://web.test:8443", &d("gitlab/grp/sub", true, "")).as_deref(), Some("https://web.test:8443/org/gitlab/grp/sub"));
        assert_eq!(u("https://moochy.dev", &d("", false, "github/octocat")).as_deref(), Some("https://moochy.dev/people/github/octocat"));
        // A missing or hostile web origin falls back to the canonical site, never to a confusable host.
        assert_eq!(u("", &d("github/foo/bar", false, "")).as_deref(), Some("https://moochy.dev/p/github/foo/bar"));
        assert_eq!(u("evil.dev/\u{1b}[2J", &d("github/foo/bar", false, "")).as_deref(), Some("https://moochy.dev/p/github/foo/bar"));
        // Wrong shapes, hostile bytes, unknown providers: no link at all.
        for x in [
            d("github/acme", false, ""),
            d("github/a/b/c", false, ""),
            d("github/foo/bar", true, ""),
            d("github/../x", false, ""),
            d("github/foo/b\u{1b}]52;c;x\u{7}", false, ""),
            d("bitbucket/foo/bar", false, ""),
            d("", false, "github/a/b"),
        ] {
            assert_eq!(u("https://moochy.dev", &x), None, "{x:?}");
        }
    }

    #[test]
    fn person_sponsorship_reads_like_an_org_donation() {
        let s = snap();
        let t = themes()[0];
        let c = ctx(&s, &t, "");
        let mut v = DonationsView::default();
        draw(&mut v, &c, 80, 24);
        v.on_input(&Input::End, &c);
        for t in themes() {
            let out = draw(&mut v, &ctx(&s, &t, ""), 160, 48);
            assert!(out.contains("person github/octocat") && out.contains("Projects funded this month") && out.contains("octocat/hello"), "{out}");
            assert!(out.contains("https://moochy.dev/people/github/octocat"), "{out}");
        }
        let Outcome::Confirm { action, body, .. } = v.on_input(&Input::Char('p'), &c) else { panic!() };
        assert_eq!(action, Action::PauseDonation("m_01J".into()));
        assert!(body.contains("github/octocat"));
        assert!(matches!(v.on_input(&Input::Char('-'), &c), Outcome::Prompt(_)));
        let Outcome::Confirm { action, .. } = v.on_input(&Input::Char('x'), &c) else { panic!() };
        assert_eq!(action, Action::StopDonation("m_01J".into()));
        let out = draw(&mut v, &ctx(&s, &t, "octo"), 80, 24);
        assert!(out.contains("person") && !out.contains("foo/bar"), "{out}");
    }

    #[test]
    fn actions_follow_status_and_confirm() {
        let s = snap();
        let t = themes()[0];
        let c = ctx(&s, &t, "");
        let mut v = DonationsView::default();
        draw(&mut v, &c, 80, 24);
        let Outcome::Confirm { action, .. } = v.on_input(&Input::Char('p'), &c) else { panic!() };
        assert_eq!(action, Action::PauseDonation("pl_1".into()));
        v.on_input(&Input::Down, &c);
        let Outcome::Confirm { action, .. } = v.on_input(&Input::Char('p'), &c) else { panic!() };
        assert_eq!(action, Action::ResumeDonation("pl_2".into()));
        v.on_input(&Input::Down, &c);
        assert_eq!(v.on_input(&Input::Char('x'), &c), Outcome::Redraw); // stopped: refused with a note
        assert!(draw(&mut v, &c, 160, 48).contains("not running"));
        v.on_input(&Input::Home, &c);
        let Outcome::Confirm { action, body, .. } = v.on_input(&Input::Char('x'), &c) else { panic!() };
        assert_eq!(action, Action::StopDonation("pl_1".into()));
        assert!(body.contains("github/foo/bar"));
    }

    #[test]
    fn lower_is_bounded_by_spent_and_limit() {
        let s = snap();
        let t = themes()[0];
        let c = ctx(&s, &t, "");
        let mut v = DonationsView::default();
        draw(&mut v, &c, 80, 24);
        let Outcome::Prompt(p) = v.on_input(&Input::Char('-'), &c) else { panic!() };
        assert!(p.label.contains("$3.10 to $19.99"), "{}", p.label);
        assert!(p.then.submit("20").is_err(), "never at or above the current limit");
        assert!(p.then.submit("3").is_err(), "never below what is spent");
        let Ok(Outcome::Confirm { action, .. }) = p.then.submit("12.50") else { panic!() };
        assert_eq!(action, Action::LowerDonation { id: "pl_1".into(), budget_uusd: 12_500_000 });
    }

    #[test]
    fn filter_narrows_and_says_so() {
        let s = snap();
        let t = themes()[0];
        let mut v = DonationsView::default();
        let out = draw(&mut v, &ctx(&s, &t, "gitlab"), 80, 24);
        assert!(out.contains("gitlab/x/y") && !out.contains("foo/bar"), "{out}");
        let out = draw(&mut v, &ctx(&s, &t, "zzz"), 80, 24);
        assert!(out.contains("Nothing matches") && out.contains("zzz"), "{out}");
    }
}
