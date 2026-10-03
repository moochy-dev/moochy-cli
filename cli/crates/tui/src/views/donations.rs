//! The Donations tab (CONTRACT §20.2): my donations with status, limit vs spent, schedule and
//! models; pause/resume, stop and lower the limit, each behind a confirmation; per-project spend
//! for organisation donations. Owner: mo-tui-donor.

use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table, Wrap};

use super::donor_kit::{self as k, Cursor, Tone};
use super::{Ctx, Input, Outcome, View};
use crate::model::Donation;
use crate::sanitize::clean;
use crate::source::Action;
use crate::theme::Theme;
use crate::widgets::dollars;

const CENT: u64 = 10_000;
const DOLLAR: u64 = 1_000_000;
/// Org donations: projects listed in the detail pane before "+N more".
const MAX_REPOS: usize = 6;

#[derive(Default)]
pub struct DonationsView {
    cur: Cursor,
    lower: Option<Lower>,
    note: Option<String>,
}

/// The "lower the limit" editor: whole-dollar steps between what is already spent and just under
/// the current limit.
struct Lower {
    id: String,
    target: String,
    budget: u64,
    spent: u64,
    floor: u64,
    ceil: u64,
    value: u64,
}

struct Status {
    tone: Tone,
    glyph: &'static str,
    label: String,
    why: &'static str,
}

fn status(t: &Theme, d: &Donation) -> Status {
    let s = |tone, uni, ascii, label: &str, why| Status { tone, glyph: k::g(t, uni, ascii), label: label.to_owned(), why };
    match d.status.as_str() {
        "active" if d.budget_uusd > 0 && d.spent_uusd >= d.budget_uusd => {
            s(Tone::Warn, "◆", "!", "limit reached", "its monthly limit is used up; it starts again next month")
        }
        "active" => s(Tone::Good, "●", "*", "active", "your devices serve it, up to the limit"),
        "paused" => s(Tone::Warn, "‖", "=", "paused", "nothing is served until you resume it"),
        "pending" => s(Tone::Info, "…", "~", "waiting", "the project owner has not accepted you yet"),
        "cancelled" | "stopped" | "revoked" | "ended" => s(Tone::Muted, "■", "x", "stopped", "stopped for good; donate again to restart"),
        "refused" => s(Tone::Bad, "✗", "x", "refused", "the owner refused this donation"),
        other => Status { tone: Tone::Info, glyph: "?", label: clean(other), why: "" },
    }
}

fn live(d: &Donation) -> bool {
    matches!(d.status.as_str(), "active" | "paused" | "pending")
}

fn visible<'a>(ctx: &Ctx<'a>) -> Vec<&'a Donation> {
    ctx.snap.donations.iter().filter(|d| k::matches(ctx.filter, &[&d.target, &d.status, &d.schedule, &d.models.join(" ")])).collect()
}

impl DonationsView {
    fn detail(&self, t: &Theme, d: &Donation) -> Vec<Line<'static>> {
        let st = status(t, d);
        let label = |s: &str| k::dim(format!("{s:<9}"));
        let mut v = vec![Line::from(vec![label("Status"), k::badge(t, st.tone, st.glyph, &st.label), k::dim(format!("  {}", st.why))])];
        let mut limit = vec![label("Limit"), Span::raw(format!("{} a month", dollars(d.budget_uusd)))];
        if d.per_task_cap_uusd > 0 {
            limit.push(k::dim(format!("{}{} per task", k::dot(t), dollars(d.per_task_cap_uusd))));
        }
        v.push(Line::from(limit));
        let mut spent = vec![label("Spent"), Span::raw(format!("{:<9}", dollars(d.spent_uusd)))];
        spent.extend(k::gauge(t, d.spent_uusd, d.budget_uusd, 16).spans);
        v.push(Line::from(spent));
        v.push(Line::from(vec![label("Left"), Span::raw(dollars(d.budget_uusd.saturating_sub(d.spent_uusd)))]));
        let sched = if d.schedule.is_empty() { "any time".to_owned() } else { clean(&d.schedule) };
        v.push(Line::from(vec![label("Schedule"), Span::raw(sched)]));
        let models = if d.models.is_empty() { "any model you have a key for".to_owned() } else { d.models.iter().map(|m| clean(m)).collect::<Vec<_>>().join(", ") };
        v.push(Line::from(vec![label("Models"), Span::raw(models)]));
        if d.org {
            v.push(Line::from(k::dim("Projects funded this month")));
            if d.per_repo_uusd.is_empty() {
                v.push(Line::from(k::dim("  none yet: the organisation's projects have not used it")));
            }
            let mut repos: Vec<&(String, u64)> = d.per_repo_uusd.iter().collect();
            repos.sort_by(|a, b| b.1.cmp(&a.1));
            let top = repos.first().map_or(0, |r| r.1);
            for (name, used) in repos.iter().take(MAX_REPOS) {
                let mut l = vec![Span::raw(format!("  {:<9}", dollars(*used)))];
                l.extend(k::gauge(t, *used, top, 8).spans.into_iter().take(2));
                l.push(Span::raw(format!(" {}", clean(name))));
                v.push(Line::from(l));
            }
            if repos.len() > MAX_REPOS {
                v.push(Line::from(k::dim(format!("  +{} more", repos.len().saturating_sub(MAX_REPOS)))));
            }
        }
        v.push(Line::raw(""));
        if let Some(lw) = &self.lower {
            let mut l = vec![k::badge(t, Tone::Info, k::g(t, "▼", "v"), "New limit"), Span::raw(format!(" {} a month ", dollars(lw.value)))];
            l.extend(k::gauge(t, lw.spent, lw.value, 10).spans);
            v.push(Line::from(l));
            v.push(Line::from(vec![
                k::key(k::g(t, "↑↓", "up/down")),
                k::dim(" $1  "),
                k::key("PgUp/PgDn"),
                k::dim(" $10  "),
                k::key("Enter"),
                k::dim(" confirm  "),
                k::key("Esc"),
                k::dim(" cancel"),
            ]));
        } else {
            let mut keys = Vec::new();
            match d.status.as_str() {
                "active" => keys.extend([k::key("p"), k::dim(" pause  ")]),
                "paused" => keys.extend([k::key("p"), k::dim(" resume  ")]),
                _ => {}
            }
            if live(d) {
                keys.extend([k::key("-"), k::dim(" lower the limit  "), k::key("x"), k::dim(" stop")]);
            }
            if !keys.is_empty() {
                v.push(Line::from(keys));
            }
        }
        if let Some(n) = &self.note {
            v.push(Line::from(k::badge(t, Tone::Warn, "!", n)));
        }
        v
    }

    fn on_lower(&mut self, input: &Input) -> Outcome {
        let Some(lw) = &mut self.lower else { return Outcome::Ignored };
        let step = |up: bool, by: u64| if up { lw.value.saturating_add(by) } else { lw.value.saturating_sub(by) };
        let next = match input {
            Input::Up | Input::Char('k') | Input::ScrollUp => step(true, DOLLAR),
            Input::Down | Input::Char('j') | Input::ScrollDown => step(false, DOLLAR),
            Input::PageUp => step(true, DOLLAR.saturating_mul(10)),
            Input::PageDown => step(false, DOLLAR.saturating_mul(10)),
            Input::Home => lw.ceil,
            Input::End => lw.floor,
            Input::Back => {
                self.lower = None;
                return Outcome::Redraw;
            }
            Input::Enter => {
                let body = format!(
                    "Lower the limit for {} from {} to {} a month? Already spent this month: {}.",
                    clean(&lw.target),
                    dollars(lw.budget),
                    dollars(lw.value),
                    dollars(lw.spent)
                );
                let action = Action::LowerDonation { id: lw.id.clone(), budget_uusd: lw.value };
                self.lower = None;
                return Outcome::Confirm { title: "Lower the limit".into(), body, action };
            }
            _ => return Outcome::Ignored,
        };
        lw.value = next.clamp(lw.floor, lw.ceil);
        Outcome::Redraw
    }
}

impl View for DonationsView {
    fn title(&self) -> &'static str {
        "Donations"
    }

    fn hints(&self) -> &'static [(&'static str, &'static str)] {
        &[("j/k", "move"), ("p", "pause/resume"), ("-", "lower limit"), ("x", "stop"), ("/", "filter")]
    }

    fn render(&mut self, f: &mut Frame, area: Rect, ctx: &Ctx) {
        let t = ctx.theme;
        if ctx.snap.donations.is_empty() {
            let lines = vec![
                Line::from(k::badge(t, Tone::Warn, k::g(t, "☀", "*"), "No donations yet")),
                Line::raw(""),
                Line::raw("Donate tokens to a project you use, up to a monthly limit:"),
                Line::from(k::key("moochy donate --repo github/owner/name --cap $20")),
                Line::raw("or to an organisation:"),
                Line::from(k::key("moochy donate --org github/owner --cap $50")),
                Line::raw(""),
                Line::from(k::dim("It starts once the project owner accepts you, and shows up here.")),
            ];
            return k::empty(f, area, t, self.title(), lines);
        }
        let rows = visible(ctx);
        let (list, detail) = k::split(area, 13);
        self.cur.sync(rows.len(), list);
        let total: u64 = rows.iter().map(|d| d.spent_uusd).fold(0, u64::saturating_add);
        let title = format!(" Donations ({}){}{} spent this month ", rows.len(), k::dot(t), dollars(total));
        if rows.is_empty() {
            let lines = vec![Line::raw(format!("No donation matches /{}", clean(ctx.filter))), Line::from(k::dim("Esc clears the filter"))];
            k::empty(f, list, t, title.trim(), lines);
        } else {
            let w = list.width;
            let mut widths = vec![Constraint::Length(15), Constraint::Min(14), Constraint::Length(17)];
            let mut header = vec!["Status", "Donating to", "Spent / limit"];
            if w >= 80 {
                widths.push(Constraint::Length(15));
                header.push("Used");
            }
            if w >= 104 {
                widths.push(Constraint::Length(12));
                header.push("Schedule");
            }
            let body = rows.iter().map(|d| {
                let st = status(t, d);
                let mut target = Vec::new();
                if d.org {
                    target.push(k::dim("org "));
                }
                target.push(Span::raw(clean(&d.target)));
                let mut cells = vec![
                    Cell::from(k::badge(t, st.tone, st.glyph, &st.label)),
                    Cell::from(Line::from(target)),
                    Cell::from(format!("{} / {}", dollars(d.spent_uusd), dollars(d.budget_uusd))),
                ];
                if w >= 80 {
                    cells.push(Cell::from(k::gauge(t, d.spent_uusd, d.budget_uusd, 9)));
                }
                if w >= 104 {
                    cells.push(Cell::from(if d.schedule.is_empty() { "any time".to_owned() } else { clean(&d.schedule) }));
                }
                Row::new(cells)
            });
            let table = Table::new(body, widths)
                .header(Row::new(header).style(k::tone(t, Tone::Muted)))
                .row_highlight_style(k::selected(t))
                .highlight_symbol(k::arrow(t))
                .block(k::block(t, title));
            f.render_stateful_widget(table, list, &mut self.cur.state);
        }
        if let (Some(area), Some(d)) = (detail, self.cur.selected().and_then(|i| rows.get(i))) {
            let title = format!(" {}{} ", if d.org { "org " } else { "" }, clean(&d.target));
            f.render_widget(Paragraph::new(self.detail(t, d)).wrap(Wrap { trim: false }).block(k::block(t, title)), area);
        }
    }

    fn on_input(&mut self, input: &Input, ctx: &Ctx) -> Outcome {
        if self.lower.is_some() {
            return self.on_lower(input);
        }
        if self.cur.on_input(input) {
            self.note = None;
            return Outcome::Redraw;
        }
        let rows = visible(ctx);
        let Some(d) = self.cur.selected().and_then(|i| rows.get(i)) else { return Outcome::Ignored };
        if d.id.is_empty() {
            return Outcome::Ignored;
        }
        let target = clean(&d.target);
        let id = clean(&d.id);
        let refuse = |me: &mut Self, why: &str| {
            me.note = Some(why.to_owned());
            Outcome::Redraw
        };
        match input {
            Input::Char('p') => match d.status.as_str() {
                "active" => Outcome::Confirm {
                    title: "Pause this donation".into(),
                    body: format!("Pause your donation to {target}? Nothing is served to it until you resume it. Same as `moochy donations pause {id}`."),
                    action: Action::PauseDonation(d.id.clone()),
                },
                "paused" => Outcome::Confirm {
                    title: "Resume this donation".into(),
                    body: format!("Resume your donation to {target}? Your devices serve it again, up to its limit. Same as `moochy donations resume {id}`."),
                    action: Action::ResumeDonation(d.id.clone()),
                },
                _ => refuse(self, "only an active or paused donation can be paused or resumed"),
            },
            Input::Char('x') if live(d) => Outcome::Confirm {
                title: "Stop this donation".into(),
                body: format!("Stop donating to {target} for good? This cannot be undone: donate again to restart. Same as `moochy donations stop {id}`."),
                action: Action::StopDonation(d.id.clone()),
            },
            Input::Char('x') => refuse(self, "this donation is not running"),
            Input::Char('-') if live(d) => {
                let floor = d.spent_uusd.div_ceil(CENT).max(1).saturating_mul(CENT);
                let ceil = (d.budget_uusd.saturating_sub(1) / CENT).saturating_mul(CENT);
                if floor > ceil {
                    return refuse(self, "nothing left to lower: the limit is already spent; stop it instead (x)");
                }
                let whole = (ceil / DOLLAR).saturating_mul(DOLLAR);
                let value = if whole >= floor { whole } else { ceil };
                self.lower = Some(Lower { id: d.id.clone(), target: d.target.clone(), budget: d.budget_uusd, spent: d.spent_uusd, floor, ceil, value });
                self.note = None;
                Outcome::Redraw
            }
            Input::Char('-') => refuse(self, "this donation is not running"),
            _ => Outcome::Ignored,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Snapshot;
    use crate::views::donor_kit::test_util::{ctx, draw, themes};

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
        Snapshot {
            donations: vec![
                d("pl_1", "github/foo/bar", "active", 20 * DOLLAR, 3_100_000),
                d("pl_2", "gitlab/x/y", "paused", 10 * DOLLAR, 0),
                d("pl_3", "github/done/it", "cancelled", 5 * DOLLAR, 5 * DOLLAR),
                org,
            ],
            ..Snapshot::default()
        }
    }

    #[test]
    fn renders_every_size_and_theme() {
        let s = snap();
        for t in themes() {
            for (w, h) in [(80, 24), (160, 48)] {
                let mut v = DonationsView::default();
                let out = draw(&mut v, &s, &t, "", w, h);
                assert!(out.contains("github/foo/bar"), "{out}");
                assert!(out.contains("active") && out.contains("paused") && out.contains("stopped"), "{out}");
                assert!(out.contains("$3.10 / $20.00"), "{out}");
                assert!(out.contains("pause"), "{out}");
            }
        }
        let mut v = DonationsView::default();
        let out = draw(&mut v, &Snapshot::default(), &themes()[0], "", 80, 24);
        assert!(out.contains("No donations yet") && out.contains("moochy donate"), "{out}");
    }

    #[test]
    fn org_detail_lists_projects_sanitized() {
        let s = snap();
        let t = themes()[0];
        let mut v = DonationsView::default();
        let c = ctx(&s, &t);
        assert_eq!(v.on_input(&Input::End, &c), Outcome::Ignored, "cursor not synced yet");
        draw(&mut v, &s, &t, "", 160, 48);
        v.on_input(&Input::End, &c);
        let out = draw(&mut v, &s, &t, "", 160, 48);
        assert!(out.contains("Projects funded this month") && out.contains("github/acme/\u{FFFD}[31mb"), "{out}");
        let b = out.find("[31mb").unwrap();
        assert!(b < out.find("github/acme/a ").unwrap_or(usize::MAX), "biggest spender first");
    }

    #[test]
    fn actions_follow_status_and_confirm() {
        let s = snap();
        let t = themes()[0];
        let c = ctx(&s, &t);
        let mut v = DonationsView::default();
        draw(&mut v, &s, &t, "", 80, 24);
        let Outcome::Confirm { action, .. } = v.on_input(&Input::Char('p'), &c) else { panic!() };
        assert_eq!(action, Action::PauseDonation("pl_1".into()));
        v.on_input(&Input::Down, &c);
        let Outcome::Confirm { action, .. } = v.on_input(&Input::Char('p'), &c) else { panic!() };
        assert_eq!(action, Action::ResumeDonation("pl_2".into()));
        v.on_input(&Input::Down, &c);
        assert_eq!(v.on_input(&Input::Char('x'), &c), Outcome::Redraw); // stopped: refused with a note
        assert!(draw(&mut v, &s, &t, "", 80, 24).contains("not running"));
        v.on_input(&Input::Home, &c);
        let Outcome::Confirm { action, body, .. } = v.on_input(&Input::Char('x'), &c) else { panic!() };
        assert_eq!(action, Action::StopDonation("pl_1".into()));
        assert!(body.contains("github/foo/bar"));
    }

    #[test]
    fn lower_is_bounded_by_spent_and_limit() {
        let s = snap();
        let t = themes()[0];
        let c = ctx(&s, &t);
        let mut v = DonationsView::default();
        draw(&mut v, &s, &t, "", 80, 24);
        assert_eq!(v.on_input(&Input::Char('-'), &c), Outcome::Redraw);
        assert!(draw(&mut v, &s, &t, "", 80, 24).contains("New limit"));
        assert_eq!(v.lower.as_ref().unwrap().value, 19 * DOLLAR);
        v.on_input(&Input::Up, &c);
        assert_eq!(v.lower.as_ref().unwrap().value, 19_990_000, "never above the current limit");
        for _ in 0..5 {
            v.on_input(&Input::PageDown, &c);
        }
        assert_eq!(v.lower.as_ref().unwrap().value, 3_100_000, "never below what is spent");
        let Outcome::Confirm { action, .. } = v.on_input(&Input::Enter, &c) else { panic!() };
        assert_eq!(action, Action::LowerDonation { id: "pl_1".into(), budget_uusd: 3_100_000 });
        assert!(v.lower.is_none());
        v.on_input(&Input::Char('-'), &c);
        assert_eq!(v.on_input(&Input::Back, &c), Outcome::Redraw);
        assert!(v.lower.is_none());
    }

    #[test]
    fn filter_narrows_and_says_so() {
        let s = snap();
        let t = themes()[0];
        let mut v = DonationsView::default();
        let out = draw(&mut v, &s, &t, "gitlab", 80, 24);
        assert!(out.contains("gitlab/x/y") && !out.contains("github/foo/bar"), "{out}");
        let out = draw(&mut v, &s, &t, "zzz", 80, 24);
        assert!(out.contains("No donation matches /zzz"), "{out}");
    }
}
