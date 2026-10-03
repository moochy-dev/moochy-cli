//! The Overview tab (CONTRACT §20.2): the hamster, this month's donations and use, live requests,
//! devices, what needs the user (pending decisions, alerts) and the latest requests. Every panel
//! is a door: click it (or its key) to open its tab. Owner: mo-tui.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph, Wrap};

use super::{Command, Ctx, Input, Outcome, View};
use crate::sanitize::clean;
use crate::theme::{Glyph, Theme};
use crate::widgets::{ago, charts, dollars, latency, short_slug, status_glyph, tokens, trunc};

const TAB_DONATIONS: usize = 1;
const TAB_SERVED: usize = 2;
const TAB_PROJECTS: usize = 3;
const TAB_DECISIONS: usize = 5;
const TAB_DEVICES: usize = 6;
const TAB_ACTIVITY: usize = 7;

/// Requests in the last 5 minutes count as live.
const LIVE_MS: u64 = 5 * 60_000;

#[derive(Default)]
pub struct OverviewView {
    /// Panel rects from the last render → the tab a click opens.
    doors: Vec<(Rect, usize)>,
}

impl View for OverviewView {
    fn title(&self) -> &'static str {
        "Overview"
    }

    fn hints(&self) -> &'static [(&'static str, &'static str)] {
        &[("d", "donations"), ("v", "live"), ("n", "decisions"), ("a", "activity")]
    }

    fn render(&mut self, f: &mut Frame, area: Rect, ctx: &Ctx) {
        self.doors.clear();
        let s = ctx.snap;
        if s.donations.is_empty() && s.projects.is_empty() && s.served.is_empty() && s.pending.is_empty() {
            render_welcome(f, area, ctx);
            return;
        }
        let top_h = if area.height >= 30 { 9 } else { 7 };
        // The middle panels take what their content needs (at most a third); the feed takes the rest.
        let need = s.donations.len().max(s.pending.len().saturating_add(s.alerts.len())).max(1) as u16;
        let mid_h = need.saturating_add(2).clamp(5, (area.height / 3).max(5));
        let [top, mid, bottom] = Layout::vertical([Constraint::Length(top_h), Constraint::Length(mid_h), Constraint::Fill(1)]).areas(area);

        // Top: hamster card + KPI tiles (2 at 80 columns, 4 when wide).
        let wide = area.width >= 120;
        let card_w = if wide { 36 } else { 30 };
        let [card, tiles] = Layout::horizontal([Constraint::Length(card_w), Constraint::Fill(1)]).areas(top);
        render_card(f, card, ctx);
        self.doors.push((card, TAB_DECISIONS));
        let n = if wide { 4 } else { 2 };
        let tile_rects = Layout::horizontal(vec![Constraint::Fill(1); n]).split(tiles);
        let mut tr = tile_rects.iter().copied();
        if let Some(r) = tr.next() {
            tile_money(f, r, ctx, "Donated", &s.donated_per_day_uusd, donated_month(ctx), budget(ctx), ctx.theme.money());
            self.doors.push((r, TAB_DONATIONS));
        }
        if let Some(r) = tr.next() {
            let used: u64 = s.projects.iter().map(|p| p.month_uusd).sum();
            let goal: u64 = s.projects.iter().map(|p| p.goal_uusd).sum();
            tile_money(f, r, ctx, "Used by my projects", &s.used_per_day_uusd, used, goal, ctx.theme.ok());
            self.doors.push((r, TAB_PROJECTS));
        }
        if let Some(r) = tr.next() {
            tile_live(f, r, ctx);
            self.doors.push((r, TAB_SERVED));
        }
        if let Some(r) = tr.next() {
            tile_devices(f, r, ctx);
            self.doors.push((r, TAB_DEVICES));
        }

        // Middle: donation meters | needs you.
        let [left, right] = Layout::horizontal([Constraint::Percentage(55), Constraint::Percentage(45)]).areas(mid);
        render_meters(f, left, ctx);
        self.doors.push((left, TAB_DONATIONS));
        render_needs(f, right, ctx);
        self.doors.push((right, TAB_DECISIONS));

        // Bottom: latest requests.
        render_live(f, bottom, ctx);
        self.doors.push((bottom, TAB_SERVED));
    }

    fn on_input(&mut self, input: &Input, _ctx: &Ctx) -> Outcome {
        let go = |t| Outcome::Command(Command::GoTo(t));
        match input {
            Input::Char('d') => go(TAB_DONATIONS),
            Input::Char('v') => go(TAB_SERVED),
            Input::Char('n') => go(TAB_DECISIONS),
            Input::Char('a') => go(TAB_ACTIVITY),
            Input::Click { col, row } => {
                self.doors.iter().find(|(r, _)| r.contains((*col, *row).into())).map_or(Outcome::Ignored, |(_, t)| go(*t))
            }
            _ => Outcome::Ignored,
        }
    }
}

fn block<'a>(th: &Theme, title: &str) -> Block<'a> {
    crate::widgets::block(*th, title)
}

fn donated_month(ctx: &Ctx) -> u64 {
    ctx.snap.donations.iter().map(|d| d.spent_uusd).sum()
}

fn budget(ctx: &Ctx) -> u64 {
    ctx.snap.donations.iter().filter(|d| d.status != "stopped").map(|d| d.budget_uusd).sum()
}

/// The mascot, drawn in ASCII so it is the same in every mode; the face follows the state.
fn hamster<'a>(th: &Theme, eyes: &'a str) -> Vec<Line<'a>> {
    let fur = Style::default().fg(th.mint());
    let cheek = Style::default().fg(th.blush());
    vec![
        Line::styled(r#" (\.-"""-./) "#, fur),
        Line::from(vec![Span::styled("  / ", fur), Span::styled(eyes, th.bold()), Span::styled(" \\  ", fur)]),
        Line::from(vec![Span::styled(" ( ", fur), Span::styled(" =", cheek), Span::styled(r"\_/", fur), Span::styled("= ", cheek), Span::styled(" ) ", fur)]),
        Line::styled(r"  \  ___  /  ", fur),
        Line::styled(r#"   "-' '-"   "#, fur),
    ]
}

fn render_card(f: &mut Frame, area: Rect, ctx: &Ctx) {
    let th = ctx.theme;
    let s = ctx.snap;
    let b = block(th, "moochy");
    let inner = b.inner(area);
    f.render_widget(b, area);
    let live = s.served.iter().any(|r| ctx.now_ms.saturating_sub(r.at_ms) < 60_000);
    let eyes = if !s.me.connected {
        "-   -"
    } else if live {
        "^   ^"
    } else {
        "o   o"
    };
    let [art, text] = Layout::horizontal([Constraint::Length(13), Constraint::Fill(1)]).areas(inner);
    f.render_widget(Paragraph::new(hamster(th, eyes)), art);
    let handle = clean(s.me.handle.trim_start_matches('@'));
    let mut lines = vec![Line::from(vec![Span::raw("Hi "), Span::styled(format!("@{handle}"), th.accent())])];
    let p = s.pending.len();
    lines.push(if p > 0 {
        Line::from(vec![Span::styled(format!("{} ", th.glyph(Glyph::Pending)), th.warn()), Span::raw(format!("{p} to decide"))])
    } else {
        Line::from(vec![Span::styled(format!("{} ", th.glyph(Glyph::Ok)), th.ok()), Span::raw("all decided")])
    });
    lines.push(if s.me.connected {
        Line::from(vec![Span::styled(format!("{} ", th.glyph(Glyph::Online)), th.ok()), Span::raw("relay up")])
    } else {
        Line::from(vec![Span::styled(format!("{} ", th.glyph(Glyph::Offline)), th.err()), Span::raw("relay down")])
    });
    if !s.me.roles.is_empty() {
        let roles = s.me.roles.iter().map(|r| clean(r)).collect::<Vec<_>>().join(" + ");
        lines.push(Line::styled(trunc(&roles, usize::from(text.width)), th.muted()));
    }
    f.render_widget(Paragraph::new(lines), text);
}

#[allow(clippy::too_many_arguments)]
fn tile_money(f: &mut Frame, area: Rect, ctx: &Ctx, title: &str, per_day: &[u64], value: u64, of: u64, style: Style) {
    let th = ctx.theme;
    let b = block(th, title);
    let inner = b.inner(area);
    f.render_widget(b, area);
    let [num, spark] = Layout::vertical([Constraint::Length(1), Constraint::Fill(1)]).areas(inner);
    let mut l = vec![Span::styled(format!("{} ", th.glyph(Glyph::Coin)), style), Span::styled(dollars(value), style.add_modifier(ratatui::style::Modifier::BOLD))];
    if of > 0 {
        l.push(Span::styled(format!(" of {}", dollars(of)), th.muted()));
    }
    f.render_widget(Paragraph::new(Line::from(l)), num);
    // The last days that fit, newest on the right; a caption under it when there is room.
    let w = usize::from(spark.width);
    let data = per_day.get(per_day.len().saturating_sub(w)..).unwrap_or_default();
    if spark.height >= 3 {
        let [g, cap] = Layout::vertical([Constraint::Fill(1), Constraint::Length(1)]).areas(spark);
        f.render_widget(charts::sparkline(*th, data, style), g);
        f.render_widget(Paragraph::new(Line::styled(format!("last {} days", data.len()), th.muted())), cap);
    } else {
        f.render_widget(charts::sparkline(*th, data, style), spark);
    }
}

fn tile_live(f: &mut Frame, area: Rect, ctx: &Ctx) {
    let th = ctx.theme;
    let b = block(th, "Live · 5 min");
    let inner = b.inner(area);
    f.render_widget(b, area);
    let recent: Vec<_> = ctx.snap.served.iter().filter(|r| ctx.now_ms.saturating_sub(r.at_ms) < LIVE_MS).collect();
    let served = recent.iter().filter(|r| r.direction == "served").count();
    let used = recent.len().saturating_sub(served);
    let lat = recent.iter().map(|r| r.latency_ms).sum::<u64>().checked_div(recent.len() as u64).unwrap_or(0);
    let lines = vec![
        Line::from(vec![Span::styled(format!("{} ", recent.len()), th.accent()), Span::raw("requests")]),
        Line::from(vec![Span::styled(format!("{} {served} ", th.glyph(Glyph::Served)), th.money()), Span::styled("served  ", th.muted()), Span::styled(format!("{} {used} ", th.glyph(Glyph::Used)), th.ok()), Span::styled("used", th.muted())]),
        Line::from(vec![Span::styled("avg ", th.muted()), Span::raw(if recent.is_empty() { "—".into() } else { latency(lat) })]),
    ];
    f.render_widget(Paragraph::new(lines), inner);
}

fn tile_devices(f: &mut Frame, area: Rect, ctx: &Ctx) {
    let th = ctx.theme;
    let s = ctx.snap;
    let b = block(th, "Devices");
    let inner = b.inner(area);
    f.render_widget(b, area);
    let on = s.devices.iter().filter(|d| d.online).count();
    let boxes = s.boxes.iter().filter(|b| b.online).count();
    let keys = s.keys.iter().filter(|k| k.present).count();
    let g = |ok: bool| if ok { (th.glyph(Glyph::Online), th.ok()) } else { (th.glyph(Glyph::Offline), th.warn()) };
    let (g1, s1) = g(on == s.devices.len());
    let lines = vec![
        Line::from(vec![Span::styled(format!("{g1} "), s1), Span::raw(format!("{on}/{} online", s.devices.len()))]),
        Line::from(vec![Span::styled(format!("{} ", th.glyph(Glyph::Online)), th.info()), Span::raw(format!("{boxes}/{} boxes up", s.boxes.len()))]),
        Line::from(vec![Span::styled(format!("{} ", th.glyph(Glyph::Ok)), th.ok()), Span::raw(format!("{keys}/{} provider keys", s.keys.len()))]),
    ];
    f.render_widget(Paragraph::new(lines), inner);
}

fn render_meters(f: &mut Frame, area: Rect, ctx: &Ctx) {
    let th = ctx.theme;
    let b = block(th, "My donations this month");
    let inner = b.inner(area);
    f.render_widget(b, area);
    if ctx.snap.donations.is_empty() {
        f.render_widget(Paragraph::new(Line::styled("No donations yet. `moochy donate github/owner/repo` gives tokens to a project.", th.muted())).wrap(Wrap { trim: true }), inner);
        return;
    }
    let name_w = (inner.width / 5).saturating_mul(2).clamp(14, 34);
    let mut lines = Vec::new();
    for d in ctx.snap.donations.iter().take(usize::from(inner.height)) {
        let g = status_glyph(&d.status);
        let name = trunc(&short_slug(&clean(&d.target), usize::from(name_w.saturating_sub(3))), usize::from(name_w.saturating_sub(3)));
        let mut l = vec![Span::styled(format!("{} ", th.glyph(g)), th.glyph_style(g)), Span::raw(format!("{name:<w$}", w = usize::from(name_w.saturating_sub(2))))];
        let money = format!(" {}", dollars(d.spent_uusd));
        let meter_w = inner.width.saturating_sub(name_w).saturating_sub(money.len() as u16).saturating_sub(1);
        if d.status == "stopped" || d.status == "paused" {
            l.push(Span::styled(format!("{:<w$}", clean(&d.status), w = usize::from(meter_w)), th.glyph_style(g)));
        } else {
            l.extend(charts::meter(*th, d.spent_uusd, d.budget_uusd, meter_w).spans);
        }
        l.push(Span::styled(money, th.money()));
        lines.push(Line::from(l));
    }
    f.render_widget(Paragraph::new(lines), inner);
}

fn render_needs(f: &mut Frame, area: Rect, ctx: &Ctx) {
    let th = ctx.theme;
    let s = ctx.snap;
    let b = block(th, "Needs you");
    let inner = b.inner(area);
    f.render_widget(b, area);
    let mut lines = Vec::new();
    let w = usize::from(inner.width);
    for p in &s.pending {
        let when = ago(ctx.now_ms, p.created_at_ms);
        let subject = trunc(&clean(&p.subject), w.saturating_sub(8).min(24));
        let room = w.saturating_sub(subject.chars().count()).saturating_sub(when.len()).saturating_sub(6);
        lines.push(Line::from(vec![
            Span::styled(format!("{} ", th.glyph(Glyph::Pending)), th.warn()),
            Span::styled(subject, th.bold()),
            Span::styled(format!(" → {} ", trunc(&short_slug(&clean(&p.target), room), room)), th.muted()),
            Span::styled(when, th.muted()),
        ]));
    }
    for a in &s.alerts {
        let g = if a.level == "error" { Glyph::Error } else { Glyph::Warn };
        lines.push(Line::from(vec![Span::styled(format!("{} ", th.glyph(g)), th.glyph_style(g)), Span::raw(trunc(&clean(&a.text), w.saturating_sub(2)))]));
    }
    if lines.is_empty() {
        lines.push(Line::from(vec![Span::styled(format!("{} ", th.glyph(Glyph::Ok)), th.ok()), Span::styled("Nothing waits for you.", th.muted())]));
    }
    f.render_widget(Paragraph::new(lines), inner);
}

fn render_live(f: &mut Frame, area: Rect, ctx: &Ctx) {
    let th = ctx.theme;
    let b = block(th, "Latest requests");
    let inner = b.inner(area);
    f.render_widget(b, area);
    if ctx.snap.served.is_empty() {
        f.render_widget(Paragraph::new(Line::styled("No requests yet. They show up here the second they run.", th.muted())), inner);
        return;
    }
    let wide = inner.width >= 100;
    let mut rows: Vec<_> = ctx.snap.served.iter().collect();
    rows.sort_by_key(|r| std::cmp::Reverse(r.at_ms));
    let lines: Vec<Line> = rows
        .into_iter()
        .take(usize::from(inner.height))
        .map(|r| {
            let (dg, ds) = if r.direction == "served" { (Glyph::Served, th.money()) } else { (Glyph::Used, th.ok()) };
            let og = status_glyph(&r.outcome);
            let mut l = vec![
                Span::styled(format!("{:>4} ", ago(ctx.now_ms, r.at_ms)), th.muted()),
                Span::styled(format!("{} ", th.glyph(dg)), ds),
                Span::styled(format!("{} ", th.glyph(og)), th.glyph_style(og)),
                Span::raw(format!("{:<20} ", trunc(&clean(&r.model), 20))),
                Span::styled(format!("{:<26} ", trunc(&short_slug(&clean(&r.project), 26), 26)), th.muted()),
                Span::raw(format!("{:>6} ", tokens(r.tokens_in.saturating_add(r.tokens_out)))),
                Span::styled(format!("{:>7}", dollars(r.cost_uusd)), th.money()),
            ];
            if wide {
                l.push(Span::styled(format!("  {:>6}  ", latency(r.latency_ms)), th.muted()));
                l.push(Span::styled(clean(&r.outcome), th.glyph_style(og)));
            }
            Line::from(l)
        })
        .collect();
    f.render_widget(Paragraph::new(lines), inner);
}


fn render_welcome(f: &mut Frame, area: Rect, ctx: &Ctx) {
    let th = ctx.theme;
    let b = block(th, "Welcome");
    let inner = b.inner(area);
    f.render_widget(b, area);
    let mut lines = hamster(th, "o   o");
    lines.push(Line::raw(""));
    lines.push(Line::styled("Nothing here yet — let's change that.", th.accent()));
    lines.push(Line::raw(""));
    lines.push(Line::from(vec![Span::styled("Donate  ", th.money()), Span::raw("moochy donate github/owner/repo")]));
    lines.push(Line::from(vec![Span::styled("Maintain ", th.ok()), Span::raw("moochy claim github/you/repo")]));
    lines.push(Line::from(vec![Span::styled("Learn   ", th.info()), Span::raw("https://moochy.dev/docs")]));
    f.render_widget(Paragraph::new(lines).centered(), inner);
}
