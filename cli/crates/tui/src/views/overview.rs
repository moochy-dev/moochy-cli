//! The Overview tab (CONTRACT §20.2): the hamster, this month's donations and use, live requests,
//! devices online, what needs the user (pending decisions, alerts) and the latest requests. Every
//! panel is a door: click it (or its key) to open its tab.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};

use super::{Command, Ctx, Input, Outcome, View};
use crate::sanitize::clean;
use crate::theme::{Glyph, Theme};
use crate::widgets::{self as w, charts};

const TAB_DONATIONS: usize = 1;
const TAB_SERVED: usize = 2;
const TAB_PROJECTS: usize = 3;
const TAB_DECISIONS: usize = 5;
const TAB_DEVICES: usize = 6;
const TAB_ACTIVITY: usize = 7;

/// Requests in the last 5 minutes count as live.
const LIVE_MS: u64 = 5 * 60_000;
/// The tiles' trend always covers this many days, resampled into the tile's width.
const TREND_DAYS: usize = 30;

#[derive(Default)]
pub struct OverviewView {
    /// Panel rects from the last render → the tab a click opens.
    doors: Vec<(Rect, usize)>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mood {
    Calm,
    Happy,
    Sleepy,
}

impl View for OverviewView {
    fn title(&self) -> &'static str {
        "Overview"
    }

    fn labels(&self) -> (&'static str, &'static str) {
        ("Overview", "Home")
    }

    fn hints(&self) -> &'static [(&'static str, &'static str)] {
        &[("d", "donations"), ("v", "live"), ("n", "decisions"), ("a", "activity")]
    }

    fn render(&mut self, f: &mut Frame, area: Rect, ctx: &Ctx) {
        self.doors.clear();
        let s = ctx.snap;
        if s.donations.is_empty() && s.projects.is_empty() && s.served.is_empty() && s.pending.is_empty() {
            return render_welcome(f, area, ctx);
        }
        let top_h = if area.height >= 30 { 8 } else { 7 };
        // The middle panels take what their content needs (at most a third); the feed takes the rest.
        let need = s.donations.len().max(s.pending.len().saturating_add(s.alerts.len())).max(1) as u16;
        let mid_h = need.saturating_add(2).clamp(5, (area.height / 3).max(5));
        let [top, mid, bottom] = Layout::vertical([Constraint::Length(top_h), Constraint::Length(mid_h), Constraint::Fill(1)]).areas(area);

        // Top: hamster card + KPI tiles. Narrow: 2 tiles, and devices + live fold into the card.
        let wide = area.width >= 120;
        let [card, tiles] = Layout::horizontal([Constraint::Length(if wide { 36 } else { 32 }), Constraint::Fill(1)]).areas(top);
        render_card(f, card, ctx, !wide);
        self.doors.push((card, TAB_DECISIONS));
        let n = if wide { 4 } else { 2 };
        let tile_rects = Layout::horizontal(vec![Constraint::Fill(1); n]).split(tiles);
        let mut tr = tile_rects.iter().copied();
        if let Some(r) = tr.next() {
            let spent: u64 = s.donations.iter().map(|d| d.spent_uusd).sum();
            let budget: u64 = s.donations.iter().filter(|d| d.status != "stopped").map(|d| d.budget_uusd).sum();
            tile_money(f, r, ctx, "Donated this month", &s.donated_per_day_uusd, spent, budget, ctx.theme.money());
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

        let [left, right] = Layout::horizontal([Constraint::Percentage(55), Constraint::Percentage(45)]).areas(mid);
        render_meters(f, left, ctx);
        self.doors.push((left, TAB_DONATIONS));
        render_needs(f, right, ctx);
        self.doors.push((right, TAB_DECISIONS));

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
            Input::Click { col, row } => self.doors.iter().find(|(r, _)| r.contains((*col, *row).into())).map_or(Outcome::Ignored, |(_, t)| go(*t)),
            _ => Outcome::Ignored,
        }
    }
}

/// All devices online ●, some ▲ (degraded is attention, not healthy), none ○.
fn fleet(on: usize, all: usize) -> Glyph {
    match on {
        0 => Glyph::Offline,
        n if n >= all => Glyph::Online,
        _ => Glyph::Warn,
    }
}

fn mood(ctx: &Ctx) -> Mood {
    if !ctx.snap.me.connected {
        Mood::Sleepy
    } else if ctx.snap.served.iter().any(|r| ctx.now_ms.saturating_sub(r.at_ms) < 60_000) {
        Mood::Happy
    } else {
        Mood::Calm
    }
}

/// Moochy, drawn with the header mark's vocabulary (◖ ◗ cheeks, a •ᴗ• face) at hero size, with
/// an ASCII twin: mint outline, blush cheeks, the face follows the state.
fn hamster(t: Theme, m: Mood) -> Vec<Line<'static>> {
    let fur = Style::default().fg(t.mint());
    let cheek = Style::default().fg(t.blush()).add_modifier(Modifier::BOLD);
    let face = t.bold();
    let (eye, mouth) = match (m, t.ascii) {
        (Mood::Calm, false) => ("•", "ᴗ"),
        (Mood::Happy, false) => ("^", "ᴗ"),
        (Mood::Sleepy, false) => ("-", "ᴗ"),
        (Mood::Calm, true) => ("o", "."),
        (Mood::Happy, true) => ("^", "."),
        (Mood::Sleepy, true) => ("-", "."),
    };
    let (ears, top, bottom, l, r) = if t.ascii {
        ("  ()     ()  ", " /---------\\ ", " \\_________/ ", "(", ")")
    } else {
        ("  ╭╮     ╭╮  ", " ╭┴┴─────┴┴╮ ", " ╰─────────╯ ", "◖", "◗")
    };
    vec![
        Line::styled(ears, fur),
        Line::styled(top, fur),
        Line::from(vec![
            Span::styled(l, cheek),
            Span::styled(format!("  {eye}  "), face),
            Span::styled(mouth, face),
            Span::styled(format!("  {eye}  "), face),
            Span::styled(r, cheek),
        ]),
        Line::styled(bottom, fur),
    ]
}

fn live_counts(ctx: &Ctx) -> (usize, usize, u64) {
    let recent: Vec<_> = ctx.snap.served.iter().filter(|r| ctx.now_ms.saturating_sub(r.at_ms) < LIVE_MS).collect();
    let served = recent.iter().filter(|r| r.direction == "served").count();
    let lat = recent.iter().map(|r| r.latency_ms).sum::<u64>().checked_div(recent.len() as u64).unwrap_or(0);
    (served, recent.len().saturating_sub(served), lat)
}

fn render_card(f: &mut Frame, area: Rect, ctx: &Ctx, fold: bool) {
    let t = *ctx.theme;
    let s = ctx.snap;
    let b = w::block(t, "moochy");
    let inner = b.inner(area);
    f.render_widget(b, area);
    let [art, _, text] = Layout::horizontal([Constraint::Length(13), Constraint::Length(1), Constraint::Fill(1)]).areas(inner);
    f.render_widget(Paragraph::new(hamster(t, mood(ctx))), art);
    let tw = usize::from(text.width);
    let handle = clean(s.me.handle.trim_start_matches('@'));
    let mut lines = vec![Line::from(vec![Span::raw("Hi "), Span::styled(w::trunc(&format!("@{handle}"), tw.saturating_sub(3)), t.accent())])];
    let p = s.pending.len();
    lines.push(if p > 0 {
        Line::from(vec![Span::styled(format!("{} ", t.glyph(Glyph::Pending)), t.warn()), Span::raw(format!("{p} to decide"))])
    } else {
        Line::from(vec![Span::styled(format!("{} ", t.glyph(Glyph::Ok)), t.ok()), Span::raw("all decided")])
    });
    if fold {
        let on = s.devices.iter().filter(|d| d.online).count();
        let g = fleet(on, s.devices.len());
        lines.push(Line::from(vec![Span::styled(format!("{} ", t.glyph(g)), t.glyph_style(g)), Span::raw(format!("{on}/{} online", s.devices.len()))]));
        let (sv, us, _) = live_counts(ctx);
        lines.push(Line::from(vec![
            Span::styled(format!("{}{sv} ", t.glyph(Glyph::Served)), t.money()),
            Span::styled(format!("{}{us} ", t.glyph(Glyph::Used)), t.ok()),
            w::muted(t, "live"),
        ]));
    } else {
        lines.push(if s.me.connected {
            Line::from(vec![Span::styled(format!("{} ", t.glyph(Glyph::Online)), t.ok()), Span::raw("relay up")])
        } else {
            Line::from(vec![Span::styled(format!("{} ", t.glyph(Glyph::Offline)), t.err()), Span::raw("relay down")])
        });
        if !s.me.roles.is_empty() {
            let roles = s.me.roles.iter().map(|r| clean(r)).collect::<Vec<_>>().join(" + ");
            lines.push(Line::from(w::muted(t, w::trunc(&roles, tw))));
        }
    }
    f.render_widget(Paragraph::new(lines), text);
}

#[allow(clippy::too_many_arguments)]
fn tile_money(f: &mut Frame, area: Rect, ctx: &Ctx, title: &str, per_day: &[u64], value: u64, of: u64, style: Style) {
    let t = *ctx.theme;
    let b = w::block(t, title);
    let inner = b.inner(area);
    f.render_widget(b, area);
    let [num, spark, cap] = Layout::vertical([Constraint::Length(1), Constraint::Fill(1), Constraint::Length(1)]).areas(inner);
    let mut l = vec![Span::styled(format!("{} ", t.glyph(Glyph::Coin)), style), Span::styled(w::dollars(value), style.add_modifier(Modifier::BOLD))];
    if of > 0 {
        l.push(w::muted(t, format!(" of {}", w::dollars(of))));
    }
    f.render_widget(Paragraph::new(w::list::fit(Line::from(l), usize::from(num.width))), num);
    // Always the last 30 days, spread over the whole width (the period never depends on it).
    let days = per_day.get(per_day.len().saturating_sub(TREND_DAYS)..).unwrap_or_default();
    let data = charts::floor_zeros(charts::resample(days, usize::from(spark.width)));
    f.render_widget(charts::sparkline(t, &data, style), spark);
    let caption = if days.is_empty() { "no data yet".to_string() } else { format!("last {TREND_DAYS} days") };
    f.render_widget(Paragraph::new(Line::from(w::muted(t, caption))), cap);
}

fn tile_live(f: &mut Frame, area: Rect, ctx: &Ctx) {
    let t = *ctx.theme;
    let b = w::block(t, "Live · 5 min");
    let inner = b.inner(area);
    f.render_widget(b, area);
    let (served, used, lat) = live_counts(ctx);
    let lines = vec![
        Line::from(vec![Span::styled(format!("{} ", served.saturating_add(used)), t.accent()), Span::raw("requests")]),
        Line::from(vec![
            Span::styled(format!("{} {served} ", t.glyph(Glyph::Served)), t.money()),
            w::muted(t, "served  "),
            Span::styled(format!("{} {used} ", t.glyph(Glyph::Used)), t.ok()),
            w::muted(t, "used"),
        ]),
        Line::from(vec![w::muted(t, "avg "), Span::raw(if served.saturating_add(used) == 0 { "—".into() } else { w::latency(lat) })]),
    ];
    f.render_widget(Paragraph::new(lines), inner);
}

fn tile_devices(f: &mut Frame, area: Rect, ctx: &Ctx) {
    let t = *ctx.theme;
    let s = ctx.snap;
    let b = w::block(t, "Devices");
    let inner = b.inner(area);
    f.render_widget(b, area);
    let on = s.devices.iter().filter(|d| d.online).count();
    let boxes = s.boxes.iter().filter(|b| b.online).count();
    let keys = s.keys.iter().filter(|k| k.present).count();
    let g = fleet(on, s.devices.len());
    let lines = vec![
        Line::from(vec![Span::styled(format!("{} ", t.glyph(g)), t.glyph_style(g)), Span::raw(format!("{on}/{} online", s.devices.len()))]),
        Line::from(vec![Span::styled(format!("{} ", t.glyph(Glyph::Online)), t.info()), Span::raw(format!("{boxes}/{} boxes up", s.boxes.len()))]),
        Line::from(vec![Span::styled(format!("{} ", t.glyph(Glyph::Ok)), t.ok()), Span::raw(format!("{keys}/{} provider keys", s.keys.len()))]),
    ];
    f.render_widget(Paragraph::new(lines), inner);
}

fn render_meters(f: &mut Frame, area: Rect, ctx: &Ctx) {
    let t = *ctx.theme;
    let b = w::block(t, "My donations this month");
    let inner = b.inner(area);
    f.render_widget(b, area);
    if ctx.snap.donations.is_empty() {
        let msg = Line::from(vec![w::muted(t, "No donations yet. "), w::key("moochy donate"), w::muted(t, " gives tokens to a project.")]);
        f.render_widget(Paragraph::new(msg).wrap(Wrap { trim: true }), inner);
        return;
    }
    let name_w = usize::from((inner.width / 5).saturating_mul(2).clamp(14, 34)).saturating_sub(3);
    let mut lines = Vec::new();
    let shown: Vec<_> = ctx.snap.donations.iter().take(usize::from(inner.height)).collect();
    let names: Vec<String> = shown.iter().map(|d| clean(if d.target.is_empty() { &d.person } else { &d.target })).collect();
    let drop = w::hosts_dropped(names.iter().map(|n| (n.as_str(), name_w)));
    for (d, n) in shown.into_iter().zip(&names) {
        let g = w::status_glyph(&d.status);
        let name = w::trunc(&w::slug(n, drop), name_w);
        let money = format!(" {:>8}", w::dollars(d.spent_uusd));
        let meter_w = usize::from(inner.width).saturating_sub(name_w).saturating_sub(3).saturating_sub(money.len());
        let mut l = vec![Span::styled(format!("{} ", t.glyph(g)), t.glyph_style(g)), Span::raw(format!("{name:<name_w$} "))];
        if d.status == "stopped" || d.status == "paused" {
            l.push(Span::styled(format!("{:<meter_w$}", clean(&d.status)), t.glyph_style(g)));
        } else {
            l.extend(charts::meter(t, d.spent_uusd, d.budget_uusd, meter_w.saturating_sub(5) as u16).spans);
        }
        l.push(Span::styled(money, t.money()));
        lines.push(Line::from(l));
    }
    f.render_widget(Paragraph::new(lines), inner);
}

fn render_needs(f: &mut Frame, area: Rect, ctx: &Ctx) {
    let t = *ctx.theme;
    let s = ctx.snap;
    let b = w::block(t, "Needs you");
    let inner = b.inner(area);
    f.render_widget(b, area);
    let wd = usize::from(inner.width);
    let mut lines = Vec::new();
    let room_of = |p: &crate::model::Pending| {
        let subject = w::trunc(&clean(&p.subject), wd.saturating_sub(8).min(24));
        wd.saturating_sub(subject.chars().count()).saturating_sub(w::ago(ctx.now_ms, p.created_at_ms).len()).saturating_sub(6)
    };
    let targets: Vec<String> = s.pending.iter().map(|p| clean(&p.target)).collect();
    let drop = w::hosts_dropped(targets.iter().zip(&s.pending).map(|(t, p)| (t.as_str(), room_of(p))));
    for p in &s.pending {
        let when = w::ago(ctx.now_ms, p.created_at_ms);
        let subject = w::trunc(&clean(&p.subject), wd.saturating_sub(8).min(24));
        let room = room_of(p);
        let arrow = if t.ascii { "->" } else { "→" };
        lines.push(Line::from(vec![
            Span::styled(format!("{} ", t.glyph(Glyph::Pending)), t.warn()),
            Span::styled(subject, t.bold()),
            w::muted(t, format!(" {arrow} {} ", w::trunc(&w::slug(&clean(&p.target), drop), room))),
            w::muted(t, when),
        ]));
    }
    for a in &s.alerts {
        let g = if a.level == "error" { Glyph::Error } else { Glyph::Warn };
        lines.push(Line::from(vec![Span::styled(format!("{} ", t.glyph(g)), t.glyph_style(g)), Span::raw(w::trunc(&clean(&a.text), wd.saturating_sub(2)))]));
    }
    if lines.is_empty() {
        lines.push(Line::from(vec![Span::styled(format!("{} ", t.glyph(Glyph::Ok)), t.ok()), w::muted(t, "Nothing waits for you.")]));
    }
    f.render_widget(Paragraph::new(lines), inner);
}

/// The latest requests as a small table with a header, the project column taking what is left.
fn render_live(f: &mut Frame, area: Rect, ctx: &Ctx) {
    let t = *ctx.theme;
    let b = w::block(t, "Latest requests");
    let inner = b.inner(area);
    f.render_widget(b, area);
    if ctx.snap.served.is_empty() {
        f.render_widget(Paragraph::new(Line::from(w::muted(t, "No requests yet. They show up here the second they run."))), inner);
        return;
    }
    let wide = inner.width >= 90;
    let fixed: usize = if wide { 65 } else { 46 };
    let proj_w = usize::from(inner.width).saturating_sub(fixed).max(8);
    let mut head = format!("{:>4}  {:<4}{:<21}{:<proj_w$}{:>7}{:>8}", "Age", "", "Model", "Project", "Tokens", "Cost");
    if wide {
        head.push_str("  Latency  Outcome");
    }
    let mut lines = vec![Line::styled(head, t.muted().add_modifier(Modifier::BOLD))];
    let mut rows: Vec<_> = ctx.snap.served.iter().collect();
    rows.sort_by_key(|r| std::cmp::Reverse(r.at_ms));
    rows.truncate(usize::from(inner.height.saturating_sub(1)));
    let drop = w::hosts_dropped(rows.iter().map(|r| (r.project.as_str(), proj_w.saturating_sub(1))));
    for r in rows {
        let (dg, ds) = if r.direction == "served" { (Glyph::Served, t.money()) } else { (Glyph::Used, t.ok()) };
        let og = w::status_glyph(&r.outcome);
        let project = w::trunc(&w::slug(&clean(&r.project), drop), proj_w.saturating_sub(1));
        let mut l = vec![
            w::muted(t, format!("{:>4}  ", w::ago(ctx.now_ms, r.at_ms))),
            Span::styled(format!("{} ", t.glyph(dg)), ds),
            Span::styled(format!("{} ", t.glyph(og)), t.glyph_style(og)),
            Span::raw(format!("{:<21}", w::trunc(&clean(&r.model), 20))),
            w::muted(t, format!("{project:<proj_w$}")),
            Span::raw(format!("{:>7}", w::tokens(r.tokens_in.saturating_add(r.tokens_out)))),
            Span::styled(format!("{:>8}", w::dollars(r.cost_uusd)), t.money()),
        ];
        if wide {
            l.push(w::muted(t, format!("  {:>7}  ", w::latency(r.latency_ms))));
            l.push(Span::styled(clean(&r.outcome), t.glyph_style(og)));
        }
        let l = Line::from(l);
        lines.push(if r.at_ms > ctx.fresh_ms { l.style(t.accent()) } else { l });
    }
    f.render_widget(Paragraph::new(lines), inner);
}

fn render_welcome(f: &mut Frame, area: Rect, ctx: &Ctx) {
    let t = *ctx.theme;
    let mut lines = w::align_block(hamster(t, mood(ctx)));
    lines.extend([Line::raw(""), Line::styled("Nothing here yet — let's change that.", t.accent()), Line::raw("")]);
    // One block, centred as a whole: the label column lines up.
    lines.extend(w::align_block(vec![
        Line::from(vec![Span::styled("Donate    ", t.money()), w::key("moochy donate --repo github/owner/name --cap $20")]),
        Line::from(vec![Span::styled("Maintain  ", t.ok()), w::key("moochy claim github/you/repo")]),
        Line::from(vec![Span::styled("Learn     ", t.info()), Span::raw(format!("{}/docs", w::web_origin(&ctx.snap.me.web)))]),
    ]));
    w::empty(f, area, t, "Welcome", lines);
}
