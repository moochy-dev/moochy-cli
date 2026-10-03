//! The Served tab (CONTRACT §20.2): live requests my devices serve and the ones my projects use —
//! model, project, tokens, cost, latency, outcome — newest first (or sorted with `s`), filterable
//! with `/`, under a per-minute sparkline.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table, Wrap};

use super::{Ctx, Input, Outcome, View};
use crate::model::Served;
use crate::sanitize::clean;
use crate::theme::{Glyph, Theme};
use crate::widgets::{self as w, TableCursor, Tone, charts, list};

const MINUTE_MS: u64 = 60_000;
/// The sparkline covers at most this many minutes (one column each).
const MAX_MINUTES: u16 = 60;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Sort {
    #[default]
    Newest,
    Cost,
    Latency,
    Tokens,
}

impl Sort {
    fn next(self) -> Sort {
        match self {
            Sort::Newest => Sort::Cost,
            Sort::Cost => Sort::Latency,
            Sort::Latency => Sort::Tokens,
            Sort::Tokens => Sort::Newest,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Sort::Newest => "newest",
            Sort::Cost => "cost",
            Sort::Latency => "latency",
            Sort::Tokens => "tokens",
        }
    }
}

#[derive(Default)]
pub struct ServedView {
    cur: TableCursor,
    /// `at_ms` of the selected row once the user moved off the newest one: new rows then no longer
    /// move the selection. `None` follows the stream.
    anchor: Option<u64>,
    sort: Sort,
}

fn visible<'a>(ctx: &Ctx<'a>, sort: Sort) -> Vec<&'a Served> {
    let mut v: Vec<&Served> = ctx.snap.served.iter().filter(|s| w::matches(ctx.filter, &[&s.project, &s.model, &s.direction, &s.outcome])).collect();
    match sort {
        Sort::Newest => v.sort_by_key(|s| std::cmp::Reverse(s.at_ms)),
        Sort::Cost => v.sort_by_key(|s| std::cmp::Reverse((s.cost_uusd, s.at_ms))),
        Sort::Latency => v.sort_by_key(|s| std::cmp::Reverse((s.latency_ms, s.at_ms))),
        Sort::Tokens => v.sort_by_key(|s| std::cmp::Reverse((s.tokens_in.saturating_add(s.tokens_out), s.at_ms))),
    }
    v
}

fn direction(t: Theme, s: &Served) -> Span<'static> {
    match s.direction.as_str() {
        "served" => w::badge(t, Tone::Warn, t.glyph(Glyph::Served), "served"),
        "used" => w::badge(t, Tone::Info, t.glyph(Glyph::Used), "used"),
        other => w::badge(t, Tone::Muted, "?", &clean(other)),
    }
}

fn outcome(t: Theme, s: &Served) -> Span<'static> {
    if s.outcome.is_empty() { w::badge(t, Tone::Info, t.glyph(Glyph::Pending), "running") } else { w::status(t, &s.outcome) }
}

fn failed(o: &str) -> bool {
    w::status_glyph(o) == Glyph::Error
}

impl ServedView {
    fn summary(t: Theme, rows: &[&Served], now: u64, minutes: u16) -> (Line<'static>, Vec<u64>) {
        let mut buckets = vec![0u64; usize::from(minutes)];
        let (mut served, mut used, mut failures, mut uusd) = (0u64, 0u64, 0u64, 0u64);
        let mut lat = Vec::new();
        for s in rows {
            let age = now.saturating_sub(s.at_ms) / MINUTE_MS;
            let Some(i) = usize::try_from(age).ok().and_then(|a| usize::from(minutes).checked_sub(a)?.checked_sub(1)) else { continue };
            if let Some(b) = buckets.get_mut(i) {
                *b = b.saturating_add(1);
            }
            match s.direction.as_str() {
                "served" => served = served.saturating_add(1),
                "used" => used = used.saturating_add(1),
                _ => {}
            }
            if failed(&s.outcome) {
                failures = failures.saturating_add(1);
            }
            uusd = uusd.saturating_add(s.cost_uusd);
            lat.push(s.latency_ms);
        }
        let dot = || w::muted(t, w::dot(t));
        let line = if lat.is_empty() {
            Line::from(w::muted(t, format!("Quiet: nothing in the last {minutes} min")))
        } else {
            lat.sort_unstable();
            let p50 = lat.get(lat.len() / 2).copied().unwrap_or(0);
            let mut l = vec![
                w::badge(t, Tone::Warn, t.glyph(Glyph::Served), &format!("{served} served")),
                dot(),
                w::badge(t, Tone::Info, t.glyph(Glyph::Used), &format!("{used} used")),
                dot(),
                Span::styled(w::cost(uusd), t.money()),
                dot(),
                Span::raw(format!("p50 {}", w::latency(p50))),
            ];
            if failures > 0 {
                l.extend([dot(), w::badge(t, Tone::Bad, t.glyph(Glyph::Error), &format!("{failures} failed"))]);
            }
            Line::from(l)
        };
        (line, buckets)
    }

    fn detail(t: Theme, s: &Served, now: u64) -> Vec<Line<'static>> {
        let why = match s.direction.as_str() {
            "served" => "  a device of yours answered it with your key",
            "used" => "  a project of yours used donated tokens",
            _ => "",
        };
        vec![
            w::kv(t, "When", format!("{} ({} UTC)", w::ago_long(now, s.at_ms), w::datetime(s.at_ms))),
            Line::from(vec![Span::styled(format!("{:<10} ", "Kind"), t.muted()), direction(t, s), w::muted(t, why)]),
            w::kv(t, "Project", clean(&s.project)),
            w::kv(t, "Model", clean(&s.model)),
            w::kv(t, "Tokens", format!("{} in{}{} out", w::tokens(s.tokens_in), w::dot(t), w::tokens(s.tokens_out))),
            w::kv_span(t, "Cost", Span::styled(w::cost(s.cost_uusd), t.money())),
            w::kv(t, "Latency", w::latency(s.latency_ms)),
            w::kv_span(t, "Outcome", outcome(t, s)),
        ]
    }
}

impl View for ServedView {
    fn title(&self) -> &'static str {
        "Served"
    }

    fn hints(&self) -> &'static [(&'static str, &'static str)] {
        &[("g", "newest (live)"), ("s", "sort")]
    }

    fn render(&mut self, f: &mut Frame, area: Rect, ctx: &Ctx) {
        let t = *ctx.theme;
        if ctx.snap.served.is_empty() {
            let lines = vec![
                Line::from(w::badge(t, Tone::Info, t.glyph(Glyph::Connecting), "Nothing served or used yet")),
                Line::raw(""),
                Line::raw("Your devices serve your donations while the app runs:"),
                Line::from(w::key("moochy up")),
                Line::raw("Your projects use donated tokens through your coding agent:"),
                Line::from(w::key("moochy run -- <agent>")),
                Line::raw(""),
                Line::from(w::muted(t, "Requests show up here live, newest first (never prompts or outputs).")),
            ];
            return w::empty(f, area, t, self.title(), lines);
        }
        let rows = visible(ctx, self.sort);
        if let Some(at) = self.anchor
            && let Some(i) = rows.iter().position(|s| s.at_ms == at)
        {
            self.cur.select(i);
        }
        let [top, rest] = Layout::vertical([Constraint::Length(5), Constraint::Min(0)]).areas(area);
        let minutes = top.width.saturating_sub(2).clamp(1, MAX_MINUTES);
        let (line, buckets) = Self::summary(t, &rows, ctx.now_ms, minutes);
        let spark_block = w::block(t, format!("Last {minutes} min"));
        let inner = spark_block.inner(top);
        f.render_widget(spark_block, top);
        let [l1, l2] = Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).areas(inner);
        f.render_widget(Paragraph::new(list::fit(line, usize::from(l1.width))), l1);
        // Right-aligned: the last column is the current minute.
        let wd = minutes.min(l2.width);
        f.render_widget(charts::sparkline(t, &buckets, t.money()), Rect { x: l2.x.saturating_add(l2.width.saturating_sub(wd)), width: wd, ..l2 });

        let (list_a, detail) = w::split(rest, 10);
        self.cur.sync(rows.len(), list_a);
        let mode = match (self.sort, self.anchor) {
            (Sort::Newest, None) => "live".to_string(),
            (Sort::Newest, Some(_)) => "held, g: newest".to_string(),
            (s, _) => format!("by {}", s.label()),
        };
        let title = format!("{} · {mode}", w::counted("Requests", rows.len(), ctx.snap.served.len()));
        if rows.is_empty() {
            return w::empty(f, list_a, t, &title, w::no_match(t, ctx.filter));
        }
        let wide = list_a.width >= 100;
        let mut widths = vec![Constraint::Length(4), Constraint::Length(8), Constraint::Min(10), Constraint::Min(10)];
        let mut header = vec!["Age", "Kind", "Project", "Model"];
        if wide {
            widths.push(Constraint::Length(13));
            header.push("Tokens in/out");
        }
        widths.push(Constraint::Length(9));
        header.push("Cost");
        if wide {
            widths.push(Constraint::Length(7));
            header.push("Latency");
        }
        widths.push(Constraint::Length(11));
        header.push("Outcome");
        let cw = list::table_widths(list_a, &widths);
        let cut = |s: String, i: usize| Cell::from(w::trunc(&s, cw.get(i).copied().unwrap_or(0)));
        let body = rows.iter().map(|s| {
            let mut cells = vec![
                Cell::from(w::muted(t, w::ago(ctx.now_ms, s.at_ms))),
                Cell::from(direction(t, s)),
                cut(w::short_slug(&clean(&s.project), cw.get(2).copied().unwrap_or(0)), 2),
                cut(clean(&s.model), 3),
            ];
            if wide {
                cells.push(Cell::from(format!("{} {} {}", w::tokens(s.tokens_in), if t.ascii { ">" } else { "→" }, w::tokens(s.tokens_out))));
            }
            cells.push(Cell::from(Span::styled(w::cost(s.cost_uusd), t.money())));
            if wide {
                cells.push(Cell::from(w::latency(s.latency_ms)));
            }
            cells.push(Cell::from(outcome(t, s)));
            Row::new(cells)
        });
        let table = Table::new(body, widths)
            .header(Row::new(header).style(t.muted()))
            .row_highlight_style(t.selected())
            .highlight_symbol(list::marker(t))
            .block(w::block_focus(t, title));
        f.render_stateful_widget(table, list_a, &mut self.cur.state);
        if let (Some(area), Some(s)) = (detail, self.cur.selected().and_then(|i| rows.get(i))) {
            f.render_widget(Paragraph::new(Self::detail(t, s, ctx.now_ms)).wrap(Wrap { trim: false }).block(w::block(t, "Request")), area);
        }
    }

    fn on_input(&mut self, input: &Input, ctx: &Ctx) -> Outcome {
        if *input == Input::Char('s') {
            self.sort = self.sort.next();
            self.anchor = None;
            self.cur.select(0);
            return Outcome::Redraw;
        }
        if !self.cur.on_input(input) {
            return Outcome::Ignored;
        }
        self.anchor = match self.cur.selected() {
            Some(0) | None => None,
            Some(i) => visible(ctx, self.sort).get(i).map(|s| s.at_ms),
        };
        Outcome::Redraw
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Snapshot;
    use crate::widgets::test_util::{NOW, ctx, draw, themes};

    fn row(ago_s: u64, dir: &str, project: &str, model: &str, outcome: &str) -> Served {
        Served {
            at_ms: NOW - ago_s * 1000,
            direction: dir.into(),
            project: project.into(),
            model: model.into(),
            tokens_in: 12_345,
            tokens_out: 678,
            cost_uusd: 12_300,
            latency_ms: 820,
            outcome: outcome.into(),
        }
    }

    fn snap() -> Snapshot {
        Snapshot {
            served: vec![
                row(300, "used", "github/me/tool", "gpt-5", "ok"),
                row(5, "served", "github/foo/bar", "claude-sonnet-4", "ok"),
                row(90, "served", "github/foo/bar", "claude-\u{1b}]52;c;eA==\u{7}opus", "timeout"),
                row(7200, "served", "github/old/one", "deepseek-chat", "ok"),
            ],
            ..Snapshot::default()
        }
    }

    #[test]
    fn renders_newest_first_with_sparkline() {
        let s = snap();
        for t in themes() {
            for (w, h) in [(80, 24), (160, 48)] {
                let mut v = ServedView::default();
                let out = draw(&mut v, &ctx(&s, &t, ""), w, h);
                let first = out.find("foo/bar").unwrap();
                assert!(first < out.find("me/tool").unwrap() && out.find("me/tool").unwrap() < out.find("old/one").unwrap(), "{out}");
                assert!(out.contains("2 served") && out.contains("1 used") && out.contains("1 failed"), "window excludes the 2h-old row:\n{out}");
                assert!(out.contains("live") && out.contains("timeout"), "{out}");
                assert!(!out.contains('\u{1b}'), "{out}");
                if w == 160 {
                    assert!(out.contains("12.3k") && out.contains("820ms"), "{out}");
                }
            }
        }
        let mut v = ServedView::default();
        let e = Snapshot::default();
        let out = draw(&mut v, &ctx(&e, &themes()[0], ""), 80, 24);
        assert!(out.contains("Nothing served or used yet") && out.contains("moochy up"), "{out}");
    }

    #[test]
    fn filter_applies_to_rows_and_summary() {
        let s = snap();
        let t = themes()[0];
        let mut v = ServedView::default();
        let out = draw(&mut v, &ctx(&s, &t, "gpt"), 160, 48);
        assert!(out.contains("github/me/tool") && !out.contains("github/foo/bar") && out.contains("0 served"), "{out}");
        let out = draw(&mut v, &ctx(&s, &t, "nope"), 80, 24);
        assert!(out.contains("Nothing matches") && out.contains("nope"), "{out}");
    }

    #[test]
    fn selection_holds_while_new_rows_arrive_and_sort_cycles() {
        let mut s = snap();
        let t = themes()[0];
        let mut v = ServedView::default();
        draw(&mut v, &ctx(&s, &t, ""), 160, 48);
        assert_eq!(v.on_input(&Input::Down, &ctx(&s, &t, "")), Outcome::Redraw);
        let held = v.anchor.unwrap();
        s.served.push(row(1, "used", "github/new/one", "gpt-5", ""));
        let out = draw(&mut v, &ctx(&s, &t, ""), 160, 48);
        assert!(out.contains("held") && out.contains("running"), "{out}");
        assert_eq!(visible(&ctx(&s, &t, ""), v.sort)[v.cur.selected().unwrap()].at_ms, held);
        v.on_input(&Input::Home, &ctx(&s, &t, ""));
        assert!(v.anchor.is_none());
        assert_eq!(v.on_input(&Input::Char('z'), &ctx(&s, &t, "")), Outcome::Ignored);
        assert_eq!(v.on_input(&Input::Char('s'), &ctx(&s, &t, "")), Outcome::Redraw);
        let out = draw(&mut v, &ctx(&s, &t, ""), 160, 48);
        assert!(out.contains("by cost"), "{out}");
    }
}
