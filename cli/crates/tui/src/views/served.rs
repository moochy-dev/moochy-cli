//! The Served tab (CONTRACT §20.2): live requests my devices serve and the ones my projects use —
//! model, project, tokens, cost, latency, outcome — newest first, filterable with `/`, under a
//! per-minute sparkline. Owner: mo-tui-donor.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Sparkline, Table, Wrap};

use super::donor_kit::{self as k, Cursor, Tone};
use super::{Ctx, Input, Outcome, View};
use crate::model::Served;
use crate::sanitize::clean;
use crate::theme::Theme;

const MINUTE_MS: u64 = 60_000;
/// The sparkline covers at most this many minutes (one column each).
const MAX_MINUTES: u16 = 60;

#[derive(Default)]
pub struct ServedView {
    cur: Cursor,
    /// `at_ms` of the selected row once the user moved off the newest one: new rows then no longer
    /// move the selection. `None` follows the stream.
    anchor: Option<u64>,
}

fn visible<'a>(ctx: &Ctx<'a>) -> Vec<&'a Served> {
    let mut v: Vec<&Served> =
        ctx.snap.served.iter().filter(|s| k::matches(ctx.filter, &[&s.project, &s.model, &s.direction, &s.outcome])).collect();
    v.sort_by_key(|s| std::cmp::Reverse(s.at_ms));
    v
}

fn direction(t: Theme, s: &Served) -> Span<'static> {
    match s.direction.as_str() {
        "served" => k::badge(t, Tone::Warn, k::g(t, "↑", "^"), "served"),
        "used" => k::badge(t, Tone::Info, k::g(t, "↓", "v"), "used"),
        other => k::badge(t, Tone::Muted, "?", &clean(other)),
    }
}

fn outcome(t: Theme, s: &Served) -> Span<'static> {
    match s.outcome.as_str() {
        "ok" | "done" | "served" => k::badge(t, Tone::Good, k::g(t, "✓", "+"), &s.outcome),
        "" => k::badge(t, Tone::Info, k::g(t, "…", "~"), "running"),
        o if failed(o) => k::badge(t, Tone::Bad, k::g(t, "✗", "x"), &clean(o)),
        o => k::badge(t, Tone::Info, k::g(t, "·", "-"), &clean(o)),
    }
}

fn failed(o: &str) -> bool {
    matches!(o, "refused" | "error" | "failed" | "timeout" | "cancelled" | "rejected" | "limit")
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
        let dot = || k::dim(k::dot(t));
        let line = if lat.is_empty() {
            Line::from(k::dim(format!("Quiet: nothing in the last {minutes} min")))
        } else {
            lat.sort_unstable();
            let p50 = lat.get(lat.len() / 2).copied().unwrap_or(0);
            let mut l = vec![
                k::badge(t, Tone::Warn, k::g(t, "↑", "^"), &format!("{served} served")),
                dot(),
                k::badge(t, Tone::Info, k::g(t, "↓", "v"), &format!("{used} used")),
                dot(),
                Span::raw(k::cost(uusd)),
                dot(),
                Span::raw(format!("p50 {}", k::latency(p50))),
            ];
            if failures > 0 {
                l.extend([dot(), k::badge(t, Tone::Bad, k::g(t, "✗", "x"), &format!("{failures} failed"))]);
            }
            Line::from(l)
        };
        (line, buckets)
    }

    fn detail(t: Theme, s: &Served, now: u64) -> Vec<Line<'static>> {
        let label = |x: &str| k::dim(format!("{x:<9}"));
        let why = match s.direction.as_str() {
            "served" => "  a device of yours answered it with your key",
            "used" => "  a project of yours used donated tokens",
            _ => "",
        };
        vec![
            Line::from(vec![label("When"), Span::raw(format!("{} ago", k::ago(now, s.at_ms)))]),
            Line::from(vec![label("Kind"), direction(t, s), k::dim(why)]),
            Line::from(vec![label("Project"), Span::raw(clean(&s.project))]),
            Line::from(vec![label("Model"), Span::raw(clean(&s.model))]),
            Line::from(vec![label("Tokens"), Span::raw(format!("{} in{}{} out", k::count(s.tokens_in), k::dot(t), k::count(s.tokens_out)))]),
            Line::from(vec![label("Cost"), Span::raw(k::cost(s.cost_uusd))]),
            Line::from(vec![label("Latency"), Span::raw(k::latency(s.latency_ms))]),
            Line::from(vec![label("Outcome"), outcome(t, s)]),
        ]
    }
}

impl View for ServedView {
    fn title(&self) -> &'static str {
        "Served"
    }

    fn hints(&self) -> &'static [(&'static str, &'static str)] {
        &[("j/k", "move"), ("g", "newest (live)"), ("/", "filter")]
    }

    fn render(&mut self, f: &mut Frame, area: Rect, ctx: &Ctx) {
        let t = *ctx.theme;
        if ctx.snap.served.is_empty() {
            let lines = vec![
                Line::from(k::badge(t, Tone::Info, k::g(t, "◌", "o"), "Nothing served or used yet")),
                Line::raw(""),
                Line::raw("Your devices serve your donations while the app runs:"),
                Line::from(k::key("moochy up")),
                Line::raw("Your projects use donated tokens through your coding agent:"),
                Line::from(k::key("moochy run -- <agent>")),
                Line::raw(""),
                Line::from(k::dim("Requests show up here live, newest first (never prompts or outputs).")),
            ];
            return k::empty(f, area, t, self.title(), lines);
        }
        let rows = visible(ctx);
        if let Some(at) = self.anchor
            && let Some(i) = rows.iter().position(|s| s.at_ms == at)
        {
            self.cur.select(i);
        }
        let [top, rest] = Layout::vertical([Constraint::Length(5), Constraint::Min(0)]).areas(area);
        let minutes = top.width.saturating_sub(2).clamp(1, MAX_MINUTES);
        let (line, buckets) = Self::summary(t, &rows, ctx.now_ms, minutes);
        let spark_block = k::block(t, format!(" Last {minutes} min "));
        let inner = spark_block.inner(top);
        f.render_widget(spark_block, top);
        let [l1, l2] = Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).areas(inner);
        f.render_widget(Paragraph::new(line), l1);
        let bars = if t.ascii { k::ASCII_BARS } else { ratatui::symbols::bar::NINE_LEVELS };
        let spark = Sparkline::default().data(&buckets).bar_set(bars).style(k::tone(t, Tone::Warn));
        // Right-aligned: the last column is the current minute.
        let w = minutes.min(l2.width);
        f.render_widget(spark, Rect { x: l2.x.saturating_add(l2.width.saturating_sub(w)), width: w, ..l2 });

        let (list, detail) = k::split(rest, 10);
        self.cur.sync(rows.len(), list);
        let mode = if self.anchor.is_none() {
            k::badge(t, Tone::Good, k::g(t, "●", "*"), "live")
        } else {
            k::badge(t, Tone::Warn, k::g(t, "‖", "="), "held (g: newest)")
        };
        let title = Line::from(vec![Span::raw(format!(" Requests ({}) ", rows.len())), mode, Span::raw(" ")]);
        if rows.is_empty() {
            let lines = vec![Line::raw(format!("No request matches /{}", clean(ctx.filter))), Line::from(k::dim("Esc clears the filter"))];
            return k::empty(f, list, t, &format!("Requests (0){}filtered", k::dot(t)), lines);
        }
        let wide = list.width >= 100;
        let mut widths = vec![Constraint::Length(4), Constraint::Length(8), Constraint::Min(10), Constraint::Min(10)];
        let mut header = vec!["Age", "Kind", "Project", "Model"];
        if wide {
            widths.push(Constraint::Length(13));
            header.push("Tokens in/out");
        }
        widths.push(Constraint::Length(8));
        header.push("Cost");
        if wide {
            widths.push(Constraint::Length(7));
            header.push("Latency");
        }
        widths.push(Constraint::Length(11));
        header.push("Outcome");
        let body = rows.iter().map(|s| {
            let mut cells = vec![
                Cell::from(k::ago(ctx.now_ms, s.at_ms)),
                Cell::from(direction(t, s)),
                Cell::from(clean(&s.project)),
                Cell::from(clean(&s.model)),
            ];
            if wide {
                cells.push(Cell::from(format!("{} {} {}", k::count(s.tokens_in), k::g(t, "→", ">"), k::count(s.tokens_out))));
            }
            cells.push(Cell::from(k::cost(s.cost_uusd)));
            if wide {
                cells.push(Cell::from(k::latency(s.latency_ms)));
            }
            cells.push(Cell::from(outcome(t, s)));
            Row::new(cells)
        });
        let table = Table::new(body, widths)
            .header(Row::new(header).style(k::tone(t, Tone::Muted)))
            .row_highlight_style(k::selected(t))
            .highlight_symbol(k::arrow(t))
            .block(k::block(t, title));
        f.render_stateful_widget(table, list, &mut self.cur.state);
        if let (Some(area), Some(s)) = (detail, self.cur.selected().and_then(|i| rows.get(i))) {
            f.render_widget(Paragraph::new(Self::detail(t, s, ctx.now_ms)).wrap(Wrap { trim: false }).block(k::block(t, " Request ")), area);
        }
    }

    fn on_input(&mut self, input: &Input, ctx: &Ctx) -> Outcome {
        if !self.cur.on_input(input) {
            return Outcome::Ignored;
        }
        self.anchor = match self.cur.selected() {
            Some(0) | None => None,
            Some(i) => visible(ctx).get(i).map(|s| s.at_ms),
        };
        Outcome::Redraw
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Snapshot;
    use crate::views::donor_kit::test_util::{NOW, ctx, draw, themes};

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
                let out = draw(&mut v, &s, t, "", w, h);
                let first = out.find("github/foo/bar").unwrap();
                assert!(first < out.find("github/me/tool").unwrap() && out.find("github/me/tool").unwrap() < out.find("github/old/one").unwrap(), "{out}");
                assert!(out.contains("2 served") && out.contains("1 used") && out.contains("1 failed"), "window excludes the 2h-old row:\n{out}");
                assert!(out.contains("live") && out.contains("timeout"), "{out}");
                assert!(!out.contains("]52;c;eA==\u{7}"), "{out}");
                if w == 160 {
                    assert!(out.contains("12.3k") && out.contains("820ms"), "{out}");
                }
            }
        }
        let mut v = ServedView::default();
        let out = draw(&mut v, &Snapshot::default(), themes()[0], "", 80, 24);
        assert!(out.contains("Nothing served or used yet") && out.contains("moochy up"), "{out}");
    }

    #[test]
    fn filter_applies_to_rows_and_summary() {
        let s = snap();
        let mut v = ServedView::default();
        let out = draw(&mut v, &s, themes()[0], "gpt", 160, 48);
        assert!(out.contains("github/me/tool") && !out.contains("github/foo/bar") && out.contains("0 served"), "{out}");
        let out = draw(&mut v, &s, themes()[0], "nope", 80, 24);
        assert!(out.contains("No request matches /nope"), "{out}");
    }

    #[test]
    fn selection_holds_while_new_rows_arrive() {
        let mut s = snap();
        let t = themes()[0];
        let mut v = ServedView::default();
        draw(&mut v, &s, t, "", 160, 48);
        assert_eq!(v.on_input(&Input::Down, &ctx(&s, &t)), Outcome::Redraw);
        let held = v.anchor.unwrap();
        s.served.push(row(1, "used", "github/new/one", "gpt-5", ""));
        let out = draw(&mut v, &s, t, "", 160, 48);
        assert!(out.contains("held") && out.contains("running"), "{out}");
        assert_eq!(visible(&ctx(&s, &t))[v.cur.selected().unwrap()].at_ms, held);
        v.on_input(&Input::Char('g'), &ctx(&s, &t));
        assert!(v.anchor.is_none());
        assert_eq!(v.on_input(&Input::Char('z'), &ctx(&s, &t)), Outcome::Ignored);
    }
}
