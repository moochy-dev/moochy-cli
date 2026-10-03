//! The Activity tab (CONTRACT §20.2): the journal, newest first and filterable, with each receipt's
//! verification (relay signature + ledger match, `moochy verify`) shown by glyph and word.

use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table, Wrap};

use super::{Ctx, Input, Outcome, View};
use crate::model::{Activity, ReceiptCheck};
use crate::sanitize::clean;
use crate::theme::{Glyph, Theme};
use crate::widgets::{self as w, TableCursor, Tone, list};

#[derive(Default)]
pub struct ActivityView {
    cur: TableCursor,
}

fn visible<'a>(ctx: &Ctx<'a>) -> Vec<&'a Activity> {
    let mut v: Vec<&Activity> = ctx.snap.activity.iter().filter(|a| w::matches(ctx.filter, &[&a.text, a.receipt.as_ref().map_or("", |r| r.id.as_str())])).collect();
    v.sort_by_key(|a| std::cmp::Reverse(a.at_ms));
    v
}

/// The receipt this entry is about: the node's field, else a public reference in the text
/// (`r_` + a 26-character ULID), unchecked.
fn receipt(a: &Activity) -> Option<(String, ReceiptCheck)> {
    if let Some(r) = &a.receipt {
        return Some((clean(&r.id), r.check.clone()));
    }
    a.text
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .find(|w| w.len() == 28 && w.starts_with("r_") && w.bytes().skip(2).all(|b| b.is_ascii_alphanumeric()))
        .map(|r| (r.to_string(), ReceiptCheck::Unchecked))
}

fn kind(t: Theme, a: &Activity) -> Span<'static> {
    match receipt(a).map(|r| r.1) {
        Some(ReceiptCheck::Verified) => w::badge(t, Tone::Good, t.glyph(Glyph::Ok), "verified"),
        Some(ReceiptCheck::Failed(_)) => w::badge(t, Tone::Bad, t.glyph(Glyph::Error), "mismatch"),
        Some(ReceiptCheck::Unchecked) => w::badge(t, Tone::Warn, t.glyph(Glyph::Coin), "receipt"),
        None => {
            // What the entry is about, from its first words (the journal has no kind field).
            let l = a.text.to_ascii_lowercase();
            let (tone, g, word) = if l.starts_with("served") {
                (Tone::Warn, Glyph::Served, "served")
            } else if l.starts_with("used") {
                (Tone::Info, Glyph::Used, "used")
            } else if l.contains("accepted") || l.contains("refused") || l.contains("asked to") {
                (Tone::Info, Glyph::Pending, "decision")
            } else if l.contains("donation") {
                (Tone::Warn, Glyph::Coin, "donation")
            } else if l.starts_with("device") || l.starts_with("box") {
                (Tone::Muted, Glyph::Online, "device")
            } else if l.starts_with("key log") {
                (Tone::Good, Glyph::Ok, "key log")
            } else {
                (Tone::Muted, Glyph::Offline, "event")
            };
            w::badge(t, tone, t.glyph(g), word)
        }
    }
}

const COLS: [Constraint; 3] = [Constraint::Length(4), Constraint::Length(11), Constraint::Min(20)];

impl View for ActivityView {
    fn title(&self) -> &'static str {
        "Activity"
    }

    fn labels(&self) -> (&'static str, &'static str) {
        ("Activity", "Log")
    }

    fn hints(&self) -> &'static [(&'static str, &'static str)] {
        &[("g/G", "newest/oldest")]
    }

    fn render(&mut self, f: &mut Frame, area: Rect, ctx: &Ctx) {
        let t = *ctx.theme;
        if ctx.snap.activity.is_empty() {
            let lines = vec![
                Line::from(w::badge(t, Tone::Info, t.glyph(Glyph::Connecting), "No activity yet")),
                Line::raw(""),
                Line::raw("The journal fills in as your devices serve and your projects use donations"),
                Line::raw("(what, when, cost and receipts; never prompts or outputs)."),
                Line::raw(""),
                Line::from(vec![Span::raw("Start the app: "), w::key("moochy up"), Span::raw("   in a shell: "), w::key("moochy journal --follow")]),
            ];
            return w::empty(f, area, t, self.title(), lines);
        }
        let rows = visible(ctx);
        let (list_a, detail) = if rows.is_empty() { (area, None) } else { w::split(area, 8) };
        self.cur.sync(rows.len(), list_a);
        let title = w::counted("Journal", rows.len(), ctx.snap.activity.len());
        if rows.is_empty() {
            return w::empty(f, list_a, t, &title, w::no_match(t, ctx.filter));
        }
        let cw = list::table_widths(list_a, &COLS);
        let text_w = cw.get(2).copied().unwrap_or(20);
        let body = rows.iter().map(|a| {
            Row::new([Cell::from(w::muted(t, w::ago(ctx.now_ms, a.at_ms))), Cell::from(kind(t, a)), Cell::from(Line::raw(w::trunc(&clean(&a.text), text_w)))])
        });
        let table = Table::new(body, COLS)
            .header(Row::new(["Age", "Kind", "Entry"]).style(t.muted()))
            .row_highlight_style(t.selected())
            .highlight_symbol(list::marker(t))
            .block(w::block_focus(t, title));
        f.render_stateful_widget(table, list_a, &mut self.cur.state);
        if let (Some(area), Some(a)) = (detail, self.cur.selected().and_then(|i| rows.get(i))) {
            let mut lines = vec![
                Line::from(vec![w::muted(t, format!("{}  ", w::datetime(a.at_ms))), w::muted(t, format!("({})  ", w::ago_long(ctx.now_ms, a.at_ms))), kind(t, a)]),
                Line::raw(clean(&a.text)),
            ];
            if let Some((id, check)) = receipt(a) {
                lines.push(match check {
                    ReceiptCheck::Verified => w::kv_span(t, "Check", w::badge(t, Tone::Good, t.glyph(Glyph::Ok), "relay signature valid, ledger matches")),
                    ReceiptCheck::Failed(why) => w::kv_span(t, "Check", w::badge(t, Tone::Bad, t.glyph(Glyph::Error), &clean(&why))),
                    ReceiptCheck::Unchecked => w::kv_span(t, "Check", w::badge(t, Tone::Warn, t.glyph(Glyph::Pending), "not verified yet")),
                });
                lines.push(Line::from(vec![w::muted(t, format!("{:<10} ", "Verify")), w::key(&format!("moochy verify {id}"))]));
            }
            f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }).block(w::block(t, "Entry")), area);
        }
    }

    fn on_input(&mut self, input: &Input, _ctx: &Ctx) -> Outcome {
        if self.cur.on_input(input) { Outcome::Redraw } else { Outcome::Ignored }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Receipt, Snapshot};
    use crate::widgets::test_util::{NOW, ctx, draw, themes};

    fn snap() -> Snapshot {
        let entry = |ago_s: u64, text: &str| Activity { at_ms: NOW - ago_s * 1000, text: text.into(), receipt: None };
        let mut checked = entry(90, "served gpt for github/foo/baz, $0.0040");
        checked.receipt = Some(Receipt { id: "r_01ARZ3NDEKTSV4RRFFQ69G5FAW".into(), check: ReceiptCheck::Failed("ledger amount differs".into()) });
        Snapshot {
            activity: vec![
                entry(3600, "donation to github/foo/bar resumed"),
                entry(30, "served claude-sonnet-4 for github/foo/bar, $0.0123, receipt r_01ARZ3NDEKTSV4RRFFQ69G5FAV"),
                entry(600, "device \u{1b}]0;pwned\u{7}tower went offline"),
                checked,
            ],
            ..Snapshot::default()
        }
    }

    #[test]
    fn renders_newest_first_with_receipts() {
        let s = snap();
        for t in themes() {
            for (w, h) in [(80, 24), (160, 48)] {
                let mut v = ActivityView::default();
                let out = draw(&mut v, &ctx(&s, &t, ""), w, h);
                let pos = ["served claude", "went offline", "resumed"].map(|x| out.find(x).unwrap());
                assert!(pos[0] < pos[1] && pos[1] < pos[2], "{out}");
                assert!(out.contains("receipt") && out.contains("moochy verify r_01ARZ3NDEKTSV4RRFFQ69G5FAV"), "{out}");
                assert!(out.contains("mismatch"), "{out}");
                assert!(out.contains("tower went offline") && !out.contains("pwned"), "{out}");
            }
        }
        let mut v = ActivityView::default();
        let e = Snapshot::default();
        let out = draw(&mut v, &ctx(&e, &themes()[0], ""), 80, 24);
        assert!(out.contains("No activity yet") && out.contains("moochy up"), "{out}");
    }

    #[test]
    fn receipt_refs_and_filter() {
        let a = |text: &str| Activity { text: text.into(), ..Activity::default() };
        assert_eq!(receipt(&a("x r_01ARZ3NDEKTSV4RRFFQ69G5FAV.")).map(|r| r.0).as_deref(), Some("r_01ARZ3NDEKTSV4RRFFQ69G5FAV"));
        assert!(receipt(&a("r_short and r_01ARZ3NDEKTSV4RRFFQ69G5FAVX")).is_none());
        let s = snap();
        let t = themes()[0];
        let mut v = ActivityView::default();
        let out = draw(&mut v, &ctx(&s, &t, "offline"), 80, 24);
        assert!(out.contains("Journal · 1/4") && !out.contains("resumed"), "{out}");
        assert_eq!(v.on_input(&Input::Down, &ctx(&s, &t, "")), Outcome::Redraw);
        assert_eq!(v.on_input(&Input::Char('z'), &ctx(&s, &t, "")), Outcome::Ignored);
    }
}
