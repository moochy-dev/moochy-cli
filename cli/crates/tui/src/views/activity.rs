//! The Activity tab (CONTRACT §20.2): the journal, newest first and filterable, with the receipt
//! of a request pointed out and how to verify it. Owner: mo-tui-donor.

use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table, Wrap};

use super::donor_kit::{self as k, Cursor, Tone};
use super::{Ctx, Input, Outcome, View};
use crate::model::Activity;
use crate::sanitize::clean;
use crate::theme::Theme;

#[derive(Default)]
pub struct ActivityView {
    cur: Cursor,
}

fn visible<'a>(ctx: &Ctx<'a>) -> Vec<&'a Activity> {
    let mut v: Vec<&Activity> = ctx.snap.activity.iter().filter(|a| k::matches(ctx.filter, &[&a.text])).collect();
    v.sort_by_key(|a| std::cmp::Reverse(a.at_ms));
    v
}

/// The public receipt reference in a journal line (`r_` + a 26-character ULID), if any.
fn receipt(text: &str) -> Option<&str> {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .find(|w| w.len() == 28 && w.starts_with("r_") && w.bytes().skip(2).all(|b| b.is_ascii_alphanumeric()))
}

fn kind(t: Theme, a: &Activity) -> Span<'static> {
    if receipt(&a.text).is_some() { k::badge(t, Tone::Warn, k::g(t, "◆", "$"), "receipt") } else { k::dim(format!("{} event", k::g(t, "·", "-"))) }
}

impl View for ActivityView {
    fn title(&self) -> &'static str {
        "Activity"
    }

    fn hints(&self) -> &'static [(&'static str, &'static str)] {
        &[("j/k", "move"), ("g/G", "newest/oldest"), ("/", "filter")]
    }

    fn render(&mut self, f: &mut Frame, area: Rect, ctx: &Ctx) {
        let t = *ctx.theme;
        if ctx.snap.activity.is_empty() {
            let lines = vec![
                Line::from(k::badge(t, Tone::Info, k::g(t, "◌", "o"), "No activity yet")),
                Line::raw(""),
                Line::raw("The journal fills in as your devices serve and your projects use donations"),
                Line::raw("(what, when, cost and receipts; never prompts or outputs)."),
                Line::raw(""),
                Line::from(vec![Span::raw("Start the app: "), k::key("moochy up"), Span::raw("   in a shell: "), k::key("moochy journal --follow")]),
            ];
            return k::empty(f, area, t, self.title(), lines);
        }
        let rows = visible(ctx);
        let (list, detail) = k::split(area, 8);
        self.cur.sync(rows.len(), list);
        if rows.is_empty() {
            let lines = vec![Line::raw(format!("No entry matches /{}", clean(ctx.filter))), Line::from(k::dim("Esc clears the filter"))];
            return k::empty(f, list, t, self.title(), lines);
        }
        let body = rows.iter().map(|a| Row::new([Cell::from(k::ago(ctx.now_ms, a.at_ms)), Cell::from(kind(t, a)), Cell::from(clean(&a.text))]));
        let table = Table::new(body, [Constraint::Length(4), Constraint::Length(9), Constraint::Min(20)])
            .header(Row::new(["Age", "Kind", "Entry"]).style(k::tone(t, Tone::Muted)))
            .row_highlight_style(k::selected(t))
            .highlight_symbol(k::arrow(t))
            .block(k::block(t, format!(" Journal ({}) ", rows.len())));
        f.render_stateful_widget(table, list, &mut self.cur.state);
        if let (Some(area), Some(a)) = (detail, self.cur.selected().and_then(|i| rows.get(i))) {
            let mut lines = vec![Line::from(vec![k::dim(format!("{} ago  ", k::ago(ctx.now_ms, a.at_ms))), kind(t, a)]), Line::raw(clean(&a.text))];
            if let Some(r) = receipt(&a.text) {
                lines.push(Line::from(k::dim("Verify it (donor signature, public key log):")));
                lines.push(Line::from(k::key(&format!("moochy verify {r}"))));
            }
            f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }).block(k::block(t, " Entry ")), area);
        }
    }

    fn on_input(&mut self, input: &Input, _ctx: &Ctx) -> Outcome {
        if self.cur.on_input(input) { Outcome::Redraw } else { Outcome::Ignored }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Snapshot;
    use crate::views::donor_kit::test_util::{NOW, ctx, draw, themes};

    fn snap() -> Snapshot {
        let entry = |ago_s: u64, text: &str| Activity { at_ms: NOW - ago_s * 1000, text: text.into() };
        Snapshot {
            activity: vec![
                entry(3600, "donation to github/foo/bar resumed"),
                entry(30, "served claude-sonnet-4 for github/foo/bar, $0.0123, receipt r_01ARZ3NDEKTSV4RRFFQ69G5FAV"),
                entry(600, "device \u{1b}]0;pwned\u{7}tower went offline"),
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
                let out = draw(&mut v, &s, t, "", w, h);
                let pos = ["served claude", "went offline", "resumed"].map(|x| out.find(x).unwrap());
                assert!(pos[0] < pos[1] && pos[1] < pos[2], "{out}");
                assert!(out.contains("receipt") && out.contains("moochy verify r_01ARZ3NDEKTSV4RRFFQ69G5FAV"), "{out}");
                assert!(out.contains("\u{FFFD}]0;pwned\u{FFFD}tower"), "{out}");
            }
        }
        let mut v = ActivityView::default();
        let out = draw(&mut v, &Snapshot::default(), themes()[0], "", 80, 24);
        assert!(out.contains("No activity yet") && out.contains("moochy up"), "{out}");
    }

    #[test]
    fn receipt_refs_and_filter() {
        assert_eq!(receipt("x r_01ARZ3NDEKTSV4RRFFQ69G5FAV."), Some("r_01ARZ3NDEKTSV4RRFFQ69G5FAV"));
        assert_eq!(receipt("r_short and r_01ARZ3NDEKTSV4RRFFQ69G5FAVX"), None);
        let s = snap();
        let t = themes()[0];
        let mut v = ActivityView::default();
        let out = draw(&mut v, &s, t, "offline", 80, 24);
        assert!(out.contains("Journal (1)") && !out.contains("resumed"), "{out}");
        assert_eq!(v.on_input(&Input::Down, &ctx(&s, &t)), Outcome::Redraw);
        assert_eq!(v.on_input(&Input::Char('z'), &ctx(&s, &t)), Outcome::Ignored);
    }
}
