//! List cursors every tab uses: [`TableCursor`] over a ratatui `Table` with a header row, and
//! [`TreeList`] — an indented list with its detail pane. Both take keys, wheel and clicks, stay
//! clamped to the rows, and draw selection the same way (Ink on Mint, `▶`).

use ratatui::Frame;
use ratatui::layout::{Constraint, Flex, Layout, Margin, Position, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{List, ListItem, ListState, Paragraph, TableState, Wrap};

use super::{block, block_focus, counted, empty, split};
use crate::theme::{Glyph, Theme};
use crate::views::Input;

/// The selection marker in front of the selected row.
#[must_use]
pub fn marker(t: Theme) -> String {
    format!("{} ", t.glyph(Glyph::Selected))
}

/// The cell widths a `Table` with `widths`, spacing 1 and a selection marker gets inside a bordered
/// `area` — so cells can be cut with `…` before they reach it (nothing silently clipped).
#[must_use]
pub fn table_widths(area: Rect, widths: &[Constraint]) -> Vec<usize> {
    let inner = area.width.saturating_sub(2).saturating_sub(2);
    Layout::horizontal(widths.iter().copied())
        .spacing(1)
        .flex(Flex::Start)
        .split(Rect::new(0, 0, inner, 1))
        .iter()
        .map(|r| usize::from(r.width))
        .collect()
}

/// Cuts a line to `w` cells with `…` (spans keep their styles).
#[must_use]
pub fn fit(line: Line<'static>, w: usize) -> Line<'static> {
    if line.width() <= w {
        return line;
    }
    let mut left = w.saturating_sub(1);
    let mut spans = Vec::new();
    for s in line.spans {
        if left == 0 {
            break;
        }
        let n = Line::raw(s.content.as_ref()).width();
        if n <= left {
            left = left.saturating_sub(n);
            spans.push(s);
        } else {
            let mut cut = String::new();
            for c in s.content.chars() {
                let cw = Line::raw(c.to_string()).width();
                if cw > left {
                    break;
                }
                left = left.saturating_sub(cw);
                cut.push(c);
            }
            spans.push(Span::styled(cut, s.style));
            left = 0;
        }
    }
    let style = spans.last().map(|s| s.style).unwrap_or_default();
    spans.push(Span::styled("…", style));
    Line::from(spans).style(line.style)
}

/// A cursor over a table drawn inside a bordered block with one header row.
#[derive(Default, Debug)]
pub struct TableCursor {
    pub state: TableState,
    body: Rect,
    len: usize,
}

impl TableCursor {
    /// Clamps the selection to `len` rows drawn in the bordered `area` (call before rendering).
    pub fn sync(&mut self, len: usize, area: Rect) {
        self.len = len;
        self.body = Rect { x: area.x.saturating_add(1), y: area.y.saturating_add(2), width: area.width.saturating_sub(2), height: area.height.saturating_sub(3) };
        let sel = if len == 0 { None } else { Some(self.state.selected().unwrap_or(0).min(len.saturating_sub(1))) };
        self.state.select(sel);
    }

    #[must_use]
    pub fn selected(&self) -> Option<usize> {
        self.state.selected().filter(|&i| i < self.len)
    }

    pub fn select(&mut self, i: usize) {
        if self.len > 0 {
            self.state.select(Some(i.min(self.len.saturating_sub(1))));
        }
    }

    /// Moves on navigation input; false for anything else.
    pub fn on_input(&mut self, input: &Input) -> bool {
        if self.len == 0 {
            return false;
        }
        let cur = self.state.selected().unwrap_or(0);
        let page = usize::from(self.body.height.max(1));
        let next = match input {
            Input::Up | Input::ScrollUp => cur.saturating_sub(1),
            Input::Down | Input::ScrollDown => cur.saturating_add(1),
            Input::PageUp => cur.saturating_sub(page),
            Input::PageDown => cur.saturating_add(page),
            Input::Home => 0,
            Input::End => self.len,
            Input::Click { col, row } => {
                if !self.body.contains(Position::new(*col, *row)) {
                    return false;
                }
                let i = self.state.offset().saturating_add(usize::from(row.saturating_sub(self.body.y)));
                if i >= self.len {
                    return false;
                }
                i
            }
            _ => return false,
        };
        self.select(next);
        true
    }
}

/// One line of a [`TreeList`]; `key` says what the cursor points at.
pub struct TreeRow<K> {
    pub depth: u8,
    pub line: Line<'static>,
    pub key: K,
}

/// An indented list with a detail pane for the selected row.
#[derive(Default)]
pub struct TreeList {
    pub sel: usize,
    state: ListState,
    list: Rect,
}

impl TreeList {
    /// The selected row, clamped to the list.
    pub fn pick<'r, K>(&mut self, rows: &'r [TreeRow<K>]) -> Option<&'r TreeRow<K>> {
        self.sel = self.sel.min(rows.len().saturating_sub(1));
        rows.get(self.sel)
    }

    /// Moves on navigation input (keys, wheel, click); `true` if it was one.
    pub fn input(&mut self, input: &Input, len: usize) -> bool {
        let last = len.saturating_sub(1);
        let page = usize::from(self.list.height.saturating_sub(3)).max(1);
        let sel = match input {
            Input::Up | Input::ScrollUp => self.sel.saturating_sub(1),
            Input::Down | Input::ScrollDown => self.sel.saturating_add(1),
            Input::PageUp => self.sel.saturating_sub(page),
            Input::PageDown => self.sel.saturating_add(page),
            Input::Home => 0,
            Input::End => last,
            Input::Click { col, row } => {
                let inner = self.list.inner(Margin::new(1, 1));
                if !inner.contains(Position::new(*col, *row)) {
                    return false;
                }
                self.state.offset().saturating_add(usize::from(row.saturating_sub(inner.y)))
            }
            _ => return false,
        };
        self.sel = sel.min(last);
        true
    }

    /// The list (focused) and the detail of the selected row; `empty` when nothing is listed.
    #[allow(clippy::too_many_arguments)]
    pub fn draw<K>(
        &mut self,
        f: &mut Frame,
        area: Rect,
        t: Theme,
        title: &str,
        rows: &[TreeRow<K>],
        total: usize,
        detail: (String, Vec<Line<'static>>),
        empty_lines: Vec<Line<'static>>,
    ) {
        if rows.is_empty() {
            self.list = Rect::default();
            return empty(f, area, t, title, empty_lines);
        }
        let (list_a, det_a) = split(area, area.height / 2);
        self.list = list_a;
        self.sel = self.sel.min(rows.len().saturating_sub(1));
        self.state.select(Some(self.sel));
        let w = usize::from(list_a.width.saturating_sub(4));
        let items = rows.iter().map(|r| {
            let mut spans = vec![Span::raw("  ".repeat(usize::from(r.depth)))];
            spans.extend(r.line.spans.iter().cloned());
            ListItem::new(fit(Line::from(spans), w))
        });
        let list = List::new(items).block(block_focus(t, counted(title, rows.len(), total))).highlight_symbol(marker(t)).highlight_style(t.selected());
        f.render_stateful_widget(list, list_a, &mut self.state);
        if let Some(d) = det_a {
            f.render_widget(Paragraph::new(detail.1).wrap(Wrap { trim: false }).block(block(t, detail.0)), d);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_cursor_clicks_and_bounds() {
        let mut c = TableCursor::default();
        c.sync(5, Rect::new(0, 0, 40, 10));
        assert_eq!(c.selected(), Some(0));
        assert!(c.on_input(&Input::End));
        assert_eq!(c.selected(), Some(4));
        assert!(c.on_input(&Input::Down));
        assert_eq!(c.selected(), Some(4));
        assert!(c.on_input(&Input::Click { col: 3, row: 3 })); // body starts at row 2
        assert_eq!(c.selected(), Some(1));
        assert!(!c.on_input(&Input::Click { col: 3, row: 9 })); // past the last row
        assert!(!c.on_input(&Input::Click { col: 3, row: 1 })); // header
        c.sync(0, Rect::new(0, 0, 40, 10));
        assert_eq!(c.selected(), None);
        assert!(!c.on_input(&Input::Down));
    }

    #[test]
    fn fit_cuts_with_ellipsis() {
        let l = Line::from(vec![Span::raw("abc"), Span::raw("defgh")]);
        assert_eq!(fit(l.clone(), 5).to_string(), "abcd…");
        assert_eq!(fit(l.clone(), 8).to_string(), "abcdefgh");
        assert_eq!(fit(l, 3).to_string(), "ab…");
        assert_eq!(table_widths(Rect::new(0, 0, 30, 5), &[Constraint::Length(5), Constraint::Min(3)]), vec![5, 20]);
    }
}
