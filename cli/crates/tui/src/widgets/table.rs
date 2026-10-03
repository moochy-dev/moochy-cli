//! The list every tab uses: fuzzy-filtered by the `/` filter, sortable (`s` next column, `S`
//! reverse, or click a header), keyboard and mouse selection kept by key across live updates,
//! columns dropped by priority when the terminal is narrow, and an empty state that says what to
//! do next.
//!
//! ```ignore
//! const COLS: &[Column] = &[Column::grow("Project", 12), Column::new("Spent", 9).right().pri(1)];
//! let rows = snap.donations.iter().enumerate().map(|(i, d)| Row::new(i, vec![
//!     Cell::text(&d.target), Cell::num(widgets::dollars(d.spent_uusd), d.spent_uusd)])).collect();
//! self.table.render(f, area, ctx, "Donations", COLS, rows, "No donations yet: run `moochy donate`");
//! // on_input: self.table.on_input(input, COLS); selected: self.table.selected() → model index
//! ```

use std::cmp::Ordering;

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell as TCell, Paragraph, Row as TRow, Table, TableState as TState, Wrap};

use super::fuzzy;
use crate::sanitize::clean;
use crate::theme::Glyph;
use crate::views::{Ctx, Input, Outcome};

#[derive(Clone, Copy, Debug)]
pub struct Column {
    pub title: &'static str,
    /// Minimum width in cells (the growing column takes the rest).
    pub width: u16,
    pub grow: bool,
    pub right: bool,
    /// 0 = always shown; higher numbers are dropped first when space runs out.
    pub priority: u8,
}

impl Column {
    #[must_use]
    pub const fn new(title: &'static str, width: u16) -> Column {
        Column { title, width, grow: false, right: false, priority: 0 }
    }
    #[must_use]
    pub const fn grow(title: &'static str, width: u16) -> Column {
        Column { title, width, grow: true, right: false, priority: 0 }
    }
    #[must_use]
    pub const fn right(mut self) -> Column {
        self.right = true;
        self
    }
    #[must_use]
    pub const fn pri(mut self, p: u8) -> Column {
        self.priority = p;
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SortKey {
    Num(u64),
    Text(String),
}

#[derive(Clone, Debug)]
pub struct Cell {
    line: Line<'static>,
    plain: String,
    sort: SortKey,
}

impl Cell {
    /// Peer/server text: sanitized here.
    #[must_use]
    pub fn text(s: &str) -> Cell {
        let c = clean(s);
        Cell { sort: SortKey::Text(c.to_lowercase()), line: Line::raw(c.clone()), plain: c }
    }
    /// Sanitized text in a style.
    #[must_use]
    pub fn styled(s: &str, style: Style) -> Cell {
        let c = clean(s);
        Cell { sort: SortKey::Text(c.to_lowercase()), line: Line::styled(c.clone(), style), plain: c }
    }
    /// Formatted number (already safe) that sorts by `key`.
    #[must_use]
    pub fn num(shown: String, key: u64) -> Cell {
        Cell { line: Line::raw(shown.clone()), plain: shown, sort: SortKey::Num(key) }
    }
    /// A prebuilt line (glyph + label…); the caller sanitized its peer text.
    #[must_use]
    pub fn line(line: Line<'static>, sort_text: &str) -> Cell {
        let plain: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        Cell { line, plain, sort: SortKey::Text(sort_text.to_lowercase()) }
    }
    /// Overrides the sort key with a number (e.g. a timestamp shown as "5m").
    #[must_use]
    pub fn sort_by(mut self, key: u64) -> Cell {
        self.sort = SortKey::Num(key);
        self
    }
    #[must_use]
    pub fn style(mut self, style: Style) -> Cell {
        self.line = self.line.style(style);
        self
    }
}

#[derive(Clone, Debug)]
pub struct Row {
    /// The model index this row shows (selection follows it across updates).
    pub key: usize,
    pub cells: Vec<Cell>,
}

impl Row {
    #[must_use]
    pub fn new(key: usize, cells: Vec<Cell>) -> Row {
        Row { key, cells }
    }
}

/// Per-view table state.
#[derive(Debug, Default)]
pub struct TableState {
    sel_key: Option<usize>,
    sel: usize,
    sort: Option<usize>,
    desc: bool,
    visible: Vec<usize>,
    inner: TState,
    /// Body area (rows) and the shown columns' x spans from the last render, for mouse hits.
    body: Rect,
    header_y: u16,
    spans: Vec<(usize, u16, u16)>,
}

impl TableState {
    /// The model index of the selected row, if any row is visible.
    #[must_use]
    pub fn selected(&self) -> Option<usize> {
        self.visible.get(self.sel).copied()
    }

    /// Number of rows after filtering, as of the last render.
    #[must_use]
    pub fn visible_len(&self) -> usize {
        self.visible.len()
    }

    /// Default sort (column, descending) for a fresh table.
    #[must_use]
    pub fn sorted_by(mut self, col: usize, desc: bool) -> TableState {
        self.sort = Some(col);
        self.desc = desc;
        self
    }

    #[allow(clippy::too_many_arguments)]
    pub fn render(&mut self, f: &mut Frame, area: Rect, ctx: &Ctx, title: &str, cols: &[Column], mut rows: Vec<Row>, empty: &str) {
        self.render_focus(f, area, ctx, title, cols, &mut rows, empty, true);
    }

    #[allow(clippy::too_many_arguments)]
    pub fn render_focus(&mut self, f: &mut Frame, area: Rect, ctx: &Ctx, title: &str, cols: &[Column], rows: &mut Vec<Row>, empty: &str, focused: bool) {
        let th = ctx.theme;
        let total = rows.len();
        if !ctx.filter.is_empty() {
            rows.retain(|r| {
                let joined: String = r.cells.iter().map(|c| c.plain.as_str()).collect::<Vec<_>>().join(" ");
                fuzzy::score(ctx.filter, &joined).is_some()
            });
        }
        if let Some(c) = self.sort {
            rows.sort_by(|a, b| {
                let o = match (a.cells.get(c), b.cells.get(c)) {
                    (Some(x), Some(y)) => x.sort.cmp(&y.sort),
                    _ => Ordering::Equal,
                };
                if self.desc { o.reverse() } else { o }
            });
        }
        self.visible.clear();
        self.visible.extend(rows.iter().map(|r| r.key));
        if let Some(pos) = self.sel_key.and_then(|k| self.visible.iter().position(|&v| v == k)) {
            self.sel = pos;
        }
        self.sel = self.sel.min(self.visible.len().saturating_sub(1));
        self.sel_key = self.selected();

        let count = if ctx.filter.is_empty() { format!(" {title} ({total}) ") } else { format!(" {title} ({}/{total}) ", rows.len()) };
        let block = Block::default()
            .borders(Borders::ALL)
            .border_set(th.border_set())
            .border_style(if focused { th.border_focus() } else { th.border() })
            .title(Span::styled(count, if focused { th.accent() } else { th.bold() }));
        let inner = block.inner(area);

        if rows.is_empty() {
            let msg = if total > 0 { format!("Nothing matches “{}”. Esc clears the filter.", clean(ctx.filter)) } else { empty.to_string() };
            f.render_widget(Paragraph::new(Line::styled(msg, th.muted())).wrap(Wrap { trim: true }).block(block), area);
            self.body = Rect::default();
            return;
        }

        // Pick columns by priority until they fit (1 cell of spacing, 2 for the selection mark).
        let mut shown: Vec<usize> = (0..cols.len()).collect();
        let need = |shown: &[usize]| -> u16 {
            shown.iter().filter_map(|&i| cols.get(i)).fold(2u16, |a, c| a.saturating_add(c.width).saturating_add(1))
        };
        while need(&shown) > inner.width && shown.len() > 1 {
            let worst = shown.iter().enumerate().max_by_key(|(_, i)| cols.get(**i).map_or(0, |c| c.priority)).map(|(p, _)| p);
            match worst {
                Some(p) if cols.get(shown.get(p).copied().unwrap_or(0)).is_some_and(|c| c.priority > 0) => {
                    shown.remove(p);
                }
                _ => break,
            }
        }
        let widths: Vec<Constraint> = shown
            .iter()
            .filter_map(|&i| cols.get(i))
            .map(|c| if c.grow { Constraint::Min(c.width) } else { Constraint::Length(c.width) })
            .collect();
        let row_area = Rect { x: inner.x.saturating_add(2), width: inner.width.saturating_sub(2), ..inner };
        let rects = Layout::horizontal(widths.clone()).spacing(1).split(row_area);
        self.spans = shown.iter().zip(rects.iter()).map(|(&i, r)| (i, r.x, r.x.saturating_add(r.width))).collect();
        self.header_y = inner.y;
        self.body = Rect { y: inner.y.saturating_add(1), height: inner.height.saturating_sub(1), ..inner };

        let arrow = |i: usize| -> &'static str {
            if self.sort == Some(i) { th.glyph(if self.desc { Glyph::Down } else { Glyph::Up }) } else { "" }
        };
        let header = TRow::new(shown.iter().filter_map(|&i| cols.get(i).map(|c| (i, c))).map(|(i, c)| {
            let t = format!("{}{}", c.title, arrow(i));
            let l = Line::styled(t, th.bold());
            TCell::from(if c.right { l.right_aligned() } else { l })
        }))
        .style(th.muted());
        let body: Vec<TRow> = rows
            .iter_mut()
            .map(|r| {
                TRow::new(shown.iter().map(|&i| {
                    let right = cols.get(i).is_some_and(|c| c.right);
                    let line = r.cells.get_mut(i).map(|c| std::mem::take(&mut c.line)).unwrap_or_default();
                    TCell::from(if right { line.right_aligned() } else { line })
                }))
            })
            .collect();
        let table = Table::new(body, widths)
            .header(header)
            .block(block)
            .column_spacing(1)
            .row_highlight_style(if focused { th.selected() } else { th.bold() })
            .highlight_symbol(Line::from(format!("{} ", th.glyph(Glyph::Selected))))
            .highlight_spacing(ratatui::widgets::HighlightSpacing::Always);
        self.inner.select(Some(self.sel));
        f.render_stateful_widget(table, area, &mut self.inner);
    }

    /// Handles navigation, sorting and mouse; returns [`Outcome::Redraw`] when something moved.
    pub fn on_input(&mut self, input: &Input, cols: &[Column]) -> Outcome {
        let n = self.visible.len();
        let page = usize::from(self.body.height.max(1));
        let old = (self.sel, self.sort, self.desc);
        match input {
            Input::Up | Input::ScrollUp => self.sel = self.sel.saturating_sub(1),
            Input::Down | Input::ScrollDown => self.sel = self.sel.saturating_add(1).min(n.saturating_sub(1)),
            Input::PageUp => self.sel = self.sel.saturating_sub(page),
            Input::PageDown => self.sel = self.sel.saturating_add(page).min(n.saturating_sub(1)),
            Input::Home => self.sel = 0,
            Input::End => self.sel = n.saturating_sub(1),
            Input::Char('s') => self.sort = Some(self.sort.map_or(0, |c| c.saturating_add(1)) .checked_rem(cols.len()).unwrap_or(0)),
            Input::Char('S') => self.desc = !self.desc,
            Input::Click { col, row } => {
                if *row == self.header_y && self.body.width > 0 {
                    if let Some(&(i, _, _)) = self.spans.iter().find(|(_, a, b)| col >= a && col < b) {
                        if self.sort == Some(i) {
                            self.desc = !self.desc;
                        } else {
                            self.sort = Some(i);
                        }
                    }
                } else if self.body.contains((*col, *row).into()) {
                    let at = usize::from(row.saturating_sub(self.body.y)).saturating_add(self.inner.offset());
                    if at < n {
                        self.sel = at;
                    }
                }
            }
            _ => return Outcome::Ignored,
        }
        self.sel_key = self.selected();
        if old == (self.sel, self.sort, self.desc) { Outcome::Ignored } else { Outcome::Redraw }
    }
}
