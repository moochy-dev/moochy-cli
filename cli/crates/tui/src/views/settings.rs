//! The Settings tab (CONTRACT §20.2): appearance (theme, colour depth, glyphs — changed live),
//! the node's configuration (read-only, never a secret) and the keybindings. Owner: mo-tui.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph};

use super::{Command, Ctx, Input, Outcome, View};
use crate::app::GLOBAL_KEYS;
use crate::sanitize::clean;
use crate::theme::{Glyph, Theme};

const ROWS: usize = 3;

#[derive(Default)]
pub struct SettingsView {
    sel: usize,
    /// Appearance rows' screen positions from the last render (mouse).
    rows_y: Option<(Rect, u16)>,
}

impl View for SettingsView {
    fn title(&self) -> &'static str {
        "Settings"
    }

    fn labels(&self) -> (&'static str, &'static str) {
        ("Settings", "Prefs")
    }

    fn hints(&self) -> &'static [(&'static str, &'static str)] {
        &[("enter", "change"), ("t", "light/dark"), ("c", "colours"), ("a", "ascii")]
    }

    fn render(&mut self, f: &mut Frame, area: Rect, ctx: &Ctx) {
        let th = ctx.theme;
        let wide = area.width >= 100;
        let (left, keys) = if wide {
            let [l, r] = Layout::horizontal([Constraint::Percentage(58), Constraint::Percentage(42)]).areas(area);
            (l, Some(r))
        } else {
            (area, None)
        };
        let [look, node] = Layout::vertical([Constraint::Length(7), Constraint::Fill(1)]).areas(left);

        let b = block(th, "Appearance", true);
        let inner = b.inner(look);
        f.render_widget(b, look);
        let items = [
            ("Theme", if th.dark { "dark" } else { "light" }, "t"),
            ("Colours", th.depth.label(), "c"),
            ("Glyphs", if th.ascii { "ASCII" } else { "Unicode" }, "a"),
        ];
        let mut lines: Vec<Line> = items
            .iter()
            .enumerate()
            .map(|(i, (k, v, key))| {
                // The selected row is one style end to end (Ink on Mint): no span keeps its own
                // colour on the fill, so nothing on it ever drops below the contrast floor.
                if i == self.sel {
                    let text = format!("{} {k:<10}{v:<14}enter or {key} ", th.glyph(Glyph::Selected));
                    return Line::styled(text, th.selected());
                }
                Line::from(vec![Span::raw("  "), Span::styled(format!("{k:<10}"), th.muted()), Span::styled(format!("{v:<14}"), th.accent()), Span::styled(format!("enter or {key}"), th.muted())])
            })
            .collect();
        lines.push(Line::styled("Start-up: --theme light|dark, --ascii, MOOCHY_THEME, NO_COLOR.", th.muted()));
        self.rows_y = Some((inner, inner.y));
        f.render_widget(Paragraph::new(lines), inner);

        let b = block(th, "Node", false);
        let inner = b.inner(node);
        f.render_widget(b, node);
        let me = &ctx.snap.me;
        let mut lines = Vec::new();
        let kv = |k: &str, v: String| Line::from(vec![Span::styled(format!("{k:<16}"), th.muted()), Span::raw(v)]);
        if !me.handle.is_empty() {
            lines.push(kv("Account", format!("@{} ({})", clean(me.handle.trim_start_matches('@')), clean(&me.pseudonym))));
        }
        if !me.web.is_empty() {
            lines.push(kv("Web", crate::widgets::web_origin(&me.web)));
        }
        // Config keys read as words (`serve_hours` → `Serve hours`); lockdown lives in Devices.
        for (k, v) in &ctx.snap.config {
            let k = clean(k).replace(['_', '.'], " ");
            let mut c = k.chars();
            let k: String = c.next().map(|f| f.to_uppercase().chain(c).collect()).unwrap_or_default();
            lines.push(kv(&k, clean(v)));
        }
        if lines.is_empty() {
            lines.push(Line::styled("The node has not reported its configuration yet (`moochy status`).", th.muted()));
        }
        if !wide {
            lines.push(Line::raw(""));
            lines.push(Line::styled("Keybindings: press ? for the full list.", th.muted()));
        }
        f.render_widget(Paragraph::new(lines), inner);

        if let Some(r) = keys {
            let b = block(th, "Keybindings", false);
            let inner = b.inner(r);
            f.render_widget(b, r);
            let fit = |l: Line<'static>| crate::widgets::list::fit(l, usize::from(inner.width));
            let mut lines: Vec<Line> = GLOBAL_KEYS
                .iter()
                .map(|(k, w)| fit(Line::from(vec![Span::styled(format!("{k:<12}"), th.key()), Span::raw(*w)])))
                .collect();
            lines.push(Line::raw(""));
            lines.push(fit(Line::styled("Each tab adds keys of its own (footer, ?).", th.muted())));
            f.render_widget(Paragraph::new(lines), inner);
        }
    }

    fn on_input(&mut self, input: &Input, _ctx: &Ctx) -> Outcome {
        let cmd = |i: usize| Outcome::Command([Command::ToggleDark, Command::CycleDepth, Command::ToggleAscii].get(i).cloned().unwrap_or(Command::ToggleDark));
        match input {
            Input::Up | Input::ScrollUp => {
                self.sel = self.sel.saturating_sub(1);
                Outcome::Redraw
            }
            Input::Down | Input::ScrollDown => {
                self.sel = self.sel.saturating_add(1).min(ROWS.saturating_sub(1));
                Outcome::Redraw
            }
            Input::Home => {
                self.sel = 0;
                Outcome::Redraw
            }
            Input::End => {
                self.sel = ROWS.saturating_sub(1);
                Outcome::Redraw
            }
            Input::Enter | Input::Char(' ') => cmd(self.sel),
            Input::Char('t') => cmd(0),
            Input::Char('c') => cmd(1),
            Input::Char('a') => cmd(2),
            Input::Click { col, row } => match self.rows_y {
                Some((r, y0)) if r.contains((*col, *row).into()) && usize::from(row.saturating_sub(y0)) < ROWS => {
                    self.sel = usize::from(row.saturating_sub(y0));
                    cmd(self.sel)
                }
                _ => Outcome::Ignored,
            },
            _ => Outcome::Ignored,
        }
    }
}

fn block<'a>(th: &Theme, title: &str, focus: bool) -> Block<'a> {
    if focus { crate::widgets::block_focus(*th, title) } else { crate::widgets::block(*th, title) }
}
