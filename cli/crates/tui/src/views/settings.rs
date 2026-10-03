//! The Settings tab (CONTRACT §20.2): appearance (theme, colour depth, glyphs — changed live),
//! the node's configuration (read-only, never a secret) and the keybindings. Owner: mo-tui.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

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
                let sel = i == self.sel;
                let mark = if sel { th.glyph(Glyph::Selected) } else { " " };
                let l = Line::from(vec![
                    Span::raw(format!("{mark} ")),
                    Span::styled(format!("{k:<10}"), if sel { th.bold() } else { th.muted() }),
                    Span::styled(format!("{v:<14}"), th.accent()),
                    Span::styled(format!("enter or {key}"), th.muted()),
                ]);
                if sel { l.style(th.selected()) } else { l }
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
            lines.push(kv("account", format!("@{} ({})", clean(me.handle.trim_start_matches('@')), clean(&me.pseudonym))));
        }
        if !me.lockdown.is_empty() {
            lines.push(kv("lockdown", clean(&me.lockdown)));
        }
        for (k, v) in &ctx.snap.config {
            lines.push(kv(&clean(k), clean(v)));
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
            let mut lines: Vec<Line> = GLOBAL_KEYS
                .iter()
                .map(|(k, w)| Line::from(vec![Span::styled(format!("{k:<12}"), th.key()), Span::raw(*w)]))
                .collect();
            lines.push(Line::raw(""));
            lines.push(Line::styled("Each tab adds its own keys in the footer and in ?.", th.muted()));
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

fn block<'a>(th: &Theme, title: &'a str, focus: bool) -> Block<'a> {
    Block::default()
        .borders(Borders::ALL)
        .border_set(th.border_set())
        .border_style(if focus { th.border_focus() } else { th.border() })
        .title(Span::styled(format!(" {title} "), if focus { th.accent() } else { th.bold() }))
}
