//! One module per tab (CONTRACT §20.2). Each implements [`View`]; the shell (`mo-tui`) draws the
//! header, tab bar, footer key bar, palette, help, toasts and dialogs around it.
//! Owners: overview, settings — mo-tui; donations, served, devices, activity — mo-tui-donor;
//! projects, orgs, decisions — mo-tui-maint.

use ratatui::Frame;
use ratatui::layout::Rect;

use crate::model::Snapshot;
use crate::source::Action;
use crate::theme::Theme;

pub mod activity;
pub mod decisions;
pub mod devices;
pub mod donations;
pub mod orgs;
pub mod overview;
pub mod projects;
pub mod served;
pub mod settings;

/// What a view needs to draw and react.
pub struct Ctx<'a> {
    pub snap: &'a Snapshot,
    pub theme: &'a Theme,
    /// The `/` filter text, if any, for the focused list.
    pub filter: &'a str,
    pub now_ms: u64,
}

/// A key or mouse input already decoded by the shell.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Input {
    Up,
    Down,
    PageUp,
    PageDown,
    Home,
    End,
    Enter,
    Back,
    Char(char),
    Click { col: u16, row: u16 },
    ScrollUp,
    ScrollDown,
}

/// What the view wants after an input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Nothing changed.
    Ignored,
    /// Re-render.
    Redraw,
    /// Ask the user first (title, body); on yes, run the action.
    Confirm { title: String, body: String, action: Action },
    /// Run now (read-only or already confirmed).
    Run(Action),
}

pub trait View {
    fn title(&self) -> &'static str;
    /// Keys shown in the footer for this view: (key, what it does).
    fn hints(&self) -> &'static [(&'static str, &'static str)];
    fn render(&mut self, f: &mut Frame, area: Rect, ctx: &Ctx);
    fn on_input(&mut self, input: &Input, ctx: &Ctx) -> Outcome;
}
