//! One module per tab (CONTRACT §20.2). Each implements [`View`]; the shell (`mo-tui`) draws the
//! header, tab bar, footer key bar, palette, help, toasts and dialogs around it.
//! Every tab draws with the shared toolkit in [`crate::widgets`] and the [`Theme`].

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
mod pending;
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
    /// Requests newer than this (`at_ms >`) just arrived: lists flash them. `u64::MAX` = none.
    pub fresh_ms: u64,
}

/// A shell command: what palette entries, the global keys and views (via [`Outcome::Command`])
/// can ask the shell to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    GoTo(usize),
    NextTab,
    PrevTab,
    Refresh,
    Help,
    Palette,
    Filter,
    /// Light ↔ dark.
    ToggleDark,
    /// Unicode ↔ ASCII glyphs and borders.
    ToggleAscii,
    /// truecolor → 256 → 16 → none → truecolor.
    CycleDepth,
    Suspend,
    Quit,
    /// Replay a key to the focused view (palette entries made from [`View::hints`]).
    Key(Input),
    /// Open a tab, then replay a key to it (palette entries of other tabs).
    TabKey(usize, Input),
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
    /// Ask the shell (switch tab, theme, help…).
    Command(Command),
    /// Ask the user for a line of text (a refuse reason, a new limit), then act on it.
    Prompt(Prompt),
    /// Tell the user why a key did nothing here ("Select a waiting request to accept").
    Toast(String),
}

/// A one-line text dialog. Typed and pasted text is sanitized and bounded to `max_len`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prompt {
    pub title: String,
    /// What this is about (shown above the field).
    pub body: String,
    pub label: String,
    pub initial: String,
    pub max_len: usize,
    pub then: Then,
}

/// What a [`Prompt`] does with the text once Enter is pressed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Then {
    /// Refuse a request with this reason (may be empty). Refusing signs nothing.
    Refuse { request_id: String, what: String },
    /// Lower a donation's monthly limit to this many dollars, between `floor` and `ceil` µ$; asks
    /// for confirmation next.
    LowerLimit { id: String, target: String, budget_uusd: u64, spent_uusd: u64, floor_uusd: u64, ceil_uusd: u64 },
}

impl Then {
    /// The outcome of submitting `text`, or why it is not acceptable (shown in the dialog).
    pub fn submit(&self, text: &str) -> Result<Outcome, String> {
        use crate::widgets::dollars;
        match self {
            Then::Refuse { request_id, what } => Ok(Outcome::Confirm {
                title: "Refuse this request?".into(),
                body: format!("Refuse {what}{}? Refusing signs nothing; the requester is told.", if text.trim().is_empty() { String::new() } else { format!(" (reason: {})", text.trim()) }),
                action: Action::Refuse { request_id: request_id.clone(), reason: text.trim().to_string() },
            }),
            Then::LowerLimit { id, target, budget_uusd, spent_uusd, floor_uusd, ceil_uusd } => {
                let v = parse_dollars(text).ok_or("type an amount like 12 or 12.50")?;
                if v < *floor_uusd || v > *ceil_uusd {
                    return Err(format!("between {} and {}", dollars(*floor_uusd), dollars(*ceil_uusd)));
                }
                Ok(Outcome::Confirm {
                    title: "Lower the limit".into(),
                    body: format!(
                        "Lower the limit for {target} from {} to {} a month? Already spent this month: {}.",
                        dollars(*budget_uusd),
                        dollars(v),
                        dollars(*spent_uusd)
                    ),
                    action: Action::LowerDonation { id: id.clone(), budget_uusd: v },
                })
            }
        }
    }
}

/// `12`, `12.5`, `$12.50` → µ$ (at most 2 decimals, at most $1,000,000).
#[must_use]
pub fn parse_dollars(s: &str) -> Option<u64> {
    let s = s.trim().trim_start_matches('$').replace(',', "");
    let (whole, frac) = s.split_once('.').unwrap_or((&s, ""));
    if whole.is_empty() && frac.is_empty() || frac.len() > 2 || !whole.chars().chain(frac.chars()).all(|c| c.is_ascii_digit()) {
        return None;
    }
    let whole: u64 = if whole.is_empty() { 0 } else { whole.parse().ok()? };
    let cents: u64 = format!("{frac:0<2}").parse().ok()?;
    if whole > 1_000_000 {
        return None;
    }
    whole.checked_mul(1_000_000)?.checked_add(cents.checked_mul(10_000)?)
}

pub trait View {
    fn title(&self) -> &'static str;
    /// Tab-bar labels when the full titles do not fit: (medium, short). Every tab switches level
    /// together, so the bar never jumps when the active tab changes.
    fn labels(&self) -> (&'static str, &'static str) {
        (self.title(), self.title())
    }
    /// Keys shown in the footer for this view: (key, what it does).
    fn hints(&self) -> &'static [(&'static str, &'static str)];
    fn render(&mut self, f: &mut Frame, area: Rect, ctx: &Ctx);
    fn on_input(&mut self, input: &Input, ctx: &Ctx) -> Outcome;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dollars_parse_strictly() {
        assert_eq!(parse_dollars("12"), Some(12_000_000));
        assert_eq!(parse_dollars("$12.5"), Some(12_500_000));
        assert_eq!(parse_dollars(" 0.07 "), Some(70_000));
        assert_eq!(parse_dollars("1,000"), Some(1_000_000_000));
        for bad in ["", ".", "12.345", "-1", "1e3", "abc", "99999999", "\u{1b}[2J"] {
            assert_eq!(parse_dollars(bad), None, "{bad}");
        }
    }

    #[test]
    fn lower_limit_is_bounded() {
        let t = Then::LowerLimit { id: "d".into(), target: "x".into(), budget_uusd: 40_000_000, spent_uusd: 10_000_000, floor_uusd: 10_000_000, ceil_uusd: 39_990_000 };
        assert!(t.submit("5").is_err());
        assert!(t.submit("40").is_err());
        let Ok(Outcome::Confirm { action, .. }) = t.submit("20") else { panic!() };
        assert_eq!(action, Action::LowerDonation { id: "d".into(), budget_uusd: 20_000_000 });
    }
}
