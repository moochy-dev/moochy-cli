//! The shell (CONTRACT §20.3): header with the hamster and connection status, tab bar, the focused
//! view, footer key bar, `?` help, `:`/Ctrl-K palette, `/` filter, toasts and the confirm dialog.
//! Pure state + render: [`App::on_event`] says whether to redraw; the terminal loop (`term.rs`)
//! and the snapshot mode (`snapshot.rs`) drive it.

use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEventKind};
use ratatui::Frame;
use ratatui::layout::{Constraint, Flex, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};

use crate::model::Snapshot;
use crate::sanitize::clean;
use crate::source::{Action, ActionResult, SourceEvent};
use crate::theme::{Depth, Glyph, Theme};
use crate::views::{self, Command, Ctx, Input, Outcome, Prompt, View};
use crate::widgets::{fuzzy, key_hint};

/// Everything the loop feeds the shell.
#[derive(Debug)]
pub enum AppEvent {
    Term(Event),
    Source(SourceEvent),
    Result(ActionResult),
    Signal(Signal),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signal {
    Quit,
    Suspend,
    Resumed,
}

/// The global bindings: one table for the footer, the help overlay, the palette and Settings.
pub const GLOBAL_KEYS: &[(&str, &str)] = &[
    ("1-9", "go to tab"),
    ("tab/S-tab", "next / prev tab, also ] ["),
    ("j/k arrows", "move"),
    ("g/G", "first / last"),
    ("PgUp/PgDn", "page"),
    ("enter", "open / act"),
    ("/", "filter this list"),
    ("esc", "clear filter / back"),
    (": ctrl-k", "command palette"),
    ("ctrl-r", "refresh (also r)"),
    ("?", "help"),
    ("ctrl-z", "suspend"),
    ("q", "quit"),
];

const FOOTER_GLOBAL: &[(&str, &str)] = &[("/", "filter"), (":", "commands"), ("?", "help"), ("q", "quit")];
const TOAST_MS: u64 = 4_000;
const MAX_TOASTS: usize = 3;
const MAX_INPUT: usize = 64;
const FLASH_MS: u64 = 1_000;
const SMILE_MS: u64 = 1_500;
const SMILE_EVERY_MS: u64 = 10_000;
const MAX_EARLY_KEYS: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Conn {
    Connecting,
    Live,
    Offline(String),
}

#[derive(Debug)]
struct Toast {
    text: String,
    glyph: Glyph,
    until_ms: u64,
}

#[derive(Debug)]
enum Mode {
    Normal,
    Filter,
    Palette { input: String, sel: usize },
    Help { scroll: u16 },
    Confirm { title: String, body: String, action: Action, yes: bool },
    Prompt { prompt: Prompt, input: String, error: Option<String> },
}

struct Item {
    label: String,
    key: &'static str,
    cmd: Command,
}

pub struct App {
    views: Vec<Box<dyn View>>,
    active: usize,
    pub snap: Snapshot,
    pub theme: Theme,
    pub conn: Conn,
    mode: Mode,
    filters: Vec<String>,
    toasts: Vec<Toast>,
    outbox: Vec<Action>,
    pub quit: bool,
    pub suspend: bool,
    /// `moochy <args>` to run in the foreground (owner-key actions, [`ActionResult::Terminal`]).
    pub external: Option<Vec<String>>,
    pub now_ms: u64,
    /// Last served/used count, to make the hamster happy when a new request shows up.
    /// Newest request time seen (a newer one is "new").
    last_served: u64,
    happy_until_ms: u64,
    last_smile_ms: u64,
    /// Rows newer than `fresh_from_ms` flash until `fresh_until_ms`.
    fresh_from_ms: u64,
    fresh_until_ms: u64,
    /// Keys typed before the first snapshot (bounded): replayed once there is data to act on.
    early: Vec<KeyEvent>,
    tab_hits: Vec<(u16, u16, usize)>,
    tab_row: u16,
    main: Rect,
}

/// The tabs, in order (number keys 1–9).
#[must_use]
#[allow(clippy::default_constructed_unit_structs)] // views grow state; `default()` stays right
pub fn default_views() -> Vec<Box<dyn View>> {
    vec![
        Box::new(views::overview::OverviewView::default()),
        Box::new(views::donations::DonationsView::default()),
        Box::new(views::served::ServedView::default()),
        Box::new(views::projects::ProjectsView::default()),
        Box::new(views::orgs::OrgsView::default()),
        Box::new(views::decisions::DecisionsView::default()),
        Box::new(views::devices::DevicesView::default()),
        Box::new(views::activity::ActivityView::default()),
        Box::new(views::settings::SettingsView::default()),
    ]
}

impl App {
    #[must_use]
    pub fn new(theme: Theme, now_ms: u64) -> App {
        Self::with_views(default_views(), theme, now_ms)
    }

    #[must_use]
    pub fn with_views(views: Vec<Box<dyn View>>, theme: Theme, now_ms: u64) -> App {
        let n = views.len();
        App {
            views,
            active: 0,
            snap: Snapshot::default(),
            theme,
            conn: Conn::Connecting,
            mode: Mode::Normal,
            filters: vec![String::new(); n],
            toasts: Vec::new(),
            outbox: Vec::new(),
            quit: false,
            suspend: false,
            external: None,
            now_ms,
            last_served: 0,
            happy_until_ms: 0,
            last_smile_ms: 0,
            fresh_from_ms: 0,
            fresh_until_ms: 0,
            early: Vec::new(),
            tab_hits: Vec::new(),
            tab_row: 1,
            main: Rect::default(),
        }
    }

    /// Actions the user asked for since the last call (the loop sends them to the source).
    pub fn take_actions(&mut self) -> Vec<Action> {
        std::mem::take(&mut self.outbox)
    }

    #[must_use]
    pub fn active(&self) -> usize {
        self.active
    }

    /// When the next toast expires, so the loop can wake up for it (no timer otherwise).
    #[must_use]
    pub fn next_deadline(&self) -> Option<u64> {
        let now = self.now_ms;
        self.toasts.iter().map(|t| t.until_ms).chain([self.happy_until_ms, self.fresh_until_ms]).filter(|&d| d > now).min()
    }

    /// True while the hamster smiles about a new request.
    #[must_use]
    pub fn smiling(&self) -> bool {
        self.happy_until_ms > self.now_ms
    }

    /// Drops expired toasts; true when something disappeared.
    pub fn expire(&mut self) -> bool {
        let n = self.toasts.len();
        let now = self.now_ms;
        self.toasts.retain(|t| t.until_ms > now);
        let smile_over = self.happy_until_ms != 0 && self.happy_until_ms <= now && std::mem::take(&mut self.happy_until_ms) != 0;
        let flash_over = self.fresh_until_ms != 0 && self.fresh_until_ms <= now && std::mem::take(&mut self.fresh_until_ms) != 0;
        n != self.toasts.len() || smile_over || flash_over
    }

    pub fn toast(&mut self, glyph: Glyph, text: &str) {
        if self.toasts.len() >= MAX_TOASTS {
            self.toasts.remove(0);
        }
        let mut text = clean(text);
        if let Some((i, _)) = text.char_indices().nth(120) {
            text.truncate(i);
        }
        self.toasts.push(Toast { text, glyph, until_ms: self.now_ms.saturating_add(TOAST_MS) });
    }

    /// Feeds one event; true when the screen must be redrawn.
    pub fn on_event(&mut self, ev: AppEvent) -> bool {
        match ev {
            AppEvent::Term(Event::Key(k)) if k.kind != KeyEventKind::Release => {
                let quit = k.code == KeyCode::Char('q') || (k.code == KeyCode::Char('c') && k.modifiers.contains(KeyModifiers::CONTROL));
                if self.conn == Conn::Connecting && !quit && self.early.len() < MAX_EARLY_KEYS {
                    self.early.push(k);
                    return false;
                }
                self.on_key(k)
            }
            AppEvent::Term(Event::Mouse(m)) => match m.kind {
                MouseEventKind::Down(MouseButton::Left) => self.on_click(m.column, m.row),
                MouseEventKind::ScrollUp => self.on_input(&Input::ScrollUp),
                MouseEventKind::ScrollDown => self.on_input(&Input::ScrollDown),
                _ => false,
            },
            AppEvent::Term(Event::Paste(p)) => self.on_paste(&p),
            AppEvent::Term(Event::Resize(..) | Event::FocusGained) | AppEvent::Signal(Signal::Resumed) => true,
            AppEvent::Term(_) => false,
            AppEvent::Source(SourceEvent::Snapshot(s)) => {
                // A new request: its row flashes for a second; the hamster smiles, at most once
                // every 10 s so the smile still means something.
                let newest = s.served.iter().map(|r| r.at_ms).max().unwrap_or(0);
                if newest > self.last_served && self.conn == Conn::Live {
                    self.fresh_from_ms = self.last_served;
                    self.fresh_until_ms = self.now_ms.saturating_add(FLASH_MS);
                    if self.now_ms >= self.last_smile_ms.saturating_add(SMILE_EVERY_MS) {
                        self.happy_until_ms = self.now_ms.saturating_add(SMILE_MS);
                        self.last_smile_ms = self.now_ms;
                    }
                }
                self.last_served = newest;
                self.snap = *s;
                self.conn = Conn::Live;
                self.replay_early();
                true
            }
            AppEvent::Source(SourceEvent::Toast(t)) => {
                self.toast(Glyph::Online, &t);
                true
            }
            AppEvent::Source(SourceEvent::Disconnected(why)) => {
                let why = clean(&why);
                self.toast(Glyph::Error, &format!("node offline: {why}"));
                self.conn = Conn::Offline(why);
                self.replay_early();
                true
            }
            AppEvent::Result(ActionResult::Done(t)) => {
                self.toast(Glyph::Ok, &t);
                true
            }
            AppEvent::Result(ActionResult::Refused(t)) => {
                self.toast(Glyph::Error, &t);
                true
            }
            AppEvent::Result(ActionResult::Terminal(args)) => {
                self.external = Some(args);
                false
            }
            AppEvent::Signal(Signal::Quit) => {
                self.quit = true;
                true
            }
            AppEvent::Signal(Signal::Suspend) => {
                self.suspend = true;
                false
            }
        }
    }

    fn replay_early(&mut self) {
        for k in std::mem::take(&mut self.early) {
            self.on_key(k);
        }
    }

    fn on_key(&mut self, k: KeyEvent) -> bool {
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        if ctrl && k.code == KeyCode::Char('c') {
            if matches!(self.mode, Mode::Normal) {
                self.quit = true;
            } else {
                self.mode = Mode::Normal;
            }
            return true;
        }
        match std::mem::replace(&mut self.mode, Mode::Normal) {
            Mode::Normal => self.on_key_normal(k, ctrl),
            Mode::Filter => self.on_key_filter(k, ctrl),
            Mode::Palette { input, sel } => self.on_key_palette(k, ctrl, input, sel),
            Mode::Help { scroll } => {
                match k.code {
                    KeyCode::Esc | KeyCode::Char('?' | 'q') | KeyCode::Enter => {}
                    KeyCode::Down | KeyCode::Char('j') => self.mode = Mode::Help { scroll: scroll.saturating_add(1) },
                    KeyCode::Up | KeyCode::Char('k') => self.mode = Mode::Help { scroll: scroll.saturating_sub(1) },
                    _ => self.mode = Mode::Help { scroll },
                }
                true
            }
            Mode::Prompt { prompt, mut input, error } => {
                match k.code {
                    KeyCode::Esc => {}
                    KeyCode::Enter => match prompt.then.submit(&input) {
                        Ok(out) => {
                            self.apply(out);
                        }
                        Err(e) => self.mode = Mode::Prompt { prompt, input, error: Some(e) },
                    },
                    KeyCode::Backspace => {
                        input.pop();
                        self.mode = Mode::Prompt { prompt, input, error: None };
                    }
                    KeyCode::Char('u') if ctrl => self.mode = Mode::Prompt { prompt, input: String::new(), error: None },
                    KeyCode::Char(c) if !ctrl && !c.is_control() => {
                        if input.chars().count() < prompt.max_len {
                            input.push(c);
                        }
                        self.mode = Mode::Prompt { prompt, input, error: None };
                    }
                    _ => self.mode = Mode::Prompt { prompt, input, error },
                }
                true
            }
            Mode::Confirm { title, body, action, yes } => {
                match k.code {
                    KeyCode::Char('y' | 'Y') => self.outbox.push(action),
                    KeyCode::Enter if yes => self.outbox.push(action),
                    KeyCode::Char('n' | 'N' | 'q') | KeyCode::Esc | KeyCode::Enter => {}
                    KeyCode::Left | KeyCode::Right | KeyCode::Tab | KeyCode::BackTab | KeyCode::Char('h' | 'l') => {
                        self.mode = Mode::Confirm { title, body, action, yes: !yes };
                    }
                    _ => self.mode = Mode::Confirm { title, body, action, yes },
                }
                true
            }
        }
    }

    fn on_key_normal(&mut self, k: KeyEvent, ctrl: bool) -> bool {
        let cmd = match k.code {
            KeyCode::Char('k') if ctrl => Some(Command::Palette),
            KeyCode::Char('z') if ctrl => Some(Command::Suspend),
            KeyCode::Char('n') if ctrl => return self.on_input(&Input::Down),
            KeyCode::Char('p') if ctrl => return self.on_input(&Input::Up),
            KeyCode::Char('d') if ctrl => return self.on_input(&Input::PageDown),
            KeyCode::Char('u') if ctrl => return self.on_input(&Input::PageUp),
            KeyCode::Char('r') if ctrl => Some(Command::Refresh),
            _ if ctrl => return false,
            KeyCode::Char('q') => Some(Command::Quit),
            KeyCode::Char('?') => Some(Command::Help),
            KeyCode::Char(':') => Some(Command::Palette),
            KeyCode::Char('/') => Some(Command::Filter),
            KeyCode::Tab => Some(Command::NextTab),
            KeyCode::BackTab => Some(Command::PrevTab),
            // The focused view gets these letters first (`r` refuses a request in Projects);
            // when it has no use for them they are the shell's.
            KeyCode::Char(c @ ('r' | '[' | ']')) => {
                if self.on_input(&Input::Char(c)) {
                    return true;
                }
                Some(match c {
                    'r' => Command::Refresh,
                    ']' => Command::NextTab,
                    _ => Command::PrevTab,
                })
            }
            KeyCode::Char(c @ '1'..='9') => Some(Command::GoTo(usize::from((c as u8).saturating_sub(b'1')))),
            KeyCode::Esc => {
                if let Some(f) = self.filters.get_mut(self.active).filter(|f| !f.is_empty()) {
                    f.clear();
                    return true;
                }
                return self.on_input(&Input::Back);
            }
            _ => None,
        };
        if let Some(c) = cmd {
            return self.exec(c);
        }
        match key_input(k) {
            Some(i) => self.on_input(&i),
            None => false,
        }
    }

    fn on_key_filter(&mut self, k: KeyEvent, ctrl: bool) -> bool {
        let Some(f) = self.filters.get_mut(self.active) else { return true };
        match k.code {
            KeyCode::Esc => f.clear(),
            KeyCode::Enter => {}
            KeyCode::Char('u') if ctrl => {
                f.clear();
                self.mode = Mode::Filter;
            }
            KeyCode::Backspace => {
                f.pop();
                self.mode = Mode::Filter;
            }
            KeyCode::Char(c) if !ctrl => {
                if f.chars().count() < MAX_INPUT {
                    f.push(c);
                }
                self.mode = Mode::Filter;
            }
            KeyCode::Up | KeyCode::Down => {
                self.mode = Mode::Filter;
                return self.on_input(if k.code == KeyCode::Up { &Input::Up } else { &Input::Down });
            }
            _ => self.mode = Mode::Filter,
        }
        true
    }

    fn on_key_palette(&mut self, k: KeyEvent, ctrl: bool, mut input: String, sel: usize) -> bool {
        let n = self.palette_matches(&input).len();
        match k.code {
            KeyCode::Esc => return true,
            KeyCode::Enter => {
                let cmd = self.palette_matches(&input).into_iter().nth(sel).map(|it| it.cmd);
                if let Some(c) = cmd {
                    self.exec(c);
                }
                return true;
            }
            KeyCode::Up => self.mode = Mode::Palette { input, sel: sel.saturating_sub(1) },
            KeyCode::Char('p') if ctrl => self.mode = Mode::Palette { input, sel: sel.saturating_sub(1) },
            KeyCode::Down | KeyCode::Tab => self.mode = Mode::Palette { input, sel: sel.saturating_add(1).min(n.saturating_sub(1)) },
            KeyCode::Char('n') if ctrl => self.mode = Mode::Palette { input, sel: sel.saturating_add(1).min(n.saturating_sub(1)) },
            KeyCode::Backspace => {
                input.pop();
                self.mode = Mode::Palette { input, sel: 0 };
            }
            KeyCode::Char(c) if !ctrl => {
                if input.chars().count() < MAX_INPUT {
                    input.push(c);
                }
                self.mode = Mode::Palette { input, sel: 0 };
            }
            _ => self.mode = Mode::Palette { input, sel },
        }
        true
    }

    fn on_paste(&mut self, raw: &str) -> bool {
        let p: String = clean(raw).chars().filter(|c| *c != '\u{FFFD}').take(MAX_INPUT).collect();
        match &mut self.mode {
            Mode::Filter => {
                if let Some(f) = self.filters.get_mut(self.active) {
                    f.extend(p.chars().take(MAX_INPUT.saturating_sub(f.chars().count())));
                }
                true
            }
            Mode::Palette { input, sel } => {
                input.extend(p.chars().take(MAX_INPUT.saturating_sub(input.chars().count())));
                *sel = 0;
                true
            }
            Mode::Prompt { prompt, input, error } => {
                // A paste is one line: anything after a line break is dropped.
                let p: String = clean(raw.lines().next().unwrap_or_default()).chars().filter(|c| *c != '\u{FFFD}').collect();
                input.extend(p.chars().take(prompt.max_len.saturating_sub(input.chars().count())));
                *error = None;
                true
            }
            _ => false,
        }
    }

    fn on_click(&mut self, col: u16, row: u16) -> bool {
        if !matches!(self.mode, Mode::Normal | Mode::Filter) {
            return false;
        }
        if row == self.tab_row {
            if let Some(&(_, _, i)) = self.tab_hits.iter().find(|(a, b, _)| col >= *a && col < *b) {
                return self.exec(Command::GoTo(i));
            }
            return false;
        }
        if self.main.contains((col, row).into()) {
            return self.on_input(&Input::Click { col, row });
        }
        false
    }

    /// Sends an input to the focused view and applies its outcome.
    fn on_input(&mut self, input: &Input) -> bool {
        if let Mode::Help { scroll } = &mut self.mode {
            match input {
                Input::ScrollDown => *scroll = scroll.saturating_add(1),
                Input::ScrollUp => *scroll = scroll.saturating_sub(1),
                _ => return false,
            }
            return true;
        }
        let empty = String::new();
        let filter = self.filters.get(self.active).unwrap_or(&empty);
        let fresh_ms = if self.now_ms < self.fresh_until_ms { self.fresh_from_ms } else { u64::MAX };
        let ctx = Ctx { snap: &self.snap, theme: &self.theme, filter, now_ms: self.now_ms, fresh_ms };
        let out = match self.views.get_mut(self.active) {
            Some(v) => v.on_input(input, &ctx),
            None => Outcome::Ignored,
        };
        self.apply(out)
    }

    fn apply(&mut self, out: Outcome) -> bool {
        match out {
            Outcome::Ignored => false,
            Outcome::Redraw => true,
            Outcome::Confirm { title, body, action } => {
                // Sanitized line by line: the body's own line breaks stay line breaks.
                let body = body.lines().map(clean).collect::<Vec<_>>().join("\n");
                self.mode = Mode::Confirm { title: clean(&title), body, action, yes: false };
                true
            }
            Outcome::Run(a) => {
                self.outbox.push(a);
                true
            }
            Outcome::Command(c) => self.exec(c),
            Outcome::Toast(t) => {
                self.toast(Glyph::Warn, &t);
                true
            }
            Outcome::Prompt(p) => {
                let input: String = clean(&p.initial).chars().take(p.max_len).collect();
                let prompt = Prompt { title: clean(&p.title), body: clean(&p.body), label: clean(&p.label), ..p };
                self.mode = Mode::Prompt { prompt, input, error: None };
                true
            }
        }
    }

    /// Runs a shell command; true when the screen changes.
    pub fn exec(&mut self, c: Command) -> bool {
        let n = self.views.len().max(1);
        match c {
            Command::GoTo(i) if i < self.views.len() => self.active = i,
            Command::GoTo(_) => return false,
            Command::NextTab => self.active = self.active.saturating_add(1).checked_rem(n).unwrap_or(0),
            Command::PrevTab => self.active = self.active.checked_sub(1).unwrap_or(n.saturating_sub(1)),
            Command::Refresh => self.outbox.push(Action::Refresh),
            Command::Help => self.mode = Mode::Help { scroll: 0 },
            Command::Palette => self.mode = Mode::Palette { input: String::new(), sel: 0 },
            Command::Filter => self.mode = Mode::Filter,
            Command::ToggleDark => self.theme.dark = !self.theme.dark,
            Command::ToggleAscii => self.theme.ascii = !self.theme.ascii,
            Command::CycleDepth => {
                self.theme.depth = match self.theme.depth {
                    Depth::TrueColor => Depth::Ansi256,
                    Depth::Ansi256 => Depth::Ansi16,
                    Depth::Ansi16 => Depth::NoColor,
                    Depth::NoColor => Depth::TrueColor,
                };
            }
            Command::Suspend => {
                self.suspend = true;
                return false;
            }
            Command::Quit => self.quit = true,
            Command::Key(i) => return self.on_input(&i),
            Command::TabKey(t, i) => {
                if t < self.views.len() {
                    self.active = t;
                }
                self.on_input(&i);
            }
        }
        true
    }

    fn palette_items(&self) -> Vec<Item> {
        let mut v: Vec<Item> = self
            .views
            .iter()
            .enumerate()
            .map(|(i, view)| Item { label: format!("Go to {}", view.title()), key: TAB_KEYS.get(i).copied().unwrap_or(""), cmd: Command::GoTo(i) })
            .collect();
        // Every tab's keys, the focused tab's first: picking one opens that tab, then presses it.
        let order = std::iter::once(self.active).chain((0..self.views.len()).filter(|&i| i != self.active));
        for t in order {
            let Some(view) = self.views.get(t) else { continue };
            for (key, what) in view.hints() {
                if let Some(i) = hint_input(key) {
                    let cmd = if t == self.active { Command::Key(i) } else { Command::TabKey(t, i) };
                    v.push(Item { label: format!("{}: {what}", view.title()), key, cmd });
                }
            }
        }
        v.extend([
            Item { label: "Refresh now".into(), key: "r", cmd: Command::Refresh },
            Item { label: "Filter this list".into(), key: "/", cmd: Command::Filter },
            Item { label: "Theme: toggle light / dark".into(), key: "", cmd: Command::ToggleDark },
            Item { label: "Theme: toggle ASCII glyphs".into(), key: "", cmd: Command::ToggleAscii },
            Item { label: "Theme: cycle colour depth".into(), key: "", cmd: Command::CycleDepth },
            Item { label: "Help: all keys".into(), key: "?", cmd: Command::Help },
            Item { label: "Suspend to shell".into(), key: "ctrl-z", cmd: Command::Suspend },
            Item { label: "Quit".into(), key: "q", cmd: Command::Quit },
        ]);
        v
    }

    fn palette_matches(&self, input: &str) -> Vec<Item> {
        let mut scored: Vec<(i64, usize, Item)> = self
            .palette_items()
            .into_iter()
            .enumerate()
            .filter_map(|(i, it)| fuzzy::score(input, &it.label).map(|s| (s, i, it)))
            .collect();
        scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        scored.into_iter().map(|(_, _, it)| it).collect()
    }

    // ---- rendering ----

    pub fn render(&mut self, f: &mut Frame) {
        self.render_frame(f);
        if self.theme.ascii {
            crate::widgets::asciify(f.buffer_mut());
        }
    }

    fn render_frame(&mut self, f: &mut Frame) {
        let area = f.area();
        let th = self.theme;
        if area.width < 60 || area.height < 15 {
            let msg = format!("moochy needs at least 60×15 (this terminal is {}×{}). Make it bigger, or q to quit.", area.width, area.height);
            f.render_widget(Paragraph::new(msg).style(th.muted()).wrap(Wrap { trim: true }), area);
            self.main = Rect::default();
            self.tab_hits.clear();
            return;
        }
        let [head, tabs, main, foot] = Layout::vertical([Constraint::Length(1), Constraint::Length(1), Constraint::Fill(1), Constraint::Length(1)]).areas(area);
        self.main = main;
        self.tab_row = tabs.y;
        self.render_header(f, head);
        self.render_tabs(f, tabs);
        let empty = String::new();
        let filter = self.filters.get(self.active).unwrap_or(&empty);
        let fresh_ms = if self.now_ms < self.fresh_until_ms { self.fresh_from_ms } else { u64::MAX };
        let ctx = Ctx { snap: &self.snap, theme: &self.theme, filter, now_ms: self.now_ms, fresh_ms };
        if let Some(v) = self.views.get_mut(self.active) {
            v.render(f, main, &ctx);
        }
        self.render_footer(f, foot);
        self.render_toasts(f, main);
        match &self.mode {
            Mode::Help { scroll } => self.render_help(f, main, *scroll),
            Mode::Palette { input, sel } => self.render_palette(f, main, input, *sel),
            Mode::Confirm { title, body, yes, .. } => render_confirm(&th, f, main, title, body, *yes),
            Mode::Prompt { prompt, input, error } => render_prompt(th, f, main, prompt, input, error.as_deref()),
            Mode::Normal | Mode::Filter => {}
        }
    }

    fn mood(&self) -> Mood {
        if !matches!(self.conn, Conn::Live) {
            Mood::Sleepy
        } else if self.happy_until_ms > self.now_ms {
            Mood::Happy
        } else {
            Mood::Calm
        }
    }

    fn render_header(&self, f: &mut Frame, area: Rect) {
        let th = &self.theme;
        let mut left = mini_hamster(th, self.mood());
        left.push(Span::styled(" moochy", th.accent()));
        if !self.snap.me.handle.is_empty() {
            left.push(Span::styled(" · ", th.muted()));
            left.push(Span::styled(format!("@{}", clean(self.snap.me.handle.trim_start_matches('@'))), th.bold()));
        }
        let mut right: Vec<Span> = Vec::new();
        let mut item = |g: Glyph, text: String, style: Style| {
            right.push(Span::styled(th.glyph(g), style));
            right.push(Span::styled(format!(" {text}  "), style));
        };
        if !self.snap.pending.is_empty() {
            item(Glyph::Pending, format!("{} pending", self.snap.pending.len()), th.warn());
        }
        if !self.snap.alerts.is_empty() {
            item(Glyph::Warn, format!("{} alert{}", self.snap.alerts.len(), if self.snap.alerts.len() == 1 { "" } else { "s" }), th.err());
        }
        match &self.conn {
            Conn::Live if self.snap.me.connected => item(Glyph::Online, "relay".into(), th.ok()),
            Conn::Live => item(Glyph::Offline, "relay offline".into(), th.warn()),
            _ => {}
        }
        match &self.conn {
            Conn::Connecting => item(Glyph::Connecting, "connecting…".into(), th.muted()),
            Conn::Live => item(Glyph::Online, "node".into(), th.ok()),
            Conn::Offline(_) => item(Glyph::Offline, "node offline".into(), th.err()),
        }
        let lw = Line::from(left.clone()).width() as u16;
        // Drop right-side items from the left until both fit.
        while Line::from(right.clone()).width() as u16 > area.width.saturating_sub(lw).saturating_sub(1) && right.len() >= 2 {
            right.drain(0..2);
        }
        let rw = Line::from(right.clone()).width() as u16;
        let [l, r] = Layout::horizontal([Constraint::Fill(1), Constraint::Length(rw)]).areas(area);
        f.render_widget(Paragraph::new(Line::from(left)), l);
        f.render_widget(Paragraph::new(Line::from(right)), r);
    }

    fn render_tabs(&mut self, f: &mut Frame, area: Rect) {
        let th = self.theme;
        let filter = self.filters.get(self.active).filter(|f| !f.is_empty()).map(|f| format!(" /{} ", clean(f)));
        let fw = filter.as_ref().map_or(0, |f| Line::raw(f.as_str()).width() as u16);
        let avail = area.width.saturating_sub(fw);
        // The active tab always shows its full title; the others use one label level for all.
        // The level is the first that fits even when the widest title is the active one, so it
        // never changes when you switch tabs (the bar does not jump): full titles, the designed
        // medium labels, the short ones, numbers only.
        let label = |i: usize, v: &dyn View, level: u8| -> String {
            let (medium, short) = v.labels();
            let name = match level {
                0 => v.title(),
                1 => medium,
                2 => short,
                _ => "",
            };
            let num = TAB_KEYS.get(i).copied().unwrap_or("");
            if name.is_empty() { format!(" {num}") } else { format!(" {num} {name}") }
        };
        let wid = |s: &str| Line::raw(s).width();
        let mut level = 3u8;
        for l in 0..4u8 {
            let base: usize = self.views.iter().enumerate().map(|(i, v)| wid(&label(i, v.as_ref(), l))).sum();
            let grow = self.views.iter().enumerate().map(|(i, v)| wid(&label(i, v.as_ref(), 0)).saturating_sub(wid(&label(i, v.as_ref(), l)))).max().unwrap_or(0);
            if base.saturating_add(grow) <= usize::from(avail) {
                level = l;
                break;
            }
        }
        let chosen: Vec<String> = self.views.iter().enumerate().map(|(i, v)| label(i, v.as_ref(), if i == self.active { 0 } else { level })).collect();
        let mut spans = Vec::new();
        self.tab_hits.clear();
        let mut x = area.x;
        for (i, t) in chosen.into_iter().enumerate() {
            let w = Line::raw(t.as_str()).width() as u16;
            self.tab_hits.push((x, x.saturating_add(w), i));
            x = x.saturating_add(w);
            let style = if i == self.active { th.selected() } else { th.muted() };
            spans.push(Span::styled(t, style));
        }
        let [l, r] = Layout::horizontal([Constraint::Fill(1), Constraint::Length(fw)]).areas(area);
        f.render_widget(Paragraph::new(Line::from(spans)), l);
        if let Some(fl) = filter {
            f.render_widget(Paragraph::new(Line::styled(fl, th.warn())), r);
        }
    }

    fn render_footer(&self, f: &mut Frame, area: Rect) {
        let th = self.theme;
        if let Mode::Filter = self.mode {
            let text = self.filters.get(self.active).map(|s| clean(s)).unwrap_or_default();
            let mut spans = vec![Span::styled("/", th.key()), Span::raw(text), Span::styled("▏", th.accent())];
            spans.push(Span::styled("   ", th.muted()));
            for (k, w) in [("enter", "keep"), ("esc", "clear"), ("up/dn", "move")] {
                spans.extend(key_hint(th, k, w));
                spans.push(Span::raw("  "));
            }
            f.render_widget(Paragraph::new(Line::from(spans)), area);
            return;
        }
        let view: &[(&str, &str)] = self.views.get(self.active).map_or(&[], |v| v.hints());
        // View keys first, then the globals; `? help` always stays (it lists the rest).
        let mut spans: Vec<Span> = vec![Span::raw(" ")];
        let mut used: usize = 1;
        // `q quit` and `? help` always stay; the rest is dropped from the right when narrow.
        let help = Line::from(key_hint(th, "?", "help").to_vec()).width().saturating_add(Line::from(key_hint(th, "q", "quit").to_vec()).width()).saturating_add(4);
        let budget = usize::from(area.width).saturating_sub(help);
        // A view hint for a key the shell owns (or one already listed) is not repeated.
        let shell = |k: &str| matches!(k, "/" | ":" | "?" | "q" | "j/k" | "↑↓" | "tab");
        let mut seen: Vec<&str> = Vec::new();
        for (k, w) in view.iter().filter(|(k, _)| !shell(k)).chain(FOOTER_GLOBAL.iter().filter(|(k, _)| *k != "?" && *k != "q")) {
            if seen.contains(k) {
                continue;
            }
            seen.push(k);
            let item = key_hint(th, k, w);
            let iw = Line::from(item.to_vec()).width().saturating_add(2);
            if used.saturating_add(iw) > budget {
                continue;
            }
            used = used.saturating_add(iw);
            spans.extend(item);
            spans.push(Span::raw("  "));
        }
        spans.extend(key_hint(th, "q", "quit"));
        spans.push(Span::raw("  "));
        spans.extend(key_hint(th, "?", "help"));
        f.render_widget(Paragraph::new(Line::from(spans)), area);
    }

    fn render_toasts(&self, f: &mut Frame, main: Rect) {
        let th = &self.theme;
        // Inside the pane, one row above its bottom border and two columns in from its right one.
        let main = main.inner(ratatui::layout::Margin::new(2, 1));
        let mut y = main.bottom();
        for t in self.toasts.iter().rev() {
            let text = format!("{} {}", th.glyph(t.glyph), t.text);
            let w = (Line::raw(text.as_str()).width() as u16).saturating_add(4).min(main.width).min(60);
            let h = 3;
            if y < main.y.saturating_add(h) {
                break;
            }
            y = y.saturating_sub(h);
            let r = Rect { x: main.right().saturating_sub(w), y, width: w, height: h };
            f.render_widget(Clear, r);
            let block = Block::default().borders(Borders::ALL).border_set(th.border_set()).border_style(th.glyph_style(t.glyph));
            f.render_widget(Paragraph::new(Line::styled(text, th.glyph_style(t.glyph))).block(block), r);
        }
    }

    fn render_help(&self, f: &mut Frame, main: Rect, scroll: u16) {
        let th = &self.theme;
        let view = self.views.get(self.active);
        let hints = view.map_or(&[][..], |v| v.hints());
        let mut left: Vec<Line> = vec![Line::styled(view.map_or("", |v| v.title()), th.accent())];
        for (k, w) in hints {
            left.push(help_line(th, k, w));
        }
        if hints.is_empty() {
            left.push(Line::styled("  no keys of its own", th.muted()));
        }
        let own: Vec<&str> = hints.iter().map(|(k, _)| *k).collect();
        let mut right: Vec<Line> = vec![Line::styled("Everywhere", th.accent())];
        for (k, w) in GLOBAL_KEYS.iter().filter(|(k, _)| !own.contains(k)) {
            right.push(help_line(th, k, w));
        }
        let mouse = Line::styled("Mouse: click a tab, a row or a panel; the wheel scrolls.", th.muted());
        // Two columns when there is room (everything on one screen), else one scrolling column.
        let two = main.width >= 76;
        let body_h = if two { left.len().max(right.len()) } else { left.len().saturating_add(right.len()).saturating_add(1) };
        let want = (body_h as u16).saturating_add(4);
        let r = centered(main, if two { 76 } else { 64 }, want);
        let more = want > r.height;
        f.render_widget(Clear, r);
        let title = if more { " Help · j/k scroll · esc closes " } else { " Help · esc closes " };
        let block = crate::widgets::block_focus(*th, "").title(Span::styled(title, th.accent()));
        let inner = block.inner(r);
        f.render_widget(block, r);
        let [body, _, foot] = Layout::vertical([Constraint::Fill(1), Constraint::Length(1), Constraint::Length(1)]).areas(inner);
        if two {
            let [a, b] = Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)]).areas(body);
            f.render_widget(Paragraph::new(fit_all(left, a.width)), a);
            f.render_widget(Paragraph::new(fit_all(right, b.width)), b);
        } else {
            left.push(Line::raw(""));
            left.extend(right);
            f.render_widget(Paragraph::new(fit_all(left, body.width)).scroll((scroll, 0)), body);
        }
        f.render_widget(Paragraph::new(mouse), foot);
    }

    fn render_palette(&self, f: &mut Frame, main: Rect, input: &str, sel: usize) {
        let th = &self.theme;
        let items = self.palette_matches(input);
        let h = (items.len().clamp(1, 10) as u16).saturating_add(4); // room for "No command matches"
        let w = 60.min(main.width.saturating_sub(4));
        let r = Rect { x: main.x.saturating_add(main.width.saturating_sub(w) / 2), y: main.y.saturating_add(1), width: w, height: h.min(main.height) };
        f.render_widget(Clear, r);
        let block = Block::default()
            .borders(Borders::ALL)
            .border_set(th.border_set())
            .border_style(th.border_focus())
            .title(Span::styled(" Commands ", th.accent()));
        let inner = block.inner(r);
        f.render_widget(block, r);
        let mut lines = vec![Line::from(vec![Span::styled(": ", th.key()), Span::raw(clean(input)), Span::styled("▏", th.accent())])];
        lines.push(Line::styled("─".repeat(usize::from(inner.width)).replace('─', if th.ascii { "-" } else { "─" }), th.border()));
        if items.is_empty() {
            lines.push(Line::styled(format!("No command matches “{}”.", clean(input)), th.muted()));
        }
        let start = sel.saturating_sub(9);
        for (i, it) in items.iter().enumerate().skip(start).take(10) {
            let kw = it.key.chars().count();
            let pad = usize::from(inner.width).saturating_sub(it.label.chars().count()).saturating_sub(kw).saturating_sub(3);
            let mut l = Line::from(vec![
                Span::raw(if i == sel { format!("{} ", th.glyph(Glyph::Selected)) } else { "  ".into() }),
                Span::raw(it.label.clone()),
                Span::raw(" ".repeat(pad)),
                Span::styled(it.key, th.muted()),
            ]);
            if i == sel {
                l = l.style(th.selected());
            }
            lines.push(l);
        }
        f.render_widget(Paragraph::new(lines), inner);
    }
}

/// Number-key labels for tabs.
const TAB_KEYS: &[&str] = &["1", "2", "3", "4", "5", "6", "7", "8", "9"];

fn help_line(th: &Theme, k: &str, w: &str) -> Line<'static> {
    Line::from(vec![Span::raw("  "), Span::styled(format!("{k:<12}"), th.key()), Span::raw(w.to_string())])
}

/// Help lines cut to their column with `…` (nothing runs into the border).
fn fit_all(lines: Vec<Line<'static>>, w: u16) -> Vec<Line<'static>> {
    lines.into_iter().map(|l| crate::widgets::list::fit(l, usize::from(w))).collect()
}

fn render_confirm(th: &Theme, f: &mut Frame, main: Rect, title: &str, body: &str, yes: bool) {
    let w = 64.min(main.width.saturating_sub(4));
    let tw = usize::from(w.saturating_sub(4).max(1));
    // Each body line wraps on its own; `code` spans show as keys, without the backticks.
    let rows: u16 = body.lines().map(|l| (l.chars().count().max(1).div_ceil(tw)) as u16).sum();
    let r = centered(main, w, rows.saturating_add(4));
    f.render_widget(Clear, r);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_set(th.border_set())
        .border_style(th.warn())
        .padding(ratatui::widgets::Padding::horizontal(1))
        .title(Span::styled(format!(" {} {title} ", th.glyph(Glyph::Warn)), th.warn().add_modifier(ratatui::style::Modifier::BOLD)));
    let inner = block.inner(r);
    f.render_widget(block, r);
    let [b, _, btn] = Layout::vertical([Constraint::Fill(1), Constraint::Length(1), Constraint::Length(1)]).areas(inner);
    let lines: Vec<Line> = body
        .lines()
        .map(|l| Line::from(l.split('`').enumerate().map(|(i, part)| if i % 2 == 1 { crate::widgets::key(part) } else { Span::raw(part.to_string()) }).collect::<Vec<_>>()))
        .collect();
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), b);
    let (ys, ns) = if yes { (th.selected(), th.muted()) } else { (th.muted(), th.selected()) };
    let buttons = Line::from(vec![Span::styled(" y  Yes, do it ", ys), Span::raw("   "), Span::styled(" n  No, cancel ", ns)]).centered();
    f.render_widget(Paragraph::new(buttons), btn);
}

/// The text-input dialog: what it is about, the field with its cursor, why the text is refused.
fn render_prompt(th: Theme, f: &mut Frame, main: Rect, p: &Prompt, input: &str, error: Option<&str>) {
    let w = 64.min(main.width.saturating_sub(4));
    let inner_w = w.saturating_sub(4).max(1);
    let body_rows = (p.body.chars().count() as u16).div_ceil(inner_w).max(1);
    let r = centered(main, w, body_rows.saturating_add(7));
    f.render_widget(Clear, r);
    let block = crate::widgets::block_focus(th, p.title.as_str());
    let inner = block.inner(r).inner(ratatui::layout::Margin::new(1, 0));
    f.render_widget(block, r);
    let [b, _, label, field, err, keys] = Layout::vertical([
        Constraint::Length(body_rows),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(inner);
    f.render_widget(Paragraph::new(p.body.clone()).wrap(Wrap { trim: true }), b);
    f.render_widget(Paragraph::new(Line::styled(p.label.clone(), th.muted())), label);
    // The field shows the end of the text when it is longer than the box.
    let room = usize::from(field.width.saturating_sub(3));
    let shown: String = input.chars().skip(input.chars().count().saturating_sub(room)).collect();
    f.render_widget(Paragraph::new(Line::from(vec![Span::styled("> ", th.key()), Span::raw(shown), Span::styled("▏", th.accent())])), field);
    if let Some(e) = error {
        f.render_widget(Paragraph::new(Line::styled(format!("{} {e}", th.glyph(Glyph::Error)), th.err())), err);
    }
    let mut k = crate::widgets::key_hint(th, "enter", "ok").to_vec();
    k.push(Span::raw("   "));
    k.extend(crate::widgets::key_hint(th, "esc", "cancel"));
    f.render_widget(Paragraph::new(Line::from(k)), keys);
}

fn centered(area: Rect, w: u16, h: u16) -> Rect {
    let [v] = Layout::vertical([Constraint::Length(h.min(area.height))]).flex(Flex::Center).areas(area);
    let [r] = Layout::horizontal([Constraint::Length(w.min(area.width))]).flex(Flex::Center).areas(v);
    r
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mood {
    Calm,
    Happy,
    Sleepy,
}

/// The one-line hamster for the header: puffed cheeks (blush) around a face that reacts.
fn mini_hamster<'a>(th: &Theme, mood: Mood) -> Vec<Span<'a>> {
    let face = match (mood, th.ascii) {
        (Mood::Calm, false) => "•ᴗ•",
        (Mood::Happy, false) => "^ᴗ^",
        (Mood::Sleepy, false) => "-ᴗ-",
        (Mood::Calm, true) => "o.o",
        (Mood::Happy, true) => "^.^",
        (Mood::Sleepy, true) => "-.-",
    };
    let (l, r) = if th.ascii { ("(", ")") } else { ("◖", "◗") };
    let cheek = Style::default().fg(th.blush());
    vec![Span::raw(" "), Span::styled(l, cheek), Span::styled(face, th.accent()), Span::styled(r, cheek)]
}

/// Maps a key to a view input (vim keys and arrows).
fn key_input(k: KeyEvent) -> Option<Input> {
    Some(match k.code {
        KeyCode::Up | KeyCode::Char('k') => Input::Up,
        KeyCode::Down | KeyCode::Char('j') => Input::Down,
        KeyCode::PageUp => Input::PageUp,
        KeyCode::PageDown => Input::PageDown,
        KeyCode::Home | KeyCode::Char('g') => Input::Home,
        KeyCode::End | KeyCode::Char('G') => Input::End,
        KeyCode::Enter => Input::Enter,
        KeyCode::Backspace | KeyCode::Left => Input::Back,
        KeyCode::Char(c) => Input::Char(c),
        _ => return None,
    })
}

/// A footer hint key that the palette can replay (single characters and `enter`).
fn hint_input(key: &str) -> Option<Input> {
    let mut cs = key.chars();
    match (cs.next(), cs.next()) {
        (Some(c), None) => Some(Input::Char(c)),
        _ if key == "enter" => Some(Input::Enter),
        _ => None,
    }
}

/// Display width of a line (tests use it to check nothing overflows).
#[doc(hidden)]
#[must_use]
pub fn tests_width(s: &str) -> usize {
    Line::raw(s).width()
}
