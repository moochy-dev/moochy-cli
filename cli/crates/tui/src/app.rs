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
use crate::views::{self, Command, Ctx, Input, Outcome, View};
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
    ("tab/S-tab", "next / previous tab"),
    ("j/k arrows", "move"),
    ("g/G", "first / last"),
    ("PgUp/PgDn", "page"),
    ("s/S", "sort column / reverse"),
    ("enter", "open / act"),
    ("/", "filter this list"),
    ("esc", "clear filter / back"),
    (": ctrl-k", "command palette"),
    ("r", "refresh"),
    ("?", "help"),
    ("ctrl-z", "suspend"),
    ("q", "quit"),
];

const FOOTER_GLOBAL: &[(&str, &str)] = &[("/", "filter"), (":", "commands"), ("?", "help"), ("q", "quit")];
const TOAST_MS: u64 = 4_000;
const MAX_TOASTS: usize = 3;
const MAX_INPUT: usize = 64;

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
    last_served: usize,
    happy_until_ms: u64,
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
        let t = self.toasts.iter().map(|t| t.until_ms).min();
        if self.happy_until_ms > self.now_ms { t.map_or(Some(self.happy_until_ms), |t| Some(t.min(self.happy_until_ms))) } else { t }
    }

    /// Drops expired toasts; true when something disappeared.
    pub fn expire(&mut self) -> bool {
        let n = self.toasts.len();
        let now = self.now_ms;
        self.toasts.retain(|t| t.until_ms > now);
        n != self.toasts.len() || (self.happy_until_ms != 0 && self.happy_until_ms <= now && std::mem::take(&mut self.happy_until_ms) != 0)
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
            AppEvent::Term(Event::Key(k)) if k.kind != KeyEventKind::Release => self.on_key(k),
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
                let served = s.served.len();
                if served > self.last_served && self.conn == Conn::Live {
                    self.happy_until_ms = self.now_ms.saturating_add(TOAST_MS);
                }
                self.last_served = served;
                self.snap = *s;
                self.conn = Conn::Live;
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
            _ if ctrl => return false,
            KeyCode::Char('q') => Some(Command::Quit),
            KeyCode::Char('?') => Some(Command::Help),
            KeyCode::Char(':') => Some(Command::Palette),
            KeyCode::Char('/') => Some(Command::Filter),
            KeyCode::Char('r') => Some(Command::Refresh),
            KeyCode::Tab | KeyCode::Char(']') => Some(Command::NextTab),
            KeyCode::BackTab | KeyCode::Char('[') => Some(Command::PrevTab),
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

    fn on_paste(&mut self, p: &str) -> bool {
        let p: String = clean(p).chars().filter(|c| *c != '\u{FFFD}').take(MAX_INPUT).collect();
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
        let ctx = Ctx { snap: &self.snap, theme: &self.theme, filter, now_ms: self.now_ms };
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
                self.mode = Mode::Confirm { title: clean(&title), body: clean(&body), action, yes: false };
                true
            }
            Outcome::Run(a) => {
                self.outbox.push(a);
                true
            }
            Outcome::Command(c) => self.exec(c),
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
        if let Some(view) = self.views.get(self.active) {
            for (key, what) in view.hints() {
                if let Some(i) = hint_input(key) {
                    v.push(Item { label: format!("{}: {what}", view.title()), key, cmd: Command::Key(i) });
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
        let ctx = Ctx { snap: &self.snap, theme: &self.theme, filter, now_ms: self.now_ms };
        if let Some(v) = self.views.get_mut(self.active) {
            v.render(f, main, &ctx);
        }
        self.render_footer(f, foot);
        self.render_toasts(f, main);
        match &self.mode {
            Mode::Help { scroll } => self.render_help(f, main, *scroll),
            Mode::Palette { input, sel } => self.render_palette(f, main, input, *sel),
            Mode::Confirm { title, body, yes, .. } => render_confirm(&th, f, main, title, body, *yes),
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
        let titles: Vec<&str> = self.views.iter().map(|v| v.title()).collect();
        let filter = self.filters.get(self.active).filter(|f| !f.is_empty()).map(|f| format!(" /{} ", clean(f)));
        let fw = filter.as_ref().map_or(0, |f| Line::raw(f.as_str()).width() as u16);
        let avail = area.width.saturating_sub(fw);
        // Full titles; then 4-letter titles except the active one; then numbers only.
        let mut chosen = Vec::new();
        for level in 0..3u8 {
            chosen = titles
                .iter()
                .enumerate()
                .map(|(i, t)| {
                    let name: String = match level {
                        _ if i == self.active => (*t).to_string(),
                        0 => (*t).to_string(),
                        1 => t.chars().take(4).collect(),
                        _ => String::new(),
                    };
                    let num = TAB_KEYS.get(i).copied().unwrap_or("");
                    if name.is_empty() { format!(" {num} ") } else { format!(" {num} {name} ") }
                })
                .collect();
            let w: usize = chosen.iter().map(|s: &String| Line::raw(s.as_str()).width()).sum();
            if w <= usize::from(avail) {
                break;
            }
        }
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
        let th = &self.theme;
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
        let help = Line::from(key_hint(th, "?", "help").to_vec()).width().saturating_add(2);
        let budget = usize::from(area.width).saturating_sub(help);
        for (k, w) in view.iter().chain(FOOTER_GLOBAL.iter().filter(|(k, _)| *k != "?")) {
            let item = key_hint(th, k, w);
            let iw = Line::from(item.to_vec()).width().saturating_add(2);
            if used.saturating_add(iw) > budget {
                continue;
            }
            used = used.saturating_add(iw);
            spans.extend(item);
            spans.push(Span::raw("  "));
        }
        spans.extend(key_hint(th, "?", "help"));
        f.render_widget(Paragraph::new(Line::from(spans)), area);
    }

    fn render_toasts(&self, f: &mut Frame, main: Rect) {
        let th = &self.theme;
        let mut y = main.bottom();
        for t in self.toasts.iter().rev() {
            let text = format!("{} {}", th.glyph(t.glyph), t.text);
            let w = (Line::raw(text.as_str()).width() as u16).saturating_add(4).min(main.width.saturating_sub(2)).min(60);
            let h = 3;
            if y < main.y.saturating_add(h) {
                break;
            }
            y = y.saturating_sub(h);
            let r = Rect { x: main.right().saturating_sub(w).saturating_sub(1), y, width: w, height: h };
            f.render_widget(Clear, r);
            let block = Block::default().borders(Borders::ALL).border_set(th.border_set()).border_style(th.glyph_style(t.glyph));
            f.render_widget(Paragraph::new(Line::styled(text, th.glyph_style(t.glyph))).block(block), r);
        }
    }

    fn render_help(&self, f: &mut Frame, main: Rect, scroll: u16) {
        let th = &self.theme;
        let view = self.views.get(self.active);
        let title = view.map_or("", |v| v.title());
        let mut lines: Vec<Line> = vec![Line::styled(title, th.accent())];
        for (k, w) in view.map_or(&[][..], |v| v.hints()) {
            lines.push(help_line(th, k, w));
        }
        if lines.len() == 1 {
            lines.push(Line::styled("  (no keys of its own: the global keys below work here)", th.muted()));
        }
        lines.push(Line::raw(""));
        lines.push(Line::styled("Everywhere", th.accent()));
        for (k, w) in GLOBAL_KEYS {
            lines.push(help_line(th, k, w));
        }
        lines.push(Line::raw(""));
        lines.push(Line::styled("Mouse: click a tab or a row, wheel scrolls, click a header to sort.", th.muted()));
        let r = centered(main, 64, (lines.len() as u16).saturating_add(2));
        f.render_widget(Clear, r);
        let block = Block::default()
            .borders(Borders::ALL)
            .border_set(th.border_set())
            .border_style(th.border_focus())
            .title(Span::styled(" Help · esc closes ", th.accent()));
        f.render_widget(Paragraph::new(lines).block(block).scroll((scroll, 0)), r);
    }

    fn render_palette(&self, f: &mut Frame, main: Rect, input: &str, sel: usize) {
        let th = &self.theme;
        let items = self.palette_matches(input);
        let h = (items.len().min(10) as u16).saturating_add(4);
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
            lines.push(Line::styled("No command matches.", th.muted()));
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

fn help_line<'a>(th: &Theme, k: &'a str, w: &'a str) -> Line<'a> {
    Line::from(vec![Span::raw("  "), Span::styled(format!("{k:<12}"), th.key()), Span::raw(w)])
}

fn render_confirm(th: &Theme, f: &mut Frame, main: Rect, title: &str, body: &str, yes: bool) {
    let w = 56.min(main.width.saturating_sub(4));
    let body_lines = (body.chars().count() as u16).checked_div(w.saturating_sub(4)).unwrap_or(0).saturating_add(1);
    let r = centered(main, w, body_lines.saturating_add(5));
    f.render_widget(Clear, r);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_set(th.border_set())
        .border_style(th.warn())
        .title(Span::styled(format!(" {} {title} ", th.glyph(Glyph::Warn)), th.warn().add_modifier(ratatui::style::Modifier::BOLD)));
    let inner = block.inner(r);
    f.render_widget(block, r);
    let [b, _, btn] = Layout::vertical([Constraint::Fill(1), Constraint::Length(1), Constraint::Length(1)]).areas(inner);
    f.render_widget(Paragraph::new(body.to_string()).wrap(Wrap { trim: true }), b);
    let (ys, ns) = if yes { (th.selected(), th.muted()) } else { (th.muted(), th.selected()) };
    let buttons = Line::from(vec![
        Span::styled(" y  Yes, do it ", ys),
        Span::raw("   "),
        Span::styled(" n  No, cancel ", ns),
    ])
    .centered();
    f.render_widget(Paragraph::new(buttons), btn);
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
