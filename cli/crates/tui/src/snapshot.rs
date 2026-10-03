//! Snapshot mode (CONTRACT §20.4): render the frame after scripted keys as plain text (or ANSI)
//! and exit. Deterministic: fixed clock from the source, truecolor, dark unless `--theme light`,
//! no environment lookups. E118, docs and the critic use it.
//!
//! Key script: characters are typed as is (spaces ignore, so `"2 j j"` works), named keys in
//! angle brackets: `<enter> <esc> <tab> <s-tab> <up> <down> <left> <right> <pgup> <pgdn> <home>
//! <end> <bs> <space> <lt> <c-x>` (Ctrl+x) and `<click:COL,ROW>`.

use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::style::{Color, Modifier};
use ratatui::text::Line;

use crate::Options;
use crate::app::{App, AppEvent};
use crate::source::{Action, Source, SourceEvent};
use crate::theme::{Depth, Glyph, Theme};

const MAX_KEYS: usize = 512;

/// Renders `source` at the `--snapshot` size after the `--keys` script; returns the frame.
pub fn snapshot(source: &mut dyn Source, opts: &Options) -> Result<String, String> {
    let (w, h) = opts.snapshot.ok_or("snapshot mode needs --snapshot COLSxROWS")?;
    let theme = Theme { depth: Depth::TrueColor, dark: opts.theme.as_deref() != Some("light"), ascii: opts.ascii };
    let mut app = App::new(theme, source.now_ms());
    feed_snapshot(&mut app, source);
    let mut term = Terminal::new(TestBackend::new(w, h)).map_err(|e| e.to_string())?;
    term.draw(|f| app.render(f)).map_err(|e| e.to_string())?;
    for ev in parse_keys(&opts.keys)? {
        app.on_event(AppEvent::Term(ev));
        for a in app.take_actions() {
            if a != Action::Refresh {
                let r = source.act(a);
                app.on_event(AppEvent::Result(r));
            }
            feed_snapshot(&mut app, source);
        }
        if let Some(args) = app.external.take() {
            app.toast(Glyph::Pending, &format!("runs `moochy {}` on the terminal", args.join(" ")));
        }
        if app.quit {
            break;
        }
        term.draw(|f| app.render(f)).map_err(|e| e.to_string())?;
    }
    let buf = term.backend().buffer();
    Ok(if opts.ansi { to_ansi(buf) } else { to_text(buf) })
}

fn feed_snapshot(app: &mut App, source: &mut dyn Source) {
    let ev = match source.snapshot() {
        Ok(s) => SourceEvent::Snapshot(Box::new(s)),
        Err(e) => SourceEvent::Disconnected(e),
    };
    app.on_event(AppEvent::Source(ev));
}

/// `120x40` → (120, 40), bounded to sane terminal sizes.
pub fn parse_size(s: &str) -> Result<(u16, u16), String> {
    let (c, r) = s.split_once(['x', 'X']).ok_or("size is COLSxROWS, e.g. 80x24")?;
    let c: u16 = c.parse().map_err(|_| "bad column count")?;
    let r: u16 = r.parse().map_err(|_| "bad row count")?;
    if !(20..=500).contains(&c) || !(5..=200).contains(&r) {
        return Err("size out of range (20..500 x 5..200)".into());
    }
    Ok((c, r))
}

pub fn parse_keys(script: &str) -> Result<Vec<Event>, String> {
    let key = |code: KeyCode, m: KeyModifiers| Event::Key(KeyEvent::new(code, m));
    let none = KeyModifiers::NONE;
    let mut out = Vec::new();
    let mut rest = script;
    while let Some(c) = rest.chars().next() {
        if out.len() >= MAX_KEYS {
            return Err(format!("more than {MAX_KEYS} keys"));
        }
        if c == '<' {
            let end = rest.find('>').ok_or("unclosed < in --keys")?;
            let name = rest.get(1..end).unwrap_or_default().to_ascii_lowercase();
            rest = rest.get(end.saturating_add(1)..).unwrap_or_default();
            let code = match name.as_str() {
                "enter" | "cr" => KeyCode::Enter,
                "esc" => KeyCode::Esc,
                "tab" => KeyCode::Tab,
                "s-tab" => KeyCode::BackTab,
                "up" => KeyCode::Up,
                "down" => KeyCode::Down,
                "left" => KeyCode::Left,
                "right" => KeyCode::Right,
                "pgup" => KeyCode::PageUp,
                "pgdn" => KeyCode::PageDown,
                "home" => KeyCode::Home,
                "end" => KeyCode::End,
                "bs" => KeyCode::Backspace,
                "space" => KeyCode::Char(' '),
                "lt" => KeyCode::Char('<'),
                n if n.starts_with("click:") => {
                    let (x, y) = n.trim_start_matches("click:").split_once(',').ok_or("click is <click:COL,ROW>")?;
                    let (column, row) = (x.parse().map_err(|_| "bad click column")?, y.parse().map_err(|_| "bad click row")?);
                    out.push(Event::Mouse(MouseEvent { kind: MouseEventKind::Down(MouseButton::Left), column, row, modifiers: none }));
                    continue;
                }
                n if n.len() == 3 && n.starts_with("c-") => {
                    let ch = n.chars().nth(2).ok_or("bad ctrl key")?;
                    out.push(key(KeyCode::Char(ch), KeyModifiers::CONTROL));
                    continue;
                }
                _ => return Err(format!("unknown key <{name}>")),
            };
            out.push(key(code, none));
        } else {
            rest = rest.get(c.len_utf8()..).unwrap_or_default();
            if c != ' ' {
                out.push(key(KeyCode::Char(c), if c.is_ascii_uppercase() { KeyModifiers::SHIFT } else { none }));
            }
        }
    }
    Ok(out)
}

/// The cells of `buf` as lines, wide characters counted once, trailing blanks trimmed.
fn rows(buf: &Buffer) -> impl Iterator<Item = Vec<&ratatui::buffer::Cell>> {
    let a = buf.area;
    (a.top()..a.bottom()).map(move |y| {
        let mut row = Vec::new();
        let mut skip = 0usize;
        for x in a.left()..a.right() {
            let Some(c) = buf.cell((x, y)) else { continue };
            if skip > 0 {
                skip = skip.saturating_sub(1);
                continue;
            }
            skip = Line::raw(c.symbol()).width().saturating_sub(1);
            row.push(c);
        }
        row
    })
}

#[must_use]
pub fn to_text(buf: &Buffer) -> String {
    let mut s = String::new();
    for row in rows(buf) {
        let line: String = row.iter().map(|c| c.symbol()).collect();
        s.push_str(line.trim_end());
        s.push('\n');
    }
    s
}

#[must_use]
pub fn to_ansi(buf: &Buffer) -> String {
    let mut s = String::new();
    for row in rows(buf) {
        let mut cur = None;
        for c in row {
            let st = (c.fg, c.bg, c.modifier);
            if cur != Some(st) {
                s.push_str(&sgr(c.fg, c.bg, c.modifier));
                cur = Some(st);
            }
            s.push_str(c.symbol());
        }
        s.push_str("\u{1b}[0m\n");
    }
    s
}

fn sgr(fg: Color, bg: Color, m: Modifier) -> String {
    let mut p = vec!["0".to_string()];
    for (bit, code) in [(Modifier::BOLD, "1"), (Modifier::DIM, "2"), (Modifier::ITALIC, "3"), (Modifier::UNDERLINED, "4"), (Modifier::REVERSED, "7")] {
        if m.contains(bit) {
            p.push(code.into());
        }
    }
    p.extend(color(fg, false));
    p.extend(color(bg, true));
    format!("\u{1b}[{}m", p.join(";"))
}

fn color(c: Color, bg: bool) -> Option<String> {
    let base: u8 = if bg { 40 } else { 30 };
    let named = |n: u8, bright: bool| Some((if bright { base.saturating_add(60) } else { base }).saturating_add(n).to_string());
    match c {
        Color::Reset => None,
        Color::Rgb(r, g, b) => Some(format!("{};2;{r};{g};{b}", base.saturating_add(8))),
        Color::Indexed(i) => Some(format!("{};5;{i}", base.saturating_add(8))),
        Color::Black => named(0, false),
        Color::Red => named(1, false),
        Color::Green => named(2, false),
        Color::Yellow => named(3, false),
        Color::Blue => named(4, false),
        Color::Magenta => named(5, false),
        Color::Cyan => named(6, false),
        Color::Gray => named(7, false),
        Color::DarkGray => named(0, true),
        Color::LightRed => named(1, true),
        Color::LightGreen => named(2, true),
        Color::LightYellow => named(3, true),
        Color::LightBlue => named(4, true),
        Color::LightMagenta => named(5, true),
        Color::LightCyan => named(6, true),
        Color::White => named(7, true),
    }
}
