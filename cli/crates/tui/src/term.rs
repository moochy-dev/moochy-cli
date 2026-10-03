//! The interactive loop (CONTRACT §20.3): one blocking channel of events (keys, mouse, paste,
//! resize, source updates, action results, signals) — the main thread sleeps in `recv` and only
//! draws after an event, so an idle dashboard costs no CPU and allocates nothing. The source runs
//! on its own worker thread (snapshots and actions never block the UI). The terminal is restored on
//! every exit path: normal return and errors (guard), panic (hook), SIGTERM/SIGHUP/SIGINT
//! (signal thread → quit), Ctrl-Z/SIGTSTP (leave, stop, re-enter on SIGCONT).

use std::io::{IsTerminal, Write, stdout};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel};
use std::sync::{Arc, Once};
use std::thread;
use std::time::Duration;

use crossterm::event::{self, DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture};
use crossterm::execute;
use crossterm::terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

use crate::Options;
use crate::app::{App, AppEvent, Signal};
use crate::sanitize::clean;
use crate::source::{Action, ActionResult, Source, SourceEvent, system_now_ms};
use crate::theme::{Env, Glyph, Theme};

/// How long the input thread waits per poll: the latency of handing the terminal to a child
/// process or suspending, nothing else (events arrive immediately).
const INPUT_POLL: Duration = Duration::from_millis(250);

/// Runs the dashboard on the real terminal until `q`, Ctrl-C or a terminating signal.
pub fn run(source: Box<dyn Source>, events: Option<Receiver<SourceEvent>>, opts: &Options) -> Result<(), String> {
    if !stdout().is_terminal() {
        return Err("moochy tui needs an interactive terminal (or use --snapshot COLSxROWS)".into());
    }
    let theme = Theme::detect(&Env::from_process(), opts.theme.as_deref(), opts.ascii);
    let (base_real, base_src) = (system_now_ms(), source.now_ms());
    let clock = move || base_src.saturating_add(system_now_ms().saturating_sub(base_real));

    let (tx, rx) = sync_channel::<AppEvent>(256);
    let (atx, arx) = sync_channel::<Action>(16);
    let w = tx.clone();
    thread::Builder::new().name("tui-source".into()).spawn(move || worker(source, &arx, &w)).map_err(|e| e.to_string())?;
    if let Some(ev) = events {
        let w = tx.clone();
        thread::Builder::new()
            .name("tui-watch".into())
            .spawn(move || {
                while let Ok(e) = ev.recv() {
                    if w.send(AppEvent::Source(e)).is_err() {
                        break;
                    }
                }
            })
            .map_err(|e| e.to_string())?;
    }
    let input = Input::spawn(tx.clone())?;
    #[cfg(unix)]
    signals(tx.clone())?;
    drop(tx);
    install_panic_hook();

    let mut guard = Guard::enter().map_err(|e| e.to_string())?;
    let mut term = Terminal::new(CrosstermBackend::new(stdout())).map_err(|e| e.to_string())?;
    let mut app = App::new(theme, clock());
    term.draw(|f| app.render(f)).map_err(|e| e.to_string())?;

    loop {
        let ev = match app.next_deadline() {
            Some(d) => rx.recv_timeout(Duration::from_millis(d.saturating_sub(clock()).max(1))),
            None => rx.recv().map_err(|_| RecvTimeoutError::Disconnected),
        };
        app.now_ms = clock();
        let mut redraw = app.expire();
        let mut next = match ev {
            Ok(e) => Some(e),
            Err(RecvTimeoutError::Timeout) => None,
            Err(RecvTimeoutError::Disconnected) => break,
        };
        // Handle this event and everything already queued, then draw once.
        while let Some(e) = next.take() {
            if let AppEvent::Signal(Signal::Resumed) = e {
                guard.reenter(&mut term)?;
            }
            redraw |= app.on_event(e);
            next = rx.try_recv().ok();
        }
        for a in app.take_actions() {
            if atx.try_send(a).is_err() {
                app.toast(Glyph::Warn, "busy: the node is still working on the last action");
                redraw = true;
            }
        }
        if app.quit {
            break;
        }
        if std::mem::take(&mut app.suspend) {
            input.pause();
            guard.leave();
            suspend_self();
            input.resume();
            guard.reenter(&mut term)?;
            redraw = true;
        }
        if let Some(args) = app.external.take() {
            input.pause();
            guard.leave();
            let r = run_external(&args);
            input.resume();
            guard.reenter(&mut term)?;
            app.now_ms = clock();
            app.on_event(AppEvent::Result(r));
            let _ = atx.try_send(Action::Refresh);
            redraw = true;
        }
        if redraw {
            term.draw(|f| app.render(f)).map_err(|e| e.to_string())?;
        }
    }
    drop(guard);
    Ok(())
}

/// Owns the source: first snapshot, then one action at a time, each followed by a snapshot.
fn worker(mut src: Box<dyn Source>, actions: &Receiver<Action>, tx: &SyncSender<AppEvent>) {
    let snap = |src: &mut Box<dyn Source>| {
        let ev = match src.snapshot() {
            Ok(s) => SourceEvent::Snapshot(Box::new(s)),
            Err(e) => SourceEvent::Disconnected(e),
        };
        tx.send(AppEvent::Source(ev)).is_ok()
    };
    if !snap(&mut src) {
        return;
    }
    while let Ok(a) = actions.recv() {
        if a != Action::Refresh && tx.send(AppEvent::Result(src.act(a))).is_err() {
            return;
        }
        if !snap(&mut src) {
            return;
        }
    }
}

/// The terminal input thread. It can be paused so a child process (or the shell after Ctrl-Z)
/// gets every keystroke: a passphrase typed for `moochy accept` must never reach us.
struct Input {
    paused: Arc<AtomicBool>,
    ack: Receiver<()>,
    thread: thread::Thread,
}

impl Input {
    fn spawn(tx: SyncSender<AppEvent>) -> Result<Input, String> {
        let paused = Arc::new(AtomicBool::new(false));
        let (ack_tx, ack) = sync_channel::<()>(1);
        let p = paused.clone();
        let h = thread::Builder::new()
            .name("tui-input".into())
            .spawn(move || {
                loop {
                    if p.load(Ordering::Acquire) {
                        let _ = ack_tx.try_send(());
                        while p.load(Ordering::Acquire) {
                            thread::park();
                        }
                        continue;
                    }
                    match event::poll(INPUT_POLL) {
                        Ok(true) => match event::read() {
                            Ok(e) => {
                                if tx.send(AppEvent::Term(e)).is_err() {
                                    return;
                                }
                            }
                            Err(_) => return,
                        },
                        Ok(false) => {}
                        Err(_) => return,
                    }
                }
            })
            .map_err(|e| e.to_string())?;
        Ok(Input { paused, ack, thread: h.thread().clone() })
    }

    fn pause(&self) {
        self.paused.store(true, Ordering::Release);
        let _ = self.ack.recv_timeout(INPUT_POLL.saturating_mul(4));
    }

    fn resume(&self) {
        self.paused.store(false, Ordering::Release);
        self.thread.unpark();
    }
}

#[cfg(unix)]
fn signals(tx: SyncSender<AppEvent>) -> Result<(), String> {
    use signal_hook::consts::{SIGCONT, SIGHUP, SIGINT, SIGTERM, SIGTSTP};
    let mut sigs = signal_hook::iterator::Signals::new([SIGTERM, SIGHUP, SIGINT, SIGTSTP, SIGCONT]).map_err(|e| e.to_string())?;
    thread::Builder::new()
        .name("tui-signals".into())
        .spawn(move || {
            for s in sigs.forever() {
                let ev = match s {
                    SIGTSTP => Signal::Suspend,
                    SIGCONT => Signal::Resumed,
                    _ => Signal::Quit,
                };
                if tx.send(AppEvent::Signal(ev)).is_err() {
                    return;
                }
            }
        })
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Stops the process the way the default SIGTSTP action would (the terminal is already restored).
fn suspend_self() {
    #[cfg(unix)]
    {
        let _ = signal_hook::low_level::raise(signal_hook::consts::SIGSTOP);
    }
}

/// Runs `moochy <args>` on the restored terminal, then waits for Enter.
fn run_external(args: &[String]) -> ActionResult {
    let shown = clean(&args.join(" "));
    let mut out = stdout();
    let _ = writeln!(out, "\n▶ moochy {shown}\n");
    let status = std::env::current_exe().and_then(|exe| std::process::Command::new(exe).args(args).status());
    let r = match status {
        Ok(s) if s.success() => ActionResult::Done(format!("moochy {shown}: done")),
        Ok(s) => ActionResult::Refused(format!("moochy {shown}: exited with {}", s.code().unwrap_or(-1))),
        Err(e) => ActionResult::Refused(format!("moochy {shown}: {e}")),
    };
    let _ = write!(out, "\nPress Enter to return to moochy tui… ");
    let _ = out.flush();
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
    r
}

/// Raw mode + alternate screen + mouse + bracketed paste while alive.
struct Guard {
    on: bool,
}

impl Guard {
    fn enter() -> std::io::Result<Guard> {
        enable_raw_mode()?;
        execute!(stdout(), EnterAlternateScreen, EnableMouseCapture, EnableBracketedPaste)?;
        Ok(Guard { on: true })
    }

    fn leave(&mut self) {
        if std::mem::take(&mut self.on) {
            restore();
        }
    }

    fn reenter(&mut self, term: &mut Terminal<CrosstermBackend<std::io::Stdout>>) -> Result<(), String> {
        if !self.on {
            *self = Guard::enter().map_err(|e| e.to_string())?;
        }
        // A full repaint without `Terminal::clear` (it asks the terminal for the cursor position
        // and waits up to 2 s for an answer some terminals never send).
        let sz = term.size().map_err(|e| e.to_string())?;
        term.resize(ratatui::layout::Rect::new(0, 0, sz.width, sz.height)).map_err(|e| e.to_string())
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        self.leave();
    }
}

fn restore() {
    let _ = disable_raw_mode();
    let _ = execute!(stdout(), DisableBracketedPaste, DisableMouseCapture, LeaveAlternateScreen, crossterm::cursor::Show);
}

/// Restores the terminal before the panic message (release builds abort, so Drop never runs).
fn install_panic_hook() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            restore();
            prev(info);
        }));
    });
}
