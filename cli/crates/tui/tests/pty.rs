//! The real loop on a real pseudo-terminal (util-linux `script`): the terminal is restored by the
//! panic hook before the panic message, and an owner-key action hands the terminal to the CLI
//! (it gets every keystroke, the dashboard comes back after Enter). Linux only (BSD `script`
//! differs; the integrator's Mac run covers macOS by hand).
//!
//! The test binary re-executes itself: `MOOCHY_TUI_PTY=1` turns the `child_*` tests into the
//! programs under test; without it they return at once.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use moochy_tui::model::Snapshot;
use moochy_tui::source::{Action, ActionResult, FakeSource, Source};
use moochy_tui::views::{Ctx, Input, Outcome, View};
use moochy_tui::{Options, demo_source};
use ratatui::Frame;
use ratatui::layout::Rect;

const CHILD: &str = "MOOCHY_TUI_PTY";

fn child() -> bool {
    std::env::var(CHILD).is_ok_and(|v| v == "1")
}

/// Runs `test` of this binary under `script`, feeding `steps` (wait for text, then type).
fn drive(test: &str, steps: &[(&str, &str)]) -> Option<(String, bool)> {
    if !cfg!(target_os = "linux") || Command::new("script").arg("--version").output().is_err() {
        eprintln!("skip: util-linux `script` not available");
        return None;
    }
    let exe = std::env::current_exe().unwrap();
    // `script` gives the pty no size of its own: set one, as a real terminal would have.
    let cmd = format!("stty cols 100 rows 30 && {} --exact {test} --nocapture --test-threads=1", exe.display());
    let mut p = Command::new("script")
        .args(["-qfec", &cmd, "/dev/null"])
        .env(CHILD, "1")
        .env("TERM", "xterm-256color")
        .env("COLUMNS", "100")
        .env("LINES", "30")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let out = Arc::new(Mutex::new(Vec::<u8>::new()));
    let mut so = p.stdout.take().unwrap();
    let o = out.clone();
    std::thread::spawn(move || {
        let mut b = [0u8; 4096];
        while let Ok(n) = so.read(&mut b) {
            if n == 0 {
                break;
            }
            o.lock().unwrap().extend_from_slice(&b[..n]);
        }
    });
    let mut stdin = p.stdin.take().unwrap();
    let mut seen = 0usize;
    for (want, keys) in steps {
        let t0 = Instant::now();
        loop {
            let text = String::from_utf8_lossy(&out.lock().unwrap()).into_owned();
            if let Some(i) = text.get(seen..).and_then(|rest| rest.find(want)) {
                seen += i + want.len();
                break;
            }
            assert!(t0.elapsed() < Duration::from_secs(10), "timed out waiting for {want:?}:\n{text}");
            std::thread::sleep(Duration::from_millis(20));
        }
        std::thread::sleep(Duration::from_millis(150));
        stdin.write_all(keys.as_bytes()).unwrap();
        stdin.flush().unwrap();
    }
    let t0 = Instant::now();
    let ok = loop {
        if let Some(s) = p.try_wait().unwrap() {
            break s.success();
        }
        if t0.elapsed() > Duration::from_secs(10) {
            let _ = p.kill();
            break false;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    std::thread::sleep(Duration::from_millis(100));
    let text = String::from_utf8_lossy(&out.lock().unwrap()).into_owned();
    Some((text, ok))
}

/// A tab that panics while drawing once it has seen `p`.
#[derive(Default)]
struct Boom(bool);

impl View for Boom {
    fn title(&self) -> &'static str {
        "Boom"
    }
    fn hints(&self) -> &'static [(&'static str, &'static str)] {
        &[("p", "panic")]
    }
    fn render(&mut self, f: &mut Frame, area: Rect, _ctx: &Ctx) {
        assert!(!self.0, "boom: a view panicked while drawing");
        f.render_widget(ratatui::widgets::Paragraph::new("READY-TO-BOOM"), area);
    }
    fn on_input(&mut self, input: &Input, _ctx: &Ctx) -> Outcome {
        self.0 = *input == Input::Char('p');
        Outcome::Redraw
    }
}

#[test]
fn child_boom() {
    if !child() {
        return;
    }
    let src = FakeSource::new(Snapshot::default(), 0);
    let _ = moochy_tui::run_views(Box::new(src), None, &Options::default(), vec![Box::new(Boom::default())]);
}

#[test]
fn panic_restores_the_terminal_before_the_message() {
    let Some((out, _)) = drive("child_boom", &[("READY-TO-BOOM", "p")]) else { return };
    let enter = out.find("\u{1b}[?1049h").expect("alternate screen entered");
    let msg = out.find("boom: a view panicked").expect("the panic message is printed");
    let leave = out[enter..].find("\u{1b}[?1049l").map(|i| i + enter).expect("alternate screen left");
    assert!(leave < msg, "the hook restores the terminal before the message is printed:\n{out:?}");
    let raw_off = out[enter..].find("\u{1b}[?1000l").map(|i| i + enter).expect("mouse capture off");
    assert!(raw_off < msg, "{out:?}");
}

/// The demo world, with the owner-key accept handed to this binary's `child_cli` test (it plays
/// `moochy accept`: reads a passphrase from the terminal).
struct Handoff(FakeSource);

impl Source for Handoff {
    fn snapshot(&mut self) -> Result<Snapshot, String> {
        self.0.snapshot()
    }
    fn act(&mut self, action: Action) -> ActionResult {
        match action {
            Action::Accept { .. } => ActionResult::Terminal(vec!["--exact".into(), "child_cli".into(), "--nocapture".into(), "--test-threads=1".into()]),
            a => self.0.act(a),
        }
    }
    fn now_ms(&self) -> u64 {
        self.0.now_ms()
    }
}

#[test]
fn child_tui() {
    if !child() {
        return;
    }
    let _ = moochy_tui::run(Box::new(Handoff(demo_source())), None, &Options::default());
}

#[test]
fn child_cli() {
    if !child() {
        return;
    }
    print!("PASSPHRASE? ");
    std::io::stdout().flush().unwrap();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).unwrap();
    println!("CLI GOT {} chars", line.trim_end().len());
}

#[test]
fn terminal_handoff_gives_the_cli_every_keystroke() {
    let Some((out, ok)) = drive(
        "child_tui",
        &[
            ("Latest requests", "4"),
            ("Projects", "j"),
            ("@grace", "a"),
            ("Accept this request?", "y"),
            ("PASSPHRASE?", "hunter2\n"),
            ("Press Enter to return", "\n"),
            (": done", "q"),
        ],
    ) else {
        return;
    };
    assert!(ok, "exits 0 on q:\n{out:?}");
    let leave = out.find("PASSPHRASE?").and_then(|p| out[..p].rfind("\u{1b}[?1049l")).expect("left the alternate screen before the CLI ran");
    let got = out.find("CLI GOT 7 chars").expect("the CLI read the whole passphrase: the dashboard did not eat it");
    let back = out[got..].find("\u{1b}[?1049h").map(|i| i + got).expect("the dashboard came back");
    assert!(leave < got && got < back, "{out:?}");
    assert!(out[back..].contains(": done"), "the result toast shows after resuming");
}
