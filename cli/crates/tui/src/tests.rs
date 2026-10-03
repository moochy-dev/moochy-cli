//! Shell tests on ratatui's TestBackend through the snapshot mode (the same path E118 uses).

use crate::{Options, demo_source, fixtures, snapshot};

fn snap(size: (u16, u16), keys: &str, f: impl Fn(&mut Options)) -> String {
    let mut o = Options { snapshot: Some(size), keys: keys.into(), demo: true, ..Options::default() };
    f(&mut o);
    snapshot(&mut demo_source(), &o).unwrap()
}

fn assert_shell(frame: &str, size: (u16, u16), what: &str) {
    let lines: Vec<&str> = frame.lines().collect();
    assert_eq!(lines.len(), usize::from(size.1), "{what}: row count\n{frame}");
    for l in &lines {
        assert!(crate::app::tests_width(l) <= usize::from(size.0), "{what}: line too wide: {l:?}");
        assert!(!l.chars().any(char::is_control), "{what}: control char in {l:?}");
    }
    assert!(lines[0].contains("moochy"), "{what}: header\n{frame}");
    assert!(lines[1].contains("1 "), "{what}: tab bar\n{frame}");
    assert!(lines.last().unwrap().contains("help"), "{what}: footer\n{frame}");
}

#[test]
fn every_tab_every_size_every_theme() {
    for size in [(80, 24), (160, 48), (100, 30)] {
        for tab in 1..=9 {
            for (name, setup) in [
                ("dark", (|_: &mut Options| {}) as fn(&mut Options)),
                ("light", |o: &mut Options| o.theme = Some("light".into())),
                ("ascii", |o: &mut Options| o.ascii = true),
            ] {
                let frame = snap(size, &tab.to_string(), setup);
                assert_shell(&frame, size, &format!("tab {tab} {name} {size:?}"));
                if name == "ascii" {
                    assert!(frame.is_ascii() || !frame.contains('╭'), "ascii borders: {frame}");
                }
            }
        }
    }
}

#[test]
fn overlays_render() {
    let help = snap((80, 24), "?", |_| {});
    assert!(help.contains("Help"), "{help}");
    assert!(help.contains("command palette"), "{help}");
    let pal = snap((80, 24), ":don", |_| {});
    assert!(pal.contains("Go to Donations"), "{pal}");
    let jumped = snap((80, 24), ":serv<enter>", |_| {});
    assert!(jumped.lines().nth(1).unwrap().contains("Served"), "{jumped}");
    let filt = snap((80, 24), "/axum", |_| {});
    assert!(filt.lines().last().unwrap().contains("/axum"), "{filt}");
}

#[test]
fn tabs_by_number_tab_key_and_mouse() {
    let f = snap((160, 48), "<tab><tab>", |_| {});
    assert!(f.lines().nth(1).unwrap().contains("3 Served"));
    // Click the second tab label on row 1.
    let f = snap((160, 48), "<click:14,1>", |_| {});
    assert!(f.contains("Donations"), "{f}");
}

#[test]
fn tiny_terminal_says_so() {
    let f = snap((40, 10), "", |_| {});
    assert!(f.contains("at least 60×15"), "{f}");
}

#[test]
fn ansi_mode_has_colours_and_text_mode_none() {
    let a = snap((80, 24), "", |o| o.ansi = true);
    assert!(a.contains("\u{1b}[0;1;38;2;125;211;174m"), "mint bold expected");
    let t = snap((80, 24), "", |_| {});
    assert!(!t.contains('\u{1b}'));
}

#[test]
fn hostile_strings_render_inert() {
    for tab in 1..=9 {
        let o = Options { snapshot: Some((160, 48)), keys: tab.to_string(), hostile: true, demo: true, ..Options::default() };
        let f = snapshot(&mut fixtures::hostile(), &o).unwrap();
        assert!(!f.chars().any(|c| c.is_control() && c != '\n'), "tab {tab}: {f:?}");
        assert!(!f.contains('\u{202E}'));
    }
}

#[test]
fn options_fail_closed() {
    let p = |a: &[&str]| Options::parse(&a.iter().map(|s| (*s).to_string()).collect::<Vec<_>>());
    assert!(p(&["--demo", "--snapshot", "80x24", "--keys", "2j<enter>"]).is_ok());
    assert!(p(&["--snapshot=160x48", "--theme=light", "--ascii", "--ansi"]).is_ok());
    assert!(p(&["--bogus"]).is_err());
    assert!(p(&["--theme", "pink"]).is_err());
    assert!(p(&["--snapshot", "9999x1"]).is_err());
    assert!(p(&["--keys", "<nope>", "--snapshot", "80x24"]).is_err());
    assert!(p(&["--keys", "j"]).is_err());
}

#[test]
fn hostile_ansi_frames_emit_only_colour_sequences() {
    // A276: the only escape sequences we ever write are SGR colours: no title, no hyperlink, no
    // OSC 52 clipboard write, no DCS, whatever the peer data says.
    for tab in 1..=9 {
        let o = Options { snapshot: Some((160, 48)), keys: tab.to_string(), hostile: true, demo: true, ansi: true, ..Options::default() };
        let f = snapshot(&mut fixtures::hostile(), &o).unwrap();
        let mut rest = f.as_str();
        while let Some(i) = rest.find('\u{1b}') {
            rest = &rest[i + 1..];
            assert!(rest.starts_with('['), "tab {tab}: non-CSI escape");
            let end = rest.find('m').expect("SGR ends with m");
            assert!(rest[1..end].chars().all(|c| c.is_ascii_digit() || c == ';'), "tab {tab}: non-SGR CSI {:?}", &rest[..=end]);
        }
    }
}

#[test]
fn a_paste_never_confirms_a_dialog() {
    use crossterm::event::Event;

    use crate::app::{App, AppEvent};
    use crate::source::{Action, SourceEvent};
    use crate::theme::Theme;

    // A275: in a confirm dialog a paste does nothing (not even "y\n"); in a text dialog it lands in
    // the field (first line only) and never submits.
    let mut app = App::new(Theme::default(), fixtures::DEMO_NOW_MS);
    app.on_event(AppEvent::Source(SourceEvent::Snapshot(Box::new(fixtures::demo()))));
    let keys = |app: &mut App, s: &str| {
        for e in crate::snapshot::parse_keys(s).unwrap() {
            app.on_event(AppEvent::Term(e));
        }
    };
    let mut term = ratatui::Terminal::new(ratatui::backend::TestBackend::new(100, 30)).unwrap();
    keys(&mut app, "2");
    term.draw(|f| app.render(f)).unwrap();
    keys(&mut app, "x"); // stop → confirm
    app.on_event(AppEvent::Term(Event::Paste("y\ny\r".into())));
    assert!(app.take_actions().is_empty(), "a paste confirmed a dialog");
    keys(&mut app, "<esc>-"); // lower the limit → text dialog
    app.on_event(AppEvent::Term(Event::Paste("30\nrm -rf\r".into())));
    assert!(app.take_actions().is_empty(), "a paste submitted a text dialog");
    term.draw(|f| app.render(f)).unwrap();
    let screen = crate::snapshot::to_text(term.backend().buffer());
    assert!(screen.contains("> 30") && !screen.contains("rm -rf"), "{screen}");
    keys(&mut app, "<enter>y");
    assert_eq!(app.take_actions(), vec![Action::LowerDonation { id: "don_7f3a".into(), budget_uusd: 30_000_000 }]);
}

#[test]
fn keys_typed_before_the_first_snapshot_are_kept() {
    use crate::app::{App, AppEvent};
    use crate::source::SourceEvent;
    use crate::theme::Theme;

    let mut app = App::new(Theme::default(), fixtures::DEMO_NOW_MS);
    for e in crate::snapshot::parse_keys("4").unwrap() {
        app.on_event(AppEvent::Term(e));
    }
    assert_eq!(app.active(), 0, "held while connecting");
    app.on_event(AppEvent::Source(SourceEvent::Snapshot(Box::new(fixtures::demo()))));
    assert_eq!(app.active(), 3, "replayed once the data is there");
}
