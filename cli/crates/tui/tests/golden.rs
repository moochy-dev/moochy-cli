//! Golden frames for every tab at 80×24 and 160×48 (CONTRACT §20.6, E118), committed under
//! `tests/snapshots/` so a reviewer can read them: `NN-tab-WxH.txt` holds the dark and the ASCII
//! frame as text (the light frame's text is the same, checked here), `NN-tab-WxH.light.ansi` the
//! light frame with its colours (`cat` it in a terminal).
//!
//! Regenerate after an intended change: `UPDATE_SNAPSHOTS=1 cargo test -p moochy-tui --test golden`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::path::PathBuf;

use moochy_tui::{Options, demo_source, snapshot};

const TABS: [&str; 9] = ["overview", "donations", "served", "projects", "orgs", "decisions", "devices", "activity", "settings"];

fn frame(tab: usize, size: (u16, u16), theme: &str, ascii: bool, ansi: bool) -> String {
    let o = Options { demo: true, snapshot: Some(size), keys: tab.to_string(), theme: Some(theme.into()), ascii, ansi, ..Options::default() };
    snapshot(&mut demo_source(), &o).unwrap()
}

#[test]
fn every_tab_matches_its_golden_frame() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/snapshots");
    let update = std::env::var_os("UPDATE_SNAPSHOTS").is_some();
    if update {
        std::fs::create_dir_all(&dir).unwrap();
    }
    let mut stale = Vec::new();
    for (i, name) in TABS.iter().enumerate() {
        let tab = i + 1;
        for size in [(80u16, 24u16), (160, 48)] {
            let dark = frame(tab, size, "dark", false, false);
            // Settings names the theme in use; every other tab differs only in colour.
            if *name != "settings" {
                assert_eq!(dark, frame(tab, size, "light", false, false), "{name}: light and dark differ only in colour");
            }
            let ascii = frame(tab, size, "dark", true, false);
            assert!(ascii.is_ascii(), "{name} {size:?}: --ascii frame has non-ASCII:\n{ascii}");
            let text = format!("# {name} {}x{} dark (light: same text)\n{dark}# {name} {}x{} --ascii\n{ascii}", size.0, size.1, size.0, size.1);
            let light = frame(tab, size, "light", false, true);
            let base = format!("{tab:02}-{name}-{}x{}", size.0, size.1);
            for (file, want) in [(format!("{base}.txt"), text), (format!("{base}.light.ansi"), light)] {
                let path = dir.join(&file);
                if update {
                    std::fs::write(&path, &want).unwrap();
                } else if std::fs::read_to_string(&path).ok().as_deref() != Some(want.as_str()) {
                    stale.push(file);
                }
            }
        }
    }
    assert!(stale.is_empty(), "frames changed: {stale:?}\nreview them with UPDATE_SNAPSHOTS=1 cargo test -p moochy-tui --test golden; git diff tests/snapshots");
}
