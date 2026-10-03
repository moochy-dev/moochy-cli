//! Test renderer shared by every view's tests.

use ratatui::Terminal;
use ratatui::backend::TestBackend;

use crate::model::Snapshot;
use crate::theme::{Depth, Theme};
use crate::views::{Ctx, View};

pub const NOW: u64 = 1_790_000_000_000;

/// Dark truecolor, light truecolor, no-colour ASCII.
pub fn themes() -> [Theme; 3] {
    [
        Theme { depth: Depth::TrueColor, dark: true, ascii: false },
        Theme { depth: Depth::TrueColor, dark: false, ascii: false },
        Theme { depth: Depth::NoColor, dark: false, ascii: true },
    ]
}

pub fn theme(ascii: bool) -> Theme {
    Theme { depth: Depth::TrueColor, dark: true, ascii }
}

pub fn ctx<'a>(snap: &'a Snapshot, theme: &'a Theme, filter: &'a str) -> Ctx<'a> {
    Ctx { snap, theme, filter, now_ms: NOW, fresh_ms: u64::MAX }
}

/// Renders `view` at w×h and returns the screen as text lines; asserts no control bytes and, in
/// `--ascii`, no non-ASCII glyph (sanitized U+FFFD aside).
pub fn draw(view: &mut dyn View, c: &Ctx, w: u16, h: u16) -> String {
    let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
    term.draw(|f| {
        view.render(f, f.area(), c);
        if c.theme.ascii {
            crate::widgets::asciify(f.buffer_mut());
        }
    })
    .unwrap();
    let buf = term.backend().buffer();
    let out: Vec<String> = (0..h).map(|y| (0..w).map(|x| buf[(x, y)].symbol().to_owned()).collect()).collect();
    let out = out.join("\n");
    if std::env::var_os("TUI_DUMP").is_some() {
        eprintln!("{w}x{h} dark={} ascii={}\n{out}", c.theme.dark, c.theme.ascii);
    }
    assert!(!out.chars().any(|ch| ch.is_control() && ch != '\n'), "control byte on screen:\n{out}");
    if c.theme.ascii {
        assert!(out.chars().all(|ch| ch.is_ascii() || ch == '\u{FFFD}'), "non-ASCII in --ascii:\n{out}");
    }
    out
}

/// The maintainer tabs' fixture: claimed projects (one paused, one hostile), an org, requests.
pub fn maint_fixture() -> Snapshot {
    use crate::model::{CoveredRepo, Decision, Me, Org, Pending, Project};
    const DAY: u64 = 86_400_000;
    Snapshot {
        me: Me { handle: "maya".into(), relay: "relay.moochy.dev".into(), web: "https://moochy.dev".into(), connected: true, ..Me::default() },
        projects: vec![
            Project { id: "r_1".into(), slug: "github/acme/widget".into(), donors: 3, pending: 1, month_uusd: 12_000_000, goal_uusd: 50_000_000, members: vec!["maya".into(), "bo".into()], funded_by: vec!["github/acme".into()], paused_since_ms: 0, per_day_uusd: vec![] },
            Project { id: "r_2".into(), slug: "github/acme/gadget".into(), donors: 0, pending: 0, month_uusd: 0, goal_uusd: 0, members: vec![], funded_by: vec![], paused_since_ms: NOW - 31 * DAY, per_day_uusd: vec![] },
            Project { id: "r_3".into(), slug: "github/acme/\u{1b}]52;c;evil\u{7}tool".into(), ..Project::default() },
        ],
        orgs: vec![Org { id: "o_1".into(), path: "github/acme".into(), covered: vec![CoveredRepo { slug: "github/acme/widget".into(), used_uusd: 3_000_000, share_cap_uusd: 10_000_000 }], donors: 2, month_uusd: 3_000_000, paused_since_ms: 0, per_day_uusd: vec![0, 1_000_000, 2_000_000], person: false }],
        pending: vec![
            Pending { request_id: "pl_01J".into(), kind: "donor".into(), target: "github/acme/widget".into(), subject: "\u{1b}[31malice".into(), summary: "$20.00/month, ≤ $0.50/request, claude-sonnet".into(), created_at_ms: NOW - 3 * 3_600_000, decide_url: String::new() },
            Pending { request_id: "pl_02K".into(), kind: "donor".into(), target: "github/acme".into(), subject: "carol".into(), summary: "$100.00/month".into(), created_at_ms: NOW - DAY, decide_url: String::new() },
        ],
        decisions: vec![
            Decision { at_ms: NOW - 2 * DAY, target: "github/acme/widget".into(), donor: "dave".into(), event: "accepted".into(), via: "passkey".into(), reason: String::new() },
            Decision { at_ms: NOW - DAY, target: "github/acme/widget".into(), donor: "eve".into(), event: "refused".into(), via: "cli".into(), reason: "not now".into() },
        ],
        ..Snapshot::default()
    }
}
