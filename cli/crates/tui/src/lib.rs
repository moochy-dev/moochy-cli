//! `moochy tui`: the terminal dashboard of Moochy (CONTRACT §20).
//!
//! Elm-style: [`app::App`] owns the [`model::Snapshot`] it got from a [`source::Source`] and the
//! [`views::View`] of each tab; events (keys, mouse, resize, source updates) go to the focused
//! view, which returns an [`views::Outcome`]. Rendering only happens after an event (no busy loop).
//! Every string that came from the server or a peer goes through [`sanitize::clean`] first.
//!
//! Entry points for the `moochy` binary (the node crate implements `NodeSource`):
//! [`Options::parse`], [`run`] (interactive), [`snapshot`] (deterministic text), [`demo_source`].
//!
//! Owners (CONTRACT §20.5): `mo-tui` — app, theme, shell, widgets, sources, snapshot mode,
//! Overview and Settings; `mo-tui-donor` — Donations, Served, Devices & keys, Activity;
//! `mo-tui-maint` — Projects, Organisations, Decisions.
#![forbid(unsafe_code)]
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects)
)]

pub mod app;
pub mod fixtures;
pub mod model;
pub mod sanitize;
pub mod snapshot;
pub mod source;
mod term;
pub mod theme;
pub mod views;
pub mod widgets;

#[cfg(test)]
mod tests;

pub use fixtures::demo_source;
pub use snapshot::snapshot;
pub use term::{run, run_views};

/// `moochy tui` flags (CONTRACT §20.4).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Options {
    /// `--demo`: fixtures instead of `node.sock`.
    pub demo: bool,
    /// `--hostile`: the demo world with escape sequences in every peer string (E121); implies demo.
    pub hostile: bool,
    /// `--demo=empty`: a brand-new account (every empty state).
    pub empty: bool,
    /// `--snapshot COLSxROWS`: print one frame and exit.
    pub snapshot: Option<(u16, u16)>,
    /// `--keys "…"`: the key script played before the snapshot ([`snapshot`] module docs).
    pub keys: String,
    /// `--theme light|dark` (default: detected).
    pub theme: Option<String>,
    /// `--ascii`: ASCII borders and glyphs.
    pub ascii: bool,
    /// `--ansi`: the snapshot keeps its colours as SGR sequences.
    pub ansi: bool,
}

pub const USAGE: &str = "moochy tui [--demo[=empty]] [--theme light|dark] [--ascii] [--snapshot COLSxROWS [--keys \"…\"] [--ansi]]";

impl Options {
    /// Parses the flags after `tui` (fails closed on anything unknown).
    pub fn parse(args: &[String]) -> Result<Options, String> {
        let mut o = Options::default();
        let mut it = args.iter();
        while let Some(a) = it.next() {
            let (flag, inline) = match a.split_once('=') {
                Some((f, v)) if f.starts_with("--") => (f, Some(v.to_string())),
                _ => (a.as_str(), None),
            };
            let mut value = || inline.clone().or_else(|| it.next().cloned()).ok_or(format!("{flag} needs a value\nusage: {USAGE}"));
            match flag {
                "--demo" => match inline.as_deref() {
                    None => o.demo = true,
                    Some("empty") => (o.demo, o.empty) = (true, true),
                    Some(v) => return Err(format!("--demo takes no value or =empty, not {}", sanitize::clean(v))),
                },
                "--hostile" => (o.demo, o.hostile) = (true, true),
                "--ascii" => o.ascii = true,
                "--ansi" => o.ansi = true,
                "--snapshot" => o.snapshot = Some(snapshot::parse_size(&value()?)?),
                "--keys" => {
                    let k = value()?;
                    snapshot::parse_keys(&k)?;
                    o.keys = k;
                }
                "--theme" => match value()?.as_str() {
                    t @ ("light" | "dark") => o.theme = Some(t.to_string()),
                    t => return Err(format!("--theme is light or dark, not {}", sanitize::clean(t))),
                },
                "-h" | "--help" => return Err(format!("usage: {USAGE}")),
                f => return Err(format!("unknown flag {}\nusage: {USAGE}", sanitize::clean(f))),
            }
        }
        if (o.ansi || !o.keys.is_empty()) && o.snapshot.is_none() {
            return Err("--keys and --ansi only go with --snapshot".into());
        }
        Ok(o)
    }
}

/// The demo (or hostile) fixture source for these options.
#[must_use]
pub fn fixture_source(opts: &Options) -> source::FakeSource {
    let mut s = if opts.hostile {
        fixtures::hostile()
    } else if opts.empty {
        source::FakeSource::new(model::Snapshot::default(), fixtures::DEMO_NOW_MS)
    } else {
        demo_source()
    };
    // Interactive demo only: snapshots stay byte-for-byte stable.
    s.live = opts.snapshot.is_none() && !opts.empty;
    s
}
