//! `moochy tui`: the terminal dashboard of Moochy (CONTRACT §20).
//!
//! Elm-style: [`app::App`] owns the [`model::Snapshot`] it got from a [`source::Source`] and the
//! [`views::View`] of each tab; events (keys, mouse, resize, source updates) go to the focused
//! view, which returns an [`views::Outcome`]. Rendering only happens after an event (no busy loop).
//! Every string that came from the server or a peer goes through [`sanitize::clean`] first.
//!
//! Owners (CONTRACT §20.5): `mo-tui` — app, theme, shell, widgets, sources, snapshot mode,
//! Overview and Settings; `mo-tui-donor` — Donations, Served, Devices & keys, Activity;
//! `mo-tui-maint` — Projects, Organisations, Decisions.
#![forbid(unsafe_code)]
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects)
)]

pub mod model;
pub mod sanitize;
pub mod source;
pub mod theme;
pub mod views;
pub mod widgets;
