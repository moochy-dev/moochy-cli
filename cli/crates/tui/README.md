# moochy-tui

`moochy tui` (or just `moochy`): the terminal dashboard of the Moochy app. It has tabs for
Overview, Donations (monthly, weekly and daily limits, and what is left), Served requests,
Devices & keys, Activity, Projects, Organisations, Decisions and Settings.

- Elm-style: `App` owns a `Snapshot` from a `Source`. Events go to the focused view, and it
  renders only after an event, with no busy loop.
- Every string from the server or a peer goes through `sanitize::clean`, so remote text cannot
  inject terminal escape sequences.
- Light and dark themes, an ASCII mode, and a deterministic snapshot mode
  (`moochy tui --snapshot 120x40`) used by the golden tests in `tests/snapshots/`.
- `moochy tui --demo` runs on fixture data, with no account needed.

Test: `cargo test -p moochy-tui`. License: Apache-2.0. Part of
[moochy-cli](https://github.com/moochy-dev/moochy-cli).
