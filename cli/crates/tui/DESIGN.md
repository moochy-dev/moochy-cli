# moochy tui: design

The terminal dashboard (CONTRACT §20). This file records what we took from the best TUIs, how the
shell behaves, and how a tab plugs in. Owner: mo-tui.

## What we took from whom

| From | What we took | What we left out |
|---|---|---|
| **lazygit** | A context-sensitive footer key bar. `?` help generated from the same binding table. `/` filters the focused list. The focused pane gets the accent border. Mouse on by default. | Nerd-font icons (they need a patched font). |
| **k9s** | `:` command mode as the way to jump anywhere. Esc always leaves a mode. Filters survive live refreshes. The cursor is kept by key, not by row. | The 2 s polling. We are event-driven. |
| **btop** | A truecolor → 256 → 16 colour ladder. A real tty gets ASCII. Meters always print their number. | A fixed refresh tick and braille graphs. Block sparklines read better at small sizes and have an ASCII set. |
| **gitui** | Tabs with number keys. Defaults that work on light *and* dark terminals. Async work off the UI thread. | — |
| **yazi** | All I/O off the render path: the source runs on a worker thread and the UI renders from a snapshot. | Plugins. |
| **helix** | A fuzzy palette over every command, with the key shown next to each entry. Light and dark detected, with a manual override. A palette of 16 terminal colours as the floor. | Modal editing. |
| **bottom** | A grid of tiles that collapses by size, and a "too small" screen instead of clipping. | — |

## The shell

```
 ◖•ᴗ•◗ moochy · @alice                      ◆ 3 pending  ▲ 2 alerts  ● relay  ● node   ← header
 1 Overview 2 Donations 3 Served 4 Projects 5 Orgs 6 Decisions 7 Devices 8 Activity …  ← tabs + /chip
╭ Donations · 4 · $70.17 spent this month ──╮╭ project github/tokio-rs/axum ───────╮
│ ▶ ✔ active   github/tokio-rs/axum  $27.42 ││ Status     ✔ active  …              │  ← focused list | detail
╰───────────────────────────────────────────╯╰─────────────────────────────────────╯
 p pause/resume  - lower limit  x stop  / filter  : commands  q quit  ? help            ← footer
```

- **Header.** The hamster's face reacts to events (`•ᴗ•` calm, `^ᴗ^` for 4 s after a new request, `-ᴗ-` when the node is unreachable), with blush cheeks. Then the user, and on the right the pending count, alerts, relay and node status. Each status is a glyph plus a word. Items drop from the left when space runs out.
- **Tabs.** Number keys `1`–`9`, `Tab`/`Shift-Tab`, `]`/`[`, or a mouse click. The labels change level **together**, so the bar never jumps when the active tab changes:
  1. full titles;
  2. the designed medium labels (`Orgs`, `Devices`);
  3. short labels (`Home Given Served Repos Orgs Decide Keys Log Settings`);
  4. numbers only.

  The active `/` filter shows as a butter chip on the right and takes only its own width.
- **Footer.** It shows the tab's `hints()`, then the globals. `q quit` and `? help` always stay. A key the shell owns, or one that is already listed, is never repeated. Items that don't fit are dropped, never cut.
- **Letters go to the tab first.**
  - `r` refuses a request in Projects, Organisations and Decisions.
  - Where a tab has no use for `r`, `[` or `]`, the shell takes them (refresh, previous/next tab). `Ctrl-R` always refreshes.
  - The shell owns `q ? : /`, the digits and Tab.
  - A key that does not apply to the selected row says why in a toast. It never does nothing silently.
- **Overlays:**
  - `?` help: two columns at 76 columns and wider, one scrolling column otherwise. It is generated from `GLOBAL_KEYS` and the tab's hints, each key listed once.
  - `:`/`Ctrl-K` palette: fuzzy over tab jumps, every tab's keys (picking one opens that tab, then presses the key), theme toggles, refresh, suspend and quit. When nothing matches, it says what was searched.
  - Confirm dialog. The body is sanitized line by line, so the owner-key consent screen keeps its layout. `` `code` `` shows as a key. **No** is focused by default; `y` runs, `n`/Esc cancels.
  - Text dialog (`Outcome::Prompt`). Used for the refuse reason and the new monthly limit. Typing is bounded by `max_len` and sanitized. A paste lands in the field (first line only) and never submits. Enter checks the text (`Then::submit`) and shows the error in place, or goes on to the confirmation.
  - Toasts, bottom-right inside the pane (never on a border). They are event-driven and expire after 4 s; the loop wakes for the expiry only while a toast is shown.
- **Too small.** Under 60×15 the app shows one sentence saying so. The designed range is 80×24 and wider. It is tested at 80×24, 100×30 and 160×48.

## One toolkit (`widgets/`)

Every tab draws with the same pieces, so the app reads as one product:

- **Panels.**
  - `block(t, title)`: rounded (`+-|` in ASCII), muted border, 1-cell padding, ` Title `.
  - `block_focus` is the list the keys move in: Mint border, accent title.
  - `counted(title, shown, total)` gives `Donations · 4`, or `· 2/4` while filtered.
  - `empty(f, area, t, title, lines)` is an empty state that says what to do next. `no_match` covers a filter that hides every row.
  - `split(area, rows)` gives list + detail: side by side from 110 columns, stacked when tall, list only when small.
- **Status.**
  - `badge(t, Tone, glyph, label)` and `status(t, word)` / `status_glyph(word)` produce glyph + word. The colour (`Tone`) only repeats the meaning.
  - Glyphs come from `Theme::glyph`: `✔ ‖ ■ ✖ ◆ ▲ ● ○ ↑ ↓ ◉ ▶`, with ASCII twins `+ = # x ~ ! * o ^ v $ >`.
- **Text.**
  - `kv` / `kv_span` give `Label      value` rows for details.
  - `col(span, w)` makes a fixed-width column in a list line.
  - `trunc` and `list::fit` cut with `…`, so nothing is silently clipped. `list::table_widths` gives the cell widths a table will get.
  - `short_slug` drops the forge prefix when the slug does not fit.
- **Money.** `dollars` has 2 decimals and prints `<$0.01` under a cent; lists and totals use it. `cost` has 4 decimals under a dollar and is used only in detail panes. Plus `tokens`, `latency`, `ago` (compact) / `ago_long` (`5m ago`), `until`, `date`, `datetime`, `percent`.
- **Charts.**
  - `charts::meter` is a bar plus a percentage, always written: mint, then butter from 80 %, coral at 100 %.
  - `charts::bar` is a dollar cap with no percentage (§19.5).
  - `charts::sparkline` is the widget; `charts::spark_text` is one row inside a paragraph.
  - `charts::resample` keeps a chart's period fixed (30 days, 60 minutes) at any width.
- **Lists.**
  - `TableCursor` is a cursor over a ratatui `Table` with a header row. `set_headers` marks section rows it never rests on.
  - `TreeList` + `TreeRow { header, depth, line, key }` is an indented list with its detail pane.
  - Selection looks the same everywhere: Ink on Mint, `▶`.
- **Filtering.** `matches(filter, fields)` is the one fuzzy matcher behind every `/`; `fuzzy::score` ranks the palette.
- **Links.** `web_origin(me.web)` is the validated public origin (falls back to `https://moochy.dev`). `decide_url(web, given, id)` is the passkey page. Share links (§9: `/p/…`, `/org/…`, `/people/…`) use `Me.web`, never `Me.relay`.
- **ASCII.** `asciify` runs on the finished frame in `--ascii`: any non-ASCII symbol a tab still draws becomes its stand-in (`…`→`~`, `·`→`-`, arrows, U+FFFD→`?`).

## Colour

DESIGN.md's mint palette, mapped for terminals (`theme.rs`):

- **No background painting.** The user's terminal background stays.
- **Each hue is a foreground in both modes.** Dark terminals get the pastel fills: Mint `#7DD3AE`, Sky, Butter, Coral-soft, Blush. Light terminals get the deep variants: Mint-deep `#1A6B4A`, Sky-deep, Butter-deep, Coral-deep, Blush-deep. These are the DESIGN.md §2 contrast pairs. There are no chips with a fill, so no low-contrast text-on-fill.
- **Selection and the active tab** are the only fill: Ink on Mint (9.0:1). Table and list highlights override every span's colour on that row. Without colour they are reverse video plus bold.
- **Depth** comes from `NO_COLOR` (non-empty means none), then `COLORTERM=truecolor|24bit`, then `TERM=*256*`, then 16 colours. `TERM=dumb` means none. You can cycle it at runtime from the palette or from Settings.
- **Light or dark** comes from `--theme`, then `MOOCHY_THEME`, then the background index in `COLORFGBG` (7 or 15 = light), and defaults to dark. (ponytail: no OSC 11 query. It races with the input reader and costs up to 100 ms on terminals that never answer. Add it with a DA1 fence if users ask.)

## Security (A273–A276, E121)

- **`sanitize::clean` on every peer string:**
  - a whole escape sequence (CSI, OSC, DCS, SOS, PM, APC, and their C1 forms) becomes **one** U+FFFD, with no payload left behind;
  - other controls and U+2028/2029 become U+FFFD;
  - Unicode Cf (bidi, zero-width, soft hyphen, tags…) is dropped;
  - variation selectors after the first are dropped;
  - combining marks are capped at 2 per base;
  - text is capped at 2048 characters.
- **We only ever emit SGR colours.** No titles, hyperlinks or OSC 52 (tested on the hostile world). A paste never confirms a dialog (tested).
- **A273 (a `Clean` newtype) is not done.** It only helps if every sink (ratatui `Span`/`Cell`) required it, which means wrapping ratatui. Instead, the hostile fixture (`--hostile`) runs through every tab in tests and E121.

## Live updates and budgets

- There is one bounded `sync_channel(256)` of `AppEvent`, fed by:
  - the input thread (crossterm)
  - the source worker (snapshots, action results, `Source::tick` for push-less sources: the demo adds a request every 3 s)
  - NodeSource's watch stream
  - the signal thread
- The main thread blocks in `recv`, handles that event plus everything already queued, then draws **once**. ratatui diffs against the previous buffer, so there is no flicker.
- Idle means one blocked `recv` and zero allocation. The input thread wakes every 250 ms in `poll`. That timeout exists only so it can be paused when a child process needs the terminal.
- The first frame is drawn before the first snapshot arrives (header shows `◌ connecting…`).

## Exit paths (the terminal is always restored)

| Path | How |
|---|---|
| `q`, Ctrl-C | The loop breaks and the `Guard` drop restores the terminal. |
| An error | The `Guard` drop restores the terminal. |
| A panic | The panic hook restores the terminal *before* the message. Release builds abort, so `Drop` never runs. Tested in `tests/pty.rs`. |
| SIGTERM, SIGHUP, SIGINT | The signal thread sends `Quit`. |
| Ctrl-Z, SIGTSTP | Pause input, leave the terminal, `raise(SIGSTOP)`. On continue, re-enter and repaint in full. |
| SIGCONT | Re-enter and repaint in full. |
| `ActionResult::Terminal(args)` | Same as suspend, but runs `moochy <args>` in the foreground, so the CLI's passphrase prompt and decoded-body + Lookup checks stay unchanged (A217/A218). It then waits for Enter, resumes and refreshes. Tested in `tests/pty.rs`: the CLI reads the whole passphrase. |

## Writing a tab

```rust
#[derive(Default)]
pub struct DonationsView { cur: TableCursor }

impl View for DonationsView {
    fn title(&self) -> &'static str { "Donations" }
    fn labels(&self) -> (&'static str, &'static str) { ("Donations", "Given") }
    fn hints(&self) -> &'static [(&'static str, &'static str)] { &[("p", "pause/resume"), ("-", "lower limit")] }
    fn render(&mut self, f: &mut Frame, area: Rect, ctx: &Ctx) {
        let t = *ctx.theme;
        let rows: Vec<_> = ctx.snap.donations.iter().filter(|d| w::matches(ctx.filter, &[&d.target])).collect();
        let (list, detail) = if rows.is_empty() { (area, None) } else { w::split(area, 14) };
        self.cur.sync(rows.len(), list);
        // Table rows: w::badge / w::status cells, list::fit or w::trunc for text, w::dollars for money;
        // .row_highlight_style(t.selected()).highlight_symbol(list::marker(t)).block(w::block_focus(t, w::counted(…)))
    }
    fn on_input(&mut self, input: &Input, ctx: &Ctx) -> Outcome {
        if self.cur.on_input(input) { return Outcome::Redraw; }
        // Outcome::Confirm for a state change, Outcome::Prompt for text, Outcome::Toast when a key does not apply.
        Outcome::Ignored
    }
}
```

**Rules for tabs:**

- Every peer string goes through `clean` (`kv`/`badge` take clean text).
- Never rely on colour alone.
- Every state change goes through `Outcome::Confirm`.
- Text input goes through `Outcome::Prompt`.
- `j/k`, arrows, `g/G`, PgUp/PgDn and Enter arrive as `Input::*`; other letters arrive as `Input::Char`.

## Snapshot mode and tests

- **Snapshot mode.** `moochy tui --demo[=empty] --snapshot 80x24 --keys "2jj<enter>" [--theme light] [--ascii] [--ansi] [--hostile]`, or `cargo run -p moochy-tui --example demo -- …`. The clock is fixed (2026-10-03 14:05 UTC), truecolor, and makes no environment lookups, so the output is stable byte for byte.
- **Keys.** Characters as typed (spaces are ignored). Named keys: `<enter> <esc> <tab> <s-tab> <up> <down> <left> <right> <pgup> <pgdn> <home> <end> <bs> <space> <lt> <c-x> <click:COL,ROW>`.
- **`tests/snapshots/`.** Every tab at 80×24 and 160×48: dark and ASCII as text, light as ANSI. `UPDATE_SNAPSHOTS=1 cargo test -p moochy-tui --test golden` regenerates them; review the diff.
- **`tests/pty.rs`.** Real PTY tests of the panic hook and the CLI hand-off.
