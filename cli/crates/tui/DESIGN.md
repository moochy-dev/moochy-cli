# moochy tui: design

The terminal dashboard (CONTRACT §20). This file records what we took from the best TUIs and
how a view plugs into the shell. Owner: mo-tui.

## What we took from whom

| From | What we took | What we left out |
|---|---|---|
| **lazygit** | A context-sensitive footer key bar. `?` help generated from the same binding table. `/` filters the focused list. Mouse on by default. | Nerd-font icons (they need a patched font). |
| **k9s** | `:` command mode as the way to jump anywhere. Esc always leaves a mode. Filters survive live refreshes. The cursor is kept by key, not by row. | The 2 s polling. We are event-driven. |
| **btop** | A truecolor → 256 → 16 colour ladder. A real tty gets ASCII. Meters always print their number. | A fixed refresh tick and braille graphs. Block sparklines read better at small sizes and have an ASCII set. |
| **gitui** | Tabs with number keys. Defaults that work on light *and* dark terminals. Async work off the UI thread. | — |
| **yazi** | All I/O off the render path: the source runs on a worker thread and the UI renders from a snapshot. | Plugins. |
| **helix** | A fuzzy palette over every command, with the key shown next to each entry. Light and dark detected, with a manual override. A palette of 16 terminal colours as the floor. | Modal editing. |
| **bottom** | A grid of tiles that collapses by size, and a "too small" screen instead of clipping. | — |

## The shell

```
 ◖•ᴗ•◗ moochy · @alice                      ◆ 3 pending  ▲ 2 alerts  ● relay  ● node   ← header
 1 Overview  2 Dona  3 Serv  4 Proj  5 Orga  6 Deci  7 Devi  8 Acti  9 Sett    /axum   ← tabs + filter chip
╭ Donations (1/4) ─────────────────────────────╮╭ Detail ───────────────────────────╮
│▌ github/tokio-rs/axum   ✔ active   $27.42 …  ││ …                                  │  ← the view
╰──────────────────────────────────────────────╯╰────────────────────────────────────╯
 p pause  enter open  / filter  : commands  q quit  ? help                               ← footer
```

- **Header.** The hamster's face reacts to events (`•ᴗ•` calm, `^ᴗ^` for 4 s after a new request, `-ᴗ-` when the node is unreachable), with blush cheeks. Then the user, and on the right the pending count, alerts, relay and node status. Each status is a glyph plus a word. Items drop from the left when space runs out.
- **Tabs.** Number keys `1`–`9`, `Tab`/`Shift-Tab`, `[`/`]`, or a mouse click. Titles compress at 80 columns: the active tab stays full and the others drop to 4 letters, then to numbers only. The active `/` filter shows as a butter chip on the right.
- **Footer.** It shows the view's `hints()` first, then the globals. `? help` always stays. Items that don't fit are dropped rather than cut.
- **Overlays:**
  - `?` help, generated from `GLOBAL_KEYS` and the view's hints.
  - `:`/`Ctrl-K` palette: fuzzy over tab jumps, the view's hints (single-char or `enter` keys are replayed to the view), theme toggles, refresh, suspend and quit.
  - Confirm dialog. **No** is focused by default. `y` runs and `n`/Esc cancels.
  - Toasts, bottom-right. They are event-driven and expire after 4 s. The loop wakes for the expiry only while a toast is shown.
- **Too small.** Under 60×15 the app shows one sentence saying so. The designed range is 80×24 and wider. It is tested at 80×24, 100×30 and 160×48.

## Colour

DESIGN.md's mint palette, mapped for terminals (`theme.rs`):

- **No background painting.** The user's terminal background stays.
- **Dark terminals** get the pastel fills: Mint `#7DD3AE`, Sky, Butter, Coral-soft and Blush.
- **Light terminals** get the deep variants: Mint-deep `#1A6B4A`, Sky-deep, Butter-deep, Coral-deep and Blush-deep. These are the DESIGN.md §2 contrast pairs.
- **Selection and the active tab** are Ink on a Mint fill (9.0:1). Without colour they are reverse video plus bold.
- **Role colours:** mint = healthy / call to action, butter = donated money and attention, coral = stop and error, sky = information. Each one is always paired with a glyph and a label (`✔ active`, `‖ paused`, `■ stopped`, `✖ refused`, `◆ pending`, `▲ warn`).
- **Depth** comes from `NO_COLOR` (non-empty means none), then `COLORTERM=truecolor|24bit`, then `TERM=*256*`, then 16 colours. `TERM=dumb` means none. You can cycle it at runtime from the palette.
- **Light or dark** comes from `--theme`, then `MOOCHY_THEME`, then the background index in `COLORFGBG` (7 or 15 = light), and defaults to dark. (ponytail: no OSC 11 query. It races with the input reader and costs up to 100 ms on terminals that never answer. Add it with a DA1 fence if users ask.)
- **ASCII.** `--ascii`, `TERM=linux` or `TERM=dumb` switch borders to `+-|` and glyphs to `* o ~ + ! x = ? # ^ v $ >`.

## Live updates and budgets

- There is one bounded `sync_channel(256)` of `AppEvent`, fed by:
  - the input thread (crossterm)
  - the source worker (snapshots and action results)
  - the optional watch stream from NodeSource
  - the signal thread
- The main thread blocks in `recv`, handles that event plus everything already queued, then draws **once**. ratatui diffs against the previous buffer, so there is no flicker.
- Idle means one blocked `recv` and zero allocation. The input thread wakes every 250 ms in `poll`. That timeout exists only so it can be paused when a child process needs the terminal. A passphrase typed for `moochy accept` never reaches us.
- The first frame is drawn before the first snapshot arrives (header shows `◌ connecting…`).
- Actions go to the worker through a bounded `sync_channel(16)`. When it is full, a toast says "busy" and nothing blocks.

## Exit paths (the terminal is always restored)

| Path | How |
|---|---|
| `q`, Ctrl-C, or `?`/Esc chains | The loop breaks and the `Guard` drop restores the terminal. |
| An error | `?` unwinds out of `run` and the `Guard` drop restores the terminal. |
| A panic | A panic hook restores the terminal first. Release builds abort, so `Drop` would never run. |
| SIGTERM, SIGHUP, SIGINT | The signal thread sends `Quit` and the loop breaks normally. |
| Ctrl-Z, SIGTSTP | Pause input, leave the terminal, `raise(SIGSTOP)`. On continue, re-enter and redraw in full. |
| SIGCONT after an external `kill -STOP` | Re-enter and redraw in full. |
| `ActionResult::Terminal(args)` | Same as suspend, but runs `moochy <args>` in the foreground. Owner-key actions keep the CLI's passphrase prompt, decoded body and Lookup check unchanged (A217/A218). It then waits for Enter, resumes and refreshes. |

## Writing a view (for mo-tui-donor and mo-tui-maint)

```rust
use crate::widgets::table::{Cell, Column, Row, TableState};
use crate::widgets::{self, master_detail, status};

const COLS: &[Column] = &[
    Column::grow("Project", 16),                 // takes the remaining width
    Column::new("Status", 10),
    Column::new("Spent", 9).right().pri(1),      // dropped first when narrow
];

#[derive(Default)]
pub struct DonationsView { table: TableState }

impl View for DonationsView {
    fn hints(&self) -> &'static [(&'static str, &'static str)] { &[("p", "pause"), ("enter", "details")] }
    fn render(&mut self, f: &mut Frame, area: Rect, ctx: &Ctx) {
        let (list, detail) = master_detail(area);
        let rows = ctx.snap.donations.iter().enumerate().map(|(i, d)| Row::new(i, vec![
            Cell::text(&d.target),                                  // sanitized
            Cell::line(status(ctx.theme, &d.status), &d.status),    // glyph + label
            Cell::num(widgets::dollars(d.spent_uusd), d.spent_uusd).style(ctx.theme.money()),
        ])).collect();
        self.table.render(f, list, ctx, "Donations", COLS, rows, "No donations yet. Run `moochy donate <repo>`.");
        if let (Some(r), Some(i)) = (detail, self.table.selected()) { /* draw ctx.snap.donations[i] */ }
    }
    fn on_input(&mut self, input: &Input, ctx: &Ctx) -> Outcome {
        match input {
            Input::Char('p') => /* Outcome::Confirm { title, body, action: Action::PauseDonation(id) } */,
            _ => self.table.on_input(input, COLS),
        }
    }
}
```

**Rules for views:**

- Sanitize every peer string: `Cell::text`, `Cell::styled` and `widgets::status` do it, and `sanitize::clean` covers the rest.
- Never rely on colour alone.
- Every state change goes through `Outcome::Confirm`.
- Return `Outcome::Command(Command::…)` to drive the shell.
- `j/k`, arrows, `g/G`, PgUp/PgDn and Enter arrive as `Input::*`, and other letters as `Input::Char`. Digits, `q ? : / r [ ]` and Tab belong to the shell. `s`/`S` sort tables.
- When `master_detail` returns `None` (small terminals), Enter should open the detail full-pane and Esc (`Input::Back`) should close it.

**Shared widgets:**

- `widgets::{dollars, tokens, latency, ago, date, datetime, status, status_glyph, key_hint, field, master_detail}`
- `widgets::charts::{sparkline, meter, hbar, permille}`
- `widgets::fuzzy::score`
- `Theme::{ok, warn, err, info, money, muted, accent, bold, selected, border, border_focus, border_set, glyph, glyph_style}`

## Snapshot mode

`moochy tui --demo --snapshot 80x24 --keys "2jj<enter>" [--theme light] [--ascii] [--ansi]`, or
`cargo run -p moochy-tui --example demo -- …` before the entry exists. The clock is fixed (fixtures:
2026-10-03 14:05 UTC), truecolor, and makes no environment lookups, so the output is stable byte for byte.

- **Keys:** characters as typed (spaces are ignored). Named keys: `<enter> <esc> <tab> <s-tab> <up> <down> <left> <right> <pgup> <pgdn> <home> <end> <bs> <space> <lt> <c-x> <click:COL,ROW>`.
- **`--hostile`:** the demo world with CSI, OSC 52/8, C1 and bidi sequences in every peer string (E121).
