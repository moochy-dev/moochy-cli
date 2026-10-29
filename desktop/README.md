# Moochy desktop

The Moochy app in a small window (Tauri 2). It is a remote control, never a second node: the window reads state and live updates from the `moochy` background process over its control socket, and runs every other step as `moochy --home H <command>`, so every check of the command-line app still applies. Your key goes to that process on stdin and is wiped from the window's memory right after.

- First run: connect this computer, add your API key, set a monthly limit, pick a project. A step that is already done (for example with the CLI) is skipped.
- Then four tabs: Home (one switch to pause donating), Donations, Projects (when you maintain one), Settings.
- Accepting a donor needs your passkey: the window opens the page on moochy.dev.
- Gift tokens (Donations tab): a single-use link worth $1 to $1,000 and its QR code, drawn on this computer. The link is shown once and never kept: copy it or save the QR code (Save SVG writes `moochy-gift.svg` to your Downloads folder). Your gifts lists each one (open, claimed, revoked, expired) with Revoke and Replace link. Claim a gift opens the `https://moochy.dev/g/…` page in your browser, where your passkey accepts it.
- Projects you maintain have a QR code of their donate page. Moochy Credits show only when the server has them on.

## App commands

The whole IPC surface (plan 14 §2.4). Each command checks its arguments before it starts `moochy`, and the window never logs a key, a gift link or a note.

| Command | Runs | Checks |
|---|---|---|
| `state` | the node snapshot, else `keys list` | |
| `act(action)` | the TUI's actions over the socket | ids; Accept and organisation changes refused (passkey on the web) |
| `login_start`, `login_cancel` | `login --roles gateway,worker --no-browser` | |
| `add_key(provider, key)` | `keys add P --key-stdin` (key on stdin only) | provider list, key shape and prefix |
| `set_limit(dollars, start_at_login)` | `safety`, `up`, `service install\|uninstall` | $1 to $100,000 |
| `donate(target, dollars, kind)` | `donate --repo\|--org\|--person T --cap N --yes` | canonical slug, $1 to $100,000 |
| `donation(op, id)` | `donations pause\|resume\|stop ID` | op list, id shape |
| `set_paused(paused)` | `pause` / `resume` | |
| `connect(client, repo, write)` | `connect C --repo P [--write --yes]` | client list, slug |
| `clients`, `doctor`, `remove_key(provider)`, `logout` | `doctor`, `keys remove P`, `logout` | provider list |
| `gift_create(dollars, note, days)` | `gift create N --expires D [--note=T] --json` | $1 to $1,000; note one line, at most 140 characters; 1 to 90 days; the answer must be a gift link |
| `gift_list` | `gift list --json` (links dropped) | |
| `gift_revoke(id, replace)` | `gift revoke ID [--replace] --json` | `gf_` + ULID |
| `credits` | `credits --json`; null when credits are off | |
| `project_qr(repo)` | `button --qr --repo P` | slug; the answer must be a moochy.dev donate page |
| `save_qr(url)` | writes the QR SVG to Downloads, never over a file | a gift link or a donate page |
| `open_web(url)` | the system browser | `https://moochy.dev/…` (or the dev relay's origin) and a fixed list; a `/g/…` path only as `/g/` + 22 base64url characters |

## Install

Download the bundle for your system from the [releases](https://github.com/moochy-dev/moochy-cli/releases) and check it:

```sh
gh attestation verify <file> --repo moochy-dev/moochy-cli --signer-workflow moochy-dev/moochy-cli/.github/workflows/desktop.yml
```

- Linux: `sudo apt install ./Moochy_<version>_amd64.deb`, or make the `.AppImage` executable and run it.
- macOS: the `.dmg` is not signed with an Apple Developer ID yet. Drag Moochy to Applications, then right-click it and choose Open (or run `xattr -dr com.apple.quarantine /Applications/Moochy.app`).

`moochy-desktop --home DIR` uses another Moochy home, like `moochy --home DIR`.

## Build

You need Rust (pinned in `rust-toolchain.toml`), the Tauri CLI (`cargo install tauri-cli --version 2.12.4 --locked`) and, on Linux, `libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev libayatana-appindicator3-dev`.

```sh
T=$(rustc -vV | sed -n 's/^host: //p')
(cd ../cli && cargo build --release -p moochy) && mkdir -p bin && cp ../cli/target/release/moochy bin/moochy-$T
cargo test && cargo clippy --all-targets -- -D warnings
cargo tauri build                       # target/release/bundle/
node ui/smoke.mjs /tmp/shots            # needs Playwright (NODE_PATH) and Chromium; CHROME=path overrides
```

`ui/` is plain HTML, CSS and JavaScript with no build step. The font is Instrument Sans (SIL Open Font License, `ui/fonts/OFL.txt`).
