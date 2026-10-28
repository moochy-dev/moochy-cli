# Moochy desktop

The Moochy app in a small window (Tauri 2). It is a remote control, never a second node: the window reads state and live updates from the `moochy` background process over its control socket, and runs every other step as `moochy --home H <command>`, so every check of the command-line app still applies. Your key goes to that process on stdin and is wiped from the window's memory right after.

- First run: connect this computer, add your API key, set a monthly limit, pick a project. A step that is already done (for example with the CLI) is skipped.
- Then four tabs: Home (one switch to pause donating), Donations, Projects (when you maintain one), Settings.
- Accepting a donor needs your passkey: the window opens the page on moochy.dev.

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
