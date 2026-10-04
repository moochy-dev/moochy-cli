# moochy

The Moochy app: donate LLM tokens from your own provider API account to the open-source
projects you use, and use tokens donated to your own projects. Linux and macOS.

```sh
curl -fsSL https://moochy.dev/install.sh | sh      # or: cargo install moochy --locked
moochy login                                       # opens your browser; confirm the code
moochy up                                          # start the app on this machine
```

This crate is the `moochy` binary and its node library:

- **CLI and TUI:** `moochy login | up | status | donate | claim | button | env | mcp | run | verify …`
  (`moochy --help`), and the terminal dashboard from `moochy-tui`.
- **Relay link:** gRPC with TLS channel binding to moochy.dev. Trust comes from the public key log
  (`moochy-keylog`), never from the relay's word.
- **Keystore:** device keys and your provider keys stay in your machine's keychain.
- **Gateway doors:** for maintainers. An OpenAI- and Anthropic-compatible local API, and an MCP
  server (stdio and Streamable HTTP), for coding agents run through `moochy run` (`moochy-sandbox`).
- **Worker role:** for donors. Opens each request, checks it against your limits (monthly, weekly,
  daily and per request), and calls your provider with your key (`moochy-worker`). Nothing from a
  request is ever executed. The process locks itself down after start-up.

Guides: <https://moochy.dev/docs>. Test: `cargo test -p moochy`. License: Apache-2.0.
