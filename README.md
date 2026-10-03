# moochy-cli

The open-source Moochy client: the `moochy` app that runs on donors' and maintainers' machines.

Moochy lets you donate tokens to open-source projects from your own LLM API account, with a monthly limit you choose. Maintainers use those tokens from any MCP client, or from any tool that lets them set a provider base URL. Your key never leaves your machine: it stays in your keychain and only this app uses it. Every request is end-to-end encrypted, so the relay only sees encrypted bytes.

Open-source client (Apache-2.0) · 100% free. No fees, no commission, no paid tier.

## Install

```sh
brew install moochy-dev/tap/moochy
```

Each release also publishes signed archives for macOS, Linux and Windows, shell and PowerShell installers, and the npm package `moochy`. To check a release, see [`deploy/client/README.md`](deploy/client/README.md#verify-a-release-users).

## Build and test

You need Rust (the version is pinned in `cli/rust-toolchain.toml`; rustup installs it).

```sh
cd cli
cargo build --release                           # the app: cli/target/release/moochy
cargo test --workspace                          # unit, vector and integration tests
cargo clippy --all-targets -- -D warnings
```

## Layout

| Path | What |
|---|---|
| `cli/` | Rust workspace: `proto` (wire format, crypto), `worker` (provider calls, safety checks), `sandbox` (`moochy run`), `node` (the `moochy` binary), `keylog` (public key log verifier), `tui` |
| `deploy/client/` | Release and supply-chain tooling, service units, containers, cloud boxes ([README](deploy/client/README.md)) |
| `spec/proto/`, `spec/vectors/` | Protocol buffers and golden test vectors used by the build and the tests |
| `docs/guides/integrations.md`, `docs/guides/donate-button.md` | Guides compiled into the app (`moochy connect`) or checked by its tests |
| `dist-workspace.toml`, `.github/` | cargo-dist release configuration and CI |

## Files shared with moochy-docs

[moochy-docs](https://github.com/moochy-dev/moochy-docs) holds the guides, the protocol specification and the design. This repository keeps byte-identical copies of the files the build needs:

- `spec/proto/` and `spec/vectors/` are produced here (the vectors by `cargo run -p moochy-proto --example vecgen -- ../spec/vectors` from `cli/`). Copy them to moochy-docs after a change.
- `docs/guides/integrations.md` and `docs/guides/donate-button.md` are written in moochy-docs. Copy them here after a change.

Relative links inside the two guide copies point to guides that live in moochy-docs.

## Related repositories

- [moochy-docs](https://github.com/moochy-dev/moochy-docs): guides, protocol specification ([`spec/protocol.md`](https://github.com/moochy-dev/moochy-docs/blob/main/spec/protocol.md), [`spec/KEYLOG.md`](https://github.com/moochy-dev/moochy-docs/blob/main/spec/KEYLOG.md)), design documents.
- [moochy-skills](https://github.com/moochy-dev/moochy-skills): agent skills for donating tokens and using donated tokens.

## Security

Report vulnerabilities by email, not in public issues: see [SECURITY.md](SECURITY.md).

## License

Apache-2.0 ([LICENSE](LICENSE)). Contributions need a DCO sign-off (`git commit -s`).
