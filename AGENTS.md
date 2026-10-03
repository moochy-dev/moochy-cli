# Rules for every agent working on the Moochy client

This repository is the open-source Moochy client (Apache-2.0): the `moochy` app in `cli/`, its release tooling in `deploy/client/`, and copies of the files it builds and tests against (`spec/proto`, `spec/vectors`, two guides in `cli/crates/node/assets/`). Every crate is published on crates.io: a file the build needs must live inside its crate. The design and the normative contract live in [moochy-docs](https://github.com/moochy-dev/moochy-docs): read [`spec/CONTRACT.md`](https://github.com/moochy-dev/moochy-docs/blob/main/spec/CONTRACT.md) first, then the plan docs it points to. Open code never depends on closed code (CONTRACT §0a). Public wording: "Open-source client (Apache-2.0) · 100% free".

## 1. Scope and git discipline

- Commit early and often with clear messages (`worker: SSE parser handles split UTF-8`). Every commit carries a DCO sign-off (`git commit -s`); `deploy/client/scripts/dco-check.sh` enforces it in CI.
- Never rewrite `main`, never force-push.
- Never run `pkill -f` or `killall`; kill only processes you started, or use `timeout`.
- Wait in the foreground for builds and tests.
- Keep scratch files out of the repository.

## 2. Testing

- Unit tests live next to the code (`cargo test --workspace` in `cli/`). Write them where a function is pure and tricky (crypto, frame codec, firewall tables, cost math).
- The end-to-end scenarios (CONTRACT §8) run real binaries against fake providers in the private relay repository. A change to the wire format, the CLI surface or the vectors needs those scenarios rerun before release.
- `spec/vectors` are generated here (`cargo run -p moochy-proto --example vecgen -- ../spec/vectors` from `cli/`). A protocol change is not done until the vectors are regenerated and copied to moochy-docs.

## 3. Rust (`cli/`): aggressive, lean, fast, safe

- `#![forbid(unsafe_code)]` in every crate (exceptions: the documented syscall module of `moochy-sandbox`, CONTRACT §15; and dev-only fuzz harnesses under `*/fuzz/`, which are not workspace members and never ship). `clippy -D warnings` with `clippy::pedantic` on; deny `unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, `arithmetic_side_effects` outside tests. Integer money math is checked (`checked_*`), never wrapping.
- Release profile (workspace root, already set): `opt-level=3`, `lto="fat"`, `codegen-units=1`, `panic="abort"`, `strip=true`.
- Hot path: zero-copy (`bytes::Bytes`), no per-chunk allocation you can avoid, no `String` building in the data plane, bounded channels everywhere, no blocking calls on the runtime.
- gRPC: `tonic` (no default TLS features; our own `tokio-rustls` connector for channel binding) + `prost`; generated code committed, never built from `.proto` at compile time.
- Crypto and TLS: `rustls` (ring provider), `ed25519-zebra` (ZIP-215), `x25519-dalek`, `hpke`, `chacha20poly1305`, `hkdf`, `sha2`, `zeroize` on every secret, `subtle` for every token/MAC comparison. No OpenSSL. No home-made crypto.
- Dependency budget: every new crate must justify itself in the commit message; prefer `default-features = false`. Commit `Cargo.lock`. Target: release binary ≤ 15 MB, idle RSS ≤ 20 MB.
- The client ships on Linux AND macOS: before you report, also run `cargo check --target aarch64-apple-darwin -p moochy-sandbox -p moochy-worker` for the crates you touched among those (the target is installed on the box; crates with C dependencies — node, proto via zstd/ring, keylog via ring since the passkey verifier — cannot be cross-checked here: say so in your report and the integrator's Mac build covers them). Linux-only APIs (MSG_CMSG_CLOEXEC, memfd, openat2, prctl, …) need a `cfg` and a macOS path. The integrator builds and runs everything on a real Mac.
- The TUI (`cli/crates/tui`, CONTRACT §20): `ratatui` (crossterm backend, `default-features = false`) + `crossterm` (+ `signal-hook` on unix, already in the tree through crossterm) are the allowed UI crates; render on events only (no busy loop), restore the terminal on every exit path, sanitize every server/peer string before it reaches the terminal.
- Every external input is hostile: lengths bounded before allocation, JSON parsed into typed structs with `deny_unknown_fields` where the contract says so, timeouts on every network operation.

**Responsiveness is a hard requirement** (CONTRACT §13 budgets, measured by E22): flush every chunk immediately, `TCP_NODELAY`, warm connections, no avoidable allocation or lock per chunk, no fsync in the per-chunk path.

## 4. Security is a feature, not a phase

- Read [`docs/plan/06-security-and-trust.md`](https://github.com/moochy-dev/moochy-docs/blob/main/docs/plan/06-security-and-trust.md). Every mitigation listed there for the client is in scope.
- [`docs/security/attack-catalog.md`](https://github.com/moochy-dev/moochy-docs/blob/main/docs/security/attack-catalog.md) lists the attacks with their counter-measure and the scenario that proves it. Check your change against it.
- `security@moochy.dev` (in SECURITY.md) is confirmed by the product owner but NOT live yet: never send to it, test it, look it up, or configure anything for it; leave the text as it is.
- Fail closed: on any doubt (bad signature, unknown field, oversize, wrong state) refuse with a specific code, never "best effort".
