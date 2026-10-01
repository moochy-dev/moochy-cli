# Rules for every agent working on Moochy

Moochy has an **open-source client (Apache-2.0: `cli/`, `spec/proto`, `spec/vectors`, `docs/guides`) and a closed-source core (relay + web + e2e + internal docs)**, and is **100% free**. Respect the boundary in CONTRACT §0a: open code never depends on closed code; public wording is "Open-source client (Apache-2.0) · 100% free". Read `spec/CONTRACT.md` first (normative), then the plan docs it points to in `docs/plan/`.

## 1. Scope and git discipline

- Work **only** inside the paths your agent owns (CONTRACT §0). Need something elsewhere → list it under `## Requests to other owners` in your final report.
- You are in your own git worktree on branch `agent/<your-name>`. Commit early and often with clear messages (`relay: scheduler actor with commit-before-assign`). Never touch `main`, never rebase, never force anything, never delete branches. There is no remote: do not push.
- Never run `pkill -f`, `killall`, or kill processes you did not start (other agents share this machine). Kill only your own PIDs, or use `timeout`.
- Wait in the **foreground** for builds and tests. Never end your turn on a background job: when your turn ends, you end.
- Put scratch files under `/mnt/fast/tmp/<your-name>/`, never in the repo.

## 2. Testing: end-to-end first

- The definition of "working" is the E2E scenario table (CONTRACT §8). Unit tests only where a function is pure and tricky (crypto, frame codec, firewall tables, cost math). No mocks of our own components in E2E: real binaries, fake **providers** only.
- Before you report done, run every E2E scenario your component participates in. A scenario you cannot run yet must `t.Skip("pending: <what>")` with the exact reason; never delete or weaken a scenario to make it pass.

## 3. Rust (`cli/`): aggressive, lean, fast, safe

- `#![forbid(unsafe_code)]` in every crate. `clippy -D warnings` with `clippy::pedantic` on; deny `unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, `arithmetic_side_effects` outside tests. Integer money math is checked (`checked_*`), never wrapping.
- Release profile (workspace root, already set): `opt-level=3`, `lto="fat"`, `codegen-units=1`, `panic="abort"`, `strip=true`.
- Hot path: zero-copy (`bytes::Bytes`), no per-chunk allocation you can avoid, no `String` building in the data plane, bounded channels everywhere, no blocking calls on the runtime.
- gRPC: `tonic` (no default TLS features; our own `tokio-rustls` connector for channel binding) + `prost`; generated code committed, never built from `.proto` at compile time.
- Crypto and TLS: `rustls` (ring provider), `ed25519-zebra` (ZIP-215), `x25519-dalek`, `hpke`, `chacha20poly1305`, `hkdf`, `sha2`, `zeroize` on every secret, `subtle` for every token/MAC comparison. No OpenSSL. No home-made crypto.
- Dependency budget: every new crate must justify itself in the commit message; prefer `default-features = false`. Commit `Cargo.lock`. Target: release binary ≤ 15 MB, idle RSS ≤ 20 MB.
- Every external input is hostile: lengths bounded before allocation, JSON parsed into typed structs with `deny_unknown_fields` where the contract says so, timeouts on every network operation.

**Responsiveness is a hard requirement** (CONTRACT §13 budgets, measured by E22): flush every chunk immediately, `TCP_NODELAY`, warm connections, no avoidable allocation or lock per chunk, no fsync in the per-chunk path.

## 4. Go (`relay/`, `e2e/`)

- Go 1.25, stdlib first. Allowed third-party: `google.golang.org/grpc` + `google.golang.org/protobuf` (the Node↔Relay link, CONTRACT §12), `modernc.org/sqlite`, `golang.org/x/crypto` (HPKE not needed relay-side), `github.com/hdevalence/ed25519consensus`, `golang.org/x/mod/sumdb/tlog`+`note` (later), `golang.org/x/oauth2` (later).
- `http.Server` with `ReadHeaderTimeout`, `ReadTimeout`, `IdleTimeout`, `MaxHeaderBytes`; `http.MaxBytesReader` on every body; bounded queues; context deadlines everywhere. `go vet` and `-race` clean.
- No content (prompts/outputs) ever written to the DB or logs. The Scheduler owns its state in one goroutine (docs/plan/04).

## 5. Security is a feature, not a phase

- Read `docs/plan/06-security-and-trust.md`. Every mitigation listed there for your component is in scope.
- `docs/security/attack-catalog.md` (owned by `mo-sec`) is the running list of attacks with their counter-measure and the E2E scenario that proves it. When it exists, check your component against it.
- Fail closed: on any doubt (bad signature, unknown field, oversize, wrong state) refuse with a specific code, never "best effort".

## 6. Web palette (fixed)

White `#FFFFFF`, dark `#0B1220`, light blue `#7DD3FC` (accent), `#0369A1` for small text links on white. Dark theme: bg `#0B1220`, text `#F8FAFC`, accent `#7DD3FC`. No other brand colours. Design ambition is maximal (CONTRACT §9: motion system, scroll-driven storytelling, view transitions, micro-interactions), within the §9 performance and accessibility budgets.

## 7. Final report (always, even when blocked)

End your run with a short summary, then **one last line of JSON**:
`{"agent":"<name>","branch":"agent/<name>","head":"<sha>","built":true|false,"e2e":{"pass":[...],"fail":[...],"skip":[...]},"done":[...],"todo":[...],"requests":[...]}`
