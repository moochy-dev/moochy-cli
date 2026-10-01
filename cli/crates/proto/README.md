# moochy-proto

The protocol core every other Moochy component trusts (Apache-2.0): `lp` encodings and labels,
strict JSON, generated gRPC types (`pb`), request/response envelopes, HPKE wraps, signatures,
receipts, money math, the deterministic input estimate, username rules, and the golden vector
generator for `spec/vectors/`.

- Build/test: `cargo test -p moochy-proto` (includes `tests/vectors.rs`: the committed vectors
  must equal what the library produces). Regenerate vectors from `cli/`:
  `cargo run -p moochy-proto --example vecgen -- ../spec/vectors`.
- Perf: runs in every `cargo test`; budgets (CONTRACT R6, §13) are enforced in release:
  `cargo test --release -p moochy-proto --test perf -- --nocapture`.
- Fuzz: `fuzz/run.sh [seconds] [workers] [inflate|json]` (stable rustc, libFuzzer + ASan, dev-only).
- Regenerate `src/pb/`: `cd pbgen && PROTOC=$HOME/.local/bin/protoc cargo run`; CI check:
  `cargo run -- --check` (exit 1 when `src/pb` is stale).
- Key log, owner keys (kinds 10/11) and receipt inclusion proofs: `moochy_keylog` (not here).

## Request opening: which API production uses

| API | Where | What it does |
|---|---|---|
| `crypto::RequestDecryptor` | **Worker parent process (production)** | AEAD, chunk order, attempt 0, last flag, sealed-size cap → still-compressed inner payload |
| `inflate::inflate_all` + `msg::InnerPayload::parse` | **Worker validator child** (`worker::validate`, single use, no files/sockets) | pure-Rust zstd decode with the 32 MiB cap, then strict JSON |
| `crypto::RequestOpener` | tests, vectors, single-process tools | both of the above in one process (`RequestDecryptor` + streaming `inflate::Inflater`) |

## Decompression of other parties' bytes (CONTRACT §15.2)

Every decompression of bytes that come from another party uses the pure-Rust `ruzstd` decoder
behind `inflate::Inflater`; C `zstd` is used only to compress our own data (it compresses
better and faster than `ruzstd`'s only encoder level; numbers in the commit history). The
inflater polices the frame header itself (single standard frame, no dictionary, no checksum,
reserved bit 0, window and declared size ≤ cap), feeds `ruzstd` one complete block at a time,
and counts output exactly, so a decompression bomb fails on the block that crosses the cap.

### Known difference: ruzstd is laxer than libzstd on some corrupt blocks

Fuzzing (`fuzz/`, differential against libzstd) found inputs that libzstd rejects as
"data corruption" while `ruzstd` decodes them to some output. This is **harmless here**:

1. **Single decoder.** Only one party ever decodes a given compressed stream: the Worker decodes
   the request it was sent. No second party (Relay, Gateway, auditor) decodes the same bytes, so
   there is no parser differential between two decoders that could make parties disagree about
   what was sent.
2. **Authenticated input.** The compressed bytes are AEAD-authenticated: they are exactly what
   the Gateway sealed, so the leniency gives an attacker no way to alter them in transit.
3. **Checked output.** Whatever comes out must still pass the strict JSON parse, the body hash,
   and the Gateway's task signature over `body_sha256`; a lenient decode of a corrupt block can
   only produce a payload that is then refused.
4. **Bounded.** The 32 MiB output cap, the window cap and the one-block-at-a-time feeding apply
   whatever `ruzstd` accepts.

What the fuzzer does enforce: no panic, no ASan report, no timeout, output ≤ cap, and identical
bytes whenever both decoders accept. Revisit if a second party ever needs to decode the same
compressed bytes (then both sides must use the same decoder, or libzstd-equivalent strictness).
