# `moochy-worker` public API

Everything that touches a provider or inspects provider traffic. Plain inputs in, events
out. No dependency on `moochy-proto`: the node does sealing, signing and the gRPC link.

## Worker pipeline (plan 07 §6.1) → calls

| Step | Call |
|---|---|
| 2. never served before, ±10 min | `Store::check_served(gateway_device, task_id, ulid_ts_ms, now_ms)` → `Stale`/`Replay` = NACK `unauthorized_task` |
| 1+3. decompress + inner payload + firewall + route (**in the validator child**, CONTRACT §15.2) | `validator.validate(&ValidateRequest{..}).await` → `Validated` (inner fields, original body, `prepared`); then the parent verifies `body_sha256`/`task_sig` and computes `req_commit` from `validated.body`. `ValidateError::nack()`: refusals as below, `bad_envelope`, or `("busy", true)` for any child failure. Never call `firewall::prepare` on a stranger's bytes in the donor process |
| 3. (in-child) firewall + route/body consistency | `firewall::prepare(&Request{..})` → `Prepared{facts, body, headers}`; then `prepared.facts.check_route(dialect, &Route{..})`. `Reject::code.nack()` gives `("firewall", false)`, `("route_mismatch", false)` or `("model_unavailable", true)`; `reject.to_string()` is the sealed detail |
| 4. local reservation | `Store::reserve(&Reservation{..})` → `Cap(_)` = NACK `local_cap` (retryable). In memory + written, **no fsync** (CONTRACT §13) |
| 6. call the provider | `Adapter::send(dialect, prepared.body, &prepared.headers)` → `Response` once headers arrive (= `task.started`), or `Failure` (`failure.nack()`; `failure.body` = native error to seal) |
| 7. stream | loop `response.next()` → forward each `Bytes` **as-is, immediately** (seal + send per chunk); `parser.feed(&chunk, sink)?.tool_ends > 0` → sign a progress checkpoint after this chunk. `next()` never waits to batch, but returns every frame already received merged into one chunk (≤ 16 KiB), and yields once after a chunk so the link writer you just woke runs first (see *Per-chunk performance*) |
| 8. end | `parser.finish()` → `Outcome{usage, model, id, complete, provider_error, forbidden, malformed, tail}`; build/sign the receipt → `Store::put_receipt(key, receipt_bytes, cost_uusd, now)` (settles + **fsync**) → `task.end` |
| 9. cancel / link lost | drop the `Response` (h2 `RST_STREAM` / h1 socket closed: the provider stops at once), then `finish()` → `usage.estimated` if final usage never came |
| NACK before the provider call | `Store::release(key)` |
| `receipt.ack` | `Store::ack(key, now)`; replay with `unacked()`, `since(ms)` (`receipt.replay_since`) |
| offer | `Store::device_left(cap, now)` → `local_cap_left`; `Response::rate_limit.headroom_pct()` → `rl_headroom` (per model; `Failure::rate_limit` on a 429) |

All `Store` methods do blocking file I/O: own the `Store` in one thread (or `spawn_blocking`).
Call `Store::compact(now)` daily (also done on `open`). Call `Adapter::warm()` at startup, on
key add, and about every minute (h2 PINGs keep the connection alive in between).

## Modules

### `validate` (donor side, CONTRACT §15.2)

The only place a stranger's request bytes are parsed: a **single-use child** with no files, no network and no keys (seccomp read/write/memory/exit, applied by moochy-sandbox).

**Wiring (mo-node):**
1. `moochy __validate` = `std::process::exit(moochy_worker::validate::child_main(std::io::stdin().lock(), std::io::stdout().lock()))`. This must be the first thing the subcommand does: no config, no keystore, no logging to files. `src/bin/moochy-validate.rs` is the same entry for tests.
2. Build one `Validator::new(spawner, ValidatorLimits { deadline: 5 s, warm: 2 })` at donor start and call `prewarm()`. `spawner` is an `Arc<dyn Fn() -> io::Result<tokio::process::Child>>` that spawns `moochy __validate` inside the moochy-sandbox lockdown with `stdin(piped)`, `stdout(piped)`, `stderr(null)`, `kill_on_drop(true)`, a clean environment and rlimits. Suggested limits: address space 512 MiB, CPU 5 s, no files beyond the inherited pipes.
3. Per task, after AEAD-opening the chunks **without decompressing** (mo-proto: decrypt-only opener), call `validate(&ValidateRequest { provider, dialect, policy, catalog, provider_model_id, user_pseudonym, max_price, route, payload })`. `route` comes from the parent's strict route-header parse; `payload` is the opened zstd bytes.
4. With the `Validated` result, build proto's `InnerPayload { body_b64: validated.body, body_sha256, headers, s, gateway_device, task_sig }`, run `verify` (body hash + `task_sig`), compute `req_commit` from `validated.body`, then send `validated.prepared.body` with `validated.prepared.headers`.

**Protocol:** parent → child is one versioned codec message (context + payload), then stdin is closed. Child → parent is `u32_be len || versioned response`: OK (S, gateway_device, task_sig, body_sha256, sorted headers, original body, facts, forwarded headers, canonical body), REFUSED (code, path, reason) or BAD_ENVELOPE (reason).

**Hard limits:**
- Child: request ≤ 33 MiB; one zstd frame, window ≤ 32 MiB, output ≤ 32 MiB, no trailing bytes; JSON depth ≤ 64 and ≤ 2 Mi values.
- Parent: response ≤ 65 MiB, read as exactly the declared length; every field is checked (sizes, UTF-8, enum values, forwarded header names ∈ {`anthropic-version`, `anthropic-beta`}, header name/value rules, device id format).
- The parent never waits for the child's exit (it is killed and reaped on drop).

**Custom transports:** `validate_on(stream, &req, deadline)` runs the same exchange over any `AsyncRead + AsyncWrite` (e.g. a socketpair to a zygote-forked, jailed child running `child_main`), and `decode_response(&buf)` is public for fully custom framing.

**Single use:** each child serves exactly one request. The replacement is spawned (via `spawn_blocking`) while the current one works. A dead idle child is discarded; a crash, timeout, non-zero exit or garbage gives `ValidateError::Child` → `("busy", true)`.

**Measured** (release, arm64 dev box, 100 KB agent body, warm pool): about +0.35 ms p50 and +0.42–0.67 ms p99 over in-process validation (≈0.26 ms).

**Trust note:** the child's verdict *is* the firewall. Isolation protects the donor's keys, files and network from a parser exploit; it cannot make a compromised child's firewall decision trustworthy. The parent still checks `body_sha256` and `task_sig` itself.


### `firewall`
- `Policy { level: Strict|Paranoid, flags: Flags, max_effort: Effort }` – pledge opt-ins. `Policy::PERMISSIVE` for the Gateway.
- `Catalog { default_effort, max_output, max_image_tokens, max_page_tokens }`: the signed-catalog numbers of the route's model. **mo-node: `engine.rs` `fw_catalog` must pass `max_page_tokens: e.max_page_tokens`** (added for CONTRACT R3).
- `Request { provider, dialect, body, headers, policy, catalog, provider_model_id, user_pseudonym, max_price }`.
- `prepare(&Request) -> Result<Prepared, Reject>`: strict JSON (CONTRACT §1), table walk (`tables.rs`), header allowlist, facts, safe mutations re-serialized from the validated tree.
- `analyze(dialect, body, headers, &policy, &catalog) -> Result<Facts, Reject>`: same checks, no mutation. **The Gateway must build the route header from `analyze(.., &Policy::PERMISSIVE, ..)`** so `est_input_tokens`, `effort`, `cache_ttl`, `flags` match the Worker bit for bit.
- `Facts { model, max_tokens, effort, est_input_tokens, cache_ttl, stream, flags, text_bytes, images, pages }`, `Facts::check_route(dialect, &Route)`. `effort` is the maximum of the top-level effort (or the catalog default) and every per-turn `output_config.effort`.
- `pool_compatible(dialect, body, headers) -> PoolRequest { body, headers, stripped }` (**Gateway, before sealing**): strips what a pooled donor refuses but the client can do without, so real clients work through the pool: top-level `safeguards` (Claude Code's billed auto-mode classifier, which also carries the maintainer's local paths), beta values outside the allowlist, and headers other than `anthropic-version`/`anthropic-beta`. Everything else is left to `analyze`. Show `stripped` as a `[moochy]` note.
- `pdf_pages(bytes) -> Option<u64>`: the deterministic PDF page count used for R3.

Safe mutations: `model` → `provider_model_id`; Anthropic dialect `metadata.user_id` = pseudonym;
OpenAI dialect with `stream: true` → `stream_options.include_usage: true`; OpenAI: `store: false`,
`safety_identifier` = pseudonym; OpenRouter: `user` = pseudonym, `usage.include: true` (OpenAI
shape), and in both shapes `provider: {max_price: {prompt, completion} ($/Mtok from the catalog µ$), allow_fallbacks: false}`.
Client-supplied `provider`, `usage`, `models`, `route`, `plugins` are refused.

### `provider`
- `Adapter::new(&AdapterConfig{provider, api_key: Zeroizing<String>, base_url, insecure_dev, dev_root, limits})`.
- **Adapter definitions** (`provider::AdapterDef::of(provider)`): the official origin and the **full path for each dialect**. `Provider::serves` is derived from this table.

| provider | origin | anthropic.messages | openai.chat |
|---|---|---|---|
| anthropic | `https://api.anthropic.com` | `/v1/messages` | — |
| openai | `https://api.openai.com` | — | `/v1/chat/completions` |
| openrouter | `https://openrouter.ai` | `/api/v1/messages` (Anthropic-compatible root `/api`) | `/api/v1/chat/completions` (OpenAI-compatible root `/api/v1`) |
| deepseek | `https://api.deepseek.com` | `/anthropic/v1/messages` (Anthropic-compatible root `/anthropic`) | `/chat/completions` |
| xai | `https://api.x.ai` | — (no Anthropic-compatible endpoint documented) | `/v1/chat/completions` (OpenAI-compatible root `/v1`) |

- **Base URL = origin, never a root.** The `base_url` override (CONTRACT §6) replaces only `scheme://host:port`; the path always comes from the table above, so the e2e fakes (`e2e/fake`) serve exactly the real paths. Accepted only with `insecure_dev` **and** a loopback **IP literal** (`localhost` refused: name resolution is attackable). A trailing `/` is fine; **any path is refused** (`http://127.0.0.1:P/api` → error "base URL must be an origin"), so nobody has to guess whether a prefix is an origin or an API root. `http://` → HTTP/1.1 (e2e fakes), `https://` → HTTP/2 (+ `dev_root` trust anchor, tests only).
- Verified against the real Go fakes for all six provider × dialect pairs (`tests/provider.rs::against_e2e_fakes`, opt-in via `MOOCHY_E2E_FAKES`).
- Auth: Anthropic `x-api-key`; others `Authorization: Bearer`.
- Transport: one warm HTTP/2 connection per adapter (multiplexed, re-dialed when closed), ALPN `h2` required, rustls/ring, Mozilla roots, `TCP_NODELAY`, stream window 2 MiB, connection window 8 MiB, keep-alive PING 20 s.
- **Loopback dev targets behave the same way** (so E77 measures production behaviour): `http://` overrides use an HTTP/1.1 keep-alive pool (up to 16 idle connections, `TCP_NODELAY`). `warm()` opens one connection ahead of time; a connection returns to the pool only after its response body was read to the end; a dropped (cancelled) response closes its connection, so the provider sees the abort and the connection is never reused. A request is retried on a fresh connection only when hyper proves it was never sent (a pooled connection the server closed in between), so a provider call is never executed twice. Verified against the real Go fakes: one TCP connection per fake for warm-up + all requests.
- `Limits` (defaults): connect 5 s, headers 30 s, idle between chunks 120 s, total 1 h, response 128 MiB, error body 64 KiB.
- **Rate limits** (`provider::RateLimit`, on `Response::rate_limit` and `Failure::rate_limit` for HTTP errors): `requests_limit`, `requests_remaining`, `tokens_limit`, `tokens_remaining` from `anthropic-ratelimit-{requests,tokens}-{limit,remaining}` or `x-ratelimit-{limit,remaining}-{requests,tokens}`; absent or unparsable headers stay `None`. `headroom_pct()` = the tighter of `remaining/limit` for requests and tokens, 0–100 (clamped; limit 0 → 0), `None` when no complete pair was sent (the node then keeps its default). Verified against the Go fakes' `SetHeadroom` (25/40/60/80 % read back exactly, both dialects).
- `Failure.nack()`: 429 → `rate_limited` (+`retry_after_ms`), 503/529 → `overloaded`, 5xx/network/timeout/401/403 → `provider_error` (retryable), 404 → `model_unavailable`, other 4xx and oversize → `provider_error` **non-retryable**.

### `stream`
- `StreamParser::new(dialect, stream)`, `feed(&chunk, &mut sink) -> Result<Chunk{tool_ends, events}, StreamError>`, `finish() -> Outcome`.
- `sink(Span{start,end}, Event)`: spans are contiguous byte ranges of whole SSE events (comments included), so the Gateway can forward byte-identical output and hold exactly the tool-call events. Events: `Other`, `ToolStart{index,id,name}`, `ToolArgs{index,json}` (a `json::Val` string, decode with `as_str`), `ToolEnd{index}`, `Forbidden{block_type}`, `Error`, `Stop`, `Invalid`. One event may yield several items with the same span.
- **Fail closed (Gateway):** on `Invalid` (unparsable/duplicate-key JSON, a stray `\r` or BOM, tool input in `content_block_start` or `message_start`, a delta for a closed/unknown tool block, a re-started index, an OpenAI choice ≠ 0, an unindexed/reopened tool call, a second name fragment, legacy `function_call`) do not forward the event and fail the task; `Outcome.malformed` is set and usage becomes estimated. Real provider streams never trigger it (fixtures, CRLF variants tested).
- Usage mapping (05 §3): Anthropic `message_start` + cumulative `message_delta`, `cache_creation` TTL split (else all 5m), `usage.iterations` summed when present; OpenAI `prompt − cached − cache_write`, DeepSeek `prompt_cache_miss/hit_tokens`, OpenRouter `usage.cost` → µ$ by exact decimal ceil (`decimal_to_uusd_ceil`), xAI `usage.cost_in_usd_ticks` (10¹⁰ ticks per $) → `ceil(ticks / 10⁴)` µ$. `output = max(completion_tokens, total_tokens − prompt_tokens)`: exact for OpenAI-style (reasoning inside `completion_tokens`) and xAI (reasoning *outside* it), never undercounting. OpenAI-shape usage is final only once the stream ended (`[DONE]` or a whole JSON body): xAI repeats cumulative usage on every chunk, so a cut stream is `estimated`. Any unparsable/duplicate-key event ⇒ `estimated`.
- Non-streamed responses: `stream = false`, feed the body, `finish()`. Tool calls of a non-streamed body: `inspect::response_tool_calls`.

### `reemit` (Gateway side, CONTRACT §15.4, attacks A162/A145)

No donor byte reaches the agent verbatim. Every event is parsed (strict JSON) into a typed form checked against a per-event allowlist and written back canonically:
- **Framing:** `event: <type>\n` (Anthropic only), then `data: <json>\n\n`, LF only. No `id:`, `retry:` or comments are written.
- **JSON:** members in schema order, minimal escapes, numbers re-validated, strings bounded.
- **Text:** human-visible fields (`text`, `thinking`, `content`, `reasoning*`, `refusal`, error `message`) go through `clean_text`.
- **Unknown optional members** are dropped and counted (`dropped_fields()`).
- **Failure** (`Err(ReemitError)`, which fails the attempt with the dialect's native retryable error: Anthropic `overloaded_error` event / OpenAI 502):
  - unknown event or block types; wrong types; oversize events (> 1 MiB) or fields;
  - duplicate keys, invalid UTF-8, a BOM;
  - CR-only or embedded-CR line endings;
  - a second `event:` or `data:` line, an `event:` name that differs from `data.type`, an `event:` line in the OpenAI dialect, `id:`/`retry:`/unknown fields;
  - a truncated final event;
  - a pre-filled `message_start.content` or tool input in `content_block_start` (must be `{}`);
  - a choice index other than 0;
  - identifiers (ids, model, tool names) outside `[A-Za-z0-9._:/@+-]` or over 256 bytes (tool names over 128).

**One-call integration in `node/src/gate.rs`:**
1. Keep one `Reemitter::new(dialect, stream)` per attempt.
2. Pass every `Bytes` the gate releases (`Gate::pop`, including its own `[moochy]` replacement events, which re-emit unchanged) through `reemitter.push(&bytes, &mut out)?`. Write only `out` to the client, then clear it.
3. At the end, call `reemitter.finish(&mut out)?`. For a non-streamed body, `finish` emits the whole canonical body; `reemit::reemit(dialect, false, &body)` does the same in one call.
4. Any `Err` means: write nothing more and fail the attempt.

Spans stay the gate's job (holding tool blocks until a verified checkpoint); re-emission is the last step before the client write.

**Verified:**
- Differential tests: for all 21 streamed and 8 non-streamed fixtures (hand-written real-provider shapes plus bodies captured from every Go fake: Anthropic, DeepSeek and OpenRouter Anthropic-shape; OpenAI, DeepSeek, OpenRouter and xAI chat), the strict parser sees the same usage, model, id, completeness and tool events before and after re-emission. The output is a fixed point and independent of chunking.
- mo-sec's A162 matrix is in `tests/reemit.rs`.
- Fuzzed: re-emission never panics and never turns an accepted stream into a malformed one.

**Cost** (release, one core): 0.7 µs per Anthropic text event, 1.2 µs per OpenAI chunk (budget 20 µs).

### `clean_text` (CONTRACT §15.4, A165/A46)

`moochy_worker::clean_text(&str) -> Cow<str>` removes:
- ESC sequences: CSI, OSC (incl. OSC 8 links and OSC 52 clipboard writes), DCS/SOS/PM/APC, and any other `ESC x`;
- C1 controls, including 8-bit CSI/OSC with their parameters;
- C0 controls except `\n` and `\t` (`\r\n` becomes `\n`; a lone `\r` is dropped) and DEL;
- bidi controls (LRE/RLE/PDF/LRO/RLO, LRI/RLI/FSI/PDI, LRM/RLM/ALM).

Clean input is returned borrowed, with no allocation. mo-node: apply it to every donor text shown in a terminal (MCP door results, NACK details, model enums). `reemit` already applies it to text fields.

Tool-call inputs stay byte-exact (they are executed), so instead `ToolSet::check_call` blocks any input containing ESC, C1 or bidi controls (tripwire rule `terminal-control`). That stops a spoofed approval prompt.

### `inspect` (Gateway side, 06 §8)
- `ToolSet::from_request(dialect, body)`, `check_call(name, input_json) -> Verdict::{Allow, Block(reason)}`: name ∈ `tools[]`, input is a strict JSON object, schema subset (`type, enum, const, properties, required, additionalProperties, items, anyOf, oneOf, allOf`; other keywords ignored), then the tripwire.
- `scan_text(text)` for MCP `moochy_delegate` results.
- `TextScanner::new()` and `push(delta) -> Option<rule>` (CONTRACT §15.4, T-C15-021): streaming tripwire over response *text* (prompt injection). A 512-byte carry-over window catches patterns split across deltas; each rule is reported once; Markdown backticks are treated as code spans. It is a flag, not a block: the Gateway adds a visible `[moochy] warning: the response suggests a dangerous command (<rule>)` notice.
- Tripwire rules: `terminal-control` (ESC/C1/bidi in tool inputs), `pipe-to-shell`, `credential-path`, `persistence`, `encoded-payload`, `raw-ip-egress`. **A speed bump, not a guarantee.**

### `store`
One CRC-32-framed append-only log holding the outbox, the served-task set and the
reservation counters. Torn tails are truncated on open (tested at every byte offset).
`put_receipt` writes the receipt *and* its settlement as one frame (atomic) and fsyncs;
everything else is written without fsync (survives a process crash; after a power loss a
reservation whose settlement was lost is settled at its amount after 24 h). Device
counters use UTC calendar months; pledge periods are caller-supplied ids (anchored per
pledge, 05 §9); open reservations always count. Bit rot in the middle of the log truncates
everything after it (lost unacked receipts settle pessimistically at the Relay).

### `json`
Strict tape parser (`parse`, `OwnedDoc`), views (`Val`), minified `write`, `write_patched`.
Rejects duplicate keys (after unescaping), invalid UTF-8, lone surrogates, raw control
characters, integers outside i64, non-finite floats, depth > 64, more than 2 Mi values
(bounds tape memory to 24 MiB whatever the body), trailing bytes.
Reusable by the node for every security/money JSON parse (route header, receipts, MCP).

## Decisions on ambiguities (safer/simpler reading)

- **PDFs (CONTRACT R3)**:
  - `strict` accepts base64 PDF `document` blocks (also nested in `tool_result`) only with the `documents` flag, at ≤ 100 pages per request. `paranoid` refuses all documents.
  - Pages = max(`/Type /Page` objects, largest `/Count`). A PDF whose page tree is only in compressed object streams is refused (it can't be counted); over-counting only raises the reservation.
  - PDF bytes are excluded from `text_bytes`; the estimate adds `pages × max_page_tokens`.
- **`text_bytes`** = body length − inline base64 image data (raw JSON bytes, escapes included: over-estimates, never under).
- **Route `flags`** must equal the body's flags exactly (not a superset).
- **Beta headers**: static allowlist in `tables.rs` (catalog-versioned list later).
  - `context-1m-*` needs `long_context`.
  - Files, code-execution, MCP, web, OAuth, `dangerous-tool-use`, `thinking-token-count`, `prompt-caching-scope`, `mid-conversation-tool-changes` and `afk-mode` are refused (`pool_compatible` strips them at the Gateway).
  - `anthropic-version` defaults to `2023-06-01`.
- **Real-client widening (T-07-087; needs the second reviewer per 06 §7.3):** observed in Claude Code 2.1.287 traffic (`tests/fixtures/clients/`):
  - `role: "system"` turns, text only, with optional per-turn `output_config.effort` (max wins);
  - `context_management` with `clear_thinking_*` / `clear_tool_uses_*` edits only (content removal, no execution);
  - betas `context-management-2025-06-27`, `mid-conversation-system-2026-04-07`, `per-turn-control-2026-07-01`.
  - `safeguards` stays refused.
- **JSON canonical form**: integers are re-emitted from their value (`-0` → `0`), so any parser reads the forwarded body the same way. This is checked against Python's `json` on 459 forwarded documents (`tests/differential.rs`) and against `serde_json` by fuzzing (`fuzz/json_diff`).
- **Paranoid** level: images and documents refused, `max_tokens ≤ 16384`.
- **Provider 4xx** (other than 401/403/404/408/429) after the firewall passed: non-retryable `provider_error` with the provider's body.
- **Estimated output** when usage is missing: max(reported, ⌈delta payload bytes / 4⌉); estimated receipts settle at the reservation anyway (05 §5.2).

## Fuzzing (`fuzz/`, T-02-040 / T-06-064 / T-07-089)

- **Setup:** a standalone libFuzzer + ASan workspace on stable rustc (`RUSTC_BOOTSTRAP`, as in `moochy-proto`); not a workspace member, never shipped. Run with `./run.sh [seconds] [targets]`.
- **Targets and invariants:**
  - `firewall`: 5 providers; `pool_compatible` never turns an accepted body into a refused one; mutated bodies are strict JSON with the same facts.
  - `json`: canonical write is a fixed point.
  - `json_diff`: the lenient `serde_json` reads the same tree.
  - `stream`: results independent of chunking.
  - `reemit`: fixed point, chunking-independent, never introduces malformation.
  - `validate`: the child on raw and on well-formed wire requests.
  - `inspect`: tool calls, PDF pages, `clean_text`, `TextScanner`, cost decimals.
- **Seeds:** every crate fixture, including the recorded client corpus and the Go-fake captures.
- **This round:** 7 targets, about 19 M executions under ASan. One finding (`-0` integer canonicalisation, fixed); no crash.

## Measured (release, dev box arm64, one core)

| What | Result |
|---|---|
| SSE parse, smallest realistic events, one event per chunk | Anthropic 423–490 MB/s (300–345 ns/chunk), OpenAI 312–346 MB/s (565–625 ns/chunk) |
| h2+TLS loopback, 50k events: read + parse | ≈1 µs/event incl. the fake's TLS |
| warm h2 request → response headers (loopback) | ≈200 µs |
| cancel (drop) → provider sees `RST_STREAM` | 20–30 µs |
| `prepare()` on a 101 KB agent body | 303 µs |

Per-chunk path: no allocation after warm-up (line/data/tape buffers reused; model/id copied once), no lock, no fsync.

## xAI (Grok) adapter

Facts relied on (docs.x.ai, fetched 2026-10-01; sources in the agent report):

- Global host `https://api.x.ai`, OpenAI-compatible `POST /v1/chat/completions`, `Authorization: Bearer <key>`. Chat Completions is labelled *legacy* (Responses API is primary) but supported. `https://us.api.x.ai` (US-only processing, +10% price) is not allowlisted. No Anthropic-compatible endpoint is documented, so xAI serves `openai.chat` only.
- Firewall: the OpenAI table, plus refused for every provider `search_parameters` (live search, billed per source) and `deferred` (stored, fetched later); `web_search_options`, `service_tier` (`priority`/`fast` = 2× price), `n > 1`, non-function tools (`web_search`, `x_search`, `code_execution`, `mcp`, collections), URL images, `input_file`/file-id parts already refused. xAI-only: `store`, `modalities`, `verbosity`, `logit_bias` (not in xAI's API). Mutations: model id, `stream_options.include_usage`, `safety_identifier` = pseudonym.
- Usage: `prompt_tokens` includes `prompt_tokens_details.cached_tokens`; `completion_tokens` is visible output only and `completion_tokens_details.reasoning_tokens` is extra (`total_tokens = prompt + completion + reasoning`); `cost_in_usd_ticks` is the authoritative charge (`provider_cost_uusd`). Every stream chunk carries cumulative `usage`.
- Rate limits: per model RPS/TPM; no rate-limit response headers are documented. `x-ratelimit-*` headers are parsed if present; otherwise `headroom_pct()` is `None`.
- **Cost-bound caveat (for the catalog/reservation):** xAI's `max_completion_tokens` bounds *visible* output only; reasoning tokens (on by default, effort `high`, cannot be disabled on grok-4.5+) are not bounded by it. See the agent report for the reservation recommendation.

## Local inference servers (provider kind `local`)

A donor's own OpenAI-compatible server (Ollama `:11434`, LM Studio `:1234`, vLLM `:8000`, llama.cpp server `:8080`). It is free (price 0), goals are counted in tokens, and it goes through the same firewall, limits, re-emission and tool-call gating as hosted providers. Dialect: `openai.chat` only, at `<base>/v1/chat/completions`.

### For mo-donor (key and host configuration)

- **`moochy keys add local --base-url http://127.0.0.1:11434 [--key-stdin] [--allow-unvetted-host]`:**
  - Validate with `provider::check_local_base_url(url, allow_unvetted) -> Result<LocalHost, ConfigError>`; the URL is an origin only (`http(s)://host[:port]`).
  - `LocalHost::Loopback`: no warning. `LocalHost::Lan` (RFC 1918, IPv6 ULA, CGNAT/Tailscale `100.64/10`): warn that prompts cross the LAN, in clear text with `http://`.
  - Always refused: link-local (`169.254/16` incl. cloud metadata, `fe80::/10`), unspecified, multicast, broadcast.
  - Public IPs and host names (DNS can rebind them) are refused unless `--allow-unvetted-host` (dev). With it the result is `LocalHost::Unvetted`; print a loud warning at every start.
- **API key:** optional. Empty means no `Authorization` header; Ollama and LM Studio ignore keys, and vLLM uses one only with `--api-key`.
- **Adapter:** `Adapter::new(&AdapterConfig { provider: Provider::Local, base_url: Some(url), api_key, insecure_dev: false, dev_root: None, limits: Limits::local() })`. Use `Adapter::new_local(&cfg, true)` only with `--allow-unvetted-host`.
  - `Limits::local()` = headers 300 s and idle 300 s: a local server may load the model and process the whole prompt before the first byte.
  - `warm()` pre-opens a keep-alive connection. `https://` requires HTTP/2 (most local servers speak HTTP/1.1, so use `http://` on loopback/LAN).
- **Model mapping:** the donor maps public catalog slugs to server model ids in config, for example `"local/qwen2.5-0.5b-instruct-q4" = "qwen2.5:0.5b"`. Discover the server's ids with `GET <base>/v1/models` (Ollama, LM Studio, vLLM and llama.cpp all serve it). Pass the server id as `provider_model_id`.
  - The firewall refuses **cloud-routed ids** (`firewall::is_cloud_routed`: Ollama `*:cloud` / `*-cloud` tags). Those requests would leave the machine for ollama.com, billed to the donor's account. The refusal is `model_unavailable`, retryable elsewhere.
- **Firewall:** same OpenAI table. Also refused: `store`, `modalities`, `verbosity` and every server-specific extension (`top_k`, `min_p`, `repeat_penalty`, `chat_template_kwargs`, `options`, …).
  - Mutations: model id mapping and `stream_options.include_usage` only. No end-user id: there is no account to attribute abuse to on the donor's own box.
- **Offer:** `rl_headroom` 100 (local servers send no rate-limit headers). `slots_max` should match the server's parallel slots (llama.cpp `-np`, Ollama `OLLAMA_NUM_PARALLEL`).
- **Usage:** from the server's `usage` (forced via `include_usage`; exact).
  - Without it, llama.cpp's cumulative `timings` give exact counts (`prompt_n` + `cache_n` = prompt tokens).
  - Otherwise usage is `estimated` (output from streamed bytes; Ollama-style `timings` without `cache_n` count all prompt tokens as input).
  - Reasoning is inside `completion_tokens`, bounded by `max_tokens`. `provider_cost_uusd` is `None`; cost = catalog price 0.

### Remote GPU servers over TLS (CONTRACT §17.3, for mo-donor)

A donor's own server on RunPod, Vast or Lambda serves as the same `local` provider kind: same firewall, `Limits::local()`, price 0 and self-reported trust tier. The only differences are the transport and the vetting.

- **Command:** `moochy keys add local --url https://abc123-8000.proxy.runpod.net [--header-from-keystore x-api-key] [--ca-file box-ca.pem | --cert-sha256 HEX]`
  1. `provider::remote_host_key(url)` returns the canonical `host:port` (lowercase; port explicit, default 443; IPv6 in brackets). Show it, and have the donor confirm it is their server (`--yes` must not skip this). Store it in the donor config's vetted list.
  2. Loopback and LAN URLs return an error from `remote_host_key`: they need no vetting and keep the `--base-url` rules above.
  3. Plain `http://` to anything off the LAN is refused, also with `--allow-unvetted-host`. That flag (dev) only skips the vetted list.
- **Adapter:** `Adapter::new_local_with(&cfg, &LocalOptions { vetted_hosts, auth_header, trust, allow_unvetted_host })`, with `cfg.api_key` empty when `auth_header` is set (both together are refused) and `dev_root: None`.
  - Pre-check the URL with `provider::check_local_url(url, &opts)`. `LocalHost::Remote` means a vetted remote host.
  - The base URL is still an origin only; the path stays `/v1/chat/completions`.
- **Auth header from the keystore:** `auth_header: Some((name, Zeroizing<String>))`, read from the keystore at start, never from config or argv.
  - The name is a lowercase token: `authorization` (value e.g. `Bearer …`), `x-api-key`, … Framing and routing headers (`host`, `content-length`, `transfer-encoding`, `cookie`, `proxy-*`, `x-forwarded-*`, …) are refused.
  - The value is a sensitive header: it is never printed by `Debug`, logs or errors. Do not log it on your side either.
- **Certificates (`RemoteTrust`):**
  - `Roots` (default): Mozilla roots (webpki-roots, as for hosted providers; no OS store) plus the host name. Fits the platform proxies (`*.proxy.runpod.net`, …).
  - `Ca(der)`: only this CA, plus the host name. Use it for a self-signed CA on the box (`--ca-file`, PEM → DER on your side).
  - `Fingerprint([u8; 32])`: SHA-256 of the server certificate's DER (`--cert-sha256`); no CA and no name check, handshake signatures still verified. Re-pin when the box rotates its certificate.
- **SSRF guards:** you get these by construction; do not re-implement them.
  - Each new connection resolves the name in the worker and is refused unless every address is public (loopback, LAN, link-local, metadata, v4-mapped all refused: DNS rebinding). The worker dials that exact address.
  - Redirects are never followed (a 3xx is a provider error).
  - Zone ids, userinfo, numeric host forms (`2130706433`, `127.1`, `0x7f.1`), a trailing dot and IDN are refused at config time.
- **Wire:** HTTP/1.1 over TLS (ALPN `http/1.1`), keep-alive pool, driven in the reading task like the plain h1 path. `Adapter::warm()` pre-opens a connection.
- **doctor/status:** show `local (remote, vetted host:port, trust: roots|ca|fingerprint)`, never the header value.

### For mo-relay (catalog and trust tier)

- **Catalog entries:** `provider: "local"`, `dialects: ["openai.chat"]`, every price field 0, `max_output` per model, `default_effort: "none"` (or the model's).
- **Own public slugs**, for example `local/<model>-<quant>`: a quantised local model is not the hosted model, so requesters opt in to it explicitly. Never reuse a hosted slug.
- **Trust tier:** add a field such as `trust: "self_reported"` for local entries. Usage comes from the donor's own server (a lying donor can inflate token counts), and nothing is billed. So:
  - local tokens count toward token-denominated goals and a separate "local compute" leaderboard, labelled self-reported;
  - they never count toward money totals;
  - receipts settle at 0 (`r = 0`, so no reservation is needed);
  - disputes still apply: visible output ±25% (03 §12.2).
- **Scheduling:** a local pledge serves only the `local/*` slugs it offers. Treat it like any donor for approvals (owner-signed `DONOR_APPROVED`).

### Verified

- **Recorded fixtures:** 16 byte-exact responses from Ollama 0.35.0 and llama.cpp server b11312 (Qwen2.5-0.5B, Qwen3-0.6B thinking), with provenance in `tests/fixtures/local/README.md`.
- **Tests:** `tests/local.rs` covers per-server usage, tool calls, lossless re-emission, the host-vetting table, adapter rules and the firewall.
- **Live test:** `MOOCHY_LOCAL_SERVERS=… cargo test --test local -- --ignored` passes end to end against both servers (text and tool call).
- **Fuzz:** `local_url` (7 M executions), plus `stream`, `reemit` and `firewall` with local seeds and `Provider::Local`; no crash.

## Per-chunk performance (E22, CONTRACT §13)

- **`Response::next()`:**
  - Returns as soon as one provider frame is there, merged with every frame already buffered (≤ 16 KiB). A lone event still comes out alone (`paced_events_are_not_batched`).
  - Then yields once on the next call. The task you woke with `tx.send` sits in tokio's LIFO slot, which other workers cannot steal, so without the yield a whole burst was read and sealed before the first link write.
  - `http://` connections (dev fakes, local donors) are polled by the awaiting task: no connection task and no cross-thread wake per chunk.
  - The idle timer is re-armed only when it fires.
- **Measured costs (this box, release):**
  - `StreamParser::feed`: 0.34 µs (Anthropic) / 0.65 µs (OpenAI) per event.
  - `Reemitter::push`: 0.67 / 1.2 µs per event.
  - `firewall::analyze` / `prepare` on the E22 100 KB body: 19 / 22 µs (SWAR string scan, 5 GB/s).
- **Consumer tip:** do not add per-chunk work between `next()` and the send. Seal and send at once, or hand the chunk to the task that writes the socket directly.
