# `moochy-worker` public API

Everything that touches a provider or inspects provider traffic. Plain inputs in, events
out. No dependency on `moochy-proto`: the node does sealing, signing and the gRPC link.

## Worker pipeline (plan 07 §6.1) → calls

| Step | Call |
|---|---|
| 2. never served before, ±10 min | `Store::check_served(gateway_device, task_id, ulid_ts_ms, now_ms)` → `Stale`/`Replay` = NACK `unauthorized_task` |
| 3. firewall + route/body consistency | `firewall::prepare(&Request{..})` → `Prepared{facts, body, headers}`; then `prepared.facts.check_route(dialect, &Route{..})`. `Reject::code.nack()` gives `("firewall", false)`, `("route_mismatch", false)` or `("model_unavailable", true)`; `reject.to_string()` is the sealed detail |
| 4. local reservation | `Store::reserve(&Reservation{..})` → `Cap(_)` = NACK `local_cap` (retryable). In memory + written, **no fsync** (CONTRACT §13) |
| 6. call the provider | `Adapter::send(dialect, prepared.body, &prepared.headers)` → `Response` once headers arrive (= `task.started`), or `Failure` (`failure.nack()`; `failure.body` = native error to seal) |
| 7. stream | loop `response.next()` → forward each `Bytes` **as-is, immediately** (seal + send per chunk); `parser.feed(&chunk, sink)?.tool_ends > 0` → sign a progress checkpoint after this chunk |
| 8. end | `parser.finish()` → `Outcome{usage, model, id, complete, provider_error, forbidden, malformed, tail}`; build/sign the receipt → `Store::put_receipt(key, receipt_bytes, cost_uusd, now)` (settles + **fsync**) → `task.end` |
| 9. cancel / link lost | drop the `Response` (h2 `RST_STREAM` / h1 socket closed: the provider stops at once), then `finish()` → `usage.estimated` if final usage never came |
| NACK before the provider call | `Store::release(key)` |
| `receipt.ack` | `Store::ack(key, now)`; replay with `unacked()`, `since(ms)` (`receipt.replay_since`) |
| offer | `Store::device_left(cap, now)` → `local_cap_left`; `Response::requests_remaining` → `rl_headroom` |

All `Store` methods do blocking file I/O: own the `Store` in one thread (or `spawn_blocking`).
Call `Store::compact(now)` daily (also done on `open`). Call `Adapter::warm()` at startup, on
key add, and about every minute (h2 PINGs keep the connection alive in between).

## Modules

### `firewall`
- `Policy { level: Strict|Paranoid, flags: Flags, max_effort: Effort }` – pledge opt-ins. `Policy::PERMISSIVE` for the Gateway.
- `Catalog { default_effort, max_output, max_image_tokens }` – the signed-catalog numbers of the route's model.
- `Request { provider, dialect, body, headers, policy, catalog, provider_model_id, user_pseudonym, max_price }`.
- `prepare(&Request) -> Result<Prepared, Reject>`: strict JSON (CONTRACT §1), table walk (`tables.rs`), header allowlist, facts, safe mutations re-serialized from the validated tree.
- `analyze(dialect, body, headers, &policy, &catalog) -> Result<Facts, Reject>`: same checks, no mutation. **The Gateway must build the route header from `analyze(.., &Policy::PERMISSIVE, ..)`** so `est_input_tokens`, `effort`, `cache_ttl`, `flags` match the Worker bit for bit.
- `Facts { model, max_tokens, effort, est_input_tokens, cache_ttl, stream, flags, text_bytes, images }`, `Facts::check_route(dialect, &Route)`.

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

- **Base URL = origin, never a root.** The `base_url` override (CONTRACT §6) replaces only `scheme://host:port`; the path always comes from the table above, so the e2e fakes (`e2e/fake`) serve exactly the real paths. Accepted only with `insecure_dev` **and** a loopback **IP literal** (`localhost` refused: name resolution is attackable). A trailing `/` is fine; **any path is refused** (`http://127.0.0.1:P/api` → error "base URL must be an origin"), so nobody has to guess whether a prefix is an origin or an API root. `http://` → HTTP/1.1 (e2e fakes), `https://` → HTTP/2 (+ `dev_root` trust anchor, tests only).
- Verified against the real Go fakes for all six provider × dialect pairs (`tests/provider.rs::against_e2e_fakes`, opt-in via `MOOCHY_E2E_FAKES`).
- Auth: Anthropic `x-api-key`; others `Authorization: Bearer`.
- Transport: one warm HTTP/2 connection per adapter (multiplexed, re-dialed when closed), ALPN `h2` required, rustls/ring, Mozilla roots, `TCP_NODELAY`, stream window 2 MiB, connection window 8 MiB, keep-alive PING 20 s.
- **Loopback dev targets behave the same way** (so E77 measures production behaviour): `http://` overrides use an HTTP/1.1 keep-alive pool (up to 16 idle connections, `TCP_NODELAY`). `warm()` opens one connection ahead of time; a connection returns to the pool only after its response body was read to the end; a dropped (cancelled) response closes its connection, so the provider sees the abort and the connection is never reused. A request is retried on a fresh connection only when hyper proves it was never sent (a pooled connection the server closed in between), so a provider call is never executed twice. Verified against the real Go fakes: one TCP connection per fake for warm-up + all requests.
- `Limits` (defaults): connect 5 s, headers 30 s, idle between chunks 120 s, total 1 h, response 128 MiB, error body 64 KiB.
- `Failure.nack()`: 429 → `rate_limited` (+`retry_after_ms`), 503/529 → `overloaded`, 5xx/network/timeout/401/403 → `provider_error` (retryable), 404 → `model_unavailable`, other 4xx and oversize → `provider_error` **non-retryable**.

### `stream`
- `StreamParser::new(dialect, stream)`, `feed(&chunk, &mut sink) -> Result<Chunk{tool_ends, events}, StreamError>`, `finish() -> Outcome`.
- `sink(Span{start,end}, Event)`: spans are contiguous byte ranges of whole SSE events (comments included), so the Gateway can forward byte-identical output and hold exactly the tool-call events. Events: `Other`, `ToolStart{index,id,name}`, `ToolArgs{index,json}` (a `json::Val` string, decode with `as_str`), `ToolEnd{index}`, `Forbidden{block_type}`, `Error`, `Stop`, `Invalid`. One event may yield several items with the same span.
- **Fail closed (Gateway):** on `Invalid` (unparsable/duplicate-key JSON, a stray `\r` or BOM, tool input in `content_block_start` or `message_start`, a delta for a closed/unknown tool block, a re-started index, an OpenAI choice ≠ 0, an unindexed/reopened tool call, a second name fragment, legacy `function_call`) do not forward the event and fail the task; `Outcome.malformed` is set and usage becomes estimated. Real provider streams never trigger it (fixtures, CRLF variants tested).
- Usage mapping (05 §3): Anthropic `message_start` + cumulative `message_delta`, `cache_creation` TTL split (else all 5m), `usage.iterations` summed when present; OpenAI `prompt − cached − cache_write`, DeepSeek `prompt_cache_miss/hit_tokens`, OpenRouter `usage.cost` → µ$ by exact decimal ceil (`decimal_to_uusd_ceil`). Any unparsable/duplicate-key event ⇒ `estimated`.
- Non-streamed responses: `stream = false`, feed the body, `finish()`. Tool calls of a non-streamed body: `inspect::response_tool_calls`.

### `inspect` (Gateway side, 06 §8)
- `ToolSet::from_request(dialect, body)`, `check_call(name, input_json) -> Verdict::{Allow, Block(reason)}`: name ∈ `tools[]`, input is a strict JSON object, schema subset (`type, enum, const, properties, required, additionalProperties, items, anyOf, oneOf, allOf`; other keywords ignored), then the tripwire.
- `scan_text(text)` for MCP `moochy_delegate` results.
- Tripwire rules: `pipe-to-shell`, `credential-path`, `persistence`, `encoded-payload`, `raw-ip-egress`. **A speed bump, not a guarantee.**

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

- **PDFs**: 06 §7.1 says "strict level denies PDFs"; only `strict` and `paranoid` exist, so PDFs are never allowed and `pages = 0` in the estimate. Text documents need the `documents` flag.
- **`text_bytes`** = body length − inline base64 image data (raw JSON bytes, escapes included: over-estimates, never under).
- **Route `flags`** must equal the body's flags exactly (not a superset).
- **Beta headers**: static allowlist in `tables.rs` (catalog-versioned list later); `context-1m-*` needs `long_context`; files/code-execution/MCP/web/OAuth/context-management betas refused. `anthropic-version` defaults to `2023-06-01`.
- **`context_management`** (server-side context editing) refused in v1.
- **Paranoid** level: images and documents refused, `max_tokens ≤ 16384`.
- **Provider 4xx** (other than 401/403/404/408/429) after the firewall passed: non-retryable `provider_error` with the provider's body.
- **Estimated output** when usage is missing: max(reported, ⌈delta payload bytes / 4⌉); estimated receipts settle at the reservation anyway (05 §5.2).

## Measured (release, dev box arm64, one core)

| What | Result |
|---|---|
| SSE parse, smallest realistic events, one event per chunk | Anthropic 423–490 MB/s (300–345 ns/chunk), OpenAI 312–346 MB/s (565–625 ns/chunk) |
| h2+TLS loopback, 50k events: read + parse | ≈1 µs/event incl. the fake's TLS |
| warm h2 request → response headers (loopback) | ≈200 µs |
| cancel (drop) → provider sees `RST_STREAM` | 20–30 µs |
| `prepare()` on a 101 KB agent body | 303 µs |

Per-chunk path: no allocation after warm-up (line/data/tape buffers reused; model/id copied once), no lock, no fsync.
