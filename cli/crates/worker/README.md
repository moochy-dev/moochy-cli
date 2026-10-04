# moochy-worker

Everything in Moochy that touches an LLM provider or inspects provider traffic. Plain inputs in,
events out; no dependency on `moochy-proto`. The public surface and the node's wiring are in
`API.md`.

| Module | Role |
|---|---|
| `firewall` | strict JSON, per-provider allowlists, route facts, safe mutations; refuses server tools, code execution and unknown keys |
| `provider` | HTTP/2 + rustls adapters for Anthropic, OpenAI, OpenRouter, DeepSeek and xAI |
| `stream` | incremental SSE/JSON response parser: usage, model, tool-call boundaries |
| `inspect` | gateway-side structural checks of tool calls, and the tripwire |
| `validate` | the single-use request validator child (no files, no network, no keys) and its parent-side client |
| `redact` | removes provider keys from everything that leaves the donor's machine |
| `reemit` | canonical re-emission of donor responses to the maintainer's agent |
| `clean_text` | strips terminal control sequences from displayed donor text |
| `store` | crash-safe local log: outbox, served tasks, spend counters for the monthly, weekly and daily limits |

Test: `cargo test -p moochy-worker`. License: Apache-2.0. Part of
[moochy-cli](https://github.com/moochy-dev/moochy-cli).
