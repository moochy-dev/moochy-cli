# OpenAI Responses dialect (CONTRACT §18.6): worker spec for the other owners

Codex only speaks `POST /v1/responses`. Moochy carries it as a **passthrough** to donors whose provider speaks it natively. mo-worker leads; this is what the worker crate provides and what each owner wires.

## The dialect

| | |
|---|---|
| Rust | `moochy_worker::Dialect::OpenAiResponses` (`Dialect::parse("openai.responses")`, `.as_str()`) |
| Wire / route header / offers | `"openai.responses"` (`PoolWorker.dialects`, catalog `dialects`, route `dialect`) |
| Validator child wire index | `2` (after `anthropic.messages` = 0, `openai.chat` = 1) |
| Providers | `Provider::serves(Dialect::OpenAiResponses)` is true only for OpenAI and xAI (`/v1/responses`) and OpenRouter (`/api/v1/responses`); false for Anthropic, DeepSeek and Local. |

The adapter, connection reuse, timeouts, flush per chunk (E22) and cancel are the same as for the other dialects: `Adapter::send(Dialect::OpenAiResponses, …)` picks the path.

## Request firewall (`firewall::analyze` / `prepare` / `pool_compatible`)

Same entry points, with `dialect = OpenAiResponses`; `ToolSet::from_request` and `response_tool_calls` also take it.

- **Allowed:**
  - `input` (a string, or items: messages by role `user`/`system`/`developer`/`assistant`, `function_call`, `function_call_output`, `custom_tool_call`, `custom_tool_call_output`, `reasoning` with `encrypted_content`);
  - `instructions`, `tools`, `tool_choice`, `parallel_tool_calls`, `max_output_tokens`, `max_tool_calls`;
  - `temperature`, `top_p`, `top_logprobs`, `stream`, `stream_options.include_obfuscation`;
  - `include` (`reasoning.encrypted_content`, `message.output_text.logprobs`), `reasoning` (`effort`, `summary`), `text` (`format`, `verbosity`), `truncation`;
  - `user`, `safety_identifier`, `prompt_cache_key`;
  - inline `data:image/` images, behind the `images` opt-in.
- **Tools:** client-executed only.
  - `function` tools: name + JSON-schema check + tripwire.
  - `custom` free-form tools such as Codex `apply_patch`: name check + tripwire on the text input.
- **Refused hosted tools** (`Reject { code: Firewall, path: "tools[i].type", reason }`, reason names the tool):
  - `web_search`, `web_search_preview`, `file_search`, `code_interpreter`;
  - `computer_use`, `computer_use_preview`, `image_generation`;
  - `mcp` (remote MCP), `local_shell`.
  - Their call items in `input` are refused too.
- **Stateless only:** each is refused with a reason that starts "stateless only" (or names the feature).
  - `store: true`, `background: true` (`false` accepted).
  - `previous_response_id`, `conversation` (`null` accepted), `input[].type = item_reference`.
  - `prompt` (stored templates), `metadata`, `prompt_cache_retention`.
  - Also refused: `service_tier`, OpenRouter routing fields, `input_file`, image URLs other than `data:image/`, and unknown members.
- **Headers:** none are forwarded for this dialect; any header is refused. The gateway must drop Codex's `session_id`, `originator`, `conversation_id` and `version` headers, which identify the maintainer.
- **Route facts:**
  - `max_tokens` = `max_output_tokens`, or the catalog `max_output` (paranoid: ≤ 16 384) when absent. Codex sends none.
  - `effort` = `reasoning.effort` (catalog default when absent); `stream` = `stream`.
- **Worker mutations** (`prepare`): `store: false` and `max_output_tokens` (= route `max_tokens`) are always written.
  - OpenAI and xAI: `safety_identifier` = pseudonym.
  - OpenRouter: `user` = pseudonym, `provider.max_price`, `provider.allow_fallbacks: false`.
- **Native error shape at the gateway** (mo-node): same as `openai.chat`: HTTP 400 `{"error":{"message":…,"type":"invalid_request_error","param":<path>,"code":<nack code>}}`. A firewall refusal before sealing uses the reject's `path` and `reason`.

## Response side (the gate)

- **`StreamParser::new(Dialect::OpenAiResponses, stream)`**, events for the gate:
  - **Tool calls:**
    - `ToolStart { index: output_index, id: call_id, name }` on `response.output_item.added` for `function_call` and `custom_tool_call`;
    - `ToolArgs` for the input in `added` and for every `function_call_arguments.delta` / `custom_tool_call_input.delta` (a JSON string: decode with `as_str`; for custom tools the decoded text is the input);
    - `ToolEnd` on `response.output_item.done`.
  - **Stop and errors:**
    - `Stop` on `response.completed` and `response.incomplete`;
    - `Error` on `response.failed` and `error`.
  - **Fail closed (`Invalid`):**
    - the `*.done` copies (`function_call_arguments.done`, `custom_tool_call_input.done`, `output_item.done`) differ from what was streamed (what the client executes is what was inspected);
    - unknown event types;
    - text events on a tool item;
    - a reopened item;
    - `response.completed` with a call still open;
    - a `response.created` with pre-filled `output`.
  - **`Forbidden`:** hosted-tool items (`web_search_call`, `mcp_call`, …).
  - **Usage** (from `response.completed`):
    - `input = input_tokens − input_tokens_details.cached_tokens`, `cache_read = cached_tokens`;
    - `output = max(output_tokens, total_tokens − input_tokens)` (reasoning included);
    - `provider_cost_uusd` from OpenRouter `usage.cost` or xAI `usage.cost_in_usd_ticks`;
    - a stream cut before `completed` gives estimated usage.
- **`Reemitter::new(Dialect::OpenAiResponses, stream)`:** canonical events with `event:` lines, whether or not the donor sent them.
  - Every event type above has a schema; anything else fails the attempt.
  - Dropped fields: padding (`obfuscation`), echoed request fields (`instructions`, `tools`, `reasoning`, `text`, …) and `logprobs`.
  - **Streamed `response.*` lifecycle events carry no `output`:** items reach the client only through the gated `output_item.*` events, never as a second, uninspected copy. Codex reads only `id`/`usage` there.
  - A stray `data: [DONE]` is not forwarded.
  - On a refused event, `push` returns the canonical events before it (deliver them, then fail).
- **`reemit::visible_texts`:** covers every Responses text field (output text, refusals, reasoning summaries and text) for the tripwire (A216).
- **Tool-call gating** works exactly as for the other dialects: hold from `ToolStart` to `ToolEnd`, `ToolSet::check_call(name, assembled input)`. **mo-node** must write the replacement for a blocked call for this dialect: drop the held `output_item.added … output_item.done` span of that call and emit a message item with the `[moochy]` notice (`response.output_item.added` message → `content_part.added` → `output_text.delta` → `output_text.done` → `content_part.done` → `output_item.done`, same `output_index`). Secret masking of `input` and the tool-result scrub apply as for `openai.chat` (`function_call_output.output`, `custom_tool_call_output.output`).

## Per owner

- **mo-proto:** `msg::Dialect::OpenAiResponses` (`#[serde(rename = "openai.responses")]`). Cost from the receipt usage above, with the same checked money math (`in`, `out`, `cache_read`; no cache writes).
- **mo-node:**
  - **Gateway route:** add the gateway route `POST /v1/responses` and the dialect variant in `engine.rs`. Today `from_wire("openai.responses")` maps to `None` (a one-arm placeholder I added so the crate compiles).
  - **API door:** add the `moochy connect codex` API-door preset (`wire_api = "responses"`).
  - **Seal targets:** seal only to `PoolWorker`s whose `dialects` contain `"openai.responses"`.
  - **Worker side:** offer the dialect only where `adapter.provider().serves(Dialect::OpenAiResponses)` and the catalog entry lists it.
  - **Blocked-call rewrite:** implement the replacement for blocked calls described above.
  - **Headers and stateful fields:** drop client headers, and refuse the stateful fields at the gateway with the native error shape before sealing (call `firewall::analyze`; same refusals).
- **mo-e2e (E111):**
  - **Fake modes:** `responses` stream and body (the fixtures in `tests/fixtures/responses/` are the shapes), plus tags for:
    - an unknown event type;
    - a `web_search_call` item;
    - `*.done` arguments differing from the deltas;
    - a tool not in `tools[]`.
  - **Checks:**
    - byte-identical canonical events;
    - cost and receipt from `usage`;
    - `store: true` and `previous_response_id` refused;
    - a donor without `openai.responses` in its offer never chosen.
- **mo-relay:**
  - **Dialect matching:** match on the `dialects` string (already generic if routing compares strings).
  - **Catalog:** list `"openai.responses"` for openai, xai and openrouter models only.
  - **Pricing:** same prices as `openai.chat`.

## Not supported (yet)

- `local_shell` items (declare a function tool).
- Hosted tools and their annotations (`output_text.annotation.added`).
- `input_file`.
- Background mode, stored responses and conversation objects.
- Responses on local servers (vLLM/Ollama speak it, but §18.6 limits it to openai, xai and openrouter).
