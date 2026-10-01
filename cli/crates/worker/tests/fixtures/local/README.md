# Local inference server fixtures (recorded)

Recorded 2026-10-01 on the dev box (linux/arm64, CPU) from real servers in Docker, bound to
127.0.0.1, `temperature: 0`. Byte-exact responses of `POST /v1/chat/completions`.

| Prefix | Server | Model |
|---|---|---|
| `ollama_*` | Ollama 0.35.0 (`ollama/ollama:latest`) | `qwen2.5:0.5b`; `*_reasoning_*`: `qwen3:0.6b` |
| `llamacpp_*` | llama.cpp server build 11312 (`0c1e57098`, `ghcr.io/ggml-org/llama.cpp:server`, `--jinja`) | `Qwen/Qwen2.5-0.5B-Instruct-GGUF:Q4_K_M`; `*_reasoning_*`: `Qwen/Qwen3-0.6B-GGUF:Q8_0` |

Cases: `stream_text_usage` (`stream_options.include_usage`), `stream_text_nousage`,
`stream_tool` (one function tool), `stream_length` (`max_tokens` hit), `body_text`,
`body_tool`, `reasoning_stream` / `reasoning_body` (thinking model).

Quirks pinned by these files (tests/local.rs):
- usage only with `include_usage`, in a final chunk with `choices: []`; `prompt_tokens`
  includes `prompt_tokens_details.cached_tokens`; reasoning is inside `completion_tokens`;
- llama.cpp adds a cumulative `timings` object (`prompt_n` + `cache_n` = prompt tokens,
  `predicted_n` = completion) on every chunk, even without `include_usage`;
- Ollama 0.35 adds `timings` (no `cache_n`; `prompt_n` = all prompt tokens) next to `usage`;
- Ollama streams a tool call in one chunk; llama.cpp streams the arguments token by token;
  llama.cpp non-streamed `tool_calls` have no `index`;
- thinking: Ollama `delta.reasoning`, llama.cpp `delta.reasoning_content` (vLLM documents
  `reasoning`, formerly `reasoning_content`);
- no rate-limit headers; no API key required.

LM Studio and vLLM could not run on this box (desktop app / GPU images); their documented
OpenAI-compatible shapes are covered by these and the hosted-provider fixtures.
