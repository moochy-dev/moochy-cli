# Moochy

Donate tokens to open-source projects from your own LLM API account, with a monthly limit you choose. Maintainers use those tokens from any MCP client, or from any tool that lets them set a provider base URL. Your API keys stay on your machine. Every request is end-to-end encrypted, and the relay only sees encrypted bytes.

**Your API keys stay on your machine.** Moochy never stores your API keys online. They stay in your machine's keychain, used only by the Moochy app on that machine, and are never sent to Moochy's servers, not even encrypted. `moochy keys add` puts a key in your keychain, only the Moochy app on that machine uses it, and requests are encrypted end to end, so Moochy's servers see neither keys nor prompts.

Donors can use Anthropic, OpenAI, OpenRouter, DeepSeek, or xAI (Grok) API keys, or a model on their own GPU (Ollama, LM Studio, vLLM, llama.cpp).

A donor's machine only makes the inference call: it never runs a command, and the app locks itself down so it cannot. Maintainers run their coding agent with `moochy run`, a built-in sandbox that can touch the project and nothing else, so a bad tool call in a response cannot reach their files, keys, or network.

**Open-source client (Apache-2.0) · 100% free.** No fees, no commission, no paid tier. The relay and web app are closed source.

This development monorepo is internal. At release, the open-source parts (`cli/`, `spec/proto`, `spec/vectors`, `spec/protocol.md`, `spec/KEYLOG.md`, `docs/guides`, `deploy/client`, `SECURITY.md`) are exported to the public `moochy-cli` repository; everything else stays in the private `moochy-core` repository (see `spec/CONTRACT.md` §0a).

- Guides (public): [`docs/guides/`](docs/guides/README.md)
- User-facing wording: [`docs/brand/VOICE.md`](docs/brand/VOICE.md)
- Design: [`docs/plan/00-PLAN.md`](docs/plan/00-PLAN.md)
- Implementation contract: [`spec/CONTRACT.md`](spec/CONTRACT.md)
- Agent rules: [`AGENTS.md`](AGENTS.md)
- Reporting a vulnerability: [`SECURITY.md`](SECURITY.md)

| Path | What |
|---|---|
| `cli/` | Rust: the `moochy` app that runs on donors' and maintainers' machines (open source, Apache-2.0) |
| `relay/` | Go: the relay and the moochy.dev web app (closed source) |
| `e2e/` | End-to-end and attack tests with fake providers (closed source) |
| `spec/` | Internal contract (closed) and the public protocol: `proto/`, `vectors/`, `protocol.md` (open source) |
| `docs/` | Public guides (`guides/`, open source); internal plan, brand, ops, and security docs (closed) |
