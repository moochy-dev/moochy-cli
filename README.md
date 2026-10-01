# Moochy

Donate a capped slice of your own LLM API budget to open-source projects. Maintainers use it from any MCP client or any tool with a provider-compatible base URL. Your key never leaves your machine; every request is end-to-end encrypted and accountable.

**Open-source client (Apache-2.0) · closed-source relay and web app · 100% free: no fees, no commission, no paid tier.**

This development monorepo is internal. At release, the open-source parts (`cli/`, `spec/proto`, `spec/vectors`, `spec/protocol.md`, `docs/guides`) are exported to the public `moochy-cli` repository; everything else stays in the private `moochy-core` repository (see `spec/CONTRACT.md` §0a).

- Design: [`docs/plan/00-PLAN.md`](docs/plan/00-PLAN.md)
- Implementation contract: [`spec/CONTRACT.md`](spec/CONTRACT.md)
- Agent rules: [`AGENTS.md`](AGENTS.md)

| Path | What |
|---|---|
| `cli/` | Rust: the `moochy` binary — gateway, MCP server, worker (open source, Apache-2.0) |
| `relay/` | Go: the relay and web app (closed source) |
| `e2e/` | End-to-end and attack tests with fake providers (closed source) |
| `spec/` | Internal contract (closed) + public protocol: `proto/`, `vectors/`, `protocol.md` (open source) |
