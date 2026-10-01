# Moochy

Donate a capped slice of your own LLM API budget to open-source projects. Maintainers use it from any MCP client or any tool with a provider-compatible base URL. Your key never leaves your machine; every request is end-to-end encrypted and accountable.

**100% open source (Apache-2.0 OR MIT). 100% free: no fees, no commission, no paid tier.**

- Design: [`docs/plan/00-PLAN.md`](docs/plan/00-PLAN.md)
- Implementation contract: [`spec/CONTRACT.md`](spec/CONTRACT.md)
- Agent rules: [`AGENTS.md`](AGENTS.md)

| Path | What |
|---|---|
| `cli/` | Rust: the `moochy` binary (gateway, MCP server, worker) |
| `relay/` | Go: the self-hostable relay and web app |
| `e2e/` | End-to-end tests with fake providers |
| `spec/` | Contract and cross-language test vectors |
