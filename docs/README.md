# provio documentation

| Document | What it covers |
|---|---|
| [owasp-agentic.md](owasp-agentic.md) | provio's controls mapped to the OWASP Top 10 for Agentic Applications (2026), with honest coverage levels |
| [comparison.md](comparison.md) | provio next to dcg, nah, cc-safety-net, the built-in agent sandboxes and Microsoft's Agent Governance Toolkit, including what provio does worse |
| [first-run.md](first-run.md) | `provio scan` (what would provio have caught?), `provio init` (a policy and hooks for every agent), `provio test` (one call, nothing run) |
| [inspection.md](inspection.md) | How a call is judged by what it runs: scripts, heredocs, `npm run`, shell inside code; and what that misses |
| [policy-reference.md](policy-reference.md) | The `provio.yaml` language: rules, conditions, verdicts, defaults, packs |
| [INTERFACES.md](INTERFACES.md) | The frozen contracts between crates: call context, verdict IR, ledger record schema, sandbox backend, CLI surface |
| [THREAT_MODEL.md](THREAT_MODEL.md) | What provio defends against, what it does not, and where each boundary sits |
| [SECURITY.md](SECURITY.md) | How to report a vulnerability, and the supported versions |
| [DECISIONS.md](DECISIONS.md) | Architecture decision records (ADRs) |
| [BRAND.md](BRAND.md) | Name, voice, and claim discipline |
| [ui.md](ui.md) | `provio ui`: the local console, its security model, and `provio check --ask ui` |
| [receipts.md](receipts.md) | Signed receipts, inclusion proofs and anchoring (Contract 7), with their threat model |
| [ledger-postgres.md](ledger-postgres.md) | The Postgres ledger store: setup, roles, schema, concurrency, TLS |
| [mcp-pins.md](mcp-pins.md) | MCP tool pinning: changed tool definitions (rug pulls) are held until you accept them |
| [mcp-http.md](mcp-http.md) | The MCP proxy over Streamable HTTP / SSE |
| [integrations/](integrations/) | Codex CLI, Gemini CLI, Cursor and Windsurf: setup, mapping, residual risks |

Internal build planning (how the project is being built, not how to use it)
lives in [internal/](internal/).

For a first run, start with the [README](../README.md); for contributing, see
[CONTRIBUTING.md](../CONTRIBUTING.md).
