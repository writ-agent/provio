# Agent integrations

All integrations speak provio's hook-gateway protocol
([`docs/INTERFACES.md`, Contract 6](../docs/INTERFACES.md)) to a `provio check`
child process, so every one of them records the same ledger evidence and
fails closed the same way: no answer from provio, no tool call.

| Package | Frameworks |
|---|---|
| [`python/`](python/) — `provio-sdk` | LangGraph, OpenAI Agents SDK, Claude Agent SDK, any callable (`@provio_tool`) |
| [`typescript/`](typescript/) — `provio-sdk` | Claude Agent SDK, any function or AI-SDK-style tool (`guard`, `guardTools`) |

Claude Code needs no package: `provio integrate claude-code` wires
`provio check --format claude-code` into its hooks, and `provio run -- claude`
does the same for one confined session.

Claude Code tool names map onto provio's policy vocabulary identically in the
Rust gateway and both packages: `Bash`/`PowerShell` → `bash` (`command`),
`Read`/`Glob`/`Grep`/`LS` → `fs.read` (`path`), `Write`/`Edit`/`MultiEdit`/
`NotebookEdit` → `fs.write` (`path`), `WebFetch` → `http` (`url.host`),
`WebSearch` → `web.search` (`query`), `mcp__<server>__<tool>` → `<tool>` on
`server`.
