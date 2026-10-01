# provio as an MCP server: `provio mcp serve`

`provio mcp serve` runs provio as an MCP server on stdio. Its tools only
read: they never run a call and never write the ledger. Governing calls stays
the job of the agent hooks (`provio init`) and of `provio proxy`.

| Tool | What it returns |
|---|---|
| `check_tool_call` | What the policy would decide for a call: `allow`, `deny` (rule and reason), `ask` or `redact`. Give `command` (a shell command), or `tool` with `args` (`fs.read`/`fs.write` with `path`, `http` with `url`, an MCP tool with `server`). Scripts the command runs or writes are judged too; pass `cwd` to read them from a project. |
| `recent_decisions` | The latest decisions in the ledger, newest first; filter by `session` or `verdict`, `limit` up to 200. |
| `list_sessions` | Every session in the ledger, with denials and whether a human approved anything. |
| `verify_ledger` | Whether the hash chain is intact, or the first record where it breaks. |
| `policy_info` | The policy in force (the `provio.yaml` in the working directory, or the starter packs when there is none), its text, and the bundled packs. |

It reads `provio.yaml` and `.provio/ledger.jsonl` from the directory it is
started in (`--policy` and `--ledger` change that).

## Add it to a client

Claude Code:

```sh
claude mcp add provio -- npx -y provio mcp serve
```

Any client that takes a JSON server list (Claude Desktop, Cursor, Windsurf,
Gemini CLI):

```json
{
  "mcpServers": {
    "provio": { "command": "npx", "args": ["-y", "provio", "mcp", "serve"] }
  }
}
```

With Python instead of Node: `"command": "uvx", "args": ["provio", "mcp", "serve"]`.
With Docker, from a checkout: `docker build -t provio .` and
`docker run -i --rm -v "$PWD:/work" provio`.

## Why an agent would call it

An agent that checks before it acts gets the refusal, and the rule and
reason behind it, before it has spent a turn on a command the hooks will
refuse anyway, and it can explain to you why. `recent_decisions` and
`verify_ledger` let you ask your assistant what happened in a session and
whether the record of it is intact.
