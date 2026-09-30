# Cursor

provio decides Cursor agent tool calls through Cursor's hooks: `preToolUse`
for built-in tools, `beforeMCPExecution` for MCP calls (it carries the
server identity and supports `ask`), and `postToolUse` / `postToolUseFailure`
for completion. Every call is recorded in the ledger.

Protocol verified against <https://cursor.com/docs/hooks>,
<https://cursor.com/docs/reference/third-party-hooks> and
<https://cursor.com/docs/reference/plugins>.

## Setup

Per project (writes `.cursor/hooks.json`, `version: 1`):

```sh
provio integrate cursor         # --print to preview
```

Project hooks run only in a trusted workspace.

For the Cursor CLI (`agent`, formerly `cursor-agent`), one confined session:

```sh
provio run -- agent             # or: provio run -- cursor-agent -p "task"
```

`provio run` passes the hooks as a local plugin, `--plugin-dir <dir>`, with
`.cursor-plugin/plugin.json` and `hooks/hooks.json` in a provio-owned control
dir outside the writable set. Cursor documents plugin-bundled hooks and the
`--plugin-dir` flag, but a CLI version that ignores plugin hooks would run
ungoverned. `provio run` reports after the session if no tool call reached
provio.

## What provio answers

Every provio entry sets **`failClosed: true`**, so a crash, timeout,
non-zero exit or missing output of the hook blocks the action (Cursor
otherwise fails open on those).

| provio verdict | hook | Cursor output | effect |
|---|---|---|---|
| allow | preToolUse / beforeMCPExecution | `{"permission":"allow"}` | runs |
| deny / any provio error | both | `{"permission":"deny","user_message","agent_message"}`, **exit 0**, stderr | blocked |
| ask (`--ask defer`, which integrate uses) | beforeMCPExecution | `{"permission":"ask",…}` | Cursor's own prompt; approval recorded as `{kind: tui, id: "cursor-prompt"}` |
| ask | preToolUse | deny | `ask` "is accepted by the schema but not enforced for preToolUse" |
| redact on an MCP tool | postToolUse | `updated_mcp_tool_output` = the result with every string leaf masked | the model sees the masked result |
| redact on any other tool | preToolUse | deny | Cursor lets a hook replace only MCP output |

Why exit 0 for a deny: Cursor honours `permission:"deny"` from exit 0, and
for its permission hooks invalid or missing JSON also blocks. Exit codes do
not survive every shell (PowerShell 5.1 turns 2 into 1). The hook command
runs in the user's shell, so it uses forward slashes and no quotes on
Windows; paths that would need quoting are refused by `provio integrate`.

`preToolUse` answers `allow` for `MCP:<tool>` calls without recording a
decision: they are decided at `beforeMCPExecution`, which carries
`mcp_server_name` (a missing server name is denied, as Cursor recommends).
Non-MCP `postToolUse` / `postToolUseFailure` events correlate by
`(conversation_id, tool_use_id)`. MCP ones have no server field, so they
correlate to the newest open `beforeMCPExecution` decision of the
conversation for the same tool and params. A post provio cannot correlate or
record adds `additional_context` with the error and fully masks an MCP
result.

## Tool mapping

| Cursor `tool_name` | provio `tool` | policy fields |
|---|---|---|
| `Shell` | `bash` | `command` |
| `Read`, `Grep`, `Glob`, `LS` | `fs.read` | `path` from `file_path` / `target_file` / … |
| `Write`, `Edit`, `Delete` | `fs.write` | `path` |
| `WebFetch` | `http` | `url` |
| `WebSearch` | `web.search` | `query` |
| MCP (`beforeMCPExecution`) | `tool_name` | `server = mcp_server_name`; params (a JSON string) parsed into args |
| anything else (`Task`, …) | unchanged | policy default |

Caller: `agent = "cursor"`, session = `conversation_id`.

## Not covered / residual risks

- **Cloud agents do not run `beforeMCPExecution`**: their MCP calls pass
  `preToolUse` ungoverned. Use `provio proxy --mcp` for those servers.
- `beforeReadFile` (context attachments) and Tab hooks are not wired.
- Cursor also runs Claude Code hooks from `.claude/settings.json`
  ("third-party hooks", on by default). provio's `claude-code` hook denies
  Cursor payloads, with a message saying so. Turn off the third-party import
  for projects that use both.
- Cursor can edit `.cursor/hooks.json` and `~/.cursor/hooks.json`. Under
  `provio run` these files and `.claude/settings*.json` are protected where the
  kernel allows (macOS); elsewhere the banner says so.
