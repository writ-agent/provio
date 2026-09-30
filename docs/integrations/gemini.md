# Gemini CLI

provio decides every Gemini CLI tool call through its `BeforeTool` /
`AfterTool` hooks and records it in the ledger.

Protocol verified against `google-gemini/gemini-cli`: `docs/hooks/reference.md`,
`docs/hooks/index.md`, and the source (`packages/core/src/hooks/hookRunner.ts`,
`hookAggregator.ts`, `hookRegistry.ts`, `hookEventHandler.ts`;
`packages/core/src/scheduler/hook-utils.ts` for `decision:"ask"`;
`packages/cli/src/config/settings.ts` for settings precedence and
`GEMINI_CLI_SYSTEM_SETTINGS_PATH`).

## Setup

Per project (writes `.gemini/settings.json`):

```sh
provio integrate gemini         # --print to preview
```

Gemini CLI runs hooks **only in a trusted folder**. Project hooks are shown
to you once as new.

For one confined session:

```sh
provio run -- gemini
```

`provio run` points `GEMINI_CLI_SYSTEM_SETTINGS_PATH` at a provio-owned file
outside the writable set. That file is a copy of your existing system
settings plus provio's hooks and `hooksConfig.enabled: true`; system settings
override user and workspace settings.
`GEMINI_CLI_SYSTEM_DEFAULTS_PATH` keeps pointing where it did. The hook gets
a per-run name, so a `hooksConfig.disabled` entry planted beforehand cannot
match it. `GEMINI_CLI_TRUST_WORKSPACE=true` is set because Gemini runs **no
hooks at all** in an untrusted folder; this also means the workspace's
`.gemini/settings.json` applies. `provio run` refuses when
`GEMINI_RESTRICTED_MODE=true` or `GEMINI_CLI_TRUST_WORKSPACE=false`.

## What provio answers

| provio verdict | Gemini output | effect |
|---|---|---|
| allow / redact | `{"decision":"allow"}`, exit 0 | tool runs |
| ask (`--ask defer`, which integrate uses) | `{"decision":"ask","systemMessage":…}`, exit 0 | Gemini's own confirmation prompt; an approved call is recorded with approver `{kind: tui, id: "gemini-cli-prompt"}` |
| ask (default `--ask deny`) | deny | blocked |
| deny / any provio error | `{"decision":"deny","reason":…}` + **exit 2** + stderr | blocked |
| redact, at `AfterTool` | `{"decision":"deny","reason":<masked llmContent>}` | the model sees the masked result, framed by Gemini as "Tool result blocked: …" |

Failure modes (hookRunner.ts): exit 0 = parse stdout JSON; exit 2 = block;
**exit 1 or other codes with non-JSON output, a timeout (provio sets 600 s;
Gemini's default is 60 s), or a spawn error mean the tool runs.** Gemini
parses stdout JSON whatever the exit code, so provio's deny JSON blocks even
if a shell rewrote the exit code. On Windows the hook runs in PowerShell and
Gemini appends its own `$LASTEXITCODE` propagation; provio quotes the command
for PowerShell (`& '…'`), and for bash on Unix.

`AfterTool` has no tool-call id. It is correlated to the **newest decision
in the same session for the same mapped call (tool, server, args) that has
no execution record yet**. Identical parallel calls each complete exactly
once. A post with no open decision, or a ledger error, withholds the output
(`decision:"deny"`, exit 2).

## Tool mapping

| Gemini `tool_name` | provio `tool` | policy fields |
|---|---|---|
| `run_shell_command` | `bash` | `command` |
| `read_file`, `list_directory`, `glob`, `grep_search`, `search_file_content` | `fs.read` | `path` from `file_path` / `dir_path` / `absolute_path` |
| `read_many_files` | `fs.read` | each of `include` / `paths`; the strictest decides |
| `write_file`, `replace`, `edit` | `fs.write` | `path` from `file_path` |
| `web_fetch` | `http` | `url`: each URL in `prompt`; the strictest decides (`urls` lists them) |
| `google_web_search` | `web.search` | `query` |
| MCP (`mcp_<server>_<tool>`) | `mcp_context.tool_name` | `server = mcp_context.server_name` (the name alone is ambiguous) |
| anything else (`save_memory`, `write_todos`, …) | unchanged | policy default |

Caller: `agent = "gemini-cli"`.

## Not covered / residual risks

- A hook timeout or a crash with non-JSON output lets the tool run.
- An untrusted folder, `hooksConfig.enabled: false`, or the hook's name in
  `hooksConfig.disabled` switch provio off after `provio integrate` (`provio run`
  pins these).
- Gemini can edit `~/.gemini/settings.json` and `.gemini/settings.json`.
  Under `provio run` both are protected where the kernel allows (macOS);
  elsewhere the banner says so.
- `/hooks disable-all` in an interactive session disables hooks for that
  session.
- Redacted results reach the model marked as a blocked tool result.
