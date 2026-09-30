# OpenAI Codex CLI

provio decides every Codex tool call that goes through Codex's lifecycle
hooks (`PreToolUse` / `PostToolUse`) and records it in the ledger.

Protocol verified against the Codex hooks docs
(<https://learn.chatgpt.com/docs/hooks>, formerly
developers.openai.com/codex/hooks) and the source in `openai/codex`
(`codex-rs/hooks`: `engine/output_parser.rs`, `events/pre_tool_use.rs`,
`engine/discovery.rs`, `engine/command_runner.rs`).

## Setup

Per project (writes `.codex/config.toml`, inline `[hooks]`; comments and
formatting are kept):

```sh
provio integrate codex          # --print to preview
codex                         # then trust provio's hooks in /hooks
```

Codex runs a non-managed hook only after you review and trust its exact
definition (`/hooks`, or the startup prompt). **Until you trust them, provio's
hooks are skipped and tools run ungoverned.** Project `.codex/` hooks also
load only in a trusted project.

For one confined session, no config change:

```sh
provio run -- codex             # or: provio run -- codex exec "task"
```

`provio run` passes the hooks as session-flag overrides
(`-c hooks.PreToolUse=[…] -c hooks.PostToolUse=[…]`), pins
`-c features.hooks=true` (session flags outrank user and project config) and
adds `--dangerously-bypass-hook-trust`, since provio vets its own hooks. That flag
also lets any *other* enabled hook run without review for that invocation.
`provio run` refuses a command that already overrides `hooks.*` or
`features.hooks` (use `--no-hooks` to pass it through unchanged).

## What provio answers

| provio verdict | Codex output | effect |
|---|---|---|
| allow | nothing, exit 0 | tool runs |
| redact | nothing at pre; at `PostToolUse` `{"decision":"block","reason":<masked result>}` | the model sees the masked result |
| deny | `hookSpecificOutput.permissionDecision:"deny"` + reason, **exit 0**, reason on stderr | blocked |
| ask | same as deny | Codex has no hook output that raises its approval prompt (`permissionDecision:"ask"` is "parsed but not supported" and the tool *runs*), so an ask fails closed |
| any provio error | same as deny | blocked |

Why exit 0: Codex blocks on exit 0 + valid deny JSON, or exit 2 + a
non-empty stderr. **Any other exit code, a timeout, a spawn failure or
invalid JSON means Codex runs the tool.** Hooks run through the session's
shell, and Windows PowerShell 5.1 turns a native exit code 2 into 1, so provio
never relies on the exit code. JSON output is ASCII-escaped so no shell
re-encoding can corrupt it.

On Windows the hook command must work in cmd.exe, PowerShell and bash, so
it uses forward slashes and no quotes. `provio integrate codex` refuses paths
that would need quoting (spaces, shell metacharacters).

`PostToolUse` correlates by `(session_id, tool_use_id)`. A missing
decision, a second completion, a ledger error, or input that differs from
what provio decided answers `decision:"block"`, which replaces the tool result
with the error (the output is withheld).

## Tool mapping

| Codex `tool_name` | provio `tool` | policy fields |
|---|---|---|
| `Bash` (shell and unified exec; argv arrays are joined) | `bash` | `command` |
| `apply_patch` | `fs.write` | `path` from each `*** Add/Update/Delete File:` / `*** Move to:` header, resolved against `cwd`; the strictest path decides; all of them in `paths` |
| `view_image` | `fs.read` | `path` |
| `mcp__<server>__<tool>` | `<tool>` | `server = <server>` |
| Claude-style names (`Read`, `Write`, `WebFetch`, …) | as for Claude Code | |
| anything else (`update_plan`, `spawn_agent`, …) | unchanged | policy default applies |

Caller: `agent = "codex"`, `non_human_id` = `agent_id` (subagents).

## Not covered / residual risks

- **Hosted tools** (web search) do not use the hook path. Codex also says
  "some specialized tool paths can opt out of the default hook path".
- Untrusted or disabled hooks (`/hooks`), `[features] hooks = false`, and
  admin `allow_managed_hooks_only = true` in `requirements.toml` all switch
  provio off without any error. `provio run` warns after the session if no tool
  call reached provio.
- A hook that times out (default 600 s) or fails to start does not block.
- Codex can edit its own `config.toml` / `hooks.json`. Under `provio run` these
  files are protected (kernel-enforced read-only on macOS; elsewhere the
  banner says they are not). Hooks planted there would run in later sessions
  outside provio.
- `permissionDecision:"ask"` is not supported by Codex, so policy `ask` rules
  always deny here.
- Codex's MCP servers can also be put behind `provio proxy --mcp`.
