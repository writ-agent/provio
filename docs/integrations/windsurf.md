# Windsurf (Cascade hooks)

provio decides Cascade's commands, file reads/writes and MCP calls through
its pre-hooks and records them through the post-hooks.

Protocol verified against <https://docs.windsurf.com/windsurf/cascade/hooks>
(now <https://docs.devin.ai/desktop/cascade/hooks>).

## Setup

```sh
provio integrate windsurf       # --print to preview
```

This writes `.devin/hooks.json`. If only the legacy `.windsurf/hooks.json`
exists, provio merges into that file instead, because Windsurf ignores the
legacy file once `.devin/hooks.json` defines hooks. Each entry has
`command` (run with `bash -c` on macOS/Linux) and `powershell` (Windows,
ending `; exit $LASTEXITCODE` so exit code 2 reaches Cascade).

Windsurf is an IDE, so there is no `provio run` injection. `provio run --
windsurf` governs only the launch and points here.

## What provio answers

Cascade blocks a pre-hook **only on exit code 2**, with stderr as the
message the agent sees. Any other exit code lets the action proceed, and
hooks cannot change or mask tool output. So:

| provio verdict | output | effect |
|---|---|---|
| allow | exit 0 | proceeds |
| deny / ask / redact / any provio error | exit 2 + reason on stderr | blocked (no confirmation hook exists; masking is impossible) |

Post hooks correlate to the newest open decision of the trajectory for the
same mapped call. An uncorrelatable post exits 2 (Cascade shows the error;
it cannot block).

## Tool mapping

| Cascade event | provio `tool` | policy fields |
|---|---|---|
| `pre_run_command` | `bash` | `command` = `command_line`, `cwd` |
| `pre_read_code` | `fs.read` | `path` = `file_path` (may be a directory) |
| `pre_write_code` | `fs.write` | `path` = `file_path` (`edits` recorded) |
| `pre_mcp_tool_use` | `mcp_tool_name` | `server = mcp_server_name`, args = `mcp_tool_arguments` |

Caller: `agent = "windsurf"`, session = `trajectory_id`.

## Not covered / residual risks

- A hook that crashes, fails to start or exits with anything but 2 lets the
  action proceed (fail-open by design in Cascade). A missing provio binary is
  not blocked.
- `ask` rules always deny, and `redact` rules deny the call.
- Cascade can edit the workspace `hooks.json`, and there is no provio boundary
  around the IDE. Use system-level hooks (`/etc/devin/hooks.json`, …) or the
  team dashboard for settings users cannot change.
