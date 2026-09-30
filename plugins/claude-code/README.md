# provio for Claude Code (plugin)

Every Claude Code tool call is checked by provio before it runs and recorded
in a tamper-evident ledger. In a project with a `provio.yaml`, that policy
decides; everywhere else the built-in starter floor does (no `rm -rf ~`, no
force push to main, no SSH or cloud key reads, no disabling its own hooks,
no `--dangerously-skip-permissions`; asks before database drops, cloud
destroys and `curl | sh`).

```text
/plugin marketplace add writ-agent/provio
/plugin install provio@provio
```

The plugin calls the `provio` binary, so install it first:

```bash
pip install provio          # or: npm install -g provio
```

Without the binary, the plugin blocks tool calls (fail closed) and says how
to install it.

| | |
|---|---|
| Policy | the project's `provio.yaml` (legacy `writ.yaml` too); otherwise the starter floor, the same policy `provio init` writes |
| Ledger | the project's `.provio/ledger.jsonl`; `~/.provio/ledger.jsonl` for projects without a policy |
| `ask` | becomes Claude Code's own permission prompt |
| `/provio:scan` | what provio would have caught in your last 30 days |
| `/provio:report` | what was stopped and approved in the last 12 hours |

Use either the plugin or `provio integrate claude-code` in a project, not
both: both would decide every call. More: [the provio README](../../README.md).
