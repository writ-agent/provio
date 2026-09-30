# provio GitHub Action

A safety floor for AI agents that run in CI. The action installs the
checksum-verified provio release, wires it into the agents your job runs,
and writes what they did into the job summary: what provio stopped, what
needed a human, and whether the ledger's hash chain is intact. The ledger
is uploaded as an artifact.

```yaml
jobs:
  agent:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: writ-agent/provio/deploy/action@v0.1.3
        with:
          agents: claude-code
          command: claude -p "fix the failing test" --allowedTools "Bash,Edit"
          fail-on-deny: "true"
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

Or wire provio first and run the agent in your own later step (for example
`anthropics/claude-code-action`), leaving `command` empty.

| Input | Default | |
|---|---|---|
| `version` | `latest` | provio release tag |
| `agents` | `claude-code` | comma-separated: `claude-code`, `codex`, `gemini`, `cursor`, `windsurf` |
| `policy` | `provio.yaml` | written with the starter floor when it does not exist |
| `command` | | agent command to run after wiring |
| `fail-on-deny` | `false` | fail the job if any call was denied |
| `artifact-name` | `provio-ledger` | ledger artifact name; empty to skip |

Outputs: `denied`, `asked` (counts from `provio report`).

In CI nobody answers an `ask`: with the default `--ask defer` wiring it
becomes the agent's own permission prompt, which a headless agent treats
as a refusal. Put what CI may do in `provio.yaml` as `allow` rules.
