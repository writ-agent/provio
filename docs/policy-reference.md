# Policy Reference — the native `provio.yaml` DSL

One file, committed to your repository, hot-reloadable, unit-testable,
shareable. The policy file is the product's centre of gravity.

## File shape

```yaml
version: 1                    # policy format version (required)
default: ask                  # verdict for unmatched calls: ask | allow | deny
packs: [floor, secrets-guard] # optional bundled packs, composed around rules (below)
rules:                        # evaluated in order; first match wins
  - id: my-rule               # unique, shown in errors and the ledger
    when: <expression>        # see below
    verdict: deny             # allow | deny | ask | redact
    reason: "human text"      # deny/ask always carry a reason (fallback provided)
    irreversible: true        # ask only: excluded from automated replay
    timeout: 5m               # ask only: 30s | 5m | 1h — headless timeout fails closed
    patterns: ["secret-regex"]# redact only: required
hosts:                        # optional named lists, referenced with `in`
  allowed: [api.github.com, "*.internal.example.com"]
```

## Fields (available in `when`)

| Field | Source | Example value |
|---|---|---|
| `tool` | tool name | `bash`, `postgres.query` |
| `command` | args.command / args.cmd | `rm -rf /` |
| `path` | args.path / args.file_path | `/home/app/.env` |
| `url.host` | host of args.url / args.uri | `api.github.com` |
| `query` | args.query / args.sql | `DROP TABLE users;` |
| `server` | MCP server identity | `github` |
| `server.trust` | external scanner verdict | `verified`, `unverified`, `malicious` |
| `agent` | calling agent product | `claude-code` |
| `mode` | interception mode | `mcp`, `processwrap`, `sdkhook` |

Unknown fields never match (they never crash the evaluator either).

## Operators

`==` · `!=` · `startswith` · `endswith` · `contains` · `matches` (Rust regex
syntax — note `regex` crate rules: escape `{`/`(` literally as `\{` `\(`) ·
`in` (membership in a named list).

Logic: `and` binds tighter than `or`; `not` and `( … )` work as expected.

```yaml
when: tool == "bash" and command matches "rm -rf|mkfs"
when: tool == "http" and not url.host in hosts.allowed
when: (server.trust == "malicious" or server.trust == "unverified") and not mode == "sdkhook"
```

Wildcard list entries: `*.internal.example.com` matches
`api.internal.example.com` on a dot boundary (not `evilinternal.example.com`).

## Packs

`packs:` names bundled policy packs ([packs/](../packs/)); every provio build
ships them, so the policy stays one short file:

```yaml
packs:
  - floor                         # the disaster floor
  - secrets-guard
  - id: github-safety
    skip: [github-pr-merge-asks]  # decide this one yourself
```

provio composes them with your `rules:` the way a careful hand-merge would:
the packs' **deny and ask** rules first (in the order listed, so a broad
allow of yours cannot open them), then **your rules**, then the packs'
**allow** rules (your denies still win), then their **redact** rules (redact
dispatches, so it goes last). A pack rule's location is `pack:<id>@<version>`,
in the ledger and in the agent's refusal. An unknown pack, a pack listed
twice, or a `skip` naming a rule the pack does not have is a policy error:
provio refuses to load the policy. `packs:` works the same with the Rego and
Cedar engines, which compile the same `provio.yaml`.

To see the composed result for a call: `provio test "<command>"`.

## The four verdicts

| Verdict | Behaviour |
|---|---|
| `allow` | Dispatch to the sandbox/backend. Recorded. |
| `deny` | Structured refusal to the agent with rule id + reason + `provio.yaml:LINE`, so the model can self-correct. Recorded. |
| `ask` | Suspend, render the exact planned action, wait for a human (`[a]llow [d]eny [e]dit [!] always allow`). Headless: out-of-band approver or fail closed on timeout. Recorded with approver identity. |
| `redact` | Execute, but mask `patterns` in the result before it re-enters the model's context. Recorded with a hash of the original. |

Unmatched calls get `default`. Ship `default: ask` (fail-closed);
`provio run --yolo` flips it to `allow` (demos only — it prints a loud warning).

Deny and ask verdicts also apply to the commands hidden behind a call (the
lines of a script it runs or writes, a heredoc fed to a shell, the
`package.json` script behind `npm run`): see [inspection.md](inspection.md).

## Testing your policy

Try one call without running it (exit 0 allow, 2 deny, 3 ask):

```bash
provio test "git push --force origin main"
provio test --tool fs.read --path .env
```

Or replay a whole recorded suite:

```bash
provio policy test --policy provio.yaml --fixtures crates/provio-policy/fixtures
```

Fixtures are YAML cases: a context (tool/command/path/…) plus the expected
verdict (and optionally rule id). A policy change that flips a recorded
outcome fails the run — prove the change before you ship it.

## Worked examples

**Ask before force-push:**
```yaml
- id: no-force-push
  when: tool == "bash" and command contains "push --force"
  verdict: ask
  reason: "Force-push rewrites shared history."
  irreversible: true
```

**Block secret reads:**
```yaml
- id: never-read-secrets
  when: path matches "\\.env|id_rsa|\\.pem$|credentials$"
  verdict: deny
  reason: "Secrets are masked from the agent by design."
```

**Mask PII in tool results:**
```yaml
- id: redact-emails
  when: tool startswith "crm"
  verdict: redact
  patterns: ["[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}"]
```

More: [examples/provio.yaml](../examples/provio.yaml) (full tour),
[ci.yaml](../examples/ci.yaml) (headless), [strict.yaml](../examples/strict.yaml)
(default-deny posture).
