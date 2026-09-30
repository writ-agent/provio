# Reddit drafts

Read each sub's current rules and sidebar before posting; they change.
Space the posts out (not all on one day), post from your own account, and
reply in the comments. Don't crosspost the same text to all three.

---

## r/LocalLLaMA

**Norms:** local-first, open source, no SaaS pitches. Self-promotion is
tolerated when it's useful and you're part of the community. Lead with "runs
locally, sends nothing" and "works with any model", and don't mention Claude
more than you have to.

**Title:** `Open-source policy gate + tamper-evident ledger for agent tool calls (local, no telemetry, any model)`

**Body:**

> I built provio, an Apache-2.0 Rust binary that sits between an agent and
> its tools. Each tool call is checked against a `provio.yaml` in your repo
> (allow / deny / ask / redact) before it runs, and recorded in a
> hash-chained ledger on disk.
>
> Why it might matter here:
>
> - **Fully local.** No daemon, no account, no telemetry. The ledger is a
>   JSONL file (SQLite optional).
> - **Model-agnostic.** provio sees tool calls, not the model, so it works the
>   same whether the agent runs on a local model or an API. Ways in: an MCP
>   proxy (`provio proxy --mcp -- <server>`, which covers every MCP client),
>   Python/TS SDK hooks for LangGraph and the OpenAI Agents SDK (both work
>   with local OpenAI-compatible endpoints), or `provio check` from any
>   agent's hook system.
> - **Deny with a reason.** The agent gets back the rule id and the
>   `provio.yaml` line, which helps smaller models correct themselves instead
>   of looping.
>
> There's a reproducible demo with no model or API key: a fixture README
> with a prompt injection (steal the SSH key, POST it to attacker.example,
> `rm -rf`), and a script that replays the agent's tool calls through the
> real gateway. The tool calls are scripted; provio's decisions and ledger are
> real. It works on Linux, macOS and Windows:
> https://github.com/writ-agent/provio/tree/main/examples/attack-demo
>
> Limits: it does not stop prompt injection. It limits what the agent can
> do. Rules only catch what they match, and a `curl` inside a shell command
> isn't seen by the http egress rule. MCP-proxy-only mode doesn't cover the
> agent's own shell. The ledger is tamper-evident, not tamper-proof.
>
> Repo: https://github.com/writ-agent/provio · in-browser playground (the
> engine compiled to WASM): https://getprovio.vercel.app/playground.html
>
> Feedback I'd like: which local agent stacks you'd want first-class hooks
> for.

---

## r/ClaudeAI

**Norms:** a project/showcase flair is required (check the sidebar for the
current name), and posts should show what you built with or for Claude. Be
specific about the Claude Code integration.

**Title:** `I made Claude Code check every tool call against a YAML policy and keep a verifiable log (open source)`

**Body:**

> provio plugs into Claude Code's `PreToolUse` / `PostToolUse` hooks:
>
> ```
> pip install provio
> provio integrate claude-code     # merges hooks into .claude/settings.json
> ```
>
> After that, every Bash, Read, Write/Edit, WebFetch and MCP call goes
> through `provio.yaml` first:
>
> - `deny` blocks the call, and Claude gets the rule, reason and file:line
>   back.
> - `ask` becomes Claude Code's own permission prompt.
> - `redact` lets the call run but masks matches (emails, keys) in the output
>   before Claude sees it.
> - Everything lands in a hash-chained ledger: `provio log`, `provio show <id>`,
>   `provio verify`.
>
> `provio run -- claude` goes further: Claude Code is launched inside an OS
> write boundary with the hooks passed via `--settings`, so a
> `disableAllHooks` written into your project settings doesn't switch them
> off. (The threat model explains what it can't protect.)
>
> Demo (image): a README with a hidden prompt injection tells Claude to read
> `~/.ssh/id_rsa`, send it to attacker.example and `rm -rf` the project.
> provio allows the README read, then denies all three and records them. The
> demo replays scripted tool calls through the real hook, so you can run it
> without an API key: https://github.com/writ-agent/provio/tree/main/examples/attack-demo
>
> It doesn't stop the injection itself; it limits what Claude can do once
> injected. Open source (Apache-2.0):
> https://github.com/writ-agent/provio

Attach `docs/launch/demo-attack.png`.

---

## r/netsec

**Norms:** a technical audience with strict rules against product
promotion. Submissions are links to technical content, not announcements.
Submit the **blog post** (or the threat model) as a link, not the repo.
Lead with the threat model and the residuals. If a standalone post doesn't
fit the current rules, use the sub's recurring discussion/tool thread
instead (see the sidebar).

**Link:** the published blog post ("Every tool call your agent makes,
authorized and provable"), or
https://github.com/writ-agent/provio/blob/main/docs/THREAT_MODEL.md

**Title:** `Threat model for gating AI agent tool calls: policy at the hook, a kernel write boundary, and a hash-chained ledger (and what each leaves open)`

**First comment (author):**

> Author here. The threat model is the part I'd most like reviewed. Short
> version:
>
> - **Controls:** a per-call policy decision at the agent's hook (fail
>   closed: in Claude Code, every provio-side error exits 2, so the tool
>   doesn't run); `provio run` launches the agent inside a write boundary
>   (Landlock + seccomp on Linux, Seatbelt on macOS, a restricted
>   Low-integrity token + Job Object on Windows); a hash-chained ledger with
>   Ed25519ph-signed checkpoints (RFC 6962 Merkle root) optionally anchored
>   in Rekor.
> - **Explicitly not solved:** prompt injection itself; exfiltration through
>   an allow-listed host; hostname-level egress filtering at the kernel layer
>   (a non-empty allow-list is refused rather than approximated); records
>   after the last receipt, which a host-level attacker can rewrite; a stolen
>   signing key; a malicious operator.
> - **Known residuals I'd like eyes on:** on Linux and Windows the agent can
>   rewrite `~/.claude/settings.json` to affect *later* sessions run outside
>   provio (Landlock can't exclude a file beneath an allowed directory, and on
>   Windows a Low process can rename over a Medium-labelled file through a
>   Low-labelled parent). On Windows the Low integrity labels persist after
>   the run. A `claude -p` started by the agent itself doesn't get provio's
>   hooks, though it stays inside the boundary.
>
> The repo includes a reproducible injection demo (scripted tool calls,
> real gateway output) and a `provio doctor` command that reports what is and
> isn't governed on the running machine.

Don't use r/netsec for a "check out my tool" post; it will be removed.
