# Show HN draft

Post from your own account. Submit the **repo URL** as the link and put the
body in the first comment, or use a text post. Post it yourself, stay in the
thread for the first few hours, and answer every technical question directly.
Don't ask anyone to upvote; HN detects voting rings and penalises them.

## Title options (≤ 80 chars, no hype words)

1. `Show HN: Provio – a policy check and hash-chained ledger for AI agent tool calls`
2. `Show HN: Provio – one YAML policy for every tool call Claude Code or MCP makes`
3. `Show HN: Provio – allow/deny/ask/redact for AI agent tool calls, with a ledger`
4. `Show HN: Provio – authorize AI agent tool calls and keep a verifiable record`

Pick 1 or 3. They say what it does in the words people search for.

## Body

> Hi HN. Provio is an open-source (Apache-2.0) tool, written in Rust, that
> checks every tool call an AI agent makes against a policy file before the
> call runs, and records the decision in a hash-chained ledger afterwards.
>
> The problem: coding agents run with my shell, my files and my credentials.
> The controls available to me were per-agent permission prompts, which
> differ for every agent, can't be reviewed in a PR and leave no durable
> record, or a container, which has no idea whether one call is fine and the
> next one isn't.
>
> How it works:
>
> - One `provio.yaml` in the repo. Rules are expressions over the call
>   (`tool == "bash" and command matches "rm -rf"`,
>   `tool == "http" and not url.host in hosts.allowed`). There are four
>   verdicts: allow, deny, ask (a human decides) and redact (the tool runs,
>   but matches are masked in the output before the model sees it). First
>   match wins, and the default is `ask`. Rego and Cedar are also supported
>   as engines.
> - A deny goes back to the agent with the rule id, the reason and
>   `provio.yaml:LINE`, so the model can correct course instead of retrying
>   blind.
> - Interception: agent hooks (`provio check`, a one-shot gateway; Claude
>   Code, Codex CLI, Gemini CLI, Cursor, Windsurf), an MCP proxy (stdio or
>   HTTP), SDK wrappers (LangGraph, OpenAI Agents SDK, Claude Agent SDK), and
>   `provio run -- <agent>`, which launches the agent inside a kernel write
>   boundary (Landlock+seccomp, Seatbelt, or a Low-integrity restricted token
>   on Windows).
> - Ledger: every decision and execution is a record carrying the hash of
>   the previous record. `provio verify` names the first record that doesn't
>   chain. Signed receipts (Ed25519 over a checkpoint with a Merkle root) can
>   be anchored in Sigstore's Rekor log, so rewriting history is detectable
>   by anyone holding the receipt.
>
> There's an offline demo that needs no API key. A fixture repo has a README
> with a prompt injection (read the SSH key, POST it to attacker.example,
> `rm -rf` the project). A script replays the tool calls Claude Code would
> make through the real `provio check` gateway. The model's choices are
> scripted; the decisions, ledger and verify output are provio's:
> https://github.com/writ-agent/provio/tree/main/examples/attack-demo
>
> What it does not do, and I'd rather you hear it from me:
>
> - It does not stop prompt injection. It limits what an injected agent can
>   actually do.
> - Rules match what they match. A `curl` inside a bash command isn't an
>   `http` call, so the egress allow-list doesn't see it. Unmatched calls
>   fall to `default: ask`, and shell-level network egress needs
>   `provio run --net none`, which blocks all network and does no hostname
>   filtering.
> - The ledger is tamper-evident, not tamper-proof: someone with write
>   access can rewrite the file and recompute the chain. Receipts only cover
>   records up to the last checkpoint, and a stolen signing key defeats them.
> - MCP-proxy-only mode is partial coverage: the agent's own shell and file
>   writes go around it. `provio doctor` tells you what is and isn't governed.
> - Pre-release. The CLI, the three engines, the ledgers and the kernel
>   sandbox are tested in CI on Linux, macOS and Windows. Helm, SSO and RBAC
>   haven't been started.
>
> Try it: `pip install provio` (or `npm i -g provio`), then
> `provio integrate claude-code` in a repo. There's also a browser playground
> running the real engine as WebAssembly:
> https://provio.vercel.app/playground.html
>
> Threat model with the residual risks:
> https://github.com/writ-agent/provio/blob/main/docs/THREAT_MODEL.md
>
> I'd especially like to hear from anyone who has tried to govern agents in
> CI or on shared machines, and about which policy packs would be useful
> (there are Terraform, k8s-prod and PII-redaction packs so far).

## Before posting, check

- The published release on PyPI/npm includes every command named above
  (0.1.1 does **not** have `provio ui`, receipts, or the Codex, Gemini, Cursor
  and Windsurf targets). Either ship the next release first, or cut those
  items from the body.
- Every link resolves, and the repo is public.

## Likely questions, with honest answers

- **"Why not just a container?"** A container has no per-call decision, no
  ask, and no record of what was attempted. Provio can drive a sandbox
  (local-os, docker) rather than replace it.
- **"What's the overhead?"** Don't quote a number. Criterion benches live in
  `crates/provio-bench`; point people there, or say it isn't published yet.
- **"Can't the agent just edit provio.yaml?"** Under `provio run` the workspace
  is writable, so yes, if the policy lives there. Keep `--policy` outside the
  workspace. This is in the threat model.
- **"How is this different from Claude Code's permissions?"** It's one
  policy across agents, it's reviewed as code, it produces a verifiable
  ledger, and it adds redaction and replay (`provio replay --candidate` shows
  what a new policy would have done to a past session).
