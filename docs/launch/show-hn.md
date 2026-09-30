# Show HN draft

Post from your own account on a **Monday around 00:00 UTC** (the slot with
the best odds; about 92% of a Show HN's star impact comes in the first 48
hours). Submit the **repo URL** as the link and put the body in the first
comment. Stay in the thread for the first hours and answer every technical
question directly. Don't ask anyone to upvote; HN penalises voting rings.

## Title options (≤ 80 chars, no hype words)

1. `Show HN: Provio – a kernel-enforced safety floor for Claude Code, Codex, Gemini`
2. `Show HN: Provio – see what your coding agents did last month, and stop the worst`
3. `Show HN: Provio – one policy for every AI coding agent, checked below the agent`

Pick 1. It names the agents people search for and the part nobody else has.

## Body

> Hi HN. Provio is an open-source (Apache-2.0, Rust) safety layer for AI
> coding agents. One policy is checked before every tool call that Claude
> Code, Codex, Gemini CLI, Cursor, Windsurf, SDK agents or MCP servers make;
> agents launched with `provio run` also sit inside a kernel write boundary;
> and every decision goes into a hash-chained ledger you can sign.
>
> Why: in anthropics/claude-code#88462 an agent in auto mode wrote a cleanup
> script whose `trap` ran `rm -rf "$HOME"`, then ran it. The permission check
> saw `bash cleanup.sh`. Most guards I tried have the same blind spot: they
> read the command string.
>
> What provio does about it:
>
> - It judges a call by what it will run: the lines of the script behind
>   `bash cleanup.sh`, the `package.json` script behind `npm run x`, a heredoc
>   fed to a shell, shell strings inside Python or JS. A dangerous script is
>   refused when the agent *writes* it.
> - Text rules still lose to `eval "$(echo … | base64 -d)"`. That is what the
>   kernel boundary is for: under `provio run`, the agent can write to its
>   workspace and nowhere else (Landlock+seccomp, Seatbelt, a low-integrity
>   token on Windows), whatever it runs. The demo below shows all three layers
>   on the #88462 script.
> - The starter policy is a "floor", not a rulebook: no recursive delete of
>   `~` or `/`, no force-push to main, no reading SSH or cloud keys, no
>   reverse shells, no agent rewriting its own hook config or relaunching
>   itself with `--dangerously-skip-permissions`; asks before `DROP DATABASE`,
>   `terraform destroy`, `git reset --hard` and `curl | sh`. Everything else
>   runs. 19 more packs (AWS/GCP/Azure, GitHub, Docker, Kubernetes, PaaS
>   CLIs, CI config, payments, …) are one line away.
> - MCP: the proxy pins tool definitions on first use; if a server rewrites a
>   tool's description later (a "rug pull"), the tool is hidden from the
>   model and its calls refused until you accept the change.
> - Ledger: hash-chained records, Ed25519-signed receipts with Merkle
>   inclusion proofs, optional anchoring in Sigstore Rekor. `provio report
>   --sign` turns a night of agent work into one page someone else can verify.
>
> The first thing I'd suggest trying reads only: `pipx run provio scan` (or
> `npx provio scan`) replays your existing Claude Code, Codex and Gemini CLI
> transcripts through the floor and prints what it would have blocked. On a
> month of my own sessions (16k tool calls) the first version asked about 170
> things; most were text inside heredocs, which is how the heredoc handling
> above came about.
>
> Demo (offline, no API key, scratch dirs stand in for $HOME):
> https://github.com/writ-agent/provio/tree/main/examples/incident-88462
>
> What it does not do:
>
> - It does not stop prompt injection. It limits what an injected agent can do.
> - Hook-based checks are only as good as the agent's hook system; an agent
>   without hooks is only governed at launch (`provio doctor` lists what is
>   covered). The kernel boundary covers writes and network, not reads.
> - The ledger is tamper-evident, not tamper-proof: someone with write access
>   can rewrite and re-chain it. Receipts anchored in Rekor make that
>   detectable for everything before the receipt.
> - It is young: 20 packs vs 50+ in dcg, one maintainer. Comparison, including
>   what provio does worse: docs/comparison.md.
>
> Install: `pip install provio`, `npm i -g provio`, or the Claude Code plugin
> (`/plugin marketplace add writ-agent/provio`). Then `provio init` in a repo.
> It was called writ until recently; the old packages point to the new ones.

## Replies to expect

- **"Just use a container."** Agree for isolation; provio's kernel boundary is
  that, without an image. The policy layer is for what a container cannot
  judge: this `git push` is fine, `git push --force origin main` is not.
- **"Regex guards are a deny list with extra steps."** Yes, for the text
  layer; that's why it reads the scripts too and why the kernel boundary
  exists. Offer the #88462 demo, act 3.
- **"Why not the agent's own sandbox?"** It's configured by, and runs beside,
  the agent it constrains; Claude Code and Cursor have no native Windows
  backend; none of them share one policy or keep a ledger.
- **Bypass reports.** Thank them, open an issue, and fix fast in public.
