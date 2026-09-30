# How provio compares

Written by the provio maintainers, so read it with that in mind. "Not documented" means we did not find it in that project's README or docs; it does not mean the feature is absent. Star counts
are from the GitHub API on 2026-09-30; features are from each project's own
README or docs on that date. Corrections are welcome as issues.

## The short version

- If you want **one command that stops an agent from deleting your work**,
  dcg, cc-safety-net and nah are good, popular, and simpler than provio.
  provio's `floor` pack covers the same disasters; `provio init` is the
  one-command setup.
- If you want **isolation around an agent**, the sandboxes built into Claude
  Code, Codex, Gemini CLI and Cursor are on by default now, and Anthropic's
  sandbox-runtime, nono and NVIDIA OpenShell do it well.
- provio is for when you want **both, from outside the agent, for every
  agent at once, with evidence**: one policy that Claude Code, Codex, Gemini
  CLI, Cursor, Windsurf, your SDK agents and your MCP servers all go
  through; checks that read what a call will run (the script behind
  `bash cleanup.sh`); a kernel write boundary under `provio run` for what
  no parser can see; and a hash-chained ledger with signed receipts you can
  hand to someone else.

## Feature by feature

| | provio | dcg | nah | cc-safety-net | built-in agent sandboxes | Microsoft Agent Governance Toolkit |
|---|---|---|---|---|---|---|
| Stars (2026-09-30) | 2 | 6,071 | 486 | 1,566 | n/a | 6,369 |
| Agents covered by hooks | Claude Code, Codex, Gemini CLI, Cursor, Windsurf, Python/TS SDKs, MCP (proxy) | ~16 coding agents | 15 | 13 | their own agent only | framework SDKs (Python, TS, Rust, Go, .NET) |
| One policy file for all of them | yes (`provio.yaml`) | not checked | not checked | not checked | no, one config per agent | yes (YAML, Rego, Cedar) |
| Rule packs | 20 bundled, composable (`packs:`) | 50+ | 47 guards | built in | n/a | policy library |
| Reads scripts a command runs / writes | yes: script lines, heredocs by consumer, `npm run` scripts, shell strings in Python/JS | not documented | not documented | not documented | n/a | n/a |
| Kernel boundary outside the agent | yes, `provio run` (Landlock+seccomp, Seatbelt, Windows low-integrity token) | not documented | not documented | not documented | yes, configured by the agent it constrains | not documented |
| Native Windows | yes | not checked | not checked | not checked | Codex yes (elevated mode needs admin); Claude Code and Cursor no | not checked |
| MCP proxy with tool pinning | yes (stdio and Streamable HTTP; changed tools held) | not documented | not documented | not documented | no | no MCP interception found |
| Tamper-evident ledger | yes, hash-chained; JSONL, SQLite or Postgres | not documented | not documented | not documented | no | "tamper-evident records" (chaining not confirmed) |
| Signed, independently verifiable receipts | yes: Ed25519, Merkle inclusion proofs, Sigstore Rekor anchoring | not documented | not documented | not documented | no | not confirmed |
| Replay past sessions through a policy | yes, `provio scan` (Claude Code, Codex, Gemini transcripts) | not documented | `nah test` tries one command | not documented | no | not documented |
| License | Apache-2.0 | custom | MIT | MIT | vendor | MIT |

## What provio does worse

- **Fewer rules.** dcg ships more than twice as many packs. provio's packs
  have near-miss fixtures and were tuned on real sessions, but coverage of
  long-tail tools is thinner.
- **More moving parts.** A policy language, three engines, three ledger
  stores, an MCP proxy and a kernel launcher are more to understand than a
  single blocker. `provio init` hides most of it; the rest is optional.
- **Young and small.** Two stars, one maintainer. The threat model
  ([THREAT_MODEL.md](THREAT_MODEL.md)) says exactly what is and is not
  covered; please test it before trusting it.
- **Text rules are text rules.** provio reads scripts, heredocs and code
  strings, but obfuscated commands (`eval "$(… | base64 -d)"`) get past it
  like any parser. The kernel boundary under `provio run` is the answer
  there, and it only covers writes and network, not everything.
