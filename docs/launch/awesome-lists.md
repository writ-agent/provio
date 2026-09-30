# Awesome-list submissions

Every list below was checked on 2026-09-23 with the GitHub API: the repo
exists and isn't archived, and its current README was read for the section
names and entry format. The entry lines copy each list's format. **No PRs or
issues were opened from this document.** Reconcile it with whatever was
actually submitted.

Two facts affect several lists:

- `writ-agent/provio` had **0 stars** when this was checked. Some lists have
  popularity bars (noted per list); submit to those later.
- The project was renamed from *writ* to *provio* on 2026-09-30 (the old
  name collided with other projects, including a `writ-cli` crate). Entries
  submitted under the old name need an update PR; `writ-agent/writ` URLs
  redirect.

Keep descriptions factual. The lists' own review rules punish marketing
language, and so does `docs/BRAND.md`.

---

## Submitted (2026-09-23)

One-line PRs, each in the list's own format and section, disclosed as prepared with Claude Code:

| List | PR |
|---|---|
| ottosulin/awesome-ai-security — Agent Runtime Security & Sandboxing | [#473](https://github.com/ottosulin/awesome-ai-security/pull/473) |
| punkpeye/awesome-mcp-servers — Security | [#14958](https://github.com/punkpeye/awesome-mcp-servers/pull/14958) |
| TensorBlock/awesome-mcp-servers — docs/security.md | [#2620](https://github.com/TensorBlock/awesome-mcp-servers/pull/2620) — **merged** |
| corca-ai/awesome-llm-security — Tools | [#357](https://github.com/corca-ai/awesome-llm-security/pull/357) |
| tensorchord/Awesome-LLMOps — Frameworks for LLM security | [#855](https://github.com/tensorchord/Awesome-LLMOps/pull/855) |
| ElNiak/awesome-ai-cybersecurity — Safety and Prevention | [#21](https://github.com/ElNiak/awesome-ai-cybersecurity/pull/21) |
| webcoyote/awesome-AI-sandbox — Policy, approvals, and audit layers | [#6](https://github.com/webcoyote/awesome-AI-sandbox/pull/6) |
| systempromptio/awesome-ai-agent-governance — Claude Code and MCP Governance | [#102](https://github.com/systempromptio/awesome-ai-agent-governance/pull/102) |
| vonzosten/awesome-LangGraph — Security & Governance | [#114](https://github.com/vonzosten/awesome-LangGraph/pull/114) |

punkpeye/awesome-mcp-servers asks for a glama.ai listing with a passing check badge (the owner submits at https://glama.ai/mcp/servers; provio is a proxy in front of servers, so check whether Glama's start-and-introspect check applies).

Waiting on eligibility: awesome-claude-code (14 days of history, ≈ Oct 5; web issue form only), awesome-langchain (auto-closes brand-new repos), awesome-rust (50+ stars).

## 1. punkpeye/awesome-mcp-servers: high fit

- **Repo:** https://github.com/punkpeye/awesome-mcp-servers (active; pushed 2026-09-23)
- **Section:** `### 🔒 Security`. Keep alphabetical order where the section
  has it.
- **Format:** `- [owner/repo](url) <legend emojis> - description`. Language
  🦀 Rust, scope 🏠 local, OS 🍎 🪟 🐧.
- **Entry:**

```markdown
- [writ-agent/provio](https://github.com/writ-agent/provio) 🦀 🏠 🍎 🪟 🐧 - MCP proxy (stdio or Streamable HTTP) that checks every `tools/call` against a `provio.yaml` policy (allow / deny / ask / redact) before forwarding it, and records each decision in a hash-chained, tamper-evident ledger (`provio verify`).
```

- **Notes:** most entries also carry a glama.ai score badge
  (`[![writ-agent/provio MCP server](https://glama.ai/mcp/servers/writ-agent/provio/badges/score.svg)](https://glama.ai/mcp/servers/writ-agent/provio)`).
  CONTRIBUTING.md doesn't require it, but almost every neighbouring entry
  has one. If provio gets listed on Glama, add the badge. The list's CONTRIBUTING.md has a note inviting
  *automated agents* to add a marker to the PR title for fast-tracking.
  Submit as yourself and ignore it.

## 2. wong2/awesome-mcp-servers: medium fit

- **Repo:** https://github.com/wong2/awesome-mcp-servers (active; pushed 2026-07-13)
- **Section:** `## Community Servers` (alphabetical). provio is a proxy
  rather than a server, so the maintainer may decline it.
- **Format:** `- **[Name](url)** - description`
- **Entry:**

```markdown
- **[provio](https://github.com/writ-agent/provio)** - Policy proxy for any MCP server: every tool call is checked against a `provio.yaml` (allow / deny / ask / redact) and recorded in a hash-chained ledger.
```

## 3. hesreallyhim/awesome-claude-code: high fit, form only

- **Repo:** https://github.com/hesreallyhim/awesome-claude-code (active; pushed 2026-09-23)
- **Section:** `## Security`
- **How to submit:** only through the web issue form,
  https://github.com/hesreallyhim/awesome-claude-code/issues/new?template=recommend-resource.yml.
  The CONTRIBUTING file says: no PRs, no `gh` CLI, or you risk being
  restricted. The maintainer also says the list is selective and that
  projects with users are more likely to be picked, so consider waiting until
  there's some adoption.
- **Rendered format (generated from the form):** `- [Name](url) by [author](url) - description`
- **Form values:**
  - Name: `provio`
  - URL: `https://github.com/writ-agent/provio`
  - Author: `writ-agent` (`https://github.com/writ-agent`)
  - Category: Security
  - Description: `PreToolUse/PostToolUse hooks (provio integrate claude-code) that check every tool call against a provio.yaml policy — allow, deny, ask via Claude Code's own prompt, or redact output — and record each decision in a hash-chained, tamper-evident ledger. provio run -- claude also launches Claude Code in an OS write boundary.`
  - License: Apache-2.0

## 4. webcoyote/awesome-AI-sandbox: high fit

- **Repo:** https://github.com/webcoyote/awesome-AI-sandbox (active; pushed 2026-06-11)
- **Section:** `## Policy, approvals, and audit layers` → `### Multiplatform`
  (alphabetical). The list favours "tools with a clear security model and
  practical documentation", so link the threat model in the PR body.
- **Format:** `- [Name](url) - description.`
- **Entry:**

```markdown
- [provio](https://github.com/writ-agent/provio) - Per-tool-call policy (allow/deny/ask/redact) for Claude Code, Codex, Gemini CLI, Cursor, MCP and agent SDKs, with a kernel write boundary for `provio run` and a hash-chained ledger.
```

## 5. systempromptio/awesome-ai-agent-governance: high fit

- **Repo:** https://github.com/systempromptio/awesome-ai-agent-governance (active; pushed 2026-09-23)
- **Section:** `## Claude Code and MCP Governance` (alphabetical).
  Alternative: `## Policy Engines and Authorisation`.
- **Format:** `- [Name](url) - description.`
- **Entry:**

```markdown
- [provio](https://github.com/writ-agent/provio) - One `provio.yaml` policy (native DSL, Rego or Cedar) checked before every tool call from Claude Code, Codex, Gemini CLI, Cursor, Windsurf, MCP clients and agent SDKs; decisions go to a hash-chained ledger with Ed25519-signed receipts that can be anchored in Sigstore Rekor. Apache-2.0.
```

## 6. vonzosten/awesome-LangGraph (formerly von-development): medium fit

- **Repo:** https://github.com/vonzosten/awesome-LangGraph (active; pushed 2026-07-10; the old `von-development/awesome-LangGraph` URL redirects here)
- **Section:** `## 🌟 Community Projects` → `### 🌍 Security & Governance`,
  a table in alphabetical order. CONTRIBUTING requires the stars badge.
- **Entry (table row):**

```markdown
| [writ-agent/provio](https://github.com/writ-agent/provio) | Policy check for LangGraph tool calls (`provio_sdk.langgraph.provio_tool_node`): allow, deny, ask or redact from a `provio.yaml`, each decision recorded in a hash-chained ledger. Apache 2.0. | ![GitHub stars](https://img.shields.io/github/stars/writ-agent/provio?style=social) |
```

## 7. kyrolabs/awesome-langchain: medium fit

- **Repo:** https://github.com/kyrolabs/awesome-langchain (active; pushed 2026-09-22)
- **Section:** `## Tools` → `### Services`. There's no security subsection;
  opening an issue first to propose one would be reasonable.
- **Format:** `- [Name](url): description ![GitHub Repo stars](badge)`
- **Entry:**

```markdown
- [provio](https://github.com/writ-agent/provio): Policy check (allow/deny/ask/redact) and hash-chained audit ledger for LangGraph and LangChain tool calls ![GitHub Repo stars](https://img.shields.io/github/stars/writ-agent/provio?style=social)
```

## 8. rust-unofficial/awesome-rust: not eligible yet

- **Repo:** https://github.com/rust-unofficial/awesome-rust (active; pushed 2026-09-22)
- **Section:** `## Applications` → `### Security tools` (alphabetical by
  `ACCOUNT/REPO`)
- **Bar:** accepted only with **more than 50 GitHub stars or more than 2,000
  crates.io downloads**. provio has neither yet; the crates are not published
  on crates.io, so leave out a crate link.
- **Entry (when eligible):**

```markdown
* [writ-agent/provio](https://github.com/writ-agent/provio) - Authorization and provenance for AI agent tool calls: a policy check (allow/deny/ask/redact), a Landlock/seccomp, Seatbelt and AppContainer sandbox, and a hash-chained ledger with signed receipts [![build](https://github.com/writ-agent/provio/actions/workflows/ci.yml/badge.svg)](https://github.com/writ-agent/provio/actions/workflows/ci.yml)
```

## 9. e2b-dev/awesome-ai-agents: low fit

- **Repo:** https://github.com/e2b-dev/awesome-ai-agents (active; pushed 2026-08-21)
- **Why low fit:** it lists *agents*, and provio isn't one. Submit only if
  you're willing to be declined. It accepts a PR or its form,
  https://forms.gle/UXQFCogLYrPFvfoUA.
- **Format:** an alphabetical `## [Name](url)` block under
  `# Open-source projects`, with `### Category`, `### Description` and
  `### Links`, inside `<details>`, matching neighbouring entries.
- **Entry:**

```markdown
## [provio](https://github.com/writ-agent/provio)
Authorization and provenance for AI agents

<details>

### Category
Security, Developer tools

### Description
- Checks every tool call an agent makes against one `provio.yaml` policy (allow / deny / ask / redact) before it runs
- Records every decision in a hash-chained, tamper-evident ledger (`provio log`, `provio verify`)
- Works with Claude Code, Codex CLI, Gemini CLI, Cursor, Windsurf, LangGraph, OpenAI Agents SDK, Claude Agent SDK and any MCP client

### Links
- [GitHub](https://github.com/writ-agent/provio)
- [Playground](https://provio.vercel.app/playground.html)
</details>
```

## 10. bureado/awesome-agent-runtime-security: probably skip

- **Repo:** https://github.com/bureado/awesome-agent-runtime-security (active; pushed 2026-09-13)
- **Why skip:** the list says it's not a good fit for "security *at*
  runtime" or for isolation that "relies on a shared kernel or a parent
  process supervisor in the same privilege level". That describes provio's
  hooks and `provio run`. The one angle that fits is **Provenance** (signed
  receipts anchored in Rekor).
- **If you submit anyway:** section `## Provenance, Instrumentation & Observability`, table `| Name | Keywords | Description |`:

```markdown
| [provio](https://github.com/writ-agent/provio) | policy, hash chain, Ed25519, Rekor, MCP | Tool-call policy check whose hash-chained ledger is checkpointed by Ed25519ph-signed receipts (RFC 6962 Merkle root) and anchored in Sigstore Rekor, so rewriting earlier records is detectable offline by anyone holding a receipt. |
```

## Checked and not recommended

- `appcypher/awesome-mcp-servers`: **archived**.
- `corca-ai/awesome-llm-security`: no push since 2025-08-20, and it focuses
  on model-layer attacks.
