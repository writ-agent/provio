# Where to share, and what to say

Venues were checked on 2026-09-23 (the forums returned HTTP 200, and the
GitHub Discussions categories were listed through the API). Read each
venue's rules before posting. Post in the one channel meant for showcases,
never in support or help channels, and never DM maintainers. Each intro is
2–3 sentences, written for that audience; link the repo and, where it fits,
the attack demo.

Links used below:
- Repo: https://github.com/writ-agent/provio
- Demo: https://github.com/writ-agent/provio/tree/main/examples/attack-demo
- Playground: https://provio.vercel.app/playground.html

---

## Model Context Protocol

**Where:**
- The MCP community Discord (the one linked from glama.ai and
  awesome-mcp-servers: https://glama.ai/mcp/discord): its showcase or
  projects channel.
- The official **MCP Contributors Discord**
  (https://modelcontextprotocol.io/community/communication) is for spec and
  SDK work, not promotion. Only join a `#security-ig` discussion there if a
  thread is already about tool-call authorization or audit, and offer
  experience rather than a link.
- GitHub Discussions on `modelcontextprotocol/modelcontextprotocol` has an
  **"Ideas – Security"** category. Use it only for a genuine protocol
  question, for example how proxies should report policy denials to clients.

**Intro:**
> provio is an open-source MCP proxy (stdio or Streamable HTTP) that checks
> every `tools/call` against a `provio.yaml` policy (allow, deny, ask, or
> redact the result) before forwarding it, and records each decision in a
> hash-chained ledger. Over HTTP, provio injects the upstream credentials
> itself and doesn't forward the agent's own `Authorization` header unless
> told to. It's honest about its limits: a proxy can't see the agent's own
> shell, and `provio doctor` says so.

## Claude Code

**Where:** the Claude Discord (https://discord.com/invite/anthropic): the
project-sharing channel. r/ClaudeAI is covered in `reddit.md`.

**Intro:**
> provio plugs into Claude Code's PreToolUse/PostToolUse hooks with one
> command (`provio integrate claude-code`). Every tool call is checked against
> a `provio.yaml` in your repo, a provio `ask` becomes Claude Code's own
> permission prompt, and everything lands in a ledger you can
> `provio verify`. There's an offline demo where an injected README tries to
> exfiltrate an SSH key, with scripted tool calls and real provio output.

## LangGraph / LangChain

**Where:** the LangChain Forum, https://forum.langchain.com, category
**"Talking Shop"**. The LangGraph repo has no GitHub Discussions.

**Intro:**
> provio-sdk wraps a LangGraph `ToolNode` (`provio_tool_node(tools, provio)`) so
> every tool call is checked against a `provio.yaml` policy before it runs:
> allow, deny (the model gets the rule and reason back as the tool result),
> ask a human, or redact the output. Each decision goes to a hash-chained
> ledger, and `provio replay --candidate` shows what a new policy would have
> done to a past run. I'd like feedback on how this fits with interrupts
> for human-in-the-loop.

## OpenAI Agents SDK

**Where:** the OpenAI Developer Community, https://community.openai.com,
category **"Community"** (the showcase area; confirm the subcategory). The
`openai/openai-agents-python` repo has no Discussions.

**Intro:**
> `provio_sdk.openai_agents.guard_agent(agent, provio)` puts a policy check in
> front of every function tool an Agents SDK agent calls: allow, deny with a
> reason the model can act on, ask a human, or redact. Decisions are recorded
> in a local hash-chained ledger, with no hosted service and no telemetry.
> It works the same whichever model backs the agent.

## Codex CLI

**Where:** GitHub Discussions on `openai/codex`, category **"Show and
tell"**, plus the **"Codex"** category on community.openai.com.

**Intro:**
> provio integrates with Codex CLI's hooks (`provio integrate codex` writes
> `.codex/config.toml` and keeps your comments). Each tool call is checked
> against a `provio.yaml` policy and recorded in a hash-chained ledger. Codex
> has no ask prompt, so a provio `ask` fails closed; `provio run -- codex` also
> launches it inside an OS write boundary.

## Gemini CLI

**Where:** GitHub Discussions on `google-gemini/gemini-cli`, category
**"Show and tell"**.

**Intro:**
> provio hooks into Gemini CLI's BeforeTool/AfterTool events
> (`provio integrate gemini`), so every tool call is checked against a
> `provio.yaml` policy: deny with a reason, a provio `ask` shown as Gemini's own
> confirmation, or redacted output. Each decision is written to a
> hash-chained ledger you can verify later.

## Cursor

**Where:** the Cursor Community Forum, https://forum.cursor.com, category
**"Showcase"**.

**Intro:**
> provio adds a policy check to Cursor's agent hooks (`provio integrate cursor`
> writes `.cursor/hooks.json` with `failClosed: true`). Tool calls and MCP
> calls are allowed, denied or sent to Cursor's own prompt according to a
> `provio.yaml` in the repo, and recorded in a hash-chained ledger. Cursor also
> runs Claude Code hooks from `.claude/settings.json`; provio detects Cursor
> payloads there and tells you which integration to use.

## Windsurf

**Where:** the Windsurf community channel (Discord or forum; check which is
current). This one is lower priority.

**Intro:**
> `provio integrate windsurf` adds a policy check to Windsurf's run_command,
> read/write and MCP hooks, recording every decision in a hash-chained
> ledger. Windsurf's hooks have no prompt or output-rewrite path, so a provio
> `ask` or `redact` is denied. The integration doc lists the residual risks.

---

## Timing

Space these out over the week after the Show HN, one or two a day, and only
when you can stay around to answer questions. Put a venue's integration
first: the Codex post leads with Codex, not Claude Code.

**Before posting:** the Codex, Gemini, Cursor and Windsurf integrations are
on `main` and **not in 0.1.1**. Don't post in those venues until a release
that includes them is on PyPI and npm.
