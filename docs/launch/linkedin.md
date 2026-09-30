# LinkedIn post

Attach `docs/launch/demo-attack.png` (or the video). Put the links in the
post body; LinkedIn shows the first ~3 lines before "see more", so the hook
is in those lines.

---

A README in a repository told an AI coding agent to read the developer's SSH
key, upload it to an outside server, and delete the project.

In the demo below, the agent tried all three. None of them happened.

I've been building provio, an open-source layer that checks every tool call an
AI agent makes against a policy file before it runs, and records each
decision in a hash-chained ledger afterwards.

What that looks like in practice:

→ One `provio.yaml` in the repository, reviewed like any other code. Four
verdicts: allow, deny, ask a human, or run and redact sensitive output.
→ A denied call goes back to the agent with the rule and the reason, so it
can correct course.
→ A ledger that `provio verify` can check. Edit a record afterwards and verify
names the record where the chain breaks. Signed receipts extend that to
whoever holds the receipt.
→ The same policy across Claude Code, Codex CLI, Gemini CLI, Cursor, MCP
servers, LangGraph and the OpenAI Agents SDK.

What it doesn't do: it doesn't stop prompt injection. It limits what an
injected agent can do, and it keeps the record. The threat model in the repo
lists the residual risks.

The demo is reproducible offline, with no API key. The agent's tool calls
are scripted; provio's decisions and ledger output are real:
https://github.com/writ-agent/provio/tree/main/examples/attack-demo

Repo (Apache-2.0): https://github.com/writ-agent/provio
Try the policy engine in your browser: https://getprovio.vercel.app/playground.html

If your team gives agents real credentials, I'd like to hear how you're
governing them today.

#AIagents #AppSec #OpenSource #DevSecOps
