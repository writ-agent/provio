# provio

**A safety floor your AI agents can't get under.** Every tool call an AI agent makes is checked
against one policy file (`provio.yaml`: allow / deny / ask / redact) before it
runs, and written to a hash-chained, tamper-evident ledger after.

This package installs the prebuilt `provio` command-line tool:

```bash
pip install provio      # or: npm install -g provio
provio --version
provio integrate claude-code   # govern every Claude Code tool call
provio run -- claude           # or launch an agent inside a kernel write boundary
provio verify                  # check the ledger's hash chain
```

For Python agent frameworks (LangGraph, OpenAI Agents SDK, Claude Agent SDK)
install [`provio-sdk`](https://pypi.org/project/provio-sdk/), which depends on this
package.

Documentation, policy reference and threat model:
https://github.com/writ-agent/provio

<!-- MCP Registry ownership marker -->
mcp-name: io.github.writ-agent/provio
