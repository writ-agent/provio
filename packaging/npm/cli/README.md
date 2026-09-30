# provio

**A safety floor your AI agents can't get under.** Every tool call an AI agent makes is checked
against one policy file (`provio.yaml`: allow / deny / ask / redact) before it
runs, and written to a hash-chained, tamper-evident ledger after.

This package installs the prebuilt `provio` command-line tool (npm fetches only the binary for your platform):

```bash
npm install -g provio   # or: pip install provio
provio --version
provio integrate claude-code   # govern every Claude Code tool call
provio run -- claude           # or launch an agent inside a kernel write boundary
provio verify                  # check the ledger's hash chain
```

For Node agents and the Claude Agent SDK, install
[`provio-sdk`](https://www.npmjs.com/package/provio-sdk), which depends on this
package.

Documentation, policy reference and threat model:
https://github.com/writ-agent/provio
