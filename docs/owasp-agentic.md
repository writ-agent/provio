# provio and the OWASP Top 10 for Agentic Applications (2026)

How provio's controls map onto the
[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/) (OWASP GenAI
Security Project, December 2025). "Partial" means provio limits the damage
of the risk but does not address its cause; the threat model
([THREAT_MODEL.md](THREAT_MODEL.md)) has the residuals.

| Risk | What provio does | Coverage |
|---|---|---|
| **ASI01 Agent Goal Hijack** | Does not detect a hijacked goal (it does not read prompts or model output). It limits what a hijacked agent can do: the `floor` pack, deny/ask rules on every tool call, the `secret_then_egress` session guard (a session that read a credential file is asked before it sends data out: the exfiltration leg of the lethal trifecta), the kernel write boundary under `provio run`, and a ledger of what it tried. | Partial (blast radius) |
| **ASI02 Tool Misuse and Exploitation** | The core of provio: every tool call (shell, file, HTTP, MCP) checked against one policy before it runs, judged by what it will run (scripts, heredocs, `npm run`); 20 packs for destructive and irreversible tool use; `ask` puts a human in front of irreversible calls. | Primary |
| **ASI03 Identity and Privilege Abuse** | `floor` and `secrets-guard` deny reading SSH keys, cloud credentials, token files and credential stores; the MCP proxy injects credentials at dispatch so the agent never holds them; `paas-safety` denies printing CLI auth tokens; once a session has read a credential file, data-carrying network calls ask (`secret_then_egress`). It does not issue or scope identities. | Partial |
| **ASI04 Agentic Supply Chain Vulnerabilities** | MCP tool pinning holds a tool whose definition changed (the rug pull) until a human accepts it; `server.trust` lets a scanner's verdict feed policy; `package-publish-guard` and `ci-config-guard` gate publishing and CI-definition edits; the floor asks before `curl \| sh`. It does not scan packages or MCP servers itself. | Partial |
| **ASI05 Unexpected Code Execution** | Scripts an agent writes or runs are read and judged line by line; shell strings inside Python/JS are extracted; reverse shells are denied; under `provio run` the process is confined to its workspace by the kernel whatever it executes. | Primary |
| **ASI06 Memory and Context Poisoning** | `redact` masks secrets in tool output before it re-enters the model's context; the floor denies the agent writing its own hook config or ledger. It does not inspect memory stores or RAG data. | Limited |
| **ASI07 Insecure Inter-Agent Communication** | MCP traffic can be proxied and decided per call (stdio and Streamable HTTP, loopback-only listener, Host/Origin checks). Agent-to-agent protocols are not interpreted. | Limited |
| **ASI08 Cascading Failures** | Fail-closed defaults (an error or missing policy denies), `irreversible` asks, and the ledger to reconstruct what happened. There is no rate limiting or circuit breaker yet. | Limited |
| **ASI09 Human-Agent Trust Exploitation** | An `ask` shows the rule and the reason, and for a hidden command the exact script line it found, so approvals are made on what will run rather than on the agent's summary; `provio report` shows what was approved and by whom. | Partial |
| **ASI10 Rogue Agents** | Every call is recorded in a hash-chained ledger with signed, Rekor-anchored receipts; `provio scan` and `provio report` surface what an agent actually did; the floor denies disabling its own guard rails and relaunching with `--dangerously-skip-permissions` / `--yolo`. | Partial (detect and contain) |

Controls referenced: [packs/](../packs/), [inspection.md](inspection.md),
[mcp-pins.md](mcp-pins.md), [receipts.md](receipts.md),
[first-run.md](first-run.md), the kernel boundary in
[THREAT_MODEL.md](THREAT_MODEL.md).
