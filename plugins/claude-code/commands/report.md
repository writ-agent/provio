---
description: What did the agent do while you were away? (provio report)
allowed-tools: Bash(provio report:*)
---

Run `provio report --format markdown --out - --since ${ARGUMENTS:-12h}` and
show its output: what provio stopped, what needed a human and how each ended,
and whether the ledger's hash chain is intact. Do not change any file.
