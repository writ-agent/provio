---
description: What would provio have caught in your agents' last 30 days?
allowed-tools: Bash(provio scan:*)
---

Run `provio scan --format markdown` (add `--days $ARGUMENTS` if a number was
given) and show its output. Then, in two or three sentences, say which of
the blocked or asked calls look like real risks and which look like noise,
and suggest the one-line `packs:` or rule change in provio.yaml that would
address the most important one. Do not change any file.
