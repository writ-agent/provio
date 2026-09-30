# claude-code#88462, replayed

In [anthropics/claude-code#88462](https://github.com/anthropics/claude-code/issues/88462)
(August 2026, auto mode), an agent wrote a cleanup script whose `trap` ran
`rm -rf "$HOME"`, then ran it. The reporter's diagnosis: "inspection happens
on the command string". The command string was `bash cleanup.sh`.

This demo replays that incident against writ in three acts, offline, with
scratch folders standing in for your home directory:

| Act | What the agent does | What stops it |
|---|---|---|
| 1 | **writes** `cleanup.sh` with the `trap 'rm -rf "$HOME"' EXIT` line | writ refuses the write: it reads the script being written ([inspection](../../docs/inspection.md)) |
| 2 | the script exists anyway (a checkout, another tool); the agent **runs** `bash cleanup.sh` | writ refuses the run: it reads the script the command runs, and names line 3 |
| 3 | the same delete, **obfuscated**: `eval "$(echo cm0gLXJmICIkSE9NRSI= \| base64 -d)"` | no text rule can read that, and writ says so (ALLOW). Run the way `writ run` runs an agent, the **kernel** refuses every write outside the workspace; the home directory survives |

Acts 1 and 2 feed the exact Claude Code `PreToolUse` payloads to the real
`writ check --format claude-code`. Act 3 runs a real shell inside writ's
kernel write boundary (Landlock on Linux, Seatbelt on macOS). The policy is
[`writ.yaml`](writ.yaml), identical to what `writ init` writes.

```bash
pip install writ-cli          # or npm install -g @writ-agent/cli
./examples/incident-88462/run.sh
```

Real output (writ 0.1.3+, Linux):

```text
Act 1. The agent writes cleanup.sh (Claude Code Write tool).
    #!/bin/bash
    set -e
    trap 'rm -rf "$HOME"' EXIT
    echo "cleaning build artifacts"
  DENY  writ denied this: rule "floor-rm-home-or-root-denied" — the file being written
(cleanup.sh) line 3 runs `trap 'rm -rf "$HOME"' EXIT`. Recursive delete of your home directory, a
top-level home folder, or a system root. No agent task needs this; name the exact subdirectory
instead. (pack:floor@0.1.0)

Act 2. The script is there anyway (a checkout, another tool), and the agent runs it:
    $ bash cleanup.sh   <- all a command-string check ever sees
  DENY  writ denied this: rule "floor-rm-home-or-root-denied" — script cleanup.sh line 3 runs
`trap 'rm -rf "$HOME"' EXIT`. …

Act 3. The same delete, obfuscated so no text rule can read it:
    $ eval "$(echo cm0gLXJmICIkSE9NRSI= | base64 -d)"
  ALLOW writ: allowed by rule "default"
  The rules miss this one, as any command parser would. Now run it the way
  writ run runs an agent: inside the kernel write boundary (workspace only).

    filesystem : enforced — writes outside the writable paths are denied by the kernel
    rm: cannot remove '/tmp/writ-88462.Vi4wH0/home/.ssh/id_ed25519': Permission denied
    rm: cannot remove '/tmp/writ-88462.Vi4wH0/home/Documents/thesis.md': Permission denied

  Home directory intact: ./.ssh/id_ed25519 ./Documents/thesis.md
  The kernel refused every write outside the workspace; no rule was involved.

The record. Every decision above is in the workspace's hash-chained ledger:
    2 sessions · 5 records · 2 denied · 0 sessions with your approvals
    chain intact · 5 records · no gaps
```

## What this shows, and what it does not

- The policy layer reads what a call will run, not only its command line,
  but it is still text matching: act 3 gets past it, as it would get past
  any command-string check. writ reports that as an ALLOW rather than
  pretending.
- The kernel boundary does not read anything. Under `writ run`, an agent can
  write to its workspace and its own state directories, and nowhere else,
  whatever it runs. Inside the workspace, everything is still fair game:
  commit or back up what you care about.
- Act 3 needs a kernel that can enforce the boundary (`writ doctor` tells
  you). On Windows, `writ run` uses a low-integrity token instead; this
  script is for Linux and macOS (WSL works).
