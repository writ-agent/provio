# THREAT_MODEL.md

Published from the first commit, per the Writ v2.0 specification §15.
A written threat model with honest exclusions is a stronger trust signal than
any feature list.

## Controls and residual risk

| Threat | Control | Residual risk |
|---|---|---|
| Agent runs a destructive command (hallucinated or injected) | Policy deny on matched patterns; kernel write and network boundary for commands run through the `local-os` sandbox backend (see below) | Novel command forms not matched by rules, mitigated by the fail-closed default (`default: ask`). The agent launched by `writ run` is inside a write boundary (see [Interactive boundary](#interactive-boundary-writ-run----agent)), but everything inside its writable set — the workspace above all — is fair game |
| Destructive command hidden behind an innocent call (`bash cleanup.sh`, `npm run x`, a heredoc fed to a shell, a script the agent writes) | The commands behind the call are judged too: script lines, `package.json` scripts, heredocs by consumer, shell strings inside Python/JS; a dangerous script is refused when it is written. See [inspection.md](inspection.md) | Obfuscated or run-time-assembled commands (`eval "$(… \| base64 -d)"`), scripts changed between the check and the run, and program logic other than literal shell strings. Under `writ run` the kernel write boundary still holds whatever the script does |
| Agent switches off its own guard rails (edits hook config, deletes the ledger, relaunches itself with `--dangerously-skip-permissions` / `--yolo`) | The `floor` pack denies writes to `.writ/` and to the agents' hook files, and launching agents with bypass flags; edits to `writ.yaml` ask | Only as strong as the command matching for shell writes (the file tools are matched by path); a user-level hook config outside the project is protected only by `writ init --global` wiring the same floor. Hook integrity itself is the agent's: see the per-agent notes below |
| Data exfiltration to an attacker-controlled host | Sandboxed commands get no network at all (hostname allow-lists are refused, not approximated); credential injection at dispatch | Exfiltration through an allow-listed host (e.g. a permitted API with a write endpoint) |
| Malicious or compromised MCP server | Per-server identity, scoped credentials, scanner verdict as a policy input (`server.trust`); tool definitions pinned on first use, so a changed description is hidden from the agent and calls to that tool are refused until a human accepts it ([mcp-pins.md](mcp-pins.md)) | A server malicious from first use is pinned as it is; a server that keeps its descriptions but changes what a tool does; prompts and resources are not pinned |
| MCP server reached over HTTP (`writ proxy --transport http`) | Same per-`tools/call` pipeline as stdio; credentials injected upstream by writ and the agent's own `Authorization`/`Cookie` never forwarded unless asked; loopback-only listener with Host/Origin checks (`--allow-remote` requires a bearer token); no redirects followed. See [mcp-http.md](mcp-http.md) | A hostile server can place data outside tool results (other JSON-RPC methods, notifications) that policy does not evaluate; like the stdio proxy, the agent can bypass it by reaching the server directly |
| Irreversible action taken without authority | `ask` verdict with a human gate; `irreversible` marking | Approval fatigue — the human clicks allow. Mitigated by keeping `ask` rare and diffs precise |
| Audit record altered after the fact | Hash chain + `writ verify` (names the first broken record); signed receipts (`writ receipt create` / `verify`: Ed25519ph over a checkpoint of ledger id, record count, tip hash and RFC 6962 Merkle root); per-call inclusion proofs (`writ receipt prove`); external anchors (`writ receipt anchor --to rekor` into the Sigstore Rekor public log, or `--to file` for an append-only log you copy elsewhere). See [receipts.md](receipts.md) | Records after the most recent receipt are tamper-evident only: a host-level attacker can rewrite or delete them and recompute the chain. Receipts do not help if the signing key is stolen or lives on a compromised host (a new receipt over a rewritten ledger verifies; only earlier anchored receipts contradict it), or if the host was already compromised when the receipt was signed. Verifiers must pin the signer's public key out of band. `--to file` anchors are witnesses only once copied to storage the ledger host cannot rewrite |
| Agent bypasses Writ entirely | Process wrap (`writ run`: launch decision, kernel write boundary, Claude Code tool-call hooks) and MCP proxy; `writ doctor` coverage report | **In MCP-proxy-only mode this is trivially possible.** Under `writ run`, per-tool-call governance exists only for agents with a hook interface (Claude Code); other agents are confined but their individual tool calls are not decided. See the residuals below. Stated loudly in the README and doctor output |

## Kernel boundary (`local-os` sandbox backend)

Applies to commands executed through `LocalOsBackend`. By default
(`EnforcementMode::Required`) a spec the running kernel cannot fully enforce
is refused at `prepare`; degraded mode is an explicit opt-in that reports
each gap as enforced, partial, or not enforced. `writ doctor` probes the
running machine rather than assuming from the OS.

| Platform | Mechanism | Enforced | Residuals |
|---|---|---|---|
| Linux | Landlock (all write rights of the running ABI) + seccomp | Writes only under the workspace, a private temp dir and `/dev/{null,zero,full}`; `socket()` of every family, non-unix `socketpair` and `io_uring` return EPERM; holds as root | Reads and exec are not restricted. Landlock ABI v1–2 cannot cover truncate (refused in Required mode). Workspaces on 9p/drvfs (WSL `/mnt/c`) are refused because Landlock misbehaves there |
| Windows | AppContainer token (low IL, no capabilities) + Job Object | Writes only in the workspace and the container profile; network blocked including loopback (when BFE and mpssvc run); kill-on-close, no breakaway, process limit | Objects that grant ALL APPLICATION PACKAGES write access stay writable. Reads are limited to what ALL APPLICATION PACKAGES can read, so tools installed under the user profile will not start. The workspace ACE persists after teardown |
| macOS | Seatbelt (`sandbox_init`, generated profile) | Writes only under workspace and temp; network denied (syscall-level tests run on CI's macOS runner) | Mach IPC is not restricted; reads are not restricted. `sandbox_init` is deprecated API that Apple may change |

No platform can filter egress by hostname at this layer, so a non-empty
`allowed_hosts` fails closed rather than being silently widened.

## Interactive boundary (`writ run -- <agent>`)

`writ run` records one `process.exec` decision, then launches the agent
**interactively** (the user's terminal, environment and exit code) inside a
kernel boundary that confines **writes** and, on request, the network.
Reads are not restricted: agents must read toolchains, node, their own
install.

**Writable set (default).** The workspace (cwd); a private temp dir created
per run (TMPDIR / TEMP / TMP point at it; removed afterwards); the agent
profile's own state dirs (claude: `~/.claude` or `$CLAUDE_CONFIG_DIR`,
`~/.claude.json`, its cache; codex: `~/.codex` or `$CODEX_HOME`; gemini:
`~/.gemini`; aider: `~/.aider`; unknown commands: nothing extra); and, when
Claude Code hooks are on, the ledger's directory (`writ check` runs inside
the boundary and appends there). Shared package caches (npm, pip, uv,
cargo) are **not** writable by default — a writable cache poisons later
unconfined runs of the same tools — and are only suggested for
`--allow-write`. Default mode refuses to launch when the kernel cannot
enforce the boundary; `--best-effort` runs and reports each gap;
`--unconfined` launches with no boundary and says so.

| Platform | Mechanism | Enforced | Not enforced |
|---|---|---|---|
| Linux | Landlock (files and dirs of the writable set, plus `/dev/tty`, `/dev/ptmx`, `/dev/pts`, `/dev/shm`) + seccomp | Writes outside the set denied (EACCES); `--net none`: `socket()` EPERM for every family; `--net open`: only unix/inet/inet6/netlink sockets, io_uring denied | Network with `--net open` (no host filtering); POSIX shared memory in `/dev/shm` is shared with the user's other processes |
| macOS | Seatbelt profile | Writes outside the set denied (EPERM); `--net none`: `(deny network*)`; protected settings files denied by rules after the allow list | Network with `--net open`; mach IPC to system daemons |
| Windows | Restricted token (no privileges, Administrators deny-only) at Low integrity + Low mandatory labels on the writable set + Job Object (kill-on-close, no breakaway) | Writes to anything not labelled Low denied (ERROR_ACCESS_DENIED) | `--net none` (a Low token cannot deny sockets; refused in default mode). Local COM/RPC/WMI brokers running at Medium are not blocked by integrity levels. FAT/exFAT volumes carry no labels (a writable path there is refused; other such volumes, e.g. USB drives, stay writable); integrity labels are not relied on for SMB shares. `%USERPROFILE%\AppData\LocalLow` is writable by any Low process |

### Windows side effect: persistent integrity labels

On Windows every path in the writable set (except the per-run temp dir)
receives an explicit, inheritable **Low** mandatory label, and it **persists
after the run**: any Low integrity process of the same user (a sandboxed
browser renderer, a document reader's sandbox) can write there too.
`writ run` lists every path that will be labelled *before* labelling it, and
repeats the list after launch. Labelling is idempotent (already-labelled
paths are skipped). To undo:

```
icacls "<path>" /setintegritylevel (OI)(CI)M
```

Add `/T` to also reset files the agent created (those carry their own Low
label). Keep the writable set small: every `--allow-write` path is labelled
the same way.

### Claude Code hooks: what can and cannot switch them off

With the claude profile (unless `--no-hooks`), writ passes its hooks with
`claude --settings <file>`. The file lives in a writ-owned directory that is
**not** in the writable set, and it pins `"disableAllHooks": false`.
Per Claude Code's settings documentation, `--settings` outranks local,
project and user settings, and `disableAllHooks` is read after precedence
applies, so an agent that writes `disableAllHooks: true` into
`~/.claude/settings.json`, `.claude/settings.json` or
`.claude/settings.local.json` does not disable writ's hooks. Hook entries
merge across levels, so deleting hooks from those files does not remove
writ's either.

It is **not** tamper-resistant:

| Residual | Platform |
|---|---|
| The agent can rewrite `~/.claude/settings.json` and the workspace's `.claude/settings*.json` and plant hooks or permissions that take effect in **later sessions run outside writ**. macOS denies writes, deletes and renames of these files (Seatbelt deny after the allow list). Linux cannot: Landlock has no way to exclude a file beneath an allowed directory, and granting only `~/.claude`'s subdirectories breaks Claude Code's atomic top-level writes (`.credentials.json`, policy caches). Windows cannot: an explicit Medium label on the file blocks in-place writes, but measured, the Low agent can still delete it, rename a new file over it, or create it, through the Low-labelled parent directory. `writ run` says `protected: NO` on those platforms | Linux, Windows |
| Managed settings outrank `--settings`: an administrator's `disableAllHooks` or `allowManagedHooksOnly` can switch writ's hooks off (the agent cannot write the managed-settings locations, which are outside the writable set) | all |
| A `claude` the agent starts itself (e.g. `claude -p ...` from its shell tool) does not get writ's `--settings`: its tool calls are not decided by writ, though it runs inside the same kernel boundary | all |
| The policy file and the ledger are only as safe as their location: inside the workspace (the default `.writ/`), or in the ledger directory granted for hooks, the agent can rewrite them. The hash chain makes after-the-fact edits evident on `writ verify`, not impossible; keep `--policy` outside the workspace | all |
| Hooks exist only for agents with a hook interface; codex, gemini, aider and generic commands are confined but their individual tool calls are not governed | all |

### Other residuals of the interactive boundary

- Everything writable is writable: the workspace (including `.git/hooks`,
  build scripts and editor configs that run later outside the boundary) and
  the agent's state dirs.
- The network is open by default and not filtered by host; exfiltration of
  anything the agent can read is not prevented.
- Linux: Landlock on filesystems with unstable inodes (WSL `/mnt/c`, some
  FUSE) is refused for the workspace or may spuriously deny writes.
- Descendants die with the run on Windows (Job kill-on-close); on Unix a
  daemonized descendant outlives writ but stays confined.

## Explicitly out of scope

- **Prompt injection is not solved.** Writ reduces the blast radius of a
  successful injection; it does not detect or prevent one.
- **Model-layer safety** — harmful content, jailbreaks, output filtering.
- **A malicious operator.** Someone who can edit `writ.yaml` and the ledger is
  inside the trust boundary. Cluster mode narrows this with RBAC and remote
  ledgers; workstation mode does not attempt it.
- **Side-effect reversal.** Writ can prevent and record. It cannot undo.

## Claim discipline (project policy)

No unearned assurance labels, no certification claims (SOC 2 applies to
organisations and hosted services, not binaries), no unbenchmarked performance
numbers. Latency figures live only in reproducible benchmarks in this
repository. Enforced by the `claim-discipline` CI job.
