# Changelog

All notable changes to writ are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and writ uses
[Semantic Versioning](https://semver.org/) from its first tagged release.
The ledger record schema is versioned separately (`schema_version`, see
[docs/INTERFACES.md](docs/INTERFACES.md)) and only ever changes additively.

## [Unreleased]

## [0.1.3] — 2026-09-30

### Renamed: writ is now **provio**

The old name collided with other projects in the same category (a Claude
Code governance tool called Writ, the `writ-agent` package on PyPI, the
`writ`/`writ-cli` crates). provio is free on GitHub, PyPI, npm and
crates.io.

| Before | Now |
|---|---|
| `writ` binary | `provio` |
| `writ.yaml`, `.writ/` | `provio.yaml`, `.provio/` (the old paths are still found, with a notice, when the new ones do not exist) |
| PyPI `writ-cli`, `writ-sdk` (`import writ_sdk`) | `provio`, `provio-sdk` (`import provio_sdk`) |
| npm `@writ-agent/cli`, `@writ-agent/sdk` | `provio` (`npx provio scan`), `provio-sdk` |
| `WRIT_*` environment variables | `PROVIO_*` |
| GitHub `writ-agent/writ` | `writ-agent/provio` (old URLs redirect) |
| Postgres default schema `writ`, `writ_schema=`/`writ_table=` | `provio`, `provio_schema=`/`provio_table=` (the old parameter names still work; pass `provio_schema=writ` to keep an existing ledger) |

Unchanged on purpose: ledgers and their hashes, and the wire-format ids
inside signed receipts, proofs and anchor lines (`writ.receipt/v1`, …), so
every receipt issued before the rename still verifies. `provio integrate`
and `provio init` recognise and replace hooks written by `writ`, and the
`floor` pack guards both `.provio/` and `.writ/`, `provio.yaml` and
`writ.yaml`.

### Added

- **Claude Code plugin** (`/plugin marketplace add writ-agent/provio`,
  `/plugin install provio@provio`): every tool call checked by provio in
  every project, with the project's provio.yaml or, where there is none, the
  starter floor; fails closed without the binary; `/provio:scan` and
  `/provio:report` commands. `provio check --if-no-policy starter` is the
  flag behind it.
- **`provio scan`**: replays what your agents already did (Claude Code, Codex
  and Gemini CLI transcripts on this machine) through the policy and prints
  a scorecard of what would have been blocked or asked, with examples per
  rule. Reads only; `--format markdown` is a shareable counts-only summary,
  `--format json` has every finding.
- **`provio init`**: writes a starter policy (`default: allow`, packs `floor`
  and `secrets-guard`; `--strict` for `default: ask`) and wires every coding
  agent found (Claude Code, Codex, Gemini CLI, Cursor, Windsurf); `--global`
  wires user-level config with the policy and ledger in `~/.provio/`; adds
  `.provio/` to `.gitignore`.
- **`provio test "<command>"`**: one call through the policy, nothing run or
  recorded; exit 0 allow, 2 deny, 3 ask. Also `--tool/--path/--content`,
  `--call <json>`, `--json`.
- **`packs:` in provio.yaml**: name bundled packs and provio composes them with
  your rules (their deny/ask first, your rules, their allow, their redact
  last); `skip:` leaves a pack rule out. Pack decisions are located as
  `pack:<id>@<version>`. Works for the native, Rego and Cedar engines and in
  the playground.
- **The `floor` pack**: the disaster floor. Denies recursive deletes of `~`,
  `/` and profile folders (including the claude-code#88462 `trap` shape),
  disk wipes, force pushes to main, reading SSH/cloud keys, reverse shells,
  agents rewriting their own hook config or ledger, and agents launched with
  `--dangerously-skip-permissions`/`--yolo`/`--trust-all-tools`; asks before
  database drops, cloud destroys, discarding uncommitted work, `curl | sh`
  and persistence. 100 fixtures, including near misses found by `provio scan`
  on real sessions.
- **Ten more policy packs** (20 in total, all bundled, each with a README
  and fixtures that include near misses): `windows-safety`, `macos-safety`,
  `linux-system-safety` (host security tooling, backups, logs, admins),
  `docker-safety`, `paas-safety` (Vercel, Netlify, Fly, Heroku, Railway,
  Wrangler, Supabase, Firebase), `ci-config-guard` (agents editing CI/CD
  definitions, CODEOWNERS, pipeline triggers), `exposure-guard` (tunnels,
  listeners on all interfaces, world-open firewall and cloud rules, public
  shares), `mcp-destructive-tools`, `outbound-comms-guard` (email, chat, SMS
  and social posts from MCP tools and the shell), `payments-guard` (Stripe
  live-mode writes denied; refunds, payouts, billing changes, crypto
  transfers ask). `provio scan --packs all` / `provio test --packs all` judge
  with every bundled pack.
- **Judged by what it runs** (`provio check`, `test`, `scan`): the commands
  behind a call are evaluated too: lines of scripts it runs (`bash x.sh`,
  `./x`, `npm run x`, `python x.py`) or writes (shell scripts,
  `package.json` scripts, Makefiles, Codex patches), heredocs by consumer,
  shell strings inside Python/JS. See docs/inspection.md.
- **MCP tool pinning** (`provio proxy`, stdio and HTTP; on by default,
  `--no-pin` to disable): tool definitions are pinned on first use; a
  changed definition (a rug pull) is removed from the agent's `tools/list`
  and calls to it are refused and recorded (`mcp-tool-pin`) until
  `provio mcp accept`. `provio mcp pins` shows old vs new. See docs/mcp-pins.md.
- **`provio report`, rebuilt**: what the agents did, led by what provio
  stopped and what needed a human (and how each ask ended), then a timeline
  per session and the ledger's integrity; `--since 12h`, `--session`,
  `--format markdown` for a pull request, `--format json`; `--sign <key>`
  embeds a signed receipt (also written next to the report) that anyone can
  check with `provio receipt verify`. Light and dark, no scripts.
- **`examples/incident-88462`**: claude-code#88462 replayed in three acts:
  the dangerous script is refused when written, refused when run, and the
  obfuscated variant (which no rule can read) is stopped by the kernel.
- `examples/starter.yaml` (what `provio init` writes) is the playground's first
  preset; new simulator calls for the floor.

### Changed

- Heredoc bodies are no longer matched as command-line text: `python - <<EOF`
  or `cat > notes.md <<EOF` bodies are judged by what consumes them.
- `secrets-guard`: `defaultdict(set)` and similar no longer trip the
  environment-dump rule.
- Policy packs are bundled by `provio-policy` (was `provio-cli`), so every
  engine and the WASM playground resolve `packs:`. Bundled packs are
  embedded with LF line endings whatever the checkout has, so the playground
  build is reproducible from a Windows working tree.

### Fixed

- The TypeScript adapter's lockfile pinned a placeholder for
  `provio`, so `npm ci` failed once 0.1.2 was on npm.

## [0.1.2] — 2026-09-25

### Added

- **`writ ui`**, a local web console: connect an agent (snippets with your
  paths, live "connected" signal), a live decision feed with full record
  detail and chain verification, an Approvals screen for `writ check --ask ui`,
  a policy editor with a "try a tool call" tester, and a sandbox screen that
  runs commands in the kernel boundary and shows escape attempts failing.
  Loopback-only, token-gated, strict CSP, no external requests.
- **More agents**: `writ check --format codex|gemini|cursor|windsurf`,
  `writ integrate` for each, and `writ run` hook injection for Codex, Gemini
  CLI and Cursor's `agent`. Every writ-side error returns that agent's
  blocking answer.
- **Signed receipts** (`writ receipt keygen|create|verify|prove|anchor`):
  Ed25519ph over a ledger checkpoint with an RFC 6962 Merkle root, per-call
  inclusion proofs, and anchoring in the Sigstore Rekor public log (verified
  offline against a pinned log key) or an append-only file.
- **Postgres ledger store** (`postgres` feature): many hosts append one
  chain under a row lock; append-only triggers; TLS via rustls with libpq
  `sslmode` semantics.
- **MCP proxy over Streamable HTTP / SSE** (`writ proxy --transport http`).
- **Browser playground** on the website: the real engine as WebAssembly.
- `--ask ui` in the Python and TypeScript SDKs.
- **Six new policy packs**: `aws-safety`, `gcp-azure-safety`, `github-safety`,
  `secrets-guard`, `database-safety`, `package-publish-guard`, each with
  fixtures; every pack now ships a README and fixtures, and
  `scripts/validate_packs.py` runs them (plus redact samples through the real
  gateway).
- Packs are **bundled into the binary**: `writ policy add <pack>` works in any
  directory (a local `./packs/<id>` still wins), and `writ ui` lists them all.
- Reproducible prompt-injection **attack demo** (`examples/attack-demo`).

### Fixed

- `k8s-prod` and `terraform-safety` missed subcommands after global flags
  (`kubectl --context prod delete`, `terraform -chdir=x destroy`); they now
  match, cover OpenTofu, and treat `apply -destroy` as a destroy.
- JSONL ledger: lock-free readers no longer report a write in progress as
  mid-file corruption (Linux, concurrent writers), and contended writers wait
  in the OS lock queue instead of polling (no starvation under load).

### Security

- `writ receipt keygen` strips Everyone / Authenticated Users / Users from
  the private key's ACL on Windows.
- A Postgres ledger URL is never printed with its password, and never written
  into agent hook configuration or a `writ run` hook command line.

## [0.1.1] — 2026-09-23

### Added

- **Prebuilt, signed `writ` binaries** for Linux x64/arm64 (static musl),
  macOS arm64/x86_64 and Windows x64 on every release, with checksums,
  Sigstore bundles, SBOMs and build provenance.
- **`writ-cli` on PyPI** (platform wheels carrying the binary) and
  **`@writ-agent/cli` on npm** (per-platform packages; npm installs only the
  one for your machine). `writ-sdk` and `@writ-agent/sdk` depend on them, so
  installing an SDK installs the binary — no repository or Rust toolchain.
- One tag-driven release workflow publishes GitHub Releases, PyPI and npm
  (with npm provenance); versions are kept in lockstep by
  `scripts/check_versions.py`.

## [0.1.0] — 2026-09-22

First published SDKs (`writ-sdk`, `@writ-agent/sdk`); they required building
the `writ` binary from source. Everything listed below under "Added",
"Changed" and "Fixed" shipped on `main` by this point.

### Added

- **Hook gateway `writ check`** (INTERFACES Contract 6): one-shot or
  `--stdio`, decide / resolve / complete, deferred asks, redaction of tool
  output, fail-closed on every error. Refs are checked against the ledger and
  work across processes.
- **Claude Code integration**: `writ check --format claude-code` hooks and
  `writ integrate claude-code`. A writ `ask` becomes Claude Code's own
  permission prompt; every writ-side failure blocks the call (exit 2).
- **`writ-sdk` Python package** ([PyPI](https://pypi.org/project/writ-sdk/), 0.1.0): LangGraph, OpenAI Agents SDK and Claude
  Agent SDK integrations plus `@writ_tool` for any callable.
- **`@writ-agent/sdk` TypeScript package** ([npm](https://www.npmjs.com/package/@writ-agent/sdk), 0.1.0): Claude Agent SDK hooks,
  `guard()` and `guardTools()`.
- The JSONL ledger is safe for many concurrent writer processes (lock file,
  tip re-read from disk).
- Brand: logo, icon, README hero and social preview.
- **Policy engines.** Rego (`writ-policy-rego`, via regorus) and Cedar
  (`writ-policy-cedar`, via cedar-policy) backends behind the same
  `PolicyEngine` trait, both verdict-identical to the native engine on the
  shared fixture corpus and fail-closed on any evaluation error.
- **SQLite ledger store** (`sqlite` feature): WAL, `synchronous=FULL`,
  append-only triggers, and concurrent writers that cannot fork the chain.
  Rows hold the exact JSONL record, so both stores produce the same hashes.
  `open_store` picks the store by content, then extension, failing closed.
- **Kernel sandbox for `local-os`**: Landlock + seccomp on Linux,
  AppContainer + Job Object on Windows, Seatbelt on macOS. Writes are
  confined to the workspace and a private temp dir, and network is denied.
  A spec the running kernel cannot fully enforce is refused unless
  best-effort mode is chosen explicitly. Tests assert the exact errno or
  Win32 error from inside the sandbox. `writ run` does not use it yet.
- **Docker sandbox backend** (`writ-sandbox-docker`): network `none` by
  default, workspace bind mount, per-exec deadlines, idempotent teardown.
- **Benchmarks** (`crates/writ-bench`, criterion) for policy evaluation,
  ledger append/verify and the MCP codec.
- **Fuzzing** (`fuzz/`, cargo-fuzz) of the policy compiler, ledger record
  decoding and the MCP codec, run weekly in CI.
- **CI**: cargo-deny (advisories, licenses, sources), claim-discipline lint
  (`scripts/claim_lint.py`), bench compilation, policy-pack validation, and
  `--all-features` test runs on Linux, macOS and Windows.
- Landing site (`site/`), code of conduct, CODEOWNERS, `.editorconfig`,
  `.gitattributes`, and a documentation index (`docs/README.md`).

### Changed

- The repository moved to [github.com/writ-agent/writ](https://github.com/writ-agent/writ).
- Ledger stores reject an append whose `record_hash` is not the record's own.
- `writ-policy` re-exports `default_verdict`, `verdict_for` and `eval_expr`
  so every engine builds verdicts from one implementation.
- Windows development uses the MSVC toolchain (ADR-009); the GNU-toolchain
  workarounds are gone.
- Internal build planning moved to `docs/internal/` (`BUILD_PLAN.md`,
  `MODEL_ROUTING.md`); `writ doctor` and the threat model now state that the
  kernel boundary does not cover the agent `writ run` launches.

### Fixed

- The MCP proxy passed output through unmasked when a redact pattern was
  invalid; it now withholds the output.
- Parallel tests on macOS shared one temp directory (microsecond clock), so
  replay tests wrote into one ledger.
- Concurrent opens of a SQLite ledger could fail with "database is locked".
- `fuzz_policy_compile` did not compile.

## Foundations (September 2026)

The first build waves, before this changelog existed:

- Frozen contracts in `writ-core`: `ToolCall`, the verdict IR, ledger record
  schema v1, `SandboxBackend`, `Approver`, and the decision pipeline.
- Native `writ.yaml` engine: parser, four verdicts, hot reload, fixture harness.
- Hash-chained JSONL ledger with `verify`, `log` and `show`.
- MCP stdio proxy with structured refusals and credential injection.
- `local-os` sandbox backend, approval gate TUI, and the `writ` CLI:
  `run`, `proxy`, `log`, `show`, `verify`, `replay`, `policy test`,
  `doctor`, `report`.
- OpenTelemetry GenAI spans, trajectory replay, three policy packs, release
  pipeline, threat model and ADRs.
