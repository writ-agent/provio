# DECISIONS.md — Architecture Decision Records (append-only)

## ADR-001: Interception, not orchestration
Provio wraps agents; it does not own the agent loop. Adoption friction is the
primary architectural constraint (spec §5). Consequence: three interception
modes (MCP proxy, process wrap, SDK hooks), never a runtime users must adopt.

## ADR-002: Ledger schema v1 is frozen
`provio verify` must verify every historical ledger version forever (plan §2 Q3).
Changes are additive-only under `schema_version`. Golden fixtures committed.

## ADR-003: Two-phase ledger records
One `Decision` record at verdict time (crash-safe evidence of the decision),
one linked `Execution` record at completion (`decision_index`). Records are
never mutated; mutation would void tamper-evidence.

## ADR-004: Pluggable policy engines behind one IR
Native DSL (default), Rego, Cedar — all compile to `provio_core::Verdict` and
must agree on the shared fixture corpus. Enterprise teams keep their language;
developers get ergonomics (spec §7).

## ADR-005: Default ledger store is JSONL; SQLite is a feature
`FileLedgerStore` (append-only JSONL) works on every platform with zero native
dependencies. `SqliteLedgerStore` (WAL mode, spec §9) ships behind the
`sqlite` cargo feature (provio-cli: `--features sqlite`, bundled SQLite, so a C
compiler is needed at build time) and can become the default workstation
store once release packaging builds with it. Both stores pass the same
generic suite and `verify_chain`, and a SQLite row is the exact JSONL line —
the store is swappable, the evidence format is not.

## ADR-006: Windows builds use the GNU toolchain in this environment
**Status: superseded by ADR-009.**
The reference build environment lacks MSVC Build Tools; the repo pins nothing —
`rust-toolchain.toml` selects `stable` only. Release binaries are built in CI
on native runners per platform (plan §3.8).

## ADR-007: No chrono; own 100-line Timestamp
**Status: the constraint is lifted by ADR-009; the decision stands** — the
own `Timestamp` and std-only test helpers work and carry no maintenance cost,
so they are kept rather than churned.
The reference GNU toolchain's bundled dlltool cannot spawn an assembler, so
any crate needing raw-dylib import libs (chrono→windows-link,
windows-sys via clap-color/tracing-ansi, tempfile) fails to build here.
Consequences: provio-core ships its own RFC 3339 `Timestamp` (fully tested);
clap and tracing-subscriber run with color/ansi default features disabled;
tests use a std-only temp-dir helper. CI on native runners may relax this.

## ADR-008: Dependency-free TUI in wave 1
The approval gate, call tree and cost meter are pure-std ANSI + line input
(no ratatui/crossterm), keeping the binary statically linkable everywhere
including this environment. A full-screen ratatui UI can layer over these
primitives in wave 2. Rendering goes to stderr: in proxy mode stdout is the
JSON-RPC protocol channel.

## ADR-009: Windows development uses the MSVC toolchain
Supersedes ADR-006. The reference Windows machine now has Visual Studio 2022
Build Tools and the Windows SDK, and the full workspace (including
`cedar-policy`, whose `stacker`/`psm` build scripts need a C compiler, and
`windows-sys` ≥ 0.52, which needs raw-dylib import libraries) builds and
passes tests with `stable-x86_64-pc-windows-msvc`. CI and release builds were
already MSVC on Windows.
Consequences: the GNU-only workarounds are removed (`scripts/env.ps1`,
`scripts/as_wrapper.c`, the `cedar-policy` target gate). The `windows-gnu`
target is not supported for development; `rust-toolchain.toml` still selects
only the `stable` channel so each platform uses its default host toolchain.
