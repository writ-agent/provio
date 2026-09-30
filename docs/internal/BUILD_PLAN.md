# PROVIO — Master Build Plan (Full-Scope, Single-Pass)
**Authorization and provenance for AI agents. One policy file, one signed ledger, any agent.**

- Source spec: `Provio_Technical_Specification_v2.0.md`
- Build strategy: **all features, all at once** — the spec's v0.1→v0.4 market phasing is intentionally ignored; final-state architecture is designed up front and every feature is built in one coordinated program.
- License: Apache-2.0 (permanent, per spec §20). Language: Rust (per spec §5).

---

## 1. Strategy: Building Everything at Once Without Chaos

The spec phases scope for *market* reasons (earn the star → habit → team → org). Those reasons do not apply to an agent-driven build; what *does* still apply is dependency order (you cannot verify a ledger that has no schema). This plan therefore:

1. **Designs the final state first.** Every crate, trait, schema, and CLI verb is specified in Wave 0 as a frozen contract, before feature code is written. This is the single most important enabler of parallel multi-agent work.
2. **Flattens all phases into one feature manifest** (§3) — nothing is deferred except what the spec itself defers indefinitely (A2A recursive sub-agent spawning) or cuts (context engine, WASM tool driver, bespoke telemetry schema).
3. **Parallelizes by crate boundary.** Rust's workspace + trait isolation maps cleanly onto agent boundaries. Each agent owns crates/deliverables, never shared files.
4. **Sequences by dependency, not by market.** Five waves (§7), where each wave's tasks are internally parallel and waves overlap where contracts allow.
5. **Matches model cost to task difficulty** (§5). Frontier-model tokens are spent only where mistakes are expensive: security boundaries, cryptographic chaining, protocol correctness, and architecture.

### Deviation risk (stated honestly, as the spec demands)
The spec warns that shipping v0.4 scope before v0.2 retention is "the standard way these projects die." That risk is about *market validation*, not code. Mitigation in this plan: the **v0.1 demo screen (spec §16) is built and polished early in Wave 2** even though cluster features continue in parallel, so a launchable product exists at every point after Wave 2.

## 2. Open Questions From the Spec — Decided Here

The spec ends with four open questions (Appendix A). This plan answers them:

| # | Question | Decision | Rationale |
|---|----------|----------|-----------|
| 1 | Which agent to wrap first? | **Claude Code** via `provio run -- claude`, with the MCP proxy being agent-agnostic from day one. | Largest hook-friendly audience; the spec's own demo uses it; MCP proxy covers Codex/others without per-agent work. |
| 2 | Native DSL vs Rego first? | **Native DSL is the default; all three engines (native, Rego, Cedar) are built** behind one `PolicyEngine` trait compiling to a shared internal decision IR. | Spec already mandates pluggability; building all-at-once removes the either/or trade-off. Native wins developer ergonomics; Rego/Cedar win enterprise. |
| 3 | Must the ledger schema be stable at first release? | **Yes.** `schema_version` field from commit one; `provio verify` must verify every historical version forever; changes only ever via additive migrations with golden fixtures. | Verify-forever is the product's core promise; a breaking schema change silently destroys evidentiary value. |
| 4 | Register names before code? | **Yes, immediately (Wave 0, day 1):** GitHub org, crates.io `provio`, npm `provio`, provio.dev / provio.sh, USPTO/EUIPO search in software classes. | Spec §2: "Names in this category are being taken weekly." Cost is trivial; loss is unrecoverable. |

## 3. Final-State Feature Manifest (Everything, No Compromises)

Union of spec v0.1–v0.4 scope. Each item carries the spec section it comes from and its acceptance test.

### 3.1 Interception (all three modes, full coverage)
| Feature | Spec | Acceptance |
|---|---|---|
| MCP proxy — full client **and** server over stdio, SSE, streamable HTTP | §6A, §11 | Round-trips real servers (postgres, github, filesystem reference servers); agent config change is the only integration step |
| Auto-discovery of tool schemas; per-server identity | §11 | `provio proxy` enumerates tools and attributes every call to a server identity |
| Credential injection at dispatch (agent never holds tokens) | §11 | Secret exists only in Provio's store; red team test: dump agent context, find no token |
| MCP scanner integration (external scanner verdict → policy input `server.trust`) | §11 | `when server.trust == "unverified"` rule fires in e2e test. **Do not build a scanner — integrate one.** |
| Process wrap: Landlock + seccomp (Linux), Seatbelt (macOS), restricted tokens + job objects (Windows) | §6B | Kernel-level deny of out-of-workspace writes and non-allowlisted egress, verified by syscall-level tests on all three OSes |
| SDK hooks: LangGraph, OpenAI Agents SDK, Claude Agent SDK | §6C, §17 | Each adapter intercepts a named tool call with typed args in its native test suite |
| `provio doctor` coverage report — states exactly which call paths are covered/blind | §6 | Output lists covered channels and **loudly** flags MCP-proxy-only bypass risk (spec §15) |

### 3.2 Policy
| Feature | Spec | Acceptance |
|---|---|---|
| Native readable DSL (`provio.yaml` as in spec §7), four verdicts: `allow` `deny` `ask` `redact` | §7 | All spec example rules compile and fire against fixtures |
| Fail-closed default (`default: ask`), `--yolo` flips to allow | §7 | Unmatched call → ask (interactive) / deny-or-OOB (headless) |
| Structured denials: rule id + reason + `provio.yaml:line` returned to the model | §7, §12 | Agent receives self-correcting refusal, never "denied by policy" |
| Hot-reload of policy file | §7 | Edit during a run takes effect without restart; reload failure keeps last-good policy |
| `irreversible: true` marking, `timeout` on ask | §7 | Irreversible calls excluded from automated replay; headless timeout fails closed |
| Rego engine backend (WASM-compiled evaluator allowed) | §7, §8 | Same fixtures, same verdicts as native engine |
| Cedar engine backend | §7 | Same fixtures, same verdicts |
| `provio policy test` — rules vs recorded fixtures | §7 | CI-style pass/fail with per-rule diffs |
| `provio policy add <pack>` — community packs w/ checksum verification; starter packs: `terraform-safety`, `k8s-prod`, `pii-redaction` | §7, §19 | Pack install verifies checksum; each starter pack ships with tests |

### 3.3 Provenance Ledger (the differentiator)
| Feature | Spec | Acceptance |
|---|---|---|
| Append-only hash-chained records: call, args, caller identity, session, verdict, rule, approver, backend, exit status, I/O hashes, prev-hash | §9 | `provio verify` reports exact break index on a tampered fixture |
| SQLite WAL (workstation) **and** Postgres + object storage (cluster) | §9, §14 | Same record format both stores; cluster backend passes same verify suite |
| Local-first, **no content capture by default** (hashes + metadata only), **zero product telemetry (absent, not opt-out)** | §9, §20 | Network trace of a full run shows no Provio-originated egress; content only appears when explicitly enabled |
| `provio log`, `provio show <call-id>` | §2, §9 | Human-readable session answers "what did my agent do last night" |
| `provio report` — shareable single-file HTML run summary | §9 | Opens offline, self-contained, screenshot-worthy |
| Sigstore keyless signed run receipts | §9 | `provio verify --receipt` validates a CI run's signature offline |
| External anchor: push signed receipt to transparency log / periodic export to append-only storage | §9 | Anchor configured → tamper-*proof* path demonstrated; docs state tamper-evident vs tamper-proof distinction verbatim |

### 3.4 Sandbox Delegation
`SandboxBackend` trait = `prepare / exec / collect / teardown` (§8). Adapters shipped separately from core, detected if present (§12 correction).
| Backend | Primitive | Acceptance |
|---|---|---|
| `local-os` (default) | Landlock+seccomp / Seatbelt / restricted tokens | 30-second quickstart, no daemon, no images |
| `docker` | cgroups v2 + namespaces | Runs in a user-supplied image; optional, detected |
| `microsandbox` | libkrun microVM | Hardware isolation locally |
| `e2b` / Firecracker | KVM microVM | Hostile/multi-tenant workload demo |
| `k8s` | kubernetes-sigs/agent-sandbox (gVisor/Kata) | Sidecar exec offload in a Kind cluster e2e |
| Reproducible benchmark suite | §8 | Published benches per backend in repo — **no prose latency claims anywhere** (claim discipline, §7/§8) |

### 3.5 Record & Replay (honest version only)
| Feature | Spec | Acceptance |
|---|---|---|
| Deterministic replay of recorded I/O + cached model provider | §10 | Re-run produces identical trajectory, zero side effects |
| Policy replay: candidate `provio.yaml` vs last N runs — "would have blocked 3 calls" | §10 | Output diff of verdict changes; **this is the platform-team trust feature** |
| Guarded branching: re-branch from step N; irreversible steps refused by default, explicit ack flag to override | §10 | Default posture is refusal; ack is logged to the ledger |

### 3.6 TUI & DX
Approval gate hero screen (exact command / file range / SQL diff; `[a]llow [d]eny [e]dit [!] always allow`), live call tree with verdict badges, cross-provider cost/token meter, rule-naming errors (§12). The §16 demo screen is reproduced pixel-faithfully as the README hero.

### 3.7 Observability
OTel **GenAI semantic conventions** (`invoke_agent → chat → execute_tool` + MCP attributes), pinned convention version, policy decisions as span events, OTLP export to any backend; regex PII/secret masking **opt-in only**, documented as defence-in-depth (§13).

### 3.8 Deployment Topologies (all three)
Workstation: static binaries (macOS arm64/x86_64, Linux glibc+musl arm64/x86_64, Windows), `brew` / `npx` / `curl | sh`. CI: GitHub Action — headless, `ask` → fail-closed or out-of-band approver, signed receipt as build artifact. Cluster: Helm chart, sidecar-per-pod or shared gateway, Postgres/S3 ledger, SSO (SAML/OIDC) + SCIM, RBAC over policies and approvals, per-agent non-human identity with delegated actor claims, SIEM/Splunk/Kafka export, Vault/KMS, air-gapped install, data-residency control (§14, §20).

### 3.9 Supply Chain & Governance (built, not promised)
Apache-2.0; SBOM (SPDX **and** CycloneDX) per release; Sigstore/cosign keyless-signed artifacts + provenance; OpenSSF Scorecard published; `SECURITY.md` with response SLA; DCO; `THREAT_MODEL.md` from first commit (verbatim spec §15 table incl. explicit out-of-scope: prompt injection not solved, no model-layer safety, malicious operator out of scope, no side-effect reversal); control mapping to NIST AI RMF + ISO 42001; EU AI Act evidence packs. **No "BANK GRADE" labels, no SOC 2 claims, no unbenchmarked performance numbers, anywhere, ever.**

### 3.10 Explicitly NOT built (spec-mandated exclusions)
Context engine/pruning; bespoke telemetry schema; WASM tool-execution driver (structurally impossible — WASI has no fork/exec); A2A recursive sub-agent spawning (spec-deferred); an MCP scanner (integrate, don't build); web UI / accounts / cloud (no fixed date, possibly never).

## 4. Final-State Architecture & Frozen Contracts

### 4.1 Repository layout (spec §18, finalized)
```
provio/
├── crates/
│   ├── provio-core/        interception → decision → dispatch pipeline (orchestrates traits below)
│   ├── provio-policy/      PolicyEngine trait + native DSL parser/evaluator + decision IR
│   ├── provio-policy-rego/ Rego backend (WASM evaluator)
│   ├── provio-policy-cedar/ Cedar backend
│   ├── provio-mcp/         MCP client/server proxy, schema discovery, credential injection
│   ├── provio-sandbox/     SandboxBackend trait + local-os adapter (per-OS modules)
│   ├── provio-sandbox-docker/  provio-sandbox-microsandbox/  provio-sandbox-firecracker/  provio-sandbox-k8s/
│   ├── provio-ledger/      record schema, hash chain, SQLite + Postgres stores, verify, receipts, anchors
│   ├── provio-replay/      recorded-I/O replay, policy replay, guarded branching
│   ├── provio-otel/        GenAI semantic-convention emitter
│   ├── provio-tui/         approval gate, live call tree, cost meter
│   └── provio-cli/         run · proxy · log · show · verify · replay · policy test/add · doctor · report
├── adapters/             langgraph (py) · agents-sdk (py) · claude-agent-sdk (ts) · native hooks
├── packs/                terraform-safety · k8s-prod · pii-redaction (+ registry format)
├── examples/             provio.yaml per stack
├── deploy/               helm/ · action/ · terraform/ · airgap/
├── docs/                 THREAT_MODEL.md · SECURITY.md · policy-reference.md · INTERFACES.md · ADRs
└── .github/              CI matrix · scorecard · cosign · release
```

### 4.2 The five frozen contracts (Wave 0 deliverables — nothing starts until these merge)
These are the only cross-agent coordination surface. Each lives in `docs/INTERFACES.md` **and** as Rust traits/schemas in code.

1. **`ToolCall` envelope** (interceptors → core): `call_id, session_id, caller_identity, mode (mcp|wrap|sdk), tool, args (JSON), server_identity?, trust_verdict?, captured_at`. Blind-spot metadata included so `doctor` can report coverage.
2. **`PolicyEngine` trait + decision IR**: `load(policy_bytes) → CompiledPolicy`; `evaluate(&ToolCallContext) → Verdict`. `Verdict = Allow | Deny{rule_id, reason, location} | Ask{rule_id, diff, timeout, irreversible} | Redact{patterns}`. All three engines must produce identical verdicts on the shared fixture corpus (`crates/provio-policy/fixtures/`).
3. **`LedgerRecord` schema v1** (versioned, additive-only forever): fields per §9 + `schema_version`, `prev_hash`, `record_hash`. Golden fixtures committed; `provio verify` must validate v1 records for the life of the project.
4. **`SandboxBackend` trait**: `prepare(spec) → Handle`; `exec(handle, ApprovedCall) → Execution`; `collect(handle) → Outputs{stdout, stderr, files, exit}`; `teardown(handle)`. Latency instrumentation hooks included from the start (for the published benchmark suite).
5. **`Approver` trait** (ask-verdict plumbing): TUI approver (workstation), out-of-band approver (CI webhook), RBAC-checked approver (cluster). Headless timeout → fail closed, always recorded with approver identity.

### 4.3 Data-flow invariants (enforced by provio-core, tested by QA agent)
- Every intercepted call produces **exactly one** ledger record, including denials and redactions (redactions record a hash of the original, §7).
- No call reaches a sandbox backend without an `Allow` (or human-approved `Ask`) verdict.
- Credential material exists only inside provio-mcp's injection path; it is never serializable into a `ToolCall` or ledger record (compile-time `secrecy::SecretString`-style types, reviewed by security agent).
- Policy hot-reload is atomic: a parse failure keeps the last-good compiled policy and logs the error with file:line.

## 5. Multi-Agent / Multi-Model Orchestration

### 5.1 Model tiers (map to whatever frontier/mid/cheap models are available at run time)
| Tier | Class (examples) | Effort | Spend policy |
|---|---|---|---|
| **T1 — Frontier** | Claude Opus-class / GPT-5-pro-class | High reasoning | Security boundaries, crypto chaining, kernel sandboxing, protocol correctness, architecture, adversarial review. **Nothing else.** |
| **T2 — Mid** | Claude Sonnet-class / GPT-5-class | Medium | Standard crate implementation, TUI, replay, OTel, container backends, CI/deploy logic, SDK adapters |
| **T3 — Economy** | Haiku-class / mini-class | Low | Boilerplate, fixtures, docs, examples, policy packs, test scaffolding, SBOM/CI plumbing, formatting |

### 5.2 Agent roster (16 agents)
| Agent | Owns | Tier | Why this tier |
|---|---|---|---|
| **A0 Architect/Orchestrator** | INTERFACES.md, ADRs, workspace scaffold, cross-agent review, merge arbitration | T1 | Contract mistakes compound across every agent |
| **A1 Policy-Native** | DSL parser/evaluator, verdict IR, hot-reload, `policy test` | T1 (parser+semantics) | Parser of untrusted input on the security path; fail-closed semantics must be exact |
| **A2 Policy-Rego/Cedar** | provio-policy-rego, provio-policy-cedar | T2 | Well-bounded adapter work against the frozen IR; WASM-Rego compile step escalates to T1 if blocked |
| **A3 Ledger** | provio-ledger: schema, hash chain, SQLite+Postgres, verify, receipts, anchors | T1 | Evidentiary correctness is the product's core promise |
| **A4 MCP Proxy** | provio-mcp: stdio/SSE/HTTP, discovery, credential injection, scanner-verdict input | T1 | Protocol correctness + credential handling on the security path |
| **A5 Sandbox-Linux** | Landlock + seccomp adapter | T1 | Kernel security boundary; unsafe-adjacent |
| **A6 Sandbox-macOS** | Seatbelt adapter | T1 | Same |
| **A7 Sandbox-Windows** | Restricted tokens + job objects | T1 | Same; historically the leakiest platform |
| **A8 Sandbox-Backends** | docker, microsandbox, firecracker/e2b, k8s adapters + benchmark suite | T2 | Trait-driven integration of existing SDKs |
| **A9 TUI** | Approval gate, call tree, cost meter, §16 demo screen | T2 | Craft-heavy UX but no security boundary |
| **A10 Replay** | provio-replay: I/O replay, policy replay, guarded branching | T2 | Deterministic logic against frozen ledger schema |
| **A11 Observability** | provio-otel GenAI emitter, opt-in PII masking | T3→T2 | Convention-following; pin spec version, map fields |
| **A12 CLI/Doctor/Report** | provio-cli verbs, coverage report, HTML report | T2 (report) / T3 (verb plumbing) | Mostly wiring to frozen traits |
| **A13 Enterprise** | Helm, sidecar/gateway, SSO/SCIM/RBAC, SIEM export, Vault/KMS, air-gap | T2 (impl) + T1 (RBAC/SSO design review) | Authz design review is T1; the rest is integration |
| **A14 DevOps/Supply-chain** | CI matrix, release, cosign, SBOM, scorecard, brew/npx/curl distribution | T3 | Config plumbing; escalates signing-key design to T1 |
| **A15 Docs/Packs/Examples** | README (spec §18 order), policy-reference, packs, examples, comparison table | T3 | Writing to a spec; hero demo copy reviewed by A0 |
| **A16 QA/Security** | Fuzz targets, e2e suites, adversarial review, claim-discipline lint | T1 (review) / T3 (test generation) | Adversarial reading of security code is frontier work; test volume is not |

### 5.3 Escalation & routing rules
- A task starts at its assigned tier. **Two failed attempts → escalate one tier.** A T1 task completed cleanly may be *downgraded* for follow-up polish.
- A0 reviews and approves every cross-crate PR touching a frozen contract; A16 reviews every PR in provio-policy, provio-ledger, provio-mcp, and all sandbox kernel adapters.
- One agent never edits another agent's crate. Cross-crate needs go through A0 as a contract change request.

## 6. Token-Efficiency Operating Protocol

How the multi-agent program avoids wasting tokens — enforced by A0:

1. **Contract-first context.** Every agent receives: its crate spec, the relevant frozen contracts, and its acceptance tests — *not* the whole spec or the whole repo. INTERFACES.md is the shared context; nothing else is.
2. **Tests as the brief.** Acceptance tests are written (or scaffolded by T3) before implementation, so the implementing agent iterates against `cargo test` instead of against conversation. Test pass = task done; no long review threads.
3. **Diff-only editing.** Agents edit by patch against known file states, never re-emit whole files. File reads are line-ranged, never whole-crate dumps.
4. **Volume work to T3 by construction.** Fixtures, golden files, doc pages, pack YAML, CI YAML, and example projects are enumerated as checklists and batch-generated in single T3 runs.
5. **No redundant exploration.** A0 maintains `docs/DECISIONS.md` (append-only ADR log). Agents cite ADRs instead of re-deriving rationale. Blocked agents post a question to A0 rather than exploring adjacent crates.
6. **Fuzz/bench loops are local.** A16 runs fuzzers and criterion benches as commands and only escalates *findings*, not raw output.
7. **One-shot prompts.** Every task prompt is self-contained (goal, contracts, files owned, acceptance command, escalation rule) so no task needs multi-turn discovery to start.
8. **Claim discipline lint (cheap, automated).** A CI grep blocks forbidden phrases ("bank grade", "sub-millisecond", "tamper-proof" without anchor qualification, "prevents prompt injection") — enforcement by tooling, not by review tokens.

## 7. Execution Waves (dependency-ordered, internally parallel)

> Waves overlap: a wave starts when its *contract dependencies* merge, not when the previous wave fully finishes.

### Wave 0 — Foundation (week 0). Agents: A0 (+A14 for plumbing). Tier: T1.
- [ ] Reserve names: GitHub org, crates.io `provio`, npm `provio`, provio.dev/provio.sh, trademark search (spec §2) — **day 1, before code**
- [ ] Cargo workspace scaffold, crate skeletons, `cargo deny`/`audit`/clippy/fmt CI baseline (T3)
- [ ] **INTERFACES.md + the five frozen contracts in code** with compile-only stub impls (T1)
- [ ] Ledger `schema_version=1` + policy DSL grammar + ADRs 001–005 (T1)
- [ ] THREAT_MODEL.md (spec §15 verbatim), SECURITY.md, DCO, Apache-2.0 headers (T3)
- **Exit:** workspace compiles; stub pipeline passes a fixture `ToolCall` end-to-end with a hardcoded `Allow`.

### Wave 1 — Core spine (parallel). Exit: the §16 demo works against real MCP servers with the native engine.
| Task | Agent | Tier |
|---|---|---|
| Native DSL parser + evaluator + 4 verdicts + hot-reload + fixture corpus | A1 | T1 |
| Hash-chained ledger, SQLite WAL, `log`/`show`/`verify` | A3 | T1 |
| MCP proxy (stdio first, then SSE/HTTP), schema discovery, credential injection | A4 | T1 |
| CLI verbs: `run`, `proxy`, `log`, `show`, `verify` + `local-os` exec passthrough | A12 | T2 |
| TUI approval gate + live call tree (the §16 screen, exact) | A9 | T2 |
| Three starter rules + example provio.yaml files | A15 | T3 |

### Wave 2 — Coverage & trust (parallel). Exit: launchable product (spec §16 exit criterion achievable).
| Task | Agent | Tier |
|---|---|---|
| Process wrap: Landlock+seccomp / Seatbelt / restricted tokens (three parallel tracks) | A5/A6/A7 | T1 |
| `provio doctor` coverage/blind-spot report | A12 | T2 |
| docker + microsandbox backends; published benchmark harness | A8 | T2 |
| Replay trio: I/O replay, policy replay, guarded branching | A10 | T2 |
| OTel GenAI emitter + opt-in masking; `provio report` HTML | A11/A12 | T3/T2 |
| `policy test`; cost/token meter | A1/A9 | T2 |
| Cross-platform release pipeline: 6 binary targets, brew/npx/curl-sh, cosign + SBOM + scorecard | A14 | T3 |
| README (spec §18 order, hero GIF of the approval gate), docs, comparison table | A15 | T3 |

### Wave 3 — Team & org (parallel). Exit: full enterprise checklist (spec §20) demonstrable.
| Task | Agent | Tier |
|---|---|---|
| Rego + Cedar engines vs shared fixture corpus | A2 | T2 |
| SDK hooks: LangGraph, OpenAI Agents SDK, Claude Agent SDK adapters | A11* | T2 |
| GitHub Action (headless, OOB approver, signed receipt artifact) | A14 | T3 |
| Postgres + object-store ledger; transparency-log anchor | A3 | T1 (anchor) |
| Helm chart, sidecar/gateway, k8s agent-sandbox + firecracker/e2b backends | A13/A8 | T2 |
| SSO (SAML/OIDC) + SCIM, RBAC, per-agent identity, SIEM/Kafka export, Vault/KMS, air-gap install | A13 | T2 + T1 design review |
| Policy-pack registry w/ checksums; `terraform-safety`, `k8s-prod`, `pii-redaction` packs | A15 | T3 |
| NIST AI RMF / ISO 42001 / EU AI Act evidence-pack generator (extends `provio report`) | A12 | T2 |

### Wave 4 — Hardening & launch. Exit: release candidate.
- [ ] A16: fuzz policy parser, MCP codec, ledger import; `cargo miri` on unsafe; adversarial review of every security-path crate; e2e suite across the OS matrix and all interception modes (T1 review / T3 generation)
- [ ] A8: publish reproducible backend latency benchmarks (replaces all prose numbers)
- [ ] A0: full claim-discipline pass on README/docs; verify every "does not do" statement (§4, §15) is present
- [ ] A15: launch assets — demo GIF, Show HN post, single coordinated launch-day plan (spec §19: Tue–Thu, early-mid UTC afternoon)
- [ ] A14: signed v1.0.0 release on all channels

## 8. Quality Gates

| Gate | Applies to | Standard |
|---|---|---|
| Unit + golden-fixture tests | every crate | Policy engines: identical verdicts across native/Rego/Cedar on the shared corpus. Ledger: tamper fixtures must break `verify` at the reported index |
| Coverage | provio-policy, provio-ledger, provio-mcp, sandbox kernel adapters | ≥90% line coverage on security-path crates; enforced in CI |
| Fuzzing | DSL parser, MCP codec, ledger record decode, policy-file hot-reload | cargo-fuzz targets in CI (nightly cron), crashes block release |
| Unsafe audit | any `unsafe` | Justification comment + miri run + A16 sign-off |
| E2E matrix | interception modes × OS × sandbox backends | Real agent (Claude Code) + real MCP servers (postgres/github/filesystem) in GitHub Actions + Kind cluster |
| Supply chain | every release | cosign keyless signature + provenance, SPDX + CycloneDX SBOM, OpenSSF Scorecard ≥ current-category best, `cargo audit`/`deny` clean |
| Claim discipline | all user-facing text | Automated forbidden-phrase lint + A0 read-through before any launch artifact |
| Docs honesty | README, THREAT_MODEL | MCP-proxy-only bypass risk stated loudly; tamper-evident ≠ tamper-proof; prompt injection explicitly out of scope |

## 9. Risk Register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Name/org unavailable at registration | Med | High | Wave-0 day-1 action; backup names ready (Chancery, Assay, Custos, Ferrule) |
| OS sandbox parity gaps (Windows restricted tokens weakest) | High | High | A5–A7 start in Wave 2 with syscall-level deny tests; `doctor` reports residual blind spots honestly rather than hiding them |
| MCP spec drift | Med | Med | Pin protocol versions; conformance suite in CI; version-negotiation tests |
| OTel GenAI conventions still evolving | High | Low | Pin a convention version, document it (spec §13); isolate mapping in provio-otel only |
| Rego-in-WASM evaluator complexity | Med | Med | Frozen IR insulates the rest; fallback: subprocess `opa` eval behind the same trait, flagged in docs |
| Ledger schema regret | Low (if Wave 0 holds) | Severe | Frozen v1 + additive-only rule + golden fixtures + verify-forever test |
| Approval-gate fatigue UX | Med | Med | Precise diffs, `always-allow-this-rule`, `ask` kept rare by starter-rule tuning |
| Cluster scope creep sinks the core | Med | High | Wave-2 exit (launchable product) is gated before Wave-3 polish continues; §16 screen is untouchable after A9 ships it |
| Crowded-category launch fizzle | Med | Med | Fair comparison table, report-artifact virality, pack flywheel, coordinated single-day launch (spec §19) |

## 10. Definition of Done

**Per crate:** acceptance tests green; clippy `-D warnings`; fmt; docs.rs-quality rustdoc on public traits; no forbidden claims; owner agent + A16 (if security-path) sign-off.

**Per wave:** wave exit criterion met in CI, demoed live by A0, DECISIONS.md updated.

**Program-level (all-at-once complete):**
1. `npx provio run -- claude` reproduces the spec §16 screen exactly on macOS, Linux, and Windows.
2. Same `provio.yaml` governs the same workload in workstation, CI (GitHub Action, signed receipt artifact), and cluster (Helm, Kind e2e) — the spec §3 "three together" gap, demonstrated.
3. `provio verify` validates the ledger; a tampered copy fails at the exact index; anchored run receipt validates offline via Sigstore.
4. Every §20 enterprise-checklist item is either shipped or is a documented, honest exclusion.
5. A new user goes from install to enforced policy in ≤30 seconds (spec §8 local-os goal).

## 11. Agent Kickoff Prompt Template (per task)

```
ROLE: You are agent <A#> on the Provio project (<one-line product>).
CONTEXT: Read only: docs/INTERFACES.md §<relevant contracts>, docs/DECISIONS.md,
         and your owned paths: <paths>. Do not read other crates.
TASK: <single deliverable> per PROVIO_MASTER_BUILD_PLAN.md §<ref>.
ACCEPTANCE: <exact command, e.g. cargo test -p provio-policy --all-features> must pass.
RULES: Edit only owned paths. No performance/security claims in text or comments
       (see claim-discipline list in docs/). Fail-closed on any ambiguity in
       security semantics — post a decision request, do not guess.
ESCALATION: Two failed test-fix iterations → stop and report the blocker with
            a minimal repro; do not keep burning attempts.
```

## 12. Immediate Next Actions

1. **Wave 0, day 1:** name/org/domain registration check (spec §2 verification list).
2. A0 drafts INTERFACES.md + ADR-001..005 (T1).
3. A14 scaffolds workspace + CI (T3) in parallel.
4. On contract merge: launch Wave 1 agents A1/A3/A4 (T1) and A9/A12 (T2) simultaneously.

*Plan generated from Provio Technical Specification v2.0. All scope decisions trace to the spec; the only deliberate deviation is the removal of market phasing, requested by the project owner, with launchability preserved via the early Wave-2 demo gate.*


---

### Appendix — Traceability: Spec Section → Plan Section

| Spec § | Plan § |
|---|---|
| §1 Executive summary / cuts | §3.10 exclusions honored |
| §2 Name & brand | §2 Q4, Wave 0 day-1, §9 risk |
| §3 Market gap | §10 program criterion #2 (three-together demo) |
| §4 Product definition | §3, §8 docs-honesty gate |
| §5 Architecture / Rust | §4.1–4.3 |
| §6 Interception modes | §3.1, Wave 1–2 |
| §7 Policy model | §3.2, §4.2 contract 2, A1/A2 |
| §8 Sandbox delegation | §3.4, §4.2 contract 4, A5–A8 |
| §9 Ledger | §3.3, §4.2 contract 3, A3 |
| §10 Record & replay | §3.5, A10 |
| §11 MCP integration | §3.1, A4 |
| §12 TUI & DX | §3.6, A9 |
| §13 Observability | §3.7, A11 |
| §14 Deployment | §3.8, Waves 2–3 |
| §15 Threat model | §3.9, §8, Wave 0 |
| §16 v0.1 demo | Wave 2 exit gate |
| §17 Roadmap | Replaced by §7 (dependency waves) |
| §18 Repo & README | §4.1, A15 |
| §19 Adoption | Wave 4 launch tasks |
| §20 Enterprise checklist | §3.9, Wave 3, §10 #4 |
| App. A open questions | §2 (all four decided) |

