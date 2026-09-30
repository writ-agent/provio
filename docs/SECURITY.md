# Security Policy

## Reporting a vulnerability

Report suspected vulnerabilities privately via **GitHub private vulnerability
reporting** (writ-agent/provio → Security → Report a vulnerability), or by email
to **gurrambhaskar.ai@gmail.com**.
Do not open a public issue for security reports.

## Response SLA

| Stage | Commitment |
|---|---|
| Acknowledgement | within 72 hours |
| Initial triage and severity assessment | within 7 days |
| Fix or mitigation plan | within 30 days for critical severity |

## Scope

In scope: the `provio` binary, all crates in this repository, the policy
engine, the ledger, the MCP proxy, and sandbox adapters. The threat model —
including explicit exclusions (prompt injection, model-layer safety,
malicious operator, side-effect reversal) — is in
[docs/THREAT_MODEL.md](THREAT_MODEL.md).

## Supply chain commitments

- Apache-2.0, permanently. The core will never be relicensed.
- Releases are Sigstore keyless-signed with provenance attestations.
- Every release ships an SBOM (SPDX and CycloneDX).
- OpenSSF Scorecard results are published.
- Contributions use DCO sign-off (`Signed-off-by`), not a CLA.
