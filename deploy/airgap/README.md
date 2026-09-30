# deploy/airgap

Wave 3 air-gapped install bundle scaffold.

This directory does not yet contain a generated bundle. It defines what a future release bundle must include and how operators can verify it offline.

## Bundle contents

A release air-gap bundle should contain:

1. Provio container images for gateway and sidecar, exported as OCI archives.
2. Helm chart under `deploy/helm` plus pinned values examples.
3. Static Provio binaries for supported offline platforms.
4. Policy packs and checksums.
5. Database migration files for the Postgres ledger backend once Wave 3 storage lands.
6. Documentation: threat model, policy reference, enterprise deployment notes, and offline upgrade/rollback steps.
7. SBOMs and signatures/provenance material that can be verified without internet access using preloaded trust roots.
8. Optional object-store bootstrap examples for MinIO or an existing S3-compatible service.

## Offline verification expectations

- Verify archive checksums before import.
- Verify image digests after loading into the private registry.
- Verify SBOM/signature material against the organization-approved offline trust root.
- Run `provio verify` against sample and migrated ledgers before enabling production approvals.

## Honest exclusions in this scaffold

- SSO/SCIM, RBAC, SIEM/Kafka export, Vault/KMS wiring, and transparency-log anchoring are integration stubs until Wave 3 implementation is complete.
- Air-gap packaging does not make MCP-proxy-only mode bypass-resistant.
- Prompt injection remains out of scope; deployment controls only reduce blast radius and preserve evidence.
