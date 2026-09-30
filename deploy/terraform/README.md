# deploy/terraform

Wave 3 infrastructure scaffold for the cluster ledger target: Postgres plus object storage. No Terraform modules are shipped yet; this directory documents the intended interface so the implementation can be reviewed before credentials or state are introduced.

## Target architecture

- **Postgres** stores append metadata, indices, hashes, receipts, actor IDs, policy/version pointers, and verification checkpoints.
- **Object storage** stores immutable ledger payload objects and exported evidence bundles.
- **Optional transparency-log anchor** records periodic roots outside the primary trust boundary. Until this is configured, the ledger is tamper-evident inside the configured store, not tamper-proof.

## Expected module outputs

Future modules should produce values that can be mapped to the Helm chart Secret refs:

- `database_url` -> Secret `provio-postgres` key `database-url`
- `object_bucket` -> Secret `provio-object-store` key `bucket`
- `object_endpoint` -> Secret `provio-object-store` key `endpoint`
- `object_region` -> Secret `provio-object-store` key `region`
- `kms_key_id` -> Secret or config consumed by the Wave 3 KMS integration

## Security requirements for the future module

- Postgres TLS required outside a private single-cluster network.
- Least-privilege database role: append/read/verify tables only; no superuser.
- Object storage versioning/object-lock where available; deny public access.
- KMS-managed encryption for database storage, object storage, and backups where the target cloud supports it.
- Backups and retention policy documented with data-residency constraints.
- Terraform state must not contain long-lived database passwords or object-store access keys; prefer workload identity or external secret managers.

## Provider scope

Provider-specific modules are Wave 3 work items. Keep cloud claims honest: AWS S3/RDS, GCS/Cloud SQL, Azure Blob/Postgres, and MinIO/self-hosted targets should be separate examples, not a single universal module.
