# gcp-azure-safety

Hard blocks and human gates for destructive Google Cloud and Azure operations
issued through `gcloud` / `gsutil` / `bq`, `az`, and the Az and Google Cloud
PowerShell modules (Windows shells resolve `gcloud.cmd` and `az.cmd`; both
are matched case-insensitively). Read-only `list` / `describe` / `show` calls
are allowed when nothing else is chained onto them.

| Rule | Verdict | Covers |
|---|---|---|
| `gcp-project-delete-denied` | deny | `gcloud projects delete`, `Remove-GcpProject` |
| `gcp-audit-logging-tamper-denied` | deny | `gcloud logging sinks/buckets/views delete` |
| `az-keyvault-purge-denied` | deny | `az keyvault [secret\|key\|certificate] purge`, `Remove-AzKeyVault* -InRemovedState` |
| `az-audit-logging-tamper-denied` | deny | diagnostic settings, Log Analytics workspace, activity-log alert deletion |
| `gcp-storage-delete-asks` | ask, irreversible | `gsutil rm/rb`, `gsutil rsync -d`, `gcloud storage rm`, `buckets delete`, `bq rm` |
| `gcp-kms-destroy-asks` | ask, irreversible | `gcloud kms keys versions destroy/disable` |
| `gcp-iam-change-asks` | ask | IAM policy bindings, `set-iam-policy`, service-account key create/upload, custom roles |
| `gcp-secret-read-asks` | ask | `secrets versions access`, `auth print-access-token/print-identity-token`, `sql generate-login-token` |
| `gcp-delete-asks` | ask, irreversible | catch-all: any `gcloud … delete/destroy`, `Remove-Gce*/Gcs*/GcSql*/…` |
| `az-rbac-change-asks` | ask | role assignments/definitions, `ad sp create-for-rbac`, credential resets, `keyvault set-policy` |
| `az-secret-read-asks` | ask | `keyvault secret show/download`, `keys list`, connection strings, `get-access-token`, SAS generation, `Get-AzKeyVaultSecret -AsPlainText`, … |
| `az-group-delete-asks` | ask, irreversible | `az group delete`, `Remove-AzResourceGroup` |
| `az-delete-asks` | ask, irreversible | catch-all: any `az … delete/purge/delete-batch`, `Remove-Az*` |
| `gcp-read-only-allowed` | allow | anchored `gcloud … list/describe`, `config list`, `info`, `gsutil ls/du` |
| `az-read-only-allowed` | allow | anchored `az … list/show`, `account show/list`, `version` |

The two allow rules refuse any command that also carries a mutating verb
(`create`, `update`, `set`, `start`, `ssh`, `get-credentials`, …), so
`gcloud compute instances create list` is not waved through because it
contains the word `list`.

## What it deliberately does not cover

- **Other mutations** (`create`, `update`, `deploy`, `start/stop`,
  `gcloud run deploy`, `az webapp deploy`) have no rule here and get your
  policy's `default` (ask, with the recommended header).
- **Project / subscription targeting.** provio sees command text only, not
  which project or subscription the CLI will act on.
- **Firebase, Terraform, Pulumi, Bicep/ARM deployments** and SDK calls from
  scripts. See `terraform-safety` and the good-first-issue list for pulumi.
- `az rest` / `gcloud … --impersonate-service-account` requests are not
  inspected beyond the rules above.

## Use it

Packs are rules you merge into your own `provio.yaml`; provio does not load
`.provio/packs/` automatically.

```bash
provio policy add gcp-azure-safety   # bundled with provio (a local ./packs/<id> wins); prints the sha256
```

Paste the `rules:` entries into your `provio.yaml`: deny/ask rules above your
own broad allows, the two `*-read-only-allowed` rules below your own denies.
Ids are prefixed `gcp-` / `az-`.

```bash
provio doctor --policy provio.yaml
provio policy test --policy provio.yaml --fixtures packs/gcp-azure-safety/fixtures
```

Fixtures: `fixtures/gcp-azure-safety.yaml` (45 cases, including Windows
`gcloud.cmd`, PowerShell cmdlets, and near misses such as
`gsutil ls gs://acme/rm-reports/` and `az vm list -o tsv | sh`).
