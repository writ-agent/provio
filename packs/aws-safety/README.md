# aws-safety

Hard blocks and human gates for destructive AWS operations issued through the
AWS CLI (`aws`, `aws.exe`, `aws.cmd`), AWS Tools for PowerShell cmdlets and
the common stack-teardown CLIs (CDK, SAM, Serverless, Copilot, Amplify).
Read-only `describe-*` / `list-*` / `get-*`, `s3 ls` and
`sts get-caller-identity` calls are allowed when nothing else is chained onto
them.

| Rule | Verdict | Covers |
|---|---|---|
| `aws-audit-logging-tamper-denied` | deny | CloudTrail stop/delete, GuardDuty, Config, Security Hub, Access Analyzer, Macie shutdown |
| `aws-organizations-denied` | deny | `organizations delete/leave/remove/close/detach/disable/deregister-*` |
| `aws-kms-key-deletion-denied` | deny | `kms schedule-key-deletion`, `Request-KMSKeyDeletion` |
| `aws-s3-force-remove-bucket-denied` | deny | `s3 rb --force`, `Remove-S3Bucket -DeleteBucketContent` |
| `aws-rds-delete-without-snapshot-denied` | deny | `rds delete-db-instance/cluster --skip-final-snapshot` or `--delete-automated-backups` |
| `aws-iam-delete-asks` | ask, irreversible | `iam delete-* / detach-* / remove-* / deactivate-*` |
| `aws-iam-privilege-change-asks` | ask | `put-*-policy`, `attach-*-policy`, trust-policy edits, `create-access-key`, login profiles |
| `aws-s3-delete-asks` | ask, irreversible | `s3 rm`, `s3 rb`, `s3 sync --delete`, `s3api delete-*` |
| `aws-s3-exposure-asks` | ask, irreversible | bucket policy / ACL / Block Public Access / website changes |
| `aws-ec2-terminate-asks` | ask, irreversible | `ec2 terminate-instances`, `Remove-EC2Instance` |
| `aws-rds-delete-asks` | ask, irreversible | any other `rds delete-db-*` |
| `aws-stack-teardown-asks` | ask, irreversible | `cloudformation delete-stack*`, `cdk destroy`, `sam delete`, `serverless remove`, … |
| `aws-secret-read-asks` | ask | calls that return secret values: `secretsmanager get-secret-value`, `ssm get-parameter --with-decryption`, `ecr get-login-password`, `sts assume-role`/`get-session-token`, `lambda get-function(-configuration)` (env vars), `kms decrypt`, … |
| `aws-powershell-remove-asks` | ask, irreversible | `Remove-/Unregister-/Revoke-/Reset-/Clear-` cmdlets of common AWS.Tools modules |
| `aws-destructive-verb-asks` | ask, irreversible | catch-all: any `aws <svc> delete-/terminate-/remove-/deregister-/purge-/destroy-/revoke-/reset-/detach-/disassociate-/disable-*` |
| `aws-read-only-allowed` | allow | anchored `aws [global flags] <svc> describe-/list-/get-*`, `s3 ls`, `configure list`, `sts get-caller-identity` |

Order matters (first match wins): the secret-reading `get-*` calls are asked
before the read-only allow can see them.

## What it deliberately does not cover

- **Other mutations** (`create-*`, `update-*`, `put-*` outside IAM/S3
  exposure, `ec2 stop-instances`, `s3 cp` uploads) have no rule here, so
  they get your policy's `default`. With the recommended `default: ask` they
  ask.
- **Which account or region.** provio sees the command text, not the
  credentials it resolves to. `--profile prod` is not treated differently
  from `--profile dev`; add your own rule if you need that.
- **SDK calls and scripts.** `python deploy.py` that calls boto3, or a
  Terraform/Pulumi apply, is invisible to command-text rules. Pair with the
  `terraform-safety` pack and your IAM permissions.
- **Line continuations between the service and the operation**
  (`aws ec2 \` newline `terminate-instances`) are not matched. Continuations
  after the operation are fine.
- `ecs describe-task-definition` and similar calls can also return
  environment variables; only the Lambda case is covered.

## Use it

Packs are rules you merge into your own `provio.yaml`; provio does not load
`.provio/packs/` automatically.

```bash
provio policy add aws-safety      # run from a checkout that contains packs/
                                # copies to .provio/packs/aws-safety.yaml and prints its sha256
```

Then paste the entries under `rules:` in `.provio/packs/aws-safety.yaml` into
the `rules:` list of your `provio.yaml`:

- put the **deny and ask** rules above any broad allow of your own (for
  example an "allow all bash in CI" rule), or those allows win first;
- keep `aws-read-only-allowed` **below** your own deny rules;
- rule ids are prefixed `aws-` so they do not collide with other packs.

Check the merged policy compiles and still behaves the way you expect:

```bash
provio doctor --policy provio.yaml
provio policy test --policy provio.yaml --fixtures packs/aws-safety/fixtures
```

The pack's fixtures assume `default: ask`; cases that expect
`rule_id: default` will differ if your policy's own rules match them first.

Fixtures: `fixtures/aws-safety.yaml` (41 cases: deny, ask, allow and near
misses such as `aws s3 ls && rm -rf ~/work` and `grep terminate-instances`).
