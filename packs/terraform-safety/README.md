# terraform-safety

Human gates and one hard block for Terraform operations against real
infrastructure.

| Rule | Verdict | Covers |
|---|---|---|
| `tf-destroy-asks` | ask, irreversible | `terraform destroy` |
| `tf-apply-prod-asks` | ask, irreversible | `terraform apply … -auto-approve` |
| `tf-state-rm-asks` | ask, irreversible | `terraform state rm` |
| `tf-force-unlock-denied` | deny | any command containing `force-unlock` |

## What it does not cover

- `terraform apply` without `-auto-approve` gets your policy default (with
  `default: ask`, it asks). So do `plan`, `import` and `state mv`.
- `tofu` (OpenTofu) is covered, and global options before the subcommand
  (`terraform -chdir=infra destroy`) are caught; `apply -destroy` counts as a
  destroy. `terragrunt` and Terraform Cloud runs are not matched; see the
  good-first-issue list for `terraform-cloud` and `pulumi`.

## Use it

```bash
provio policy add terraform-safety   # bundled with provio (a local ./packs/<id> wins); prints the sha256
```

Paste the `rules:` entries into your `provio.yaml`, then `provio policy test
--policy provio.yaml --fixtures packs/terraform-safety/fixtures`. Fixtures:
`fixtures/terraform-safety.yaml` (6 cases).
