# k8s-prod

Guardrails for `kubectl` against production clusters: namespace deletion is
refused; deletes, rollout restarts and `exec` whose command line mentions
`prod`/`production` ask; `kubectl drain` always asks.

| Rule | Verdict | Covers |
|---|---|---|
| `k8s-delete-ns-denied` | deny | `kubectl delete ns/namespace …` |
| `k8s-prod-delete-asks` | ask, irreversible | `kubectl delete …` with `prod`/`production` in the command |
| `k8s-prod-rollout-asks` | ask | `kubectl rollout restart …` with `prod`/`production` |
| `k8s-exec-prod-asks` | ask | `kubectl exec …` with `prod`/`production` |
| `k8s-drain-asks` | ask | `kubectl drain` |

## Known gaps

- Subcommands are matched anywhere after `kubectl` within one pipeline
  segment, so global flags before them (`kubectl --context prod delete …`)
  are caught; a verb that appears only inside a quoted argument can still
  match (a false ask, never a false allow).
- "Production" is detected by the words `prod`/`production` anywhere in the
  command, not from the active kube context. Commands run against the
  current context with no such word are not treated as production.
- No read-only allow rules: `kubectl get/describe/logs` get your default.
- `helm` is not covered (see the good-first-issue list).

## Use it

```bash
provio policy add k8s-prod   # bundled with provio (a local ./packs/<id> wins); prints the sha256
```

Paste the `rules:` entries into your `provio.yaml` above any broad allow of
your own, then `provio policy test --policy provio.yaml --fixtures
packs/k8s-prod/fixtures`. Fixtures: `fixtures/k8s-prod.yaml` (8 cases).
