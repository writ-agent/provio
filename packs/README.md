# Policy packs

A pack is a reusable set of `writ.yaml` rules for one risk area. Each pack
directory has a `pack.yaml` (`id`, `version`, `description`, `rules`), a
`README.md` saying what it covers and what it deliberately does not, and a
`fixtures/` directory that proves its verdicts with `writ policy test`.

| Pack | What it does |
|---|---|
| [floor](floor/) | **Start here.** The disaster floor: denies recursive deletes of `~` or `/`, disk wipes, force pushes to main, reading SSH/cloud keys, reverse shells, agents rewriting their own hook config or launching with `--yolo`-style flags; asks before database drops, cloud destroys, discarding uncommitted work, `curl \| sh` and persistence. Low-noise enough for every project. |
| [aws-safety](aws-safety/) | Denies audit-log tampering, Organizations changes, KMS key deletion, `s3 rb --force`; asks before IAM, S3, EC2, RDS and stack deletions and secret reads; allows read-only `describe/list/get`. |
| [gcp-azure-safety](gcp-azure-safety/) | The same for `gcloud`/`gsutil`/`bq` and `az` (plus Az / Google Cloud PowerShell): denies project deletion, Key Vault purge and audit-log deletion; asks before deletes, IAM/RBAC changes and secret reads; allows `list/describe/show`. |
| [github-safety](github-safety/) | Denies force pushes to protected branches, `push --mirror`, `gh repo delete`, branch-protection changes, `pr merge --admin`, `gh auth token`; asks before other force pushes, history rewrites, discarding work, secrets, releases, merges and GitHub MCP delete/merge tools; allows read-only `git`/`gh`. |
| [secrets-guard](secrets-guard/) | Denies reading SSH keys, cloud credentials, `.env`, key files, registry tokens and OS credential stores, plus credential-store commands, env dumps and egress of secret files; masks common token formats in read output. |
| [database-safety](database-safety/) | Asks before DROP, TRUNCATE, ALTER, and DELETE/UPDATE without WHERE through SQL MCP servers and database CLIs, plus `dropdb`, Redis/Mongo wipes and ORM resets; allows a single read-only SELECT. |
| [package-publish-guard](package-publish-guard/) | Asks before npm/pnpm/yarn, PyPI, crates.io, RubyGems, container-image, Helm, NuGet, Maven/Gradle and PowerShell Gallery publishes; denies npm unpublish/deprecate and ownership changes; allows dry runs. |
| [terraform-safety](terraform-safety/) | Asks before `terraform destroy`, `apply -auto-approve` and `state rm`; denies `force-unlock`. |
| [k8s-prod](k8s-prod/) | Denies `kubectl delete namespace`; asks before prod deletes, rollout restarts, exec and `drain`. |
| [pii-redaction](pii-redaction/) | Masks emails, AWS keys, private-key headers and SSN shapes in tool results (read its README about placement first). |

## Using a pack

Name bundled packs in your `writ.yaml`; every writ build ships them:

```yaml
version: 1
default: ask
packs: [floor, secrets-guard, github-safety]
rules:
  # your own rules
```

writ places each pack's rules around yours the way a careful hand-merge
would, so **placement is not your problem**:

1. The packs' **deny and ask** rules go first, in the order you list the
   packs, so a broad allow of yours cannot open them.
2. Your own `rules:` come next.
3. The packs' **allow** rules (read-only calls) go after yours, so your
   denies still win.
4. The packs' **redact** rules go last. `redact` runs the call and masks
   the output, so a redact rule also lets the calls it matches through
   without a prompt (see `secrets-guard` and `pii-redaction`).

Evaluation is first match wins. A decision from a pack rule names it as
its location (`pack:floor@0.1.0`), in the ledger and in the agent's
refusal. To decide one pack rule differently, leave it out and write your
own:

```yaml
packs:
  - floor
  - id: github-safety
    skip: [github-pr-merge-asks]
```

An unknown pack, a pack listed twice, or a `skip` naming a rule the pack
does not have is a policy error (writ refuses to load it).

To review or fork a pack instead, copy it out and merge its rules by hand
(then follow the same placement):

```bash
writ policy add aws-safety
# installed pack 'aws-safety' → .writ/packs/aws-safety.yaml
# sha256: …
```

Rule ids are prefixed per pack (`floor-`, `aws-`, `gcp-`/`az-`, `github-`,
`secrets-`, `db-`, `publish-`, `tf-`, `k8s-`), so several packs merge
without id collisions. Where two packs cover the same command (for example
`gh auth token`), the first one listed decides.

Packs match command text, paths, SQL, and MCP tool/server names; they
cannot see what a program does once it runs, which account a CLI resolves
to, or which database a URL points at. Each README lists its own gaps.

Check the merged result:

```bash
writ doctor --policy writ.yaml
writ policy test --policy writ.yaml --fixtures packs/<id>/fixtures
```

A pack's fixtures are written against the pack alone under `default: ask`;
cases that expect `rule_id: default` can differ once your own rules sit in
front of them.

## Validating packs (CI)

`python scripts/validate_packs.py [--writ path/to/writ]` compiles every
pack (wrapped in `version: 1` / `default: ask`) and every example policy,
requires each pack to have a `README.md` and `fixtures/`, runs each pack's
fixtures with `writ policy test`, and, where a pack ships
`redact-samples.yaml`, drives sample tool output through `writ check` to
prove what gets masked. The `packs` CI job runs it on every push.

## Write your own pack

See **Contribute a policy pack** in [CONTRIBUTING.md](../CONTRIBUTING.md),
and [docs/policy-reference.md](../docs/policy-reference.md) for the rule
language. In short:

1. Copy the closest existing pack (`aws-safety` for a CLI,
   `database-safety` for an MCP server, `secrets-guard` for paths and
   redaction) to `packs/<your-pack>/`.
2. Give every deny/ask a `reason` a human can act on, set
   `irreversible: true` where there is no undo, and prefix rule ids.
3. Write fixtures for each rule: a hit, a Windows or PowerShell variant
   where it applies, and near misses that must **not** match.
4. Write the README: what it covers, what it does not, where the rules go.
5. `python scripts/validate_packs.py` must pass.

Ideas waiting for an owner: [docs/launch/good-first-issues.md](../docs/launch/good-first-issues.md).
