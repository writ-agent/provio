# ci-config-guard

Human gates on an agent changing CI/CD: editing pipeline definitions,
CODEOWNERS or dependency-bot configuration, and starting, re-running or
disabling pipelines. A pipeline runs with the repository's secrets and
deploy credentials, so a one-line workflow edit can send them elsewhere or
ship code without review. Editing CI is often the task itself, so these
ask; they do not refuse. Reading the files is never matched.

```yaml
version: 1
default: ask
packs: [floor, ci-config-guard]
```

| Rule | Verdict | Covers |
|---|---|---|
| `ci-actions-permissions-change-denied` | deny | `gh api` writes (`-X PUT/PATCH/POST/DELETE`, or `-f`/`-F`/`--field`/`--input`, which make gh POST) to `/actions/permissions*`, `/actions/runner-groups`, `/actions/oidc/customization`, `/environments/<name>`; any call to `/actions/runners/registration-token`, `remove-token`, `generate-jitconfig` |
| `ci-workflow-write-asks` | ask | file-tool writes (`fs.write`) to `.github/workflows/*.yml\|yaml`, `.github/actions/**`, `.gitlab-ci.yml`, `.gitlab/ci/*.yml`, `.circleci/**`, `Jenkinsfile`, `azure-pipelines.yml`, `.azure-pipelines/*.yml`, `.buildkite/**`, `bitbucket-pipelines.yml`, `.travis.yml`, `cloudbuild.yaml`, `.drone.yml`, `.woodpecker.yml` / `.woodpecker/*.yml`, `buildspec.yml`, `appveyor.yml`, `codemagic.yaml`, `.tekton/*.yml`; shell writes where one of these (or the `.github`, `.github/workflows`, `.circleci`, `.buildkite` directory) is the target |
| `ci-review-config-write-asks` | ask | the same for `CODEOWNERS` (any location), `.github/dependabot.yml`, `renovate.json(5)`, `.renovaterc` |
| `ci-pipeline-trigger-asks` | ask | `gh workflow run/enable/disable`, `gh run rerun/cancel`, `gh api …/dispatches` and `…/actions/runs/<id>/rerun\|cancel\|approve`, `glab ci run/retry/trigger/cancel`, `az pipelines run`, `az pipelines build queue` |

A shell write counts only when the CI file is its **target**: the last
argument of `rm`/`mv`/`cp`/`tee`/`install`/`ln`/`truncate` (and the
Windows `copy`/`move`/`del`), a `>` or `>>` redirect target (including
`cat > file <<EOF`), the file of `sed -i` / `perl -i` / `yq -i`, the
`-Path`/`-FilePath` of `Set-Content`/`Add-Content`/`Out-File`/`New-Item`,
the `-Destination` of `Copy-Item`/`Move-Item`, or the output of
`curl -o` / `wget -O`. `cat`, `grep`, `sed -n`, `actionlint` and
`cp .github/workflows/ci.yml /tmp/` do not match. `gh`, `glab` and `az` are
matched at the start of a pipeline segment or after `sudo`/`env`/`xargs`,
so `echo "gh workflow run …"` does not match.

## What it deliberately does not cover

- **Other ways a file changes.** `git checkout other-branch -- .github/`,
  `git apply`, `patch`, `tar x`, a script that writes the workflow, or an
  editor opened through the shell are not seen. provio's script inspection
  and, under `provio run`, the kernel write boundary are the backstop.
- **Pushing the edit.** A workflow edited outside the agent and pushed
  by it is a `git push`; see `github-safety`. `pull_request_target`
  workflows that run fork code are a repository setting, not a command.
- **Actions secrets and variables** (`gh secret set`, `gh variable set`)
  are in `github-safety` (`github-secret-change-asks`).
- **Other CI systems' APIs** (CircleCI, Buildkite, Jenkins CLI or REST
  triggers, `curl` to a webhook) are not matched as triggers.
- **Branch protection and rulesets** are in `github-safety`
  (`github-branch-protection-change-denied`).
- **Reads.** Reading a workflow never matches, including through `fs.read`.

## Tests

`fixtures/ci-config-guard.yaml` (49 cases): every rule, POSIX and Windows
paths, heredoc / `>>` / `sed -i` / `yq -i` / `tee` / `cp` / `rm -rf` /
`Set-Content -Path` / `curl -o` writes, and near misses that must not
match (`cat`, `sed -n`, `grep … > /tmp/x`, `cp` of a workflow to `/tmp`,
`actionlint … 2>&1`, `.github/workflows/README.md`, issue templates,
`gh api` GETs of permissions and environments, `gh workflow list`,
`gh run watch`, `glab ci status`, an `echo` naming `gh workflow run`).
