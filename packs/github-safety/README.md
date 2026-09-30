# github-safety

Hard blocks and human gates for destructive git and GitHub operations: force
pushes to protected branches, `git push --mirror`, history rewrites,
discarding uncommitted work, destructive `gh` CLI calls, and the delete /
merge tools of a GitHub MCP server. Read-only `git` and `gh` inspection is
allowed when nothing else is chained onto it.

| Rule | Verdict | Covers |
|---|---|---|
| `github-push-mirror-denied` | deny | `git push --mirror` |
| `github-force-push-protected-denied` | deny | `--force`, `--force-with-lease`, `-f`, `+refspec` pushes naming `main`, `master`, `trunk`, `develop`, `prod`, `production`, `release*` |
| `github-repo-delete-denied` | deny | `gh repo delete` |
| `github-branch-protection-change-denied` | deny | `gh api` DELETE/PUT/PATCH/POST on `/branches/*/protection` or `/rulesets` |
| `github-pr-merge-admin-denied` | deny | `gh pr merge --admin` (bypasses required reviews) |
| `github-auth-token-denied` | deny | `gh auth token`, `gh auth status --show-token` |
| `github-force-push-asks` | ask, irreversible | any other force push (including bare `git push -f`) |
| `github-remote-ref-delete-asks` | ask, irreversible | `git push --delete`, `git push origin :ref` |
| `github-history-rewrite-asks` | ask, irreversible | `filter-branch`, `filter-repo`, `update-ref -d`, `replace`, `reflog expire --expire=now`, `gc --prune=now`, BFG |
| `github-discard-work-asks` | ask, irreversible | `reset --hard`, `clean -f…`, `checkout -- .`, `restore .`, `stash drop/clear`, `branch -D` |
| `github-secret-change-asks` | ask, irreversible | `gh secret/variable set/delete/remove` |
| `github-release-delete-asks` | ask, irreversible | `gh release delete / delete-asset` |
| `github-repo-settings-asks` | ask, irreversible | visibility / default-branch changes, archive, rename, `gh repo create --public` |
| `github-api-delete-asks` | ask, irreversible | `gh api -X DELETE …` |
| `github-pr-merge-asks` | ask | `gh pr merge` |
| `github-cli-delete-asks` | ask, irreversible | catch-all: `gh <noun> delete/remove` |
| `github-mcp-destructive-asks` | ask, irreversible | MCP server named `*github*`: tools `delete_*`, `remove_*`, `merge_*`, `cancel_*`, `archive_*`, `transfer_*`, `*_delete`, repository/branch-protection/secret updates |
| `github-mcp-read-allowed` | allow | MCP server named `*github*`: tools `get_*`, `list_*`, `search_*` |
| `github-git-read-only-allowed` | allow | anchored `git status/log/diff/show/blame/…`, `git branch -a`, `git remote -v`, … plus a narrow pipe tail (`\| head -n N`, `\| wc -l`, `\| grep PATTERN` with no file argument) |
| `github-gh-read-only-allowed` | allow | anchored `gh pr/issue/repo/run/release/… list/view/status/diff/checks`, `gh search …` |

**Protected branches** are a fixed list in
`github-force-push-protected-denied`; edit it to match your repository's
branch protection. `git log --output=FILE` is excluded from the read-only
allow because it writes a file.

## What it deliberately does not cover

- **Plain pushes** (`git push origin main` without force) and commits fall
  to your policy's `default`. Branch protection on GitHub is still the real
  control for direct pushes.
- **Local rebases and amends** are not gated; they only matter once
  force-pushed, which is covered.
- **MCP write tools** such as `push_files` / `create_or_update_file` get
  the policy default: provio sees the tool name, not the target branch
  argument.
- **Reading untrusted content.** `github-mcp-read-allowed` and `gh issue view`
  let the agent read issue and PR text written by anyone, which is a prompt
  injection path. Drop those allow rules if your agent works on public
  repositories with write credentials in reach.
- GitLab / Bitbucket CLIs (`glab`, `bb`) are not covered.

## Use it

Packs are rules you merge into your own `provio.yaml`; provio does not load
`.provio/packs/` automatically.

```bash
provio policy add github-safety   # bundled with provio (a local ./packs/<id> wins); prints the sha256
```

Paste the `rules:` entries into your `provio.yaml`: deny/ask rules above your
own broad allows, the allow rules below your own denies. If you also use
`secrets-guard`, its `gh auth token` deny overlaps with
`github-auth-token-denied`; either one is enough. Ids are prefixed `github-`.
The MCP rules match the server identity provio records, which for Claude Code
is the `<server>` in `mcp__<server>__<tool>`.

```bash
provio doctor --policy provio.yaml
provio policy test --policy provio.yaml --fixtures packs/github-safety/fixtures
```

Fixtures: `fixtures/github-safety.yaml` (49 cases, including near misses such
as `git push -u origin mainline-fix`, `git push --follow-tags`,
`git log | grep key ~/.ssh/id_rsa` and `git diff > changes.patch`).
