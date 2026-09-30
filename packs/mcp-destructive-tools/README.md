# mcp-destructive-tools

Human gates on MCP tools that delete data, share it, change who can reach
it, revoke credentials, or run shell commands, on any MCP server except
GitHub (`github-safety` covers GitHub). The rules read only the tool name
and the server identity, so they work for servers provio has never seen:

```yaml
version: 1
default: allow        # or ask
packs: [floor, mcp-destructive-tools]
```

| Rule | Verdict | Covers |
|---|---|---|
| `mcp-exec-tool-asks` | ask | tools that run a shell command or process: `execute_command`, `run_command`, `runCommand`, `start_process`, `interact_with_process` (Desktop Commander), `shell`, `terminal`, `run_script`, `ssh_exec`/`ssh_execute`, any `exec` token (`pods_exec`, `exec_in_pod`, `docker_exec`); `exec_sql`-style SQL tools are left to `database-safety` |
| `mcp-sharing-permission-asks` | ask | `share_*`, `unshare_*`, `grant_*`, `make_public`, and add/create/update/set/remove/transfer of `permission`, `sharing`, `acl`, `collaborator`, `access`, `owner(ship)`, `role_binding`, `iam_policy` (`share_file`, `create_permission`, `addCollaborator`, `update-file-permissions`); not `create_access_token`/`access_key` |
| `mcp-credential-change-asks` | ask, irreversible | `revoke*`, and rotate/roll/regenerate/reset/invalidate of keys, tokens, secrets, credentials, passwords, certificates, sessions |
| `mcp-destructive-tool-asks` | ask, irreversible | `delete`, `destroy`, `purge`, `truncate`, `wipe`, `erase`, `drop`, `remove`, `rm`, `rmdir`, `unlink`, `del`, `flushall`/`flushdb`, `empty_trash`, `reset_branch`/`reset_database`, as a whole token anywhere in the name: `delete_file`, `delete_entities`, `jira_delete_issue`, `API-delete-a-block`, `deleteConfluencePage`, `TwilioApiV2010--DeleteMessage`, `r2_bucket_delete`, `drop_collection` |
| `mcp-trash-tool-asks` | ask | `trash_*`, `*_trash`, `move_to_trash` (restorable until the trash is emptied) |

**Name matching.** The verb must be a whole token in snake_case,
kebab-case or camelCase: `list_deleted_files`, `undelete_file`,
`select_dropdown_option` and `uploadToSharePoint` do not match. A tool
whose first token is a read verb (`get`, `list`, `search`, `find`,
`describe`, `read`, `fetch`, `query`, `view`, `show`, `preview`,
`retrieve`, `export`, ...) or a restore verb (`undo`, `restore`,
`recover`, `untrash`) never matches, nor does a name ending in `_preview`
or `_dry_run`. Excluded on purpose: `remove_label`/`remove_tag`/
`remove_reaction`/`remove_background`, `purge_cache`/`clear_cache`,
`drag_and_drop`.

Every rule requires an MCP server identity, so an agent's built-in tools
(Cursor's `delete_file`, `fs.write`, `bash`) are not matched. For Claude
Code the server is the `<server>` in `mcp__<server>__<tool>`.

## What it deliberately does not cover

- **Which object a tool touches.** `delete_file` in a scratch directory
  and in production data ask alike; provio sees `path`, `url`, `query` and
  `command` arguments, not ids such as `issue_key` or `pageId`.
- **Tools whose names hide the action.** `update_page` with a "replace
  all content" argument, `batch_modify`, or a generic `make_api_request`
  (Square) / `call_api` tool are not matched.
- **Moves, renames and archives** (`move_file`, `rename_*`, `archive_*`):
  routine in most workspaces and recoverable, so they get your `default`.
- **Code interpreters and browsers** (`run_code`, `execute_python` in a
  hosted sandbox, `browser_evaluate`, `puppeteer_evaluate`): these run in
  a sandbox or a page, not on the host shell, and gating them would ask on
  nearly every call.
- **The command inside an exec tool.** Shell rules in provio packs (the
  floor included) match `tool == "bash"`; a command sent through
  `execute_command` is only gated by `mcp-exec-tool-asks`, not checked
  against the shell rules. Write your own rules on `command` without the
  `tool` condition if you need that.
- **SQL.** `drop_table` is gated here by name; SQL sent through `query`/
  `execute_sql` is `database-safety`'s job.
- **GitHub** servers: `github-safety`.

## Tests

`fixtures/mcp-destructive-tools.yaml` (45 cases): every rule on tool names
from real servers (filesystem, memory, Desktop Commander, Atlassian,
Notion, Twilio, Cloudflare, Supabase, Redis, Gmail, Google Drive, Kubernetes), plus
near misses that must not fire (`list_deleted_files`, `get_deleted_items`,
`undelete_file`, `delete_file_preview`, `drag_and_drop`, `remove_label`,
`purge_cache`, `rotate_image`, `uploadToSharePoint`, `create_access_token`,
`execute_sql`,
`move_file`, GitHub's `delete_file`, a built-in `delete_file` with no
server).
