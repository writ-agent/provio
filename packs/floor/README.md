# floor

The disaster floor: the few things an AI agent must never do on its own,
whatever permission mode it runs in (auto, `--yolo`, "don't ask again").
Every rule names a disaster, not a style preference, so the pack is
low-noise enough to turn on everywhere:

```yaml
version: 1
default: allow        # or ask
packs: [floor]
```

With `packs:`, the floor's rules are placed **before** your own, so a broad
allow of yours (`tool == "bash"`) cannot open it. To decide one rule
differently, leave it out and write your own:
`packs: [{ id: floor, skip: [floor-shutdown-asks] }]`.

| Rule | Verdict | Covers |
|---|---|---|
| `floor-rm-home-or-root-denied` | deny | recursive `rm` of `/`, `~`, `$HOME`, `"$HOME"` (the [claude-code#88462](https://github.com/anthropics/claude-code/issues/88462) shape, including inside `trap '…'` and `sh -c '…'`), `/home/<u>`, `/Users/<u>`, system roots, top-level home folders (`~/Documents`, `~/.ssh`, …), drive roots and `C:\Users\<u>` |
| `floor-rm-no-preserve-root-denied` | deny | `rm --no-preserve-root` |
| `floor-windows-recursive-delete-denied` | deny | `Remove-Item -Recurse` / `rd /s` of a drive root, `C:\Windows`, the user profile |
| `floor-find-delete-home-or-root-denied` | deny | `find ~ … -delete`, `find / … -exec rm` |
| `floor-disk-and-system-wipe-denied` | deny | `mkfs`, `wipefs`, `diskpart`, `Format-Volume`, `dd of=/dev/sdX`, `> /dev/nvme0n1`, `shred /dev/…`, `format C:`, fork bombs, `chmod/chown -R` of `/` or `~`, `kill -9 -1` |
| `floor-force-push-main-denied` | deny | `--force`, `-f`, `--force-with-lease`, `+main` pushes to `main`/`master` |
| `floor-private-keys-denied` | deny | reading SSH private keys, `~/.aws/credentials`, gcloud credentials (file tools, and `cat`/`cp`/`curl`/`scp`/… of them); `*.pub` stays readable |
| `floor-reverse-shell-denied` | deny | `/dev/tcp/…`, `nc -e`, `socat exec:`, Python socket + subprocess, PowerShell `TCPClient` |
| `floor-guard-config-write-denied` | deny | writes to `.writ/` (ledger, state) and to the agent hook configuration: `.claude/settings*.json`, `.codex/config.toml` and `hooks.json`, `.gemini/settings.json`, `.cursor/hooks.json`, Windsurf `hooks.json` |
| `floor-agent-bypass-flags-denied` | deny | launching an agent with its checks off: `--dangerously-skip-permissions`, `--dangerously-bypass-approvals-and-sandbox`, `--yolo`, `--trust-all-tools`, `--approval-mode yolo`, `--permission-mode bypassPermissions` (how the s1ngularity/Nx malware recruited local AI CLIs) |
| `floor-authorized-keys-write-denied` | deny | adding keys to `~/.ssh/authorized_keys` |
| `floor-policy-edit-asks` | ask | the agent editing a `writ.yaml` |
| `floor-rm-workspace-asks` | ask, irreversible | `rm -rf .`, `..`, `*`, `.git`, `$PWD` |
| `floor-discard-uncommitted-work-asks` | ask, irreversible | `git reset --hard`, `clean -f`, `checkout -- .`, `restore .`, `stash drop/clear` |
| `floor-database-drop-asks` | ask, irreversible | `DROP DATABASE/SCHEMA` (shell or SQL MCP tools), `dropdb`, Redis `FLUSHALL`, Mongo `dropDatabase()`, `prisma migrate reset`, `rails db:drop`, `supabase db reset` |
| `floor-cloud-destroy-asks` | ask, irreversible | `terraform/tofu/terragrunt/pulumi/cdk destroy`, `gcloud projects delete`, `az group delete`, `aws s3 rb --force`, `aws s3 rm --recursive`, RDS/CloudFormation deletes, `kubectl delete ns/--all`, Fly/Heroku/Railway/Vercel/Firebase destroys |
| `floor-remote-script-exec-asks` | ask | `curl … \| sh`, `irm … \| iex` |
| `floor-persistence-asks` | ask | writes to shell profiles, `crontab`, `launchctl load`, `schtasks /create`, `systemctl enable`, Run keys |
| `floor-shutdown-asks` | ask | `shutdown`, `reboot`, `Stop-Computer`, … |

## What it deliberately does not cover

- **What a script does once it runs.** The floor reads the command line. A
  script that deletes your home directory (`bash cleanup.sh`) is caught by
  writ's script inspection (the gateway reads scripts the agent runs and
  writes) and, under `writ run`, by the kernel write boundary, not by these
  regexes alone. See [docs/THREAT_MODEL.md](../../docs/THREAT_MODEL.md).
- **Everything that is merely risky.** Package publishes, IAM changes,
  `DROP TABLE`, secret files such as `.env`: add `package-publish-guard`,
  `aws-safety`, `database-safety`, `secrets-guard` next to it.
- **Obfuscation.** `eval "$(echo cm0gLXJmIH4= | base64 -d)"` is not decoded.
  Command regexes are a first line; the kernel boundary is the backstop.

## Tests

`fixtures/floor.yaml`: every rule, plus near misses that must not fire
(`rm -rf node_modules`, `git rm -r --cached .`, `ssh -i ~/.ssh/id_ed25519`,
`git push -f origin mainline-fix`, `cat .claude/settings.json 2>/dev/null`,
…).
