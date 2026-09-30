# Good first issues: policy packs

Eight issue drafts for packs the community could add next. Each one is
sized for a first contribution: one directory under `packs/`, no Rust. Copy
a draft into a GitHub issue with the labels `good first issue` and `pack`.
These are drafts only; nothing here has been filed yet.

## Acceptance criteria shared by every pack issue

Paste this block into each issue under its own criteria.

- [ ] `packs/<id>/pack.yaml` with `id`, `version: 0.1.0`, a one-line
      `description`, and `rules`. Rule ids carry a pack prefix.
- [ ] Every `deny` and `ask` has a `reason` that tells a human what to check;
      `irreversible: true` wherever there is no undo.
- [ ] Regexes use `(?i)` where the tool is case-insensitive (Windows
      executables, SQL), keep a match inside one pipeline segment
      (`[^;&|]*`), and any `allow` is anchored (`^…$`) and rejects shell
      metacharacters, so `<safe command> && <anything>` is never allowed.
- [ ] `packs/<id>/fixtures/<id>.yaml`: at least one hit per rule, a Windows
      or PowerShell variant where the tool runs there, and **near misses**
      that must not match. Fixtures are evaluated against the pack under
      `version: 1` / `default: ask`, so unmatched cases expect
      `rule_id: default`.
- [ ] `packs/<id>/README.md`: what it covers (a rule table), what it
      deliberately does not cover, where the rules go in `provio.yaml`.
- [ ] A line for the pack in `packs/README.md`.
- [ ] `python scripts/validate_packs.py` passes locally (CI runs it too).
- [ ] `python scripts/claim_lint.py` is clean.
- [ ] The PR body describes the threat the pack addresses (see
      CONTRIBUTING.md, "Contribute a policy pack").

How agent tools reach the policy: Claude Code `Bash`/`PowerShell` become
tool `bash` with `command`; `Read`/`Write`/`Edit` become `fs.read`/`fs.write`
with `path`; `WebFetch` becomes `http` with `url.host`; `mcp__<server>__<tool>`
becomes tool `<tool>` on `server`. Details: `adapters/README.md` and
`docs/policy-reference.md`.

---

## 1. Pack: `terraform-cloud` (Terragrunt, Terraform Cloud / HCP)

**Why.** `terraform-safety` (0.2.0) covers `terraform`/`tofu` destroy
(including `apply -destroy` and global flags such as `-chdir`),
`apply -auto-approve`, `state rm` and `force-unlock`. It does not cover
Terragrunt, Terraform Cloud / HCP runs, or several other state-changing
subcommands.

**Scope.**
- Terragrunt: `run-all destroy` / `run-all apply` (especially with
  `--terragrunt-non-interactive`), `destroy`, `apply -auto-approve`.
- `terraform workspace delete`, `terraform import`, `state mv`, `state push`
  (ask).
- `tfe`/`hcp` CLI or `curl … app.terraform.io/api/v2/…` run applies and
  workspace deletes (ask).

**Acceptance.** The shared criteria, plus fixtures for
`terragrunt run-all destroy`, a Terraform Cloud run apply, and near misses
such as `terraform plan -destroy` (a plan, not a destroy).

**Copy from.** `packs/terraform-safety` for the `binary [flags] subcommand`
regex shape and the reasons.

## 2. Pack: `pulumi`

**Why.** Pulumi stacks own real infrastructure the same way Terraform state
does, and `pulumi destroy --yes` or `pulumi up --yes` runs with no prompt.

**Scope.**
- Ask (irreversible): `pulumi destroy`, `pulumi up --yes`/`-y`,
  `pulumi stack rm`, `pulumi state delete`, `pulumi refresh --yes`,
  `pulumi cancel`.
- Deny: `pulumi stack rm --force` (removes the stack even with resources).
- Ask: `pulumi config set --secret`, `pulumi stack output --show-secrets`
  (secret into context).
- Allow: anchored `pulumi preview`, `stack ls`, `stack output` without
  `--show-secrets`, `whoami`.

**Acceptance.** The shared criteria, plus near misses such as
`pulumi preview --diff` and `pulumi up` **without** `--yes`.

**Copy from.** `packs/terraform-safety` (shape) and `packs/aws-safety`
(anchored read-only allow, secret-read ask).

## 3. Pack: `docker-compose`

**Why.** Agents run Docker constantly. A few commands destroy data
(`docker volume rm`, `docker system prune -a --volumes`,
`docker compose down -v`) or hand the agent the host
(`docker run --privileged`, `-v /:/host`, `-v /var/run/docker.sock:…`).

**Scope.**
- Ask (irreversible): `docker compose down -v/--volumes`,
  `docker volume rm/prune`, `docker system prune` with `--volumes` or `-a`,
  `docker rm -f` of more than one container.
- Deny: `docker run`/`compose run` with `--privileged`, `--pid=host`,
  `--net=host` plus a host root mount, a bind mount of `/` or `C:\`, or the
  Docker socket (`/var/run/docker.sock`, `//./pipe/docker_engine`).
- Allow: anchored `docker ps`, `images`, `logs`, `inspect`,
  `compose ps/logs/config`.
- Leave `docker push` to `package-publish-guard`; say so in the README.

**Acceptance.** The shared criteria, plus Windows named-pipe and PowerShell
cases, and near misses such as `docker compose down` (no `-v`) and
`-v ./data:/data`.

**Copy from.** `packs/github-safety` (deny vs. ask split, anchored allow with
a narrow pipe tail).

## 4. Pack: `helm`

**Why.** `helm uninstall` deletes every resource in a release, and
`helm upgrade --install --force` or `--reset-values` against the wrong
kube context can take a production service down. `k8s-prod` covers
`kubectl` only.

**Scope.**
- Ask (irreversible): `helm uninstall`/`delete`/`del`, `helm rollback`,
  `helm upgrade … --force` or `--reset-values`.
- Ask: `helm plugin install` (plugins run arbitrary code).
- Ask: `helm upgrade --install` whose command mentions `prod`/`production`
  (mirror `k8s-prod`).
- Ask: `helm get values --all` / `helm get manifest` (may print secrets).
- Allow: anchored `helm list`, `status`, `history`, `template`, `lint`,
  `show`, `search`, `repo list`.
- Leave `helm push` to `package-publish-guard`.

**Acceptance.** The shared criteria, plus `helm.exe` cases and near misses
such as `helm template . | kubectl diff -f -`.

**Copy from.** `packs/k8s-prod` (prod detection) and `packs/aws-safety`
(regex style).

## 5. Pack: `stripe-billing-mcp`

**Why.** Billing MCP servers give an agent tools that move money: refunds,
payment links, subscription cancellations, invoice finalization. A single
confused tool call is a real financial event, and there is no undo for a
payout.

**Scope.**
- Ask (irreversible) on a server whose name matches `stripe` (and the same
  idea for other billing servers you use): tools that refund, cancel,
  finalize, void, pay, create payment links or payouts, and anything
  starting `delete_`/`cancel_`/`update_subscription`.
- Deny: payout and balance-transfer tools, API-key and webhook-endpoint
  management.
- Allow: `list_*`, `retrieve_*`/`get_*`, `search_*` read tools.
- Redact (at the end of the file): email addresses and card-shaped
  fragments in results (see `pii-redaction`).
- Also cover the Stripe CLI in `bash`: `stripe refunds create`,
  `stripe … delete`, `stripe listen --forward-to` (ask).

**Acceptance.** The shared criteria. Check the current tool names of the
MCP server you target and list them in the README; fixtures use the
`tool` + `server` shape (see `packs/github-safety/fixtures`).

**Copy from.** `packs/github-safety` (MCP `server matches` + `tool matches`
rules) and `packs/pii-redaction`.

## 6. Pack: `outbound-messages` (Slack and email sending)

**Why.** Sending a message is irreversible and public-facing, and it is the
most common exfiltration channel once an agent has read something
sensitive. Slack and email MCP servers expose `post_message`/`send_email`
style tools next to harmless read tools.

**Scope.**
- Ask (irreversible): tools on servers matching `slack|gmail|email|outlook|
  smtp|sendgrid|postmark|resend|teams` whose names contain `send`, `post`,
  `reply`, `forward`, `publish`, `invite`, `schedule_message`.
- Deny: deleting messages or channels, changing channel membership or
  workspace settings.
- Allow: `list_*`, `get_*`, `search_*`, `read_*` on those servers (note the
  prompt-injection caveat in the README, as `github-safety` does).
- `bash`: `curl`/`Invoke-RestMethod` to `hooks.slack.com`,
  `api.sendgrid.com`, `api.postmarkapp.com`, and `sendmail`/`mail`/
  `Send-MailMessage` (ask). `http` tool: the same hosts via `url.host in`
  a named `hosts:` list.

**Acceptance.** The shared criteria, plus a `hosts:` list used with
`url.host in hosts.<name>` and fixtures for a WebFetch-shaped `http` call.

**Copy from.** `packs/github-safety` (MCP rules) and `examples/ci.yaml`
(`hosts:` lists).

## 7. Pack: `browser-automation` (Playwright MCP and friends)

**Why.** Browser MCP servers let an agent navigate anywhere, type into
forms, upload local files and run JavaScript in the page, often in a
browser profile that is already signed in. That combines untrusted input
(web pages) with real authority (the user's sessions).

**Scope.**
- On servers matching `playwright|puppeteer|browser|chrome`:
  - Ask: navigation to hosts outside a `hosts.browser_allowed` list
    (`browser_navigate` carries a `url`, so `url.host` works).
  - Ask (irreversible): form submission, typing and clicking on pages
    outside the allow list, file upload tools, JavaScript evaluation tools.
  - Deny: file upload tools whose `path` is a credential file (reuse the
    path patterns from `secrets-guard`).
  - Allow: snapshot, screenshot, console and network-log read tools.
- README: which tool names you checked against, and that the pack cannot
  see page content or which account is signed in.

**Acceptance.** The shared criteria, plus fixtures for an allowed host, a
disallowed host, and an upload of `~/.ssh/id_rsa`.

**Copy from.** `packs/secrets-guard` (path patterns) and `examples/provio.yaml`
(`egress-allowlist` with `url.host in hosts.allowed`).

## 8. Pack: `filesystem-outside-repo`

**Why.** Most coding tasks never need to write outside the repository, yet
agents do edit `~/.bashrc`, `~/.gitconfig`, shell profiles, `/etc/hosts`,
startup folders and CI config in other checkouts. Those are persistence and
supply-chain paths.

**Scope.**
- Deny `fs.write` (and MCP filesystem `write_file`/`edit_file`/`move_file`)
  to shell and tool startup files: `.bashrc`, `.zshrc`, `.profile`,
  PowerShell `$PROFILE` paths (`Documents\PowerShell\*profile.ps1`),
  `.gitconfig`, `.ssh/config`, git hooks (`.git/hooks/`), Windows Startup
  folders, `/etc/`, `C:\Windows\`, LaunchAgents, systemd user units,
  crontabs.
- Ask on `fs.write` to any absolute path under a home directory
  (`/home/*`, `/Users/*`, `C:\Users\*`) that is not under a configurable
  workspace prefix. The DSL has no workspace variable, so document a
  placeholder rule the user edits (`not path startswith "/path/to/repo"`).
- `bash`: `>>`/`>` redirection, `tee`, `Add-Content`/`Set-Content` into the
  same startup files (deny).

**Acceptance.** The shared criteria, plus Windows paths with backslashes,
`fs.write` fixtures shaped like Claude Code's `Write` (`file_path`), and
near misses such as a repo file named `bashrc.example`.

**Copy from.** `packs/secrets-guard` (path regexes with `[/\x5c]` for both
separators, `not path matches` exclusions).
