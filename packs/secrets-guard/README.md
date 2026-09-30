# secrets-guard

Keeps credential material out of the agent's context. It denies reads (and
writes) of key, token and cloud-credential files by path, denies shell
commands that read, copy or exfiltrate those files, pull secrets out of
keychains, password managers and CLI token caches, or dump the environment.
It also masks common token formats in the output of file reads and
read-only shell commands.

| Rule | Verdict | Covers |
|---|---|---|
| `secrets-ssh-keys-denied` | deny | `~/.ssh/id_*` (not `*.pub`), `identity`, `*_key`, `authorized_keys`, host keys, `*.ppk` |
| `secrets-cloud-credentials-denied` | deny | `~/.aws/credentials`, AWS SSO/CLI caches, gcloud config dir (Linux/macOS and `%APPDATA%\gcloud`), `application_default_credentials.json`, Azure token caches, `~/.kube/config`, `*kubeconfig*`, OCI config |
| `secrets-dotenv-denied` | deny | `.env`, `.env.*`, `.envrc`, `.dev.vars`, except `.env.example/.sample/.template/.dist/.defaults` |
| `secrets-key-files-denied` | deny | `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.jks`, `*.keystore`, `*.kdbx` |
| `secrets-token-files-denied` | deny | `.npmrc`, `.pypirc`, `.netrc`/`_netrc`, `.git-credentials`, `.pgpass`, `.my.cnf`, `.vault-token`, Docker `config.json`, gh `hosts.yml`, cargo/gem/terraform credentials, Maven `settings.xml` |
| `secrets-os-credential-stores-denied` | deny | browser password/cookie stores, macOS Keychains, Windows `Microsoft\Credentials`/`Protect`/`Vault`, `/etc/shadow`, `/proc/*/environ`, `pass` and GnuPG private keys |
| `secrets-egress-denied` | deny | a network tool (`curl`, `wget`, `scp`, `rsync`, `nc`, `Invoke-WebRequest`, `certutil`, …) in the same command as a credential path |
| `secrets-shell-read-denied` | deny | `cat`/`type`/`Get-Content`/`grep`/`base64`/`python`/… on a credential path; `cp`/`mv`/`Copy-Item` with a credential file as the source |
| `secrets-credential-store-commands-denied` | deny | macOS `security find-*-password`, `secret-tool`, `pass show`, 1Password `op read`, `bw get`, `vault kv get`, `cmdkey /list`, `Get-StoredCredential`, `git credential fill`, `gh auth token`, `gcloud auth print-access-token`, `az account get-access-token`, `aws configure export-credentials`, `kubectl config view --raw`, `kubectl get secret -o yaml` |
| `secrets-env-dump-denied` | deny | bare `env`/`printenv`/`set`/`export -p`, `Get-ChildItem env:`, `os.environ`/`process.env` dumps, printing a secret-named variable (`echo $GITHUB_TOKEN`, `$env:OPENAI_API_KEY`) |
| `secrets-redact-file-reads` | redact | every `fs.read` not denied above |
| `secrets-redact-shell-reads` | redact | anchored read-only shell commands: `cat`, `type`, `Get-Content`, `head`, `tail`, `grep`, `rg`, `findstr`, `git log/show/diff`, `docker logs`, `kubectl logs`, `journalctl` |

Masked formats: PEM private-key blocks (complete, or a header without its END
line), AWS access key IDs and secret/session keys next to their names, GitHub
classic and fine-grained tokens, Slack tokens and webhook URLs, JWTs, Google
API keys, Stripe keys, OpenAI/Anthropic-style `sk-` keys, npm and PyPI
tokens, `scheme://user:password@` URLs and `Authorization:` headers. Every
pattern is bounded and runs on Rust's linear-time regex engine.

## Where to put the rules (important)

`redact` means **run the call, then mask the result**. A redact rule
therefore also lets every call it matches through without a prompt. So:

- merge the **deny** rules near the **top** of your `provio.yaml`, above any
  rule that could allow a read;
- merge the two **redact** rules at the very **end**, after all of your own
  rules and other packs. Placed earlier, `secrets-redact-file-reads` would
  pre-empt any later `fs.read` rule of yours (for example a deny on a
  directory);
- if your posture is "ask before every read", leave the two redact rules
  out and keep only the denies.

## What it deliberately does not cover

- **Arbitrary programs.** `python script.py` that opens `~/.aws/credentials`
  itself, or a build tool that prints a token, is invisible to command-text
  rules. The redact rules mask known token formats only in output of the
  commands they match. Pair this pack with `provio run` confinement and keep
  long-lived credentials out of the agent's environment.
- **Search tools.** Claude Code's `Grep`/`Glob` carry the search root as
  `path`; a recursive search from `~` is not denied by these path rules
  (its output is still redacted by `secrets-redact-file-reads`).
- **Unknown token formats and passwords in prose** are not masked. Add your
  own patterns to the redact rules' `patterns` lists.
- **MCP tool results** are not redacted by this pack (use `pii-redaction`
  or your own rule scoped to the servers you trust).
- `cp .env.example .env` is allowed through to your default; `cp .env x`
  is denied. `cat .env.example` is not denied.

## Use it

Packs are rules you merge into your own `provio.yaml`; provio does not load
`.provio/packs/` automatically.

```bash
provio policy add secrets-guard   # bundled with provio (a local ./packs/<id> wins); prints the sha256
```

Paste the deny rules at the top of `rules:` and the redact rules at the end
(the redact rules share one pattern list through a YAML anchor,
`&secret_patterns` / `*secret_patterns`; keep both rules together, or
duplicate the list). Ids are prefixed `secrets-`. Overlaps: `gh auth token`
is also denied by `github-safety`; `gcloud`/`az` token printing is asked
(not denied) by `gcp-azure-safety`, and whichever rule comes first wins.

```bash
provio doctor --policy provio.yaml
provio policy test --policy provio.yaml --fixtures packs/secrets-guard/fixtures
```

Fixtures: `fixtures/secrets-guard.yaml` (61 cases, Windows paths and
PowerShell included, plus near misses such as `id_ed25519.pub`,
`environment.ts`, `grep process.env`, `env NODE_ENV=test npm test` and
`set -euo pipefail`). `redact-samples.yaml` (9 samples) drives real tool
output through `provio check` and asserts which strings are masked and which
survive; `scripts/validate_packs.py` runs both.
