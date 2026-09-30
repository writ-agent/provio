# pii-redaction

Masks common PII and secret shapes (email addresses, AWS-style access keys,
private-key headers, SSN-shaped numbers) in tool results before they
re-enter the model's context.

| Rule | Verdict | Matches calls | Masks |
|---|---|---|---|
| `redact-emails` | redact | `crm*`, `http*`, `fs*` tools | email addresses |
| `redact-aws-keys` | redact | `fs*`, `bash*`, `http` | `AKIA…` keys, `aws_secret_access_key…` |
| `redact-private-keys` | redact | every call in `mcp` or `sdkhook` mode | `-----BEGIN … PRIVATE KEY-----` headers |
| `redact-ssn-like` | redact | `crm*`, `postgres*` | `123-45-6789` shapes |

## Read this before merging

`redact` means **run the call, then mask the result**. These rules match
broadly (every `fs.*` call, every `bash` call, every MCP call), so wherever
they sit in your `provio.yaml` they let those calls through **without a
prompt**, and they pre-empt every rule below them. Merge them at the very
**end** of your rules, after all deny/ask rules, or narrow the `when`
clauses to the read-only tools you want masked. `secrets-guard` shows the
narrower pattern (redact only `fs.read` and anchored read-only shell
commands) and masks a larger set of token formats.

Only the first matching rule applies, so a call gets one rule's patterns:
an `fs.read` result is masked for emails only (the first match), not for
AWS keys as well.

## Use it

```bash
provio policy add pii-redaction   # bundled with provio (a local ./packs/<id> wins); prints the sha256
```

Paste the `rules:` entries at the end of your `provio.yaml`, then `provio policy
test --policy provio.yaml --fixtures packs/pii-redaction/fixtures`. Fixtures:
`fixtures/pii-redaction.yaml` (7 cases).
