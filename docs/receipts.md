# Receipts and anchoring

`provio verify` makes the ledger **tamper-evident**: an edited record or a
broken link is caught and named by index. It cannot catch a rewrite. Anyone
who can write `.provio/ledger.jsonl` can edit a record and recompute every hash
after it, or delete the file, and the new chain verifies.

Receipts and anchors close part of that gap:

- A **receipt** is a signed checkpoint of the ledger: its identity, how many
  records it had, the hash of the last one, and a Merkle root over all of them,
  signed with an Ed25519 key. If you keep the receipt and the public key, any
  later edit, rewrite, reordering or truncation of a record at or before the
  checkpoint is detected, and the failing record is named where possible.
  Records appended after the checkpoint are allowed.
- An **inclusion proof** shows that one call's records are covered by a
  receipt, without shipping the ledger.
- An **anchor** is an outside witness that a receipt existed at a given time:
  an entry in the public Sigstore Rekor transparency log, or a line in an
  append-only file you copy somewhere the ledger host cannot rewrite.

```sh
provio receipt keygen --out ~/.config/provio/receipt.key     # + receipt.key.pub
provio receipt create --key ~/.config/provio/receipt.key --out r.json [--session S]
provio receipt anchor r.json --to rekor                    # or: --to file [--anchor-log PATH]
provio receipt verify r.json --pubkey ~/.config/provio/receipt.key.pub
provio receipt prove <call-id> --receipt r.json --out p.json
provio receipt verify p.json --pubkey receipt.key.pub      # no ledger needed
```

`verify` prints one line per check and exits **0** when every check passes,
**1** otherwise. Each failure says what broke: `signature: INVALID`,
`checkpoint: record 4 was altered: its record_hash does not match its contents`,
`checkpoint: the ledger was truncated: it has 7 records, the receipt covers 10`,
`rekor anchor (log index N): signed entry timestamp does not verify`, and so on.

---

## Contract 7 — Receipts (`provio_receipts`)

Versioned by the `format` string of each file. A new version gets a new
`format` value and a new canonical context string; `provio receipt verify` keeps
reading every earlier version.

### 7.1 Receipt file: `writ.receipt/v1`

```json
{
  "format": "writ.receipt/v1",
  "checkpoint": {
    "ledger_id": "71b14079…3d4d",
    "records": 4,
    "tip_index": 3,
    "tip_hash": "47ced6f8…daef",
    "merkle_root": "c3bb23d7…747f",
    "session": { "id": "s-1", "records": 2, "merkle_root": "…" },
    "created_at": "2026-09-23T12:09:59Z",
    "signer": "ed25519:3668382c…969e"
  },
  "signature": {
    "alg": "ed25519ph",
    "public_key": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA…\n-----END PUBLIC KEY-----\n",
    "value": "<base64 of the 64-byte signature>"
  },
  "anchors": [ { "type": "rekor", … }, { "type": "file", … } ]
}
```

| Field | Meaning |
|---|---|
| `checkpoint.ledger_id` | `record_hash` of record 0. Stable for the life of the ledger; identifies which ledger the receipt is about. |
| `checkpoint.records` | Records covered, always `tip_index + 1`, at least 1. |
| `checkpoint.tip_index` | Index of the last covered record. |
| `checkpoint.tip_hash` | `record_hash` of record `tip_index`. Because every record chains to the previous one, this alone commits to records `0..=tip_index`. |
| `checkpoint.merkle_root` | RFC 6962 Merkle tree hash over records `0..=tip_index` (§7.4). Makes per-record inclusion proofs possible. |
| `checkpoint.session` | Optional. `id`: session id. `records`: how many covered records belong to it. `merkle_root`: RFC 6962 root over just those records, in ledger order. |
| `checkpoint.created_at` | RFC 3339 UTC, whole seconds, exactly `YYYY-MM-DDTHH:MM:SSZ`. This is the signer's own clock. An anchor's time is the independent one. |
| `checkpoint.signer` | `ed25519:` + lowercase hex SHA-256 of the 32-byte raw public key. |
| `signature.alg` | `ed25519ph`. |
| `signature.public_key` | The signer's SPKI PEM public key, included so `anchor` can submit it. It proves nothing about **who** signed. Pin the key you expect with `--pubkey`. |
| `signature.value` | Standard base64 (padded) of the Ed25519ph signature over the canonical bytes (§7.2). |
| `anchors` | Optional list. The signature does not cover it. Each anchor carries its own proof (§7.6). |

`checkpoint` and `checkpoint.session` reject unknown fields, because a field
the signature doesn't cover can't be allowed inside the signed object.

### 7.2 Canonical bytes and signature

The checkpoint is never signed as JSON. It is rendered as this ASCII text.
Every line ends in LF (`0x0A`), including the last one, and fields are
separated by a single space:

```text
writ.receipt.checkpoint.v1
ledger_id <64 lowercase hex>
records <decimal>
tip_index <decimal>
tip_hash <64 lowercase hex>
merkle_root <64 lowercase hex>
session -
created_at <YYYY-MM-DDTHH:MM:SSZ>
signer ed25519:<64 lowercase hex>
```

For a session-scoped receipt the `session` line is
`session <lowercase hex of the UTF-8 session id> <decimal records> <64 hex root>`.
Hex-encoding the id keeps spaces and newlines in a session id from changing
the line structure.

Decimals have no sign, no leading zeros and no separators. Before rendering,
every field is validated against its pattern (64 lowercase hex characters,
`records == tip_index + 1`, the timestamp shape, the `ed25519:` prefix, and so
on). A receipt that fails validation is rejected rather than normalized, so
each checkpoint has exactly one canonical encoding.

**Domain separation.** The first line, `writ.receipt.checkpoint.v1`, is the
context string. No other provio object starts with it, so a signature over a
checkpoint can't be replayed as a signature over anything else, and v2 will
use a different line.

**Signature.** Ed25519ph as defined in RFC 8032 §5.1: the message is
pre-hashed with SHA-512, and the RFC 8032 context is empty (`dom2(1, "")`).
Verification uses the strict variant (`verify_prehashed_strict`: it rejects
small-order keys and non-canonical signatures). provio uses Ed25519ph rather
than plain Ed25519 because Rekor's `hashedrekord` type accepts Ed25519 keys
only as Ed25519ph over a SHA-512 digest. The signature in the receipt can
therefore be submitted to Rekor unchanged, and anchoring does not need the
private key. The RFC 8032 context has to stay empty for that to work, which is
why domain separation lives in the message's first line.

### 7.3 Keys

- `provio receipt keygen --out K [--force]` draws a 32-byte seed from the OS
  CSPRNG (`getrandom`) and writes:
  - `K`: the private key, PKCS#8 v2 PEM (`-----BEGIN PRIVATE KEY-----`,
    RFC 8410).
  - `K.pub`: the public key, SPKI PEM (`-----BEGIN PUBLIC KEY-----`).
- It refuses to overwrite either file unless `--force` is given.
- **Unix:** `K` is created with `O_EXCL` and mode `0600`.
- **Windows:** `K` is created, then `icacls K /inheritance:r /grant:r
  <USERDOMAIN>\<USERNAME>:F` removes inherited entries and grants full control
  to the current user only. The test suite checks the resulting ACL. There is
  a limitation: for the moment between creation and the `icacls` call, the
  file carries its directory's inherited ACL. Under your user profile that
  normally means you, SYSTEM and Administrators. If `icacls` fails, keygen
  still writes the key and prints a warning telling you to restrict it
  yourself.
- The private key is **not encrypted at rest**. See §9 for key management.

### 7.4 Merkle tree

This is RFC 6962 §2.1, restated in RFC 9162 §2.1. It is the same tree that
Certificate Transparency and Rekor use.

- Leaf data for record `i` is the 32 raw bytes of its `record_hash`
  (hex-decoded), in ledger order.
- Leaf hash: `SHA-256(0x00 ‖ leaf data)`.
- Node hash: `SHA-256(0x01 ‖ left ‖ right)`.
- For `n > 1` leaves, split at `k`, the largest power of two less than `n`:
  `MTH(D[0:n]) = node(MTH(D[0:k]), MTH(D[k:n]))`.
- A one-leaf tree's root is its leaf hash.

Inclusion proofs are the RFC 9162 §2.1.3 audit paths, listed from the leaf to
the root, and are verified with the §2.1.3.2 algorithm. The implementation is
checked against the Certificate Transparency reference roots, and against
real Rekor inclusion proofs.

### 7.5 Verification

`provio receipt verify R [--pubkey P] [--rekor-pubkey L] [--anchor-log F]`:

1. **Signature.** Parse the file, validate the checkpoint, and check the
   Ed25519ph signature. With `--pubkey`, the receipt must be signed by that
   key, or verify fails with `signed by X, not by the pinned key Y`. Without
   it, only self-consistency is checked and the output says `NOT pinned`.
   `checkpoint.signer` must match the key. If the signature fails, the
   checkpoint is not checked, because it can't be trusted.
2. **Checkpoint.** Stream the ledger at `--ledger`. A JSONL ledger is read
   line by line without creating, locking or repairing it; a torn final line
   (a write in progress) ends the stream, as it does in the store. Other
   stores (SQLite, …) are read through `provio_ledger::open_store`. For each record
   `i` in `0..=tip_index`:
   - The record must parse.
   - Its `index` field must be `i`.
   - Its `record_hash` must match its contents.
   - Its `prev_hash` must link to record `i-1`.

   The first record that fails any of these is named:
   `record i was altered: <which check>`. In addition:
   - Record 0's hash must equal `ledger_id`. Otherwise: "different ledger, or
     rewritten from the start".
   - Record `tip_index`'s hash must equal `tip_hash`. Otherwise: "the chain is
     internally consistent but was rewritten at or before record N". This is
     the rewrite-and-recompute case. The receipt can't say which earlier
     record changed, only that one did.
   - A ledger shorter than `records` fails as truncated. A missing ledger
     fails.
   - The Merkle root, and the session root if scoped, are recomputed and must
     match.
3. **After the checkpoint.** Appended records are counted and allowed. If a
   record after the tip does not continue the chain, verify fails with
   `the checkpoint holds, but record N (after it) does not continue the chain;
   run provio verify`. The receipt's own claim still stands, but the ledger does
   not.
4. **Anchors.** Each anchor is verified as in §7.6. A Rekor anchor for a log
   with no pinned key and no `--rekor-pubkey` fails; it is not skipped.

Exit 0 only if every check passed.

### 7.6 Anchors

#### Rekor (`provio receipt anchor R --to rekor [--url U] [--rekor-pubkey L]`)

This was checked against the Rekor OpenAPI spec and the `hashedrekord` v0.0.1
schema, and tested live against `rekor.sigstore.dev` on 2026-09-23. See
Sources.

The command sends `POST {U}/api/v1/log/entries` (default
`U = https://rekor.sigstore.dev`) with:

```json
{"apiVersion":"0.0.1","kind":"hashedrekord","spec":{
  "data":{"hash":{"algorithm":"sha512","value":"<hex SHA-512 of the canonical bytes>"}},
  "signature":{"content":"<signature.value>",
               "publicKey":{"content":"<base64 of signature.public_key (the PEM)>"}}}}
```

The digest is SHA-512, not SHA-256, because Rekor rejects SHA-256 with Ed25519
keys. For Ed25519, `hashedrekord` means Ed25519ph with SHA-512 (Rekor ≥ 1.3.6,
sigstore/rekor#1945).

- On `201`, the response `{ "<uuid>": LogEntry }` is parsed.
- On `409` (an identical entry already exists), the `Location` entry is
  fetched instead.
- Any other status fails with the status code and the start of the response
  body, and the receipt is left unchanged.
- The response is verified (§ below) before anything is written. The anchor
  is then added to the receipt: in place by default, atomically via a temp
  file and rename, or to `--out`.

Stored anchor (`"type": "rekor"`):

| Field | From the log entry |
|---|---|
| `url`, `uuid` | Log base URL. Entry UUID (tree id + leaf hash). |
| `log_id` | `logID`: hex SHA-256 of the log's DER public key. |
| `log_index` | `logIndex` (global, across shards). |
| `integrated_time` | `integratedTime`: Unix seconds when the log included the entry. |
| `body` | `body`: base64 of the canonicalized entry, byte for byte as returned. |
| `signed_entry_timestamp` | `verification.signedEntryTimestamp`: base64 DER ECDSA signature. |
| `inclusion_proof` | `verification.inclusionProof`: `log_index` (index within the shard's tree), `root_hash`, `tree_size`, `hashes` (leaf to root), `checkpoint` (signed note). |

Offline verification against the log key:

1. **The entry is this receipt.** The decoded `body` must be a
   `hashedrekord` 0.0.1 whose SHA-512 digest equals this checkpoint's, whose
   signature equals `signature.value`, and whose public key equals the
   receipt's key. `uuid` must end in the entry's leaf hash
   `SHA-256(0x00 ‖ body)`. An anchor copied from another receipt fails here.
2. **SET.** `log_id` must equal the SHA-256 of the trusted key. The SET must
   verify as ECDSA P-256 / SHA-256 over the RFC 8785 canonical JSON
   `{"body":…,"integratedTime":…,"logID":…,"logIndex":…}`. Editing the time
   or the index fails here.
3. **Inclusion.** The RFC 6962 proof must lead from the leaf hash to
   `root_hash` at `tree_size`. The `checkpoint` note's size and base64 root
   must equal the proof's. One of its `— <origin> <base64(keyhint₄ ‖ DER sig)>`
   lines must carry the first 4 bytes of `log_id` as the key hint and verify
   over the note body, which is everything before the blank line, including
   its final newline.

**Log key.** The production key for `rekor.sigstore.dev` is **pinned** in
`provio_receipts::rekor::PINNED_PUBLIC_KEY_PEM`. Its log ID is
`c0d23d6a…9591801d`. It is the key served at
`https://rekor.sigstore.dev/api/v1/log/publicKey` and distributed in the
Sigstore TUF root. Verify never contacts the network. For any other URL, pass
`--rekor-pubkey L` to both anchor and verify. If you don't, anchor fetches
`/api/v1/log/publicKey` once, with a warning, only to sanity-check the
response. verify then refuses the anchor until you supply the key. provio does
not follow Sigstore TUF key rotation. If the public instance rotates its key,
the pin must be updated in a provio release.

What an anchor proves: an entry committing to this exact checkpoint and
signature was in a public, append-only, monitored log at `integrated_time`.
If you later present a different receipt for the same ledger, it cannot
predate that entry. The receipt itself also cannot be quietly withdrawn: the
log entry stays.

Privacy: the entry publishes the checkpoint's SHA-512 digest, the signature
and your public key. No ledger content, call arguments, session ids or hashes
of records are sent. The key does link your anchors to each other.

#### File (`provio receipt anchor R --to file [--anchor-log F]`)

This appends one JSON line to `F` and fsyncs it. The default `F` is
`anchors.log` next to the ledger. The line looks like this:

```json
{"format":"writ.anchor-line/v1","anchored_at":"…","ledger_id":"…","records":N,"tip_hash":"…","merkle_root":"…","signer":"ed25519:…","checkpoint_sha512":"…","signature":"…"}
```

It stores `{"type":"file","path","line_sha256","anchored_at"}` in the
receipt. verify looks for a line with that SHA-256 in `--anchor-log` (default:
the recorded path) and checks that it describes this checkpoint and
signature.

**A file anchor proves nothing by itself.** A file on the same host as the
ledger can be rewritten by whoever rewrites the ledger. It becomes a witness
only once you copy it somewhere that host can't rewrite: a git remote with
protected history, an object-lock (WORM) bucket, a different machine or
administrator. At that point verify it with `--anchor-log <that copy>`.
`anchored_at` is the local clock.

### 7.7 Inclusion proof file: `writ.inclusion-proof/v1`

`provio receipt prove <call-id> --receipt R [--out P]` first checks that the
ledger still matches R (§7.5 step 2). It then writes:

```json
{ "format": "writ.inclusion-proof/v1", "call_id": "…", "receipt": { …R… },
  "entries": [ { "record": { …full LedgerRecord… }, "leaf_index": 6,
                 "tree_size": 10, "audit_path": ["<hex>", …] } ] }
```

There is one entry per covered record of that call, normally its decision
and its execution. `provio receipt verify P --pubkey K`:

- checks the embedded receipt's signature and anchors;
- for each entry, recomputes `record_hash` from the record's contents, then
  the leaf hash, then walks the path to `checkpoint.merkle_root`;
- requires `leaf_index == record.index` and `tree_size == checkpoint.records`.

No ledger is needed. A proof contains that call's full record, including its
arguments, so treat it with the same care as the ledger. A call appended after
the receipt's tip is not covered; create a new receipt first.

---

## 8. Threat model

What each layer adds:

| Attacker action | Hash chain only (`provio verify`) | + receipt, public key held elsewhere | + anchor |
|---|---|---|---|
| Edit one record, leave the hashes | Detected, index named | Detected, index named | — |
| Edit, then recompute the chain after it | **Not detected** | Detected: `rewritten at or before record N` | — |
| Delete or reorder records | Detected when the chain breaks | Detected, index named | — |
| Truncate the tail | **Not detected** | Detected: `truncated` (for records up to the checkpoint) | — |
| Delete the whole ledger | Nothing left to check | Detected: `no ledger`. Contents are not recoverable. | — |
| Forge a new receipt with the stolen key | n/a | **Not detected** | The old receipt's anchor still exists and predates the forgery. A backdated forgery is contradicted by `integrated_time`. |
| Claim a receipt was made earlier than it was | n/a | `created_at` is the signer's word | Rekor's `integrated_time` is the independent time |
| Withdraw or replace a receipt after sharing it | n/a | Possible if nobody kept a copy | The Rekor entry stays in the public log |

What receipts and anchoring **do not** do:

- **Records after the last receipt are not protected.** A receipt covers
  records up to its tip and nothing later. Create and anchor receipts often:
  per session, on a timer, or from CI. The gap between receipts is exactly
  what an attacker can rewrite without detection.
- **A compromised host before anchoring.** If the attacker controls the host
  when the receipt is created, they choose what gets signed. A receipt proves
  the ledger has not changed *since*; it does not prove the ledger was true
  *when signed*. The same holds for records the attacker wrote while in
  control.
- **A stolen signing key.** Whoever has the key can sign a receipt over a
  rewritten ledger. Anchors of earlier receipts still pin the earlier state,
  and they show when each receipt was logged. A rewritten ledger can't satisfy
  an earlier anchored receipt, but a verifier who only sees the new receipt
  can't tell. Rotate the key and treat receipts signed after the compromise as
  untrusted.
- **The verifier must get the public key out of band.** The key embedded in
  the receipt is only self-consistency. Pin the key with `--pubkey`, taken from
  somewhere the attacker can't edit.
- **Deleting the ledger and every copy of the receipt.** Receipts only help if
  someone keeps them. An anchor proves a receipt existed, and the Rekor body
  is enough to recognise it, but it cannot rebuild the ledger.
- **Rekor's trust assumptions.** An anchor is as trustworthy as the log and
  the pinned key. The public-good instance is monitored, but provio does not
  itself check consistency between checkpoints (split-view detection); that is
  left to Sigstore's monitors.
- **Local clocks.** `created_at` and file-anchor `anchored_at` are the local
  clock. Only a Rekor `integrated_time` is independent.
- **Correctness of the recorded decisions.** A receipt certifies that the
  records are unchanged, not that the policy was right or that every tool call
  went through provio (see THREAT_MODEL.md, "Agent bypasses Provio entirely").

## 9. Key management

- Keep the private key **off the host whose ledger it signs**, if you can.
  Best is a CI job or a separate machine that pulls the ledger, runs
  `provio receipt create` and `anchor`, and keeps the receipts. A key on the
  same host is only as safe as that host.
- The private key file is unencrypted PKCS#8. Protect it with file
  permissions (set by keygen), full-disk encryption, or a secrets manager. Do
  not commit it.
- Distribute the `.pub` file, or the `ed25519:` key id, through a channel the
  ledger host can't change: the repo's protected branch, your team's docs, the
  verifier's own config. Verifiers must pass `--pubkey`.
- Use one key per ledger or per deployment. A Rekor anchor publishes the
  public key, which links every anchor made with it.
- To rotate, `keygen` a new key, publish the new `.pub`, and keep the old one
  so earlier receipts still verify. If a key leaks, record when it leaked;
  receipts anchored before that time remain meaningful.

## Sources

- Rekor OpenAPI (`POST /api/v1/log/entries`, `LogEntry`, `InclusionProof`,
  `GET /api/v1/log/publicKey`):
  https://github.com/sigstore/rekor/blob/main/openapi.yaml
- `hashedrekord` v0.0.1 schema:
  https://github.com/sigstore/rekor/blob/main/pkg/types/hashedrekord/v0.0.1/hashedrekord_v0_0_1_schema.json
- Ed25519ph in `hashedrekord` (SHA-512 required for Ed25519 keys):
  https://github.com/sigstore/rekor/pull/1945 and
  https://github.com/sigstore/rekor/issues/851
- Production log key / tree info:
  https://rekor.sigstore.dev/api/v1/log/publicKey and
  https://rekor.sigstore.dev/api/v1/log
- RFC 8032 (Ed25519ph), RFC 6962 / RFC 9162 §2.1 (Merkle trees, inclusion
  proofs), RFC 8785 (JSON canonicalization of the SET payload), C2SP
  signed-note format (the Rekor checkpoint).
