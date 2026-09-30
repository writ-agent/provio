# Postgres ledger store

`PostgresLedgerStore` keeps the PROVIO ledger in a PostgreSQL table so that many
hosts can append to one hash chain: one `provio check` per tool call across a
fleet of runners, several `provio proxy` instances, CI jobs. It implements the
same `LedgerStore` trait as the JSONL and SQLite stores and stores exactly the
same bytes, so `provio verify` gives the same answer for a record whichever store
holds it (Contract 3, ADR-005).

It ships behind the `postgres` cargo feature of `provio-ledger` (and of
`provio-cli`, which passes it through):

```sh
cargo build --release -p provio-cli --features postgres
```

No C toolchain beyond what Rust itself needs: TLS is rustls with the `ring`
provider (not aws-lc-rs, so no CMake or NASM). On Windows, `ring` compiles a
few C files with the MSVC `cl.exe` that comes with the Build Tools Rust's MSVC
toolchain already needs for `link.exe`; on Linux and macOS it uses the system
C compiler that Rust's linker driver uses.

## Setup

PostgreSQL 11 or newer, with a `UTF8` database (checked on connect: any other
server encoding could transcode records, and they must be byte-exact).

A minimal setup, one role that owns and writes the ledger:

```sql
CREATE ROLE provio LOGIN PASSWORD '...';
CREATE DATABASE provio OWNER provio;
```

```sh
export PGPASSWORD='...'          # keeps the password out of argv and configs
provio --ledger 'postgres://provio@db.internal:5432/provio?sslmode=verify-full' verify
```

The first writer to open the ledger (for example the first `provio check`)
creates schema `provio` and the objects below. After that, nothing is ever
created or altered. Read-only commands never create anything, so `provio
verify` before the first append reports "no PROVIO ledger".

### Recommended: separate owner and writer roles

The append-only triggers bind every role **except the table owner and
superusers**, who can disable them. Run agents as a writer role that does not
own the tables:

```sql
CREATE ROLE provio_owner LOGIN PASSWORD '...';   -- used once, to create the tables
CREATE ROLE provio_writer LOGIN PASSWORD '...';  -- what hosts use
CREATE SCHEMA provio AUTHORIZATION provio_owner;
```

Open the ledger once for writing as `provio_owner` to create the tables. For
example, run the first `provio check` with the owner's credentials, or call
`PostgresLedgerStore::open` from Rust. Then grant:

```sql
GRANT USAGE ON SCHEMA provio TO provio_writer;
GRANT SELECT, INSERT ON provio.ledger TO provio_writer;
-- UPDATE is needed only for the append lock (SELECT ... FOR UPDATE);
-- an actual UPDATE of the marker is rejected by its trigger.
GRANT SELECT, UPDATE ON provio.ledger_meta TO provio_writer;
```

For auditors, `GRANT USAGE` on the schema plus `SELECT` on both tables is
enough for `provio verify`, `provio log` and `provio show`.

With this setup, `provio_writer` gets "must be owner" for `ALTER TABLE ...
DISABLE TRIGGER` and `DROP TABLE`, "permission denied" for `UPDATE`, `DELETE`
and `TRUNCATE` on the ledger, and the trigger's "append-only" error for an
`UPDATE` of the marker. We checked each of these against PostgreSQL 16.

## Connection URL

A libpq-style `postgres://` or `postgresql://` URL. Any `--ledger` value that
starts with one of these selects the Postgres store; it is never treated as a
file path. Without the `postgres` feature, such a value is an error (the build
fails closed, as it does for SQLite without the `sqlite` feature).

| Parameter | Meaning |
|---|---|
| `provio_schema` | Schema holding the ledger (default `provio`). `[a-z_][a-z0-9_]*`, not `pg_*`. |
| `provio_table` | Ledger table name (default `ledger`); up to 50 characters. The other objects are named after it (`<table>_meta`, `<table>_append_guard`, ...). |
| `sslmode` | `disable`, `allow`, `prefer` (default), `require`, `verify-ca`, `verify-full`. See [TLS](#tls). |
| `sslrootcert` | PEM file of trusted roots, or `system` for the OS store. |
| anything else | Passed to `tokio-postgres` (`host`, `port`, `user`, `dbname`, `connect_timeout`, `application_name`, `target_session_attrs`, ...). Unknown keys are an error. |

`PGPASSWORD`, `PGSSLMODE` and `PGSSLROOTCERT` are used when the URL does not
set the value. `connect_timeout` defaults to 10 s, and `application_name` to
`provio-ledger`. `sslcert`/`sslkey` (client certificates) are not supported yet
and are rejected rather than ignored.

The store never prints or logs the password. Every error and `Debug`
output names the ledger with the password replaced by `***`.
`provio_ledger::display_ledger(path)` does the same for callers.

Several ledgers can share a schema (`provio_table=team_a`, `provio_table=team_b`).
A schema that contains anything other than PROVIO ledgers is refused. So is a
`<table>` without a marker, a marker from another application, and a marker
with an unknown store version. The store never adds tables to a schema it
does not recognise.

## Schema (store version 1)

```sql
CREATE TABLE provio.ledger_meta (             -- marker + append lock
    singleton     BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    application   TEXT    NOT NULL,         -- 'provio-ledger'
    store_version INTEGER NOT NULL,         -- 1
    ledger_table  TEXT    NOT NULL,         -- 'ledger'
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE provio.ledger (
    idx    BIGINT PRIMARY KEY CHECK (idx >= 0),
    record TEXT   NOT NULL,                 -- the exact JSONL line
    CONSTRAINT ledger_idx_is_record_index
        CHECK (idx = (provio.ledger_json_field(record, 'index'))::bigint)
);
```

- `record` is `TEXT`, never `JSONB`: it holds `serde_json::to_string` of the
  record, byte for byte what the JSONL store writes as a line. (JSONB would
  reorder keys and change whitespace.) A JSONL → Postgres → JSONL copy produces
  an identical file, and the test suite checks this, including records with
  non-ASCII text and `\u0000` escapes.
- `provio.ledger_json_field(record, key)` is an `IMMUTABLE` SQL function that
  returns one top-level field. Postgres' JSON operators reject the escape
  `\u0000` anywhere in a document, and records embed arbitrary tool arguments.
  So the function maps `\u0000` to `\u0001` before parsing. Only `index`,
  `prev_hash` and `record_hash` are ever extracted (digits and hex), so the
  mapping cannot change a compared value.
- Triggers:
  - `ledger_append_guard` (`BEFORE INSERT`, per row) locks the marker row.
    It then requires `idx` to equal the ledger length and the record's
    `prev_hash` to equal the tip's `record_hash` (64 zeros for the genesis
    record).
  - `ledger_no_update`, `ledger_no_delete` and `ledger_no_truncate`
    (per statement) raise `provio ledger is append-only: ... rejected`. The
    same three exist on `ledger_meta`. Statement-level triggers fire even
    when no row matches, and an upsert (`INSERT ... ON CONFLICT DO UPDATE`)
    is rejected by the insert guard before it can update anything.
- The functions run with `search_path = pg_catalog, pg_temp` and use
  schema-qualified names, so another schema's objects cannot be substituted.

## Concurrency model

Many writers on many hosts append to one chain:

1. The writer begins a `READ COMMITTED` transaction and sets
   `lock_timeout` to `provio_ledger::LOCK_TIMEOUT` (10 s).
2. It runs `SELECT store_version FROM provio.ledger_meta WHERE singleton
   FOR UPDATE`. This is the append lock. Every appender takes it before
   reading the tip: the store on any host, and the insert trigger for raw
   SQL writers. It also confirms the marker on every append.
3. It reads the tip (`ORDER BY idx DESC LIMIT 1`). Under `READ COMMITTED`
   each statement takes a new snapshot after the lock was granted, so the
   tip includes every committed append. The store sets the isolation level
   explicitly, so a server default of `REPEATABLE READ` cannot pin a stale
   snapshot.
4. It rejects the record unless `index` equals the ledger length and
   `prev_hash` equals the tip's `record_hash`. Before any of this, without
   the lock, it also rejects a record whose `record_hash` is not the hash of
   its own contents.
5. `INSERT` runs (the trigger re-checks the same rule inside Postgres), then
   `COMMIT`.

A writer whose record was built on a tip that has since moved gets
`ProvioError::Ledger("append rejected: record index N but ledger length is M
...")`. The wording is identical to the JSONL and SQLite stores, so
`provio_ledger::retry_append` / `is_append_race` rebuild the record on the new
tip and try again. A writer that cannot get the lock within 10 s fails closed.

Raw SQL writers are serialized the same way, because the trigger takes the
lock. Two `psql` sessions that insert the same index at the same time cannot
both succeed: the second waits for the first to commit, then sees the new
tip, and the trigger rejects its insert. Even with triggers disabled, the
primary key stops two rows claiming the same index.

Durability: an append is acknowledged after `COMMIT` returns. If the server
default is `synchronous_commit = off`, the store raises it to `on` for its
session, so an acknowledged record survives a database crash (ADR-003). For
synchronous replication, set `synchronous_commit` server-side
(`remote_write`, `remote_apply`); the store never lowers it.

Connections: each store holds one connection. If the server closes it
(restart, failover, idle timeout), reads reconnect and retry once. An append
reconnects and retries only when `BEGIN` itself failed, because nothing can
have been written at that point. A failure later in the transaction is
returned to the caller, and the next call reconnects.

Opening a store checks every link, as the other stores do: index sequence,
`prev_hash` chain, and that every row parses. It pages through the table
(512 rows per query) inside one `REPEATABLE READ READ ONLY` snapshot. This is
linear in ledger size. Full hash verification is `provio verify`
(`verify_postgres`), which also reads one snapshot, never writes, and never
creates anything: verifying a URL with no ledger behind it is an error.

## What the triggers do and do not guarantee

The triggers and constraints are **tamper-evidence support, not prevention**.

They do:

- stop accidental rewrites (a stray `UPDATE`, a migration tool, a
  `TRUNCATE` in the wrong database) and forks (a second record at an existing
  index, a record whose `prev_hash` does not extend the tip);
- bind every role that does not own the tables, as described in
  [Recommended: separate owner and writer roles](#recommended-separate-owner-and-writer-roles).

They do not:

- stop the table owner or a superuser. They can `ALTER TABLE ... DISABLE
  TRIGGER`, drop constraints, `DROP TABLE`, or edit data files directly.
  Event triggers could block some DDL, but they need a superuser to install
  and a superuser can remove them, so the store does not rely on them;
- check `record_hash` inside the database. Computing the canonical payload
  hash in SQL would duplicate `provio-core`. The store checks it before
  inserting, and `provio verify` checks every record;
- protect against a compromised writer that appends well-formed but false
  records. That is what policy, approvals and signed receipts are for.

What survives all of this is the hash chain. Edit, delete or reorder any row
by any means, and `provio verify` reports the exact index where the chain
breaks. Export the ledger (or anchor its receipts) somewhere the database
owner cannot write, and a rewrite of the whole table becomes detectable too.

## TLS

rustls 0.23 with the `ring` provider. `sslmode` follows libpq:

| `sslmode` | TLS | Server certificate |
|---|---|---|
| `disable` | never | — |
| `allow`, `prefer` (default) | if the server offers it | not checked, unless `sslrootcert` is set (then as `verify-ca`) |
| `require` | required | not checked, unless `sslrootcert` is set (then as `verify-ca`) |
| `verify-ca` | required | must chain to a trusted root |
| `verify-full` | required | must chain to a trusted root and match the host name |

Trusted roots come from `sslrootcert` (PEM). When it is absent or `system`,
they come from the operating system's store (`rustls-native-certs`: the
Windows certificate store, macOS keychain, or the Linux CA bundle).

`allow` is treated as `prefer` (tokio-postgres has no plaintext-first mode).
SCRAM channel binding uses the server certificate when TLS is on. Use
`verify-full` for any network you do not control. `require` only encrypts;
it does not prove which server you reached.

## CLI

With a `provio` built with `--features postgres`:

```sh
export PGPASSWORD=...
L='postgres://provio_writer@db.internal/provio?sslmode=verify-full'
provio --ledger "$L" verify
provio --ledger "$L" log
provio --ledger "$L" show <call_id>
provio --ledger "$L" check < request.json
```

Status: `show`, `replay`, `check` and `proxy` pass the URL straight to the
store. `provio ui` is URL-aware. `log`, `verify`, `report` and `doctor` still
check that `--ledger` exists as a file, so they refuse a URL; this is being
fixed. `integrate` and `run` write `--ledger` into generated hook
configuration. Use a URL without a password there, and supply the password
through `PGPASSWORD` (`~/.pgpass` is not read).

Library callers can always use `provio_ledger::verify(url)`,
`sessions(url)` and `find_by_call_id(url, id)` directly.

## Testing

The shared store-generic suite (`crates/provio-ledger/tests/common`) runs
against Postgres. So do the Postgres-specific tests in
`tests/postgres_ledger.rs`, which cover:

- triggers rejecting `UPDATE`, `DELETE`, `TRUNCATE`, forks and upserts;
- raw inserters serialized by the trigger lock;
- concurrent writers across threads and connections, both long-lived and
  one connection per append;
- JSONL → Postgres → JSONL byte equality;
- refusal of foreign, marker-less and future-version schemas;
- read paths that never create anything;
- password redaction;
- reconnect after the server drops the connection;
- `sslmode` handling.

They need a server:

```sh
PROVIO_POSTGRES_URL='postgres://provio:pw@localhost/provio_test' \
  cargo test -p provio-ledger --all-features
```

Each test uses its own schema (`provio_test_<pid>_<n>`). Schemas left behind by
earlier runs are dropped on first use, so point the variable at a scratch
database. Without the variable, every Postgres test prints a skip notice and
passes. Optional: `PROVIO_POSTGRES_TLS=1` checks `sslmode=require` against a
TLS-enabled server, and `PROVIO_POSTGRES_SSLROOTCERT=<pem>` checks `verify-ca`.
