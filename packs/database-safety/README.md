# database-safety

Human gates for destructive SQL, whether it arrives through a SQL MCP server
(the reference postgres and sqlite servers, MySQL, Supabase, Neon, DBHub and
anything else that passes SQL in `args.sql` or `args.query`) or through a
database CLI (`psql`, `mysql`, `mariadb`, `sqlite3`, `sqlcmd`,
`Invoke-Sqlcmd`, `duckdb`, `clickhouse-client`, …). A single read-only
`SELECT` through MCP is allowed.

| Rule | Verdict | Covers |
|---|---|---|
| `db-drop-asks` | ask, irreversible | `DROP TABLE/DATABASE/SCHEMA/VIEW/INDEX/FUNCTION/ROLE/…` |
| `db-truncate-asks` | ask, irreversible | `TRUNCATE` |
| `db-alter-asks` | ask, irreversible | `ALTER TABLE/DATABASE/SCHEMA/ROLE/USER/…`, `RENAME TABLE` |
| `db-delete-without-where-asks` | ask, irreversible | `DELETE` with no `WHERE`, or `WHERE 1=1` / `WHERE TRUE` |
| `db-update-without-where-asks` | ask, irreversible | `UPDATE … SET` with no `WHERE`, or a tautological one |
| `db-privilege-change-asks` | ask | `GRANT`, `REVOKE`, `CREATE ROLE/USER`, `SET ROLE` |
| `db-write-asks` | ask | any other writing statement (`INSERT`, `UPDATE`, `DELETE`, `MERGE`, `CREATE`, `COPY`, `CALL`, `VACUUM`, …) |
| `db-cli-destructive-asks` | ask, irreversible | a database CLI running DROP/TRUNCATE/ALTER, or DELETE/UPDATE without WHERE |
| `db-cli-drop-tools-asks` | ask, irreversible | `dropdb`, `dropuser`, `mysqladmin drop`, `pg_restore --clean`, `redis-cli FLUSHALL/FLUSHDB`, `mongosh` `dropDatabase()`/`.drop()`/`deleteMany({})` |
| `db-migration-reset-asks` | ask, irreversible | `prisma migrate reset`, `prisma db push --force-reset/--accept-data-loss`, `rails db:drop/reset`, `manage.py flush`, `drizzle-kit drop`, `typeorm schema:drop`, `alembic downgrade base`, `flyway clean`, … |
| `db-select-allowed` | allow | one `SELECT`/`WITH`/`EXPLAIN`/`SHOW`/`DESCRIBE` statement with no write keyword, `INTO`, `FOR UPDATE`, or side-effecting function (`pg_terminate_backend`, `setval`, `pg_read_file`, `dblink`, `LOAD_FILE`, `pg_sleep`, …) |
| `db-schema-introspection-allowed` | allow | `list_tables` / `describe_table` style tools on a database MCP server |

**How keywords are matched.** On the MCP side, statement keywords count only
at the start of a statement (after the beginning of the query or a `;`, plus
whitespace and `--` / `/* */` comments). So `SELECT 'DROP TABLE users'` and a
column named `drop_reason` do not trigger `db-drop-asks`. A query that mixes
statements is judged per statement for DROP/TRUNCATE/ALTER. The WHERE check
looks at the whole query, so a multi-statement batch where one statement has
a WHERE and another does not is caught by `db-write-asks` (ask) rather than
the irreversible rule. The allow never admits more than one statement.

`web.search` and `http` calls are excluded: their `query` field is not SQL.

## What it deliberately does not cover

- **Which database.** provio does not know whether the MCP server or the
  `DATABASE_URL` points at production. Scope with your own rule on `server`
  (for example `server == "postgres-prod"`) if you run several.
- **SQL files and migrations.** `psql -f migrate.sql`, stored procedures and
  ORM code run SQL provio never sees. The CLI allow list is empty on purpose:
  `psql -c "SELECT …"` gets your policy default.
- **Keywords inside SQL string literals on the CLI side.** The SQL there is
  inside shell quoting, so `psql -c "SELECT 'DROP TABLE x'"` asks. That is a
  false ask, never a false allow.
- **NoSQL beyond the few Mongo/Redis wipes listed**, and data exfiltration
  through SELECT (use `secrets-guard` / `pii-redaction` for result masking).

## Use it

Packs are rules you merge into your own `provio.yaml`; provio does not load
`.provio/packs/` automatically.

```bash
provio policy add database-safety   # bundled with provio (a local ./packs/<id> wins); prints the sha256
```

Paste the `rules:` entries into your `provio.yaml`: the ask rules above any
broad allow of your own for your database tools, `db-select-allowed` below
your own denies. Ids are prefixed `db-`. `examples/provio.yaml`'s
`protect-production-db` rule is a narrower version of `db-drop-asks` /
`db-truncate-asks` / `db-alter-asks`; keep one or the other.

```bash
provio doctor --policy provio.yaml
provio policy test --policy provio.yaml --fixtures packs/database-safety/fixtures
```

Fixtures: `fixtures/database-safety.yaml` (37 cases across postgres, mysql,
sqlite, supabase and DBHub tool shapes and the CLIs, with near misses such as
a DROP inside a string literal, `SELECT … FOR UPDATE`, `SELECT … INTO`, two
SELECTs in one call, and a WebSearch about DROP TABLE).
