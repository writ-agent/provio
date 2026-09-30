# paas-safety

Human gates for hosting-platform CLIs: Vercel (`vercel`, `vc`), Netlify
(`netlify`, `ntl`), Fly.io (`fly`, `flyctl`), Heroku, Railway, Cloudflare
Wrangler, Supabase and Firebase. Printing a platform API token is refused.

```yaml
version: 1
default: ask
packs: [floor, paas-safety]
```

`floor` already asks before whole-app destroys (`vercel rm`,
`fly apps destroy`, `heroku apps:destroy`, `railway down`,
`firebase projects:delete`) and before any `supabase db reset`. This pack
covers the finer-grained operations on the same platforms.

A CLI is matched at the start of a pipeline segment, after `sudo`, `env`,
`sh -c '…'`, `npx`/`pnpx`/`bunx`/`pnpm dlx`/`npm exec` (with or without
`@version`), and behind `VAR=value` assignments. The subcommand is matched
anywhere after the binary in that segment, so `fly -a shop-prod secrets set`
and `wrangler --env production delete` match. `.exe`, `.cmd` and `.ps1`
suffixes (npm shims on Windows) match too.

| Rule | Verdict | Covers |
|---|---|---|
| `paas-token-print-denied` | deny | `heroku auth:token`, `heroku authorizations:create`, `fly auth token`, `wrangler auth token`, `firebase login:ci`; reading a CLI's stored login with a file tool or `cat`/`grep`/`cp`/`curl`/…: Vercel `com.vercel.cli/auth.json`, Netlify `config.json`, `~/.fly/config.yml`, `~/.supabase/access-token`, Wrangler `config/default.toml`, `~/.railway/config.json`, Firebase `configstore/firebase-tools.json` |
| `paas-env-change-asks` | ask, irreversible | `vercel env add/rm/update`, `netlify env:set/unset/import/clone`, `fly secrets set/unset/import`, `heroku config:set/unset/edit`, `railway variables --set`, `railway variable set/delete`, `wrangler secret put/delete/bulk`, `supabase secrets set/unset`, `firebase functions:config:set/unset`, `functions:secrets:set/destroy/prune`, `apphosting:secrets:set` |
| `paas-secret-read-asks` | ask | `vercel env pull`, `vercel pull`, `netlify env:get`, `netlify env:list --plain/--json`, `heroku config` / `config:get`, `railway variables` (listing) |
| `paas-data-wipe-asks` | ask, irreversible | `heroku pg:reset`, `pg:copy`, `pg:backups:restore`; `supabase db reset --linked/--db-url`; `wrangler d1 execute` with `DROP TABLE/INDEX/VIEW/TRIGGER`, `DELETE FROM` or `TRUNCATE`; `firebase firestore:delete -r/--recursive/--all-collections`, `database:remove` |
| `paas-resource-delete-asks` | ask, irreversible | `vercel domains/dns/certs/alias/project rm`; `netlify sites:delete`; `fly volumes destroy`, `fly machines destroy`; `heroku addons:destroy/remove/detach`, `pg:backups:delete`, `domains:remove/clear`, `pipelines:destroy`, `spaces:destroy`; `railway environment delete`, `railway volume delete`; `wrangler delete` (the Worker), `wrangler r2 bucket / kv namespace / kv bulk / d1 / queues / vectorize / hyperdrive / pages project delete`; `supabase projects/functions/branches/orgs delete`, `supabase storage rm`; `firebase functions:delete`, `hosting:sites:delete`, `firestore:databases:delete`, `extensions:uninstall` |
| `paas-app-offline-asks` | ask | `fly scale count 0`, `heroku ps:scale web=0`, `heroku maintenance:on`, `firebase hosting:disable` |
| `paas-prod-deploy-asks` | ask | `vercel --prod`, `vercel deploy --prod`, `--target production`, `vercel promote`, `vercel rollback`; `netlify deploy --prod` / `--prod-if-unlocked`; `wrangler deploy/publish/versions deploy --env production` (or `prod`), `wrangler rollback`, `wrangler d1 migrations apply --remote`; `firebase deploy -P/--project <name containing prod>`; `git push heroku`; `heroku releases:rollback`; `supabase db push` (targets the linked project unless `--local`; `--dry-run` passes), `supabase migration up --linked` |

Order matters (first match wins): env changes are checked before the
secret-read listing, so `railway variables --set` asks as a change.

## What it deliberately does not cover

- **Which account, team or project a CLI resolves to.** Production is
  recognised only from the command text: `--prod`, `--env production`,
  a Firebase project name containing `prod`. A plain `wrangler deploy`,
  `fly deploy`, `firebase deploy` or `railway up` against a production app
  gets your policy's `default`. Add your own rule naming your app
  (`command matches "fly(ctl)? deploy.*shop-prod"`) if you need that.
- **`vercel build --prod`** builds locally and is not asked; the deploy
  after it is.
- **Render.** Its CLI has no destructive commands worth a rule yet; use
  the dashboard's own confirmation.
- **Single-item deletes** (`wrangler kv key delete`, `firebase
  firestore:delete <doc>` without `-r`, `wrangler r2 object delete`) and
  `netlify env:list` without `--plain`/`--json`: left to the `default`.
- **SQL behind a file or an ORM.** `wrangler d1 execute --file=x.sql` and
  `supabase db push` of a migration that drops a table are judged by the
  command, not by the SQL they carry; pair with `database-safety`.
- **Deploys through CI.** A push that triggers a production pipeline is a
  `git push`; see `github-safety` and `ci-config-guard`.

## Tests

`fixtures/paas-safety.yaml` (73 cases): every rule with `npx`/`pnpm dlx`,
`@version`, `.exe`/`.cmd` and global-flag variants, plus near misses that
must not match (`vercel build --prod`, `vercel deploy`, `netlify deploy`
without `--prod`, `wrangler deploy --env staging`, `fly scale count 10`,
`heroku ps:scale web=2:standard-2x`, `supabase db push --dry-run`,
`wrangler kv key delete`, `git push origin heroku-fix`, a commit message
naming `vercel --prod`, `fly.toml`).
