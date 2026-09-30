#!/usr/bin/env bash
# One-time remote setup for Provio.
#
# GitHub organisations cannot be created with `gh`; create `writ-agent` in the
# web UI first: https://github.com/organizations/new
set -euo pipefail

org="${PROVIO_ORG:-writ-agent}"
repo="${PROVIO_REPO_NAME:-provio}"
current_owner="${PROVIO_CURRENT_OWNER:-bhaskargurram-ai}"

echo "== 1. Org check =="
if ! gh api "orgs/$org" --jq .login >/dev/null 2>&1; then
  cat <<EOF
Org '$org' does not exist or this token cannot see it.
Create it in the GitHub web UI, then re-run:
  https://github.com/organizations/new

To transfer the current repo manually:
  gh api repos/$current_owner/$repo/transfer -f new_owner=$org
EOF
  exit 1
fi

echo "== 2. Transfer repo into org (idempotent best-effort) =="
if gh repo view "$org/$repo" >/dev/null 2>&1; then
  echo "repo already exists at $org/$repo"
else
  gh api "repos/$current_owner/$repo/transfer" -f "new_owner=$org"
fi
git remote set-url origin "https://github.com/$org/$repo.git"

echo "== 3. Metadata =="
gh repo edit "$org/$repo" \
  --description 'Authorization and provenance for AI agents. One policy file, one signed ledger, any agent.' \
  --homepage 'https://getprovio.vercel.app' \
  --add-topic ai-agents --add-topic mcp --add-topic policy \
  --add-topic audit --add-topic provenance --add-topic rust --add-topic security

echo "== 4. Branch protection on main =="
gh api "repos/$org/$repo/branches/main/protection" -X PUT \
  -f required_status_checks='{"strict":true,"contexts":["test","claim-discipline"]}' \
  -f required_pull_request_reviews='{"required_approving_review_count":1}' \
  -F enforce_admins=false \
  -f restrictions='null' >/dev/null

cat <<EOF
== 5. Remaining manual steps ==
- crates.io: claim/publish the provio crate name
- npm: claim the provio package name
- domains: provio.dev / provio.sh
- trademark: USPTO/EUIPO software-class search

Done.
EOF