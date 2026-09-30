# github_setup.ps1 — one-time remote setup for the Provio repo.
# Run AFTER creating the `writ-agent` org in the GitHub web UI
# (orgs cannot be created via API/CLI). Until then the repo lives at
# github.com/bhaskargurram-ai/provio and transfers cleanly (stars, history,
# issues all preserved by GitHub's transfer feature).
$ErrorActionPreference = 'Stop'
$org = 'writ-agent'
$repo = 'provio'

Write-Host '== 1. Org check =='
try {
    gh api "orgs/$org" --jq .login
} catch {
    Write-Host "Org '$org' does not exist yet."
    Write-Host "Create it at https://github.com/organizations/new (name: $org), then re-run."
    Write-Host 'Transferring the existing repo preserves everything:'
    Write-Host "  gh api repos/bhaskargurram-ai/provio/transfer -f new_owner=$org"
    exit 1
}

Write-Host '== 2. Transfer repo into the org =='
gh api repos/bhaskargurram-ai/provio/transfer -f new_owner=$org
git remote set-url origin "https://github.com/$org/$repo.git"

Write-Host '== 3. Repo metadata =='
gh repo edit "$org/$repo" `
    --description 'Authorization and provenance for AI agents. One policy file, one signed ledger, any agent.' `
    --homepage 'https://provio.vercel.app' `
    --add-topic ai-agents --add-topic mcp --add-topic policy `
    --add-topic audit --add-topic provenance --add-topic rust --add-topic security

Write-Host '== 4. Branch protection on main =='
gh api "repos/$org/$repo/branches/main/protection" -X PUT `
    -f required_status_checks='{"strict":true,"contexts":["test","claim-discipline"]}' `
    -f required_pull_request_reviews='{"required_approving_review_count":1}' `
    -F enforce_admins=false

Write-Host '== 5. Remaining manual steps (spec section 2: VERIFY BEFORE YOU COMMIT) =='
Write-Host '  - crates.io:  cargo publish --dry-run to claim the `provio` name'
Write-Host '  - npm:        npm publish (placeholder package) to claim `provio`'
Write-Host '  - domains:    provio.dev / provio.sh'
Write-Host '  - trademark:  USPTO/EUIPO search, software classes'
Write-Host 'Done.'
