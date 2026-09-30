#!/bin/sh
# The provio Claude Code plugin hook: hand the hook payload (stdin) to
# `provio check --format claude-code`, which answers in Claude Code's hook
# format and records the decision.
#
# Policy: the project's provio.yaml (or a pre-rename writ.yaml) when there
# is one, with its ledger in the project's .provio/; otherwise the built-in
# starter policy (the floor and secrets-guard packs), recorded to
# ~/.provio/ledger.jsonl.
#
# Fails closed: without the provio binary the tool call is blocked (exit 2)
# with an install hint, never silently let through.

provio="${PROVIO_BIN:-}"
if [ -z "$provio" ]; then
  for c in provio "$HOME/.provio/bin/provio" "$HOME/.local/bin/provio"; do
    if command -v "$c" >/dev/null 2>&1; then
      provio="$c"
      break
    fi
  done
fi
if [ -z "$provio" ]; then
  echo "provio plugin: the provio binary is not installed, so this tool call is blocked (fail closed). Install it with 'pip install provio' or 'npm install -g provio', or disable the plugin." >&2
  exit 2
fi

dir="${CLAUDE_PROJECT_DIR:-$PWD}"
if [ -f "$dir/provio.yaml" ]; then
  exec "$provio" --policy "$dir/provio.yaml" --ledger "$dir/.provio/ledger.jsonl" \
    check --format claude-code --ask defer
elif [ -f "$dir/writ.yaml" ]; then
  exec "$provio" --policy "$dir/writ.yaml" --ledger "$dir/.writ/ledger.jsonl" \
    check --format claude-code --ask defer
else
  exec "$provio" --policy "$dir/provio.yaml" \
    check --format claude-code --ask defer --if-no-policy starter
fi
