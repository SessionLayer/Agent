#!/usr/bin/env bash
#
# SessionLayer Agent — canonical quality gate.
#
# Self-contained: runs the full Rust quality suite and then enforces the audit
# rule (zero OPEN findings of severity medium or higher). This is the single
# entrypoint used by CI (.github/workflows/ci.yml), `make agent-gate`, and the
# ROUND_FINAL idle hook. Exit non-zero => the gate fails.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "== cargo fmt --check =="
cargo fmt --all --check

echo "== cargo clippy (deny warnings) =="
cargo clippy --all-targets --all-features -- -D warnings

echo "== cargo nextest run =="
cargo nextest run --all-features

echo "== cargo audit (deny warnings) =="
cargo audit -D warnings

echo "== cargo deny check =="
cargo deny check

echo "== audit findings: zero open medium+ =="
open=0
shopt -s nullglob
for f in audit/F-*.md; do
  sev=$(grep -iE '^- *Severity:' "$f" | head -1 | sed -E 's/.*Severity:[[:space:]]*//I' | tr 'A-Z' 'a-z' | tr -cd 'a-z')
  st=$(grep -iE '^- *Status:' "$f" | head -1 | sed -E 's/.*Status:[[:space:]]*//I' | tr 'A-Z' 'a-z' | tr -cd 'a-z-')
  case "$sev" in
    critical|high|medium)
      if [ "$st" = open ]; then
        echo "OPEN $sev: $f"
        open=$((open + 1))
      fi
      ;;
  esac
done
if [ "$open" -gt 0 ]; then
  echo "$open open medium+"
  exit 1
fi

echo "gate OK"
