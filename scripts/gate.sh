#!/usr/bin/env bash
#
# SessionLayer Agent — canonical quality gate.
#
# Self-contained: runs the full Rust quality suite and then enforces the audit
# no-defer rule (zero OPEN of ANY severity + no Deferred). This is the single
# entrypoint used by CI (.github/workflows/ci.yml), `make agent-gate`, and the
# ROUND_FINAL idle hook. Exit non-zero => the gate fails.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "== non-root container posture (static) =="
./scripts/check-dockerfile-nonroot.sh

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

echo "== audit findings: zero OPEN of ANY severity + no Deferred =="
# NO-DEFER findings gate (Session 3 §7): block on ANY finding whose Status is
# Open, of ANY severity (critical|high|medium|low|info), AND fail on any finding
# whose Status is Deferred — the no-defer rule bans kicking work down the road.
# Verified-Fixed and Accepted-Risk are the only allowed statuses. Parse
# FAIL-CLOSED: any unparseable/unknown Status blocks. Resolved/accepted findings
# may be moved to audit/closed/ (which this glob does not scan). Only top-level
# audit/F-*.md are scanned.
open=0; deferred=0; bad=0
shopt -s nullglob
for f in audit/F-*.md; do
  st=$(grep -iE '^- *Status:' "$f" | head -1 \
        | sed -E 's/.*Status:[[:space:]]*//I' | tr 'A-Z' 'a-z' | tr -cd 'a-z-')
  case "$st" in
    verified-fixed|accepted-risk) : ;;
    open) echo "OPEN finding: $f"; open=$((open+1)) ;;
    deferred) echo "DEFERRED finding (banned by the no-defer gate): $f"; deferred=$((deferred+1)) ;;
    *) echo "UNPARSEABLE/unknown status ('$st'): $f"; bad=$((bad+1)) ;;
  esac
done
total=$((open + deferred + bad))
if [ "$total" -gt 0 ]; then
  echo "findings gate FAILED: $open open, $deferred deferred, $bad unparseable"; exit 1
fi

echo "gate OK"
