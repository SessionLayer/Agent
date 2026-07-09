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

echo "== audit findings: zero unresolved medium+ =="
# Parse FAIL-CLOSED: extract only the first alphabetic token after each label so
# trailing prose (e.g. "medium (needs confirm)") cannot dilute the match, and
# treat any medium+ finding that is not EXPLICITLY resolved — or any finding
# with an unrecognizable severity — as blocking. Resolved/accepted medium+
# findings must be moved to audit/closed/ (which this glob does not scan) so the
# posture stays consistent with the parent-scope idle hook. Only top-level
# audit/F-*.md are scanned.
blocking=0
shopt -s nullglob
for f in audit/F-*.md; do
  sev=$(grep -iE '^- *Severity:' "$f" | head -1 \
        | sed -E 's/.*Severity:[[:space:]]*([A-Za-z]+).*/\1/I' | tr 'A-Z' 'a-z')
  st=$(grep -iE '^- *Status:' "$f" | head -1 \
        | sed -E 's/.*Status:[[:space:]]*([A-Za-z-]+).*/\1/I' | tr 'A-Z' 'a-z')
  case "$sev" in
    critical|high|medium)
      case "$st" in
        verified-fixed|accepted-risk) : ;; # explicitly resolved -> not blocking
        *) echo "BLOCKING $sev (status='${st:-none}'): $f"; blocking=$((blocking + 1)) ;;
      esac
      ;;
    low|info) : ;; # informational -> not blocking
    *)
      echo "MALFORMED finding (severity='${sev:-none}'): $f"
      blocking=$((blocking + 1))
      ;;
  esac
done
if [ "$blocking" -gt 0 ]; then
  echo "$blocking blocking finding(s) — resolve, or move resolved medium+ to audit/closed/"
  exit 1
fi

echo "gate OK"
