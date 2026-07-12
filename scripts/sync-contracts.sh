#!/usr/bin/env bash
#
# Re-vendor the cross-repo contract the Agent generates from.
#
# The canonical source of truth is
#   ControlPlane-API/contracts/proto/sessionlayer/controlplane/v1/*.proto
# (Design §13, FR-API-1). Because the parent SessionLayer/ folder is NOT a git
# repo, each consumer vendors a byte-identical copy it commits and generates
# from (build.rs) — see CLAUDE.md "Contract vendoring".
#
# This script re-copies those copies WHEN the sibling contracts repo is present
# (local dev / the parent working tree). In CI — which checks out THIS repo
# alone — the source is absent, so the script is a documented no-op and the
# committed vendored copies are authoritative.
#
# Usage:
#   scripts/sync-contracts.sh          # re-vendor if source present
#   scripts/sync-contracts.sh --check  # verify the vendored copies are in sync
set -euo pipefail

cd "$(dirname "$0")/.."

# The vendored proto set. common.proto declares no service; agent.proto (S12)
# declares the AgentIdentity gRPC plane (EnrollAgent / RenewAgentIdentity).
RELS=(
  "sessionlayer/controlplane/v1/common.proto"
  "sessionlayer/controlplane/v1/agent.proto"
)
SRC_ROOT="../ControlPlane-API/contracts/proto"
DST_ROOT="proto"

mode="${1:-sync}"

if [ ! -d "$SRC_ROOT" ]; then
  echo "note: canonical contracts source not found at ${SRC_ROOT}."
  echo "      CI checks out the Agent repo alone; the committed ${DST_ROOT} copies are authoritative."
  echo "      No action taken."
  exit 0
fi

rc=0
for REL in "${RELS[@]}"; do
  SRC="${SRC_ROOT}/${REL}"
  DST="${DST_ROOT}/${REL}"
  if [ ! -f "$SRC" ]; then
    echo "DRIFT: canonical ${SRC} is missing" >&2
    rc=1
    continue
  fi
  case "$mode" in
    --check)
      if diff -u "$DST" "$SRC" >/dev/null 2>&1; then
        echo "in sync: ${DST} matches the canonical ${SRC}"
      else
        echo "DRIFT: ${DST} differs from the canonical ${SRC}" >&2
        diff -u "$DST" "$SRC" >&2 || true
        echo "Run scripts/sync-contracts.sh to re-vendor, then review + commit." >&2
        rc=1
      fi
      ;;
    sync)
      mkdir -p "$(dirname "$DST")"
      cp "$SRC" "$DST"
      echo "vendored: ${SRC} -> ${DST}"
      ;;
    *)
      echo "usage: $0 [--check]" >&2
      exit 2
      ;;
  esac
done

if [ "$mode" = "sync" ]; then
  echo "Review the diff and commit; then re-generate with 'cargo build'."
fi
exit "$rc"
