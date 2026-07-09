#!/usr/bin/env bash
#
# Re-vendor the cross-repo contract the Agent generates from.
#
# The canonical source of truth is
#   ControlPlane-API/contracts/proto/sessionlayer/controlplane/v1/common.proto
# (Design §13, FR-API-1). Because the parent SessionLayer/ folder is NOT a git
# repo, each consumer vendors a byte-identical copy it commits and generates
# from (build.rs) — see CLAUDE.md "Contract vendoring".
#
# This script re-copies that copy WHEN the sibling contracts repo is present
# (local dev / the parent working tree). In CI — which checks out THIS repo
# alone — the source is absent, so the script is a documented no-op and the
# committed vendored copy is authoritative.
#
# Usage:
#   scripts/sync-contracts.sh          # re-vendor if source present
#   scripts/sync-contracts.sh --check  # verify the vendored copy is in sync
set -euo pipefail

cd "$(dirname "$0")/.."

REL="sessionlayer/controlplane/v1/common.proto"
SRC="../ControlPlane-API/contracts/proto/${REL}"
DST="proto/${REL}"

mode="${1:-sync}"

if [ ! -f "$SRC" ]; then
  echo "note: canonical contracts source not found at ${SRC}."
  echo "      CI checks out the Agent repo alone; the committed ${DST} is authoritative."
  echo "      No action taken."
  exit 0
fi

case "$mode" in
  --check)
    if diff -u "$DST" "$SRC" >/dev/null 2>&1; then
      echo "in sync: ${DST} matches the canonical ${SRC}"
    else
      echo "DRIFT: ${DST} differs from the canonical ${SRC}" >&2
      diff -u "$DST" "$SRC" >&2 || true
      echo "Run scripts/sync-contracts.sh to re-vendor, then review + commit." >&2
      exit 1
    fi
    ;;
  sync)
    mkdir -p "$(dirname "$DST")"
    cp "$SRC" "$DST"
    echo "vendored: ${SRC} -> ${DST}"
    echo "Review the diff and commit; then re-generate with 'cargo build'."
    ;;
  *)
    echo "usage: $0 [--check]" >&2
    exit 2
    ;;
esac
