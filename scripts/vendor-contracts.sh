#!/usr/bin/env bash
#
# Vendor the contracts the Agent generates from, from SessionLayer/Contracts,
# pinned by contracts.lock (tag + resolved commit SHA). Replaces the old
# sibling-checkout-path sync script, which was a silent no-op in CI (CI
# checks out one repo at a time, so a sibling path never exists there). This
# script does a REAL git clone of the pinned tag and verifies the resolved
# commit SHA matches contracts.lock before copying anything, so a moved or
# re-pushed tag can't silently swap content. Git-only: no GitHub API token,
# no hosted registry, works fully offline once the tag is fetched.
#
# Usage:
#   scripts/vendor-contracts.sh          # re-vendor if drifted
#   scripts/vendor-contracts.sh --check  # verify the vendored copies are in sync
set -euo pipefail
cd "$(dirname "$0")/.."

LOCK="contracts.lock"
mode="${1:-sync}"

repo=$(sed -n 's/^repo=//p' "$LOCK")
tag=$(sed -n 's/^tag=//p' "$LOCK")
want_sha=$(sed -n 's/^sha=//p' "$LOCK")

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

git clone --quiet --depth 1 --branch "$tag" "https://github.com/${repo}.git" "$tmp/src"
got_sha="$(git -C "$tmp/src" rev-parse HEAD)"
if [ "$got_sha" != "$want_sha" ]; then
  echo "DRIFT: ${repo}@${tag} resolves to ${got_sha}, but ${LOCK} pins ${want_sha}." >&2
  echo "       The tag may have moved. Refusing to vendor without a reviewed contracts.lock update." >&2
  exit 1
fi

RELS=(
  "sessionlayer/controlplane/v1/common.proto"
  "sessionlayer/controlplane/v1/agent.proto"
  "sessionlayer/agent/v1/wire.proto"
)
SRC_ROOT="$tmp/src/contracts/proto"
DST_ROOT="proto"

EXTRAS=(
  "$tmp/src/contracts/wire/conformance/frames.json|tests/conformance/frames.json"
)

rc=0

sync_one() {
  local SRC="$1" DST="$2"
  if [ ! -f "$SRC" ]; then
    echo "DRIFT: canonical ${SRC} is missing" >&2
    rc=1
    return
  fi
  case "$mode" in
    --check)
      if diff -u "$DST" "$SRC" >/dev/null 2>&1; then
        echo "in sync: ${DST} matches the canonical ${SRC}"
      else
        echo "DRIFT: ${DST} differs from the canonical ${SRC}" >&2
        diff -u "$DST" "$SRC" >&2 || true
        echo "Run scripts/vendor-contracts.sh to re-vendor, then review + commit." >&2
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
}

for REL in "${RELS[@]}"; do
  sync_one "${SRC_ROOT}/${REL}" "${DST_ROOT}/${REL}"
done
for PAIR in "${EXTRAS[@]}"; do
  sync_one "${PAIR%%|*}" "${PAIR##*|}"
done

if [ "$mode" = "sync" ]; then
  echo "Vendored from ${repo}@${tag} (${got_sha:0:12}). Review the diff, regenerate with 'cargo build', and commit."
fi
exit "$rc"
