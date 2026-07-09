#!/usr/bin/env bash
#
# Full verification of the non-root container posture: build the image and
# assert the effective runtime USER is non-root (FR-CONN-6 / Design §9.3).
#
# Requires Docker + network (pulls the base images). Not run in the required
# `gate` job to keep it fast and offline-safe — the cheap static equivalent is
# scripts/check-dockerfile-nonroot.sh. Use this locally or in a release
# pipeline: `scripts/verify-nonroot-image.sh`.
set -euo pipefail

cd "$(dirname "$0")/.."
IMAGE="${1:-sessionlayer-agent:verify}"

echo "== building $IMAGE =="
docker build -t "$IMAGE" .

user="$(docker inspect -f '{{.Config.User}}' "$IMAGE")"
echo "image Config.User = '${user}'"

case "${user%%:*}" in
  ""|root|0)
    echo "FAIL: image runs as root (Config.User='${user}')." >&2
    exit 1
    ;;
esac

# Confirm the runtime can execute as that user and is genuinely non-root.
echo "== running '$IMAGE --version-json' =="
docker run --rm "$IMAGE" --version-json

echo "OK: $IMAGE runs as non-root user '${user}'."
