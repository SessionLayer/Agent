#!/usr/bin/env bash
#
# Static assertion of the non-root container posture (FR-CONN-6 / Design §9.3).
#
# Verifies, WITHOUT a network pull or a full image build, that the final runtime
# stage of the Dockerfile drops to a dedicated non-root USER and never resets to
# root afterwards. This runs in the required `gate` CI job so a regression that
# reintroduces a root runtime fails the merge deterministically and cheaply. A
# full build-and-`docker inspect` verification is available via
# scripts/verify-nonroot-image.sh (needs Docker + network).
set -euo pipefail

cd "$(dirname "$0")/.."
DOCKERFILE="${1:-Dockerfile}"

# The last USER directive in the file governs the runtime user (the builder
# stage may legitimately run as root; only the final stage ships).
last_user="$(grep -iE '^\s*USER\s+' "$DOCKERFILE" | tail -1 | sed -E 's/^\s*[Uu][Ss][Ee][Rr]\s+//' | tr -d '\r')"

if [ -z "$last_user" ]; then
  echo "FAIL: no USER directive found in $DOCKERFILE — the runtime would default to root." >&2
  exit 1
fi

# Strip any group part (user:group) and any quotes.
user_part="${last_user%%:*}"
user_part="${user_part//\"/}"

case "$user_part" in
  root|0)
    echo "FAIL: final USER in $DOCKERFILE is '$last_user' (root). FR-CONN-6 requires non-root." >&2
    exit 1
    ;;
  "")
    echo "FAIL: final USER in $DOCKERFILE is empty." >&2
    exit 1
    ;;
  *)
    echo "OK: final runtime USER in $DOCKERFILE is '$last_user' (non-root)."
    ;;
esac
