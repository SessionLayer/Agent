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

# `docker build .` (no --target) ships the LAST stage, so the runtime user is
# the last USER directive *within the final stage* — a USER line in an earlier
# stage does not carry over. Scope the parse to the final stage (from the last
# FROM line to EOF) so appending a rootful final stage cannot pass by inheriting
# an earlier stage's USER. Fail closed if the final stage has no USER at all
# (it would inherit the base image's default, typically root).
final_stage_start="$(grep -niE '^\s*FROM\s+' "$DOCKERFILE" | tail -1 | cut -d: -f1)"
if [ -z "$final_stage_start" ]; then
  echo "FAIL: no FROM directive found in $DOCKERFILE." >&2
  exit 1
fi

last_user="$(tail -n +"$final_stage_start" "$DOCKERFILE" \
  | grep -iE '^\s*USER\s+' | tail -1 \
  | sed -E 's/^\s*[Uu][Ss][Ee][Rr]\s+//' | tr -d '\r')"

if [ -z "$last_user" ]; then
  echo "FAIL: the final build stage of $DOCKERFILE has no USER directive — the runtime would default to the base image's user (typically root)." >&2
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
