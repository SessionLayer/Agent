# F-docker-1: static non-root check was stage-unaware (fail-open on multi-stage edits)
- Severity: low
- Status: Verified-Fixed
- Area: docker

Flagged by `redteam-auditor` in the Session One red-team pass.

## Issue
`scripts/check-dockerfile-nonroot.sh` asserted the *textually last* `USER`
directive in the whole Dockerfile was non-root. But `docker build .` ships the
last *stage*, whose effective user is the last `USER` **within that stage**.
Appending a rootful final stage with no `USER` line (or reordering stages) would
leave the runtime running as root while the check still passed on the
builder/runtime `USER 65532` line earlier in the file. This is the only non-root
enforcement in the required `gate` job, so the guard was defeatable.

## Fix
The check now scopes the parse to the final stage (from the last `FROM` line to
EOF) before selecting the last `USER`, and fails closed if the final stage has
**no** `USER` directive (it would inherit the base image's default, typically
root). Additionally, the static check is now invoked from `scripts/gate.sh` so
local runs, `make agent-gate`, and CI all enforce it uniformly. The full
build-and-`docker inspect` verification (`scripts/verify-nonroot-image.sh`) was
also run and confirmed the shipped image runs as `65532:65532`.
