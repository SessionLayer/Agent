#!/usr/bin/env bash
#
# SessionLayer Agent — canonical quality gate.
#
# Self-contained: runs the full Rust quality suite. The single entrypoint used
# by CI (.github/workflows/ci.yml) and locally. Exit non-zero => the gate fails.
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

# Toolchain-pin coupling (NFR-7). A Dependabot bump moved the Dockerfile base to
# rust:1.97-bookworm while every other pin stayed at 1.95.0, and nothing failed:
# the rust:* images ship rustup, the builder copies rust-toolchain.toml, so the
# pinned toolchain is silently fetched over the network instead of coming from
# the image. Only an explicit check catches that.
pinned=$(sed -nE 's/^channel[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' rust-toolchain.toml)
base=$(sed -nE 's/^FROM rust:([0-9]+\.[0-9]+(\.[0-9]+)?)-.*/\1/p' Dockerfile | head -1)
if [ -z "$pinned" ] || [ -z "$base" ]; then
  echo "toolchain-pin gate FAILED: could not parse pins (rust-toolchain.toml='$pinned' Dockerfile='$base')"; exit 1
fi
case "$pinned" in
  "$base"|"$base".*) : ;;
  *) echo "toolchain-pin gate FAILED: Dockerfile builds on rust:$base but rust-toolchain.toml pins $pinned"; exit 1 ;;
esac

echo "gate OK"
