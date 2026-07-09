# SessionLayer Agent container image.
#
# ── Non-root by construction (FR-CONN-6 / Design §9.3, decision D24) ──────────
# The Agent MUST NOT run as root. Node host keys are root-only; a root Agent
# process, if compromised, could read the host key and impersonate the node,
# collapsing the platform's host-identity guarantee from
# "node-root-compromise" back to "agent-process-compromise". This image
# therefore builds the binary as a normal user in a throwaway builder stage and
# runs it in a minimal runtime under a DEDICATED non-root user. There is no
# `USER root` in the final stage and no setuid anywhere.
#
# Reproducibility / provenance (NFR-7): the toolchain is pinned via
# rust-toolchain.toml; base images SHOULD additionally be pinned by digest in a
# release pipeline (left as a tag here so the reference build stays legible).

# ---- Builder ---------------------------------------------------------------
FROM rust:1.95-bookworm AS builder

# protoc is required at build time by tonic-build/prost-build to generate the
# contract types from the vendored common.proto.
RUN apt-get update \
 && apt-get install -y --no-install-recommends protobuf-compiler \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy the manifest set first so dependency compilation caches across source
# edits. build.rs + proto are needed because the build script runs during the
# dependency/codegen step.
COPY Cargo.toml Cargo.lock rust-toolchain.toml build.rs ./
COPY proto ./proto
COPY src ./src

# Build the release binary. cargo runs as the image's default (root) user in the
# BUILDER stage only — nothing from that context is carried into the runtime. The
# binary is already stripped via `[profile.release] strip = "symbols"`.
RUN cargo build --release --locked --bin sessionlayer-agent

# ---- Runtime ---------------------------------------------------------------
# Distroless: no shell, no package manager, minimal attack surface. The
# `:nonroot` variant ships a pre-created unprivileged user (uid/gid 65532) and
# sets it as the default USER; we re-assert it explicitly below so the posture
# is visible and cannot regress silently.
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

LABEL org.opencontainers.image.title="SessionLayer Agent" \
      org.opencontainers.image.description="Per-node outbound connector for the SessionLayer Zero-Trust SSH platform." \
      org.opencontainers.image.licenses="GPL-3.0-only" \
      org.opencontainers.image.source="https://github.com/SessionLayer/Agent"

COPY --from=builder /build/target/release/sessionlayer-agent /usr/local/bin/sessionlayer-agent

# Dedicated, unprivileged, numeric user (works even without /etc/passwd lookups
# and lets Kubernetes enforce runAsNonRoot). 65532 is distroless's `nonroot`.
USER 65532:65532

ENTRYPOINT ["/usr/local/bin/sessionlayer-agent"]
