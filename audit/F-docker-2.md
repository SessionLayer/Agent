# F-docker-2: container base images pinned by mutable tag, not digest
- Severity: info
- Status: Accepted-Risk
- Area: docker

Flagged by both auditors in the Session One red-team pass.

## Issue
`Dockerfile` uses `rust:1.95-bookworm` and `gcr.io/distroless/cc-debian12:nonroot`
— both mutable tags. A registry compromise or tag repoint could swap the base,
and it weakens the NFR-7 reproducibility intent the header advertises.

## Decision: Accepted-Risk (this session)
Real risk is bounded: no image is a CI/release artifact this session, and the
primary non-root control (`USER 65532`, re-asserted explicitly) survives a tag
repoint. The Dockerfile comment already documents that bases SHOULD be pinned by
`@sha256:` digest in the release pipeline.

## Follow-up
Pin both `FROM` lines by digest when the signing/provenance/SBOM release
pipeline lands (NFR-7), tracking the digest bump alongside the toolchain pin.
