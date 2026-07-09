# F-supply-2: tonic carries ~10 unused transitive crates this session
- Severity: low
- Status: Accepted-Risk
- Area: supply-chain

Flagged by `security-reviewer` in the Session One red-team pass.

## Issue
`tonic` (runtime) has no consumer this session — the Agent's live plane is the
framed wire protocol, not gRPC — yet it pulls ~10 crates into the graph
exclusively via itself (`http`, `http-body(-util)`, `tower-layer`,
`tower-service`, `base64`, `percent-encoding`, `pin-project`, `async-trait`,
`tokio-stream`). The `pub use tonic;` re-export makes the edge *tracked* by
audit/deny but does not reduce the compiled-in attack surface.

## Decision: Accepted-Risk (this session)
`tonic` is an explicit Session One baseline-deps deliverable (toolchain symmetry
with the Gateway/Control Plane and readiness for CP-adjacent codegen). It is
retained per that directive. Mitigations applied: `default-features = false`
drops the heavy transport/hyper stack; the crates are covered by `cargo audit`
(0 advisories) and the exact-match license allow-list; the misleading
"tracked = not surface" justification was corrected in `Cargo.toml`/`src/lib.rs`
to state the real trade-off.

## Follow-up
If a runtime gRPC consumer never materialises, slim to build-only `tonic-build`
in the session that would have used it. Tracked here so the choice is explicit,
not silent.
