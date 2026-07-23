//! Build script: generate Rust types from the vendored contract.
//!
//! The Agent is **contract-first** (Design §13, FR-API-1): it does not
//! hand-write the shared message types or gRPC stubs, it generates them from a
//! byte-identical vendored copy of the canonical protos (see
//! `scripts/vendor-contracts.sh` and CLAUDE.md "Contract vendoring").
//!
//! - `common.proto` — the shared messages (`ProtocolVersion`, `ComponentInfo`);
//!   no service.
//! - `agent.proto` (S12) — the `AgentIdentity` service (`EnrollAgent`,
//!   `RenewAgentIdentity`). We emit the **client** (the Agent's own enroll/renew
//!   calls) and the **server** (used only by the in-process mock CP in tests) so
//!   the whole plane is exercised end-to-end from generated code.

use std::path::Path;

fn main() {
    let proto_root = Path::new("proto");
    let v1 = "sessionlayer/controlplane/v1";
    let common = proto_root.join(v1).join("common.proto");
    let agent = proto_root.join(v1).join("agent.proto");
    // The Agent<->Gateway wire payloads (S14). Messages only — the protocol is a
    // framed binary transport, not gRPC, so no service is declared.
    let wire = proto_root.join("sessionlayer/agent/v1").join("wire.proto");

    // Rebuild only when a contract file (or this script) changes.
    println!("cargo:rerun-if-changed={}", common.display());
    println!("cargo:rerun-if-changed={}", agent.display());
    println!("cargo:rerun-if-changed={}", wire.display());
    println!("cargo:rerun-if-changed=build.rs");

    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(&[common, agent], &[proto_root.to_path_buf()])
        .expect("failed to generate Rust types from the vendored CP protos");

    // wire.proto imports sessionlayer.controlplane.v1 (ComponentInfo,
    // ProtocolVersion). Generate it in a second pass with those types declared
    // EXTERNAL, so it references the module generated above instead of emitting a
    // second, divergent copy of the shared contract types.
    tonic_prost_build::configure()
        .extern_path(".sessionlayer.controlplane.v1", "crate::proto")
        .compile_protos(&[wire], &[proto_root.to_path_buf()])
        .expect("failed to generate Rust types from the vendored wire proto");
}
