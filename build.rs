//! Build script: generate Rust types from the vendored contract.
//!
//! The Agent is **contract-first** (Design §13, FR-API-1): it does not
//! hand-write the shared message types, it generates them from a byte-identical
//! vendored copy of the canonical `common.proto` (see `scripts/sync-contracts.sh`
//! and CLAUDE.md "Contract vendoring"). `common.proto` declares no service, so
//! only the prost message types (`ProtocolVersion`, `ComponentInfo`) are
//! emitted — no gRPC client/server stub. The Agent's live plane to the Gateway
//! is the framed wire protocol (`contracts/wire/agent-gateway-v1.md`), not gRPC.

use std::path::Path;

fn main() {
    let proto_root = Path::new("proto");
    let common = proto_root.join("sessionlayer/controlplane/v1/common.proto");

    // Rebuild only when the contract (or this script) changes.
    println!("cargo:rerun-if-changed={}", common.display());
    println!("cargo:rerun-if-changed=build.rs");

    tonic_build::configure()
        // No service in common.proto → no client/server codegen.
        .build_client(false)
        .build_server(false)
        // Emit the generated module into OUT_DIR; included via src/proto.rs.
        .compile_protos(&[common], &[proto_root])
        .expect("failed to generate Rust types from the vendored common.proto");
}
