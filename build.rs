//! Generate Rust types from vendored contract (Design §13, FR-API-1).

use std::path::Path;

fn main() {
    let proto_root = Path::new("proto");
    let v1 = "sessionlayer/controlplane/v1";
    let common = proto_root.join(v1).join("common.proto");
    let agent = proto_root.join(v1).join("agent.proto");
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

    tonic_prost_build::configure()
        .extern_path(".sessionlayer.controlplane.v1", "crate::proto")
        .compile_protos(&[wire], &[proto_root.to_path_buf()])
        .expect("failed to generate Rust types from the vendored wire proto");
}
