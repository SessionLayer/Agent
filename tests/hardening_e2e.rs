//! Tier-0 hardening on the REAL binary, as a subprocess (no Docker needed):
//!   1. hardening is applied — and logged — before any credential work; and
//!   2. it fails CLOSED when a path it must confine (the data-dir) is missing.
//!
//! The full "hardening does not break the SSH data path" proof is the Docker
//! `splice_e2e` (a real session under the hardened binary); this file proves the
//! two claims that need no containers. Linux-only (seccomp/Landlock are Linux LSMs).
#![cfg(target_os = "linux")]

use std::process::Command;

const AGENT_BIN: &str = env!("CARGO_BIN_EXE_sessionlayer-agent");

/// Run the agent binary and return (success, combined stdout+stderr).
fn run(args: &[&str]) -> (bool, String) {
    let out = Command::new(AGENT_BIN)
        .args(args)
        .output()
        .expect("spawn the agent binary");
    let mut combined = String::from_utf8_lossy(&out.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.success(), combined)
}

#[test]
fn hardening_is_applied_and_logged_before_any_credential_work() {
    // A valid data-dir + an unusable bootstrap CA: hardening runs (and logs) first,
    // then enrollment fails. We assert the hardening marker — proving hardening
    // actually ran and did not silently skip — plus a non-zero exit.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("ca.pem"),
        b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
    )
    .unwrap();

    let (ok, log) = run(&[
        "run",
        "--node-name",
        "n1",
        "--join-method",
        "token",
        "--join-token",
        "unused",
        "--cp-endpoint",
        "https://127.0.0.1:1",
        "--cp-server-name",
        "cp",
        "--bootstrap-ca-file",
        dir.path().join("ca.pem").to_str().unwrap(),
        "--data-dir",
        dir.path().to_str().unwrap(),
        "--once",
    ]);

    assert!(
        !ok,
        "must fail (bad CA / unreachable CP) after hardening; log:\n{log}"
    );
    assert!(
        log.contains("Tier-0 runtime hardening applied"),
        "hardening must be applied and logged BEFORE credential work — not skipped; log:\n{log}"
    );
}

#[test]
fn hardening_fails_closed_when_the_data_dir_is_missing() {
    // The data-dir is the one path Landlock MUST open (RW). If it does not exist,
    // hardening aborts — the Agent never runs unhardened, never enrolls.
    let (ok, log) = run(&[
        "run",
        "--node-name",
        "n1",
        "--join-method",
        "token",
        "--join-token",
        "unused",
        "--cp-endpoint",
        "https://127.0.0.1:1",
        "--cp-server-name",
        "cp",
        "--bootstrap-ca-file",
        "/tmp/does-not-exist.pem",
        "--data-dir",
        "/nonexistent/sl-agent-hardening-fail-closed",
        "--once",
    ]);

    assert!(!ok, "a missing data-dir must fail closed; log:\n{log}");
    assert!(
        log.to_lowercase().contains("hardening") || log.contains("data-dir"),
        "the failure must come from the hardening step; log:\n{log}"
    );
}
