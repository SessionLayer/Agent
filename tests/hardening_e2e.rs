//! Tier-0 hardening on the REAL binary, as a subprocess (no Docker needed):
//!   1. hardening is applied — and logged — before any credential work; and
//!   2. it fails CLOSED when a path it must confine (the data-dir) is missing.
//!
//! The full "hardening does not break the SSH data path" proof is the Docker
//! `splice_e2e` (a real session under the hardened binary); this file proves the
//! two claims that need no containers. Linux-only (seccomp/Landlock are Linux LSMs).
#![cfg(target_os = "linux")]

use std::process::{Command, ExitStatus};

const AGENT_BIN: &str = env!("CARGO_BIN_EXE_sessionlayer-agent");

/// Run the agent binary and return (exit status, combined stdout+stderr). The
/// status distinguishes a clean non-zero exit from a **signal kill** (SIGSYS) —
/// which is what lets this test catch an incomplete seccomp allow-list.
fn run(args: &[&str]) -> (ExitStatus, String) {
    let out = Command::new(AGENT_BIN)
        .args(args)
        .output()
        .expect("spawn the agent binary");
    let mut combined = String::from_utf8_lossy(&out.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status, combined)
}

#[test]
fn hardening_is_applied_and_the_agent_survives_the_filter_to_the_join_path() {
    // A valid data-dir + an unusable bootstrap CA: hardening runs (and logs) first,
    // then the Agent proceeds past the filter into the join path before enrollment
    // fails on the CA. This must NOT be a SIGSYS kill (which would mean the seccomp
    // allow-list is incomplete on the startup path) — assert the process was not
    // signal-killed AND that a post-filter survival marker appears.
    use std::os::unix::process::ExitStatusExt;

    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("ca.pem"),
        b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
    )
    .unwrap();

    let (status, log) = run(&[
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
        status.signal().is_none(),
        "the Agent was signal-killed ({:?}) under its own filter — the seccomp \
         allow-list is incomplete on the startup path; log:\n{log}",
        status.signal()
    );
    assert!(
        !status.success(),
        "must still fail on the bad CA after surviving the filter; log:\n{log}"
    );
    assert!(
        log.contains("Tier-0 runtime hardening applied"),
        "hardening must be applied and logged BEFORE credential work — not skipped; log:\n{log}"
    );
    // Post-filter survival marker: it built the runtime + opened the data-dir + reached
    // the join path, all under seccomp+Landlock, without being killed.
    assert!(
        log.contains("no persisted identity") || log.contains("joining the platform"),
        "the Agent must survive the filter and reach the join path; log:\n{log}"
    );
}

#[test]
fn hardening_fails_closed_when_the_data_dir_is_missing() {
    // The data-dir is the one path Landlock MUST open (RW). If it does not exist,
    // hardening aborts — the Agent never runs unhardened, never enrolls.
    let (status, log) = run(&[
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

    assert!(
        !status.success(),
        "a missing data-dir must fail closed; log:\n{log}"
    );
    assert!(
        log.to_lowercase().contains("hardening") || log.contains("data-dir"),
        "the failure must come from the hardening step; log:\n{log}"
    );
}
