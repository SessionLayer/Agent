//! Docker E2E (Design testing rule): the Agent runs **non-root in a container**
//! and joins a CP (FR-CONN-6, FR-JOIN-1/2). The CP is the in-process mock (real
//! TLS 1.3 mTLS); the Agent runs as a compiled binary inside a container, reached
//! over `--network host`. Two claims:
//!   1. a non-root (uid 65532) container enrolls end-to-end and persists identity;
//!   2. the same binary REFUSES to run as root (uid 0) — fail-closed (Part C).
//!
//! The container base is `ubuntu:rolling` (glibc matches the build host, so the
//! host-built binary runs without an in-container rebuild). The production
//! image's non-root posture is verified separately by `scripts/*nonroot*.sh`
//! (static Dockerfile check in the gate + a `docker inspect` on the real
//! distroless image). Skips cleanly when Docker is unavailable.

mod support;

use std::path::Path;
use std::process::Command;
use std::time::Duration;
use support::MockCp;

const BASE_IMAGE: &str = "ubuntu:rolling";
const AGENT_BIN: &str = env!("CARGO_BIN_EXE_sessionlayer-agent");

fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn ensure_base_image() -> bool {
    Command::new("docker")
        .args(["pull", "-q", BASE_IMAGE])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// `docker run` the agent binary in a container, returning (status, stdout+stderr).
fn run_agent_container(user: &str, data_dir: &Path, endpoint: &str, token: &str) -> (bool, String) {
    let out = Command::new("docker")
        .args([
            "run",
            "--rm",
            "--network",
            "host",
            "--user",
            user,
            "-v",
            &format!("{AGENT_BIN}:/agent:ro"),
            "-v",
            &format!("{}:/data", data_dir.display()),
            BASE_IMAGE,
            "/agent",
            "run",
            "--node-name",
            "node-docker",
            "--join-method",
            "token",
            "--join-token",
            token,
            "--cp-endpoint",
            endpoint,
            "--cp-server-name",
            "controlplane",
            "--bootstrap-ca-file",
            "/data/ca.pem",
            "--data-dir",
            "/data",
            "--once",
        ])
        .output()
        .expect("docker run");
    let mut combined = String::from_utf8_lossy(&out.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.success(), combined)
}

// Multi-thread: the in-process mock CP server runs as a spawned task, and the
// blocking `docker run` is offloaded to the blocking pool (below), so the two
// never starve each other on a single runtime thread.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agent_joins_from_nonroot_container_and_refuses_root() {
    if !docker_available() {
        eprintln!("skip: docker unavailable");
        return;
    }
    if !ensure_base_image() {
        eprintln!("skip: cannot pull {BASE_IMAGE}");
        return;
    }

    let cp = MockCp::start().await;
    // Give the server a beat to accept connections.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let endpoint = cp.endpoint().to_string();

    let dir = tempfile::tempdir().unwrap();
    // The container's uid 65532 must be able to read the CA and write identity.json.
    std::fs::write(dir.path().join("ca.pem"), cp.ca_pem()).unwrap();
    world_writable(dir.path());

    // (1) Non-root container joins end-to-end.
    let token = cp.mint_token();
    let (ok, log) = run_container_blocking("65532:65532", dir.path(), &endpoint, &token).await;
    assert!(ok, "non-root container must join successfully; log:\n{log}");
    assert!(
        dir.path().join("identity.json").exists(),
        "the joined identity must be persisted; log:\n{log}"
    );

    // (2) The same binary REFUSES to run as root (fail-closed, FR-CONN-6).
    let dir2 = tempfile::tempdir().unwrap();
    std::fs::write(dir2.path().join("ca.pem"), cp.ca_pem()).unwrap();
    world_writable(dir2.path());
    let (root_ok, root_log) =
        run_container_blocking("0:0", dir2.path(), &endpoint, &cp.mint_token()).await;
    assert!(
        !root_ok,
        "a root container must be refused (fail-closed); log:\n{root_log}"
    );
    assert!(
        !dir2.path().join("identity.json").exists(),
        "a refused root agent must never persist an identity"
    );
}

/// Run the (blocking) `docker run` on the blocking pool so the mock CP server
/// task keeps running on the runtime worker while the container connects.
async fn run_container_blocking(
    user: &str,
    data_dir: &Path,
    endpoint: &str,
    token: &str,
) -> (bool, String) {
    let (user, data_dir, endpoint, token) = (
        user.to_string(),
        data_dir.to_path_buf(),
        endpoint.to_string(),
        token.to_string(),
    );
    tokio::task::spawn_blocking(move || run_agent_container(&user, &data_dir, &endpoint, &token))
        .await
        .expect("join docker task")
}

#[cfg(unix)]
fn world_writable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path).unwrap().permissions();
    perms.set_mode(0o777);
    std::fs::set_permissions(path, perms).unwrap();
}

#[cfg(not(unix))]
fn world_writable(_path: &Path) {}
