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
    tokio::time::sleep(Duration::from_millis(300)).await;
    let endpoint = cp.endpoint().to_string();

    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("ca.pem"), cp.ca_pem()).unwrap();
    world_writable(dir.path());

    let token = cp.mint_token();
    let (ok, log) = run_container_blocking("65532:65532", dir.path(), &endpoint, &token).await;
    assert!(ok, "non-root container must join successfully; log:\n{log}");
    assert!(
        dir.path().join("identity.json").exists(),
        "the joined identity must be persisted; log:\n{log}"
    );

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
