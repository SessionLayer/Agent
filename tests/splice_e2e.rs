//! Docker E2E for the Session-Fourteen splice (Design testing rule: real sshd in a
//! container, never the host's).
//!
//! **One container is the node**: it runs the node's real OpenSSH `sshd` AND the
//! real Agent binary as a **non-root** user (uid 65532), exactly as a production
//! node does. The Agent dials **out** to an in-process test Gateway on the host,
//! which signals a dial-back; the Agent splices that connection to its own node's
//! `sshd` on loopback.
//!
//! What this proves that no unit test can:
//!   1. the splice is a live bidirectional pipe into the node's **real** sshd — a
//!      genuine SSH protocol version exchange + KEXINIT crosses it, and then a
//!      **complete certificate-authenticated SSH session** runs a command;
//!   2. **FR-AUD-4** — the node's own sshd log (LogLevel VERBOSE) records the
//!      certificate **key-id**, giving a second audit trail that is independent of
//!      the Agent (the Agent neither writes it nor can suppress it);
//!   3. **FR-CONN-6** — the Agent runs non-root and **cannot read the node's host
//!      key**, which is what makes the Gateway's no-TOFU host verification
//!      meaningful; and a root-run Agent still refuses to start;
//!   4. the confused-deputy defence: a non-loopback `--splice-addr` refuses to boot.
//!
//! Skips cleanly when Docker is unavailable.

mod support;

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use support::gateway::{GwOptions, TestGateway};
use support::MockCp;
use tokio::net::TcpListener;

const AGENT_BIN: &str = env!("CARGO_BIN_EXE_sessionlayer-agent");
const SSHD_IMAGE: &str = "sessionlayer-agent-test-sshd:latest";
const NODE_IMAGE: &str = "sessionlayer-agent-test-node:latest";
const NODE_NAME: &str = "node-e2e";
const CLIENT_IMAGE: &str = "sessionlayer-agent-test-ssh-client:latest";
/// The inner certificate's key-id in the real platform: session_id + identity.
/// The node's sshd logs exactly this string — that is the correlation key.
const KEY_ID: &str = "sess-e2e-14:alice@corp";

fn docker(args: &[&str]) -> (bool, String) {
    let out = Command::new("docker").args(args).output().expect("docker");
    let mut combined = String::from_utf8_lossy(&out.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.success(), combined)
}

fn docker_available() -> bool {
    docker(&["info"]).0
}

fn build_images(repo: &Path) -> bool {
    let sshd_ctx = repo.join("testing/docker/sshd");
    let node_ctx = repo.join("testing/docker/node");
    let client_ctx = repo.join("testing/docker/ssh-client");
    let (ok, log) = docker(&["build", "-q", "-t", SSHD_IMAGE, sshd_ctx.to_str().unwrap()]);
    if !ok {
        eprintln!("skip: cannot build the sshd fixture:\n{log}");
        return false;
    }
    let (ok, log) = docker(&[
        "build",
        "-q",
        "-t",
        NODE_IMAGE,
        "--build-arg",
        &format!("SSHD_IMAGE={SSHD_IMAGE}"),
        node_ctx.to_str().unwrap(),
    ]);
    if !ok {
        eprintln!("skip: cannot build the node image:\n{log}");
        return false;
    }
    let (ok, log) = docker(&[
        "build",
        "-q",
        "-t",
        CLIENT_IMAGE,
        client_ctx.to_str().unwrap(),
    ]);
    if !ok {
        eprintln!("skip: cannot build the ssh-client image:\n{log}");
        return false;
    }
    true
}

/// A free localhost TCP port (bound then released — good enough for a test).
fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

struct Container(String);

impl Drop for Container {
    fn drop(&mut self) {
        let _ = docker(&["rm", "-f", &self.0]);
    }
}

impl Container {
    fn logs(&self) -> String {
        docker(&["logs", &self.0]).1
    }
    fn exec(&self, args: &[&str]) -> (bool, String) {
        let mut full = vec!["exec", self.0.as_str()];
        full.extend_from_slice(args);
        docker(&full)
    }
}

#[cfg_attr(not(unix), ignore)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn agent_splices_a_real_ssh_session_into_the_nodes_own_sshd() {
    if !docker_available() {
        eprintln!("skip: docker unavailable");
        return;
    }
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    if !build_images(repo) {
        return;
    }

    // --- the SSH client container: it owns the user CA and signs the cert -------
    // ssh-keygen never runs on the host (the platform's testing rule).
    let workdir = tempfile::tempdir().unwrap();
    world_writable(workdir.path());
    let client = Container(format!("sl-agent-e2e-client-{}", std::process::id()));
    let (ok, log) = docker(&[
        "run",
        "-d",
        "--rm",
        "--name",
        &client.0,
        "--network",
        "host",
        "-v",
        &format!("{}:/work", workdir.path().display()),
        CLIENT_IMAGE,
    ]);
    assert!(ok, "ssh-client container must start: {log}");

    // A user CA (the platform's session CA, in miniature) and a user key.
    let (ok, log) = client.exec(&[
        "sh",
        "-c",
        "ssh-keygen -q -t ed25519 -N '' -f /work/user_ca -C session-ca && \
         ssh-keygen -q -t ed25519 -N '' -f /work/id -C user",
    ]);
    assert!(ok, "key generation: {log}");

    // Sign a user certificate whose KEY-ID is `session_id + identity` — the exact
    // string the Gateway stamps into the inner-leg certificate, and the exact string
    // the node's sshd will log (FR-AUD-4).
    let (ok, log) = client.exec(&[
        "sh",
        "-c",
        &format!("ssh-keygen -q -s /work/user_ca -I '{KEY_ID}' -n deploy -V -5m:+1h /work/id.pub"),
    ]);
    assert!(ok, "certificate signing: {log}");
    let trusted_user_ca = std::fs::read_to_string(workdir.path().join("user_ca.pub")).unwrap();

    // --- the control plane + the Gateway, in-process on the host ---------------
    let cp = MockCp::start().await;
    let token = "SLDB1.e2e-dial-back-capability";
    let mut gw = TestGateway::start_with(
        &cp,
        GwOptions {
            expect_token: Some(token.to_string()),
            heartbeat_secs: 5,
            ping: true,
            ..Default::default()
        },
    )
    .await;

    // --- the node container: real sshd + the real Agent, NON-ROOT --------------
    let data = tempfile::tempdir().unwrap();
    std::fs::write(data.path().join("ca.pem"), cp.ca_pem()).unwrap();
    world_writable(data.path());
    let sshd_port = free_port();

    let node = Container(format!("sl-agent-e2e-node-{}", std::process::id()));
    let endpoint = gw.endpoint();
    let cp_endpoint = cp.endpoint().to_string();
    let join_token = cp.mint_token();
    let splice_addr = format!("127.0.0.1:{sshd_port}");
    let (ok, log) = docker(&[
        "run",
        "-d",
        "--rm",
        "--name",
        &node.0,
        "--network",
        "host", // the in-process CP + Gateway listen on the host's loopback
        "-e",
        &format!("TRUSTED_USER_CA={}", trusted_user_ca.trim()),
        "-e",
        &format!("SSHD_PORT={sshd_port}"),
        // Enable the OTLP exporter so the hardened run also exercises the export
        // path's syscalls under seccomp (no collector listens → the exporter's
        // connect attempts to 4317 are harmless; 4317 is auto-added to the egress
        // allow-list). Proves the KILL-default allow-list covers OTLP-on too.
        "-e",
        "OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4317",
        "-v",
        &format!("{AGENT_BIN}:/agent:ro"),
        "-v",
        &format!("{}:/data", data.path().display()),
        NODE_IMAGE,
        // everything below is `sessionlayer-agent run ...`
        "--node-name",
        NODE_NAME,
        "--join-method",
        "token",
        "--join-token",
        &join_token,
        "--cp-endpoint",
        &cp_endpoint,
        "--cp-server-name",
        "controlplane",
        "--bootstrap-ca-file",
        "/data/ca.pem",
        "--data-dir",
        "/data",
        "--gateway-endpoint",
        &endpoint,
        "--gateway-server-name",
        gw.server_name(),
        "--splice-addr",
        &splice_addr,
    ]);
    assert!(ok, "node container must start: {log}");

    // The Agent enrolled (S12) and dialled OUT to the Gateway (S14 Part A).
    let hello = gw.await_registration().await;
    assert_eq!(
        hello.component.unwrap().name,
        "SessionLayer Agent",
        "the registering peer must be the real Agent binary"
    );

    // (3) FR-CONN-6: the Agent account cannot read the node's host key. This is the
    // whole reason the agent model does not weaken host verification.
    let (readable, _) = node.exec(&[
        "setpriv",
        "--reuid=65532",
        "--regid=65532",
        "--clear-groups",
        "cat",
        "/etc/ssh/ssh_host_ed25519_key",
    ]);
    assert!(
        !readable,
        "the non-root Agent account MUST NOT be able to read the node's host key"
    );

    // --- the dial-back + the splice -------------------------------------------
    // The Gateway bridges the spliced byte stream to a local TCP listener, exactly
    // as it hands the ByteStream to its inner leg; a real `ssh` client drives it.
    let bridge = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bridge_port = bridge.local_addr().unwrap().port();

    gw.send_dial_back(gw.dial_back_request(NODE_NAME, token))
        .await;
    let splice = gw.await_splice().await;
    assert_eq!(splice.token, token, "the token is presented verbatim");
    let result = gw.await_result().await;
    assert!(result.accepted, "the dial-back must be accepted");

    tokio::spawn(async move {
        let (tcp, _) = bridge.accept().await.expect("ssh client connects");
        splice.bridge(tcp).await;
    });

    // A REAL SSH session — version exchange, KEXINIT, certificate auth, exec —
    // through the Gateway, over the WebSocket splice, into the node's real sshd.
    let ssh = format!(
        "ssh -p {bridge_port} -i /work/id -o CertificateFile=/work/id-cert.pub \
         -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
         -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=20 \
         deploy@127.0.0.1 'echo SPLICE_OK && id -un'"
    );
    let (ok, out) = client.exec(&["sh", "-c", &ssh]);
    assert!(
        ok && out.contains("SPLICE_OK"),
        "a real SSH session must complete over the splice; ssh said:\n{out}\n\nnode log:\n{}",
        node.logs()
    );
    assert!(
        out.contains("deploy"),
        "the session must land as the certificate's principal; got:\n{out}"
    );

    // Part A (S21): the whole splice above ran under the HARDENED binary — the real
    // Agent applied seccomp + Landlock (+ coredump hygiene) before it built its
    // runtime and enrolled, and a full certificate-authenticated SSH session still
    // completed. Prove hardening actually ran (it must never silently skip).
    assert!(
        node.logs().contains("Tier-0 runtime hardening applied"),
        "the Agent must apply Tier-0 hardening; the splice ran under it. node log:\n{}",
        node.logs()
    );

    // Part A (S21): a SECOND session — a real SFTP/SCP file transfer — over the SAME
    // hardened splice, proving file-transfer (not just exec) survives hardening. The
    // Agent splices opaque ciphertext, so exec/shell/sftp share one code path and one
    // syscall surface; this is belt-and-braces evidence for the KILL-default list.
    let bridge2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bridge2_port = bridge2.local_addr().unwrap().port();
    let mut req2 = gw.dial_back_request(NODE_NAME, token);
    req2.request_id = "req-sftp".to_string();
    gw.send_dial_back(req2).await;
    let splice2 = gw.await_splice().await;
    assert_eq!(splice2.token, token);
    assert!(
        gw.await_result().await.accepted,
        "the SFTP dial-back must be accepted"
    );
    tokio::spawn(async move {
        let (tcp, _) = bridge2.accept().await.expect("scp client connects");
        splice2.bridge(tcp).await;
    });

    // scp uses the SFTP protocol by default in modern OpenSSH; the node's sshd has
    // `Subsystem sftp internal-sftp`. Transfer a file and verify it landed.
    let scp = format!(
        "printf 'hardened-transfer-payload\\n' > /work/payload && \
         scp -P {bridge2_port} -i /work/id -o CertificateFile=/work/id-cert.pub \
         -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
         -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=20 \
         /work/payload deploy@127.0.0.1:/tmp/sl-payload"
    );
    let (ok, out) = client.exec(&["sh", "-c", &scp]);
    assert!(
        ok,
        "an SFTP/SCP transfer must complete over the hardened splice; scp said:\n{out}\n\nnode log:\n{}",
        node.logs()
    );
    let (landed, content) = node.exec(&["cat", "/tmp/sl-payload"]);
    assert!(
        landed && content.contains("hardened-transfer-payload"),
        "the transferred file must land on the node over the splice; got:\n{content}\nscp said:\n{out}"
    );

    // (2) FR-AUD-4: the node's OWN sshd log carries the certificate key-id. This
    // trail is written by sshd, not by the Agent — the Agent cannot forge or
    // suppress it, which is precisely what makes it a second, independent record.
    let mut node_log = String::new();
    for _ in 0..40 {
        node_log = node.logs();
        if node_log.contains(KEY_ID) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(
        node_log.contains(KEY_ID),
        "the node's sshd log must record the certificate key-id ({KEY_ID}) for a \
         session that arrived over the splice — the tamper-independent second trail \
         (FR-AUD-4). Log was:\n{node_log}"
    );
    assert!(
        node_log.contains("Accepted publickey")
            || node_log.contains("Accepted certificate")
            || node_log.contains("ID sess-e2e-14"),
        "the sshd log must show the certificate being accepted; log:\n{node_log}"
    );
}

/// The Agent refuses to start as root, and refuses a splice target that is not
/// loopback — both fail closed, in the real binary, in a container.
#[cfg_attr(not(unix), ignore)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agent_refuses_root_and_a_non_loopback_splice_target() {
    if !docker_available() {
        eprintln!("skip: docker unavailable");
        return;
    }
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    if !build_images(repo) {
        return;
    }

    let cp = MockCp::start().await;
    let data = tempfile::tempdir().unwrap();
    std::fs::write(data.path().join("ca.pem"), cp.ca_pem()).unwrap();
    world_writable(data.path());

    let base: Vec<String> = vec![
        "run".into(),
        "--rm".into(),
        "--network".into(),
        "host".into(),
        "-v".into(),
        format!("{AGENT_BIN}:/agent:ro"),
        "-v".into(),
        format!("{}:/data", data.path().display()),
    ];

    let run = |user: &str, splice: &str, token: String| {
        let mut args = base.clone();
        args.extend(["--user".into(), user.into(), "ubuntu:rolling".into()]);
        args.extend([
            "/agent".into(),
            "run".into(),
            "--node-name".into(),
            "node-refuse".into(),
            "--join-method".into(),
            "token".into(),
            "--join-token".into(),
            token,
            "--cp-endpoint".into(),
            cp.endpoint().to_string(),
            "--cp-server-name".into(),
            "controlplane".into(),
            "--bootstrap-ca-file".into(),
            "/data/ca.pem".into(),
            "--data-dir".into(),
            "/data".into(),
            "--splice-addr".into(),
            splice.into(),
            "--once".into(),
        ]);
        let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        docker(&refs)
    };

    // Root is refused BEFORE any credential is loaded (FR-CONN-6, fail closed).
    let (ok, log) = run("0:0", "127.0.0.1:22", cp.mint_token());
    assert!(!ok, "a root Agent must refuse to start; log:\n{log}");
    assert!(
        !data.path().join("identity.json").exists(),
        "a refused root Agent must never persist an identity"
    );

    // A routable splice target is refused at startup: no Gateway can make the Agent
    // a network pivot, and the Agent will not even come up misconfigured (§5).
    let (ok, log) = run("65532:65532", "10.0.0.5:22", cp.mint_token());
    assert!(
        !ok,
        "a non-loopback --splice-addr must refuse to start; log:\n{log}"
    );
    assert!(
        log.contains("loopback"),
        "the refusal must say why (loopback-only); log:\n{log}"
    );
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
