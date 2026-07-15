//! Agent↔Gateway connectivity integration tests (Session Fourteen), against an
//! in-process **test Gateway** that speaks the frozen wire protocol over a real
//! WSS transport with real mTLS (`support::gateway`). The Agent's identity is a
//! real S12 credential enrolled from the in-process mock CP, so the whole path —
//! enroll, dial out, preface, dial-back, splice — runs as it does in production.
//!
//! Covers: Part A (control channel: register, liveness, reconnect, fail-closed
//! negotiation), Part B (dial-back + splice, node binding, fast-fail, concurrency
//! cap), the SSRF / confused-deputy defence, and the availability invariant that
//! the renew loop is **spawned, not awaited** — a terminal identity outcome must
//! not tear down a live spliced session.

mod support;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use sessionlayer_agent::config::{parse_splice_addr, GatewayConfig};
use sessionlayer_agent::gateway::GatewayClient;
use sessionlayer_agent::identity::{
    self, IdentityStore, RenewAhead, RenewAheadConfig, RenewHandle, RenewOutcome,
};
use sessionlayer_agent::join::TokenJoin;
use sessionlayer_agent::proto::wire::DialBackErrorCode;
use sessionlayer_agent::supervisor;
use support::gateway::{GwOptions, TestGateway, GATEWAY_SERVER_NAME};
use support::MockCp;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

const CT: Duration = Duration::from_secs(5);
const RT: Duration = Duration::from_secs(10);
const NODE: &str = "node-a";

/// A loopback listener that echoes everything it is sent — the test's stand-in for
/// the node's `sshd` (the real one is exercised in the Docker E2E). Returns its
/// address and a counter of accepted connections.
fn spawn_echo_listener() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));

    let count = accepted.clone();
    tokio::spawn(async move {
        let listener = TcpListener::from_std(listener).unwrap();
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            count.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    (addr, accepted)
}

fn gateway_config(gw: &TestGateway, splice_addr: SocketAddr) -> GatewayConfig {
    GatewayConfig {
        endpoints: vec![gw.endpoint()],
        server_name: GATEWAY_SERVER_NAME.to_string(),
        splice_addr,
        max_concurrent_splices: 32,
        connect_timeout: CT,
        backoff_initial: Duration::from_millis(50),
        backoff_max: Duration::from_millis(200),
        drain_deadline: Duration::from_secs(10),
    }
}

/// Enroll a real S12 identity against the mock CP and return the renew driver
/// (whose handle is what the control channel authenticates with).
async fn enrolled_agent(cp: &MockCp, dir: &std::path::Path, node: &str) -> RenewAhead {
    let store = IdentityStore::open(dir).unwrap();
    let params = cp.channel_params(CT, RT);
    let cred = identity::enroll(
        &store,
        &params,
        &cp.bootstrap_anchors(),
        &TokenJoin::new(cp.mint_token()),
        node,
    )
    .await
    .expect("enrollment");

    RenewAhead::new(
        store,
        RenewAheadConfig {
            renew_ahead_fraction: 2.0 / 3.0,
            renew_jitter_fraction: 0.1,
            retry_backoff: Duration::from_secs(1),
            channel: params,
        },
        cred,
    )
}

/// Run just the control channel (no supervisor) until the returned sender is set.
fn spawn_client(
    config: GatewayConfig,
    renew: &RenewAhead,
) -> (watch::Sender<bool>, tokio::task::JoinHandle<()>) {
    let client = GatewayClient::new(config, renew.handle()).expect("valid gateway config");
    let (stop_tx, stop_rx) = watch::channel(false);
    (stop_tx, tokio::spawn(client.run(stop_rx)))
}

// ---------------------------------------------------------------------------
// Part A — the outbound control channel
// ---------------------------------------------------------------------------

#[tokio::test]
async fn agent_dials_out_and_registers_on_the_gateway_control_channel() {
    let cp = MockCp::start().await;
    let mut gw = TestGateway::start(&cp).await;
    let dir = tempfile::tempdir().unwrap();
    let renew = enrolled_agent(&cp, dir.path(), NODE).await;
    let (addr, _) = spawn_echo_listener();

    let (_stop, _task) = spawn_client(gateway_config(&gw, addr), &renew);

    // Registration proves: TCP + TLS 1.3 + mTLS (the Gateway REQUIRES a client cert
    // and verifies it against the internal CA) + the §3 preface all completed.
    let hello = gw.await_registration().await;
    let component = hello.component.expect("HELLO carries ComponentInfo (§3)");
    assert_eq!(component.protocol_max.unwrap().major, 1);
    assert_eq!(component.protocol_min.unwrap().minor, 0);
    assert_eq!(gw.registrations(), 1);
}

#[tokio::test]
async fn agent_answers_ping_with_pong_echoing_the_nonce() {
    let cp = MockCp::start().await;
    let mut gw = TestGateway::start_with(
        &cp,
        GwOptions {
            ping: true,
            heartbeat_secs: 1,
            ..Default::default()
        },
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let renew = enrolled_agent(&cp, dir.path(), NODE).await;
    let (addr, _) = spawn_echo_listener();

    let (_stop, _task) = spawn_client(gateway_config(&gw, addr), &renew);
    gw.await_registration().await;

    // The test Gateway asserts the echoed nonce on every PONG it decodes.
    for _ in 0..40 {
        if gw.pongs() >= 2 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the Agent must answer PING with PONG (got {})", gw.pongs());
}

#[tokio::test]
async fn agent_reconnects_after_the_control_channel_drops() {
    let cp = MockCp::start().await;
    let mut gw = TestGateway::start(&cp).await;
    let dir = tempfile::tempdir().unwrap();
    let renew = enrolled_agent(&cp, dir.path(), NODE).await;
    let (addr, _) = spawn_echo_listener();

    let (_stop, _task) = spawn_client(gateway_config(&gw, addr), &renew);
    gw.await_registration().await;
    assert_eq!(gw.registrations(), 1);

    // Kill the channel from the Gateway side: the Agent must redial (backoff +
    // jitter) and re-run the FULL preface — there is no resumption (§7).
    gw.drop_control().await;
    gw.await_registration().await;
    assert_eq!(
        gw.registrations(),
        2,
        "the Agent must re-register after the channel drops"
    );
}

#[tokio::test]
async fn version_reject_fails_closed_and_the_agent_never_registers() {
    let cp = MockCp::start().await;
    let gw = TestGateway::start_with(
        &cp,
        GwOptions {
            version_reject: true,
            ..Default::default()
        },
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let renew = enrolled_agent(&cp, dir.path(), NODE).await;
    let (addr, _) = spawn_echo_listener();

    let (_stop, _task) = spawn_client(gateway_config(&gw, addr), &renew);

    // FR-HA-9: no downgrade, no guessing. The Agent may retry the connection
    // indefinitely, but it must NEVER complete a preface against a Gateway that
    // rejected its version.
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(
        gw.registrations(),
        0,
        "a VERSION_REJECT must fail closed — the Agent must not register"
    );
    assert_eq!(gw.dialback_attempts(), 0);
}

#[tokio::test]
async fn a_selected_version_we_never_advertised_is_refused() {
    let cp = MockCp::start().await;
    // The Gateway "selects" protocol 2.0 — outside the range the Agent offered.
    let gw = TestGateway::start_with(
        &cp,
        GwOptions {
            bogus_selected: Some((2, 0)),
            ..Default::default()
        },
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let renew = enrolled_agent(&cp, dir.path(), NODE).await;
    let (addr, _) = spawn_echo_listener();

    let (_stop, _task) = spawn_client(gateway_config(&gw, addr), &renew);

    // The Agent must REJECT a version it never advertised and never settle into a
    // usable channel. It tears the connection down and redials (backoff + jitter),
    // so the server sees repeated short-lived preface attempts rather than one live
    // channel — registrations climbs instead of stopping at 1.
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        gw.registrations() >= 2,
        "the Agent must refuse the bogus version and keep redialling, not adopt the \
         channel (registrations={})",
        gw.registrations()
    );
    // And it never sends an application frame under a version it did not advertise.
    assert_eq!(gw.dialback_attempts(), 0);
}

// ---------------------------------------------------------------------------
// Part B — dial-back + splice
// ---------------------------------------------------------------------------

#[tokio::test]
async fn agent_dials_back_and_splices_bytes_to_its_local_target() {
    let cp = MockCp::start().await;
    let token = "SLDB1.opaque-capability.signature";
    let mut gw = TestGateway::start_with(
        &cp,
        GwOptions {
            expect_token: Some(token.to_string()),
            ..Default::default()
        },
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let renew = enrolled_agent(&cp, dir.path(), NODE).await;
    let (splice_addr, accepted) = spawn_echo_listener();

    let (_stop, _task) = spawn_client(gateway_config(&gw, splice_addr), &renew);
    gw.await_registration().await;

    gw.send_dial_back(gw.dial_back_request(NODE, token)).await;
    let mut splice = gw.await_splice().await;

    // The token was presented VERBATIM (it is opaque to the Agent).
    assert_eq!(splice.token, token);

    // The fast-fail result arrives at splice-live, not at session end (§5).
    let result = gw.await_result().await;
    assert!(result.accepted, "the dial-back must be reported accepted");
    assert_eq!(result.request_id, "req-1");

    // Bytes cross the splice in both directions, opaque to the Agent.
    let payload = b"SSH-2.0-SessionLayer\r\n";
    splice.write(payload).await;
    let echoed = splice.read_exactly(payload.len()).await;
    assert_eq!(
        echoed, payload,
        "the splice must be a live bidirectional pipe"
    );
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        1,
        "the splice must land on the LOCALLY CONFIGURED target"
    );
}

#[tokio::test]
async fn agent_refuses_a_dial_back_for_a_node_that_is_not_its_own() {
    let cp = MockCp::start().await;
    let mut gw = TestGateway::start(&cp).await;
    let dir = tempfile::tempdir().unwrap();
    let renew = enrolled_agent(&cp, dir.path(), NODE).await;
    let (splice_addr, accepted) = spawn_echo_listener();

    let (_stop, _task) = spawn_client(gateway_config(&gw, splice_addr), &renew);
    gw.await_registration().await;

    // A Gateway must not be able to task this Agent for another node: the binding is
    // the dNSName SAN of the Agent's OWN certificate, which the CP stamped.
    gw.send_dial_back(gw.dial_back_request("some-other-node", "t"))
        .await;

    let result = gw.await_result().await;
    assert!(!result.accepted);
    assert_eq!(result.error, DialBackErrorCode::Refused as i32);
    assert_eq!(
        gw.dialback_attempts(),
        0,
        "a refusal must happen BEFORE anything is dialled"
    );
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        0,
        "a refused request must never touch the node's sshd"
    );
}

#[tokio::test]
async fn a_failed_local_dial_fast_fails_so_the_gateway_need_not_wait() {
    let cp = MockCp::start().await;
    let mut gw = TestGateway::start(&cp).await;
    let dir = tempfile::tempdir().unwrap();
    let renew = enrolled_agent(&cp, dir.path(), NODE).await;

    // A loopback port with nothing listening: the node's sshd is "down".
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let dead_addr = closed.local_addr().unwrap();
    drop(closed);

    let (_stop, _task) = spawn_client(gateway_config(&gw, dead_addr), &renew);
    gw.await_registration().await;

    gw.send_dial_back(gw.dial_back_request(NODE, "t")).await;

    let result = gw.await_result().await;
    assert!(!result.accepted);
    assert_eq!(
        result.error,
        DialBackErrorCode::LocalDialFailed as i32,
        "the Gateway must learn the node's sshd is down immediately (§7.1 'node offline')"
    );
}

#[tokio::test]
async fn dial_backs_beyond_the_concurrency_cap_are_refused_not_queued() {
    let cp = MockCp::start().await;
    let mut gw = TestGateway::start(&cp).await;
    let dir = tempfile::tempdir().unwrap();
    let renew = enrolled_agent(&cp, dir.path(), NODE).await;
    let (splice_addr, _) = spawn_echo_listener();

    let mut config = gateway_config(&gw, splice_addr);
    config.max_concurrent_splices = 1;
    let (_stop, _task) = spawn_client(config, &renew);
    gw.await_registration().await;

    gw.send_dial_back(gw.dial_back_request(NODE, "t1")).await;
    let _live = gw.await_splice().await;
    let first = gw.await_result().await;
    assert!(first.accepted);

    // The cap is a refusal, not a queue: an Agent must not accumulate unbounded work.
    let mut second = gw.dial_back_request(NODE, "t2");
    second.request_id = "req-2".to_string();
    gw.send_dial_back(second).await;

    let result = gw.await_result().await;
    assert_eq!(result.request_id, "req-2");
    assert!(!result.accepted);
    assert_eq!(result.error, DialBackErrorCode::Refused as i32);
}

// ---------------------------------------------------------------------------
// The SSRF / confused-deputy defence (contract §5)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_splice_target_is_never_taken_from_the_wire() {
    let cp = MockCp::start().await;
    let mut gw = TestGateway::start(&cp).await;
    let dir = tempfile::tempdir().unwrap();
    let renew = enrolled_agent(&cp, dir.path(), NODE).await;

    // Two listeners: the one the Agent is CONFIGURED to splice to, and a "victim"
    // the hostile Gateway would love to reach. DIAL_BACK_REQUEST carries no target
    // field at all, so there is structurally nothing to point at the victim — and
    // the Agent only ever connects to its own configured address.
    let (configured, configured_hits) = spawn_echo_listener();
    let (victim, victim_hits) = spawn_echo_listener();
    assert_ne!(configured, victim);

    let (_stop, _task) = spawn_client(gateway_config(&gw, configured), &renew);
    gw.await_registration().await;

    gw.send_dial_back(gw.dial_back_request(NODE, "t")).await;
    let mut splice = gw.await_splice().await;
    splice.write(b"ping").await;
    assert_eq!(splice.read_exactly(4).await, b"ping");

    assert_eq!(configured_hits.load(Ordering::SeqCst), 1);
    assert_eq!(
        victim_hits.load(Ordering::SeqCst),
        0,
        "no Gateway may redirect the Agent's splice — it is not a network pivot"
    );
}

#[tokio::test]
async fn a_non_loopback_splice_target_refuses_to_start() {
    // The confused-deputy defence is enforced at startup, before anything is dialled:
    // a routable target, the wildcard, and a hostname are all refused.
    for bad in [
        "10.0.0.5:22",
        "0.0.0.0:22",
        "192.168.1.10:22",
        "localhost:22",
    ] {
        assert!(
            parse_splice_addr(bad).is_err(),
            "{bad} must be refused at startup"
        );
    }
    assert!(parse_splice_addr("127.0.0.1:22").is_ok());

    // And no construction path bypasses it: GatewayClient::new validates too.
    let cp = MockCp::start().await;
    let gw = TestGateway::start(&cp).await;
    let dir = tempfile::tempdir().unwrap();
    let renew = enrolled_agent(&cp, dir.path(), NODE).await;

    let mut config = gateway_config(&gw, "127.0.0.1:22".parse().unwrap());
    config.splice_addr = "10.0.0.5:22".parse().unwrap();
    assert!(
        GatewayClient::new(config, renew.handle()).is_err(),
        "a non-loopback splice target must fail closed even if it skips the parser"
    );
}

#[tokio::test]
async fn a_hostile_dial_back_endpoint_cannot_be_used_as_a_pivot() {
    let cp = MockCp::start().await;
    let mut gw = TestGateway::start(&cp).await;
    let dir = tempfile::tempdir().unwrap();
    let renew = enrolled_agent(&cp, dir.path(), NODE).await;
    let (splice_addr, splice_hits) = spawn_echo_listener();

    let (_stop, _task) = spawn_client(gateway_config(&gw, splice_addr), &renew);
    gw.await_registration().await;

    // `dial_back_endpoint` IS attacker-controlled. Two layers stop it being a pivot:
    // (1) the Agent only dials back to a Gateway in its CONFIGURED set, so an
    // arbitrary host:port is refused BEFORE any connect (no TCP touch at all); and
    // (2) even a configured endpoint is TLS + mTLS verified against the pinned CA
    // with the configured server name. Here the hostile endpoint is unconfigured, so
    // layer (1) fires: nothing is dialled.
    let (victim, victim_hits) = spawn_echo_listener();
    let mut req = gw.dial_back_request(NODE, "t");
    req.dial_back_endpoint = format!("wss://{victim}");
    gw.send_dial_back(req).await;

    let result = gw.await_result().await;
    assert!(!result.accepted);
    assert_eq!(
        result.error,
        DialBackErrorCode::Refused as i32,
        "an endpoint outside the configured Gateway set must be refused before dialling"
    );
    // Neither the node's sshd nor the victim was ever touched — the Agent is not a
    // network-connect primitive for a hostile Gateway.
    assert_eq!(splice_hits.load(Ordering::SeqCst), 0);
    assert_eq!(
        victim_hits.load(Ordering::SeqCst),
        0,
        "an unconfigured dial-back endpoint must never be connected to"
    );
}

// ---------------------------------------------------------------------------
// Availability: the renew loop is SPAWNED, not awaited (contract §7)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_terminal_identity_outcome_drains_live_splices_instead_of_killing_them() {
    let cp = MockCp::start().await;
    let token = "SLDB1.opaque";
    let mut gw = TestGateway::start_with(
        &cp,
        GwOptions {
            expect_token: Some(token.to_string()),
            ..Default::default()
        },
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let renew = enrolled_agent(&cp, dir.path(), NODE).await;
    let handle: RenewHandle = renew.handle();
    let (splice_addr, _) = spawn_echo_listener();

    let config = gateway_config(&gw, splice_addr);
    let drain_deadline = config.drain_deadline;
    let client = GatewayClient::new(config, renew.handle()).unwrap();

    // The supervisor runs the identity loop and the connectivity role concurrently.
    // If the renew loop were awaited inline (the S12 shape), the control channel
    // would never even start.
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let sup = tokio::spawn(supervisor::run(
        renew,
        Some(client),
        drain_deadline,
        async move {
            let _ = shutdown_rx.await;
        },
    ));

    gw.await_registration().await;
    gw.send_dial_back(gw.dial_back_request(NODE, token)).await;
    let mut splice = gw.await_splice().await;
    splice.write(b"before").await;
    assert_eq!(splice.read_exactly(6).await, b"before");

    // Now force a TERMINAL identity outcome: the CP locks the node, and the manual
    // trigger makes the renew loop discover it immediately. This stops the Agent
    // taking NEW work — but someone's live SSH session is mid-flight.
    cp.lock_node(NODE);
    handle.trigger().await;

    // The live splice MUST survive: a user's session is not collateral damage of a
    // credential problem. It keeps carrying bytes while the Agent drains.
    for i in 0..5 {
        let msg = format!("still-alive-{i}");
        splice.write(msg.as_bytes()).await;
        assert_eq!(
            splice.read_exactly(msg.len()).await,
            msg.as_bytes(),
            "a terminal identity outcome must NOT tear down a live spliced session"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Ending the session releases the drain latch; the process then exits with the
    // S12 exit-code contract intact (RepairNeeded = exit 4), NOT a clean 0.
    splice.close().await;
    let outcome = tokio::time::timeout(Duration::from_secs(25), sup)
        .await
        .expect("the supervisor must finish once live splices have drained")
        .expect("supervisor task");
    assert_eq!(
        outcome,
        RenewOutcome::RepairNeeded,
        "the S12 terminal exit-code contract must survive the S14 restructure"
    );
    drop(shutdown_tx);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_clean_shutdown_still_returns_the_s12_shutdown_outcome() {
    let cp = MockCp::start().await;
    let gw = TestGateway::start(&cp).await;
    let dir = tempfile::tempdir().unwrap();
    let renew = enrolled_agent(&cp, dir.path(), NODE).await;
    let (splice_addr, _) = spawn_echo_listener();

    let config = gateway_config(&gw, splice_addr);
    let client = GatewayClient::new(config, renew.handle()).unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let sup = tokio::spawn(supervisor::run(
        renew,
        Some(client),
        Duration::from_secs(5),
        async move {
            let _ = shutdown_rx.await;
        },
    ));

    tokio::time::sleep(Duration::from_millis(300)).await;
    let _ = shutdown_tx.send(());

    let outcome = tokio::time::timeout(Duration::from_secs(15), sup)
        .await
        .expect("clean shutdown must not hang")
        .unwrap();
    assert_eq!(outcome, RenewOutcome::Shutdown);
}

/// The dial-back connection must present the SAME mTLS identity as the control
/// channel: the test Gateway asserts a client certificate on every connection, so
/// a dial-back that reaches STREAM_OPEN has proven it. This test additionally shows
/// a raw TCP connection to the Gateway (no client cert) cannot become a dial-back.
#[tokio::test]
async fn an_unauthenticated_connection_cannot_reach_the_dial_back_role() {
    let cp = MockCp::start().await;
    let gw = TestGateway::start(&cp).await;
    let addr = gw.endpoint().replace("wss://", "");

    let mut tcp = TcpStream::connect(&addr).await.expect("tcp connects");
    // Plaintext bytes at a TLS listener: the rustls server treats the HTTP request
    // as a malformed ClientHello and answers with a TLS **alert** record (content
    // type 0x15), then closes — it never speaks HTTP and never upgrades to a
    // WebSocket, so no dial-back role is reachable and the node is never touched.
    let _ = tcp
        .write_all(b"GET /agent/v1/dialback HTTP/1.1\r\n\r\n")
        .await;
    let mut buf = [0u8; 64];
    let n = tcp.read(&mut buf).await.unwrap_or(0);
    let got = &buf[..n];
    assert!(
        n == 0 || got[0] == 0x15,
        "a non-TLS peer must get only a TLS alert or nothing — never an HTTP/WS \
         response (got {n} bytes: {got:02x?})"
    );
    assert!(
        !got.windows(4).any(|w| w == b"HTTP"),
        "the Gateway must not speak HTTP to a plaintext peer"
    );
    assert_eq!(
        gw.dialback_attempts(),
        0,
        "a non-mTLS peer must never reach the dial-back role"
    );
}
