//! Telemetry carries correlation, never content (OTEL-CONTRACT §5).
//!
//! Runs the REAL enroll → dial-back → splice path with a capturing `tracing`
//! subscriber, then asserts the captured spans/events contain the `session_id`
//! (correlation works) but NEVER the dial-back token or the join token (no secret
//! reaches any span, attribute, or log). This exercises the actual instrumented
//! code (`agent.enroll` / `agent.dial_back` / `agent.splice`), not a mock of it.

mod support;

use std::io::Write;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sessionlayer_agent::config::{GatewayConfig, GatewayEndpoint};
use sessionlayer_agent::gateway::GatewayClient;
use sessionlayer_agent::identity::{self, IdentityStore, RenewAhead, RenewAheadConfig};
use sessionlayer_agent::join::TokenJoin;
use support::gateway::{GwOptions, TestGateway, GATEWAY_SERVER_NAME};
use support::MockCp;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::EnvFilter;

const CT: Duration = Duration::from_secs(5);
const RT: Duration = Duration::from_secs(10);

/// A `MakeWriter` that appends everything the subscriber writes to a shared buffer.
#[derive(Clone)]
struct CaptureWriter(Arc<Mutex<Vec<u8>>>);
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CaptureWriter {
    type Writer = CaptureGuard;
    fn make_writer(&'a self) -> Self::Writer {
        CaptureGuard(self.0.clone())
    }
}
struct CaptureGuard(Arc<Mutex<Vec<u8>>>);
impl Write for CaptureGuard {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn spawn_echo_listener() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let listener = TcpListener::from_std(listener).unwrap();
        while let Ok((mut sock, _)) = listener.accept().await {
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
    addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_secret_reaches_any_span_log_or_attribute() {
    let buf = Arc::new(Mutex::new(Vec::<u8>::new()));
    // Trace-level for the Agent (every span/event), info for the noisy TLS/gRPC
    // deps — thorough on our own code without drowning in library trace.
    let subscriber = tracing_subscriber::fmt()
        .with_writer(CaptureWriter(buf.clone()))
        .with_env_filter(EnvFilter::new("sessionlayer_agent=trace,info"))
        .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
        .with_ansi(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("install capturing subscriber");

    // The two secrets that must NEVER appear in telemetry.
    const DIALBACK_TOKEN: &str = "SLDB1.SECRET-DIALBACK-do-not-log.signature";
    const SESSION_ID: &str = "sess-nocontent-4242";

    let cp = MockCp::start().await;
    let join_token = cp.mint_token();

    let mut gw = TestGateway::start_with(
        &cp,
        GwOptions {
            expect_token: Some(DIALBACK_TOKEN.to_string()),
            ..Default::default()
        },
    )
    .await;

    // Enroll — exercises the `agent.enroll` span with the join token in scope.
    let dir = tempfile::tempdir().unwrap();
    let store = IdentityStore::open(dir.path()).unwrap();
    let params = cp.channel_params(CT, RT);
    let cred = identity::enroll(
        &store,
        &params,
        &cp.bootstrap_anchors(),
        &TokenJoin::new(join_token.clone()),
        "node-nc",
    )
    .await
    .expect("enroll");
    let renew = RenewAhead::new(
        store,
        RenewAheadConfig {
            renew_ahead_fraction: 2.0 / 3.0,
            renew_jitter_fraction: 0.1,
            retry_backoff: Duration::from_secs(1),
            channel: params,
        },
        cred,
    );

    let splice_addr = spawn_echo_listener();
    let config = GatewayConfig {
        endpoints: vec![GatewayEndpoint {
            url: gw.endpoint(),
            failure_domain: "az-a".to_string(),
            server_name: GATEWAY_SERVER_NAME.to_string(),
        }],
        splice_addr,
        max_concurrent_splices: 32,
        min_control_channels: 1,
        connect_timeout: CT,
        backoff_initial: Duration::from_millis(50),
        backoff_max: Duration::from_millis(200),
        drain_deadline: Duration::from_secs(5),
    };
    let client = GatewayClient::new(config, renew.handle()).unwrap();
    let (stop_tx, task) = {
        let (tx, rx) = watch::channel(false);
        (tx, tokio::spawn(client.run(rx)))
    };
    gw.await_registration().await;

    // Dial back + splice — the `agent.dial_back` / `agent.splice` spans, carrying
    // the session_id, while the token is presented to the Gateway verbatim.
    let mut req = gw.dial_back_request("node-nc", DIALBACK_TOKEN);
    req.session_id = SESSION_ID.to_string();
    gw.send_dial_back(req).await;
    let mut splice = gw.await_splice().await;
    assert_eq!(splice.token, DIALBACK_TOKEN, "token presented verbatim");
    assert!(gw.await_result().await.accepted);
    splice.write(b"SSH-2.0-x\r\n").await;
    let _ = splice.read_exactly(11).await;

    // Let the spans close, then read what the subscriber captured.
    let _ = stop_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(3), task).await;
    tokio::time::sleep(Duration::from_millis(150)).await;

    let captured = String::from_utf8_lossy(&buf.lock().unwrap()).into_owned();
    assert!(
        !captured.is_empty(),
        "the capturing subscriber recorded nothing"
    );

    // Correlation IS present.
    assert!(
        captured.contains(SESSION_ID),
        "session_id must appear for trace correlation; captured:\n{captured}"
    );
    // Secrets are NOT — the whole point of §5.
    assert!(
        !captured.contains(DIALBACK_TOKEN),
        "the dial-back token leaked into telemetry:\n{captured}"
    );
    assert!(
        !captured.contains("SECRET-DIALBACK"),
        "a dial-back-token fragment leaked into telemetry:\n{captured}"
    );
    assert!(
        !captured.contains(join_token.as_str()),
        "the join token leaked into telemetry:\n{captured}"
    );
}
