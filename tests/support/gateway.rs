//! In-process **test Gateway**: a server-side implementation of the frozen
//! Agent↔Gateway wire protocol (`contracts/wire/agent-gateway-v1.md`) over a real
//! `wss://` listener with real mTLS.
//!
//! It is deliberately a *separate* implementation of the protocol, not a reuse of
//! the Agent's: the frame decoder below is written from the §2/§4 tables, and the
//! Agent's own decoder enforces the agent-inbound direction and would reject the
//! Agent's own frames. A test that drove the code under test with itself would
//! prove nothing about the wire.
//!
//! TLS: a serverAuth leaf (SAN `gateway`) issued by the **same** internal CA the
//! mock CP runs, so the Agent's `Credential.ca_chain_der` is the trust anchor for
//! the Gateway exactly as in production; client certificates are **required** and
//! verified against that CA, so a connection that reaches the preface has already
//! proven the Agent's mTLS identity.
#![allow(dead_code)]
// The tungstenite `accept_hdr_async` callback must return `Result<Response,
// ErrorResponse>`; the large `Err` variant is the library's type, not ours.
#![allow(clippy::result_large_err)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use prost::Message as _;
use sessionlayer_agent::gateway::wire::{encode, encode_msg, MsgType, FRAME_HEADER_LEN};
use sessionlayer_agent::proto::wire::{
    AgentHello, DialBackAccept, DialBackAuth, DialBackRequest, DialBackResult, GatewayHelloAck,
    Ping, Pong, StreamClose, StreamCloseReason, VersionReject, WireError, WireErrorCode,
};
use sessionlayer_agent::proto::{ComponentInfo, ProtocolVersion};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

use super::MockCp;

/// The Gateway's enrolled name — the dNSName SAN of its serverAuth leaf, and the
/// name the Agent is told to verify.
pub const GATEWAY_SERVER_NAME: &str = "gateway";

const CONTROL_PATH: &str = "/agent/v1/control";
const DIALBACK_PATH: &str = "/agent/v1/dialback";

type ServerWs = WebSocketStream<tokio_rustls::server::TlsStream<TcpStream>>;

/// A frame as the server sees it (§2). Independent of the Agent's decoder.
#[derive(Debug, Clone)]
pub struct Frame {
    pub version: u8,
    pub ty: u8,
    pub payload: Vec<u8>,
}

fn decode_frame(bytes: &[u8]) -> Option<Frame> {
    if bytes.len() < FRAME_HEADER_LEN {
        return None;
    }
    let declared = u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]) as usize;
    let payload = &bytes[FRAME_HEADER_LEN..];
    if declared != payload.len() {
        return None;
    }
    Some(Frame {
        version: bytes[0],
        ty: bytes[1],
        payload: payload.to_vec(),
    })
}

/// How this Gateway should behave — each knob exists to drive one fail-closed path.
#[derive(Debug, Clone)]
pub struct GwOptions {
    pub heartbeat_secs: u32,
    pub max_frame_bytes: u32,
    /// Answer HELLO with VERSION_REJECT (§3): the Agent must fail closed.
    pub version_reject: bool,
    /// Select a version the Agent never advertised: it must refuse this too.
    pub bogus_selected: Option<(u32, u32)>,
    /// Send PING at the heartbeat cadence and expect PONG.
    pub ping: bool,
    /// Refuse any DIAL_BACK_AUTH whose token is not this one.
    pub expect_token: Option<String>,
    /// The dNSName SAN this Gateway's serverAuth leaf carries (its enrolled name).
    /// Defaults to `GATEWAY_SERVER_NAME`; set distinct values per instance to
    /// exercise the real diverse-gateway case where SANs differ per gateway.
    pub server_name: Option<String>,
}

impl Default for GwOptions {
    fn default() -> Self {
        Self {
            heartbeat_secs: 1,
            max_frame_bytes: 64 * 1024,
            version_reject: false,
            bogus_selected: None,
            ping: false,
            expect_token: None,
            server_name: None,
        }
    }
}

/// What the test observes happening on the wire.
#[derive(Debug)]
pub enum GwEvent {
    /// A control channel completed the preface (§3) — the Agent is registered.
    Registered(Box<AgentHello>),
    /// A control channel ended.
    ControlClosed,
    /// A DIAL_BACK_RESULT arrived on the control channel (§5 fast-fail).
    Result(DialBackResult),
    /// A dial-back connection authenticated and reached STREAM_OPEN: the splice is
    /// live and the byte stream is now the test's to drive.
    Spliced(Box<DialBackConn>),
    /// A dial-back connection was refused (bad token) or died before STREAM_OPEN.
    DialBackFailed(String),
}

enum Cmd {
    Send(Vec<u8>),
    Close,
}

/// A live splice, from the Gateway's side. The bytes are opaque — in production
/// they are the SSH session the Gateway owns end-to-end with the node's sshd.
pub struct DialBackConn {
    ws: ServerWs,
    version: u8,
    /// The token the Agent presented, verbatim.
    pub token: String,
    pub request_id: String,
}

impl std::fmt::Debug for DialBackConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DialBackConn")
            .field("request_id", &self.request_id)
            .finish_non_exhaustive()
    }
}

impl DialBackConn {
    /// Push bytes toward the node's sshd (STREAM_DATA).
    pub async fn write(&mut self, data: &[u8]) {
        let frame = encode(self.version, MsgType::StreamData, data);
        self.ws
            .send(Message::Binary(frame.into()))
            .await
            .expect("send STREAM_DATA");
    }

    /// The next chunk of bytes coming back from the node's sshd, or `None` at close.
    pub async fn read(&mut self) -> Option<Vec<u8>> {
        loop {
            match self.ws.next().await {
                Some(Ok(Message::Binary(b))) => {
                    let frame = decode_frame(&b).expect("well-formed frame");
                    assert_eq!(frame.version, self.version, "frame VER must be negotiated");
                    match frame.ty {
                        t if t == MsgType::StreamData as u8 => return Some(frame.payload),
                        t if t == MsgType::StreamClose as u8 => return None,
                        other => panic!("unexpected type {other:#04x} on a live splice"),
                    }
                }
                Some(Ok(_)) => continue,
                Some(Err(_)) | None => return None,
            }
        }
    }

    /// Read until `want` bytes have arrived (or the splice closes).
    pub async fn read_exactly(&mut self, want: usize) -> Vec<u8> {
        let mut got = Vec::new();
        while got.len() < want {
            match self.read().await {
                Some(chunk) => got.extend_from_slice(&chunk),
                None => break,
            }
        }
        got
    }

    /// Bridge the splice to a TCP stream, so a real `ssh` client on the other end
    /// of `tcp` drives the node's real sshd through the Agent — which is exactly
    /// what the Gateway does with the ByteStream it is handed at STREAM_OPEN.
    pub async fn bridge(self, tcp: TcpStream) {
        let (mut sink, mut stream) = self.ws.split();
        let (mut rd, mut wr) = tcp.into_split();
        let version = self.version;

        let to_client = tokio::spawn(async move {
            while let Some(Ok(msg)) = stream.next().await {
                let Message::Binary(b) = msg else { continue };
                let Some(frame) = decode_frame(&b) else { break };
                if frame.ty == MsgType::StreamData as u8 {
                    if wr.write_all(&frame.payload).await.is_err() {
                        break;
                    }
                } else if frame.ty == MsgType::StreamClose as u8 {
                    break;
                }
            }
            let _ = wr.shutdown().await;
        });

        let to_node = tokio::spawn(async move {
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                match rd.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let frame = encode(version, MsgType::StreamData, &buf[..n]);
                        if sink.send(Message::Binary(frame.into())).await.is_err() {
                            break;
                        }
                    }
                }
            }
            let close = encode_msg(
                version,
                MsgType::StreamClose,
                &StreamClose {
                    reason: StreamCloseReason::Eof as i32,
                },
            );
            let _ = sink.send(Message::Binary(close.into())).await;
            let _ = sink.close().await;
        });

        let _ = tokio::join!(to_client, to_node);
    }

    pub async fn close(mut self) {
        let close = encode_msg(
            self.version,
            MsgType::StreamClose,
            &StreamClose {
                reason: StreamCloseReason::Eof as i32,
            },
        );
        let _ = self.ws.send(Message::Binary(close.into())).await;
        let _ = self.ws.close(None).await;
    }
}

/// A running test Gateway. Aborts its listener on drop.
pub struct TestGateway {
    addr: SocketAddr,
    server_name: String,
    opts: GwOptions,
    events: mpsc::UnboundedReceiver<GwEvent>,
    control: Arc<Mutex<Option<mpsc::Sender<Cmd>>>>,
    registrations: Arc<AtomicUsize>,
    dialback_attempts: Arc<AtomicUsize>,
    pongs: Arc<AtomicUsize>,
    /// Events read from the channel while waiting for a *different* kind. The
    /// control-channel `DIAL_BACK_RESULT` and the dial-back `Spliced` arrive on
    /// separate connections and can interleave either way; buffering keeps an
    /// `await_result` from discarding a `Spliced` an `await_splice` still needs.
    buffered: std::collections::VecDeque<GwEvent>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for TestGateway {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl TestGateway {
    pub async fn start(cp: &MockCp) -> TestGateway {
        Self::start_with(cp, GwOptions::default()).await
    }

    pub async fn start_with(cp: &MockCp, opts: GwOptions) -> TestGateway {
        sessionlayer_agent::tls::install_ring_provider();

        // The Gateway's serverAuth leaf comes from the SAME internal CA that issued
        // the Agent's identity — that CA is the Agent's only trust anchor here. The
        // SAN is this instance's enrolled name (distinct per gateway in HA).
        let server_name = opts
            .server_name
            .clone()
            .unwrap_or_else(|| GATEWAY_SERVER_NAME.to_string());
        let (cert_pem, key_pem) = cp.issue_server_leaf(&[server_name.as_str(), "localhost"]);
        let certs: Vec<_> = pem::parse_many(&cert_pem)
            .unwrap()
            .into_iter()
            .filter(|p| p.tag() == "CERTIFICATE")
            .map(|p| rustls::pki_types::CertificateDer::from(p.into_contents()))
            .collect();
        let key = pem::parse_many(key_pem.as_bytes()).unwrap();
        let key = key
            .into_iter()
            .find(|p| p.tag().ends_with("PRIVATE KEY"))
            .expect("server key");
        let key = rustls::pki_types::PrivateKeyDer::try_from(key.into_contents()).unwrap();

        // Client certificates are REQUIRED and verified against the internal CA:
        // an Agent that cannot present its S12 identity never reaches the preface.
        let mut roots = rustls::RootCertStore::empty();
        for anchor in cp.bootstrap_anchors() {
            roots
                .add(rustls::pki_types::CertificateDer::from(anchor))
                .unwrap();
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            roots.into(),
            provider.clone(),
        )
        .build()
        .expect("client verifier");
        let tls = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)
            .expect("server tls config");

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(tls));

        let (events_tx, events) = mpsc::unbounded_channel();
        let control: Arc<Mutex<Option<mpsc::Sender<Cmd>>>> = Arc::new(Mutex::new(None));
        let registrations = Arc::new(AtomicUsize::new(0));
        let dialback_attempts = Arc::new(AtomicUsize::new(0));
        let pongs = Arc::new(AtomicUsize::new(0));

        let task = {
            let (opts, control, registrations, dialback_attempts, pongs) = (
                opts.clone(),
                control.clone(),
                registrations.clone(),
                dialback_attempts.clone(),
                pongs.clone(),
            );
            tokio::spawn(async move {
                loop {
                    let Ok((tcp, _)) = listener.accept().await else {
                        return;
                    };
                    let (
                        acceptor,
                        opts,
                        events_tx,
                        control,
                        registrations,
                        dialback_attempts,
                        pongs,
                    ) = (
                        acceptor.clone(),
                        opts.clone(),
                        events_tx.clone(),
                        control.clone(),
                        registrations.clone(),
                        dialback_attempts.clone(),
                        pongs.clone(),
                    );
                    tokio::spawn(async move {
                        let Ok(tls) = acceptor.accept(tcp).await else {
                            return;
                        };
                        // mTLS is enforced by rustls itself: no client certificate,
                        // no connection. Assert it here so the test cannot pass on a
                        // silently anonymous handshake.
                        assert!(
                            tls.get_ref()
                                .1
                                .peer_certificates()
                                .is_some_and(|c| !c.is_empty()),
                            "the Agent must present an mTLS client certificate"
                        );

                        let path = Arc::new(Mutex::new(String::new()));
                        let seen = path.clone();
                        let ws = tokio_tungstenite::accept_hdr_async(
                            tls,
                            move |req: &Request, res: Response| {
                                *seen.lock().unwrap() = req.uri().path().to_string();
                                Ok(res)
                            },
                        )
                        .await;
                        let Ok(ws) = ws else { return };
                        let path = path.lock().unwrap().clone();

                        match path.as_str() {
                            CONTROL_PATH => {
                                serve_control(ws, opts, events_tx, control, registrations, pongs)
                                    .await
                            }
                            DIALBACK_PATH => {
                                dialback_attempts.fetch_add(1, Ordering::SeqCst);
                                serve_dialback(ws, opts, events_tx).await
                            }
                            other => panic!("Agent dialled an unknown path: {other}"),
                        }
                    });
                }
            })
        };

        TestGateway {
            addr,
            server_name,
            opts,
            events,
            control,
            registrations,
            dialback_attempts,
            pongs,
            buffered: std::collections::VecDeque::new(),
            task,
        }
    }

    pub fn endpoint(&self) -> String {
        format!("wss://{}", self.addr)
    }

    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    /// How many control channels have completed the preface (a reconnect adds one).
    pub fn registrations(&self) -> usize {
        self.registrations.load(Ordering::SeqCst)
    }

    /// How many dial-back connections were attempted (0 proves a refusal never
    /// touched the network).
    pub fn dialback_attempts(&self) -> usize {
        self.dialback_attempts.load(Ordering::SeqCst)
    }

    /// Read one event straight off the channel (bounded), ignoring the buffer.
    async fn recv_raw(&mut self) -> GwEvent {
        tokio::time::timeout(Duration::from_secs(20), self.events.recv())
            .await
            .expect("timed out waiting for a Gateway event")
            .expect("gateway event channel closed")
    }

    /// The next event, draining any buffered ones first.
    pub async fn next_event(&mut self) -> GwEvent {
        if let Some(e) = self.buffered.pop_front() {
            return e;
        }
        self.recv_raw().await
    }

    /// Wait until an Agent has registered on the control channel. Events of other
    /// kinds seen while waiting are buffered, not discarded.
    pub async fn await_registration(&mut self) -> AgentHello {
        if let Some(pos) = self
            .buffered
            .iter()
            .position(|e| matches!(e, GwEvent::Registered(_)))
        {
            if let Some(GwEvent::Registered(h)) = self.buffered.remove(pos) {
                return *h;
            }
        }
        loop {
            match self.recv_raw().await {
                GwEvent::Registered(h) => return *h,
                other => self.buffered.push_back(other),
            }
        }
    }

    /// How many PONGs the Agent has echoed (liveness, §7).
    pub fn pongs(&self) -> usize {
        self.pongs.load(Ordering::SeqCst)
    }

    pub async fn await_result(&mut self) -> DialBackResult {
        if let Some(pos) = self
            .buffered
            .iter()
            .position(|e| matches!(e, GwEvent::Result(_)))
        {
            if let Some(GwEvent::Result(r)) = self.buffered.remove(pos) {
                return r;
            }
        }
        loop {
            match self.recv_raw().await {
                GwEvent::Result(r) => return r,
                // A `DialBackFailed` (the dial-back connection ended before
                // STREAM_OPEN) is EXPECTED alongside a failure `Result` — e.g. a
                // LocalDialFailed closes the dial-back and reports on the control
                // channel. It is not a test failure here; keep waiting for the Result.
                other => self.buffered.push_back(other),
            }
        }
    }

    pub async fn await_splice(&mut self) -> DialBackConn {
        if let Some(pos) = self
            .buffered
            .iter()
            .position(|e| matches!(e, GwEvent::Spliced(_)))
        {
            if let Some(GwEvent::Spliced(c)) = self.buffered.remove(pos) {
                return *c;
            }
        }
        loop {
            match self.recv_raw().await {
                GwEvent::Spliced(conn) => return *conn,
                GwEvent::DialBackFailed(why) => panic!("dial-back failed: {why}"),
                other => self.buffered.push_back(other),
            }
        }
    }

    /// Send a DIAL_BACK_REQUEST on the live control channel.
    pub async fn send_dial_back(&self, req: DialBackRequest) {
        let frame = encode_msg(1, MsgType::DialBackRequest, &req);
        let tx = self.current_control().await;
        tx.send(Cmd::Send(frame)).await.expect("control channel up");
    }

    /// Drop the control channel from the server side (the reconnect test).
    pub async fn drop_control(&self) {
        let tx = self.current_control().await;
        let _ = tx.send(Cmd::Close).await;
    }

    async fn current_control(&self) -> mpsc::Sender<Cmd> {
        for _ in 0..200 {
            if let Some(tx) = self.control.lock().unwrap().clone() {
                return tx;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("no control channel registered");
    }

    /// A DIAL_BACK_REQUEST bound to `node_name`, carrying `token`.
    pub fn dial_back_request(&self, node_name: &str, token: &str) -> DialBackRequest {
        DialBackRequest {
            request_id: "req-1".to_string(),
            node_name: node_name.to_string(),
            session_id: "sess-1".to_string(),
            principal: "deploy".to_string(),
            gateway_id: "gw-1".to_string(),
            dial_back_endpoint: self.endpoint(),
            token: token.to_string(),
            not_after_epoch_seconds: 0,
        }
    }
}

fn component() -> ComponentInfo {
    ComponentInfo {
        name: "SessionLayer Gateway (test)".to_string(),
        semver: "0.1.0".to_string(),
        protocol_min: Some(ProtocolVersion { major: 1, minor: 0 }),
        protocol_max: Some(ProtocolVersion { major: 1, minor: 0 }),
    }
}

/// The §3 preface, server side: read HELLO, answer HELLO_ACK (or VERSION_REJECT).
/// Returns the Agent's HELLO once the preface has completed.
async fn preface(ws: &mut ServerWs, opts: &GwOptions) -> Option<AgentHello> {
    let msg = tokio::time::timeout(Duration::from_secs(10), ws.next())
        .await
        .ok()??
        .ok()?;
    let Message::Binary(bytes) = msg else {
        return None;
    };
    let frame = decode_frame(&bytes)?;
    if frame.ty != MsgType::Hello as u8 {
        return None;
    }
    let hello = AgentHello::decode(&frame.payload[..]).ok()?;

    if opts.version_reject {
        let reject = encode_msg(
            frame.version,
            MsgType::VersionReject,
            &VersionReject {
                gateway_min: Some(ProtocolVersion { major: 9, minor: 0 }),
                gateway_max: Some(ProtocolVersion { major: 9, minor: 9 }),
            },
        );
        let _ = ws.send(Message::Binary(reject.into())).await;
        let _ = ws.close(None).await;
        return None;
    }

    let selected = opts
        .bogus_selected
        .map(|(major, minor)| ProtocolVersion { major, minor })
        .unwrap_or(ProtocolVersion { major: 1, minor: 0 });
    let ack = encode_msg(
        frame.version,
        MsgType::HelloAck,
        &GatewayHelloAck {
            component: Some(component()),
            selected: Some(selected),
            heartbeat_interval_secs: opts.heartbeat_secs,
            max_frame_bytes: opts.max_frame_bytes,
        },
    );
    ws.send(Message::Binary(ack.into())).await.ok()?;
    Some(hello)
}

async fn serve_control(
    mut ws: ServerWs,
    opts: GwOptions,
    events: mpsc::UnboundedSender<GwEvent>,
    control: Arc<Mutex<Option<mpsc::Sender<Cmd>>>>,
    registrations: Arc<AtomicUsize>,
    pongs: Arc<AtomicUsize>,
) {
    let Some(hello) = preface(&mut ws, &opts).await else {
        return;
    };
    registrations.fetch_add(1, Ordering::SeqCst);
    let _ = events.send(GwEvent::Registered(Box::new(hello)));

    let (cmd_tx, mut cmd_rx) = mpsc::channel::<Cmd>(16);
    // "Re-registration replaces" (§7): the newest control channel is the live one.
    *control.lock().unwrap() = Some(cmd_tx);

    let mut ping = tokio::time::interval(Duration::from_secs(opts.heartbeat_secs.max(1) as u64));
    ping.tick().await; // the immediate first tick
    let mut nonce = 0u64;

    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => match cmd {
                Some(Cmd::Send(frame)) => {
                    if ws.send(Message::Binary(frame.into())).await.is_err() {
                        break;
                    }
                }
                Some(Cmd::Close) | None => break,
            },

            _ = ping.tick(), if opts.ping => {
                nonce += 1;
                let frame = encode_msg(1, MsgType::Ping, &Ping { nonce });
                if ws.send(Message::Binary(frame.into())).await.is_err() {
                    break;
                }
            }

            msg = ws.next() => {
                let Some(Ok(Message::Binary(bytes))) = msg else {
                    match msg {
                        Some(Ok(_)) => continue,
                        _ => break,
                    }
                };
                let Some(frame) = decode_frame(&bytes) else { break };
                assert_eq!(frame.version, 1, "frame VER must be the negotiated major");
                match frame.ty {
                    t if t == MsgType::Pong as u8 => {
                        let p = Pong::decode(&frame.payload[..]).expect("PONG payload");
                        assert!(p.nonce > 0, "PONG must echo the PING nonce (§7)");
                        pongs.fetch_add(1, Ordering::SeqCst);
                    }
                    t if t == MsgType::DialBackResult as u8 => {
                        let r = DialBackResult::decode(&frame.payload[..])
                            .expect("DIAL_BACK_RESULT payload");
                        let _ = events.send(GwEvent::Result(r));
                    }
                    t if t == MsgType::Error as u8 => {
                        let e = WireError::decode(&frame.payload[..]).expect("ERROR payload");
                        let _ = events.send(GwEvent::DialBackFailed(format!("agent ERROR: {e:?}")));
                        break;
                    }
                    other => panic!("unexpected type {other:#04x} on the control channel"),
                }
            }
        }
    }

    let _ = ws.close(None).await;
    *control.lock().unwrap() = None;
    let _ = events.send(GwEvent::ControlClosed);
}

/// The dial-back role (§5/§6): preface, DIAL_BACK_AUTH, DIAL_BACK_ACCEPT,
/// STREAM_OPEN — then the splice is handed to the test.
async fn serve_dialback(mut ws: ServerWs, opts: GwOptions, events: mpsc::UnboundedSender<GwEvent>) {
    if preface(&mut ws, &opts).await.is_none() {
        let _ = events.send(GwEvent::DialBackFailed("preface failed".into()));
        return;
    }

    let Some(Ok(Message::Binary(bytes))) = ws.next().await else {
        let _ = events.send(GwEvent::DialBackFailed("no DIAL_BACK_AUTH".into()));
        return;
    };
    let Some(frame) = decode_frame(&bytes) else {
        let _ = events.send(GwEvent::DialBackFailed("malformed DIAL_BACK_AUTH".into()));
        return;
    };
    assert_eq!(
        frame.ty,
        MsgType::DialBackAuth as u8,
        "DIAL_BACK_AUTH must be the FIRST frame after the preface (§5)"
    );
    let auth = DialBackAuth::decode(&frame.payload[..]).expect("DIAL_BACK_AUTH payload");

    // The token is a capability: a mismatch is UNAUTHORIZED and the connection dies
    // without the node ever being touched.
    if let Some(expected) = &opts.expect_token {
        if &auth.token != expected {
            let err = encode_msg(
                1,
                MsgType::Error,
                &WireError {
                    code: WireErrorCode::Unauthorized as i32,
                    message: "dial-back token refused".to_string(),
                },
            );
            let _ = ws.send(Message::Binary(err.into())).await;
            let _ = ws.close(None).await;
            let _ = events.send(GwEvent::DialBackFailed("token refused".into()));
            return;
        }
    }

    let accept = encode_msg(1, MsgType::DialBackAccept, &DialBackAccept {});
    if ws.send(Message::Binary(accept.into())).await.is_err() {
        let _ = events.send(GwEvent::DialBackFailed("accept failed".into()));
        return;
    }

    // STREAM_OPEN is the readiness signal: the node's sshd is connected (§5).
    let Some(Ok(Message::Binary(bytes))) = ws.next().await else {
        let _ = events.send(GwEvent::DialBackFailed("no STREAM_OPEN".into()));
        return;
    };
    let Some(frame) = decode_frame(&bytes) else {
        let _ = events.send(GwEvent::DialBackFailed("malformed STREAM_OPEN".into()));
        return;
    };
    if frame.ty == MsgType::StreamClose as u8 {
        let close = StreamClose::decode(&frame.payload[..]).expect("STREAM_CLOSE payload");
        let _ = events.send(GwEvent::DialBackFailed(format!(
            "stream closed before open: {:?}",
            close.reason
        )));
        return;
    }
    assert_eq!(
        frame.ty,
        MsgType::StreamOpen as u8,
        "expected STREAM_OPEN (0x30) once the node's sshd is connected"
    );

    let _ = events.send(GwEvent::Spliced(Box::new(DialBackConn {
        ws,
        version: 1,
        token: auth.token,
        request_id: auth.request_id,
    })));
}
