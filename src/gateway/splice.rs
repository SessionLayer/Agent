//! Dial-back and splice (`contracts/wire/agent-gateway-v1.md` §5; FR-CONN-2).
//!
//! On a `DIAL_BACK_REQUEST` the Agent opens a **second** mutually-authenticated
//! WebSocket to the Gateway, presents the single-use token as its first frame,
//! and — once the Gateway accepts — connects to the node's own `sshd` on
//! **loopback** and splices the two together.
//!
//! What crosses this splice is SSH-layer **ciphertext**. The Agent never inspects
//! it, never logs it, never retains it, and structurally cannot read it: the SSH
//! session is end-to-end between the Gateway and the node's `sshd` (Design §9.3).
//! The Agent holds no session credential and is not a party to the inner-leg
//! certificate or to host-identity verification.
//!
//! **The splice target is never taken from the wire** (contract §5).
//! `DIAL_BACK_REQUEST` carries no target by design; the destination comes only from
//! [`crate::config::GatewayConfig::splice_addr`], which is validated to be loopback
//! at startup. No Gateway — however compromised — can redirect the splice or use
//! the Agent as a network pivot.

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use zeroize::Zeroizing;

use crate::config::GatewayConfig;
use crate::gateway::client::preface;
use crate::gateway::transport::{self, GatewayWs, DIALBACK_PATH};
use crate::gateway::wire::{self, Inbound, Role};
use crate::gateway::{GatewayError, Negotiated};
use crate::identity::Credential;
use crate::proto::wire::{
    DialBackAuth, DialBackErrorCode, DialBackRequest, StreamClose, StreamCloseReason,
};

/// Copy buffer. Bounded by the negotiated frame size, so one read is at most one
/// `STREAM_DATA` frame and a peer's frame bound is never exceeded.
const CHUNK: usize = 16 * 1024;

/// After one splice direction reaches EOF, how long the other may keep draining to
/// its own EOF before it is cut. Bounds a half-open peer from pinning the splice
/// (and its concurrency permit) open; it only starts once the first direction ends.
const HALF_CLOSE_DRAIN: Duration = Duration::from_secs(10);

/// A dial-back failure, as the code the Gateway is told plus the detail for our own
/// operator log. The SSH user always sees the single generic §7.1 outcome
/// ("target node is offline / unreachable") — this never reaches them.
type Failure = (DialBackErrorCode, GatewayError);

/// Whether a wire-supplied `dial_back_endpoint` is one of the Gateways this Agent
/// was configured to reach (authority match). A malformed endpoint is not
/// configured. See the confused-deputy note in [`dial_back`].
fn endpoint_is_configured(config: &GatewayConfig, endpoint: &str) -> bool {
    let Ok(wanted) = transport::authority_of(endpoint) else {
        return false;
    };
    config
        .endpoints
        .iter()
        .filter_map(|e| transport::authority_of(e).ok())
        .any(|a| a == wanted)
}

/// A dial-back that has reached `STREAM_OPEN`: the Gateway accepted the token and
/// the node's `sshd` is connected. Splitting the dial-back here is what lets the
/// caller report the outcome on the control channel the moment it is known —
/// `DIAL_BACK_RESULT` is a **fast-fail** signal (§5), so it must not wait for the
/// session to end.
pub struct Live {
    ws: GatewayWs,
    tcp: TcpStream,
    negotiated: Negotiated,
}

impl Live {
    /// Splice until either side EOFs or errors, returning why it ended.
    pub async fn run(self) -> StreamCloseReason {
        splice(self.ws, self.tcp, self.negotiated).await
    }
}

/// Dial back, authorize, and connect the node's `sshd` — everything up to and
/// including `STREAM_OPEN`. The returned [`Live`] carries the spliceable pair.
///
/// The `token` in `req` is **opaque**: presented verbatim, never logged, never
/// persisted, never echoed.
pub async fn dial_back(
    config: &GatewayConfig,
    cred: &Credential,
    mut req: DialBackRequest,
) -> Result<Live, Failure> {
    // Take the token out of the message and hold it in a scrub-on-drop buffer for
    // the short time we need it, so it does not linger in a plain heap allocation.
    let token = Zeroizing::new(std::mem::take(&mut req.token));
    let request_id = req.request_id.clone();

    // Defence in depth for the confused-deputy invariant (§5/§8). The splice target
    // is already loopback-only; here we constrain the OTHER wire-carried destination
    // — `dial_back_endpoint`, the address the Agent connects back to. The contract
    // fixes it to "the owning Gateway's address; in single-Gateway mode it is the
    // same Gateway", so it MUST be one of the Gateways this Agent was configured to
    // talk to. Otherwise an authenticated-but-hostile Gateway could aim the Agent's
    // TCP connect + TLS ClientHello at any address the node can reach (a weak but
    // real network-pivot / recon primitive), even though the TLS handshake itself
    // would then fail closed against the pinned CA. Refuse before dialling.
    if !endpoint_is_configured(config, &req.dial_back_endpoint) {
        tracing::warn!(
            request_id = %request_id.escape_debug(),
            endpoint = %req.dial_back_endpoint.escape_debug(),
            "refusing a dial-back to an endpoint this Agent was not configured to reach"
        );
        return Err((
            DialBackErrorCode::Refused,
            GatewayError::Endpoint {
                endpoint: req.dial_back_endpoint.clone(),
                reason: "not among the configured --gateway-endpoint set".to_string(),
            },
        ));
    }

    let mut ws = transport::connect(
        &req.dial_back_endpoint,
        &config.server_name,
        DIALBACK_PATH,
        cred,
        config.connect_timeout,
    )
    .await
    .map_err(|e| (DialBackErrorCode::TransportFailed, e))?;

    let negotiated = preface(&mut ws, Role::DialBack, config.connect_timeout)
        .await
        .map_err(|e| (DialBackErrorCode::TransportFailed, e))?;

    let auth = wire::out::dial_back_auth(
        negotiated.version,
        &DialBackAuth {
            token: token.to_string(),
            request_id: request_id.clone(),
        },
    );
    drop(token);
    ws.send(Message::Binary(auth.into())).await.map_err(|e| {
        (
            DialBackErrorCode::TransportFailed,
            GatewayError::Io {
                what: "dial-back connection",
                reason: e.to_string(),
            },
        )
    })?;

    await_accept(&mut ws, negotiated, config.connect_timeout).await?;

    // Only now is the local connection opened — never before the Gateway has
    // accepted the token, so an unauthorized signal cannot even touch the node's
    // sshd.
    let tcp = match tokio::time::timeout(
        config.connect_timeout,
        TcpStream::connect(config.splice_addr),
    )
    .await
    {
        Ok(Ok(tcp)) => tcp,
        Ok(Err(e)) => {
            return Err(local_dial_failed(&mut ws, negotiated, e.to_string()).await);
        }
        Err(_) => {
            let after = config.connect_timeout;
            return Err(local_dial_failed(
                &mut ws,
                negotiated,
                format!("timed out after {after:?}"),
            )
            .await);
        }
    };
    // Interactive SSH rides this splice; Nagle would add keystroke latency.
    let _ = tcp.set_nodelay(true);

    // STREAM_OPEN is the Agent -> Gateway proof that the loopback connection is up:
    // only the Agent knows when that happened, and the Gateway hands the stream to
    // the inner leg at this point and not before.
    ws.send(Message::Binary(
        wire::out::stream_open(negotiated.version).into(),
    ))
    .await
    .map_err(|e| {
        (
            DialBackErrorCode::TransportFailed,
            GatewayError::Io {
                what: "dial-back connection",
                reason: e.to_string(),
            },
        )
    })?;

    tracing::info!(
        request_id = %request_id.escape_debug(),
        session_id = %req.session_id.escape_debug(),
        splice_addr = %config.splice_addr,
        "splice live (opaque ciphertext; the Agent never reads it)"
    );

    Ok(Live {
        ws,
        tcp,
        negotiated,
    })
}

/// Wait for `DIAL_BACK_ACCEPT`. A `WireError` here means the Gateway refused the
/// token (bad signature, expired, replayed, or bound to another agent/session/node)
/// — fail closed, and do not touch the node.
async fn await_accept(
    ws: &mut GatewayWs,
    negotiated: Negotiated,
    timeout: Duration,
) -> Result<(), Failure> {
    let msg = tokio::time::timeout(timeout, ws.next())
        .await
        .map_err(|_| {
            (
                DialBackErrorCode::TransportFailed,
                GatewayError::Preface(format!("no DIAL_BACK_ACCEPT within {timeout:?}")),
            )
        })?;

    let bytes = match msg {
        Some(Ok(Message::Binary(b))) => b.to_vec(),
        Some(Ok(Message::Close(_))) | None => {
            // A close in place of an accept is the Gateway refusing the token.
            return Err((DialBackErrorCode::TokenRejected, GatewayError::Closed));
        }
        Some(Ok(_)) => {
            return Err((
                DialBackErrorCode::TransportFailed,
                GatewayError::Protocol(wire::CodecError::TextMessage),
            ))
        }
        Some(Err(e)) => {
            return Err((
                DialBackErrorCode::TransportFailed,
                GatewayError::Io {
                    what: "dial-back connection",
                    reason: e.to_string(),
                },
            ))
        }
    };

    match wire::decode(
        &bytes,
        negotiated.version,
        negotiated.max_frame_bytes,
        Role::DialBack,
    ) {
        Ok(Inbound::DialBackAccept(_)) => Ok(()),
        Ok(Inbound::Error(err)) => {
            // Untrusted peer text: log it escaped, never interpolate it (§8).
            tracing::warn!(
                code = err.code,
                message = %err.message.escape_debug(),
                "Gateway refused the dial-back token"
            );
            Err((
                DialBackErrorCode::TokenRejected,
                GatewayError::Preface("dial-back token refused".to_string()),
            ))
        }
        Ok(other) => Err((
            DialBackErrorCode::TransportFailed,
            GatewayError::Preface(format!(
                "expected DIAL_BACK_ACCEPT, got {:?}",
                other.msg_type()
            )),
        )),
        Err(e) => Err((
            DialBackErrorCode::TransportFailed,
            GatewayError::Protocol(e),
        )),
    }
}

/// The node's sshd is down or unreachable: tell the Gateway on **both** channels so
/// it fails fast instead of waiting out its dial-back deadline — the user gets the
/// §7.1 "node offline / unreachable" outcome promptly.
async fn local_dial_failed(ws: &mut GatewayWs, negotiated: Negotiated, reason: String) -> Failure {
    let close = wire::out::stream_close(
        negotiated.version,
        &StreamClose {
            reason: StreamCloseReason::LocalDialFailed as i32,
        },
    );
    let _ = ws.send(Message::Binary(close.into())).await;
    let _ = ws.close(None).await;
    (
        DialBackErrorCode::LocalDialFailed,
        GatewayError::Connect {
            endpoint: "the node's local sshd".to_string(),
            reason,
        },
    )
}

/// Splice the dial-back connection to the node's sshd, in both directions, until
/// either side EOFs or errors.
///
/// The two directions run as **independent tasks**, each with its own await point,
/// so backpressure is per-direction: a slow Gateway stops us reading from the node,
/// and a slow node stops us reading from the Gateway, but neither can
/// head-of-line-block the other, and nothing is buffered unboundedly.
async fn splice(ws: GatewayWs, tcp: TcpStream, negotiated: Negotiated) -> StreamCloseReason {
    let (mut sink, mut stream) = ws.split();
    let (mut node_rd, mut node_wr) = tcp.into_split();
    let frame_cap = CHUNK.min(negotiated.max_frame_bytes as usize);
    let version = negotiated.version;

    // Gateway -> node.
    let to_node = tokio::spawn(async move {
        while let Some(msg) = stream.next().await {
            let bytes = match msg {
                Ok(Message::Binary(b)) => b,
                Ok(Message::Close(_)) | Err(_) => break,
                Ok(_) => continue,
            };
            match wire::decode(&bytes, version, negotiated.max_frame_bytes, Role::DialBack) {
                Ok(Inbound::StreamData(data)) => {
                    // Awaited: if sshd is slow, we stop reading the Gateway.
                    if node_wr.write_all(&data).await.is_err() {
                        return StreamCloseReason::IoError;
                    }
                }
                Ok(Inbound::StreamClose(_)) => {
                    let _ = node_wr.shutdown().await;
                    return StreamCloseReason::Eof;
                }
                Ok(_) => return StreamCloseReason::IoError,
                Err(e) => {
                    tracing::warn!(error = %e, "protocol error on the dial-back connection");
                    return StreamCloseReason::IoError;
                }
            }
        }
        let _ = node_wr.shutdown().await;
        StreamCloseReason::Eof
    });

    // Node -> Gateway.
    let to_gateway = tokio::spawn(async move {
        let mut buf = vec![0u8; frame_cap];
        let reason = loop {
            match node_rd.read(&mut buf).await {
                Ok(0) => break StreamCloseReason::Eof,
                Ok(n) => {
                    let frame = wire::encode(version, wire::MsgType::StreamData, &buf[..n]);
                    // `send` flushes, so a slow Gateway backpressures the node read
                    // rather than growing a buffer here.
                    if sink.send(Message::Binary(frame.into())).await.is_err() {
                        break StreamCloseReason::IoError;
                    }
                }
                Err(_) => break StreamCloseReason::IoError,
            }
        };
        let close = wire::out::stream_close(
            version,
            &StreamClose {
                reason: reason as i32,
            },
        );
        let _ = sink.send(Message::Binary(close.into())).await;
        let _ = sink.close().await;
        reason
    });

    // Clean half-close (matches the S8 bridge): when one direction reaches EOF its
    // task has ALREADY shut down its peer's write half (node_wr.shutdown /
    // sink.close), so the peer sees EOF and finishes. We then let the OTHER
    // direction drain its in-flight bytes to its own EOF rather than abort()ing it
    // mid-flight — bounded by HALF_CLOSE_DRAIN so a peer that half-closes without
    // reciprocating cannot pin the splice (and its concurrency permit) open. The
    // grace only starts once the first direction has ended, so it never truncates a
    // live session.
    let (mut to_node, mut to_gateway) = (to_node, to_gateway);
    tokio::select! {
        r = &mut to_node => {
            let _ = tokio::time::timeout(HALF_CLOSE_DRAIN, &mut to_gateway).await;
            to_gateway.abort();
            r.unwrap_or(StreamCloseReason::IoError)
        }
        r = &mut to_gateway => {
            let _ = tokio::time::timeout(HALF_CLOSE_DRAIN, &mut to_node).await;
            to_node.abort();
            r.unwrap_or(StreamCloseReason::IoError)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_data_frames_never_exceed_the_negotiated_bound() {
        // The read buffer is what caps a STREAM_DATA frame; a Gateway that
        // negotiated a small bound must never be sent a larger frame.
        for max_frame_bytes in [wire::MIN_FRAME_BYTES, 8192, wire::PREFERRED_MAX_FRAME_BYTES] {
            let cap = CHUNK.min(max_frame_bytes as usize);
            assert!(cap <= max_frame_bytes as usize);
            let frame = wire::encode(1, wire::MsgType::StreamData, &vec![0u8; cap]);
            assert_eq!(frame.len(), wire::FRAME_HEADER_LEN + cap);
        }
    }

    fn config_with(endpoints: &[&str]) -> GatewayConfig {
        GatewayConfig {
            endpoints: endpoints.iter().map(|s| s.to_string()).collect(),
            server_name: "gateway".to_string(),
            splice_addr: "127.0.0.1:22".parse().unwrap(),
            max_concurrent_splices: 32,
            connect_timeout: Duration::from_secs(5),
            backoff_initial: Duration::from_secs(1),
            backoff_max: Duration::from_secs(30),
            drain_deadline: Duration::from_secs(30),
        }
    }

    #[test]
    fn dial_back_endpoint_must_be_a_configured_gateway() {
        // The confused-deputy defence for the wire-carried dial-back address: only a
        // Gateway this Agent was configured to reach is dialled. An authenticated but
        // hostile Gateway cannot aim the Agent's connect at an arbitrary host:port.
        let config = config_with(&["wss://gw-a.example:8443", "wss://gw-b.example:8443"]);

        // Same host:port (any path) is allowed — the path is contract-fixed anyway.
        assert!(endpoint_is_configured(
            &config,
            "wss://gw-a.example:8443/agent/v1/dialback"
        ));
        assert!(endpoint_is_configured(&config, "wss://gw-b.example:8443"));

        // Anything not in the configured set is refused: a different host, a
        // different port, a bare IP, loopback, link-local metadata, or garbage.
        for pivot in [
            "wss://gw-a.example:9999",
            "wss://evil.example:8443",
            "wss://10.0.0.5:8443",
            "wss://127.0.0.1:8443",
            "wss://169.254.169.254:80",
            "not-a-uri",
            "ws://gw-a.example:8443",
        ] {
            assert!(
                !endpoint_is_configured(&config, pivot),
                "{pivot} must not be treated as a configured Gateway"
            );
        }
    }
}
