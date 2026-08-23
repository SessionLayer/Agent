//! **The splice target is never taken from the wire.**
//! `DIAL_BACK_REQUEST` carries no target by design; the destination comes only from
//! [`crate::config::GatewayConfig::splice_addr`], which is validated to be loopback
//! at startup. No Gateway - however compromised - can redirect the splice or use
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

const CHUNK: usize = 16 * 1024;

const HALF_CLOSE_DRAIN: Duration = Duration::from_secs(10);

type Failure = (DialBackErrorCode, GatewayError);

fn configured_endpoint<'a>(
    config: &'a GatewayConfig,
    endpoint: &str,
) -> Option<&'a crate::config::GatewayEndpoint> {
    let wanted = transport::authority_of(endpoint).ok()?;
    config
        .endpoints
        .iter()
        .find(|e| transport::authority_of(&e.url).ok().as_deref() == Some(wanted.as_str()))
}

pub struct Live {
    ws: GatewayWs,
    tcp: TcpStream,
    negotiated: Negotiated,
}

impl Live {
    pub async fn run(self) -> StreamCloseReason {
        splice(self.ws, self.tcp, self.negotiated).await
    }
}

pub async fn dial_back(
    config: &GatewayConfig,
    cred: &Credential,
    mut req: DialBackRequest,
) -> Result<Live, Failure> {
    let token = Zeroizing::new(std::mem::take(&mut req.token));
    let request_id = req.request_id.clone();

    // Defence in depth for the confused-deputy invariant. The splice target
    // is already loopback-only; here we constrain the OTHER wire-carried destination
    // - `dial_back_endpoint`, the address the Agent connects back to. It MUST be one
    // of the Gateways this Agent was configured to talk to. Otherwise an
    // authenticated-but-hostile Gateway could aim the Agent's TCP connect + TLS
    // ClientHello at any address the node can reach (a weak but real network-pivot /
    // recon primitive), even though the TLS handshake itself would then fail closed
    // against the pinned CA. Refuse before dialling.
    let Some(gateway) = configured_endpoint(config, &req.dial_back_endpoint) else {
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
    };

    let mut ws = transport::connect(
        &req.dial_back_endpoint,
        &gateway.server_name,
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

async fn splice(ws: GatewayWs, tcp: TcpStream, negotiated: Negotiated) -> StreamCloseReason {
    let (mut sink, mut stream) = ws.split();
    let (mut node_rd, mut node_wr) = tcp.into_split();
    let frame_cap = CHUNK.min(negotiated.max_frame_bytes as usize);
    let version = negotiated.version;

    let to_node = tokio::spawn(async move {
        while let Some(msg) = stream.next().await {
            let bytes = match msg {
                Ok(Message::Binary(b)) => b,
                Ok(Message::Close(_)) | Err(_) => break,
                Ok(_) => continue,
            };
            match wire::decode(&bytes, version, negotiated.max_frame_bytes, Role::DialBack) {
                Ok(Inbound::StreamData(data)) => {
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

    // Clean half-close: when one direction reaches EOF its task has ALREADY shut
    // down its peer's write half (node_wr.shutdown / sink.close), so the peer sees
    // EOF and finishes. We then let the OTHER direction drain its in-flight bytes to
    // its own EOF rather than abort()ing it mid-flight - bounded by HALF_CLOSE_DRAIN
    // so a peer that half-closes without reciprocating cannot pin the splice (and
    // its concurrency permit) open. The grace only starts once the first direction
    // has ended, so it never truncates a live session.
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
        for max_frame_bytes in [wire::MIN_FRAME_BYTES, 8192, wire::PREFERRED_MAX_FRAME_BYTES] {
            let cap = CHUNK.min(max_frame_bytes as usize);
            assert!(cap <= max_frame_bytes as usize);
            let frame = wire::encode(1, wire::MsgType::StreamData, &vec![0u8; cap]);
            assert_eq!(frame.len(), wire::FRAME_HEADER_LEN + cap);
        }
    }

    fn config_with(endpoints: &[&str]) -> GatewayConfig {
        GatewayConfig {
            endpoints: endpoints
                .iter()
                .map(|s| crate::config::GatewayEndpoint {
                    url: s.to_string(),
                    failure_domain: s.to_string(),
                    server_name: "gateway".to_string(),
                })
                .collect(),
            splice_addr: "127.0.0.1:22".parse().unwrap(),
            max_concurrent_splices: 32,
            min_control_channels: 1,
            connect_timeout: Duration::from_secs(5),
            backoff_initial: Duration::from_secs(1),
            backoff_max: Duration::from_secs(30),
            drain_deadline: Duration::from_secs(30),
        }
    }

    #[test]
    fn dial_back_endpoint_must_be_a_configured_gateway() {
        let config = config_with(&["wss://gw-a.example:8443", "wss://gw-b.example:8443"]);

        assert!(
            configured_endpoint(&config, "wss://gw-a.example:8443/agent/v1/dialback").is_some()
        );
        assert!(configured_endpoint(&config, "wss://gw-b.example:8443").is_some());

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
                configured_endpoint(&config, pivot).is_none(),
                "{pivot} must not be treated as a configured Gateway"
            );
        }
    }
}
