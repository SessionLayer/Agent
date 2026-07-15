//! The outbound control channel (`contracts/wire/agent-gateway-v1.md` §1/§3/§7).
//!
//! One long-lived `wss://` connection per Agent->Gateway pair, authenticated with
//! the S12 renewable mTLS identity. It carries the preface, liveness, and
//! **dial-back requests** — never session bytes (each session gets its own
//! dial-back connection, so a file transfer can never head-of-line-block a
//! heartbeat or a lock).
//!
//! Reconnects indefinitely with exponential backoff + jitter. Every reconnect
//! re-runs the full TLS + mTLS + preface path: no resumption, no cached
//! authorization. A credential rotation (S12 renew-ahead) reconnects with the new
//! certificate.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::sync::{mpsc, watch, OwnedSemaphorePermit, Semaphore};
use tokio_tungstenite::tungstenite::Message;

use crate::config::{GatewayConfig, GatewayEndpoint};
use crate::gateway::transport::{self, GatewayWs, CONTROL_PATH};
use crate::gateway::wire::{self, Inbound, Role};
use crate::gateway::{GatewayError, Negotiated};
use crate::identity::{jittered_backoff, Credential, RenewHandle};
use crate::proto::wire::{DialBackErrorCode, DialBackRequest, DialBackResult};
use crate::version;

/// Bounds on what a `HELLO_ACK` may propose. A Gateway that proposes a heartbeat
/// we cannot honour, or no heartbeat at all, would leave a dead channel
/// undetectable — which silently strands the node. Fail closed instead.
const MIN_HEARTBEAT: Duration = Duration::from_secs(1);
const MAX_HEARTBEAT: Duration = Duration::from_secs(300);

/// Why one connection ended, which decides whether we back off before redialling.
enum Ended {
    /// The Agent was told to stop: no reconnect.
    Stopped,
    /// The credential rotated: reconnect immediately with the new certificate (this
    /// is not a fault, so it must not consume backoff).
    CredentialRotated,
    /// The peer closed, went silent, or faulted: reconnect with backoff.
    Fault(GatewayError),
}

/// State shared by every control channel this Agent runs: the config, the renew
/// handle they all authenticate with, the **global** splice cap (shared across
/// channels — the node's total concurrent-session budget, not per-Gateway), and the
/// reachability counter that drives the all-Gateways-lost degrade.
struct Shared {
    config: Arc<GatewayConfig>,
    renew: RenewHandle,
    /// Caps concurrent splices across all channels. Also the drain latch: when every
    /// permit is free, no session is live.
    splices: Arc<Semaphore>,
    /// How many control channels are currently registered. When it reaches zero the
    /// node is unreachable (FR-HA-6 degrade); when it climbs off zero, reachable.
    reachable: Arc<AtomicUsize>,
    total_channels: usize,
}

impl Shared {
    /// Wait for live splices to finish, bounded. Acquiring every permit proves no
    /// session is live. Called once, after all channels have stopped.
    async fn drain(&self) {
        let permits = self.config.max_concurrent_splices as u32;
        let live = permits as usize - self.splices.available_permits();
        if live == 0 {
            tracing::info!("gateway control channels stopped; no live sessions to drain");
            return;
        }
        tracing::info!(
            live,
            deadline_secs = self.config.drain_deadline.as_secs(),
            "gateway control channels stopped; draining live spliced sessions"
        );
        match tokio::time::timeout(
            self.config.drain_deadline,
            self.splices.acquire_many(permits),
        )
        .await
        {
            Ok(_) => tracing::info!("all spliced sessions drained"),
            Err(_) => tracing::warn!(
                live = permits as usize - self.splices.available_permits(),
                "drain deadline reached — cutting remaining spliced sessions"
            ),
        }
    }
}

/// The Agent's Gateway-facing client. Holds one control channel per configured
/// endpoint concurrently — for HA, ≥2 to failure-domain-diverse Gateways (FR-HA-6);
/// for single-instance, exactly one. The Agent does **not** mesh; each channel is an
/// independent dial-out to one Gateway.
pub struct GatewayClient {
    shared: Arc<Shared>,
}

impl GatewayClient {
    /// Build the client, validating the configuration (loopback splice target,
    /// endpoint diversity when multi-homed, caps) **before** anything is dialled —
    /// fail closed at startup.
    pub fn new(
        config: GatewayConfig,
        renew: RenewHandle,
    ) -> Result<Self, crate::config::ConfigError> {
        config.validate()?;
        let splices = Arc::new(Semaphore::new(config.max_concurrent_splices));
        let total_channels = config.endpoints.len();
        Ok(Self {
            shared: Arc::new(Shared {
                config: Arc::new(config),
                renew,
                splices,
                reachable: Arc::new(AtomicUsize::new(0)),
                total_channels,
            }),
        })
    }

    /// Dial out on **all** configured Gateways concurrently and serve until `stop` is
    /// set, each channel reconnecting indefinitely. When all channels have stopped,
    /// **live splices are drained** up to `drain_deadline` — a terminal identity
    /// outcome stops *new* work but must not tear down sessions already carrying a
    /// user's SSH stream (contract §7).
    pub async fn run(self, stop: watch::Receiver<bool>) {
        let shared = self.shared;
        tracing::info!(
            channels = shared.total_channels,
            failure_domains = shared.config.distinct_failure_domains(),
            splice_addr = %shared.config.splice_addr,
            max_concurrent_splices = shared.config.max_concurrent_splices,
            "gateway control channels starting (dial-out to diverse Gateways; no mesh)"
        );

        let mut tasks = Vec::with_capacity(shared.total_channels);
        for ep in shared.config.endpoints.clone() {
            // The authority was validated at startup; a failure here is defensive.
            let authority = match transport::authority_of(&ep.url) {
                Ok(a) => a,
                Err(e) => {
                    tracing::error!(endpoint = %ep.url, error = %e, "skipping an unusable endpoint");
                    continue;
                }
            };
            let channel = ControlChannel {
                shared: shared.clone(),
                endpoint: ep,
                authority,
            };
            let stop = stop.clone();
            tasks.push(tokio::spawn(async move { channel.run(stop).await }));
        }

        for task in tasks {
            let _ = task.await;
        }
        shared.drain().await;
    }
}

/// One control channel: a persistent dial-out to a single Gateway, with its own
/// reconnect loop. Every channel shares the [`Shared`] state.
struct ControlChannel {
    shared: Arc<Shared>,
    endpoint: GatewayEndpoint,
    /// This channel's Gateway authority (`host:port`), for the per-channel dial-back
    /// affinity check.
    authority: String,
}

impl ControlChannel {
    async fn run(self, mut stop: watch::Receiver<bool>) {
        let mut backoff = self.shared.config.backoff_initial;
        while !*stop.borrow() {
            let cred = self.shared.renew.current();
            match self.serve_once(&cred, &mut stop, &mut backoff).await {
                Ended::Stopped => break,
                Ended::CredentialRotated => {
                    tracing::info!(
                        endpoint = %self.endpoint.url,
                        "credential rotated — reconnecting with the new certificate"
                    );
                    continue;
                }
                Ended::Fault(err) => {
                    let delay = jittered_backoff(backoff, random_sample());
                    tracing::warn!(
                        endpoint = %self.endpoint.url,
                        error = %err,
                        retry_in_ms = delay.as_millis() as u64,
                        "gateway control channel down — reconnecting"
                    );
                    backoff = next_backoff(backoff, self.shared.config.backoff_max);
                    tokio::select! {
                        _ = tokio::time::sleep(delay) => {}
                        _ = stop.changed() => {}
                    }
                }
            }
        }
    }

    /// One connection: dial, preface, then serve frames until it ends.
    async fn serve_once(
        &self,
        cred: &Credential,
        stop: &mut watch::Receiver<bool>,
        backoff: &mut Duration,
    ) -> Ended {
        let mut ws = match transport::connect(
            &self.endpoint.url,
            &self.endpoint.server_name,
            CONTROL_PATH,
            cred,
            self.shared.config.connect_timeout,
        )
        .await
        {
            Ok(ws) => ws,
            Err(e) => return Ended::Fault(e),
        };

        let negotiated =
            match preface(&mut ws, Role::Control, self.shared.config.connect_timeout).await {
                Ok(n) => n,
                Err(e) => return Ended::Fault(e),
            };

        // A completed preface means the endpoint is healthy: reset the backoff so a
        // channel that later drops redials promptly rather than at the last (grown)
        // interval.
        *backoff = self.shared.config.backoff_initial;
        // Registered = reachable through this Gateway; the guard tracks the fleet-wide
        // reachability count and logs the all-down degrade when it hits zero.
        let _registered = Reachability::register(&self.shared, &self.endpoint);
        tracing::info!(
            agent_id = %cred.agent_id,
            node_name = %cred.node_name,
            endpoint = %self.endpoint.url,
            failure_domain = %self.endpoint.failure_domain,
            generation = cred.generation,
            protocol = negotiated.version,
            heartbeat_secs = negotiated.heartbeat_interval.as_secs(),
            "registered on a Gateway control channel"
        );

        self.serve_frames(ws, negotiated, cred, stop).await
    }

    async fn serve_frames(
        &self,
        ws: GatewayWs,
        negotiated: Negotiated,
        cred: &Credential,
        stop: &mut watch::Receiver<bool>,
    ) -> Ended {
        let (mut sink, mut stream) = ws.split();
        // Spawned dial-back tasks report their fast-fail outcome here; the control
        // loop is the single writer on this connection.
        let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(16);
        let mut rotated = self.shared.renew.subscribe();
        // Ignore the credential we already hold; only a *change* matters.
        rotated.mark_unchanged();

        // Two missed intervals ⇒ dead (§7).
        let liveness = negotiated.heartbeat_interval.saturating_mul(2);
        let mut deadline = tokio::time::Instant::now() + liveness;

        loop {
            tokio::select! {
                biased;

                _ = stop.changed() => return Ended::Stopped,

                _ = rotated.changed() => return Ended::CredentialRotated,

                Some(frame) = out_rx.recv() => {
                    if let Err(e) = sink.send(Message::Binary(frame.into())).await {
                        return Ended::Fault(GatewayError::Io {
                            what: "control channel",
                            reason: e.to_string(),
                        });
                    }
                }

                _ = tokio::time::sleep_until(deadline) => {
                    return Ended::Fault(GatewayError::Io {
                        what: "control channel",
                        reason: format!(
                            "no frame from the Gateway for {liveness:?} (two missed heartbeats)"
                        ),
                    });
                }

                msg = stream.next() => {
                    let msg = match msg {
                        Some(Ok(m)) => m,
                        Some(Err(e)) => return Ended::Fault(GatewayError::Io {
                            what: "control channel",
                            reason: e.to_string(),
                        }),
                        None => return Ended::Fault(GatewayError::Closed),
                    };

                    let bytes = match binary_payload(msg) {
                        Ok(Some(b)) => b,
                        Ok(None) => continue, // a WebSocket control frame (ping/pong/close handling)
                        Err(e) => return Ended::Fault(e),
                    };

                    // Any frame proves the peer is alive, not only a PING.
                    deadline = tokio::time::Instant::now() + liveness;

                    let inbound = match wire::decode(
                        &bytes,
                        negotiated.version,
                        negotiated.max_frame_bytes,
                        Role::Control,
                    ) {
                        Ok(f) => f,
                        Err(e) => return Ended::Fault(GatewayError::Protocol(e)),
                    };

                    match inbound {
                        Inbound::Ping(p) => {
                            let pong = wire::out::pong(negotiated.version, p.nonce);
                            if let Err(e) = sink.send(Message::Binary(pong.into())).await {
                                return Ended::Fault(GatewayError::Io {
                                    what: "control channel",
                                    reason: e.to_string(),
                                });
                            }
                        }
                        Inbound::Pong(_) => {}
                        Inbound::DialBackRequest(req) => {
                            self.on_dial_back_request(*req, negotiated, cred, &out_tx);
                        }
                        Inbound::Error(err) => {
                            // Peer-supplied text is untrusted: log it escaped, and
                            // never interpolate it into an error chain (§8).
                            tracing::warn!(
                                code = err.code,
                                message = %err.message.escape_debug(),
                                "Gateway reported a protocol error; closing"
                            );
                            return Ended::Fault(GatewayError::Closed);
                        }
                        other => {
                            return Ended::Fault(GatewayError::Protocol(
                                wire::CodecError::IllegalForRole {
                                    ty: other.msg_type() as u8,
                                    role: Role::Control,
                                },
                            ));
                        }
                    }
                }
            }
        }
    }

    /// Decide whether to serve a dial-back, and if so spawn it.
    ///
    /// Three refusals happen here, before anything is dialled:
    /// 1. **The node must be ours.** A Gateway must not be able to task this Agent
    ///    for another node; the binding is the `dNSName` SAN of our own certificate
    ///    (`Credential.node_name`), which the CP stamped and we cannot self-assert.
    /// 2. **Per-channel affinity (FR-HA-6).** A request that arrived on THIS channel
    ///    may only dial back to THIS Gateway. In the HA model the node's owning
    ///    Gateway signals over its own control channel, so the dial-back endpoint
    ///    always equals the arriving channel. A gw-A that named gw-B's endpoint would
    ///    be trying to make the Agent open a connection to gw-B — refused. This
    ///    tightens F-connect-1 (which only required *a* configured Gateway) to *this*
    ///    channel's Gateway, so a compromised Gateway cannot task the Agent to reach a
    ///    peer Gateway.
    /// 3. **Capacity.** Beyond the shared cap we refuse rather than queue.
    fn on_dial_back_request(
        &self,
        req: DialBackRequest,
        negotiated: Negotiated,
        cred: &Credential,
        out_tx: &mpsc::Sender<Vec<u8>>,
    ) {
        let request_id = req.request_id.clone();

        if req.node_name != cred.node_name {
            tracing::warn!(
                request_id = %request_id.escape_debug(),
                requested_node = %req.node_name.escape_debug(),
                own_node = %cred.node_name,
                "refusing a dial-back request for a node that is not ours"
            );
            refuse(
                out_tx,
                negotiated.version,
                &request_id,
                DialBackErrorCode::Refused,
            );
            return;
        }

        let affine = transport::authority_of(&req.dial_back_endpoint)
            .map(|a| a == self.authority)
            .unwrap_or(false);
        if !affine {
            tracing::warn!(
                request_id = %request_id.escape_debug(),
                requested_endpoint = %req.dial_back_endpoint.escape_debug(),
                channel = %self.authority,
                "refusing a dial-back whose endpoint is not this control channel's Gateway (affinity)"
            );
            refuse(
                out_tx,
                negotiated.version,
                &request_id,
                DialBackErrorCode::Refused,
            );
            return;
        }

        let permit: OwnedSemaphorePermit = match self.shared.splices.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                tracing::warn!(
                    request_id = %request_id.escape_debug(),
                    cap = self.shared.config.max_concurrent_splices,
                    "refusing a dial-back request: at the concurrent-splice cap"
                );
                refuse(
                    out_tx,
                    negotiated.version,
                    &request_id,
                    DialBackErrorCode::Refused,
                );
                return;
            }
        };

        let config = self.shared.config.clone();
        let cred = cred.clone();
        let out_tx = out_tx.clone();
        let version = negotiated.version;
        tokio::spawn(async move {
            let _permit = permit; // released when the splice ends → the drain latch
            let request_id = req.request_id.clone();

            // The result is emitted as soon as the outcome is KNOWN, never at the end
            // of the session: it is a fast-fail signal (§5), so that the Gateway need
            // not wait out its dial-back deadline to learn the node's sshd is down.
            // Readiness is proven by STREAM_OPEN on the dial-back connection, not by
            // this frame.
            let live = match crate::gateway::splice::dial_back(&config, &cred, req).await {
                Ok(live) => live,
                Err((code, err)) => {
                    tracing::warn!(
                        request_id = %request_id.escape_debug(),
                        error = %err,
                        code = ?code,
                        "dial-back failed"
                    );
                    let _ = out_tx
                        .send(wire::out::dial_back_result(
                            version,
                            &DialBackResult {
                                request_id,
                                accepted: false,
                                error: code as i32,
                            },
                        ))
                        .await;
                    return;
                }
            };

            let _ = out_tx
                .send(wire::out::dial_back_result(
                    version,
                    &DialBackResult {
                        request_id: request_id.clone(),
                        accepted: true,
                        error: DialBackErrorCode::Unspecified as i32,
                    },
                ))
                .await;

            let reason = live.run().await;
            tracing::info!(
                request_id = %request_id.escape_debug(),
                reason = ?reason,
                "splice closed"
            );
        });
    }
}

/// Tracks fleet-wide reachability for the FR-HA-6 degrade. One is held for the
/// lifetime of a registered connection; the count is the number of currently-
/// registered control channels. **0 live channels is the hard degrade**: the node
/// is unreachable and callers must fall back to out-of-band tooling (there is
/// deliberately no bespoke fallback — the value of diverse channels is that all-lost
/// is rare). Dropping **below `min_control_channels`** (but still >0) warns that the
/// operator's requested redundancy is lost — for single-instance (min 1) the only
/// signal is the all-lost one, which is correct.
struct Reachability<'a> {
    shared: &'a Shared,
}

impl<'a> Reachability<'a> {
    fn register(shared: &'a Shared, endpoint: &GatewayEndpoint) -> Self {
        let now = shared.reachable.fetch_add(1, Ordering::SeqCst) + 1;
        if now == 1 {
            tracing::info!(
                endpoint = %endpoint.url,
                "node is reachable: a Gateway control channel is up"
            );
        }
        if now == shared.config.min_control_channels && shared.config.min_control_channels > 1 {
            tracing::info!(
                connected = now,
                "control-channel redundancy restored to the configured minimum"
            );
        }
        tracing::debug!(
            connected = now,
            of = shared.total_channels,
            "control channels up"
        );
        Self { shared }
    }
}

impl Drop for Reachability<'_> {
    fn drop(&mut self) {
        let now = self.shared.reachable.fetch_sub(1, Ordering::SeqCst) - 1;
        if now == 0 {
            tracing::error!(
                "ALL Gateway control channels are down — this node is UNREACHABLE. \
                 Degrade to out-of-band tooling (FR-HA-6); new sessions get the §7.1 \
                 'node offline / unreachable' outcome until a channel recovers"
            );
        } else if now < self.shared.config.min_control_channels {
            tracing::warn!(
                connected = now,
                min = self.shared.config.min_control_channels,
                "a control channel dropped below the configured minimum redundancy"
            );
        } else {
            tracing::debug!(
                connected = now,
                of = self.shared.total_channels,
                "a control channel dropped"
            );
        }
    }
}

fn refuse(out_tx: &mpsc::Sender<Vec<u8>>, version: u8, request_id: &str, code: DialBackErrorCode) {
    let frame = wire::out::dial_back_result(
        version,
        &DialBackResult {
            request_id: request_id.to_string(),
            accepted: false,
            error: code as i32,
        },
    );
    // try_send: refusing must never block the control loop.
    let _ = out_tx.try_send(frame);
}

/// Extract the payload of a WebSocket **binary** message. A text message is a
/// protocol error (§2); WebSocket-level ping/pong/close are handled by the library
/// and carry no frame.
fn binary_payload(msg: Message) -> Result<Option<Vec<u8>>, GatewayError> {
    match msg {
        Message::Binary(b) => Ok(Some(b.into())),
        Message::Text(_) => Err(GatewayError::Protocol(wire::CodecError::TextMessage)),
        Message::Close(_) => Err(GatewayError::Closed),
        Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => Ok(None),
    }
}

/// The connection preface (§3), run identically on **both** roles.
///
/// Sends `HELLO`, then requires exactly one of `HELLO_ACK` (adopt the negotiated
/// parameters) or `VERSION_REJECT` (**fail closed** — never downgrade, never guess:
/// FR-HA-9). Anything else is a protocol error. Bounded in time: a peer that
/// completes the TLS handshake and then goes silent must not hold a slot forever.
pub(crate) async fn preface(
    ws: &mut GatewayWs,
    role: Role,
    timeout: Duration,
) -> Result<Negotiated, GatewayError> {
    // The preface itself is sent at our own WIRE max major (§3); every later frame
    // carries the negotiated major. The wire version is deliberately independent of
    // the gRPC/component version (F-wireversion-2).
    let ver = version::WIRE_PROTOCOL_MAJOR as u8;

    let hello = wire::out::hello(ver, version::wire_component_info());
    ws.send(Message::Binary(hello.into()))
        .await
        .map_err(|e| GatewayError::Io {
            what: "preface",
            reason: e.to_string(),
        })?;

    let msg = tokio::time::timeout(timeout, ws.next())
        .await
        .map_err(|_| GatewayError::Preface(format!("no HELLO_ACK within {timeout:?}")))?;

    let bytes = match msg {
        Some(Ok(m)) => binary_payload(m)?
            .ok_or_else(|| GatewayError::Preface("expected HELLO_ACK".to_string()))?,
        Some(Err(e)) => {
            return Err(GatewayError::Io {
                what: "preface",
                reason: e.to_string(),
            })
        }
        None => return Err(GatewayError::Closed),
    };

    // Before negotiation the payload bound is the absolute ceiling (the WebSocket
    // reader already refuses anything larger).
    match wire::decode(&bytes, ver, wire::MAX_FRAME_BYTES_CEILING, role)? {
        Inbound::HelloAck(ack) => negotiated_from(ack),
        Inbound::VersionReject(rej) => Err(GatewayError::VersionRejected {
            gateway_min: rej.gateway_min.map(fmt_version).unwrap_or_default(),
            gateway_max: rej.gateway_max.map(fmt_version).unwrap_or_default(),
        }),
        other => Err(GatewayError::Preface(format!(
            "expected HELLO_ACK, got {:?}",
            other.msg_type()
        ))),
    }
}

fn fmt_version(v: crate::proto::ProtocolVersion) -> String {
    format!("{}.{}", v.major, v.minor)
}

/// Validate what the Gateway selected, and fail closed if it is outside what this
/// Agent actually supports. A peer does not get to pick a version we never
/// advertised, nor a frame bound we would have to allocate for.
fn negotiated_from(ack: crate::proto::wire::GatewayHelloAck) -> Result<Negotiated, GatewayError> {
    let selected = ack.selected.ok_or_else(|| {
        GatewayError::Preface("HELLO_ACK carried no selected version".to_string())
    })?;

    let (min, max) = (version::WIRE_PROTOCOL_MIN, version::WIRE_PROTOCOL_MAX);
    let in_range = selected.major == min.major
        && selected.major == max.major
        && selected.minor >= min.minor
        && selected.minor <= max.minor;
    if !in_range {
        return Err(GatewayError::Preface(format!(
            "Gateway selected protocol {}.{}, which is outside our advertised {}.{}-{}.{}",
            selected.major, selected.minor, min.major, min.minor, max.major, max.minor
        )));
    }

    let heartbeat = Duration::from_secs(u64::from(ack.heartbeat_interval_secs));
    if heartbeat < MIN_HEARTBEAT || heartbeat > MAX_HEARTBEAT {
        return Err(GatewayError::Preface(format!(
            "Gateway proposed a {}s heartbeat, outside the accepted {}s-{}s \
             (a channel with no usable liveness probe would strand the node silently)",
            ack.heartbeat_interval_secs,
            MIN_HEARTBEAT.as_secs(),
            MAX_HEARTBEAT.as_secs()
        )));
    }

    if ack.max_frame_bytes < wire::MIN_FRAME_BYTES
        || ack.max_frame_bytes > wire::MAX_FRAME_BYTES_CEILING
    {
        return Err(GatewayError::Preface(format!(
            "Gateway proposed max_frame_bytes {}, outside the accepted {}-{}",
            ack.max_frame_bytes,
            wire::MIN_FRAME_BYTES,
            wire::MAX_FRAME_BYTES_CEILING
        )));
    }

    Ok(Negotiated {
        version: selected.major as u8,
        heartbeat_interval: heartbeat,
        max_frame_bytes: ack.max_frame_bytes,
    })
}

/// Double the backoff, capped. Jitter is applied separately at each use so two
/// Agents that entered backoff together do not redial in lockstep (§7).
fn next_backoff(current: Duration, max: Duration) -> Duration {
    current.saturating_mul(2).min(max)
}

fn random_sample() -> f64 {
    use rand_core::RngCore;
    let x = rand_core::OsRng.next_u32();
    (f64::from(x) / f64::from(u32::MAX)) * 2.0 - 1.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::wire::GatewayHelloAck;
    use crate::proto::ProtocolVersion;

    fn ack(major: u32, minor: u32, heartbeat: u32, max_frame: u32) -> GatewayHelloAck {
        GatewayHelloAck {
            component: None,
            selected: Some(ProtocolVersion { major, minor }),
            heartbeat_interval_secs: heartbeat,
            max_frame_bytes: max_frame,
        }
    }

    #[test]
    fn accepts_the_baseline_negotiation() {
        let n = negotiated_from(ack(1, 0, 15, wire::PREFERRED_MAX_FRAME_BYTES)).unwrap();
        assert_eq!(n.version, 1);
        assert_eq!(n.heartbeat_interval, Duration::from_secs(15));
        assert_eq!(n.max_frame_bytes, wire::PREFERRED_MAX_FRAME_BYTES);
    }

    #[test]
    fn refuses_a_version_we_never_advertised() {
        // Fail closed: a Gateway does not get to select a protocol outside the
        // range we offered, in either direction.
        for (major, minor) in [(2, 0), (0, 9), (1, 7)] {
            assert!(
                negotiated_from(ack(major, minor, 15, wire::PREFERRED_MAX_FRAME_BYTES)).is_err(),
                "selected {major}.{minor} must be refused"
            );
        }
    }

    #[test]
    fn refuses_a_hello_ack_with_no_selected_version() {
        let mut a = ack(1, 0, 15, wire::PREFERRED_MAX_FRAME_BYTES);
        a.selected = None;
        assert!(negotiated_from(a).is_err());
    }

    #[test]
    fn refuses_an_unusable_heartbeat_including_none_at_all() {
        // 0 = "no heartbeat" would leave a dead channel undetectable.
        for hb in [0, 301, 3600] {
            assert!(
                negotiated_from(ack(1, 0, hb, wire::PREFERRED_MAX_FRAME_BYTES)).is_err(),
                "heartbeat {hb}s must be refused"
            );
        }
    }

    #[test]
    fn refuses_a_frame_bound_outside_what_we_will_allocate() {
        for max_frame in [
            0,
            64,
            wire::MIN_FRAME_BYTES - 1,
            wire::MAX_FRAME_BYTES_CEILING + 1,
        ] {
            assert!(
                negotiated_from(ack(1, 0, 15, max_frame)).is_err(),
                "max_frame_bytes {max_frame} must be refused"
            );
        }
        assert!(negotiated_from(ack(1, 0, 15, wire::MIN_FRAME_BYTES)).is_ok());
        assert!(negotiated_from(ack(1, 0, 15, wire::MAX_FRAME_BYTES_CEILING)).is_ok());
    }

    #[test]
    fn backoff_doubles_and_caps() {
        let max = Duration::from_secs(30);
        let mut b = Duration::from_secs(1);
        let mut seen = vec![b];
        for _ in 0..8 {
            b = next_backoff(b, max);
            seen.push(b);
        }
        assert_eq!(
            seen,
            vec![
                Duration::from_secs(1),
                Duration::from_secs(2),
                Duration::from_secs(4),
                Duration::from_secs(8),
                Duration::from_secs(16),
                Duration::from_secs(30),
                Duration::from_secs(30),
                Duration::from_secs(30),
                Duration::from_secs(30),
            ]
        );
    }

    #[test]
    fn backoff_jitter_spreads_reconnects_around_the_base() {
        // Fleet de-sync (§7): two Agents that lost the same Gateway must not redial
        // in lockstep. ±50% around the base, and never negative.
        let base = Duration::from_secs(10);
        assert_eq!(jittered_backoff(base, -1.0), Duration::from_secs(5));
        assert_eq!(jittered_backoff(base, 0.0), Duration::from_secs(10));
        assert_eq!(jittered_backoff(base, 1.0), Duration::from_secs(15));

        for _ in 0..64 {
            let d = jittered_backoff(base, random_sample());
            assert!(
                d >= Duration::from_secs(5) && d <= Duration::from_secs(15),
                "{d:?}"
            );
        }
    }
}
