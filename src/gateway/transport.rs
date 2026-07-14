//! Dial **out** to a Gateway: TCP -> TLS 1.3 (mTLS) -> WebSocket
//! (`contracts/wire/agent-gateway-v1.md` §1).
//!
//! The Agent always dials; the Gateway never dials a node, so a node needs zero
//! inbound reachability. Both connection roles present the **same** S12 mTLS client
//! certificate and verify the Gateway's **serverAuth** leaf against the same
//! internal CA the Agent already holds (`Credential.ca_chain_der`), with the
//! Gateway's *enrolled name* as the expected server name — dial an address, verify
//! a name. There is no TOFU on this path.

use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::Uri;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::{client_async_with_config, WebSocketStream};

use crate::gateway::wire::{FRAME_HEADER_LEN, MAX_FRAME_BYTES_CEILING};
use crate::gateway::GatewayError;
use crate::identity::Credential;
use crate::mtls::Tls13OnlyPinnedVerifier;

/// The long-lived control connection (§1).
pub const CONTROL_PATH: &str = "/agent/v1/control";
/// One per session, torn down with it (§1).
pub const DIALBACK_PATH: &str = "/agent/v1/dialback";

/// A mutually-authenticated WebSocket to a Gateway.
pub type GatewayWs = WebSocketStream<tokio_rustls::client::TlsStream<TcpStream>>;

/// Split a `wss://host:port[/...]` endpoint into the authority we dial. The **path
/// is taken from the contract, never from the endpoint string** — the two roles
/// have fixed paths (§1), so neither an operator typo nor a hostile
/// `dial_back_endpoint` can steer the Agent onto a different resource.
fn authority_of(endpoint: &str) -> Result<String, GatewayError> {
    let uri: Uri = endpoint.parse().map_err(|_| GatewayError::Endpoint {
        endpoint: endpoint.to_string(),
        reason: "not a valid URI".to_string(),
    })?;
    match uri.scheme_str() {
        Some("wss") => {}
        _ => {
            // Refuse `ws://` outright: the mTLS identity and the session bytes may
            // never ride an unauthenticated, unencrypted transport (fail closed).
            return Err(GatewayError::Endpoint {
                endpoint: endpoint.to_string(),
                reason: "scheme must be wss:// (TLS is mandatory)".to_string(),
            });
        }
    }
    let host = uri.host().ok_or_else(|| GatewayError::Endpoint {
        endpoint: endpoint.to_string(),
        reason: "no host".to_string(),
    })?;
    let port = uri.port_u16().unwrap_or(443);
    Ok(if host.contains(':') {
        format!("[{host}]:{port}") // IPv6 literal
    } else {
        format!("{host}:{port}")
    })
}

/// PEM -> the DER material rustls needs for client auth. The key stays in memory
/// only as long as the config build; `PrivateKeyDer` scrubs it on drop.
fn client_auth_material(
    cred: &Credential,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), GatewayError> {
    let certs: Vec<CertificateDer<'static>> =
        crate::mtls::pem_certs_to_der(&cred.identity.cert_pem)
            .map_err(|e| GatewayError::ClientIdentity(e.to_string()))?
            .into_iter()
            .map(CertificateDer::from)
            .collect();
    if certs.is_empty() {
        return Err(GatewayError::ClientIdentity(
            "the credential holds no client certificate".to_string(),
        ));
    }

    let blocks = pem::parse_many(cred.identity.key_pem.as_str())
        .map_err(|e| GatewayError::ClientIdentity(format!("client key PEM parse failed: {e}")))?;
    let key = blocks
        .into_iter()
        .find(|p| p.tag().ends_with("PRIVATE KEY"))
        .ok_or_else(|| {
            GatewayError::ClientIdentity("client key PEM holds no PRIVATE KEY block".to_string())
        })?;
    let key = PrivateKeyDer::try_from(key.into_contents())
        .map_err(|e| GatewayError::ClientIdentity(format!("unusable client key: {e}")))?;

    Ok((certs, key))
}

/// Build the mTLS client config: the pinned TLS-1.3-only verifier over the
/// credential's own CA chain, presenting the credential's leaf.
fn tls_config(cred: &Credential) -> Result<rustls::ClientConfig, GatewayError> {
    crate::tls::install_ring_provider();

    let verifier = Arc::new(
        Tls13OnlyPinnedVerifier::new(&cred.ca_chain_der)
            .map_err(|e| GatewayError::TrustAnchor(e.to_string()))?,
    );
    let (certs, key) = client_auth_material(cred)?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| GatewayError::TrustAnchor(format!("TLS protocol versions: {e}")))?
        .dangerous() // "dangerous" only in that it replaces the webpki-roots default:
        // the verifier below is STRICTER (pinned to the internal CA).
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(certs, key)
        .map_err(|e| GatewayError::ClientIdentity(format!("client auth material rejected: {e}")))
}

/// The WebSocket reader bound. This is what actually prevents an oversized frame
/// from being *buffered* (the codec's negotiated bound is the second line): a
/// message beyond the ceiling is refused by the reader before it is assembled.
fn ws_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(FRAME_HEADER_LEN + MAX_FRAME_BYTES_CEILING as usize))
        .max_frame_size(Some(FRAME_HEADER_LEN + MAX_FRAME_BYTES_CEILING as usize))
}

/// Dial a Gateway and complete TCP + TLS 1.3 (mTLS) + the WebSocket upgrade on
/// `path`, all inside `connect_timeout` (a hung peer must never hang the Agent).
pub async fn connect(
    endpoint: &str,
    server_name: &str,
    path: &str,
    cred: &Credential,
    connect_timeout: Duration,
) -> Result<GatewayWs, GatewayError> {
    let authority = authority_of(endpoint)?;
    let config = Arc::new(tls_config(cred)?);

    // The name we VERIFY is the Gateway's enrolled name from local config — never
    // the host we happened to dial, and never anything taken from the wire.
    let name =
        ServerName::try_from(server_name.to_string()).map_err(|_| GatewayError::Endpoint {
            endpoint: server_name.to_string(),
            reason: "--gateway-server-name is not a valid DNS name".to_string(),
        })?;

    let request = format!("wss://{authority}{path}")
        .parse::<Uri>()
        .map_err(|_| GatewayError::Endpoint {
            endpoint: endpoint.to_string(),
            reason: "endpoint is not a valid wss:// URI".to_string(),
        })?
        .into_client_request()
        .map_err(|e| GatewayError::Endpoint {
            endpoint: endpoint.to_string(),
            reason: format!("not a valid WebSocket request: {e}"),
        })?;

    let connect = async {
        let tcp = TcpStream::connect(&authority)
            .await
            .map_err(|e| GatewayError::Connect {
                endpoint: authority.clone(),
                reason: e.to_string(),
            })?;
        // Interactive SSH rides this splice; Nagle would add keystroke latency.
        let _ = tcp.set_nodelay(true);

        let tls = TlsConnector::from(config)
            .connect(name, tcp)
            .await
            .map_err(|e| GatewayError::Tls {
                endpoint: authority.clone(),
                reason: e.to_string(),
            })?;

        let (ws, _response) = client_async_with_config(request, tls, Some(ws_config()))
            .await
            .map_err(|e| GatewayError::WebSocket {
                endpoint: authority.clone(),
                reason: e.to_string(),
            })?;
        Ok::<_, GatewayError>(ws)
    };

    match tokio::time::timeout(connect_timeout, connect).await {
        Ok(result) => result,
        Err(_) => Err(GatewayError::Timeout {
            endpoint: authority,
            after: connect_timeout,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_takes_host_and_port_and_ignores_any_path() {
        // The path is contract-fixed per role; whatever a peer puts in the endpoint
        // string cannot steer us onto another resource.
        assert_eq!(
            authority_of("wss://gw.example:8443/some/other/path").unwrap(),
            "gw.example:8443"
        );
        assert_eq!(authority_of("wss://gw.example").unwrap(), "gw.example:443");
        assert_eq!(authority_of("wss://[::1]:9443").unwrap(), "[::1]:9443");
    }

    #[test]
    fn plaintext_and_malformed_endpoints_are_refused() {
        for bad in [
            "ws://gw.example:8443",
            "http://gw.example",
            "https://gw.example",
            "gw.example:8443",
            "",
        ] {
            assert!(
                authority_of(bad).is_err(),
                "{bad:?} must be refused (TLS is mandatory on this transport)"
            );
        }
    }
}
