//! In-process mock Control Plane for the Agent join/identity integration tests.
//!
//! A real TLS 1.3 tonic server (ring provider) that owns an internal mTLS CA
//! (rcgen, ECDSA P-256) and serves the `AgentIdentity` gRPC plane with
//! client-auth-**optional** (the bootstrap exception: `EnrollAgent` needs no
//! client cert; `RenewAgentIdentity` enforces one per-RPC via `peer_certs`). It
//! mirrors, in miniature, the real CP's behaviour the Agent must interoperate
//! with — including the generation-counter clone detection + auto-lock (§8.2).
//! Deliberately focused: proof VERIFICATION is only as deep as an Agent-side test
//! needs (the real JWKS/operator-CA/PoP verification lives in the CP repo);
//! caller resolution is by issued-certificate identity.
#![allow(dead_code)]

pub mod gateway;

use sessionlayer_agent::join::MTLS_JOIN_POP_CONTEXT;
use sessionlayer_agent::mtls::{self, ChannelParams};
use sessionlayer_agent::proto::agent_identity_server::{AgentIdentity, AgentIdentityServer};
use sessionlayer_agent::proto::{
    enroll_agent_request::Proof, EnrollAgentRequest, EnrollAgentResponse,
    RenewAgentIdentityRequest, RenewAgentIdentityResponse,
};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};

/// A self-signed test CA (ECDSA P-256) that signs CSRs and issues leaf certs.
pub struct TestCa {
    params: rcgen::CertificateParams,
    key_pem: String,
    cert_der: Vec<u8>,
}

impl TestCa {
    pub fn generate(cn: &str) -> Self {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = rcgen::CertificateParams::new(vec![cn.to_string()]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let cert = params.self_signed(&key).unwrap();
        Self {
            cert_der: cert.der().to_vec(),
            key_pem: key.serialize_pem(),
            params,
        }
    }

    pub fn cert_der(&self) -> &[u8] {
        &self.cert_der
    }

    pub fn cert_pem(&self) -> Vec<u8> {
        mtls::cert_der_to_pem(&self.cert_der)
    }

    fn issuer(&self) -> rcgen::Issuer<'static, rcgen::KeyPair> {
        let key = rcgen::KeyPair::from_pem(&self.key_pem).unwrap();
        rcgen::Issuer::new(self.params.clone(), key)
    }

    /// Sign an externally-generated PKCS#10 CSR (DER), returning the leaf DER.
    fn sign_csr(&self, csr_der: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        let typed = rustls::pki_types::CertificateSigningRequestDer::from(csr_der.to_vec());
        let csr = rcgen::CertificateSigningRequestParams::from_der(&typed)?;
        let cert = csr.signed_by(&self.issuer())?;
        Ok(cert.der().to_vec())
    }

    /// Issue a server leaf (fresh key) with a serverAuth EKU and the given SANs.
    pub fn server_leaf(&self, sans: &[&str]) -> (Vec<u8>, String) {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params =
            rcgen::CertificateParams::new(sans.iter().map(|s| s.to_string()).collect::<Vec<_>>())
                .unwrap();
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2100, 1, 1);
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let cert = params.signed_by(&key, &self.issuer()).unwrap();
        (mtls::cert_der_to_pem(cert.der()), key.serialize_pem())
    }
}

/// Per-agent registry record.
struct AgentRecord {
    node_id: String,
    node_name: String,
    generation: u64,
    locked: bool,
}

struct MockState {
    ca: TestCa,
    agents: HashMap<String, AgentRecord>,
    /// node_name -> agent_id of the ACTIVE identity (one per node, FR-JOIN-6).
    node_active_agent: HashMap<String, String>,
    /// Issued client-cert DER -> agent_id (current + previous, for renew overlap).
    leaf_to_agent: HashMap<Vec<u8>, String>,
    valid_tokens: HashSet<String>,
    consumed_tokens: HashSet<String>,
    expected_oidc: Option<String>,
    expected_operator_vk: Option<p256::ecdsa::VerifyingKey>,
    locked_nodes: HashSet<String>,
    cert_ttl: Duration,
    next_id: u64,
}

#[derive(Clone)]
struct MockSvc(Arc<Mutex<MockState>>);

fn epoch(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

#[tonic::async_trait]
impl AgentIdentity for MockSvc {
    async fn enroll_agent(
        &self,
        request: Request<EnrollAgentRequest>,
    ) -> Result<Response<EnrollAgentResponse>, Status> {
        let req = request.into_inner();
        let node_name = req.node_name;
        let csr = req.pkcs10_csr;
        let proof = req
            .proof
            .ok_or_else(|| Status::unauthenticated("no join proof"))?;

        let mut st = self.0.lock().unwrap();

        // Verify the JoinMethod proof (depth sufficient for an Agent-side test).
        match &proof {
            Proof::Token(t) => {
                let tok = &t.join_token;
                if !st.valid_tokens.contains(tok) || st.consumed_tokens.contains(tok) {
                    return Err(Status::unauthenticated("invalid or consumed token"));
                }
                st.consumed_tokens.insert(tok.clone()); // single-use self-destruct
            }
            Proof::Oidc(o) => {
                if st.expected_oidc.as_deref() != Some(o.workload_token.as_str()) {
                    return Err(Status::unauthenticated("workload token not accepted"));
                }
            }
            Proof::Mtls(m) => {
                let vk = st
                    .expected_operator_vk
                    .ok_or_else(|| Status::unauthenticated("mtls join not configured"))?;
                let mut message = MTLS_JOIN_POP_CONTEXT.to_vec();
                message.extend_from_slice(&csr);
                let sig = p256::ecdsa::Signature::from_der(&m.pop_signature)
                    .map_err(|_| Status::unauthenticated("malformed PoP signature"))?;
                use p256::ecdsa::signature::Verifier;
                vk.verify(&message, &sig)
                    .map_err(|_| Status::unauthenticated("PoP does not verify"))?;
            }
        }

        // Revocation is not bypassable by re-join: an incident lock covering the
        // node fails closed regardless of method (§8.1).
        if st.locked_nodes.contains(&node_name) {
            return Err(Status::permission_denied("node is locked"));
        }
        // One active identity per node — re-enroll of an active node is refused
        // (rotation goes through renew).
        if st.node_active_agent.contains_key(&node_name) {
            return Err(Status::failed_precondition("node already enrolled"));
        }

        let leaf = st
            .ca
            .sign_csr(&csr)
            .map_err(|_| Status::invalid_argument("invalid CSR"))?;
        let id = st.next_id;
        st.next_id += 1;
        let agent_id = format!("agent-{id}");
        let node_id = format!("node-{id}");
        let now = SystemTime::now();
        let nb = now - Duration::from_secs(300);
        let na = now + st.cert_ttl;

        st.agents.insert(
            agent_id.clone(),
            AgentRecord {
                node_id: node_id.clone(),
                node_name: node_name.clone(),
                generation: 0,
                locked: false,
            },
        );
        st.node_active_agent.insert(node_name, agent_id.clone());
        st.leaf_to_agent.insert(leaf.clone(), agent_id.clone());

        Ok(Response::new(EnrollAgentResponse {
            certificate: leaf,
            ca_chain: vec![st.ca.cert_der().to_vec()],
            agent_id,
            node_id,
            generation: 0,
            not_before_epoch_seconds: epoch(nb),
            not_after_epoch_seconds: epoch(na),
        }))
    }

    async fn renew_agent_identity(
        &self,
        request: Request<RenewAgentIdentityRequest>,
    ) -> Result<Response<RenewAgentIdentityResponse>, Status> {
        // mTLS client cert REQUIRED for renewal (no bootstrap exception).
        let peer = request
            .peer_certs()
            .ok_or_else(|| Status::unauthenticated("client certificate required"))?;
        let leaf = peer
            .first()
            .ok_or_else(|| Status::unauthenticated("client certificate required"))?
            .as_ref()
            .to_vec();
        let req = request.into_inner();

        let mut st = self.0.lock().unwrap();

        let agent_id = st
            .leaf_to_agent
            .get(&leaf)
            .cloned()
            .ok_or_else(|| Status::unauthenticated("unknown client certificate"))?;

        let (generation, node_name, node_id, locked) = {
            let rec = st
                .agents
                .get(&agent_id)
                .ok_or_else(|| Status::unauthenticated("unknown identity"))?;
            (
                rec.generation,
                rec.node_name.clone(),
                rec.node_id.clone(),
                rec.locked,
            )
        };

        if locked || st.locked_nodes.contains(&node_name) {
            return Err(Status::permission_denied("identity locked"));
        }

        // §8.2 clone detection: a declared generation that does not match the
        // stored one means a cloned credential forked the counter. AUTO-LOCK the
        // identity (and its node) and refuse; never auto-clear.
        if req.current_generation != generation {
            st.agents.get_mut(&agent_id).unwrap().locked = true;
            st.locked_nodes.insert(node_name);
            return Err(Status::failed_precondition(
                "generation mismatch (identity auto-locked)",
            ));
        }

        let new_leaf = st
            .ca
            .sign_csr(&req.pkcs10_csr)
            .map_err(|_| Status::invalid_argument("invalid CSR"))?;
        let new_gen = generation + 1;
        {
            let rec = st.agents.get_mut(&agent_id).unwrap();
            rec.generation = new_gen;
        }
        // Keep the PREVIOUS leaf mapped too (renew-ahead overlap: an in-flight
        // request may still present the prior cert), then add the new one.
        st.leaf_to_agent.insert(new_leaf.clone(), agent_id.clone());

        let now = SystemTime::now();
        let nb = now - Duration::from_secs(300);
        let na = now + st.cert_ttl;
        Ok(Response::new(RenewAgentIdentityResponse {
            certificate: new_leaf,
            ca_chain: vec![st.ca.cert_der().to_vec()],
            agent_id,
            node_id,
            generation: new_gen,
            not_before_epoch_seconds: epoch(nb),
            not_after_epoch_seconds: epoch(na),
        }))
    }
}

/// A running mock Control Plane. Aborts its server task on drop.
pub struct MockCp {
    endpoint: String,
    server_name: String,
    state: Arc<Mutex<MockState>>,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for MockCp {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl MockCp {
    /// Start a mock CP (SAN {controlplane, localhost, 127.0.0.1}, 1h cert TTL).
    pub async fn start() -> MockCp {
        sessionlayer_agent::tls::install_ring_provider();

        let ca = TestCa::generate("SessionLayer Internal mTLS CA");
        let (server_cert_pem, server_key_pem) =
            ca.server_leaf(&["controlplane", "localhost", "127.0.0.1"]);
        let ca_pem = ca.cert_pem();

        let state = Arc::new(Mutex::new(MockState {
            ca,
            agents: HashMap::new(),
            node_active_agent: HashMap::new(),
            leaf_to_agent: HashMap::new(),
            valid_tokens: HashSet::new(),
            consumed_tokens: HashSet::new(),
            expected_oidc: None,
            expected_operator_vk: None,
            locked_nodes: HashSet::new(),
            cert_ttl: Duration::from_secs(3600),
            next_id: 1,
        }));

        let tls = ServerTlsConfig::new()
            .identity(Identity::from_pem(
                &server_cert_pem,
                server_key_pem.as_bytes(),
            ))
            .client_ca_root(Certificate::from_pem(&ca_pem))
            .client_auth_optional(true);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);

        let svc = MockSvc(state.clone());
        let server = tokio::spawn(async move {
            let _ = Server::builder()
                .tls_config(tls)
                .expect("server tls config")
                .add_service(AgentIdentityServer::new(svc))
                .serve_with_incoming(incoming)
                .await;
        });

        MockCp {
            endpoint: format!("https://{addr}"),
            server_name: "controlplane".to_string(),
            state,
            server,
        }
    }

    /// The `https://127.0.0.1:PORT` endpoint the mock CP listens on.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// The bootstrap CA as PEM (for writing an anchor file a container can read).
    pub fn ca_pem(&self) -> Vec<u8> {
        mtls::cert_der_to_pem(self.state.lock().unwrap().ca.cert_der())
    }

    pub fn channel_params(&self, connect: Duration, rpc: Duration) -> ChannelParams {
        ChannelParams {
            endpoint: self.endpoint.clone(),
            server_name: self.server_name.clone(),
            connect_timeout: connect,
            rpc_timeout: rpc,
        }
    }

    /// The bootstrap trust anchor(s) — the internal CA DER the Agent pins.
    pub fn bootstrap_anchors(&self) -> Vec<Vec<u8>> {
        vec![self.state.lock().unwrap().ca.cert_der().to_vec()]
    }

    /// Register + return a valid single-use join token (TokenJoin).
    pub fn mint_token(&self) -> String {
        let mut st = self.state.lock().unwrap();
        let token = format!("join-token-{}", st.next_id);
        st.next_id += 1;
        st.valid_tokens.insert(token.clone());
        token
    }

    /// Configure the accepted OidcJoin workload token.
    pub fn set_expected_oidc(&self, token: &str) {
        self.state.lock().unwrap().expected_oidc = Some(token.to_string());
    }

    /// Set the TTL of issued certs. `Duration::ZERO` makes every issued cert land
    /// already-expired (`not_after == now`) — the renew-storm condition (F-renewstorm-1).
    pub fn set_cert_ttl(&self, ttl: Duration) {
        self.state.lock().unwrap().cert_ttl = ttl;
    }

    /// Configure the operator public key MtlsJoin PoP is verified against.
    pub fn set_operator_vk(&self, vk: p256::ecdsa::VerifyingKey) {
        self.state.lock().unwrap().expected_operator_vk = Some(vk);
    }

    /// The recorded generation of an agent id, if known.
    pub fn recorded_generation(&self, agent_id: &str) -> Option<u64> {
        self.state
            .lock()
            .unwrap()
            .agents
            .get(agent_id)
            .map(|r| r.generation)
    }

    /// Whether a node is locked (e.g. by clone detection).
    pub fn is_node_locked(&self, node_name: &str) -> bool {
        self.state.lock().unwrap().locked_nodes.contains(node_name)
    }

    /// Force-lock a node (incident lock).
    pub fn lock_node(&self, node_name: &str) {
        self.state
            .lock()
            .unwrap()
            .locked_nodes
            .insert(node_name.to_string());
    }

    /// Issue a serverAuth leaf from the internal mTLS CA. The test Gateway uses this
    /// so its server certificate chains to the SAME CA the Agent holds as its trust
    /// anchor — exactly the production relationship (wire contract §1).
    pub fn issue_server_leaf(&self, sans: &[&str]) -> (Vec<u8>, String) {
        self.state.lock().unwrap().ca.server_leaf(sans)
    }
}
