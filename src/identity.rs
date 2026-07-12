//! Agent mTLS X.509 identity lifecycle (Session Twelve; Design §4, §8).
//!
//! A deliberate port + generalization of the Session-Four Gateway module
//! (`Gateway/gateway-core/src/identity.rs`): the Agent and Gateway solve the same
//! renewable-CP-identity problem. The Agent bootstraps with a [`JoinMethod`]
//! proof (token / delegated-OIDC / operator-mTLS) instead of a single enrollment
//! token, and thereafter holds a **renewable internal mTLS X.509 identity**
//! carrying a **generation counter** — the ongoing credential is ALWAYS mTLS
//! X.509 + generation counter regardless of join method (D25/D28). This module
//! owns:
//!
//! - **Key custody (D2/§15).** The Agent generates its ECDSA P-256 keypair + a
//!   PKCS#10 CSR locally and sends only the CSR; the mTLS private key never
//!   leaves. [`generate_keypair_and_csr`].
//! - **Bootstrap.** [`enroll`] runs `JoinMethod.attest(csr)` and calls
//!   `AgentIdentity.EnrollAgent` over the bootstrap channel, receiving the issued
//!   cert + CA chain + generation 0, bound to a stable node.
//! - **Persist-before-adopt (§8.2).** [`IdentityStore::persist_issued`] writes the
//!   new credential to the data-dir **atomically** (temp + fsync + rename + dir
//!   fsync) *before* it is adopted, so a crash between persist and adopt leaves a
//!   recoverable, consistent state — never a torn credential.
//! - **Single-writer lock (§8.2).** [`IdentityStore::open`] holds an exclusive
//!   advisory lock on the data-dir so two Agent processes can't race the
//!   credential / generation counter. A second holder is refused (fail closed).
//! - **Renew-ahead (§8.1, FR-JOIN-4).** [`RenewAhead`] renews at a configurable
//!   TTL fraction with jitter, plus a startup check and a manual trigger, each
//!   renewal **incrementing the generation** with persist-before-adopt. A
//!   CP-reported **generation mismatch** is a security event (§8.2 clone
//!   detection): the CP auto-locks the identity; the Agent refuses to adopt and
//!   stops the loop (operator re-provision; no auto-clear).
//! - **Lockable principal.** A locked/revoked identity (the CP refuses
//!   renew/re-enroll) is handled fail-closed — the old credential is kept, never
//!   a silent downgrade.

use crate::join::{JoinError, JoinMethod, JoinProof};
use crate::mtls::{self, ChannelParams, ClientIdentity};
use crate::proto::agent_identity_client::AgentIdentityClient;
use crate::proto::{
    enroll_agent_request, EnrollAgentRequest, MtlsJoinProof, OidcJoinProof,
    RenewAgentIdentityRequest, TokenJoinProof,
};
use crate::version;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, Zeroizing};

/// On-disk manifest schema version, so a future format change is detectable.
const MANIFEST_VERSION: u32 = 1;
const MANIFEST_NAME: &str = "identity.json";
const MANIFEST_TMP: &str = "identity.json.tmp";
const LOCK_NAME: &str = ".agent-identity.lock";

/// A failure in the identity lifecycle. Every variant is fail-closed: the caller
/// keeps whatever credential it already held and never proceeds unauthenticated.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    /// Filesystem error reading/writing the credential data-dir.
    #[error("identity store I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The data-dir is already locked by another Agent process (§8.2).
    #[error("data-dir {path} is locked by another Agent process")]
    AlreadyLocked { path: PathBuf },

    /// The persisted manifest could not be parsed — treated as unusable (fail
    /// closed) rather than guessed at.
    #[error("persisted identity manifest is corrupt: {0}")]
    Corrupt(String),

    /// Building or connecting the mTLS/bootstrap channel failed (§10.3).
    #[error(transparent)]
    Mtls(#[from] mtls::MtlsError),

    /// Producing the JoinMethod bootstrap proof failed (§8.1).
    #[error(transparent)]
    Join(#[from] JoinError),

    /// Keypair or CSR generation failed.
    #[error("keypair/CSR generation failed: {0}")]
    Csr(#[from] rcgen::Error),

    /// The CP refused the RPC (invalid/consumed proof, locked identity, version
    /// mismatch, …). The caller fails closed. Only the gRPC status **code** is
    /// rendered — never the CP-supplied message, which is untrusted wire text
    /// (log-injection / terminal-escape guard); the code is available
    /// programmatically via the wrapped `Status`.
    #[error("Control Plane refused the identity RPC (gRPC status {:?})", .0.code())]
    Rpc(#[from] tonic::Status),

    /// The CP returned a generation that is not exactly `current + 1` — a
    /// security event (§8.2): a cloned credential forks the counter. Refused and
    /// flagged; never silently adopted.
    #[error("generation mismatch: expected {expected}, Control Plane returned {got} (security event, refusing to adopt)")]
    GenerationMismatch { expected: u64, got: u64 },
}

/// The persisted credential manifest. A single file so the atomic rename gives
/// all-or-nothing crash safety. Written `0600` on unix. Deliberately NOT
/// `Debug`/`Clone`: it carries the private key.
#[derive(Serialize, Deserialize)]
struct CredentialManifest {
    manifest_version: u32,
    /// CP-assigned stable principal id (UUID string).
    agent_id: String,
    /// The stable node id (UUID string) the credential is bound to (FR-JOIN-6).
    node_id: String,
    /// The stable node name bound into the identity.
    node_name: String,
    /// Monotonic generation counter (§8.2). Enrollment is 0; each renewal +1.
    generation: u64,
    not_before_epoch_seconds: i64,
    not_after_epoch_seconds: i64,
    /// Issued leaf certificate, PEM.
    cert_pem: String,
    /// Issuing CA chain, PEM (issuing CA first, root last) — the trust anchor for
    /// the CP's server certificate.
    ca_chain_pem: Vec<String>,
    /// The mTLS private key, PEM. On-disk storage is unavoidable for a renewable
    /// identity; the file is `0600` and every in-memory copy is a [`Zeroizing`]
    /// buffer scrubbed on drop.
    #[serde(with = "crate::secret::serde_zeroizing_string")]
    key_pem: Zeroizing<String>,
}

/// A fully-adopted Agent credential: everything needed to present the mTLS client
/// identity and to verify the CP's server certificate.
#[derive(Clone)]
pub struct Credential {
    /// CP-assigned stable principal id.
    pub agent_id: String,
    /// The stable node id the credential is bound to (FR-JOIN-6).
    pub node_id: String,
    /// The stable node name bound into the identity.
    pub node_name: String,
    /// Monotonic generation counter (§8.2).
    pub generation: u64,
    pub not_before: SystemTime,
    pub not_after: SystemTime,
    /// The mTLS client identity (leaf cert PEM + private key PEM, zeroized).
    pub identity: ClientIdentity,
    /// CA chain (DER) — trust anchors for verifying the CP server certificate.
    pub ca_chain_der: Vec<Vec<u8>>,
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential")
            .field("agent_id", &self.agent_id)
            .field("node_id", &self.node_id)
            .field("node_name", &self.node_name)
            .field("generation", &self.generation)
            .field("not_before", &self.not_before)
            .field("not_after", &self.not_after)
            .field("identity", &self.identity)
            .field("ca_chain_len", &self.ca_chain_der.len())
            .finish()
    }
}

impl Credential {
    fn from_manifest(m: CredentialManifest) -> Result<Self, IdentityError> {
        let ca_chain_der = m.ca_chain_pem.iter().try_fold(Vec::new(), |mut acc, pem| {
            acc.extend(mtls::pem_certs_to_der(pem.as_bytes())?);
            Ok::<_, mtls::MtlsError>(acc)
        })?;
        let (not_before, not_after) =
            validated_window(m.not_before_epoch_seconds, m.not_after_epoch_seconds)?;
        Ok(Self {
            agent_id: m.agent_id,
            node_id: m.node_id,
            node_name: m.node_name,
            generation: m.generation,
            not_before,
            not_after,
            identity: ClientIdentity {
                cert_pem: m.cert_pem.into_bytes(),
                key_pem: m.key_pem,
            },
            ca_chain_der,
        })
    }
}

/// A freshly-issued credential (RPC response fields + the locally-held keypair)
/// to be persisted then adopted.
struct IssuedCredential {
    agent_id: String,
    node_id: String,
    node_name: String,
    generation: u64,
    not_before_epoch_seconds: i64,
    not_after_epoch_seconds: i64,
    cert_der: Vec<u8>,
    ca_chain_der: Vec<Vec<u8>>,
    key_pem: Zeroizing<String>,
}

/// A locally-generated keypair + its PKCS#10 CSR, ready to send to the CP.
pub struct KeypairCsr {
    /// PEM of the private key (never leaves the Agent; zeroized on drop).
    pub key_pem: Zeroizing<String>,
    /// The PKCS#10 CertificationRequest, DER.
    pub csr_der: Vec<u8>,
}

impl std::fmt::Debug for KeypairCsr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeypairCsr")
            .field("key_pem", &"<redacted>")
            .field("csr_der_len", &self.csr_der.len())
            .finish()
    }
}

/// Generate a fresh ECDSA P-256 keypair and a PKCS#10 CSR whose subject
/// alternative name is `node_name`. The private key stays local; only the CSR
/// (public key + proof of possession) is ever sent (D2/§15).
pub fn generate_keypair_and_csr(node_name: &str) -> Result<KeypairCsr, IdentityError> {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let params = rcgen::CertificateParams::new(vec![node_name.to_string()])?;
    let csr = params.serialize_request(&key)?;
    Ok(KeypairCsr {
        key_pem: Zeroizing::new(key.serialize_pem()),
        csr_der: csr.der().to_vec(),
    })
}

/// Owns the credential data-dir and the process-wide single-writer lock (§8.2).
///
/// The advisory lock is held for the lifetime of the process: the underlying
/// `RwLock<File>` is intentionally leaked to obtain a `'static` write guard (one
/// tiny allocation per process, released when the process exits). This guarantees
/// a second Agent process cannot open the same data-dir and race the generation
/// counter.
pub struct IdentityStore {
    data_dir: PathBuf,
    _lock: fd_lock::RwLockWriteGuard<'static, std::fs::File>,
}

impl IdentityStore {
    /// Open (creating if needed) the data-dir and acquire the exclusive
    /// single-writer lock. A second holder is refused (fail closed).
    pub fn open(data_dir: impl AsRef<Path>) -> Result<Self, IdentityError> {
        let data_dir = data_dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&data_dir)?;

        let lock_path = data_dir.join(LOCK_NAME);
        let file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)?;

        let lock: &'static mut fd_lock::RwLock<std::fs::File> =
            Box::leak(Box::new(fd_lock::RwLock::new(file)));
        let guard = lock.try_write().map_err(|_| IdentityError::AlreadyLocked {
            path: data_dir.clone(),
        })?;

        Ok(Self {
            data_dir,
            _lock: guard,
        })
    }

    /// The data-dir this store guards.
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// Load the persisted credential, if any. A missing manifest is `Ok(None)`
    /// (the un-enrolled state); a present-but-unparseable manifest is
    /// [`IdentityError::Corrupt`] (fail closed).
    pub fn load(&self) -> Result<Option<Credential>, IdentityError> {
        let path = self.data_dir.join(MANIFEST_NAME);
        let mut bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let parsed = serde_json::from_slice::<CredentialManifest>(&bytes)
            .map_err(|e| IdentityError::Corrupt(format!("{path:?}: {e}")));
        bytes.zeroize();
        let manifest = parsed?;
        if manifest.manifest_version != MANIFEST_VERSION {
            return Err(IdentityError::Corrupt(format!(
                "unsupported manifest version {}",
                manifest.manifest_version
            )));
        }
        Ok(Some(Credential::from_manifest(manifest)?))
    }

    /// Persist an issued credential **atomically**, then return the adopted
    /// in-memory [`Credential`]. This is the persist-before-adopt point (§8.2):
    /// the disk write completes before the caller adopts the returned value, so a
    /// crash between the two leaves the new credential fully on disk.
    fn persist_issued(&self, issued: IssuedCredential) -> Result<Credential, IdentityError> {
        // Persist-AFTER-validate: reject a bad CP-supplied validity window BEFORE
        // it can reach disk — otherwise a hostile/corrupt epoch would brick the
        // Agent into a load-time crash-loop (NFR-2).
        validated_window(
            issued.not_before_epoch_seconds,
            issued.not_after_epoch_seconds,
        )?;

        let ca_chain_pem: Vec<String> = issued
            .ca_chain_der
            .iter()
            .map(|der| String::from_utf8_lossy(&mtls::cert_der_to_pem(der)).into_owned())
            .collect();
        let cert_pem =
            String::from_utf8_lossy(&mtls::cert_der_to_pem(&issued.cert_der)).into_owned();

        let manifest = CredentialManifest {
            manifest_version: MANIFEST_VERSION,
            agent_id: issued.agent_id.clone(),
            node_id: issued.node_id.clone(),
            node_name: issued.node_name.clone(),
            generation: issued.generation,
            not_before_epoch_seconds: issued.not_before_epoch_seconds,
            not_after_epoch_seconds: issued.not_after_epoch_seconds,
            cert_pem,
            ca_chain_pem,
            key_pem: issued.key_pem,
        };

        let mut json = serde_json::to_vec_pretty(&manifest)
            .map_err(|e| IdentityError::Corrupt(format!("serialize manifest: {e}")))?;
        let write_result = atomic_write(&self.data_dir, MANIFEST_NAME, MANIFEST_TMP, &json);
        // The serialized buffer contains the private key; scrub it once the
        // on-disk copy (0600) is durable.
        json.zeroize();
        write_result?;

        Credential::from_manifest(manifest)
    }
}

/// Map a [`JoinProof`] onto the proto oneof for `EnrollAgentRequest`.
fn proof_to_proto(proof: JoinProof) -> enroll_agent_request::Proof {
    match proof {
        JoinProof::Token(t) => enroll_agent_request::Proof::Token(TokenJoinProof {
            join_token: (*t).clone(),
        }),
        JoinProof::Oidc(t) => enroll_agent_request::Proof::Oidc(OidcJoinProof {
            workload_token: (*t).clone(),
        }),
        JoinProof::Mtls {
            operator_certificate_der,
            pop_signature,
        } => enroll_agent_request::Proof::Mtls(MtlsJoinProof {
            operator_certificate: operator_certificate_der,
            pop_signature,
        }),
    }
}

/// Enroll the Agent: generate a keypair + CSR, produce the [`JoinMethod`] proof
/// bound to that CSR, call `EnrollAgent` over the bootstrap (server-auth) channel,
/// and persist-before-adopt the issued identity (generation 0).
/// `bootstrap_trust_anchors_der` is the operator-pinned CP anchor used to verify
/// the CP server certificate pre-enrollment.
pub async fn enroll(
    store: &IdentityStore,
    params: &ChannelParams,
    bootstrap_trust_anchors_der: &[Vec<u8>],
    join: &dyn JoinMethod,
    node_name: &str,
) -> Result<Credential, IdentityError> {
    let kc = generate_keypair_and_csr(node_name)?;
    let proof = join.attest(&kc.csr_der)?;

    let channel = mtls::connect_bootstrap(params, bootstrap_trust_anchors_der).await?;
    let mut client = AgentIdentityClient::new(channel);

    let resp = client
        .enroll_agent(tonic::Request::new(EnrollAgentRequest {
            pkcs10_csr: kc.csr_der.clone(),
            node_name: node_name.to_string(),
            client: Some(version::component_info()),
            proof: Some(proof_to_proto(proof)),
        }))
        .await?
        .into_inner();

    // Enrollment always issues generation 0 (contract). A different value is a
    // contract violation → fail closed.
    if resp.generation != 0 {
        return Err(IdentityError::GenerationMismatch {
            expected: 0,
            got: resp.generation,
        });
    }

    store.persist_issued(IssuedCredential {
        agent_id: resp.agent_id,
        node_id: resp.node_id,
        node_name: node_name.to_string(),
        generation: resp.generation,
        not_before_epoch_seconds: resp.not_before_epoch_seconds,
        not_after_epoch_seconds: resp.not_after_epoch_seconds,
        cert_der: resp.certificate,
        ca_chain_der: resp.ca_chain,
        key_pem: kc.key_pem,
    })
}

/// Renew the Agent's identity: generate a fresh keypair + CSR, call
/// `RenewAgentIdentity` over the **mTLS** channel authenticated by the current
/// credential, verify the returned generation is exactly `current + 1` (else a
/// [`IdentityError::GenerationMismatch`] security event), and persist-before-adopt
/// the rotated identity.
pub async fn renew(
    store: &IdentityStore,
    params: &ChannelParams,
    current: &Credential,
) -> Result<Credential, IdentityError> {
    let kc = generate_keypair_and_csr(&current.node_name)?;

    let channel = mtls::connect_mtls(params, &current.ca_chain_der, &current.identity).await?;
    let mut client = AgentIdentityClient::new(channel);

    let resp = client
        .renew_agent_identity(tonic::Request::new(RenewAgentIdentityRequest {
            pkcs10_csr: kc.csr_der.clone(),
            current_generation: current.generation,
            client: Some(version::component_info()),
        }))
        .await?
        .into_inner();

    let expected = current.generation + 1;
    if resp.generation != expected {
        return Err(IdentityError::GenerationMismatch {
            expected,
            got: resp.generation,
        });
    }

    store.persist_issued(IssuedCredential {
        agent_id: resp.agent_id,
        node_id: resp.node_id,
        node_name: current.node_name.clone(),
        generation: resp.generation,
        not_before_epoch_seconds: resp.not_before_epoch_seconds,
        not_after_epoch_seconds: resp.not_after_epoch_seconds,
        cert_der: resp.certificate,
        ca_chain_der: resp.ca_chain,
        key_pem: kc.key_pem,
    })
}

/// Compute how long to wait, from `now`, before triggering renew-ahead. The
/// trigger fires when a `fraction` of the certificate TTL has elapsed, shifted by
/// `jitter_sample` (`[-1, 1]`) times `jitter_fraction` of the TTL to de-sync a
/// fleet. The effective fraction is clamped to `[0, 0.95]`. If the trigger instant
/// is already past, the delay is zero — renew now.
pub fn compute_renew_delay(
    now: SystemTime,
    not_before: SystemTime,
    not_after: SystemTime,
    fraction: f64,
    jitter_fraction: f64,
    jitter_sample: f64,
) -> Duration {
    let ttl = match not_after.duration_since(not_before) {
        Ok(d) => d,
        Err(_) => return Duration::ZERO,
    };
    let eff = (fraction + jitter_sample * jitter_fraction).clamp(0.0, 0.95);
    let trigger_offset = ttl.mul_f64(eff);
    match not_before.checked_add(trigger_offset) {
        Some(trigger_instant) => trigger_instant
            .duration_since(now)
            .unwrap_or(Duration::ZERO),
        None => Duration::ZERO,
    }
}

/// Fraction of TTL remaining at `now`, in `[0, 1]`. Used by the startup check.
pub fn remaining_fraction(now: SystemTime, not_before: SystemTime, not_after: SystemTime) -> f64 {
    let ttl = match not_after.duration_since(not_before) {
        Ok(d) if !d.is_zero() => d,
        _ => return 0.0,
    };
    let remaining = not_after.duration_since(now).unwrap_or(Duration::ZERO);
    (remaining.as_secs_f64() / ttl.as_secs_f64()).clamp(0.0, 1.0)
}

/// A uniform jitter sample in `[-1, 1]` from the OS RNG, for production use.
fn random_jitter_sample() -> f64 {
    use rand_core::RngCore;
    let x = rand_core::OsRng.next_u32();
    (f64::from(x) / f64::from(u32::MAX)) * 2.0 - 1.0
}

// ---- atomic file write --------------------------------------------------------

/// Atomically publish `bytes` as `data_dir/final_name` via a temp file + fsync +
/// rename + directory fsync, so a crash never leaves a torn file. On unix the file
/// is created `0600` before any secret is written.
fn atomic_write(
    data_dir: &Path,
    final_name: &str,
    tmp_name: &str,
    bytes: &[u8],
) -> Result<(), std::io::Error> {
    use std::io::Write;

    let tmp = data_dir.join(tmp_name);
    let final_path = data_dir.join(final_name);

    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);

    std::fs::rename(&tmp, &final_path)?;

    let dir = std::fs::File::open(data_dir)?;
    dir.sync_all()?;
    Ok(())
}

// ---- epoch helpers ------------------------------------------------------------

/// Convert Unix epoch seconds to a [`SystemTime`] with **checked** arithmetic.
/// Returns `None` on overflow (e.g. a hostile/corrupt `i64::MIN`), so a bad
/// CP-supplied value can never panic and callers fail closed.
fn systemtime_from_epoch(epoch_seconds: i64) -> Option<SystemTime> {
    if epoch_seconds >= 0 {
        UNIX_EPOCH.checked_add(Duration::from_secs(epoch_seconds as u64))
    } else {
        UNIX_EPOCH.checked_sub(Duration::from_secs(epoch_seconds.unsigned_abs()))
    }
}

/// Validate a certificate validity window from CP-supplied epoch seconds: the
/// endpoints must be non-negative, convert without overflow, and satisfy
/// `not_before <= not_after`. A bad window is [`IdentityError::Corrupt`] — never a
/// panic, and (used in `persist_issued` before the write) never persisted to disk
/// (NFR-2).
fn validated_window(nb: i64, na: i64) -> Result<(SystemTime, SystemTime), IdentityError> {
    if nb < 0 || na < 0 {
        return Err(IdentityError::Corrupt(format!(
            "certificate validity epoch is negative (not_before {nb}, not_after {na})"
        )));
    }
    let not_before = systemtime_from_epoch(nb)
        .ok_or_else(|| IdentityError::Corrupt(format!("not_before epoch {nb} out of range")))?;
    let not_after = systemtime_from_epoch(na)
        .ok_or_else(|| IdentityError::Corrupt(format!("not_after epoch {na} out of range")))?;
    if not_after < not_before {
        return Err(IdentityError::Corrupt(format!(
            "certificate validity window inverted (not_before {nb} > not_after {na})"
        )));
    }
    Ok((not_before, not_after))
}

// ---- renew-ahead loop ---------------------------------------------------------

/// A handle to trigger a renewal on demand and to observe the current credential.
pub struct RenewHandle {
    trigger_tx: tokio::sync::mpsc::Sender<()>,
    current_rx: tokio::sync::watch::Receiver<std::sync::Arc<Credential>>,
}

impl RenewHandle {
    /// Request an immediate renewal (manual trigger, FR-JOIN-4). Best-effort.
    pub async fn trigger(&self) {
        let _ = self.trigger_tx.send(()).await;
    }

    /// The most recently adopted credential.
    pub fn current(&self) -> std::sync::Arc<Credential> {
        self.current_rx.borrow().clone()
    }

    /// A receiver for observing credential rotations.
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<std::sync::Arc<Credential>> {
        self.current_rx.clone()
    }
}

/// The renew-ahead loop configuration.
#[derive(Debug, Clone)]
pub struct RenewAheadConfig {
    /// TTL fraction elapsed before renew-ahead fires.
    pub renew_ahead_fraction: f64,
    /// Jitter as a fraction of the TTL (`±`).
    pub renew_jitter_fraction: f64,
    /// Retry backoff after a transient renewal failure.
    pub retry_backoff: Duration,
    /// The CP channel parameters for renewal RPCs.
    pub channel: ChannelParams,
}

/// The renew-ahead driver. Owns the [`IdentityStore`] and the current credential.
pub struct RenewAhead {
    store: IdentityStore,
    config: RenewAheadConfig,
    current_tx: tokio::sync::watch::Sender<std::sync::Arc<Credential>>,
    current_rx: tokio::sync::watch::Receiver<std::sync::Arc<Credential>>,
    trigger_rx: tokio::sync::mpsc::Receiver<()>,
    trigger_tx: tokio::sync::mpsc::Sender<()>,
}

impl RenewAhead {
    /// Create the driver seeded with an already-adopted `initial` credential.
    pub fn new(store: IdentityStore, config: RenewAheadConfig, initial: Credential) -> Self {
        let initial = std::sync::Arc::new(initial);
        let (current_tx, current_rx) = tokio::sync::watch::channel(initial);
        let (trigger_tx, trigger_rx) = tokio::sync::mpsc::channel(1);
        Self {
            store,
            config,
            current_tx,
            current_rx,
            trigger_rx,
            trigger_tx,
        }
    }

    /// A handle to trigger renewals and observe the current credential.
    pub fn handle(&self) -> RenewHandle {
        RenewHandle {
            trigger_tx: self.trigger_tx.clone(),
            current_rx: self.current_rx.clone(),
        }
    }

    /// Run the loop until `shutdown` resolves. Each iteration waits until the
    /// jittered renew-ahead instant (or a manual trigger, or shutdown), then
    /// renews with persist-before-adopt and publishes the new credential. A
    /// generation-mismatch security event (clone detection) stops the loop.
    pub async fn run(mut self, mut shutdown: impl std::future::Future<Output = ()> + Unpin) {
        loop {
            let current = self.current_rx.borrow().clone();
            let delay = compute_renew_delay(
                SystemTime::now(),
                current.not_before,
                current.not_after,
                self.config.renew_ahead_fraction,
                self.config.renew_jitter_fraction,
                random_jitter_sample(),
            );

            tokio::select! {
                biased;
                _ = &mut shutdown => {
                    tracing::info!("renew-ahead loop shutting down");
                    return;
                }
                _ = self.trigger_rx.recv() => {
                    tracing::info!("renew-ahead: manual trigger");
                }
                _ = tokio::time::sleep(delay) => {
                    tracing::info!(generation = current.generation, "renew-ahead: TTL fraction reached");
                }
            }

            match renew(&self.store, &self.config.channel, &current).await {
                Ok(new_cred) => {
                    tracing::info!(
                        agent_id = %new_cred.agent_id,
                        generation = new_cred.generation,
                        "renewed mTLS identity (persist-before-adopt)"
                    );
                    let _ = self.current_tx.send(std::sync::Arc::new(new_cred));
                }
                Err(IdentityError::GenerationMismatch { expected, got }) => {
                    // Security event (§8.2): the CP auto-locks the identity on a
                    // mismatch (possible clone). Refuse + stop; do NOT keep
                    // retrying. Operator re-provision (no auto-clear).
                    tracing::error!(
                        expected,
                        got,
                        "SECURITY: generation mismatch on renewal — the identity is auto-locked by the Control Plane (possible clone); stopping renew-ahead, operator re-provision required (§8.2)"
                    );
                    return;
                }
                Err(e) if is_repair_needed(&e) => {
                    // A rejection the CP will keep returning: locked identity,
                    // unknown/rotated client cert, or a stale generation the CP
                    // has already advanced past. Stop + flag for re-enrollment
                    // (§8.1). Fail-closed: the old credential is kept.
                    tracing::error!(
                        error = %e,
                        "REPAIR-NEEDED: renewal rejected by the Control Plane (locked / unknown cert / stale generation) — stopping renew-ahead; re-provision required (§8.1)"
                    );
                    return;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "renew-ahead: renewal failed transiently, will retry");
                    tokio::select! {
                        biased;
                        _ = &mut shutdown => return,
                        _ = tokio::time::sleep(self.config.retry_backoff) => {}
                    }
                }
            }
        }
    }
}

/// Whether a renewal error is a **repair-needed** rejection (the CP will keep
/// returning it) rather than a transient blip. Locked identity, unknown/rotated
/// client certificate, and a stale generation the CP has already advanced past
/// all map to gRPC codes that mean "this credential can't renew itself" → stop
/// and require re-provision (§8.1). `GenerationMismatch` is handled separately.
fn is_repair_needed(err: &IdentityError) -> bool {
    matches!(
        err,
        IdentityError::Rpc(status)
            if matches!(
                status.code(),
                tonic::Code::FailedPrecondition
                    | tonic::Code::Unauthenticated
                    | tonic::Code::PermissionDenied
            )
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch(now: SystemTime) -> i64 {
        now.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
    }

    #[test]
    fn keypair_and_csr_are_generated_and_key_stays_local() {
        let kc = generate_keypair_and_csr("node-x").unwrap();
        assert!(kc.csr_der.len() > 64, "CSR should be a real DER structure");
        assert!(kc.key_pem.starts_with("-----BEGIN"));
        assert!(
            !kc.csr_der
                .windows(16)
                .any(|w| w == &kc.key_pem.as_bytes()[..16]),
            "no fragment of the private key may appear in the CSR"
        );
    }

    #[test]
    fn compute_renew_delay_two_thirds_no_jitter() {
        let now = UNIX_EPOCH + Duration::from_secs(1_000);
        let delay = compute_renew_delay(
            now,
            now,
            now + Duration::from_secs(300),
            2.0 / 3.0,
            0.1,
            0.0,
        );
        assert_eq!(delay, Duration::from_secs(200));
    }

    #[test]
    fn compute_renew_delay_is_zero_when_past_trigger() {
        let not_before = UNIX_EPOCH + Duration::from_secs(1_000);
        let not_after = not_before + Duration::from_secs(300);
        let now = not_before + Duration::from_secs(250);
        assert_eq!(
            compute_renew_delay(now, not_before, not_after, 2.0 / 3.0, 0.0, 0.0),
            Duration::ZERO
        );
    }

    #[test]
    fn compute_renew_delay_jitter_is_bounded_before_expiry() {
        let now = UNIX_EPOCH + Duration::from_secs(1_000);
        let delay = compute_renew_delay(now, now, now + Duration::from_secs(300), 0.9, 0.5, 1.0);
        assert!(
            delay <= Duration::from_secs(285),
            "must renew before expiry"
        );
    }

    #[test]
    fn store_single_writer_lock_rejects_second_holder() {
        let dir = tempfile::tempdir().unwrap();
        let _first = IdentityStore::open(dir.path()).expect("first holder acquires the lock");
        let second = IdentityStore::open(dir.path());
        assert!(
            matches!(second, Err(IdentityError::AlreadyLocked { .. })),
            "a second process must be refused the data-dir lock"
        );
    }

    #[test]
    fn load_is_none_when_unenrolled() {
        let dir = tempfile::tempdir().unwrap();
        let store = IdentityStore::open(dir.path()).unwrap();
        assert!(store.load().unwrap().is_none());
    }

    #[test]
    fn persist_rejects_out_of_range_epoch_and_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let store = IdentityStore::open(dir.path()).unwrap();
        let mut issued = sample_issued("agent-bad", 0, SystemTime::now());
        issued.not_before_epoch_seconds = i64::MIN;
        let err = store.persist_issued(issued).unwrap_err();
        assert!(matches!(err, IdentityError::Corrupt(_)));
        assert!(
            store.load().unwrap().is_none(),
            "a rejected credential must never reach disk"
        );
    }

    #[test]
    fn load_rejects_out_of_range_epoch_without_panicking() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(MANIFEST_NAME);
        {
            let store = IdentityStore::open(dir.path()).unwrap();
            store
                .persist_issued(sample_issued("agent-tamper", 0, SystemTime::now()))
                .unwrap();
        }
        let bytes = std::fs::read(&path).unwrap();
        let mut manifest: CredentialManifest = serde_json::from_slice(&bytes).unwrap();
        manifest.not_before_epoch_seconds = i64::MIN;
        std::fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();

        let store = IdentityStore::open(dir.path()).unwrap();
        assert!(matches!(store.load(), Err(IdentityError::Corrupt(_))));
    }

    #[test]
    fn rpc_error_does_not_leak_cp_message() {
        // A hostile CP status message with ANSI + newline must not reach a log or
        // startup-stderr sink — neither via the error's own Display, nor via the
        // source chain that `#[from] tonic::Status` establishes when the error is
        // wrapped for propagation to `fn main`'s Termination Debug-print.
        let hostile = "evil\n\u{1b}[2Jline";
        let err = IdentityError::Rpc(tonic::Status::permission_denied(hostile));

        // (a) The error's own Display renders only the gRPC code.
        let disp = format!("{err}");
        assert!(!disp.contains("evil"), "Display leaked CP message: {disp}");
        assert!(!disp.contains('\u{1b}'));
        assert!(disp.contains("PermissionDenied"));

        // (b) The `main.rs` enroll/renew boundary wrap MUST flatten to the
        // code-only Display (`anyhow!("… {e}")`) and carry NO `tonic::Status`
        // source. Using `.context(_)` instead would keep the Status as `source()`,
        // and the source-chain-walking Debug print would emit the CP message.
        let wrapped = anyhow::anyhow!("agent enrollment failed: {err}");
        let dbg = format!("{wrapped:?}");
        assert!(
            !dbg.contains("evil"),
            "anyhow Debug leaked the CP message via the source chain: {dbg}"
        );
        assert!(!dbg.contains('\u{1b}'));
        assert_eq!(
            wrapped.chain().count(),
            1,
            "wrap must carry no error source"
        );
    }

    #[test]
    fn repair_needed_classifies_terminal_rejections() {
        assert!(is_repair_needed(&IdentityError::Rpc(
            tonic::Status::permission_denied("locked")
        )));
        assert!(is_repair_needed(&IdentityError::Rpc(
            tonic::Status::unauthenticated("unknown cert")
        )));
        assert!(is_repair_needed(&IdentityError::Rpc(
            tonic::Status::failed_precondition("stale generation")
        )));
        assert!(!is_repair_needed(&IdentityError::Rpc(
            tonic::Status::unavailable("cp restarting")
        )));
        assert!(!is_repair_needed(&IdentityError::Io(
            std::io::Error::other("x")
        )));
    }

    #[test]
    fn inverted_validity_window_is_rejected() {
        assert!(matches!(
            validated_window(1_000, 500),
            Err(IdentityError::Corrupt(_))
        ));
        assert!(validated_window(500, 1_000).is_ok());
    }

    #[test]
    fn persist_then_load_roundtrips_and_survives_simulated_crash() {
        let dir = tempfile::tempdir().unwrap();
        let now = SystemTime::now();
        let issued = sample_issued("agent-7", 0, now);
        let (want_id, want_gen, want_node) = (
            issued.agent_id.clone(),
            issued.generation,
            issued.node_id.clone(),
        );

        {
            let store = IdentityStore::open(dir.path()).unwrap();
            let adopted = store.persist_issued(issued).unwrap();
            assert_eq!(adopted.agent_id, want_id);
            // "crash": drop `adopted` and `store` without using them further.
        }

        let store2 = IdentityStore::open(dir.path()).unwrap();
        let loaded = store2
            .load()
            .unwrap()
            .expect("credential recovered after crash");
        assert_eq!(loaded.agent_id, want_id);
        assert_eq!(loaded.node_id, want_node);
        assert_eq!(loaded.generation, want_gen);
        assert!(loaded
            .identity
            .cert_pem
            .starts_with(b"-----BEGIN CERTIFICATE"));
        assert!(!loaded.ca_chain_der.is_empty());
    }

    #[test]
    fn persist_increments_generation_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let now = SystemTime::now();
        let store = IdentityStore::open(dir.path()).unwrap();

        let c0 = store
            .persist_issued(sample_issued("agent-9", 0, now))
            .unwrap();
        assert_eq!(c0.generation, 0);
        let c1 = store
            .persist_issued(sample_issued("agent-9", 1, now))
            .unwrap();
        assert_eq!(c1.generation, 1);
        assert_eq!(store.load().unwrap().unwrap().generation, 1);
    }

    #[test]
    fn corrupt_manifest_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let store = IdentityStore::open(dir.path()).unwrap();
        std::fs::write(dir.path().join(MANIFEST_NAME), b"{ not valid json").unwrap();
        assert!(matches!(store.load(), Err(IdentityError::Corrupt(_))));
    }

    #[cfg(unix)]
    #[test]
    fn persisted_manifest_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let store = IdentityStore::open(dir.path()).unwrap();
        store
            .persist_issued(sample_issued("agent-perm", 0, SystemTime::now()))
            .unwrap();
        let mode = std::fs::metadata(dir.path().join(MANIFEST_NAME))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o600,
            "credential manifest must be owner-read/write only"
        );
    }

    /// Build a sample issued credential with a real self-signed cert + CA so the
    /// PEM round-trips exercise the actual encode/parse path.
    fn sample_issued(agent_id: &str, generation: u64, now: SystemTime) -> IssuedCredential {
        let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let ca_params = rcgen::CertificateParams::new(vec!["test-ca".to_string()]).unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let leaf_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let leaf_params = rcgen::CertificateParams::new(vec!["cp.internal".to_string()]).unwrap();
        let leaf = leaf_params.self_signed(&leaf_key).unwrap();

        IssuedCredential {
            agent_id: agent_id.to_string(),
            node_id: "00000000-0000-0000-0000-0000000000aa".to_string(),
            node_name: "node-test".to_string(),
            generation,
            not_before_epoch_seconds: epoch(now),
            not_after_epoch_seconds: epoch(now + Duration::from_secs(3600)),
            cert_der: leaf.der().to_vec(),
            ca_chain_der: vec![ca_cert.der().to_vec()],
            key_pem: Zeroizing::new(leaf_key.serialize_pem()),
        }
    }
}
