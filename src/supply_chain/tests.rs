//! The verify-before-run tamper matrix (NFR-7). A correctly signed, provenanced,
//! correct-identity binary verifies; an unsigned, a tampered, a wrong-identity,
//! and a wrong-workflow binary are each refused (fail closed). Plus the
//! trust-anchor edge cases a reviewer would probe: an expired leaf, a chain to an
//! un-pinned CA, and a Rekor SET not bound to the artifact.
//!
//! Fixtures build a real Fulcio-shaped chain (P-384 root and intermediate, P-256
//! leaf) with the exact Sigstore-bundle fields, so this exercises the real
//! verifier, not a mock.

use base64::Engine as _;
use p256::ecdsa::signature::Signer;
use rcgen::string::Ia5String;
use rcgen::{
    BasicConstraints, CertificateParams, CustomExtension, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::*;

const ISSUER: &str = "https://token.actions.githubusercontent.com";
const REPO: &str = "https://github.com/SessionLayer/Agent";
const SAN_OK: &str =
    "https://github.com/SessionLayer/Agent/.github/workflows/release.yml@refs/tags/v1.2.3";
const BUILD_TYPE: &str = "https://actions.github.io/buildtypes/workflow/v1";
const LOG_TIME: i64 = 1_800_000_000; // ~2027-01, inside the fixtures' leaf window.

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn der_utf8(s: &str) -> Vec<u8> {
    let mut v = vec![0x0c, s.len() as u8];
    v.extend_from_slice(s.as_bytes());
    v
}

/// DSSE PAE — replicated from `dsse` (a private sibling) so the fixture signs the
/// exact bytes the verifier reconstructs.
fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"DSSEv1 ");
    out.extend_from_slice(payload_type.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload_type.as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload);
    out
}

struct Params {
    san: String,
    issuer: String,
    source_repo: String,
    leaf_not_before: (i32, u8, u8),
    leaf_not_after: (i32, u8, u8),
    /// Sign the leaf with an un-pinned intermediate (forged chain).
    forge_chain: bool,
    /// Emit a Rekor provenance body that does NOT reference the payload digest.
    unbind_set: bool,
}

impl Default for Params {
    fn default() -> Self {
        Self {
            san: SAN_OK.into(),
            issuer: ISSUER.into(),
            source_repo: REPO.into(),
            leaf_not_before: (2020, 1, 1),
            leaf_not_after: (2100, 1, 1),
            forge_chain: false,
            unbind_set: false,
        }
    }
}

fn ca(cn: &str, alg: &'static rcgen::SignatureAlgorithm) -> (CertificateParams, KeyPair) {
    let key = KeyPair::generate_for(alg).unwrap();
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.distinguished_name.push(DnType::CommonName, cn);
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    p.not_before = rcgen::date_time_ymd(2020, 1, 1);
    p.not_after = rcgen::date_time_ymd(2100, 1, 1);
    (p, key)
}

struct Fixture {
    binary: Vec<u8>,
    trust: TrustRoot,
    policy: VerificationPolicy,
    leaf_sk: p256::ecdsa::SigningKey,
    rekor_sk: p256::ecdsa::SigningKey,
    leaf_der: Vec<u8>,
    p: Params,
}

fn build(p: Params) -> Fixture {
    let (root_params, root_key) = ca("Test Fulcio Root", &rcgen::PKCS_ECDSA_P384_SHA384);
    let root_cert = root_params.clone().self_signed(&root_key).unwrap();
    let root_der = root_cert.der().to_vec();
    let root_issuer = Issuer::new(root_params, root_key);

    let (inter_params, inter_key) = ca("Test Fulcio Intermediate", &rcgen::PKCS_ECDSA_P384_SHA384);
    let inter_cert = inter_params
        .clone()
        .signed_by(&inter_key, &root_issuer)
        .unwrap();
    let inter_der = inter_cert.der().to_vec();
    let inter_issuer = Issuer::new(inter_params, inter_key);

    // An independent CA that is NOT in the trust root — used to forge a chain.
    let (rogue_params, rogue_key) = ca("Rogue CA", &rcgen::PKCS_ECDSA_P384_SHA384);
    let rogue_issuer = Issuer::new(rogue_params, rogue_key);

    let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut leaf = CertificateParams::new(Vec::<String>::new()).unwrap();
    leaf.distinguished_name.push(DnType::CommonName, "sigstore");
    leaf.subject_alt_names = vec![SanType::URI(Ia5String::try_from(p.san.clone()).unwrap())];
    leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::CodeSigning];
    leaf.custom_extensions = vec![
        CustomExtension::from_oid_content(&[1, 3, 6, 1, 4, 1, 57264, 1, 8], der_utf8(&p.issuer)),
        CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 57264, 1, 12],
            der_utf8(&p.source_repo),
        ),
    ];
    let (ny, nm, nd) = p.leaf_not_before;
    let (ay, am, ad) = p.leaf_not_after;
    leaf.not_before = rcgen::date_time_ymd(ny, nm, nd);
    leaf.not_after = rcgen::date_time_ymd(ay, am, ad);
    let signer = if p.forge_chain {
        &rogue_issuer
    } else {
        &inter_issuer
    };
    let leaf_cert = leaf.signed_by(&leaf_key, signer).unwrap();
    let leaf_der = leaf_cert.der().to_vec();

    use p256::pkcs8::DecodePrivateKey;
    let leaf_sk = p256::ecdsa::SigningKey::from_pkcs8_pem(&leaf_key.serialize_pem()).unwrap();
    let rekor_sk = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);

    let trust = TrustRoot {
        fulcio_cas: vec![root_der, inter_der],
        rekor_keys: vec![*rekor_sk.verifying_key()],
    };

    Fixture {
        binary: b"the-real-sessionlayer-agent-binary".to_vec(),
        trust,
        policy: VerificationPolicy {
            oidc_issuer: ISSUER.into(),
            workflow_ref_prefix:
                "https://github.com/SessionLayer/Agent/.github/workflows/release.yml@refs/tags/v"
                    .into(),
            source_repo_uri: REPO.into(),
            build_type: BUILD_TYPE.into(),
        },
        leaf_sk,
        rekor_sk,
        leaf_der,
        p,
    }
}

impl Fixture {
    fn set_b64(&self, body_b64: &str, log_id_hex: &str, log_index: i64) -> String {
        let payload =
            super::rekor::canonical_set_payload(body_b64, LOG_TIME, log_id_hex, log_index);
        let sig: p256::ecdsa::Signature = self.rekor_sk.sign(payload.as_bytes());
        b64(sig.to_der().as_bytes())
    }

    fn tlog(&self, body_b64: &str, log_index: i64) -> Value {
        let log_id_bytes = [0x11u8; 32];
        let log_id_hex = to_hex(&log_id_bytes);
        json!({
            "logIndex": log_index.to_string(),
            "integratedTime": LOG_TIME.to_string(),
            "logId": { "keyId": b64(&log_id_bytes) },
            "inclusionPromise": { "signedEntryTimestamp": self.set_b64(body_b64, &log_id_hex, log_index) },
            "canonicalizedBody": body_b64,
            "kindVersion": { "kind": "hashedrekord", "version": "0.0.1" },
        })
    }

    /// cosign blob-signature bundle over `binary`.
    fn blob_bundle(&self, binary: &[u8]) -> Bundle {
        let digest = Sha256::digest(binary);
        let sig: p256::ecdsa::Signature = self.leaf_sk.sign(binary);
        let body = format!(
            r#"{{"kind":"hashedrekord","spec":{{"data":{{"hash":{{"algorithm":"sha256","value":"{}"}}}}}}}}"#,
            to_hex(&digest)
        );
        let v = json!({
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "verificationMaterial": {
                "certificate": { "rawBytes": b64(&self.leaf_der) },
                "tlogEntries": [ self.tlog(&b64(body.as_bytes()), 42) ],
            },
            "messageSignature": {
                "messageDigest": { "algorithm": "SHA2_256", "digest": b64(&digest) },
                "signature": b64(sig.to_der().as_bytes()),
            },
        });
        Bundle::parse(v.to_string().as_bytes()).unwrap()
    }

    /// SLSA provenance attestation bundle attesting `binary`.
    fn prov_bundle(&self, binary: &[u8]) -> Bundle {
        let digest_hex = to_hex(&Sha256::digest(binary));
        let statement = json!({
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [ { "name": "sessionlayer-agent", "digest": { "sha256": digest_hex } } ],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {
                "buildDefinition": {
                    "buildType": BUILD_TYPE,
                    "externalParameters": { "workflow": {
                        "repository": REPO, "ref": "refs/tags/v1.2.3", "path": ".github/workflows/release.yml"
                    }},
                },
                "runDetails": { "builder": { "id": SAN_OK } },
            },
        });
        let payload = serde_json::to_vec(&statement).unwrap();
        let payload_type = "application/vnd.in-toto+json";
        let sig: p256::ecdsa::Signature = self.leaf_sk.sign(&pae(payload_type, &payload));
        let payload_digest_hex = to_hex(&Sha256::digest(&payload));
        let bound = if self.p.unbind_set {
            "0".repeat(64)
        } else {
            payload_digest_hex
        };
        let body = format!(
            r#"{{"kind":"dsse","spec":{{"payloadHash":{{"algorithm":"sha256","value":"{bound}"}}}}}}"#
        );
        let v = json!({
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "verificationMaterial": {
                "certificate": { "rawBytes": b64(&self.leaf_der) },
                "tlogEntries": [ self.tlog(&b64(body.as_bytes()), 43) ],
            },
            "dsseEnvelope": {
                "payload": b64(&payload),
                "payloadType": payload_type,
                "signatures": [ { "sig": b64(sig.to_der().as_bytes()) } ],
            },
        });
        Bundle::parse(v.to_string().as_bytes()).unwrap()
    }

    fn verify(&self, binary: &[u8]) -> Result<VerifiedRelease, VerifyError> {
        verify_binary(
            binary,
            &self.blob_bundle(binary),
            &self.prov_bundle(binary),
            &self.policy,
            &self.trust,
        )
    }
}

#[test]
fn accepts_valid_release() {
    let f = build(Params::default());
    let ok = f
        .verify(&f.binary)
        .expect("a correctly signed release must verify");
    assert_eq!(ok.san, SAN_OK);
    assert_eq!(ok.source_repo, REPO);
    assert_eq!(ok.digest_hex, to_hex(&Sha256::digest(&f.binary)));
}

#[test]
fn refuses_unsigned() {
    // No signature material at all — the "unsigned binary" case.
    let empty = Bundle::parse(br#"{"verificationMaterial":{"tlogEntries":[]}}"#).unwrap();
    let f = build(Params::default());
    let err = verify_binary(
        &f.binary,
        &empty,
        &f.prov_bundle(&f.binary),
        &f.policy,
        &f.trust,
    )
    .unwrap_err();
    assert!(matches!(err, VerifyError::Transparency(_)), "got {err:?}");
}

#[test]
fn refuses_tampered_binary() {
    let f = build(Params::default());
    // Bundles attest the real binary; verify a mutated one against them.
    let mut tampered = f.binary.clone();
    tampered.extend_from_slice(b"+backdoor");
    let err = verify_binary(
        &tampered,
        &f.blob_bundle(&f.binary),
        &f.prov_bundle(&f.binary),
        &f.policy,
        &f.trust,
    )
    .unwrap_err();
    assert!(matches!(err, VerifyError::DigestMismatch(_)), "got {err:?}");
}

#[test]
fn refuses_wrong_identity() {
    let err = build(Params {
        san: "https://github.com/evil/Agent/.github/workflows/release.yml@refs/tags/v1.2.3".into(),
        source_repo: "https://github.com/evil/Agent".into(),
        ..Default::default()
    })
    .verify_default()
    .unwrap_err();
    assert!(
        matches!(err, VerifyError::Identity { field, .. } if field == "san_workflow_ref" || field == "source_repository"),
        "got {err:?}"
    );
}

#[test]
fn refuses_wrong_workflow() {
    let err = build(Params {
        san: "https://github.com/SessionLayer/Agent/.github/workflows/evil.yml@refs/tags/v1.2.3"
            .into(),
        ..Default::default()
    })
    .verify_default()
    .unwrap_err();
    assert!(
        matches!(err, VerifyError::Identity { field, .. } if field == "san_workflow_ref"),
        "got {err:?}"
    );
}

#[test]
fn refuses_expired_at_log_time() {
    let err = build(Params {
        leaf_not_before: (2019, 1, 1),
        leaf_not_after: (2019, 6, 1), // ends long before LOG_TIME (~2027)
        ..Default::default()
    })
    .verify_default()
    .unwrap_err();
    assert!(matches!(err, VerifyError::CertValidity(_)), "got {err:?}");
}

#[test]
fn refuses_forged_chain() {
    let err = build(Params {
        forge_chain: true,
        ..Default::default()
    })
    .verify_default()
    .unwrap_err();
    assert!(matches!(err, VerifyError::Chain(_)), "got {err:?}");
}

#[test]
fn refuses_set_not_bound_to_artifact() {
    let err = build(Params {
        unbind_set: true,
        ..Default::default()
    })
    .verify_default()
    .unwrap_err();
    assert!(matches!(err, VerifyError::Transparency(_)), "got {err:?}");
}

#[test]
fn refuses_untrusted_rekor_key() {
    // The bundle's SET is signed by a key not in the trust root.
    let mut f = build(Params::default());
    f.trust.rekor_keys =
        vec![*p256::ecdsa::SigningKey::random(&mut rand_core::OsRng).verifying_key()];
    let err = f.verify(&f.binary).unwrap_err();
    assert!(matches!(err, VerifyError::Transparency(_)), "got {err:?}");
}

impl Fixture {
    fn verify_default(&self) -> Result<VerifiedRelease, VerifyError> {
        self.verify(&self.binary)
    }
}

// --- The run/update boundary: an unverified binary is never launched/installed.

use std::cell::RefCell;
use std::path::{Path, PathBuf};

struct SpyLauncher {
    launched: RefCell<Option<PathBuf>>,
}
impl crate::update::Launcher for SpyLauncher {
    fn launch(&self, binary: &Path) -> std::io::Result<()> {
        *self.launched.borrow_mut() = Some(binary.to_path_buf());
        Ok(())
    }
}

#[test]
fn run_launches_only_a_verified_binary() {
    let f = build(Params::default());
    let updater = crate::update::SelfUpdater::new(f.trust.clone(), f.policy.clone());
    let blob = f.blob_bundle(&f.binary);
    let prov = f.prov_bundle(&f.binary);

    let tmp = tempfile::tempdir().unwrap();
    let cand = tmp.path().join("candidate");

    std::fs::write(&cand, &f.binary).unwrap();
    let spy = SpyLauncher {
        launched: RefCell::new(None),
    };
    updater.run(&cand, &blob, &prov, &spy).unwrap();
    assert_eq!(spy.launched.into_inner().as_deref(), Some(cand.as_path()));

    // A tampered candidate on disk (bundles unchanged) must be refused, unlaunched.
    std::fs::write(&cand, b"tampered").unwrap();
    let spy = SpyLauncher {
        launched: RefCell::new(None),
    };
    let err = updater.run(&cand, &blob, &prov, &spy).unwrap_err();
    assert!(
        matches!(err, crate::update::UpdateError::Verify(_)),
        "got {err:?}"
    );
    assert!(
        spy.launched.into_inner().is_none(),
        "must not launch an unverified binary"
    );
}

#[test]
fn install_never_writes_an_unverified_binary() {
    let f = build(Params::default());
    let updater = crate::update::SelfUpdater::new(f.trust.clone(), f.policy.clone());
    let blob = f.blob_bundle(&f.binary);
    let prov = f.prov_bundle(&f.binary);

    let tmp = tempfile::tempdir().unwrap();
    let cand = tmp.path().join("candidate");
    let live = tmp.path().join("live-agent");
    std::fs::write(&live, b"OLD-VERIFIED-BINARY").unwrap();

    // Tampered candidate → refused; the live binary is untouched.
    std::fs::write(&cand, b"tampered").unwrap();
    let err = updater.install(&cand, &blob, &prov, &live).unwrap_err();
    assert!(
        matches!(err, crate::update::UpdateError::Verify(_)),
        "got {err:?}"
    );
    assert_eq!(std::fs::read(&live).unwrap(), b"OLD-VERIFIED-BINARY");

    // Valid candidate → installed atomically.
    std::fs::write(&cand, &f.binary).unwrap();
    updater.install(&cand, &blob, &prov, &live).unwrap();
    assert_eq!(std::fs::read(&live).unwrap(), f.binary);
}
