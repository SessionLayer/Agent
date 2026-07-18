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
use p256::pkcs8::EncodePublicKey;
use rcgen::string::Ia5String;
use rcgen::{
    BasicConstraints, CertificateParams, CustomExtension, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType, SerialNumber,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::trust::{CtLogKey, FulcioCa, RekorKey, TimeRange};
use super::*;

/// OID `1.3.6.1.4.1.11129.2.4.2` (embedded SCT list), as rcgen OID components.
const SCT_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 11129, 2, 4, 2];

/// A `validFor` window that contains every fixture's `LOG_TIME` — the default so
/// the pre-existing tamper matrix is unaffected by window enforcement.
const OPEN_WINDOW: TimeRange = TimeRange {
    start: 0,
    end: None,
};

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
    /// Pin a CT-log key in the trust root, making SCT verification mandatory.
    ct_pinned: bool,
    /// Embed a precert SCT in the leaf (real Fulcio shape). Requires `ct_pinned`
    /// to be enforced; without it the leaf simply carries the extension.
    embed_sct: bool,
    /// Sign the embedded SCT with a key that is NOT the pinned CT-log key.
    sct_wrong_key: bool,
    /// Embed a certificate OTHER than the signing leaf in the Rekor body.
    wrong_body_cert: bool,
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
            ct_pinned: false,
            embed_sct: false,
            sct_wrong_key: false,
            wrong_body_cert: false,
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
    /// A different, valid certificate (the CA root) for the wrong-body-cert case.
    alt_cert_der: Vec<u8>,
    p: Params,
}

fn spki_of(cert_der: &[u8]) -> Vec<u8> {
    let (_, c) = x509_parser::parse_x509_certificate(cert_der).unwrap();
    c.public_key().raw.to_vec()
}

fn pem_of(der: &[u8]) -> String {
    pem::encode(&pem::Pem::new("CERTIFICATE", der.to_vec()))
}

fn der_len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        return vec![n as u8];
    }
    let mut be = n.to_be_bytes().to_vec();
    while be.first() == Some(&0) {
        be.remove(0);
    }
    let mut out = vec![0x80 | be.len() as u8];
    out.extend_from_slice(&be);
    out
}

fn u24(n: usize) -> [u8; 3] {
    let b = (n as u32).to_be_bytes();
    [b[1], b[2], b[3]]
}

/// RFC 6962 §3.2 precert signed data — kept independent of `sct.rs` so the accept
/// test cross-checks the verifier's own encoding AND its precert reconstruction.
fn sct_signed_data(timestamp_ms: u64, issuer_key_hash: &[u8], precert_tbs: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8, 0u8]; // sct_version v1, signature_type certificate_timestamp
    out.extend_from_slice(&timestamp_ms.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // precert_entry
    out.extend_from_slice(issuer_key_hash);
    out.extend_from_slice(&u24(precert_tbs.len()));
    out.extend_from_slice(precert_tbs);
    out.extend_from_slice(&0u16.to_be_bytes()); // CtExtensions (empty)
    out
}

/// RFC 6962 §3.3 SignedCertificateTimestampList in the inner DER OCTET STRING the
/// X.509 extension expects (single SCT).
fn sct_list_extension(log_id: &[u8; 32], timestamp_ms: u64, sig_der: &[u8]) -> Vec<u8> {
    let mut sct = vec![0u8]; // version
    sct.extend_from_slice(log_id);
    sct.extend_from_slice(&timestamp_ms.to_be_bytes());
    sct.extend_from_slice(&0u16.to_be_bytes()); // extensions
    sct.push(4); // hash: sha256
    sct.push(3); // sig: ecdsa
    sct.extend_from_slice(&(sig_der.len() as u16).to_be_bytes());
    sct.extend_from_slice(sig_der);

    let mut entry = (sct.len() as u16).to_be_bytes().to_vec();
    entry.extend_from_slice(&sct);
    let mut list = (entry.len() as u16).to_be_bytes().to_vec();
    list.extend_from_slice(&entry);

    let mut octet = vec![0x04];
    octet.extend_from_slice(&der_len(list.len()));
    octet.extend_from_slice(&list);
    octet
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
    // Fixed serial so the precert (no SCT) and final (with SCT) leaves differ ONLY
    // by the SCT extension — the exact relationship the RFC 6962 reconstruction
    // relies on.
    let serial = SerialNumber::from(0x5145_1a4e_0be5_71c3u64);
    let mk = |extra: Option<Vec<u8>>| -> Vec<u8> {
        let mut leaf = CertificateParams::new(Vec::<String>::new()).unwrap();
        leaf.distinguished_name.push(DnType::CommonName, "sigstore");
        leaf.serial_number = Some(serial.clone());
        leaf.subject_alt_names = vec![SanType::URI(Ia5String::try_from(p.san.clone()).unwrap())];
        leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::CodeSigning];
        let mut exts = vec![
            CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 57264, 1, 8],
                der_utf8(&p.issuer),
            ),
            CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 57264, 1, 12],
                der_utf8(&p.source_repo),
            ),
        ];
        if let Some(sct) = extra {
            exts.push(CustomExtension::from_oid_content(SCT_OID, sct));
        }
        leaf.custom_extensions = exts;
        let (ny, nm, nd) = p.leaf_not_before;
        let (ay, am, ad) = p.leaf_not_after;
        leaf.not_before = rcgen::date_time_ymd(ny, nm, nd);
        leaf.not_after = rcgen::date_time_ymd(ay, am, ad);
        let signer = if p.forge_chain {
            &rogue_issuer
        } else {
            &inter_issuer
        };
        leaf.signed_by(&leaf_key, signer).unwrap().der().to_vec()
    };

    let issuer_spki = spki_of(&inter_der);
    let mk_ct_key = || {
        let sk = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
        let spki = sk.verifying_key().to_public_key_der().unwrap();
        let log_id: [u8; 32] = Sha256::digest(spki.as_bytes()).into();
        (sk, log_id)
    };

    let (leaf_der, ctlog_keys) = if p.embed_sct {
        let precert_tbs = super::der::tbs_of_certificate(&mk(None)).unwrap();
        let issuer_key_hash = Sha256::digest(&issuer_spki);
        let (ct_sk, log_id) = mk_ct_key();
        let ts_ms = LOG_TIME as u64 * 1000;
        let signed = sct_signed_data(ts_ms, &issuer_key_hash, &precert_tbs);
        let sign_sk = if p.sct_wrong_key {
            p256::ecdsa::SigningKey::random(&mut rand_core::OsRng)
        } else {
            ct_sk.clone()
        };
        let ct_sig: p256::ecdsa::Signature = sign_sk.sign(&signed);
        let sct_ext = sct_list_extension(&log_id, ts_ms, ct_sig.to_der().as_bytes());
        let keys = if p.ct_pinned {
            vec![CtLogKey {
                key: *ct_sk.verifying_key(),
                log_id,
                valid_for: OPEN_WINDOW,
            }]
        } else {
            vec![]
        };
        (mk(Some(sct_ext)), keys)
    } else {
        // No embedded SCT. With ct_pinned, this is the missing-SCT refusal case.
        let keys = if p.ct_pinned {
            let (ct_sk, log_id) = mk_ct_key();
            vec![CtLogKey {
                key: *ct_sk.verifying_key(),
                log_id,
                valid_for: OPEN_WINDOW,
            }]
        } else {
            vec![]
        };
        (mk(None), keys)
    };

    let alt_cert_der = root_der.clone();
    use p256::pkcs8::DecodePrivateKey;
    let leaf_sk = p256::ecdsa::SigningKey::from_pkcs8_pem(&leaf_key.serialize_pem()).unwrap();
    let rekor_sk = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);

    let trust = TrustRoot {
        fulcio_cas: vec![
            FulcioCa {
                der: root_der,
                valid_for: OPEN_WINDOW,
            },
            FulcioCa {
                der: inter_der,
                valid_for: OPEN_WINDOW,
            },
        ],
        rekor_keys: vec![RekorKey {
            key: *rekor_sk.verifying_key(),
            valid_for: OPEN_WINDOW,
        }],
        ctlog_keys,
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
        alt_cert_der,
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

    /// The base64-of-PEM cert the Rekor body embeds (the signing leaf, or — for
    /// the cross-bind negative — a different valid cert).
    fn body_cert_b64(&self) -> String {
        let der = if self.p.wrong_body_cert {
            &self.alt_cert_der
        } else {
            &self.leaf_der
        };
        b64(pem_of(der).as_bytes())
    }

    /// cosign blob-signature bundle over `binary`.
    fn blob_bundle(&self, binary: &[u8]) -> Bundle {
        Bundle::parse(self.blob_bundle_value(binary).to_string().as_bytes()).unwrap()
    }

    fn blob_bundle_value(&self, binary: &[u8]) -> Value {
        let digest = Sha256::digest(binary);
        let sig: p256::ecdsa::Signature = self.leaf_sk.sign(binary);
        let body = json!({
            "kind": "hashedrekord",
            "apiVersion": "0.0.1",
            "spec": {
                "signature": {
                    "content": b64(sig.to_der().as_bytes()),
                    "publicKey": { "content": self.body_cert_b64() },
                },
                "data": { "hash": { "algorithm": "sha256", "value": to_hex(&digest) } },
            },
        })
        .to_string();
        json!({
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "verificationMaterial": {
                "certificate": { "rawBytes": b64(&self.leaf_der) },
                "tlogEntries": [ self.tlog(&b64(body.as_bytes()), 42) ],
            },
            "messageSignature": {
                "messageDigest": { "algorithm": "SHA2_256", "digest": b64(&digest) },
                "signature": b64(sig.to_der().as_bytes()),
            },
        })
    }

    /// SLSA provenance attestation bundle attesting `binary`.
    fn prov_bundle(&self, binary: &[u8]) -> Bundle {
        Bundle::parse(self.prov_bundle_value(binary).to_string().as_bytes()).unwrap()
    }

    fn prov_bundle_value(&self, binary: &[u8]) -> Value {
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
        let body = json!({
            "kind": "dsse",
            "apiVersion": "0.0.1",
            "spec": {
                "payloadHash": { "algorithm": "sha256", "value": bound },
                "signatures": [ { "signature": b64(sig.to_der().as_bytes()), "verifier": self.body_cert_b64() } ],
            },
        })
        .to_string();
        json!({
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
        })
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
    // The version rides on the identity-pinned SAN tag ref (anti-rollback input).
    assert_eq!(ok.version.as_deref(), Some("1.2.3"));
}

// --- Anti-rollback: a validly-signed OLDER release is refused (F-DIV-1).

#[test]
fn refuses_signed_downgrade() {
    let f = build(Params::default()); // release v1.2.3
    let updater = crate::update::SelfUpdater::new(f.trust.clone(), f.policy.clone())
        .with_rollback_floor("2.0.0", false)
        .unwrap();
    let blob = f.blob_bundle(&f.binary);
    let prov = f.prov_bundle(&f.binary);
    let tmp = tempfile::tempdir().unwrap();
    let cand = tmp.path().join("candidate");
    let live = tmp.path().join("live");
    std::fs::write(&cand, &f.binary).unwrap();
    std::fs::write(&live, b"CURRENT-2.0.0").unwrap();

    let err = updater.install(&cand, &blob, &prov, &live).unwrap_err();
    assert!(
        matches!(err, crate::update::UpdateError::Downgrade { .. }),
        "got {err:?}"
    );
    assert_eq!(std::fs::read(&live).unwrap(), b"CURRENT-2.0.0"); // not overwritten

    // Same signed release is accepted when it is an UPGRADE over the floor.
    let up = crate::update::SelfUpdater::new(f.trust.clone(), f.policy.clone())
        .with_rollback_floor("1.0.0", false)
        .unwrap();
    up.install(&cand, &blob, &prov, &live).unwrap();
    assert_eq!(std::fs::read(&live).unwrap(), f.binary);

    // And the downgrade is permitted only with the explicit override.
    std::fs::write(&live, b"CURRENT-2.0.0").unwrap();
    let forced = crate::update::SelfUpdater::new(f.trust.clone(), f.policy.clone())
        .with_rollback_floor("2.0.0", true)
        .unwrap();
    forced.install(&cand, &blob, &prov, &live).unwrap();
    assert_eq!(std::fs::read(&live).unwrap(), f.binary);
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
    f.trust.rekor_keys = vec![RekorKey {
        key: *p256::ecdsa::SigningKey::random(&mut rand_core::OsRng).verifying_key(),
        valid_for: OPEN_WINDOW,
    }];
    let err = f.verify(&f.binary).unwrap_err();
    assert!(matches!(err, VerifyError::Transparency(_)), "got {err:?}");
}

// --- Certificate transparency: the leaf's embedded SCT (RFC 6962) must verify
// under a pinned CT log, or the release is refused (a rogue Fulcio can't sign
// off-log). The fixture signs the SCT over an INDEPENDENTLY-built precert, so a
// passing accept also proves the verifier's precert reconstruction is byte-exact.

#[test]
fn accepts_valid_embedded_sct() {
    let f = build(Params {
        ct_pinned: true,
        embed_sct: true,
        ..Default::default()
    });
    f.verify(&f.binary)
        .expect("a leaf with a valid embedded SCT under a pinned CT log must verify");
}

#[test]
fn refuses_missing_sct_when_ct_pinned() {
    let f = build(Params {
        ct_pinned: true,
        embed_sct: false,
        ..Default::default()
    });
    let err = f.verify(&f.binary).unwrap_err();
    assert!(matches!(err, VerifyError::Sct(_)), "got {err:?}");
}

#[test]
fn refuses_sct_signed_by_unpinned_ct_key() {
    let f = build(Params {
        ct_pinned: true,
        embed_sct: true,
        sct_wrong_key: true,
        ..Default::default()
    });
    let err = f.verify(&f.binary).unwrap_err();
    assert!(matches!(err, VerifyError::Sct(_)), "got {err:?}");
}

/// No CT log pinned ⇒ SCT not enforced (matches sigstore-go): a leaf without an
/// SCT still verifies. The production trust root pins one, so this is not a
/// bypass — it is the "operator hasn't configured CT" posture.
#[test]
fn no_ct_pinned_does_not_require_sct() {
    let f = build(Params::default());
    assert!(f.trust.ctlog_keys.is_empty());
    f.verify(&f.binary)
        .expect("no pinned CT log ⇒ SCT optional");
}

// --- Leaf ⇄ Rekor-body cross-bind: the cert embedded in the log entry body must
// be the very leaf that signed the artifact.

#[test]
fn refuses_body_cert_not_the_signing_leaf() {
    let f = build(Params {
        wrong_body_cert: true,
        ..Default::default()
    });
    let err = f.verify(&f.binary).unwrap_err();
    assert!(matches!(err, VerifyError::Transparency(_)), "got {err:?}");
}

/// Ground truth for the RFC 6962 precert: stripping the SCT extension from a final
/// leaf must byte-equal an independently-built leaf that never carried it (same
/// fixed serial, same other extensions). This isolates the DER surgery from the
/// signature check.
#[test]
fn precert_reconstruction_strips_only_the_sct_extension() {
    let (ca_params, ca_key) = ca("Recon CA", &rcgen::PKCS_ECDSA_P384_SHA384);
    let issuer = Issuer::new(ca_params, ca_key);
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let serial = SerialNumber::from(0x0102_0304_0506_0708u64);
    let mk = |with_sct: bool| -> Vec<u8> {
        let mut leaf = CertificateParams::new(Vec::<String>::new()).unwrap();
        leaf.distinguished_name.push(DnType::CommonName, "sigstore");
        leaf.serial_number = Some(serial.clone());
        leaf.subject_alt_names = vec![SanType::URI(
            Ia5String::try_from("https://example/x".to_string()).unwrap(),
        )];
        leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::CodeSigning];
        let mut exts = vec![CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 57264, 1, 8],
            der_utf8("iss"),
        )];
        if with_sct {
            exts.push(CustomExtension::from_oid_content(
                SCT_OID,
                vec![0x04, 0x02, 0xde, 0xad],
            ));
        }
        leaf.custom_extensions = exts;
        leaf.signed_by(&key, &issuer).unwrap().der().to_vec()
    };
    let oid_der = [
        0x06u8, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x02,
    ];
    let reconstructed = super::der::remove_extension(
        &super::der::tbs_of_certificate(&mk(true)).unwrap(),
        &oid_der,
    )
    .unwrap();
    assert_eq!(
        reconstructed,
        super::der::tbs_of_certificate(&mk(false)).unwrap()
    );
}

impl Fixture {
    fn verify_default(&self) -> Result<VerifiedRelease, VerifyError> {
        self.verify(&self.binary)
    }

    /// Re-emit this fixture's real Fulcio chain + Rekor key as a
    /// `trusted_root.json`, so the `validFor` tests exercise the *actual*
    /// RFC3339-window parse + enforcement path end to end, not a hand-built
    /// `TrustRoot`. `*_end` is the optional window upper bound (RFC3339); `None`
    /// = open-ended, which must remain "still valid".
    fn trusted_root_json(&self, rekor_end: Option<&str>, ca_end: Option<&str>) -> Vec<u8> {
        let window = |end: Option<&str>| {
            let mut m = json!({ "start": "2020-01-01T00:00:00.000Z" });
            if let Some(e) = end {
                m["end"] = json!(e);
            }
            m
        };
        let certs: Vec<Value> = self
            .trust
            .fulcio_cas
            .iter()
            .map(|ca| json!({ "rawBytes": b64(&ca.der) }))
            .collect();
        let spki = self.trust.rekor_keys[0].key.to_public_key_der().unwrap();
        let v = json!({
            "tlogs": [ {
                "publicKey": {
                    "rawBytes": b64(spki.as_bytes()),
                    "keyDetails": "PKIX_ECDSA_P256_SHA_256",
                    "validFor": window(rekor_end),
                }
            } ],
            "certificateAuthorities": [ {
                "certChain": { "certificates": certs },
                "validFor": window(ca_end),
            } ],
        });
        serde_json::to_vec(&v).unwrap()
    }

    fn verify_with(&self, trust: &TrustRoot) -> Result<VerifiedRelease, VerifyError> {
        verify_binary(
            &self.binary,
            &self.blob_bundle(&self.binary),
            &self.prov_bundle(&self.binary),
            &self.policy,
            trust,
        )
    }

    /// A full production-shaped `trusted_root.json` (Fulcio CAs + Rekor tlog key +
    /// CT-log key), all open-ended — used to freeze the golden fixture.
    fn golden_trusted_root_json(&self) -> Vec<u8> {
        let window = json!({ "start": "2020-01-01T00:00:00.000Z" });
        let certs: Vec<Value> = self
            .trust
            .fulcio_cas
            .iter()
            .map(|ca| json!({ "rawBytes": b64(&ca.der) }))
            .collect();
        let rekor_spki = self.trust.rekor_keys[0].key.to_public_key_der().unwrap();
        let ct_spki = self.trust.ctlog_keys[0].key.to_public_key_der().unwrap();
        let v = json!({
            "tlogs": [ { "publicKey": {
                "rawBytes": b64(rekor_spki.as_bytes()),
                "keyDetails": "PKIX_ECDSA_P256_SHA_256",
                "validFor": window,
            } } ],
            "certificateAuthorities": [ {
                "certChain": { "certificates": certs },
                "validFor": window,
            } ],
            "ctlogs": [ { "publicKey": {
                "rawBytes": b64(ct_spki.as_bytes()),
                "keyDetails": "PKIX_ECDSA_P256_SHA_256",
                "validFor": window,
            } } ],
        });
        serde_json::to_vec_pretty(&v).unwrap()
    }
}

// --- Sigstore `validFor` windows (F-supplychain-validfor-1). LOG_TIME is
// 2027-01-15T08:00:00Z; the retired windows end one second before it.

/// Positive control: `integratedTime` inside both windows AND an ABSENT `end`
/// (open-ended) must be accepted — proves absent-end means "still valid", so the
/// enforcement introduces no false refusal on a current trust root.
#[test]
fn accepts_when_log_time_in_all_windows_open_ended() {
    let f = build(Params::default());
    let trust = TrustRoot::from_trusted_root_json(&f.trusted_root_json(None, None))
        .expect("open-ended windows load");
    f.verify_with(&trust)
        .expect("log time inside both open-ended windows must verify");
}

/// A SET signed by a Rekor key whose `validFor.end` precedes `integratedTime`
/// (retired-then-compromised bare log key) must be refused.
#[test]
fn refuses_retired_rekor_key_window() {
    let f = build(Params::default());
    let trust =
        TrustRoot::from_trusted_root_json(&f.trusted_root_json(Some("2027-01-15T07:59:59Z"), None))
            .expect("trust root loads");
    let err = f.verify_with(&trust).unwrap_err();
    assert!(matches!(err, VerifyError::Transparency(_)), "got {err:?}");
}

/// A candidate whose Fulcio CA `validFor.end` precedes `integratedTime`
/// (retired-but-unexpired CA) must be refused.
#[test]
fn refuses_expired_fulcio_ca_window() {
    let f = build(Params::default());
    let trust =
        TrustRoot::from_trusted_root_json(&f.trusted_root_json(None, Some("2027-01-15T07:59:59Z")))
            .expect("trust root loads");
    let err = f.verify_with(&trust).unwrap_err();
    assert!(matches!(err, VerifyError::CertValidity(_)), "got {err:?}");
}

// --- The update boundary: an unverified binary is never installed.

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

#[test]
fn install_writes_verified_bytes_under_concurrent_mutation() {
    // TOCTOU regression: install must write the exact bytes it VERIFIED, never a
    // second read of the candidate path. A mutator thread rewrites the candidate
    // between (and during) install calls; every install that returns Ok MUST have
    // written content whose digest equals the verified digest. The old re-read
    // (`fs::copy(candidate,..)`) would sometimes install garbage under this race.
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let f = build(Params::default());
    let updater = crate::update::SelfUpdater::new(f.trust.clone(), f.policy.clone());
    let blob = f.blob_bundle(&f.binary);
    let prov = f.prov_bundle(&f.binary);
    let tmp = tempfile::tempdir().unwrap();
    let cand = tmp.path().join("candidate");
    let live = tmp.path().join("live");
    std::fs::write(&cand, &f.binary).unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let mutator = {
        let cand = cand.clone();
        let good = f.binary.clone();
        let stop = stop.clone();
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let _ = std::fs::write(&cand, b"GARBAGE-not-the-verified-binary");
                let _ = std::fs::write(&cand, &good);
            }
        })
    };

    let want = to_hex(&Sha256::digest(&f.binary));
    let mut ok_installs = 0;
    for _ in 0..60 {
        // Bias toward a good read so the race window (read→verify→write) is
        // actually exercised on Ok installs; the mutator still corrupts freely.
        let _ = std::fs::write(&cand, &f.binary);
        if updater.install(&cand, &blob, &prov, &live).is_ok() {
            let installed = to_hex(&Sha256::digest(std::fs::read(&live).unwrap()));
            assert_eq!(
                installed, want,
                "install wrote content != the verified digest (TOCTOU)"
            );
            ok_installs += 1;
        }
    }
    stop.store(true, Ordering::Relaxed);
    mutator.join().unwrap();
    assert!(
        ok_installs > 0,
        "the race never let a valid install through — test ineffective"
    );
}

// --- Golden fixture: a committed, real-schema Sigstore bundle (public material
// only — the ephemeral signing keys are discarded) driven end-to-end through the
// file-based verify path, plus a single-field tamper battery. Proof the whole
// chain composes on frozen data, not only on synthetic vectors.

const GOLDEN_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/supply_chain/testdata/golden"
);

/// Regenerate the committed golden fixture (opt-in via `SL_REGEN_GOLDEN`). Writes
/// only public certs/signatures/SET/SCT; the signing keys never leave this test.
#[test]
fn regenerate_golden_fixture() {
    if std::env::var_os("SL_REGEN_GOLDEN").is_none() {
        return;
    }
    let f = build(Params {
        ct_pinned: true,
        embed_sct: true,
        ..Default::default()
    });
    std::fs::create_dir_all(GOLDEN_DIR).unwrap();
    std::fs::write(format!("{GOLDEN_DIR}/agent-binary"), &f.binary).unwrap();
    std::fs::write(
        format!("{GOLDEN_DIR}/agent.cosign.sigstore.json"),
        serde_json::to_vec_pretty(&f.blob_bundle_value(&f.binary)).unwrap(),
    )
    .unwrap();
    std::fs::write(
        format!("{GOLDEN_DIR}/agent.provenance.sigstore.json"),
        serde_json::to_vec_pretty(&f.prov_bundle_value(&f.binary)).unwrap(),
    )
    .unwrap();
    std::fs::write(
        format!("{GOLDEN_DIR}/trusted_root.json"),
        f.golden_trusted_root_json(),
    )
    .unwrap();
}

fn golden_bytes(name: &str) -> Vec<u8> {
    std::fs::read(format!("{GOLDEN_DIR}/{name}"))
        .unwrap_or_else(|e| panic!("golden {name}: {e} (run with SL_REGEN_GOLDEN=1 to create)"))
}

fn golden_json(name: &str) -> Value {
    serde_json::from_slice(&golden_bytes(name)).unwrap()
}

/// Verify a (possibly tampered) golden triple through the real file-based path,
/// under the PRODUCTION identity policy.
fn run_golden(
    binary: &[u8],
    blob: &Value,
    prov: &Value,
    trust: &TrustRoot,
) -> Result<VerifiedRelease, VerifyError> {
    let tmp = tempfile::tempdir().unwrap();
    let bp = tmp.path().join("agent");
    let blp = tmp.path().join("blob.json");
    let pvp = tmp.path().join("prov.json");
    std::fs::write(&bp, binary).unwrap();
    std::fs::write(&blp, blob.to_string()).unwrap();
    std::fs::write(&pvp, prov.to_string()).unwrap();
    verify_files(
        &bp,
        &blp,
        &pvp,
        trust,
        &VerificationPolicy::sessionlayer_agent(),
    )
}

/// Flip one byte inside a base64 JSON field — leaves the JSON structure intact so
/// the CRYPTO, not the parser, must reject it.
fn flip_b64(v: &mut Value, ptr: &str) {
    let s = v
        .pointer(ptr)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("no field {ptr}"))
        .to_string();
    let mut raw = base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .unwrap();
    let i = raw.len() / 2;
    raw[i] ^= 0x01;
    *v.pointer_mut(ptr).unwrap() = Value::String(b64(&raw));
}

#[test]
fn golden_bundle_verifies_and_rejects_tampering() {
    let binary = golden_bytes("agent-binary");
    let blob = golden_json("agent.cosign.sigstore.json");
    let prov = golden_json("agent.provenance.sigstore.json");
    let trust = TrustRoot::from_trusted_root_json(&golden_bytes("trusted_root.json"))
        .expect("golden trusted_root.json loads");
    assert!(
        !trust.ctlog_keys.is_empty(),
        "golden must pin a CT log so the SCT path is exercised"
    );

    // Untampered: the whole chain composes on frozen, real-schema data.
    let rel = run_golden(&binary, &blob, &prov, &trust).expect("golden bundle must verify");
    assert_eq!(rel.version.as_deref(), Some("1.2.3"));

    // Tamper battery — each single-field mutation is refused (fail closed).
    let cert = "/verificationMaterial/certificate/rawBytes";
    let set = "/verificationMaterial/tlogEntries/0/inclusionPromise/signedEntryTimestamp";
    for ptr in [cert, set] {
        let mut b = blob.clone();
        flip_b64(&mut b, ptr);
        assert!(
            run_golden(&binary, &b, &prov, &trust).is_err(),
            "tampered blob {ptr} must be refused"
        );
        let mut p = prov.clone();
        flip_b64(&mut p, ptr);
        assert!(
            run_golden(&binary, &blob, &p, &trust).is_err(),
            "tampered prov {ptr} must be refused"
        );
    }

    let mut b = blob.clone();
    flip_b64(&mut b, "/messageSignature/messageDigest/digest");
    assert!(
        run_golden(&binary, &b, &prov, &trust).is_err(),
        "tampered artifact digest must be refused"
    );

    let mut p = prov.clone();
    flip_b64(&mut p, "/dsseEnvelope/payload");
    assert!(
        run_golden(&binary, &blob, &p, &trust).is_err(),
        "tampered provenance payload must be refused"
    );

    let mut bin = binary.clone();
    let i = bin.len() / 2;
    bin[i] ^= 0x01;
    assert!(
        run_golden(&bin, &blob, &prov, &trust).is_err(),
        "tampered binary must be refused"
    );
}
