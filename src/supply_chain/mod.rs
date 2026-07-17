//! Verify-before-run/update (Part E / NFR-7): a node refuses to run or update to
//! an Agent binary that is not Sigstore-verified against our release identity.
//!
//! Given a candidate binary and its release artifacts (a SLSA provenance
//! attestation bundle and a cosign blob-signature bundle), verification is fully
//! **offline** and **fails closed** on any miss:
//!   1. the Fulcio leaf chains to a **pinned** Sigstore root ([`trust`]/[`cert`]);
//!   2. a **pinned-key Rekor SET** proves the signing was logged and dates the
//!      short-lived leaf ([`rekor`]);
//!   3. the signer **identity** matches policy — repo + release workflow + issuer
//!      ([`policy`]) — this is the wrong-identity / wrong-workflow rejection;
//!   4. the provenance subject digest **equals the candidate binary** and the
//!      cosign signature verifies over it ([`dsse`]) — this is the tampered-binary
//!      rejection; both Rekor entries are cross-bound to the digest.
//!
//! [`SelfUpdater`](crate::update::SelfUpdater) calls [`verify_binary`] before it
//! will exec/replace anything.

mod bundle;
mod cert;
mod dsse;
mod error;
mod policy;
mod rekor;
mod trust;

use std::path::Path;

use sha2::{Digest, Sha256};

pub use bundle::Bundle;
pub use error::VerifyError;
pub use policy::VerificationPolicy;
pub use trust::TrustRoot;

const SLSA_PROVENANCE_V1: &str = "https://slsa.dev/provenance/v1";

#[derive(Debug, Clone)]
pub struct VerifiedRelease {
    pub digest_hex: String,
    pub san: String,
    pub source_repo: String,
}

/// Verify a candidate binary against its provenance + blob-signature bundles.
/// `Ok` means every check in the module doc passed; any `Err` is a fail-closed
/// refusal (the caller MUST NOT run/install the binary).
pub fn verify_binary(
    binary: &[u8],
    blob_bundle: &Bundle,
    provenance_bundle: &Bundle,
    policy: &VerificationPolicy,
    trust: &TrustRoot,
) -> Result<VerifiedRelease, VerifyError> {
    let digest = Sha256::digest(binary);
    let digest_hex = hex(&digest);

    // (1) The SLSA provenance attestation — identity + what-was-built.
    let (prov_leaf, prov_entry) = verify_identity(provenance_bundle, policy, trust)?;
    let env = provenance_bundle.dsse_envelope.as_ref().ok_or_else(|| {
        VerifyError::Provenance("provenance bundle is not a DSSE attestation".into())
    })?;
    let leaf_key = load_leaf_key(&prov_leaf.public_key_sec1)?;
    let payload = dsse::verify_envelope(env, &leaf_key)?;
    rekor::require_body_binds(prov_entry, &hex(&Sha256::digest(&payload)))?;
    let prov = dsse::parse_statement(&payload)?;
    check_provenance(&prov, &digest_hex, policy)?;

    // (2) The cosign blob signature over the binary — same identity, direct
    // integrity. Defence-in-depth alongside the digest binding from (1).
    let (blob_leaf, blob_entry) = verify_identity(blob_bundle, policy, trust)?;
    let msg = blob_bundle
        .message_signature
        .as_ref()
        .ok_or_else(|| VerifyError::Bundle("blob bundle is not a message signature".into()))?;
    if msg.digest_bytes()?.as_slice() != &digest[..] {
        return Err(VerifyError::DigestMismatch(
            "cosign messageDigest does not equal the candidate binary".into(),
        ));
    }
    let blob_key = load_leaf_key(&blob_leaf.public_key_sec1)?;
    let blob_sig = p256::ecdsa::Signature::from_der(&msg.signature_der()?)
        .map_err(|e| VerifyError::Signature(format!("cosign signature DER: {e}")))?;
    {
        use p256::ecdsa::signature::hazmat::PrehashVerifier;
        blob_key
            .verify_prehash(&digest, &blob_sig)
            .map_err(|e| VerifyError::Signature(format!("cosign blob signature: {e}")))?;
    }
    rekor::require_body_binds(blob_entry, &digest_hex)?;

    Ok(VerifiedRelease {
        digest_hex,
        san: prov_leaf.san.unwrap_or_default(),
        source_repo: prov_leaf.source_repo.unwrap_or_default(),
    })
}

/// Convenience wrapper reading everything from files (the `verify`/`update` CLI).
pub fn verify_files(
    binary_path: &Path,
    blob_bundle_path: &Path,
    provenance_path: &Path,
    trust_root: &TrustRoot,
    policy: &VerificationPolicy,
) -> Result<VerifiedRelease, VerifyError> {
    let binary = read(binary_path)?;
    let blob = Bundle::parse(&read(blob_bundle_path)?)?;
    let prov = Bundle::parse(&read(provenance_path)?)?;
    verify_binary(&binary, &blob, &prov, policy, trust_root)
}

fn read(path: &Path) -> Result<Vec<u8>, VerifyError> {
    std::fs::read(path).map_err(|source| VerifyError::Io {
        path: path.display().to_string(),
        source,
    })
}

/// Verify a bundle's transparency + certificate chain + signer identity, common
/// to both the provenance and blob bundles. Returns the leaf identity and the
/// (borrowed) Rekor entry for the caller's artifact cross-bind.
fn verify_identity<'b>(
    bundle: &'b Bundle,
    policy: &VerificationPolicy,
    trust: &TrustRoot,
) -> Result<(cert::LeafInfo, &'b bundle::TlogEntry), VerifyError> {
    let entry = bundle.tlog_entry()?;
    let integrated_time = rekor::verify_set(entry, &trust.rekor_keys)?;
    let leaf_der = bundle.leaf_cert_der()?;
    let leaf = cert::parse_and_chain(&leaf_der, trust, integrated_time)?;

    match &leaf.issuer {
        Some(i) if i == &policy.oidc_issuer => {}
        other => {
            return Err(VerifyError::Identity {
                field: "oidc_issuer",
                got: other.clone().unwrap_or_default(),
            })
        }
    }
    match &leaf.san {
        Some(s) if policy.san_matches(s) => {}
        other => {
            return Err(VerifyError::Identity {
                field: "san_workflow_ref",
                got: other.clone().unwrap_or_default(),
            })
        }
    }
    match &leaf.source_repo {
        Some(r) if r == &policy.source_repo_uri => {}
        other => {
            return Err(VerifyError::Identity {
                field: "source_repository",
                got: other.clone().unwrap_or_default(),
            })
        }
    }
    Ok((leaf, entry))
}

fn check_provenance(
    prov: &dsse::Provenance,
    digest_hex: &str,
    policy: &VerificationPolicy,
) -> Result<(), VerifyError> {
    if prov.predicate_type != SLSA_PROVENANCE_V1 {
        return Err(VerifyError::Provenance(format!(
            "unexpected predicateType {:?}",
            prov.predicate_type
        )));
    }
    if !prov.subject_sha256.iter().any(|d| d == digest_hex) {
        return Err(VerifyError::DigestMismatch(
            "no provenance subject digest matches the candidate binary".into(),
        ));
    }
    match &prov.build_type {
        Some(bt) if bt == &policy.build_type => {}
        other => {
            return Err(VerifyError::Provenance(format!(
                "unexpected buildType {other:?}"
            )))
        }
    }
    if !prov
        .source_repo_refs
        .iter()
        .any(|r| r.contains(&policy.source_repo_uri))
    {
        return Err(VerifyError::Provenance(
            "provenance does not name the expected source repository".into(),
        ));
    }
    Ok(())
}

fn load_leaf_key(sec1: &[u8]) -> Result<p256::ecdsa::VerifyingKey, VerifyError> {
    p256::ecdsa::VerifyingKey::from_sec1_bytes(sec1)
        .map_err(|e| VerifyError::Signature(format!("leaf public key: {e}")))
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests;
