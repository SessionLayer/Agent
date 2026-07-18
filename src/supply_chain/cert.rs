//! Fulcio leaf handling: verify the leaf chains to a **pinned** Sigstore root,
//! was valid at the transparency-log integration time, is a code-signing cert,
//! and extract the identity (SAN workflow ref + OIDC issuer + source repo). The
//! chain signature checks use x509-parser's `verify` (ring) — never a hand-rolled
//! ECDSA path — over a fixed set of pinned CAs, so there is no path-building
//! ambiguity to exploit.

use x509_parser::prelude::*;

use super::error::VerifyError;
use super::policy;
use super::trust::{TimeRange, TrustRoot};

pub struct LeafInfo {
    pub san: Option<String>,
    pub issuer: Option<String>,
    pub source_repo: Option<String>,
    /// SEC1 uncompressed point of the leaf's P-256 key (verifies blob/DSSE sigs).
    pub public_key_sec1: Vec<u8>,
}

/// Parse the leaf, verify it chains to a pinned root and was valid at
/// `at_time` (the Rekor integration time — the only trusted clock), require the
/// code-signing EKU, and return its identity + public key.
pub fn parse_and_chain(
    leaf_der: &[u8],
    trust: &TrustRoot,
    at_time: i64,
) -> Result<LeafInfo, VerifyError> {
    let (_, leaf) = X509Certificate::from_der(leaf_der)
        .map_err(|e| VerifyError::Chain(format!("leaf parse: {e}")))?;

    if trust.fulcio_cas.is_empty() {
        return Err(VerifyError::TrustAnchor(
            "no pinned Fulcio CA certificates".into(),
        ));
    }
    let cas: Vec<(X509Certificate<'_>, TimeRange)> = trust
        .fulcio_cas
        .iter()
        .map(|ca| {
            X509Certificate::from_der(&ca.der)
                .map(|(_, c)| (c, ca.valid_for))
                .map_err(|e| VerifyError::TrustAnchor(format!("pinned CA parse: {e}")))
        })
        .collect::<Result<_, _>>()?;

    verify_chain(&leaf, &cas, at_time)?;

    let nb = leaf.validity().not_before.timestamp();
    let na = leaf.validity().not_after.timestamp();
    if at_time < nb || at_time > na {
        return Err(VerifyError::CertValidity(format!(
            "log time {at_time} outside leaf validity [{nb}, {na}]"
        )));
    }

    require_code_signing(&leaf)?;

    Ok(LeafInfo {
        san: extract_san_uri(&leaf),
        issuer: extract_fulcio_issuer(&leaf),
        source_repo: extract_fulcio_ext(&leaf, policy::OID_FULCIO_SOURCE_REPO_URI),
        public_key_sec1: leaf.public_key().subject_public_key.data.to_vec(),
    })
}

/// Walk leaf → pinned intermediate → pinned self-signed root, verifying every
/// issuer signature and CA constraint. Fail closed if any link is missing.
fn verify_chain(
    leaf: &X509Certificate<'_>,
    cas: &[(X509Certificate<'_>, TimeRange)],
    at_time: i64,
) -> Result<(), VerifyError> {
    let mut current = leaf;
    for _ in 0..6 {
        let (issuer, window) = cas
            .iter()
            .find(|(ca, _)| {
                ca.subject() == current.issuer()
                    && current.verify_signature(Some(ca.public_key())).is_ok()
            })
            .ok_or_else(|| {
                VerifyError::Chain(format!(
                    "no pinned issuer for subject {:?}",
                    current.subject().to_string()
                ))
            })?;

        require_ca(issuer)?;
        let inb = issuer.validity().not_before.timestamp();
        let ina = issuer.validity().not_after.timestamp();
        if at_time < inb || at_time > ina {
            return Err(VerifyError::CertValidity(format!(
                "pinned CA {:?} not valid at log time {at_time}",
                issuer.subject().to_string()
            )));
        }
        // The Sigstore trusted-root `validFor` bounds when this CA may anchor a
        // signature — enforce it against the trusted clock so a retired-but-
        // still-unexpired Fulcio CA cannot vouch for a fresh signing event
        // (F-supplychain-validfor-1).
        if !window.contains(at_time) {
            return Err(VerifyError::CertValidity(format!(
                "pinned CA {:?} outside its trusted-root validity window at log time {at_time}",
                issuer.subject().to_string()
            )));
        }

        if issuer.subject() == issuer.issuer() {
            // Reached a self-signed pinned root; confirm its own signature.
            issuer
                .verify_signature(Some(issuer.public_key()))
                .map_err(|e| VerifyError::Chain(format!("pinned root self-signature: {e}")))?;
            return Ok(());
        }
        current = issuer;
    }
    Err(VerifyError::Chain("certificate chain too long".into()))
}

fn require_ca(cert: &X509Certificate<'_>) -> Result<(), VerifyError> {
    match cert.basic_constraints() {
        Ok(Some(bc)) if bc.value.ca => Ok(()),
        _ => Err(VerifyError::Chain(format!(
            "pinned issuer {:?} is not a CA",
            cert.subject().to_string()
        ))),
    }
}

fn require_code_signing(leaf: &X509Certificate<'_>) -> Result<(), VerifyError> {
    match leaf.extended_key_usage() {
        Ok(Some(eku)) if eku.value.code_signing => Ok(()),
        _ => Err(VerifyError::NotCodeSigning),
    }
}

fn extract_san_uri(leaf: &X509Certificate<'_>) -> Option<String> {
    let san = leaf.subject_alternative_name().ok().flatten()?;
    for name in &san.value.general_names {
        if let GeneralName::URI(uri) = name {
            return Some((*uri).to_string());
        }
    }
    None
}

/// The OIDC issuer: prefer the DER-encoded `.1.8`, fall back to the legacy raw
/// `.1.1`.
fn extract_fulcio_issuer(leaf: &X509Certificate<'_>) -> Option<String> {
    extract_fulcio_ext(leaf, policy::OID_FULCIO_ISSUER)
        .or_else(|| extract_fulcio_ext(leaf, policy::OID_FULCIO_ISSUER_LEGACY))
}

fn extract_fulcio_ext(leaf: &X509Certificate<'_>, oid: &str) -> Option<String> {
    for ext in leaf.extensions() {
        if ext.oid.to_id_string() == oid {
            return Some(decode_fulcio_string(ext.value));
        }
    }
    None
}

/// Fulcio's newer extensions wrap the value in a DER UTF8String; the legacy
/// `.1.1` is a raw string. Accept either.
fn decode_fulcio_string(v: &[u8]) -> String {
    der_utf8string(v).unwrap_or_else(|| String::from_utf8_lossy(v).into_owned())
}

fn der_utf8string(v: &[u8]) -> Option<String> {
    if v.first() != Some(&0x0c) {
        return None;
    }
    let (len, hdr) = der_len(&v[1..])?;
    let start = 1usize.checked_add(hdr)?;
    let end = start.checked_add(len)?;
    let body = v.get(start..end)?;
    std::str::from_utf8(body).ok().map(|s| s.to_string())
}

fn der_len(v: &[u8]) -> Option<(usize, usize)> {
    let first = *v.first()?;
    if first & 0x80 == 0 {
        return Some((first as usize, 1));
    }
    let n = (first & 0x7f) as usize;
    if n == 0 || n > 4 {
        return None;
    }
    let mut len = 0usize;
    for &b in v.get(1..1 + n)? {
        len = (len << 8) | b as usize;
    }
    Some((len, 1 + n))
}
