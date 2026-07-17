//! The pinned trust root: Sigstore Fulcio CA certificates (chain anchor) and
//! Rekor transparency-log public keys. In production these come from a
//! Sigstore-distributed `trusted_root.json` (TUF repo `tuf-repo-cdn.sigstore.dev`),
//! pinned by digest by the operator. Nothing here reaches the network — the file
//! is provided at rest, so verification is fully offline and deterministic.

use base64::Engine as _;
use p256::pkcs8::spki::DecodePublicKey;
use serde::Deserialize;

use super::error::VerifyError;

#[derive(Clone)]
pub struct TrustRoot {
    /// Fulcio CA certificates (root + intermediate), DER.
    pub fulcio_cas: Vec<Vec<u8>>,
    /// Rekor log signing keys (P-256).
    pub rekor_keys: Vec<p256::ecdsa::VerifyingKey>,
}

impl TrustRoot {
    pub fn from_trusted_root_json(bytes: &[u8]) -> Result<Self, VerifyError> {
        let tr: TrustedRoot = serde_json::from_slice(bytes)
            .map_err(|e| VerifyError::TrustAnchor(format!("trusted_root.json: {e}")))?;

        let mut fulcio_cas = Vec::new();
        for ca in &tr.certificate_authorities {
            for cert in &ca.cert_chain.certificates {
                fulcio_cas.push(decode_b64(&cert.raw_bytes)?);
            }
        }
        if fulcio_cas.is_empty() {
            return Err(VerifyError::TrustAnchor(
                "trusted_root.json has no Fulcio certificate authorities".into(),
            ));
        }

        let mut rekor_keys = Vec::new();
        for tlog in &tr.tlogs {
            let der = decode_b64(&tlog.public_key.raw_bytes)?;
            rekor_keys.push(verifying_key_from_spki(&der)?);
        }
        if rekor_keys.is_empty() {
            return Err(VerifyError::TrustAnchor(
                "trusted_root.json has no Rekor tlog keys".into(),
            ));
        }

        Ok(Self {
            fulcio_cas,
            rekor_keys,
        })
    }
}

pub(super) fn verifying_key_from_spki(
    der: &[u8],
) -> Result<p256::ecdsa::VerifyingKey, VerifyError> {
    p256::ecdsa::VerifyingKey::from_public_key_der(der)
        .map_err(|e| VerifyError::TrustAnchor(format!("Rekor public key (SPKI DER): {e}")))
}

fn decode_b64(s: &str) -> Result<Vec<u8>, VerifyError> {
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|e| VerifyError::TrustAnchor(format!("base64: {e}")))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TrustedRoot {
    #[serde(default)]
    tlogs: Vec<Tlog>,
    #[serde(default)]
    certificate_authorities: Vec<CertificateAuthority>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Tlog {
    public_key: PublicKey,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublicKey {
    raw_bytes: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CertificateAuthority {
    cert_chain: CertChain,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CertChain {
    certificates: Vec<RawCert>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawCert {
    raw_bytes: String,
}
