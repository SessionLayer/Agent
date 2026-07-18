//! Certificate-transparency (SCT) verification, RFC 6962. Fulcio embeds a Signed
//! Certificate Timestamp in the leaf (X.509 extension `1.3.6.1.4.1.11129.2.4.2`)
//! proving the CA logged the certificate to a public CT log. cosign/sigstore-go
//! verify it so a *compromised Fulcio* cannot mint an off-log signing cert; we do
//! the same, offline, against the **pinned** CT-log key(s) — and fail closed.
//!
//! We verify the embedded **precert** SCT (the form Fulcio emits): the log signs
//! over the leaf's TBSCertificate with this very extension stripped, prefixed by
//! the SHA-256 of the issuer's SubjectPublicKeyInfo ([`der`](super::der) does the
//! reconstruction). Enforcement is gated on a CT log being pinned: a trust root
//! with no `ctlogs` does not require an SCT (matches sigstore-go), but the
//! production `trusted_root.json` pins one, so releases must be logged.

use p256::ecdsa::signature::Verifier;
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

use super::der;
use super::error::VerifyError;
use super::trust::CtLogKey;

/// OID `1.3.6.1.4.1.11129.2.4.2` (embedded SCT list), DER-encoded.
const OID_SCT_LIST_DER: &[u8] = &[
    0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x02,
];
const OID_SCT_LIST_STR: &str = "1.3.6.1.4.1.11129.2.4.2";

const SCT_VERSION_V1: u8 = 0;
const SIG_TYPE_CERTIFICATE_TIMESTAMP: u8 = 0;
const ENTRY_TYPE_PRECERT: u16 = 1;

/// Verify the leaf's embedded SCT(s) against the pinned CT logs. `at_time` is the
/// trusted Rekor integration clock, used for the CT-log key `validFor` window (a
/// retired CT key cannot vouch for a fresh cert — same rule as Fulcio/Rekor).
/// No pinned CT log ⇒ CT not enforced (`Ok`); a pinned log with no valid SCT ⇒
/// refuse.
pub fn verify_embedded_scts(
    leaf_der: &[u8],
    leaf: &X509Certificate<'_>,
    issuer_spki_der: &[u8],
    ctlog_keys: &[CtLogKey],
    at_time: i64,
) -> Result<(), VerifyError> {
    if ctlog_keys.is_empty() {
        return Ok(());
    }

    let ext_value = leaf
        .extensions()
        .iter()
        .find(|e| e.oid.to_id_string() == OID_SCT_LIST_STR)
        .map(|e| e.value)
        .ok_or_else(|| {
            VerifyError::Sct("Fulcio leaf carries no embedded SCT (not logged to CT)".into())
        })?;

    let scts = parse_sct_list(ext_value)?;

    // The precert entry the log signed: issuer key hash ‖ (leaf TBS − SCT ext).
    let precert_tbs = der::remove_extension(&der::tbs_of_certificate(leaf_der)?, OID_SCT_LIST_DER)?;
    let issuer_key_hash = Sha256::digest(issuer_spki_der);

    let mut retired = false;
    for sct in &scts {
        let Some(key) = ctlog_keys.iter().find(|k| k.log_id == sct.log_id) else {
            continue;
        };
        if !key.valid_for.contains(at_time) {
            retired = true;
            continue;
        }
        let signed = precert_signed_data(
            sct.timestamp_ms,
            &issuer_key_hash,
            &precert_tbs,
            &sct.extensions,
        );
        if key.key.verify(&signed, &sct.signature).is_ok() {
            return Ok(());
        }
    }

    Err(VerifyError::Sct(if retired {
        "embedded SCT is from a CT log key outside its trusted-root validity window (retired key)"
            .into()
    } else {
        "no embedded SCT verifies under a pinned CT log key".into()
    }))
}

struct Sct {
    log_id: [u8; 32],
    timestamp_ms: u64,
    extensions: Vec<u8>,
    signature: p256::ecdsa::Signature,
}

/// Parse the `SignedCertificateTimestampList` (RFC 6962 §3.3): the extension
/// value double-wraps an OCTET STRING around a TLS-serialized list of SCTs.
fn parse_sct_list(ext_value: &[u8]) -> Result<Vec<Sct>, VerifyError> {
    let (tag, hdr, len) = der::read_tlv(ext_value)?;
    if tag != 0x04 {
        return Err(VerifyError::Sct(
            "SCT extension is not the expected OCTET STRING".into(),
        ));
    }
    let list = ext_value
        .get(hdr..hdr + len)
        .ok_or_else(|| VerifyError::Sct("SCT list truncated".into()))?;

    let mut r = Reader::new(list);
    let total = r.u16()? as usize;
    let body = r.take(total)?;
    let mut inner = Reader::new(body);
    let mut out = Vec::new();
    while !inner.is_empty() {
        let sct_len = inner.u16()? as usize;
        let bytes = inner.take(sct_len)?;
        out.push(parse_sct(bytes)?);
    }
    if out.is_empty() {
        return Err(VerifyError::Sct("empty SCT list".into()));
    }
    Ok(out)
}

fn parse_sct(bytes: &[u8]) -> Result<Sct, VerifyError> {
    let mut r = Reader::new(bytes);
    if r.u8()? != SCT_VERSION_V1 {
        return Err(VerifyError::Sct("unsupported SCT version".into()));
    }
    let mut log_id = [0u8; 32];
    log_id.copy_from_slice(r.take(32)?);
    let timestamp_ms = r.u64()?;
    let ext_len = r.u16()? as usize;
    let extensions = r.take(ext_len)?.to_vec();
    // digitally-signed: hash(1) ‖ sig(1) ‖ opaque signature<0..2^16-1>.
    let (hash_alg, sig_alg) = (r.u8()?, r.u8()?);
    if (hash_alg, sig_alg) != (4, 3) {
        // sha256 / ecdsa — the only pinned CT key type.
        return Err(VerifyError::Sct(
            "unsupported SCT signature algorithm".into(),
        ));
    }
    let sig_len = r.u16()? as usize;
    let sig_der = r.take(sig_len)?;
    let signature = p256::ecdsa::Signature::from_der(sig_der)
        .map_err(|e| VerifyError::Sct(format!("SCT signature DER: {e}")))?;
    Ok(Sct {
        log_id,
        timestamp_ms,
        extensions,
        signature,
    })
}

/// The bytes the CT log signs for a precert entry (RFC 6962 §3.2).
fn precert_signed_data(
    timestamp_ms: u64,
    issuer_key_hash: &[u8],
    precert_tbs: &[u8],
    ct_extensions: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(precert_tbs.len() + 64);
    out.push(SCT_VERSION_V1);
    out.push(SIG_TYPE_CERTIFICATE_TIMESTAMP);
    out.extend_from_slice(&timestamp_ms.to_be_bytes());
    out.extend_from_slice(&ENTRY_TYPE_PRECERT.to_be_bytes());
    out.extend_from_slice(issuer_key_hash);
    out.extend_from_slice(&u24(precert_tbs.len()));
    out.extend_from_slice(precert_tbs);
    out.extend_from_slice(&(ct_extensions.len() as u16).to_be_bytes());
    out.extend_from_slice(ct_extensions);
    out
}

fn u24(n: usize) -> [u8; 3] {
    let b = (n as u32).to_be_bytes();
    [b[1], b[2], b[3]]
}

struct Reader<'a> {
    b: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b }
    }
    fn is_empty(&self) -> bool {
        self.b.is_empty()
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], VerifyError> {
        if self.b.len() < n {
            return Err(VerifyError::Sct("SCT structure truncated".into()));
        }
        let (a, rest) = self.b.split_at(n);
        self.b = rest;
        Ok(a)
    }
    fn u8(&mut self) -> Result<u8, VerifyError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, VerifyError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u64(&mut self) -> Result<u64, VerifyError> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_be_bytes(a))
    }
}
