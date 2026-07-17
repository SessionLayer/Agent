//! Rekor transparency verification. The `SignedEntryTimestamp` (SET) is an ECDSA
//! signature by a **pinned** Rekor key over the canonical entry metadata; a valid
//! SET proves the signing event was publicly logged and yields `integratedTime`
//! — the trusted clock used to validate the short-lived Fulcio leaf. We also
//! cross-bind the entry body to the artifact digest so a *valid* SET from an
//! unrelated entry cannot be substituted.

use base64::Engine as _;
use p256::ecdsa::signature::Verifier;

use super::bundle::TlogEntry;
use super::error::VerifyError;

/// Verify the SET under any pinned Rekor key and return the trusted
/// `integratedTime`.
pub fn verify_set(
    entry: &TlogEntry,
    rekor_keys: &[p256::ecdsa::VerifyingKey],
) -> Result<i64, VerifyError> {
    let integrated_time = entry.integrated_time()?;
    let log_index: i64 = entry
        .log_index
        .parse()
        .map_err(|_| VerifyError::Transparency("non-integer logIndex".into()))?;
    let key_id = entry
        .log_id
        .as_ref()
        .ok_or_else(|| VerifyError::Transparency("no logId in Rekor entry".into()))?;
    let log_id_hex = to_hex(&decode_b64(&key_id.key_id)?);

    let payload = canonical_set_payload(
        &entry.canonicalized_body,
        integrated_time,
        &log_id_hex,
        log_index,
    );

    let sig = p256::ecdsa::Signature::from_der(&entry.set_signature()?)
        .map_err(|e| VerifyError::Transparency(format!("SET signature DER: {e}")))?;

    let ok = rekor_keys
        .iter()
        .any(|k| k.verify(payload.as_bytes(), &sig).is_ok());
    if !ok {
        return Err(VerifyError::Transparency(
            "SignedEntryTimestamp does not verify under any pinned Rekor key".into(),
        ));
    }
    Ok(integrated_time)
}

/// The exact payload Rekor signs: keys sorted (body, integratedTime, logID,
/// logIndex); `body` is the *original* canonicalizedBody base64 string,
/// integers unquoted. Shared with the tamper-matrix fixtures so they can't drift.
pub(super) fn canonical_set_payload(
    body_b64: &str,
    integrated_time: i64,
    log_id_hex: &str,
    log_index: i64,
) -> String {
    format!(
        r#"{{"body":"{body_b64}","integratedTime":{integrated_time},"logID":"{log_id_hex}","logIndex":{log_index}}}"#
    )
}

/// Fail closed unless the logged entry body references `digest_hex` — binds the
/// (independently verified) SET to *this* artifact/payload.
pub fn require_body_binds(entry: &TlogEntry, digest_hex: &str) -> Result<(), VerifyError> {
    let body = entry.body_bytes()?;
    if String::from_utf8_lossy(&body).contains(digest_hex) {
        Ok(())
    } else {
        Err(VerifyError::Transparency(
            "Rekor entry body does not reference the artifact digest".into(),
        ))
    }
}

fn decode_b64(s: &str) -> Result<Vec<u8>, VerifyError> {
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|e| VerifyError::Transparency(format!("base64: {e}")))
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
