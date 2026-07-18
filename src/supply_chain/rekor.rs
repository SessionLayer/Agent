//! Rekor transparency verification. The `SignedEntryTimestamp` (SET) is an ECDSA
//! signature by a **pinned** Rekor key over the canonical entry metadata; a valid
//! SET proves the signing event was publicly logged and yields `integratedTime`
//! — the trusted clock used to validate the short-lived Fulcio leaf. We also
//! cross-bind the entry body to the artifact digest so a *valid* SET from an
//! unrelated entry cannot be substituted.

use base64::Engine as _;
use p256::ecdsa::signature::Verifier;
use serde_json::Value;

use super::bundle::TlogEntry;
use super::error::VerifyError;
use super::trust::RekorKey;

/// Verify the SET under any pinned Rekor key **whose `validFor` window contains
/// the entry's `integratedTime`**, and return that trusted time. The window
/// check is what stops a retired-then-compromised bare log key (no X.509
/// validity of its own) from minting a SET for a fresh signing event.
pub fn verify_set(entry: &TlogEntry, rekor_keys: &[RekorKey]) -> Result<i64, VerifyError> {
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

    let mut sig_ok_but_retired = false;
    let ok = rekor_keys.iter().any(|rk| {
        if rk.key.verify(payload.as_bytes(), &sig).is_ok() {
            if rk.valid_for.contains(integrated_time) {
                return true;
            }
            sig_ok_but_retired = true;
        }
        false
    });
    if !ok {
        return Err(VerifyError::Transparency(if sig_ok_but_retired {
            format!(
                "SignedEntryTimestamp verifies but the Rekor key was outside its trusted-root \
                 validity window at log time {integrated_time} (retired key)"
            )
        } else {
            "SignedEntryTimestamp does not verify under any pinned Rekor key".into()
        }));
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

/// Fail closed unless the certificate embedded in the Rekor entry body is exactly
/// the leaf that signed the artifact. Binding the tlog entry to the *verified
/// leaf* (not merely "a Rekor entry exists for this digest") stops a valid SET +
/// body from an unrelated signing event being stitched onto this leaf.
pub fn require_body_binds_leaf(entry: &TlogEntry, leaf_der: &[u8]) -> Result<(), VerifyError> {
    let body = entry.body_bytes()?;
    let v: Value = serde_json::from_slice(&body)
        .map_err(|e| VerifyError::Transparency(format!("Rekor entry body is not JSON: {e}")))?;

    // The cert lives at different JSON paths across Rekor entry kinds: hashedrekord
    // (`spec.signature.publicKey.content`), dsse/intoto (`spec.signatures[].verifier`
    // or `spec.publicKey`). Each is base64 of a PEM (or DER) certificate.
    let mut found_any = false;
    for c in embedded_cert_candidates(&v) {
        let der = match decode_cert(c) {
            Some(d) => d,
            None => continue,
        };
        found_any = true;
        if der == leaf_der {
            return Ok(());
        }
    }
    Err(VerifyError::Transparency(if found_any {
        "Rekor entry body embeds a certificate other than the signing leaf".into()
    } else {
        "Rekor entry body embeds no signing certificate to cross-bind".into()
    }))
}

fn embedded_cert_candidates(v: &Value) -> Vec<&str> {
    let mut out = Vec::new();
    out.extend(
        v.pointer("/spec/signature/publicKey/content")
            .and_then(Value::as_str),
    );
    out.extend(v.pointer("/spec/publicKey").and_then(Value::as_str));
    if let Some(sigs) = v.pointer("/spec/signatures").and_then(Value::as_array) {
        for s in sigs {
            out.extend(s.get("verifier").and_then(Value::as_str));
        }
    }
    out
}

/// A candidate is base64 of either a PEM certificate or raw DER.
fn decode_cert(b64_str: &str) -> Option<Vec<u8>> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64_str.trim())
        .ok()?;
    if raw.starts_with(b"-----BEGIN") {
        pem::parse(&raw).ok().map(|p| p.contents().to_vec())
    } else {
        Some(raw)
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
