use p256::ecdsa::signature::Verifier;
use serde_json::Value;

use super::bundle::DsseEnvelope;
use super::error::VerifyError;

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

pub fn verify_envelope(
    env: &DsseEnvelope,
    leaf_key: &p256::ecdsa::VerifyingKey,
) -> Result<Vec<u8>, VerifyError> {
    let payload = env.payload_bytes()?;
    let sig = p256::ecdsa::Signature::from_der(&env.signature_der()?)
        .map_err(|e| VerifyError::Signature(format!("DSSE signature DER: {e}")))?;
    let framed = pae(&env.payload_type, &payload);
    leaf_key
        .verify(&framed, &sig)
        .map_err(|e| VerifyError::Signature(format!("DSSE envelope signature: {e}")))?;
    Ok(payload)
}

pub struct Provenance {
    pub predicate_type: String,
    pub subject_sha256: Vec<String>,
    pub build_type: Option<String>,
    pub source_repo_refs: Vec<String>,
}

pub fn parse_statement(payload: &[u8]) -> Result<Provenance, VerifyError> {
    let v: Value = serde_json::from_slice(payload)
        .map_err(|e| VerifyError::Provenance(format!("in-toto statement JSON: {e}")))?;

    let predicate_type = v
        .get("predicateType")
        .and_then(Value::as_str)
        .ok_or_else(|| VerifyError::Provenance("statement has no predicateType".into()))?
        .to_string();

    let mut subject_sha256 = Vec::new();
    if let Some(subjects) = v.get("subject").and_then(Value::as_array) {
        for s in subjects {
            if let Some(d) = s.pointer("/digest/sha256").and_then(Value::as_str) {
                subject_sha256.push(d.to_ascii_lowercase());
            }
        }
    }

    let build_type = v
        .pointer("/predicate/buildDefinition/buildType")
        .and_then(Value::as_str)
        .map(str::to_string);

    let mut source_repo_refs = Vec::new();
    if let Some(r) = v
        .pointer("/predicate/buildDefinition/externalParameters/workflow/repository")
        .and_then(Value::as_str)
    {
        source_repo_refs.push(r.to_string());
    }
    if let Some(r) = v
        .pointer("/predicate/runDetails/builder/id")
        .and_then(Value::as_str)
    {
        source_repo_refs.push(r.to_string());
    }

    Ok(Provenance {
        predicate_type,
        subject_sha256,
        build_type,
        source_repo_refs,
    })
}
