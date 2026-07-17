//! Parse the subset of the Sigstore bundle (`application/vnd.dev.sigstore.bundle.v0.3+json`)
//! that the verifier needs. This is the format emitted by both
//! `cosign sign-blob --new-bundle-format` and `actions/attest-build-provenance`,
//! and attached to every release. Integers are proto-JSON (int64-as-string).

use base64::Engine as _;
use serde::Deserialize;

use super::error::VerifyError;

fn b64(s: &str) -> Result<Vec<u8>, VerifyError> {
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|e| VerifyError::Bundle(format!("base64: {e}")))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Bundle {
    #[serde(default)]
    pub media_type: Option<String>,
    pub verification_material: VerificationMaterial,
    #[serde(default)]
    pub message_signature: Option<MessageSignature>,
    #[serde(default)]
    pub dsse_envelope: Option<DsseEnvelope>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationMaterial {
    /// New single-cert form.
    #[serde(default)]
    pub certificate: Option<RawCert>,
    /// Older chain form; the leaf is the first entry.
    #[serde(default)]
    pub x509_certificate_chain: Option<CertChain>,
    #[serde(default)]
    pub tlog_entries: Vec<TlogEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawCert {
    pub raw_bytes: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertChain {
    pub certificates: Vec<RawCert>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TlogEntry {
    pub log_index: String,
    pub integrated_time: String,
    #[serde(default)]
    pub log_id: Option<LogId>,
    pub inclusion_promise: Option<InclusionPromise>,
    pub canonicalized_body: String,
    #[serde(default)]
    pub kind_version: Option<KindVersion>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogId {
    pub key_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InclusionPromise {
    pub signed_entry_timestamp: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KindVersion {
    pub kind: String,
    pub version: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageSignature {
    pub message_digest: MessageDigest,
    pub signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageDigest {
    pub algorithm: String,
    pub digest: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DsseEnvelope {
    pub payload: String,
    pub payload_type: String,
    pub signatures: Vec<DsseSignature>,
}

#[derive(Debug, Deserialize)]
pub struct DsseSignature {
    pub sig: String,
}

impl Bundle {
    pub fn parse(json: &[u8]) -> Result<Self, VerifyError> {
        serde_json::from_slice(json).map_err(|e| VerifyError::Bundle(format!("json: {e}")))
    }

    /// The DER bytes of the Fulcio leaf certificate.
    pub fn leaf_cert_der(&self) -> Result<Vec<u8>, VerifyError> {
        let vm = &self.verification_material;
        if let Some(c) = &vm.certificate {
            return b64(&c.raw_bytes);
        }
        if let Some(chain) = &vm.x509_certificate_chain {
            let leaf = chain
                .certificates
                .first()
                .ok_or_else(|| VerifyError::Bundle("empty x509CertificateChain".into()))?;
            return b64(&leaf.raw_bytes);
        }
        Err(VerifyError::Bundle(
            "no signing certificate in bundle".into(),
        ))
    }

    pub fn tlog_entry(&self) -> Result<&TlogEntry, VerifyError> {
        // Exactly-one transparency entry is required (fail closed): a bundle with
        // no Rekor entry cannot be checked for inclusion, so we refuse it.
        match self.verification_material.tlog_entries.as_slice() {
            [entry] => Ok(entry),
            [] => Err(VerifyError::Transparency(
                "bundle carries no Rekor transparency-log entry".into(),
            )),
            many => Err(VerifyError::Transparency(format!(
                "expected exactly one Rekor entry, found {}",
                many.len()
            ))),
        }
    }
}

impl TlogEntry {
    pub fn set_signature(&self) -> Result<Vec<u8>, VerifyError> {
        let p = self.inclusion_promise.as_ref().ok_or_else(|| {
            VerifyError::Transparency("no inclusionPromise (SET) in entry".into())
        })?;
        b64(&p.signed_entry_timestamp)
    }

    pub fn body_bytes(&self) -> Result<Vec<u8>, VerifyError> {
        b64(&self.canonicalized_body)
    }

    pub fn integrated_time(&self) -> Result<i64, VerifyError> {
        self.integrated_time
            .parse()
            .map_err(|_| VerifyError::Transparency("non-integer integratedTime".into()))
    }
}

impl MessageSignature {
    pub fn digest_bytes(&self) -> Result<Vec<u8>, VerifyError> {
        if self.message_digest.algorithm != "SHA2_256" {
            return Err(VerifyError::Bundle(format!(
                "unsupported messageDigest algorithm {:?}",
                self.message_digest.algorithm
            )));
        }
        b64(&self.message_digest.digest)
    }

    pub fn signature_der(&self) -> Result<Vec<u8>, VerifyError> {
        b64(&self.signature)
    }
}

impl DsseEnvelope {
    pub fn payload_bytes(&self) -> Result<Vec<u8>, VerifyError> {
        b64(&self.payload)
    }

    pub fn signature_der(&self) -> Result<Vec<u8>, VerifyError> {
        let sig = self
            .signatures
            .first()
            .ok_or_else(|| VerifyError::Bundle("DSSE envelope has no signatures".into()))?;
        b64(&sig.sig)
    }
}
