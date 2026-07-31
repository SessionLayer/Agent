//! `JoinMethod` — the bootstrap phase of the agent join lifecycle.

use std::path::PathBuf;
use zeroize::Zeroizing;

/// Domain-separation prefix for MtlsJoin proof-of-possession: binds cert to THIS CSR to prevent replay.
pub const MTLS_JOIN_POP_CONTEXT: &[u8] = b"sessionlayer-mtls-join-pop-v1:";

#[derive(Debug, thiserror::Error)]
pub enum JoinError {
    #[error("join credential unavailable: {0}")]
    Source(String),
    #[error("MtlsJoin operator material invalid: {0}")]
    OperatorMaterial(String),
    #[error("MtlsJoin proof-of-possession signing failed: {0}")]
    Pop(String),
}

pub enum JoinProof {
    Token(Zeroizing<String>),
    Oidc(Zeroizing<String>),
    Mtls {
        operator_certificate_der: Vec<u8>,
        pop_signature: Vec<u8>,
    },
}

impl std::fmt::Debug for JoinProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JoinProof::Token(_) => f.write_str("JoinProof::Token(<redacted>)"),
            JoinProof::Oidc(_) => f.write_str("JoinProof::Oidc(<redacted>)"),
            JoinProof::Mtls { pop_signature, .. } => f
                .debug_struct("JoinProof::Mtls")
                .field("pop_signature_len", &pop_signature.len())
                .finish(),
        }
    }
}

pub trait JoinMethod: Send + Sync {
    fn method_name(&self) -> &'static str;
    fn attest(&self, csr_der: &[u8]) -> Result<JoinProof, JoinError>;
}

pub struct TokenJoin {
    token: Zeroizing<String>,
}

impl TokenJoin {
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            token: Zeroizing::new(token.into()),
        }
    }
}

impl JoinMethod for TokenJoin {
    fn method_name(&self) -> &'static str {
        "token"
    }

    fn attest(&self, _csr_der: &[u8]) -> Result<JoinProof, JoinError> {
        if self.token.trim().is_empty() {
            return Err(JoinError::Source("join token is empty".to_string()));
        }
        Ok(JoinProof::Token(self.token.clone()))
    }
}

pub enum WorkloadTokenSource {
    Literal(Zeroizing<String>),
    File(PathBuf),
}

pub struct OidcJoin {
    source: WorkloadTokenSource,
}

impl OidcJoin {
    pub fn from_file(path: impl Into<PathBuf>) -> Self {
        Self {
            source: WorkloadTokenSource::File(path.into()),
        }
    }

    pub fn from_literal(token: impl Into<String>) -> Self {
        Self {
            source: WorkloadTokenSource::Literal(Zeroizing::new(token.into())),
        }
    }
}

impl JoinMethod for OidcJoin {
    fn method_name(&self) -> &'static str {
        "oidc"
    }

    fn attest(&self, _csr_der: &[u8]) -> Result<JoinProof, JoinError> {
        let token = match &self.source {
            WorkloadTokenSource::Literal(t) => t.clone(),
            WorkloadTokenSource::File(path) => {
                let raw = std::fs::read_to_string(path)
                    .map_err(|e| JoinError::Source(format!("reading workload token file: {e}")))?;
                Zeroizing::new(raw.trim().to_string())
            }
        };
        if token.is_empty() {
            return Err(JoinError::Source("workload token is empty".to_string()));
        }
        Ok(JoinProof::Oidc(token))
    }
}

pub struct MtlsJoin {
    operator_certificate_der: Vec<u8>,
    signing_key: p256::ecdsa::SigningKey,
}

impl MtlsJoin {
    pub fn from_pem(cert_pem: &[u8], key_pem: &str) -> Result<Self, JoinError> {
        let text = std::str::from_utf8(cert_pem)
            .map_err(|e| JoinError::OperatorMaterial(format!("cert is not UTF-8 PEM: {e}")))?;
        let der = pem::parse_many(text)
            .map_err(|e| JoinError::OperatorMaterial(format!("cert PEM parse failed: {e}")))?
            .into_iter()
            .find(|p| p.tag() == "CERTIFICATE")
            .map(|p| p.into_contents())
            .ok_or_else(|| {
                JoinError::OperatorMaterial("no CERTIFICATE block in operator cert".to_string())
            })?;
        let signing_key = load_signing_key(key_pem)?;
        Ok(Self {
            operator_certificate_der: der,
            signing_key,
        })
    }
}

fn load_signing_key(key_pem: &str) -> Result<p256::ecdsa::SigningKey, JoinError> {
    use p256::pkcs8::DecodePrivateKey;
    p256::ecdsa::SigningKey::from_pkcs8_pem(key_pem).map_err(|e| {
        JoinError::OperatorMaterial(format!("operator key is not ECDSA P-256 PKCS#8: {e}"))
    })
}

impl JoinMethod for MtlsJoin {
    fn method_name(&self) -> &'static str {
        "mtls"
    }

    fn attest(&self, csr_der: &[u8]) -> Result<JoinProof, JoinError> {
        use p256::ecdsa::signature::Signer;
        let mut message = Vec::with_capacity(MTLS_JOIN_POP_CONTEXT.len() + csr_der.len());
        message.extend_from_slice(MTLS_JOIN_POP_CONTEXT);
        message.extend_from_slice(csr_der);
        let sig: p256::ecdsa::Signature = self.signing_key.sign(&message);
        Ok(JoinProof::Mtls {
            operator_certificate_der: self.operator_certificate_der.clone(),
            pop_signature: sig.to_der().as_bytes().to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_join_yields_token_proof_and_rejects_empty() {
        let jm = TokenJoin::new("abc123");
        assert_eq!(jm.method_name(), "token");
        assert!(matches!(jm.attest(b"csr").unwrap(), JoinProof::Token(_)));
        let empty = TokenJoin::new("   ");
        assert!(matches!(empty.attest(b"csr"), Err(JoinError::Source(_))));
    }

    #[test]
    fn oidc_join_reads_literal_and_file() {
        let lit = OidcJoin::from_literal("header.payload.sig");
        assert!(matches!(lit.attest(b"csr").unwrap(), JoinProof::Oidc(_)));

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        std::fs::write(&path, "  file.jwt.token\n").unwrap();
        let f = OidcJoin::from_file(&path);
        match f.attest(b"csr").unwrap() {
            JoinProof::Oidc(t) => assert_eq!(&*t, "file.jwt.token"),
            _ => panic!("expected oidc proof"),
        }
    }

    #[test]
    fn mtls_join_pop_signature_verifies_and_binds_the_csr() {
        use p256::ecdsa::signature::Verifier;
        let (cert_pem, key_pem, verifying_key) = sample_operator();
        let jm = MtlsJoin::from_pem(cert_pem.as_bytes(), &key_pem).unwrap();
        assert_eq!(jm.method_name(), "mtls");

        let csr = b"the-enrollment-csr-der-bytes";
        let (cert_der, sig_der) = match jm.attest(csr).unwrap() {
            JoinProof::Mtls {
                operator_certificate_der,
                pop_signature,
            } => (operator_certificate_der, pop_signature),
            _ => panic!("expected mtls proof"),
        };
        assert!(!cert_der.is_empty());

        let mut message = MTLS_JOIN_POP_CONTEXT.to_vec();
        message.extend_from_slice(csr);
        let sig = p256::ecdsa::Signature::from_der(&sig_der).unwrap();
        assert!(verifying_key.verify(&message, &sig).is_ok());

        let mut other = MTLS_JOIN_POP_CONTEXT.to_vec();
        other.extend_from_slice(b"a-different-csr");
        assert!(verifying_key.verify(&other, &sig).is_err());
    }

    #[test]
    fn mtls_join_rejects_bad_key() {
        let (cert_pem, _key_pem, _vk) = sample_operator();
        let err = MtlsJoin::from_pem(
            cert_pem.as_bytes(),
            "-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----\n",
        );
        assert!(matches!(err, Err(JoinError::OperatorMaterial(_))));
    }

    fn sample_operator() -> (String, String, p256::ecdsa::VerifyingKey) {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let key_pem = key.serialize_pem();
        let params = rcgen::CertificateParams::new(vec!["node-a".to_string()]).unwrap();
        let cert = params.self_signed(&key).unwrap();
        use p256::pkcs8::DecodePrivateKey;
        let sk = p256::ecdsa::SigningKey::from_pkcs8_pem(&key_pem).unwrap();
        let vk = *sk.verifying_key();
        (cert.pem(), key_pem, vk)
    }
}
