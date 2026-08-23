use thiserror::Error;

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("reading candidate binary {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("malformed Sigstore bundle: {0}")]
    Bundle(String),

    #[error("no trust anchor: {0}")]
    TrustAnchor(String),

    #[error("certificate chain does not verify to the pinned Sigstore root: {0}")]
    Chain(String),

    #[error("signing certificate was not valid at log-integration time: {0}")]
    CertValidity(String),

    #[error("signing certificate is not a code-signing certificate")]
    NotCodeSigning,

    #[error("signer identity does not match policy: {field}: got {got:?}")]
    Identity { field: &'static str, got: String },

    #[error("transparency (Rekor) verification failed: {0}")]
    Transparency(String),

    #[error("certificate transparency (SCT) verification failed: {0}")]
    Sct(String),

    #[error("cryptographic signature does not verify: {0}")]
    Signature(String),

    #[error("artifact digest is not attested (subject digest mismatch): {0}")]
    DigestMismatch(String),

    #[error("provenance predicate does not match policy: {0}")]
    Provenance(String),
}
