//! Verification failures. Every variant is a distinct **fail-closed** reason so
//! the tamper matrix (and an operator) can tell *why* a binary was refused —
//! and so a caller can never confuse "refused" with "ran".

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

    /// The Fulcio leaf/intermediate signature does not chain to a pinned root.
    #[error("certificate chain does not verify to the pinned Sigstore root: {0}")]
    Chain(String),

    /// The short-lived leaf was not valid at the transparency-log integration
    /// time (the only trusted clock — never the local wall clock).
    #[error("signing certificate was not valid at log-integration time: {0}")]
    CertValidity(String),

    #[error("signing certificate is not a code-signing certificate")]
    NotCodeSigning,

    /// Identity policy miss (issuer / SAN workflow / source repository). This is
    /// the "wrong-identity" and "wrong-workflow" rejection.
    #[error("signer identity does not match policy: {field}: got {got:?}")]
    Identity { field: &'static str, got: String },

    /// Transparency requirement: the Rekor SignedEntryTimestamp is absent,
    /// invalid, or does not bind to this artifact.
    #[error("transparency (Rekor) verification failed: {0}")]
    Transparency(String),

    /// Certificate-transparency requirement: the Fulcio leaf carries no embedded
    /// Signed Certificate Timestamp, or none verifies under a pinned, in-window CT
    /// log key — i.e. we cannot prove the cert was actually logged (a rogue Fulcio
    /// could issue off-log). Fail closed.
    #[error("certificate transparency (SCT) verification failed: {0}")]
    Sct(String),

    #[error("cryptographic signature does not verify: {0}")]
    Signature(String),

    /// The provenance subject digest does not equal the candidate binary's
    /// digest. This is the "tampered binary" rejection.
    #[error("artifact digest is not attested (subject digest mismatch): {0}")]
    DigestMismatch(String),

    #[error("provenance predicate does not match policy: {0}")]
    Provenance(String),
}
