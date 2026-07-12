//! rustls crypto-provider install for the CP <-> Agent mTLS plane (§10, §15).
//!
//! The whole plane runs over **TLS 1.3, mutually authenticated** (VERSIONING §7,
//! Design §8). rustls needs a process-wide crypto provider installed before any
//! client/server config or custom certificate verifier is constructed. We use
//! the **ring** provider (not aws-lc-rs) to avoid a C/asm build toolchain
//! (`rustls` is built with `default-features = false, features = ["ring", ...]`).

/// Install the process-wide **ring** rustls crypto provider, idempotently.
///
/// Safe to call from every entry point (daemon start, each test). Returns `true`
/// if this call installed the provider, `false` if one was already installed —
/// either way a provider is guaranteed present on return.
pub fn install_ring_provider() -> bool {
    if rustls::crypto::CryptoProvider::get_default().is_some() {
        return false;
    }
    rustls::crypto::ring::default_provider()
        .install_default()
        .is_ok()
}

/// Whether a process-wide rustls crypto provider has been installed.
pub fn crypto_provider_installed() -> bool {
    rustls::crypto::CryptoProvider::get_default().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installing_the_provider_is_idempotent_and_leaves_one_installed() {
        let _ = install_ring_provider();
        assert!(crypto_provider_installed());
        let _ = install_ring_provider();
        assert!(crypto_provider_installed());
    }
}
