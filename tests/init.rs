//! Process-initialisation test.
//!
//! Kept in its own integration binary so the process-wide rustls crypto provider
//! install happens in a clean process (nextest runs each test in a fresh
//! process; this file also stays correct under plain `cargo test`).

#[test]
fn init_process_installs_crypto_provider_idempotently() {
    // Installing the single explicit rustls crypto provider must succeed...
    sessionlayer_agent::init_process().expect("crypto provider install should succeed");
    // ...and be idempotent: a second call is a no-op that still reports success
    // (a provider is guaranteed present), so every entry point can call it.
    sessionlayer_agent::init_process().expect("init_process must be idempotent");
    assert!(sessionlayer_agent::tls::crypto_provider_installed());
}
