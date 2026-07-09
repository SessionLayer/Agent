//! Process-initialisation test.
//!
//! Kept in its own integration binary so the process-wide rustls crypto
//! provider install happens exactly once (nextest runs each test in a fresh
//! process; this file also stays correct under plain `cargo test`).

#[test]
fn init_process_installs_crypto_provider() {
    // First install in this process must succeed.
    sessionlayer_agent::init_process().expect("crypto provider install should succeed once");

    // A second attempt fails closed (a provider is already set) — proving the
    // install is real and single-shot, not a silent no-op.
    assert!(
        sessionlayer_agent::init_process().is_err(),
        "second install must report the provider is already set"
    );
}
