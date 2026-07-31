#[test]
fn init_process_installs_crypto_provider_idempotently() {
    sessionlayer_agent::init_process().expect("crypto provider install should succeed");
    sessionlayer_agent::init_process().expect("init_process must be idempotent");
    assert!(sessionlayer_agent::tls::crypto_provider_installed());
}
