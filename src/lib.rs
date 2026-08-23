#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(rust_2018_idioms)]

pub mod config;
pub mod gateway;
pub mod hardening;
pub mod identity;
pub mod join;
pub mod mtls;
pub mod privilege;
mod secret;
pub mod supervisor;
pub mod supply_chain;
pub mod telemetry;
pub mod tls;
pub mod update;
pub mod version;

pub mod proto {
    #![allow(clippy::all, missing_docs, rustdoc::all)]
    include!(concat!(env!("OUT_DIR"), "/sessionlayer.controlplane.v1.rs"));

    pub mod wire {
        #![allow(clippy::all, missing_docs, rustdoc::all)]
        include!(concat!(env!("OUT_DIR"), "/sessionlayer.agent.v1.rs"));
    }
}

pub const LONG_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    "\ncomponent:      SessionLayer Agent",
    "\nwire-protocol:  1.0 - 1.0  (N-1 window; contracts/wire/agent-gateway-v1.md)",
    "\ngrpc-contract:  sessionlayer.controlplane.v1  (vendored common.proto + agent.proto)"
);

#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("failed to install the process rustls crypto provider")]
    CryptoProviderInstall,
}

pub fn init_process() -> Result<(), AgentError> {
    tls::install_ring_provider();
    if tls::crypto_provider_installed() {
        Ok(())
    } else {
        Err(AgentError::CryptoProviderInstall)
    }
}
