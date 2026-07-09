//! Version and protocol-range surface.
//!
//! Two distinct notions of "version" (Design §16A, contracts/VERSIONING.md):
//! * the **build (artifact) version** — SemVer `major.minor.patch`, sourced
//!   from Cargo so it can never drift from the package; and
//! * the **wire-protocol version** — `major.minor` only (patch never changes
//!   the wire contract), advertised as an inclusive `[min, max]` range and
//!   negotiated at connect with an N-1 compatibility window.
//!
//! This module only *describes* those versions. The negotiation algorithm
//! itself (FR-HA-9) is deliberately out of scope for Session One and lives with
//! the wire transport in a later session.

use serde::Serialize;

use crate::proto::{ComponentInfo, ProtocolVersion};

/// Formal component name — the exact string carried in the wire `HELLO` preface
/// and in `ComponentInfo.name` on the gRPC plane.
pub const COMPONENT_NAME: &str = "SessionLayer Agent";

/// Build version (SemVer 2.0.0), single-sourced from `Cargo.toml`.
pub const SEMVER: &str = env!("CARGO_PKG_VERSION");

/// Wire-protocol major this build speaks.
pub const PROTOCOL_MAJOR: u32 = 1;
/// Wire-protocol minor this build speaks.
pub const PROTOCOL_MINOR: u32 = 0;

/// Inclusive lowest wire-protocol version supported.
///
/// From the first MINOR bump onward this stays one minor behind
/// [`PROTOCOL_MAX`] to honour the N-1 window (contracts/VERSIONING.md §4). At
/// the `1.0` baseline there is no prior minor, so `min == max`.
pub const PROTOCOL_MIN: ProtocolVersion = ProtocolVersion {
    major: PROTOCOL_MAJOR,
    minor: PROTOCOL_MINOR,
};

/// Inclusive highest wire-protocol version supported.
pub const PROTOCOL_MAX: ProtocolVersion = ProtocolVersion {
    major: PROTOCOL_MAJOR,
    minor: PROTOCOL_MINOR,
};

/// Render a [`ProtocolVersion`] as `"major.minor"`.
pub fn display_version(v: &ProtocolVersion) -> String {
    format!("{}.{}", v.major, v.minor)
}

/// The Agent's [`ComponentInfo`] — the pre-authentication identity/version
/// descriptor exchanged in the wire `HELLO` preface and safe to send before
/// mutual authentication (it carries no secrets; see `common.proto`).
pub fn component_info() -> ComponentInfo {
    ComponentInfo {
        name: COMPONENT_NAME.to_string(),
        semver: SEMVER.to_string(),
        protocol_min: Some(PROTOCOL_MIN),
        protocol_max: Some(PROTOCOL_MAX),
    }
}

/// A machine-readable version descriptor (surfaced by `--version-json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VersionInfo {
    /// Formal component name.
    pub component: &'static str,
    /// Build version (SemVer).
    pub semver: &'static str,
    /// Inclusive lowest supported wire-protocol version, `"major.minor"`.
    pub protocol_min: String,
    /// Inclusive highest supported wire-protocol version, `"major.minor"`.
    pub protocol_max: String,
}

/// Build the machine-readable version descriptor.
pub fn version_info() -> VersionInfo {
    VersionInfo {
        component: COMPONENT_NAME,
        semver: SEMVER,
        protocol_min: display_version(&PROTOCOL_MIN),
        protocol_max: display_version(&PROTOCOL_MAX),
    }
}
