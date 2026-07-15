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

/// CP↔Agent **gRPC/component** protocol major this build speaks (the version
/// carried in `ComponentInfo` on the identity plane). The Agent↔Gateway **wire**
/// protocol has its own [`WIRE_PROTOCOL_MAJOR`] — the two are independent.
pub const PROTOCOL_MAJOR: u32 = 1;
/// See [`PROTOCOL_MAJOR`].
pub const PROTOCOL_MINOR: u32 = 0;

/// Inclusive lowest CP↔Agent gRPC/component protocol version supported.
///
/// From the first MINOR bump onward this stays one minor behind
/// [`PROTOCOL_MAX`] to honour the N-1 window (contracts/VERSIONING.md §4). At
/// the `1.0` baseline there is no prior minor, so `min == max`.
pub const PROTOCOL_MIN: ProtocolVersion = ProtocolVersion {
    major: PROTOCOL_MAJOR,
    minor: PROTOCOL_MINOR,
};

/// Inclusive highest CP↔Agent gRPC/component protocol version supported.
pub const PROTOCOL_MAX: ProtocolVersion = ProtocolVersion {
    major: PROTOCOL_MAJOR,
    minor: PROTOCOL_MINOR,
};

/// Agent↔Gateway **wire** protocol version (`contracts/wire/agent-gateway-v1.md`),
/// FROZEN at 1.0. This is a **separate** protocol from the CP↔Agent gRPC plane
/// ([`PROTOCOL_MAJOR`] et al.) and carries its own constant on purpose
/// (F-wireversion-2): a later bump of the gRPC/component version must never
/// silently make the wire `HELLO` advertise a wire version this build does not
/// implement. `min == max` at the 1.0 baseline (no prior minor for the N-1 window).
pub const WIRE_PROTOCOL_MAJOR: u32 = 1;
/// See [`WIRE_PROTOCOL_MAJOR`].
pub const WIRE_PROTOCOL_MINOR: u32 = 0;

/// Inclusive lowest Agent↔Gateway wire-protocol version supported.
pub const WIRE_PROTOCOL_MIN: ProtocolVersion = ProtocolVersion {
    major: WIRE_PROTOCOL_MAJOR,
    minor: WIRE_PROTOCOL_MINOR,
};

/// Inclusive highest Agent↔Gateway wire-protocol version supported.
pub const WIRE_PROTOCOL_MAX: ProtocolVersion = ProtocolVersion {
    major: WIRE_PROTOCOL_MAJOR,
    minor: WIRE_PROTOCOL_MINOR,
};

/// The Agent's [`ComponentInfo`] for the **wire** `HELLO` preface — the same
/// identity as [`component_info`] but carrying the WIRE protocol range, so the
/// wire negotiation is driven only by [`WIRE_PROTOCOL_MIN`]/[`WIRE_PROTOCOL_MAX`].
pub fn wire_component_info() -> ComponentInfo {
    ComponentInfo {
        name: COMPONENT_NAME.to_string(),
        semver: SEMVER.to_string(),
        protocol_min: Some(WIRE_PROTOCOL_MIN),
        protocol_max: Some(WIRE_PROTOCOL_MAX),
    }
}

/// Render a [`ProtocolVersion`] as `"major.minor"`.
pub fn display_version(v: &ProtocolVersion) -> String {
    format!("{}.{}", v.major, v.minor)
}

/// The Agent's [`ComponentInfo`] for the **CP↔Agent gRPC plane** (enroll/renew
/// handshake) and the `--version` surface. Carries no secrets. The wire `HELLO`
/// preface uses [`wire_component_info`] instead — see [`WIRE_PROTOCOL_MAJOR`].
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
