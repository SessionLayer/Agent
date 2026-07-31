//! Version and protocol-range surface.

use serde::Serialize;

use crate::proto::{ComponentInfo, ProtocolVersion};

pub const COMPONENT_NAME: &str = "SessionLayer Agent";

pub const SEMVER: &str = env!("CARGO_PKG_VERSION");

pub const PROTOCOL_MAJOR: u32 = 1;
pub const PROTOCOL_MINOR: u32 = 0;

pub const PROTOCOL_MIN: ProtocolVersion = ProtocolVersion {
    major: PROTOCOL_MAJOR,
    minor: PROTOCOL_MINOR,
};

pub const PROTOCOL_MAX: ProtocolVersion = ProtocolVersion {
    major: PROTOCOL_MAJOR,
    minor: PROTOCOL_MINOR,
};

pub const WIRE_PROTOCOL_MAJOR: u32 = 1;
pub const WIRE_PROTOCOL_MINOR: u32 = 0;

pub const WIRE_PROTOCOL_MIN: ProtocolVersion = ProtocolVersion {
    major: WIRE_PROTOCOL_MAJOR,
    minor: WIRE_PROTOCOL_MINOR,
};

pub const WIRE_PROTOCOL_MAX: ProtocolVersion = ProtocolVersion {
    major: WIRE_PROTOCOL_MAJOR,
    minor: WIRE_PROTOCOL_MINOR,
};

pub fn wire_component_info() -> ComponentInfo {
    ComponentInfo {
        name: COMPONENT_NAME.to_string(),
        semver: SEMVER.to_string(),
        protocol_min: Some(WIRE_PROTOCOL_MIN),
        protocol_max: Some(WIRE_PROTOCOL_MAX),
    }
}

pub fn display_version(v: &ProtocolVersion) -> String {
    format!("{}.{}", v.major, v.minor)
}

pub fn component_info() -> ComponentInfo {
    ComponentInfo {
        name: COMPONENT_NAME.to_string(),
        semver: SEMVER.to_string(),
        protocol_min: Some(PROTOCOL_MIN),
        protocol_max: Some(PROTOCOL_MAX),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VersionInfo {
    pub component: &'static str,
    pub semver: &'static str,
    pub protocol_min: String,
    pub protocol_max: String,
}

pub fn version_info() -> VersionInfo {
    VersionInfo {
        component: COMPONENT_NAME,
        semver: SEMVER,
        protocol_min: display_version(&PROTOCOL_MIN),
        protocol_max: display_version(&PROTOCOL_MAX),
    }
}
