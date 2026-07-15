//! Version / contract-type tests (deliverable §6.3.2).
//!
//! These construct the generated `ComponentInfo` / `ProtocolVersion` types and
//! assert the Session One baseline: the supported wire-protocol range is
//! exactly 1.0-1.0, the descriptor round-trips through JSON, and the human
//! `--version` string cannot silently drift from the numeric constants.

use sessionlayer_agent::proto::{ComponentInfo, ProtocolVersion};
use sessionlayer_agent::version;

#[test]
fn component_info_advertises_agent_identity() {
    let info: ComponentInfo = version::component_info();

    assert_eq!(info.name, "SessionLayer Agent");
    assert_eq!(info.semver, env!("CARGO_PKG_VERSION"));
    assert_eq!(info.semver, "0.1.0");

    // Both bounds are present (they are proto3 message fields → Option).
    assert!(info.protocol_min.is_some(), "protocol_min must be set");
    assert!(info.protocol_max.is_some(), "protocol_max must be set");
}

#[test]
fn supported_protocol_range_is_exactly_1_0() {
    // Constructed directly from the generated type.
    let min: ProtocolVersion = version::PROTOCOL_MIN;
    let max: ProtocolVersion = version::PROTOCOL_MAX;

    assert_eq!(min, ProtocolVersion { major: 1, minor: 0 });
    assert_eq!(max, ProtocolVersion { major: 1, minor: 0 });

    // Session One baseline: no prior minor exists, so min == max (the N-1
    // window only becomes load-bearing from the first minor bump).
    assert_eq!(min, max);

    // And the ComponentInfo carries the same bounds.
    let info = version::component_info();
    assert_eq!(info.protocol_min, Some(min));
    assert_eq!(info.protocol_max, Some(max));
}

#[test]
fn wire_protocol_range_is_exactly_1_0() {
    // F-wireversion-2: the Agent↔Gateway WIRE protocol is fixed at 1.0 and is a
    // SEPARATE constant from the gRPC/component version, so a later gRPC bump can
    // never make the wire HELLO advertise a wire version this build cannot speak.
    assert_eq!(
        version::WIRE_PROTOCOL_MIN,
        ProtocolVersion { major: 1, minor: 0 }
    );
    assert_eq!(
        version::WIRE_PROTOCOL_MAX,
        ProtocolVersion { major: 1, minor: 0 }
    );
    assert_eq!(version::WIRE_PROTOCOL_MIN, version::WIRE_PROTOCOL_MAX);

    let info = version::wire_component_info();
    assert_eq!(info.name, "SessionLayer Agent");
    assert_eq!(info.protocol_min, Some(version::WIRE_PROTOCOL_MIN));
    assert_eq!(info.protocol_max, Some(version::WIRE_PROTOCOL_MAX));
}

#[test]
fn display_version_formats_major_minor() {
    assert_eq!(
        version::display_version(&ProtocolVersion { major: 1, minor: 0 }),
        "1.0"
    );
    assert_eq!(
        version::display_version(&ProtocolVersion { major: 2, minor: 7 }),
        "2.7"
    );
}

#[test]
fn version_info_serialises_to_stable_json() {
    let json = serde_json::to_value(version::version_info()).expect("serialise VersionInfo");

    assert_eq!(json["component"], "SessionLayer Agent");
    assert_eq!(json["semver"], "0.1.0");
    assert_eq!(json["protocol_min"], "1.0");
    assert_eq!(json["protocol_max"], "1.0");
}

#[test]
fn long_version_string_matches_numeric_constants() {
    // Guard against the hand-written `--version` banner drifting from the numeric
    // constants. The banner's line is the WIRE protocol (it cites
    // agent-gateway-v1.md), so it tracks the WIRE constants, not the gRPC ones.
    let expected_range = format!(
        "{} - {}",
        version::display_version(&version::WIRE_PROTOCOL_MIN),
        version::display_version(&version::WIRE_PROTOCOL_MAX)
    );
    assert!(
        sessionlayer_agent::LONG_VERSION.contains(&expected_range),
        "LONG_VERSION ({:?}) must contain the numeric range {:?}",
        sessionlayer_agent::LONG_VERSION,
        expected_range
    );
    assert!(sessionlayer_agent::LONG_VERSION.contains(env!("CARGO_PKG_VERSION")));
}
