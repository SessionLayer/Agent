//! Wire-conformance vectors (Part H): run the frozen golden frames through the
//! Agent's OWN `gateway::wire` codec so drift in framing or the type registry
//! fails in the Agent's CI, not only in a human cross-repo pass (the S14
//! `F-wireversion-1` class). No peer binary is needed — the golden bytes ARE the
//! peer. Vectors are vendored from `contracts/wire/conformance/frames.json`.
//!
//! ADAPTED to the Agent codec, which is deliberately **asymmetric** to the
//! Gateway's raw frame codec the reference drop-in targets: `decode` returns a
//! typed, role- and direction-checked `Inbound`, not a raw `{ver,type,payload}`.
//! So a frame the Agent has no business *receiving* (its own outbound types) is
//! refused, and a Gateway↔Gateway RELAY frame (0x24–0x26), which the Agent's
//! registry does not include, is refused as `UnknownType`. Both are correct,
//! security-relevant Agent behaviour, asserted here rather than papered over.
//!
//! This test pins: (1) the frozen §2 framing + the exact payload bytes for every
//! golden frame (incl. RELAY, via the framing formula) and the Agent's `encode` for
//! every type it owns; (2) the Agent accepts every frame it may receive; (3) the
//! Agent refuses every outbound / relay / reserved type; (4) the decoder rejects
//! each malformed negative with the mapped error.

use sessionlayer_agent::gateway::wire::{self, CodecError, Inbound, MsgType, Role};

const VECTORS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/conformance/frames.json"
));

/// The negotiated `max_frame_bytes` the golden `oversized` negative is pinned to.
const MAX: u32 = 65536;

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd-length hex: {s}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn tohex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The §2 framing, computed independently of the codec: `VER|TYPE|LEN(u32 BE)|PL`.
fn framed(ver: u8, type_byte: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![ver, type_byte];
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Map a golden type byte to the Agent's `MsgType`, or `None` for a type the Agent
/// codec does not own (the RELAY_* Gateway↔Gateway types, and anything reserved).
fn agent_msg_type(type_byte: u8) -> Option<MsgType> {
    Some(match type_byte {
        0x01 => MsgType::Hello,
        0x02 => MsgType::HelloAck,
        0x03 => MsgType::VersionReject,
        0x10 => MsgType::Ping,
        0x11 => MsgType::Pong,
        0x20 => MsgType::DialBackRequest,
        0x21 => MsgType::DialBackResult,
        0x22 => MsgType::DialBackAuth,
        0x23 => MsgType::DialBackAccept,
        0x30 => MsgType::StreamOpen,
        0x31 => MsgType::StreamData,
        0x32 => MsgType::StreamClose,
        0x7E => MsgType::Error,
        _ => return None,
    })
}

/// How the Agent treats a received frame of this type: the role to decode it on if
/// the Agent may receive it, or a refusal class.
enum Rx {
    /// The Agent may receive it on this role.
    Accept(Role),
    /// The Agent's own outbound type — it must never *receive* it.
    Outbound,
    /// A type the Agent's registry does not include (RELAY_*) or a reserved type.
    Foreign,
}

fn classify(type_byte: u8) -> Rx {
    match type_byte {
        // Legal on both roles / control-inbound.
        0x02 | 0x03 | 0x10 | 0x11 | 0x20 | 0x7E => Rx::Accept(Role::Control),
        // Dial-back-role inbound.
        0x23 | 0x31 | 0x32 => Rx::Accept(Role::DialBack),
        // Agent → Gateway (outbound-only).
        0x01 | 0x21 | 0x22 | 0x30 => Rx::Outbound,
        // RELAY_OPEN/ACCEPT/REJECT and any reserved byte.
        _ => Rx::Foreign,
    }
}

struct Frame {
    name: String,
    ver: u8,
    type_byte: u8,
    payload: Vec<u8>,
    frame: Vec<u8>,
}

fn vectors() -> serde_json::Value {
    serde_json::from_str(VECTORS).expect("parse frames.json")
}

fn frames(v: &serde_json::Value) -> Vec<Frame> {
    v["frames"]
        .as_array()
        .expect("frames[]")
        .iter()
        .map(|f| Frame {
            name: f["name"].as_str().unwrap().to_string(),
            ver: f["ver"].as_u64().unwrap() as u8,
            type_byte: f["type"].as_u64().unwrap() as u8,
            payload: unhex(f["payload_hex"].as_str().unwrap()),
            frame: unhex(f["frame_hex"].as_str().unwrap()),
        })
        .collect()
}

#[test]
fn golden_frames_are_framed_and_encoded_byte_exact() {
    let v = vectors();
    let frames = frames(&v);
    assert!(frames.len() >= 16, "expected the full §4 catalogue");

    for f in frames {
        // The frozen §2 layout, verified independently for EVERY type (incl. the
        // RELAY types the Agent does not decode) — pins framing + payload bytes.
        assert_eq!(
            framed(f.ver, f.type_byte, &f.payload),
            f.frame,
            "{}: frame does not match the frozen VER|TYPE|LEN|PAYLOAD layout",
            f.name
        );

        // For every type the Agent OWNS, its real `encode` must reproduce the golden
        // frame byte-for-byte — the same encoder used on the wire.
        if let Some(mt) = agent_msg_type(f.type_byte) {
            assert_eq!(
                tohex(&wire::encode(f.ver, mt, &f.payload)),
                tohex(&f.frame),
                "{}: Agent encode() must reproduce the golden frame",
                f.name
            );
        }
    }
}

#[test]
fn decoder_accepts_every_frame_the_agent_may_receive() {
    let v = vectors();
    for f in frames(&v) {
        let Rx::Accept(role) = classify(f.type_byte) else {
            continue;
        };
        let inbound = wire::decode(&f.frame, f.ver, MAX, role)
            .unwrap_or_else(|e| panic!("{}: an inbound frame must decode, got {e:?}", f.name));
        assert_eq!(
            inbound.msg_type() as u8,
            f.type_byte,
            "{}: decoded type byte must match the golden",
            f.name
        );
        // STREAM_DATA is the one type whose payload the codec keeps raw (SSH
        // ciphertext) — pin that it is carried verbatim, uninspected.
        if let Inbound::StreamData(raw) = &inbound {
            assert_eq!(
                raw, &f.payload,
                "{}: STREAM_DATA payload must be verbatim",
                f.name
            );
        }
    }
}

#[test]
fn decoder_refuses_outbound_relay_and_reserved_types() {
    let v = vectors();
    for f in frames(&v) {
        match classify(f.type_byte) {
            Rx::Outbound | Rx::Foreign => {
                // A frame the Agent must never *receive* is refused on EITHER role:
                // its own outbound types (direction), and RELAY_*/reserved types the
                // registry does not include (unknown). The Agent never processes a
                // frame it has no business receiving.
                assert!(
                    wire::decode(&f.frame, f.ver, MAX, Role::Control).is_err()
                        && wire::decode(&f.frame, f.ver, MAX, Role::DialBack).is_err(),
                    "{}: type {:#04x} must never be accepted inbound",
                    f.name,
                    f.type_byte
                );
            }
            Rx::Accept(_) => {}
        }
    }
}

#[test]
fn relay_types_are_refused_as_unknown_to_the_agent() {
    // The Agent's registry deliberately excludes the Gateway↔Gateway RELAY types
    // (0x24–0x26): the Agent is not a party to that protocol. Refusing them as
    // UnknownType (rather than silently accepting) keeps the shared type-number
    // registry pinned without giving the Agent a decoder for foreign frames.
    let v = vectors();
    for f in frames(&v) {
        if (0x24..=0x26).contains(&f.type_byte) {
            let err = wire::decode(&f.frame, f.ver, MAX, Role::DialBack)
                .expect_err(&format!("{}: a RELAY frame must be refused", f.name));
            assert!(
                matches!(err, CodecError::UnknownType(t) if t == f.type_byte),
                "{}: expected UnknownType({:#04x}), got {err:?}",
                f.name,
                f.type_byte
            );
        }
    }
}

#[test]
fn decoder_rejects_the_negative_vectors() {
    let v = vectors();
    for n in v["decode_negatives"]
        .as_array()
        .expect("decode_negatives[]")
    {
        let name = n["name"].as_str().unwrap();
        let expect = n["expect"].as_str().unwrap();
        let bytes = unhex(n["hex"].as_str().unwrap());

        // The negotiated major is 1; the length/oversized cases use STREAM_DATA
        // (0x31), which is legal on the dial-back role, so decode reaches the framing
        // checks rather than short-circuiting on role. The oversized case is rejected
        // on the declared LENGTH header alone — the absent body is never buffered.
        let err = wire::decode(&bytes, 1, MAX, Role::DialBack)
            .expect_err(&format!("{name}: must be rejected"));

        let got = match err {
            CodecError::TooShort { .. } => "Short",
            CodecError::LengthMismatch { .. } => "LengthMismatch",
            CodecError::Oversized { .. } => "TooLarge",
            CodecError::VersionMismatch { .. } => "BadVersion",
            CodecError::UnknownType(_) => "UnknownType",
            other => panic!("{name}: unexpected rejection {other:?}"),
        };
        assert_eq!(got, expect, "{name}: wrong rejection reason");
    }
}
