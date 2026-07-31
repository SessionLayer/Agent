use sessionlayer_agent::gateway::wire::{self, CodecError, Inbound, MsgType, Role};

const VECTORS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/conformance/frames.json"
));

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

fn framed(ver: u8, type_byte: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![ver, type_byte];
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

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

enum Rx {
    Accept(Role),
    Outbound,
    Foreign,
}

fn classify(type_byte: u8) -> Rx {
    match type_byte {
        0x02 | 0x03 | 0x10 | 0x11 | 0x20 | 0x7E => Rx::Accept(Role::Control),
        0x23 | 0x31 | 0x32 => Rx::Accept(Role::DialBack),
        0x01 | 0x21 | 0x22 | 0x30 => Rx::Outbound,
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
        assert_eq!(
            framed(f.ver, f.type_byte, &f.payload),
            f.frame,
            "{}: frame does not match the frozen VER|TYPE|LEN|PAYLOAD layout",
            f.name
        );

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
