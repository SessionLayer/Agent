//! The Agent<->Gateway frame codec (`contracts/wire/agent-gateway-v1.md` §2/§4).
//!
//! One frame per WebSocket **binary** message:
//!
//! ```text
//! VER(1) | TYPE(1) | LENGTH(u32 BE) | PAYLOAD (LENGTH bytes)
//! ```
//!
//! Every payload is the protobuf message named in §4 **except** `STREAM_DATA`,
//! whose payload is raw opaque bytes (SSH-layer ciphertext): the session hot path
//! pays no encoding cost and the Agent has no decoder for what it carries.
//!
//! Shared by both connection roles. Decoding is fail-closed: an unknown type, a
//! reserved type, a type illegal for the role or direction, a version mismatch, a
//! short frame, trailing garbage, or an oversized payload are all protocol errors.

use prost::Message;

use crate::proto::wire::{
    DialBackAccept, DialBackRequest, GatewayHelloAck, Ping, Pong, StreamClose, VersionReject,
    WireError,
};

/// `VER | TYPE | LENGTH(u32)`.
pub const FRAME_HEADER_LEN: usize = 6;

/// The largest payload this Agent will ever buffer, whatever a Gateway proposes.
/// The negotiated `max_frame_bytes` must land within
/// `[MIN_FRAME_BYTES, MAX_FRAME_BYTES_CEILING]` or the preface fails closed — so a
/// hostile `HELLO_ACK` cannot talk us into an unbounded read buffer. The WebSocket
/// reader is configured with this ceiling, which is what actually stops an
/// oversized frame from being buffered at all (the codec bound below is the
/// second, negotiated line).
pub const MAX_FRAME_BYTES_CEILING: u32 = 1 << 20;

/// The smallest sane negotiated frame bound: below this the preface messages
/// themselves would not fit, so it can only be a misconfiguration or an attempt to
/// wedge the channel.
pub const MIN_FRAME_BYTES: u32 = 4096;

/// What we ask for, and what a sane Gateway will echo: 64 KiB of ciphertext per
/// frame comfortably exceeds the SSH maximum packet size, so a single SSH packet
/// never straddles frames for a bandwidth reason.
pub const PREFERRED_MAX_FRAME_BYTES: u32 = 64 * 1024;

/// Which connection a frame arrived on. A type legal on one role is a protocol
/// error on the other (§4): the control channel never carries session bytes, and a
/// dial-back connection never carries a dial-back request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Control,
    DialBack,
}

/// The §4 message catalogue. Numbers are stable and never reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MsgType {
    Hello = 0x01,
    HelloAck = 0x02,
    VersionReject = 0x03,
    Ping = 0x10,
    Pong = 0x11,
    DialBackRequest = 0x20,
    DialBackResult = 0x21,
    DialBackAuth = 0x22,
    DialBackAccept = 0x23,
    StreamOpen = 0x30,
    StreamData = 0x31,
    StreamClose = 0x32,
    Error = 0x7E,
}

impl MsgType {
    fn from_u8(v: u8) -> Option<Self> {
        // 0x40 NODE_STATUS, 0x50 CREDENTIAL_ROTATE and 0x7F GOAWAY are *reserved*
        // and MUST be rejected as protocol errors until they are defined (§4);
        // falling through to `None` is exactly that.
        Some(match v {
            0x01 => Self::Hello,
            0x02 => Self::HelloAck,
            0x03 => Self::VersionReject,
            0x10 => Self::Ping,
            0x11 => Self::Pong,
            0x20 => Self::DialBackRequest,
            0x21 => Self::DialBackResult,
            0x22 => Self::DialBackAuth,
            0x23 => Self::DialBackAccept,
            0x30 => Self::StreamOpen,
            0x31 => Self::StreamData,
            0x32 => Self::StreamClose,
            0x7E => Self::Error,
            _ => return None,
        })
    }

    fn legal_in(self, role: Role) -> bool {
        match self {
            Self::Hello | Self::HelloAck | Self::VersionReject | Self::Error => true,
            Self::Ping | Self::Pong | Self::DialBackRequest | Self::DialBackResult => {
                role == Role::Control
            }
            Self::DialBackAuth
            | Self::DialBackAccept
            | Self::StreamOpen
            | Self::StreamData
            | Self::StreamClose => role == Role::DialBack,
        }
    }

    /// Whether an Agent may *receive* this type. The §4 table fixes a direction
    /// per type; a Gateway sending us an Agent->Gateway-only type is a protocol
    /// error, not something to tolerate.
    fn agent_may_receive(self) -> bool {
        match self {
            Self::HelloAck
            | Self::VersionReject
            | Self::Ping
            | Self::Pong
            | Self::DialBackRequest
            | Self::DialBackAccept
            | Self::StreamData
            | Self::StreamClose
            | Self::Error => true,
            Self::Hello | Self::DialBackAuth | Self::DialBackResult | Self::StreamOpen => false,
        }
    }
}

/// A framing/decoding failure. Every variant is a protocol error: the caller sends
/// `ERROR(PROTOCOL)` and closes (fail closed — never "skip and continue", which
/// would let a peer desynchronise the stream deliberately).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CodecError {
    #[error("frame shorter than the {FRAME_HEADER_LEN}-byte header ({got} bytes)")]
    TooShort { got: usize },

    #[error("frame version {got} does not match the negotiated version {expected}")]
    VersionMismatch { got: u8, expected: u8 },

    #[error("unknown or reserved message type {0:#04x}")]
    UnknownType(u8),

    #[error("message type {ty:#04x} is not legal on the {role:?} connection")]
    IllegalForRole { ty: u8, role: Role },

    #[error("message type {ty:#04x} may not be sent to an Agent")]
    IllegalDirection { ty: u8 },

    #[error("declared length {declared} does not match the {actual} payload bytes present")]
    LengthMismatch { declared: u32, actual: usize },

    #[error("payload of {len} bytes exceeds the negotiated maximum of {max}")]
    Oversized { len: u32, max: u32 },

    #[error("payload is not a valid {message} protobuf")]
    Decode { message: &'static str },

    #[error("a WebSocket text message is a protocol error on this transport")]
    TextMessage,
}

/// A decoded inbound frame. `StreamData` keeps its payload raw and uninspected.
#[derive(Debug)]
pub enum Inbound {
    HelloAck(GatewayHelloAck),
    VersionReject(VersionReject),
    Ping(Ping),
    Pong(Pong),
    DialBackRequest(Box<DialBackRequest>),
    DialBackAccept(DialBackAccept),
    StreamData(Vec<u8>),
    StreamClose(StreamClose),
    Error(WireError),
}

impl Inbound {
    /// The wire type, for logging a frame we then reject.
    pub fn msg_type(&self) -> MsgType {
        match self {
            Self::HelloAck(_) => MsgType::HelloAck,
            Self::VersionReject(_) => MsgType::VersionReject,
            Self::Ping(_) => MsgType::Ping,
            Self::Pong(_) => MsgType::Pong,
            Self::DialBackRequest(_) => MsgType::DialBackRequest,
            Self::DialBackAccept(_) => MsgType::DialBackAccept,
            Self::StreamData(_) => MsgType::StreamData,
            Self::StreamClose(_) => MsgType::StreamClose,
            Self::Error(_) => MsgType::Error,
        }
    }
}

/// Encode one frame. `payload` is already-serialized protobuf, or — for
/// `STREAM_DATA` — raw session ciphertext.
pub fn encode(version: u8, ty: MsgType, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
    out.push(version);
    out.push(ty as u8);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Encode a protobuf-payload frame.
pub fn encode_msg<M: Message>(version: u8, ty: MsgType, msg: &M) -> Vec<u8> {
    encode(version, ty, &msg.encode_to_vec())
}

/// Decode one inbound WebSocket binary message into a frame, enforcing the
/// negotiated version, the negotiated payload bound, the role, and the direction.
pub fn decode(
    bytes: &[u8],
    expected_version: u8,
    max_payload: u32,
    role: Role,
) -> Result<Inbound, CodecError> {
    if bytes.len() < FRAME_HEADER_LEN {
        return Err(CodecError::TooShort { got: bytes.len() });
    }
    let version = bytes[0];
    if version != expected_version {
        return Err(CodecError::VersionMismatch {
            got: version,
            expected: expected_version,
        });
    }

    let raw_type = bytes[1];
    let ty = MsgType::from_u8(raw_type).ok_or(CodecError::UnknownType(raw_type))?;
    if !ty.legal_in(role) {
        return Err(CodecError::IllegalForRole { ty: raw_type, role });
    }
    if !ty.agent_may_receive() {
        return Err(CodecError::IllegalDirection { ty: raw_type });
    }

    let declared = u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
    if declared > max_payload {
        return Err(CodecError::Oversized {
            len: declared,
            max: max_payload,
        });
    }
    let payload = &bytes[FRAME_HEADER_LEN..];
    // LENGTH must equal the remaining bytes exactly: a short frame AND a frame
    // with trailing garbage are both protocol errors (§2).
    if declared as usize != payload.len() {
        return Err(CodecError::LengthMismatch {
            declared,
            actual: payload.len(),
        });
    }

    fn parse<M: Message + Default>(payload: &[u8], name: &'static str) -> Result<M, CodecError> {
        M::decode(payload).map_err(|_| CodecError::Decode { message: name })
    }

    Ok(match ty {
        MsgType::HelloAck => Inbound::HelloAck(parse(payload, "GatewayHelloAck")?),
        MsgType::VersionReject => Inbound::VersionReject(parse(payload, "VersionReject")?),
        MsgType::Ping => Inbound::Ping(parse(payload, "Ping")?),
        MsgType::Pong => Inbound::Pong(parse(payload, "Pong")?),
        MsgType::DialBackRequest => {
            Inbound::DialBackRequest(Box::new(parse(payload, "DialBackRequest")?))
        }
        MsgType::DialBackAccept => Inbound::DialBackAccept(parse(payload, "DialBackAccept")?),
        MsgType::StreamClose => Inbound::StreamClose(parse(payload, "StreamClose")?),
        MsgType::Error => Inbound::Error(parse(payload, "WireError")?),
        // Opaque by contract: never parsed, never inspected, never logged.
        MsgType::StreamData => Inbound::StreamData(payload.to_vec()),
        MsgType::Hello | MsgType::DialBackAuth | MsgType::DialBackResult | MsgType::StreamOpen => {
            unreachable!("rejected by the direction/role checks above")
        }
    })
}

/// Types the Agent sends but never receives; kept next to the codec so a
/// reviewer sees both halves of the catalogue in one place.
pub mod out {
    use super::{encode_msg, MsgType};
    use crate::proto::wire::{AgentHello, DialBackAuth, DialBackResult, Pong, StreamClose};
    use crate::proto::ComponentInfo;

    pub fn hello(version: u8, component: ComponentInfo) -> Vec<u8> {
        encode_msg(
            version,
            MsgType::Hello,
            &AgentHello {
                component: Some(component),
            },
        )
    }

    pub fn pong(version: u8, nonce: u64) -> Vec<u8> {
        encode_msg(version, MsgType::Pong, &Pong { nonce })
    }

    pub fn dial_back_result(version: u8, msg: &DialBackResult) -> Vec<u8> {
        encode_msg(version, MsgType::DialBackResult, msg)
    }

    pub fn dial_back_auth(version: u8, msg: &DialBackAuth) -> Vec<u8> {
        encode_msg(version, MsgType::DialBackAuth, msg)
    }

    pub fn stream_open(version: u8) -> Vec<u8> {
        encode_msg(
            version,
            MsgType::StreamOpen,
            &crate::proto::wire::StreamOpen {},
        )
    }

    pub fn stream_close(version: u8, msg: &StreamClose) -> Vec<u8> {
        encode_msg(version, MsgType::StreamClose, msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const V: u8 = 1;
    const MAX: u32 = PREFERRED_MAX_FRAME_BYTES;

    fn ping_frame(nonce: u64) -> Vec<u8> {
        encode_msg(V, MsgType::Ping, &Ping { nonce })
    }

    #[test]
    fn ping_round_trips_through_the_codec() {
        let frame = ping_frame(0xDEAD_BEEF);
        assert_eq!(frame[0], V);
        assert_eq!(frame[1], 0x10);
        match decode(&frame, V, MAX, Role::Control).unwrap() {
            Inbound::Ping(p) => assert_eq!(p.nonce, 0xDEAD_BEEF),
            other => panic!("expected Ping, got {other:?}"),
        }
    }

    #[test]
    fn stream_data_payload_is_raw_bytes_not_protobuf() {
        // The bytes below are not a valid protobuf message; STREAM_DATA must still
        // carry them verbatim (they are SSH ciphertext, and the Agent has no
        // decoder for them by design).
        let ciphertext = vec![0xFF, 0x00, 0x91, 0x7E, 0x42];
        let frame = encode(V, MsgType::StreamData, &ciphertext);
        match decode(&frame, V, MAX, Role::DialBack).unwrap() {
            Inbound::StreamData(got) => assert_eq!(got, ciphertext),
            other => panic!("expected StreamData, got {other:?}"),
        }
    }

    #[test]
    fn frame_shorter_than_the_header_is_a_protocol_error() {
        for len in 0..FRAME_HEADER_LEN {
            let err = decode(&vec![0u8; len], V, MAX, Role::Control).unwrap_err();
            assert_eq!(err, CodecError::TooShort { got: len });
        }
    }

    #[test]
    fn wrong_version_byte_is_a_protocol_error() {
        let mut frame = ping_frame(1);
        frame[0] = 2;
        assert_eq!(
            decode(&frame, V, MAX, Role::Control).unwrap_err(),
            CodecError::VersionMismatch {
                got: 2,
                expected: V
            }
        );
    }

    #[test]
    fn unknown_and_reserved_types_are_protocol_errors() {
        // 0x40 NODE_STATUS / 0x50 CREDENTIAL_ROTATE / 0x7F GOAWAY are reserved:
        // they MUST be rejected until they are defined, exactly like garbage.
        for ty in [0x00u8, 0x40, 0x50, 0x7F, 0xAB, 0xFF] {
            let mut frame = ping_frame(1);
            frame[1] = ty;
            assert_eq!(
                decode(&frame, V, MAX, Role::Control).unwrap_err(),
                CodecError::UnknownType(ty),
                "type {ty:#04x} must be refused"
            );
        }
    }

    #[test]
    fn a_type_is_illegal_on_the_wrong_role() {
        // Session bytes may never appear on the control channel...
        let data = encode(V, MsgType::StreamData, b"x");
        assert_eq!(
            decode(&data, V, MAX, Role::Control).unwrap_err(),
            CodecError::IllegalForRole {
                ty: 0x31,
                role: Role::Control
            }
        );
        // ...and a dial-back request may never appear on a dial-back connection.
        let req = encode_msg(V, MsgType::DialBackRequest, &DialBackRequest::default());
        assert_eq!(
            decode(&req, V, MAX, Role::DialBack).unwrap_err(),
            CodecError::IllegalForRole {
                ty: 0x20,
                role: Role::DialBack
            }
        );
    }

    #[test]
    fn agent_to_gateway_only_types_are_refused_inbound() {
        // A Gateway echoing us our own direction's frames is a protocol error, not
        // something to tolerate: it is how a peer probes for a lenient parser.
        for (ty, role) in [
            (MsgType::Hello, Role::Control),
            (MsgType::DialBackResult, Role::Control),
            (MsgType::DialBackAuth, Role::DialBack),
            (MsgType::StreamOpen, Role::DialBack),
        ] {
            let frame = encode(V, ty, b"");
            assert_eq!(
                decode(&frame, V, MAX, role).unwrap_err(),
                CodecError::IllegalDirection { ty: ty as u8 },
                "{ty:?} must not be accepted from a Gateway"
            );
        }
    }

    #[test]
    fn short_payload_and_trailing_garbage_are_protocol_errors() {
        let frame = ping_frame(7);

        let mut truncated = frame.clone();
        truncated.pop();
        assert!(matches!(
            decode(&truncated, V, MAX, Role::Control).unwrap_err(),
            CodecError::LengthMismatch { .. }
        ));

        let mut trailing = frame.clone();
        trailing.push(0x00);
        assert!(matches!(
            decode(&trailing, V, MAX, Role::Control).unwrap_err(),
            CodecError::LengthMismatch { .. }
        ));
    }

    #[test]
    fn oversized_frame_is_rejected_on_the_declared_length_alone() {
        // The DoS guard must fire on the LENGTH header, before the payload is
        // considered — a peer must not be able to make us size a buffer from a
        // number it chose.
        let mut frame = encode(V, MsgType::StreamData, b"");
        frame[2..6].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(
            decode(&frame, V, 1024, Role::DialBack).unwrap_err(),
            CodecError::Oversized {
                len: u32::MAX,
                max: 1024
            }
        );

        // And a payload one byte over the negotiated bound is refused.
        let over = encode(V, MsgType::StreamData, &vec![0u8; 1025]);
        assert_eq!(
            decode(&over, V, 1024, Role::DialBack).unwrap_err(),
            CodecError::Oversized {
                len: 1025,
                max: 1024
            }
        );
    }

    #[test]
    fn garbage_protobuf_payload_is_a_protocol_error() {
        // A well-framed frame whose payload is not the protobuf the type promises.
        let frame = encode(V, MsgType::HelloAck, &[0xFF, 0xFF, 0xFF, 0xFF]);
        assert!(matches!(
            decode(&frame, V, MAX, Role::Control).unwrap_err(),
            CodecError::Decode { .. }
        ));
    }

    #[test]
    fn agent_outbound_hello_carries_the_component_range() {
        let frame = out::hello(V, crate::version::wire_component_info());
        match decode(&frame, V, MAX, Role::Control) {
            // The Agent never *receives* HELLO, so decoding its own must be
            // refused by direction — proving the guard is not type-blind.
            Err(CodecError::IllegalDirection { ty }) => assert_eq!(ty, 0x01),
            other => panic!("expected an inbound-direction refusal, got {other:?}"),
        }
        assert_eq!(frame[1], MsgType::Hello as u8);
    }
}
