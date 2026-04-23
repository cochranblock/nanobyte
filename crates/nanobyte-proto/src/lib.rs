//! nanobyte-proto — packed binary wire format for NANOBYTE.
//!
//! Frame layout (big-endian on the wire):
//!
//! ```text
//!   0                   1                   2                   3
//!   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |  magic[0]     |  magic[1]     |  version      |  payload_kind  |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |  seq (u16, big-endian)        |  payload_len (u16, be)         |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |                  payload  (payload_len bytes)                  |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |  crc16 (u16, be)              |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! Block 0.0 ships the header + CRC + a single payload kind (Heartbeat) so
//! `nanobyte-hive` and `nanobyte-sim` can exchange valid frames end-to-end.
//! Block 0.1 fills in MoteFrame / AddressBlock encoders.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use nanobyte_core::{FRAME_MAGIC, PROTOCOL_VERSION};

/// Fixed-size frame header — 8 bytes. Sized so an aligned APD frame capture
/// can decode the header before committing to reading the payload.
pub const HEADER_LEN: usize = 8;

/// CRC-16/CCITT-FALSE — same polynomial used in many embedded protocols,
/// mature implementations in every language the mission might need to decode.
const CRC16_ALG: crc::Algorithm<u16> = crc::CRC_16_IBM_3740;

/// Wire-protocol errors. Kept minimal — anything beyond "didn't parse" is
/// the caller's problem.
#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    /// Frame was shorter than the minimum 10 bytes (8-byte header + 2-byte CRC).
    #[error("frame too short: {0} bytes")]
    TooShort(usize),
    /// First two bytes did not match `FRAME_MAGIC`.
    #[error("bad magic: expected {expected:02x?}, got {got:02x?}")]
    BadMagic {
        /// Expected magic bytes.
        expected: [u8; 2],
        /// What we actually saw.
        got: [u8; 2],
    },
    /// Protocol version older than the mothership supports.
    #[error("unsupported protocol version: {0}")]
    UnsupportedVersion(u8),
    /// Payload length in header doesn't match actual bytes available.
    #[error("length mismatch: header says {header}, frame has {actual}")]
    LengthMismatch {
        /// Length from the header field.
        header: usize,
        /// Actual payload bytes remaining after the header.
        actual: usize,
    },
    /// CRC did not match.
    #[error("crc mismatch: expected {expected:04x}, got {got:04x}")]
    CrcMismatch {
        /// CRC we computed over the payload.
        expected: u16,
        /// CRC read from the end of the frame.
        got: u16,
    },
}

use thiserror as _thiserror; // keep the dep pinned while we're not using it elsewhere

/// Parsed frame header with validated magic + version.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Header {
    /// Protocol version byte; always matches `PROTOCOL_VERSION` on Block 0.0.
    pub version: u8,
    /// Distinguishes command frames (mothership→mote), telemetry frames
    /// (mote→mothership), and heartbeat frames (either direction).
    pub payload_kind: u8,
    /// Monotonic sequence number, wraps at u16::MAX.
    pub seq: u16,
    /// Payload length in bytes, not counting the trailing CRC.
    pub payload_len: u16,
}

/// Encode a frame: header + payload + CRC-16 trailer. Returns the full wire
/// bytes. Caller owns the payload slice; we don't allocate for it.
pub fn encode(header: Header, payload: &[u8]) -> Vec<u8> {
    let total_len = HEADER_LEN + payload.len() + 2;
    let mut buf = Vec::with_capacity(total_len);
    buf.push(FRAME_MAGIC[0]);
    buf.push(FRAME_MAGIC[1]);
    buf.push(header.version);
    buf.push(header.payload_kind);
    buf.extend_from_slice(&header.seq.to_be_bytes());
    buf.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    buf.extend_from_slice(payload);
    let crc = crc::Crc::<u16>::new(&CRC16_ALG).checksum(payload);
    buf.extend_from_slice(&crc.to_be_bytes());
    buf
}

/// Decode a frame. Returns (header, payload-slice) borrowed from the input
/// bytes. Validates magic, version, length, and CRC before returning.
pub fn decode(bytes: &[u8]) -> Result<(Header, &[u8]), ProtoError> {
    if bytes.len() < HEADER_LEN + 2 {
        return Err(ProtoError::TooShort(bytes.len()));
    }
    let magic = [bytes[0], bytes[1]];
    if magic != FRAME_MAGIC {
        return Err(ProtoError::BadMagic {
            expected: FRAME_MAGIC,
            got: magic,
        });
    }
    let version = bytes[2];
    if version != PROTOCOL_VERSION {
        return Err(ProtoError::UnsupportedVersion(version));
    }
    let payload_kind = bytes[3];
    let seq = u16::from_be_bytes([bytes[4], bytes[5]]);
    let payload_len = u16::from_be_bytes([bytes[6], bytes[7]]) as usize;
    let expected_total = HEADER_LEN + payload_len + 2;
    if bytes.len() != expected_total {
        return Err(ProtoError::LengthMismatch {
            header: payload_len,
            actual: bytes.len().saturating_sub(HEADER_LEN + 2),
        });
    }
    let payload = &bytes[HEADER_LEN..HEADER_LEN + payload_len];
    let got_crc = u16::from_be_bytes([bytes[HEADER_LEN + payload_len], bytes[HEADER_LEN + payload_len + 1]]);
    let expected_crc = crc::Crc::<u16>::new(&CRC16_ALG).checksum(payload);
    if got_crc != expected_crc {
        return Err(ProtoError::CrcMismatch {
            expected: expected_crc,
            got: got_crc,
        });
    }
    Ok((
        Header {
            version,
            payload_kind,
            seq,
            payload_len: payload_len as u16,
        },
        payload,
    ))
}

/// Payload kind constants. Block 0.0 defines only Heartbeat; later blocks
/// add Telemetry and Command.
pub mod kind {
    /// Zero-payload "I'm alive" frame. Per P30 — every mote must emit one
    /// on every interrogation regardless of classification result.
    pub const HEARTBEAT: u8 = 0x01;
    /// Mote → mothership telemetry carrying a `MoteFrame`.
    pub const TELEMETRY: u8 = 0x02;
    /// Mothership → mote command carrying an `AddressBlock`.
    pub const COMMAND: u8 = 0x03;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heartbeat_roundtrip() {
        let h = Header {
            version: PROTOCOL_VERSION,
            payload_kind: kind::HEARTBEAT,
            seq: 42,
            payload_len: 0,
        };
        let bytes = encode(h, &[]);
        assert_eq!(bytes.len(), HEADER_LEN + 2);
        let (parsed, payload) = decode(&bytes).expect("decode roundtrip");
        assert_eq!(parsed, h);
        assert!(payload.is_empty());
    }

    #[test]
    fn telemetry_with_payload_roundtrips() {
        let h = Header {
            version: PROTOCOL_VERSION,
            payload_kind: kind::TELEMETRY,
            seq: 1337,
            payload_len: 5,
        };
        let payload = [0xDE, 0xAD, 0xBE, 0xEF, 0x42];
        let bytes = encode(h, &payload);
        let (parsed, got_payload) = decode(&bytes).expect("decode");
        assert_eq!(parsed, h);
        assert_eq!(got_payload, &payload);
    }

    #[test]
    fn flipped_bit_in_payload_fails_crc() {
        let h = Header {
            version: PROTOCOL_VERSION,
            payload_kind: kind::TELEMETRY,
            seq: 1,
            payload_len: 3,
        };
        let mut bytes = encode(h, &[1, 2, 3]);
        bytes[HEADER_LEN] ^= 0x01; // corrupt one payload bit
        assert!(matches!(decode(&bytes), Err(ProtoError::CrcMismatch { .. })));
    }

    #[test]
    fn bad_magic_rejected() {
        let h = Header {
            version: PROTOCOL_VERSION,
            payload_kind: kind::HEARTBEAT,
            seq: 0,
            payload_len: 0,
        };
        let mut bytes = encode(h, &[]);
        bytes[0] = 0xFF;
        assert!(matches!(decode(&bytes), Err(ProtoError::BadMagic { .. })));
    }

    #[test]
    fn unsupported_version_rejected() {
        let h = Header {
            version: 0xFE,
            payload_kind: kind::HEARTBEAT,
            seq: 0,
            payload_len: 0,
        };
        let bytes = encode(h, &[]);
        assert!(matches!(decode(&bytes), Err(ProtoError::UnsupportedVersion(0xFE))));
    }

    #[test]
    fn too_short_rejected() {
        assert!(matches!(decode(&[0x4E, 0xB0]), Err(ProtoError::TooShort(_))));
    }
}
