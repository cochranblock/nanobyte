//! nanobyte-core — shared types for the Shotgun Nanobyte Sensor Swarm.
//!
//! `no_std` compatible so the mote firmware can depend on this crate directly
//! without pulling std. Host crates get the `std` feature by default (Display
//! impls, friendly error types); the mote target opts out.
//!
//! The type taxonomy here intentionally tracks the §5 science loop in the
//! mission plan:
//!
//! - `MoteId` — which mote is talking
//! - `VoxelAddr` — which asteroid cell is being probed
//! - `Classification` — the 4-way output of the 1-bit BNN
//! - `MoteFrame` — a single telemetry report from one mote
//! - `AddressBlock` — a mothership command targeting up to 64 motes in one OPA window
//!
//! Wire encoding lives in `nanobyte-proto`, not here. This crate is types only.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![warn(missing_docs)]

/// Protocol version. Bumped on any breaking wire-format change so the
/// mothership can reject frames from an out-of-date mote release.
pub const PROTOCOL_VERSION: u8 = 0x01;

/// 2-byte magic number prefixing every `nanobyte-proto` frame. `0xNB01`.
/// Distinct enough from common bitstreams to fail closed on garbage in the
/// APD demodulator.
pub const FRAME_MAGIC: [u8; 2] = [0x4E, 0xB0];

/// Addressable mote identifier. 24 bits supports ~16 M motes per mission,
/// 16× our Block 1.0 swarm size of 1 M. The high byte encodes the deployment
/// cassette so post-mortem analysis can tell which batch a mote came from.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MoteId(pub u32);

impl MoteId {
    /// Extract the 8-bit cassette id (which deployment batch).
    pub const fn cassette(self) -> u8 {
        ((self.0 >> 16) & 0xFF) as u8
    }

    /// Extract the 16-bit in-cassette serial.
    pub const fn serial(self) -> u16 {
        (self.0 & 0xFFFF) as u16
    }
}

/// 3D voxel address on the asteroid body. Coordinates are in centimeters
/// from the body-centered inertial frame origin. Signed i32 gives ±21 000 km
/// range — beyond any plausible body we'd prospect.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct VoxelAddr {
    /// X coordinate, cm, body-fixed frame.
    pub x: i32,
    /// Y coordinate, cm, body-fixed frame.
    pub y: i32,
    /// Z coordinate, cm, body-fixed frame.
    pub z: i32,
}

/// 4-way classification output of the mote's 1-bit BNN.
///
/// Encoded as u8 on the wire so new classes can be added without re-flashing
/// old motes — they emit `Other` for anything outside their trained set.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Classification {
    /// No signal above noise floor. Also used as the mandatory heartbeat
    /// code per P30 — a mote emits `Null` on every interrogation even if its
    /// sensors saw nothing, so silence is diagnosable as failure.
    Null = 0,
    /// Platinum-group emission line above FP-calibrated threshold.
    Platinum = 1,
    /// Water / hydroxyl signature (308 nm OH line + thermal pulse shape).
    Water = 2,
    /// Ferromagnetic signature without characteristic spectral lines.
    /// Differential hint for nickel-iron bodies.
    Metallic = 3,
    /// Signal present but doesn't match any trained class.
    Other = 255,
}

impl Classification {
    /// Convert from the raw u8 that arrives over the wire. Unknown values
    /// map to `Other` rather than panicking — forward-compatible decode.
    pub const fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Null,
            1 => Self::Platinum,
            2 => Self::Water,
            3 => Self::Metallic,
            _ => Self::Other,
        }
    }
}

/// A single telemetry frame emitted by one mote in response to one
/// interrogation-laser poll. Compact enough to ride a 2 ms kHz-modulated
/// chirp with margin for CRC and error-correction.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MoteFrame {
    /// Which mote is talking.
    pub mote: MoteId,
    /// Monotonically increasing sequence number per mote. Wraps at u16::MAX.
    /// Gaps in sequence = dropped frames = known signal loss.
    pub seq: u16,
    /// BNN classification for this interrogation cycle.
    pub class: Classification,
    /// BNN confidence, 0..=255. 1-bit BNN doesn't produce a probability,
    /// but we encode an ancillary signal (thermal-pulse SNR) here for
    /// downstream fusion by the 3D-CNN on the mothership.
    pub confidence: u8,
    /// Housekeeping: cap voltage at inference time, in centivolts.
    /// Ground ops uses this to detect motes entering brownout regime.
    pub cap_mv_over_10: u8,
    /// Housekeeping: local temperature, signed centi-degrees Celsius.
    pub temp_c100: i16,
}

/// A command from the mothership addressing a block of up to 64 motes
/// within one OPA beam window. The OPA addresses the block geometrically;
/// each mote within the block self-selects by matching `mote_mask` against
/// its 6-bit self-id within the block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddressBlock {
    /// Which voxel the LIBS laser just fired at, for mote correlation.
    pub voxel: VoxelAddr,
    /// Mothership sequence counter — motes echo this in `MoteFrame::seq`.
    pub campaign_seq: u16,
    /// Bitmask: which 6-bit mote ids within this OPA block should respond.
    /// Full 0xFFFF_FFFF_FFFF_FFFF = broadcast; targeted masks save power.
    pub mote_mask: u64,
    /// Post-ablation delay window, microseconds. Motes sample their
    /// sensors at t0 + delay after the LIBS pulse — tunes the afterglow
    /// observation to the chemistry being probed.
    pub sample_delay_us: u16,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classification_roundtrip_u8() {
        for c in [Classification::Null, Classification::Platinum, Classification::Water, Classification::Metallic, Classification::Other] {
            assert_eq!(Classification::from_u8(c as u8), c);
        }
    }

    #[test]
    fn classification_unknown_becomes_other() {
        assert_eq!(Classification::from_u8(42), Classification::Other);
        assert_eq!(Classification::from_u8(99), Classification::Other);
    }

    #[test]
    fn mote_id_splits_cassette_and_serial() {
        let id = MoteId(0x00_2A_C3_04);
        assert_eq!(id.cassette(), 0x2A);
        assert_eq!(id.serial(), 0xC304);
    }

    #[test]
    fn frame_magic_is_distinct() {
        // Loose sanity: the magic isn't all-zeros or all-ones, which would
        // be trivially produced by a dead or stuck APD channel.
        assert_ne!(FRAME_MAGIC, [0x00, 0x00]);
        assert_ne!(FRAME_MAGIC, [0xFF, 0xFF]);
    }
}
