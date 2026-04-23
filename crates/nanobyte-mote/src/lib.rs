//! nanobyte-mote — firmware for a single dust mote.
//!
//! `no_std` + `panic = abort`. Block 0.0 is the state-machine skeleton
//! plus pinned public APIs. The BNN inference kernel, the ADC driver,
//! and the MEMS mirror driver land in subsequent blocks.
//!
//! **Timing budget (P28)** — every function below has a plasma-regime tag
//! in its doc comment: `sleep`, `wake`, `sample`, `infer`, `modulate`.
//! Any new function must declare which regime it belongs to or it will
//! fail code review. See the plan document §3 wake-cycle table.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]
#![warn(missing_docs)]

use nanobyte_core::{Classification, MoteFrame, MoteId};

/// Mote wake-cycle state machine. Each variant is a plasma regime per P28.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MoteState {
    /// Capacitor charging from PV. ~0.01 μW drain. No code executing.
    Sleep,
    /// Triple-redundant flash decode and clock setup. ~5 μJ, ~80 μs budget.
    Wake,
    /// ADC + thermistor + hall read. ~2 μJ, ~200 μs budget.
    Sample,
    /// 1-bit BNN inference over the sampled window. ~8 μJ, ~400 μs budget.
    Infer,
    /// Drive MEMS mirror in kHz-modulated chirp carrying class + id.
    /// ~4 μJ, ~2 ms budget. Includes mandatory heartbeat per P30.
    Modulate,
}

/// The per-mote persistent identity + tiny bit of non-volatile state.
/// Lives in the NOR flash boot sector; read at every Wake, written
/// only at ground-commanded reflash events.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MoteIdentity {
    /// This mote's id. Assigned at cassette packing time.
    pub id: MoteId,
    /// Monotonic sequence counter. Persists across sleeps. Wraps at u16::MAX.
    pub seq: u16,
    /// BNN weight bank version. Lets the mothership validate that a mote
    /// is running the expected classifier before trusting its telemetry.
    pub bnn_version: u8,
}

/// Sampled sensor reading for one interrogation cycle.
///
/// Kept as an owned, copyable struct — no heap, no slices, no lifetimes.
/// Fits in 12 bytes on rv32imc; the whole thing lives in SRAM for the
/// duration of one Sample → Infer → Modulate loop and is discarded.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SensorSample {
    /// 4-pixel photodiode array output, ADC counts. UV + NIR blocking filters.
    pub photodiode: [u16; 4],
    /// Thermistor reading, centi-degrees Celsius.
    pub temp_c100: i16,
    /// Hall-probe reading, signed integer proportional to flux density.
    pub hall: i16,
    /// Capacitor voltage at sample time, millivolts / 10.
    pub cap_mv_over_10: u8,
}

/// The 1-bit BNN classifier. Block 0.0 ships a trivial implementation
/// (always returns `Null`) so higher-level integration tests can run.
/// Block 0.2 replaces this with real weights trained on LIBS-afterglow
/// simulant data in `nanobyte-sim`.
pub trait Classifier {
    /// **Regime: infer.** Must complete within 400 μs on a 25 MHz rv32imc.
    /// Any impl that cannot prove this statically is disqualified — see P28.
    fn classify(&self, sample: &SensorSample) -> Classification;
}

/// Block 0.0 placeholder classifier. Always returns `Null` — which doubles
/// as the mandatory heartbeat per P30, so a mote running this exact binary
/// is indistinguishable from a correctly-sensing mote finding nothing.
#[derive(Copy, Clone, Debug, Default)]
pub struct NullClassifier;

impl Classifier for NullClassifier {
    fn classify(&self, _sample: &SensorSample) -> Classification {
        Classification::Null
    }
}

/// Compose a `MoteFrame` from an identity, a sample, and a classification.
/// Called at the end of Infer, consumed by Modulate.
///
/// **Regime: infer (tail)**. Zero allocation. Pure function.
pub fn build_frame(
    identity: &MoteIdentity,
    sample: &SensorSample,
    class: Classification,
) -> MoteFrame {
    MoteFrame {
        mote: identity.id,
        seq: identity.seq,
        class,
        // Confidence on Block 0.0 is a fixed placeholder; real confidence
        // derives from the BNN's signed output margin once we ship weights.
        confidence: 0,
        cap_mv_over_10: sample.cap_mv_over_10,
        temp_c100: sample.temp_c100,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_sample() -> SensorSample {
        SensorSample {
            photodiode: [0, 0, 0, 0],
            temp_c100: 2000,
            hall: 0,
            cap_mv_over_10: 33,
        }
    }

    #[test]
    fn null_classifier_always_heartbeat() {
        let c = NullClassifier;
        assert_eq!(c.classify(&fixture_sample()), Classification::Null);
    }

    #[test]
    fn frame_carries_identity_and_sample_housekeeping() {
        let id = MoteIdentity {
            id: MoteId(0x0000_0001),
            seq: 7,
            bnn_version: 0,
        };
        let s = fixture_sample();
        let f = build_frame(&id, &s, Classification::Platinum);
        assert_eq!(f.mote, id.id);
        assert_eq!(f.seq, 7);
        assert_eq!(f.class, Classification::Platinum);
        assert_eq!(f.cap_mv_over_10, 33);
        assert_eq!(f.temp_c100, 2000);
    }
}
