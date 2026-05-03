//! Pre-built circuits for Tenzro Network operations.
//!
//! [`airs`] holds the Plonky3 STARK AIRs — the current and only circuit
//! definitions.

pub mod airs;

pub use airs::{
    InferenceAir, IdentityAir, SettlementAir,
    NUM_INFERENCE_COLS, NUM_INFERENCE_PUBLIC_VALUES,
    NUM_IDENTITY_COLS, NUM_IDENTITY_PUBLIC_VALUES,
    NUM_SETTLEMENT_COLS, NUM_SETTLEMENT_PUBLIC_VALUES,
    generate_inference_trace, inference_public_inputs,
    generate_identity_trace, identity_public_inputs,
    generate_settlement_trace, settlement_public_inputs,
};
