//! Pre-built circuits for Tenzro Network operations.
//!
//! [`airs`] holds the Plonky3 STARK AIRs — the current and only circuit
//! definitions.

pub mod airs;

pub use airs::{
    InferenceAir, IdentityAir, PqQcAggregationAir, SettlementAir,
    NUM_INFERENCE_COLS, NUM_INFERENCE_PUBLIC_VALUES,
    NUM_IDENTITY_COLS, NUM_IDENTITY_PUBLIC_VALUES,
    NUM_SETTLEMENT_COLS, NUM_SETTLEMENT_PUBLIC_VALUES,
    cols_for as pq_qc_cols_for, generate_inference_trace, inference_public_inputs,
    generate_identity_trace, identity_public_inputs,
    generate_pq_qc_trace, message_digest as pq_qc_message_digest,
    pq_qc_public_inputs, public_values_for as pq_qc_public_values_for,
    generate_settlement_trace, settlement_public_inputs,
};
