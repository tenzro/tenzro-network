//! Pre-built circuits for Tenzro Network operations.
//!
//! [`airs`] holds the Plonky3 STARK AIRs — the current and only circuit
//! definitions.

pub mod airs;

pub use airs::{
    IdentityAir, InferenceAir, NUM_IDENTITY_COLS, NUM_IDENTITY_PUBLIC_VALUES, NUM_INFERENCE_COLS,
    NUM_INFERENCE_PUBLIC_VALUES, NUM_SETTLEMENT_COLS, NUM_SETTLEMENT_PUBLIC_VALUES,
    PqQcAggregationAir, SettlementAir, cols_for as pq_qc_cols_for, generate_identity_trace,
    generate_inference_trace, generate_pq_qc_trace, generate_settlement_trace,
    identity_public_inputs, inference_public_inputs, message_digest as pq_qc_message_digest,
    pq_qc_public_inputs, public_values_for as pq_qc_public_values_for, settlement_public_inputs,
};
