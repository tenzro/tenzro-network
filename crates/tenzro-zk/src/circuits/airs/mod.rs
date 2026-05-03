//! Plonky3 STARK AIRs for Tenzro circuits.
//!
//! Each module ports one of the legacy R1CS circuits in
//! [`crate::circuits`] to a [`p3_air::Air`] over the [`KoalaBear`] field.
//! Once all consumers (tenzro-vm, tenzro-settlement, tenzro-node, …) have
//! migrated to these AIRs, the legacy R1CS circuit modules will be deleted
//! per task #143.
//!
//! [`KoalaBear`]: p3_koala_bear::KoalaBear

pub mod inference;
pub mod settlement;
pub mod identity;

pub use inference::{
    InferenceAir, NUM_INFERENCE_COLS, NUM_INFERENCE_PUBLIC_VALUES,
    generate_inference_trace, inference_public_inputs,
};
pub use settlement::{
    SettlementAir, NUM_SETTLEMENT_COLS, NUM_SETTLEMENT_PUBLIC_VALUES,
    generate_settlement_trace, settlement_public_inputs,
};
pub use identity::{
    IdentityAir, NUM_IDENTITY_COLS, NUM_IDENTITY_PUBLIC_VALUES,
    generate_identity_trace, identity_public_inputs,
};
