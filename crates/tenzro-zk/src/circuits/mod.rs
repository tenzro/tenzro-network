//! The statements Tenzro proves.
//!
//! [`preimage`] holds the one AIR both circuits use in the Plonky3 systems: a
//! SHA3-256 preimage statement under a per-circuit domain label, evaluated
//! with an in-circuit Keccak-f permutation. The AIR is field-generic, which
//! is what lets the same statement be proven in both Plonky3 systems; the
//! Halo2 system proves the same statement with its own circuit
//! ([`crate::halo2`]).

pub mod preimage;

pub use preimage::{Circuit, PreimageAir};
