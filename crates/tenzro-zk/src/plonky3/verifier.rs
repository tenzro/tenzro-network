//! Plonky3 STARK verifier — wraps `p3_uni_stark::verify`.
//!
//! Mirrors [`Plonky3Prover`](super::prover::Plonky3Prover) but on the verify
//! side: each Tenzro circuit instantiates its AIR, recovers the public values
//! from the wire-encoded proof, and calls [`Plonky3Verifier::verify_air`].
//!
//! The verifier owns its own [`TenzroStarkConfig`] — Plonky3 configs are
//! cheap to construct (just Poseidon2 round constants and FRI parameters), so
//! we don't share between prover and verifier. This keeps the verifier
//! independently audit-able and means a node that only verifies (doesn't
//! prove) carries no proving-side state.

use core::marker::PhantomData;

use p3_air::Air;
use p3_uni_stark::{
    Proof as P3Proof, SymbolicAirBuilder, VerificationError, VerifierConstraintFolder, verify,
};

use super::config::{Pcs, TenzroStarkConfig, Val, build_testnet_config};
use p3_commit::Pcs as PcsTrait;

/// Error returned when STARK verification fails.
pub type Plonky3VerificationError = VerificationError<<Pcs as PcsTrait<
    super::config::Challenge,
    super::config::Challenger,
>>::Error>;

/// A STARK verifier bound to a specific AIR.
pub struct Plonky3Verifier<A> {
    config: TenzroStarkConfig,
    _air: PhantomData<A>,
}

impl<A> Default for Plonky3Verifier<A> {
    fn default() -> Self {
        Self::new()
    }
}

impl<A> Plonky3Verifier<A> {
    /// Construct a verifier with the pinned testnet config.
    pub fn new() -> Self {
        Self {
            config: build_testnet_config(),
            _air: PhantomData,
        }
    }

    /// Borrow the underlying [`TenzroStarkConfig`].
    pub fn config(&self) -> &TenzroStarkConfig {
        &self.config
    }
}

impl<A> Plonky3Verifier<A>
where
    A: Air<SymbolicAirBuilder<Val>>
        + for<'a> Air<VerifierConstraintFolder<'a, TenzroStarkConfig>>,
{
    /// Verify a STARK `proof` for `air` against the claimed `public_values`.
    pub fn verify_air(
        &self,
        air: &A,
        proof: &P3Proof<TenzroStarkConfig>,
        public_values: &[Val],
    ) -> Result<(), Plonky3VerificationError> {
        verify(&self.config, air, proof, public_values)
    }
}
