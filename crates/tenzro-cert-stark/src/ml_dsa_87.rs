//! Compact certificates over ML-DSA-87 session keys: the verifier layout
//! ([`mldsa`]), its lattice arithmetic tables ([`arith`]) and the proof
//! ([`compact`]), instantiated for the ML-DSA-87 parameter set.

/// The ML-DSA-87 parameters (FIPS 204, Table 1).
pub mod params {
    /// Rows of the key matrix.
    pub const K: usize = 8;
    /// Columns of the key matrix.
    pub const L: usize = 7;
    /// Nonzero coefficients of the challenge.
    pub const TAU: usize = 60;
    /// `tau * eta`.
    pub const BETA: i32 = 120;
    /// Largest number of hint bits.
    pub const OMEGA: usize = 75;
    /// Length of the challenge seed `c~`.
    pub const C_TILDE_BYTES: usize = 64;
    /// Domain of the digest of a committee's keys a proof is bound to.
    pub const KEYS_DOMAIN: &[u8] = b"tenzro/compact-certificate/keys/ml-dsa-87";
    /// The composite label session signatures of this parameter set carry
    /// as their ML-DSA context.
    pub const LABEL: &[u8] = b"COMPSIG-MLDSA87-ECDSA-P384-SHA512";
    /// The parameter set, as the `ml-dsa` crate names it.
    #[cfg(test)]
    pub type MlDsa = ml_dsa::MlDsa87;
}

// Each parameter set compiles its own copy of these files against its own
// `params`, so loading them from both modules is the point.
#[allow(clippy::duplicate_mod)]
#[path = "mldsa.rs"]
pub mod mldsa;

#[allow(clippy::duplicate_mod)]
#[path = "arith.rs"]
pub mod arith;

#[allow(clippy::duplicate_mod)]
#[path = "compact.rs"]
pub mod compact;
