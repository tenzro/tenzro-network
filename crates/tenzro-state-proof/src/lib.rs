//! The state trie's hash rules and the verifier of state proofs.
//!
//! Everything here is a pure function over bytes: no storage, no I/O. The
//! trie that builds proofs and a light client that only checks them use the
//! same code, so they agree by construction.

pub mod hashing;
pub mod proof;

pub use proof::{ProofError, ProofTerminal, StateProof, verify_state_proof};
