//! Decentralized storage provider for Tenzro Network.
//!
//! This crate turns the content-addressed iroh transport (`tenzro-iroh`) into a
//! paid, fault-tolerant storage service with four cooperating layers:
//!
//! - [`provider`] — the provider daemon: accept an object, erasure-encode
//!   it, publish the shards over iroh, and serve the object back on request.
//! - [`pdp`] — provable data possession: nonce-selected chunk samples,
//!   each answered with the chunk and its Merkle path against a per-shard root
//!   committed at store time. Proofs are a few kilobytes whatever the object
//!   size, and the verifier never downloads a shard.
//! - [`redundancy`] — systematic Reed-Solomon erasure coding (and its
//!   `k = 1` replication degenerate case) so an object survives the loss of up
//!   to `m` shards.
//! - [`metering`] — per-byte pricing and per-epoch streaming payment,
//!   gated on passing the retrievability challenge each epoch.
//! - [`placement`] — rendezvous (HRW) hashing so shards self-select onto
//!   multiple independent providers with no coordinator.
//!
//! # Economic model
//!
//! A renter pays through a compute claim in consensus state that commits the
//! object's descriptor digest. The bond delivering the claim is found
//! available for an hour only while it proves possession of that object to
//! validators' probes, and the claim settles hour by hour on those verdicts.
//! This crate stores, proves and verifies; it holds no balances.

#![deny(missing_docs)]

pub mod error;
pub mod pdp;
pub mod placement;
pub mod provider;
pub mod redundancy;

pub use error::{Result, StorageProviderError};
pub use pdp::{PdpChallenge, PdpItem, PdpProof, new_pdp_challenge, prove, verify};
pub use placement::{
    MemberReachability, TieredCandidate, TieredHolders, hrw_score, select_holders,
    select_tiered_holders, should_replicate, should_replicate_tiered,
};
pub use provider::{ObjectDescriptor, ShardRef, StorageProvider};
pub use redundancy::{RedundancyScheme, Shard, encode, reconstruct};
