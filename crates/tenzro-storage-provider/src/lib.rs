//! Decentralized storage provider for Tenzro Network.
//!
//! This crate turns the content-addressed iroh transport (`tenzro-iroh`) into a
//! paid, fault-tolerant storage service with four cooperating layers:
//!
//! - [`provider`] (D1) — the provider daemon: accept an object, erasure-encode
//!   it, publish the shards over iroh, and serve the object back on request.
//! - [`por`] (D2) — proof of retrievability: random nonce-based spot-check
//!   challenges proving a provider still holds the shards it was paid for.
//! - [`redundancy`] (D3) — systematic Reed-Solomon erasure coding (and its
//!   `k = 1` replication degenerate case) so an object survives the loss of up
//!   to `m` shards.
//! - [`metering`] (D4) — per-byte pricing and per-epoch streaming payment,
//!   gated on passing the retrievability challenge each epoch.
//! - [`placement`] — rendezvous (HRW) hashing so shards self-select onto
//!   multiple independent providers with no coordinator.
//!
//! # Economic model
//!
//! Storage is billed like rental (TOKENOMICS §9): a renter pre-funds a deposit,
//! each epoch's slice (`size_bytes × rate`) streams to the provider only when a
//! retrievability challenge passes, and repeated misses terminate the deal and
//! return the renter's unearned funds. Provider stake (held by the staking
//! subsystem) collateralizes the obligation; this crate moves deposit value and
//! signals misses, but does not own slashing policy.

#![deny(missing_docs)]

pub mod error;
pub mod metering;
pub mod placement;
pub mod por;
pub mod provider;
pub mod redundancy;

pub use error::{Result, StorageProviderError};
pub use placement::{
    hrw_score, select_holders, select_tiered_holders, should_replicate, should_replicate_tiered,
    MemberReachability, TieredCandidate, TieredHolders,
};
pub use metering::{
    ChargeOutcome, StorageDeal, StorageDealStatus, StorageMeter, StoragePricing,
};
pub use por::{
    answer_challenge, challenge_digest, new_challenge, verify_challenge, Challenge,
    ChallengeResponse,
};
pub use provider::{ObjectDescriptor, ShardRef, StorageProvider};
pub use redundancy::{encode, reconstruct, RedundancyScheme, Shard};
