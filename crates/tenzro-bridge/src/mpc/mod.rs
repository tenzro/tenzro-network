//! # MPC threshold-ECDSA bridge signer
//!
//! DKLS23 t-of-n threshold signing wiring for `EvmTransactionSigner`. Replaces
//! the single-key bridge signer (`SealedSecp256k1Key`) with a distributed
//! signing committee whose individual share holders never reconstruct the full
//! private scalar.
//!
//! ## Module layout
//!
//! - [`setup`] — `InstanceId` domain-separated session identifier and parameter
//!   bundle (`MpcParameters`) used by every protocol round.
//! - [`keygen`] — DKG session adapter producing per-party `KeyshareEnvelope`
//!   records, sealed and persisted via [`store`].
//! - [`sealing`] — TEE-rooted HKDF + AES-256-GCM envelope used to seal
//!   serialized DKLS23 `Party<C>` payloads before write-through.
//! - [`sign`] — distributed signing session driver producing a recoverable
//!   secp256k1 signature ready for EVM transaction submission.
//! - [`refresh`] — per-epoch proactive share refresh (`ReKey` + `Refresh`).
//! - [`committee`] — committee selection adapted from
//!   `tenzro_training::committee::select_witness_committee`.
//! - [`abort`] — `MpcAbortEvidence` quorum-required evidence packets for the
//!   identifiable-abort → slashing pipeline.
//! - [`store`] — TEE-sealed keyshare storage abstraction
//!   (`CF_MPC_KEYSHARES`).
//! - [`transport`] — round-message abstraction (`MpcRoundMessage` +
//!   `Transport` trait).
//! - [`libp2p_relay`] — `Transport` implementation bound to the libp2p
//!   request-response + gossipsub `tenzro/mpc/v1` protocols.
//!
//! ## Status
//!
//! Task #16 (this file): module tree scaffolding + cross-module data types.
//! Behavior wiring lands incrementally in tasks #17–#22.

pub mod abort;
pub mod committee;
pub mod keygen;
pub mod libp2p_relay;
pub mod pkr_scheduler;
pub mod presign;
pub mod refresh;
pub mod sealing;
pub mod setup;
pub mod sign;
pub mod store;
pub mod transport;

pub use pkr_scheduler::{
    PkrCadence, PkrScheduler, PkrSchedulerSnapshot, RotationReason, RotationTrigger,
};
pub use presign::{
    PresignPool, PresignPoolConfig, PresignPoolStats, PresignTuple, SharedPresignPool,
};
