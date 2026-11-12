//! Tenzro consensus: a signature-free DAG ordering core with post-quantum,
//! hardware-signed checkpoint certificates.
//!
//! # Layers
//!
//! 1. **Channels** ([`channel`]). Validators talk over the node's QUIC
//!    connections, each upgraded by a handshake both sides sign with their
//!    per-boot session keys ([`session`], composite ML-DSA-65 with
//!    ECDSA-P256) and keyed by a hybrid X25519 + ML-KEM-768 exchange. Every
//!    frame carries a MAC. Each boot, a validator's hardware key signs one
//!    announcement ([`announce`]) naming its endpoint and session key; peers
//!    dial and admit only that endpoint and accept only that session key.
//! 2. **Dissemination** ([`batch`]). Each validator cuts its mempool into
//!    batches and pushes them to every validator; its vertices introduce
//!    them. A validator echoes a vertex only once it holds the batches the
//!    vertex introduces, so a delivered vertex's batches can always be
//!    fetched, and a batch is ordered with the vertex that introduced it.
//! 3. **Ordering** ([`vertex`], [`rbc`], [`dag`], [`core`]). Each round,
//!    each validator reliably broadcasts one unsigned vertex referencing a
//!    quorum of the previous round. Round leaders ([`schedule`]) commit when a
//!    quorum of the next round references them; a committed leader orders its
//!    causal history into one block. Ordering is final for every honest
//!    validator while at most a third of the seats are Byzantine.
//! 4. **Checkpoints** ([`checkpoint`]). About twice a second every
//!    validator signs a checkpoint over the blocks since the last one and its
//!    executed state; a quorum of signatures is a certificate anyone can
//!    verify, and signing two checkpoints with one index is slashable. The
//!    session certificates that tie the signatures to hardware keys travel
//!    once per epoch ([`session::SessionBook`]); every minute a
//!    [`compact`] certificate replaces the quorum's ML-DSA-65 signatures with
//!    one STARK, and a [`light_client`] follows these from genesis.
//!
//! Stake enters every quorum through seats ([`committee`]).

pub mod admission;
pub mod announce;
pub mod batch;
pub mod channel;
pub mod checkpoint;
pub mod committee;
pub mod compact;
mod compact_certificate;
pub mod compact_work;
pub mod config;
pub mod core;
pub mod dag;
pub mod epoch_manager;
pub mod error;
pub mod eu_ai_act;
pub mod event_proof;
pub mod evidence_pack;
mod kem;
pub mod launch_check;
pub mod light_client;
pub mod mempool;
mod nversion;
pub mod ordering;
pub mod rbc;
pub mod recovery_manifest;
pub mod schedule;
pub mod session;
pub mod training_provenance;
pub mod validator;
pub mod validator_key;
pub mod vertex;
pub mod wire;

#[cfg(test)]
mod harness;
#[cfg(test)]
mod liveness_scenarios;

pub use admission::{
    AdmissionConfig, AdmissionController, AdmissionDecision, BucketSnapshot, DefaultLaneResolver,
    Lane, LaneResolver, LaneStats,
};
pub use batch::{BatchPayload, OrderedBatch};
pub use checkpoint::{
    Certificate, CertificateContext, Checkpoint, CheckpointEquivocation, CheckpointVote,
    FULL_BUNDLE_EVERY, KvVoteHighWater, PublishedCertificate, STATE_ROOT_LAG, VoteHighWater,
    sign_checkpoint, state_root_height,
};
pub use committee::{Committee, Member, ValidatorIndex};
pub use config::{ConsensusConfig, TimeRules};
pub use core::{
    Core, CoreConfig, CoreSizes, CoreStats, EpochStart, Event, Record, Segment, Target,
};
pub use epoch_manager::{Epoch, EpochManager, EpochStateStore, EpochStats};
pub use error::{ConsensusError, Result};
pub use mempool::{Mempool, MempoolStats, SenderRegistry, is_registration_path};
pub use ordering::{OrderingState, Resumed};
pub use rbc::RbcStats;
pub use session::{SessionBook, SessionCertificate};
pub use validator::{ValidatorInfo, ValidatorSet, ValidatorStatus};
pub use validator_key::{CompositeSignature, ValidatorPublicKey, ValidatorSigner};
pub use wire::{Frame, Frontier, Message};
