//! A light client for Tenzro Ledger.
//!
//! It starts from a committee the caller trusts, follows the committee from
//! epoch to epoch through the handover each epoch's last checkpoint commits,
//! and accepts a checkpoint only under a certificate a quorum of the current
//! committee's seats signed. A value read from a node is then checked against
//! the state root of a certified checkpoint, so nothing a node says is taken
//! on trust. [`identity`] does that for an identity's keys;
//! [`event_proof`] checks an event against a certified checkpoint.
//!
//! The crate does no network I/O: the caller supplies the transport as one
//! JSON-RPC call ([`driver::Node`]) or hands replies in itself ([`rpc`]), so
//! one implementation serves every SDK.

pub mod client;
#[cfg(feature = "compact")]
pub mod compact;
pub mod driver;
pub mod error;
pub mod event_proof;
pub mod identity;
pub mod light_client;
pub mod rpc;
pub mod state;
#[cfg(any(test, feature = "test-support"))]
pub mod testkit;
pub mod wire;

pub use client::{Certified, Clock, Conflict, LightClient, Proof, TrustAnchor};
pub use error::{LightError, Result};
pub use identity::{ProvenIdentity, ProvenKeyHistory};
pub use state::{StateClaim, verify_state};
pub use tenzro_finality::checkpoint::{Certificate, Checkpoint};
pub use tenzro_finality::committee::Member;
pub use tenzro_finality::session::SessionCertificate;
