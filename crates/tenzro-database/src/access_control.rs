//! Access control for served databases.
//!
//! Every database carries an [`AccessPolicy`] that declares who may read and
//! administer it, across all three placement tiers — a database served on the
//! local machine, across a LAN segment, or sharded across the network is gated
//! the same way. The policy and its confidential-seal companion are shared with
//! the file-storage tier so both surfaces gate reads and writes identically; the
//! definitions live in `tenzro-types` and are re-exported here.
//!
//! This layer is auth-primitive-agnostic: it stores the policy; adjudication is
//! a node-layer concern that links `tenzro-auth` and matches the caller's
//! capability against the policy before touching the engine.
//!
//! Two layers, composable:
//!
//! 1. [`AccessPolicy`] — the default gate for every tier (public, owner-only, an
//!    explicit DID allow-list, or a capability the caller must present) plus the
//!    AAP action strings a node adjudicates against.
//! 2. [`ConfidentialSeal`] — an opt-in second layer for the network tier. When
//!    present the on-holder bytes are ciphertext; the data key is wrapped once
//!    per authorized DID. Wrapping and unwrapping happen in the node/client
//!    layer that links the crypto; this layer only records the envelopes.

pub use tenzro_types::access_policy::{
    AccessPolicy, ConfidentialSeal, WrappedDataKey, DEFAULT_READ_ACTION, DEFAULT_WRITE_ACTION,
    WRAP_ALG,
};
