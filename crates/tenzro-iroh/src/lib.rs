//! Iroh integration for Tenzro Network.
//!
//! This crate is the bridge between Tenzro's `tenzro://` URI scheme
//! (defined in `tenzro_types::tenzro_uri`) and the [iroh](https://iroh.computer)
//! QUIC-native content-addressed transport (Apache-2.0,
//! <https://github.com/n0-computer/iroh>).
//!
//! # Architecture
//!
//! ```text
//!  RPC / CLI / MCP / A2A handlers
//!         |
//!         v
//!  tenzro_uri::TenzroUri  (parsed URI)
//!         |
//!         v
//!  IrohResolver::dispatch(uri) ──► iroh-blobs   (Blob / Model / Gradient /
//!                                                Shard / Memory / Receipt)
//!                              ──► iroh-docs    (Manifest)
//!                              ──► iroh::Endpoint (Node / Did)
//! ```
//!
//! # Phase A2 scope (current)
//!
//! - `IrohResolver` trait — the dispatch surface that crates depend on
//!   without pulling in the iroh runtime.
//! - `IrohBackedResolver` — concrete implementation wrapping an
//!   `iroh::Endpoint` + `iroh_blobs::store::mem::MemStore` + the
//!   `BlobsProtocol` router. Handles `tenzro://blob/...` (and the other
//!   content-addressed variants that map to a single BLAKE3 hash).
//! - `IrohBlobsDaBackend` — adapter that satisfies
//!   `tenzro_storage::da::DaBackend` over the same resolver, so offloaded
//!   receipts (inference, agent-message, channel-update) flow through
//!   iroh-blobs instead of the inline fallback. Registered by `tenzro-node`
//!   under `DaBackendId::IrohBlobs`.
//! - `TenzroIrohConfig` — configuration struct used by `tenzro-node` to
//!   construct the resolver.
//! - Error type that bridges `tenzro_types::tenzro_uri::TenzroUriError`
//!   into the iroh-side resolution errors.
//!
//! # Out of scope (later phases)
//!
//! - Filesystem-backed blob store (`FsStore::load(path)`) — wired when
//!   the node config grows a persistence flag. Phase A2 ships the
//!   in-memory variant first so the receipt-offload path is exercisable
//!   in tests and on validators that re-derive their receipt cache.
//! - `tenzro://manifest/...` was originally penciled in as an iroh-docs
//!   surface. Phase B2 (#217) replaced that with sponsor-DID-signed
//!   `SealedDatasetManifest` distribution on the `tenzro/training`
//!   gossipsub topic + per-shard ciphertext fetch over iroh-blobs (see
//!   [`IrohSealedShardStore`]) — see the `IrohSealedShardStore` rustdoc
//!   for the "why no iroh-docs" rationale.
//! - `tenzro://node/...` and `tenzro://did/...` dialing — separate
//!   surface in the libp2p ↔ iroh discovery bridge (Phase C1, #219).
//!
//! # Phase C2 (#220) — TDIP-anchored Pkarr discovery
//!
//! [`IrohBackedResolver::bind_with_config`] accepts a [`TenzroIrohConfig`]
//! with a `pkarr_relay_url` (Tenzro-operated relay, e.g.
//! `https://pkarr.tenzro.network/pkarr`) and a `secret_key_seed` (the
//! node's TDIP Ed25519 seed). The resulting iroh `EndpointId` is
//! byte-identical to the node's TDIP public key, and Pkarr addressing
//! records are published to the Tenzro relay — anchoring discovery to
//! the on-chain DID without an extra attestation layer. See
//! [`tdip::derive_iroh_secret_key_from_ed25519`] for the seam.

#![deny(missing_docs)]

pub mod config;
pub mod da_backend;
pub mod error;
pub mod gradient_store;
pub mod jsonrpc;
pub mod resolver;
pub mod sealed_shard_store;
pub mod tdip;

pub use config::TenzroIrohConfig;
pub use da_backend::IrohBlobsDaBackend;
pub use error::{IrohError, IrohResult};
pub use gradient_store::IrohGradientStore;
pub use jsonrpc::{
    call as jsonrpc_call, DeferredJsonRpcDispatcher, JsonRpcDispatcher, JsonRpcProtocol, ALPN_A2A,
    ALPN_MCP,
};
pub use resolver::{IrohBackedResolver, IrohResolver};
pub use sealed_shard_store::IrohSealedShardStore;
pub use tdip::derive_iroh_secret_key_from_ed25519;

// Re-export the parsed URI type so downstream crates only need to import
// `tenzro_iroh::TenzroUri` rather than reaching into `tenzro_types`.
pub use tenzro_types::tenzro_uri::{TenzroUri, TenzroUriError};
