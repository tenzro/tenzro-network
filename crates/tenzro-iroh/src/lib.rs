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
//!  IrohResolver::dispatch(uri) ──► iroh-blobs   (Blob / Model / Receipt)
//!                              ──► iroh::Endpoint (Node / Did)
//! ```
//!
//! # Scope
//!
//! - `IrohResolver` trait — the dispatch surface that crates depend on
//!   without pulling in the iroh runtime.
//! - `IrohBackedResolver` — concrete implementation wrapping an
//!   `iroh::Endpoint` + a blob store + the `BlobsProtocol` router.
//!   Config-driven binds use a persistent redb-backed
//!   `iroh_blobs::store::fs::FsStore` under `{data_dir}/iroh/blobs` so
//!   published blobs survive restart; `bind_in_memory` keeps a `MemStore`
//!   for tests. Handles `tenzro://blob/...` (and the other
//!   content-addressed variants that map to a single BLAKE3 hash).
//!   Cross-node fetches consult the URI's provider hint first, then the
//!   provider cache fed by signed `tenzro/blobs` gossip announcements.
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
//! - `tenzro://node/...` and `tenzro://did/...` URI resolution.
//!
//! # Identity, relays and discovery
//!
//! Nodes are addressed by machine identity. The endpoint key is fresh at
//! every bind and held only in memory; the machine's hardware key certifies
//! it in a signed [`identity_record::EndpointRecord`]. Records travel on
//! Tenzro's own discovery network ([`discovery`]): every node stores,
//! verifies and answers them on the `tenzro/discovery` ALPN, and resolves
//! `EndpointId`s from them. Relaying is an operator role ([`relay`]),
//! announced by the operator's own record.
//! [`identity_transport::IdentityTransport`] admits relays by those records
//! and joins the network through any known node identity. No relay,
//! discovery service or peer is built in.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod block_sync;
pub mod config;
pub mod connection_limits;
pub mod consensus;
pub mod da_backend;
pub mod discovery;
pub mod error;
pub mod gossip;
pub mod identity_gate;
pub mod identity_record;
pub mod identity_transport;
pub mod jsonrpc;
pub mod lan_discovery;
pub mod licence_gate;
pub mod limits;
pub mod paths;
pub mod pq_endpoint;
pub mod reachability;
pub mod relay;
pub mod request;
pub mod resolver;
pub mod state_sync;
pub mod tpm_sign;
pub mod update_advert;

pub use block_sync::{
    ALPN_BLOCK_SYNC, BlockSyncServer, DeferredBlockSyncServer, block_sync_request,
};
pub use config::{EndpointSecret, TenzroIrohConfig};
pub use consensus::{
    ALPN_CONSENSUS, ConsensusStreamHandler, DeferredConsensusHandler, open_consensus_connection,
    open_consensus_stream, read_frame, read_frame_idle, write_frame,
};
pub use da_backend::IrohBlobsDaBackend;
pub use discovery::{ALPN_DISCOVERY, DiscoveryStore};
pub use error::{IrohError, IrohResult};
pub use identity_gate::{ALPN_ONBOARD, Admit, AlpnAccess, IdentityGate, RegistryView, alpn_access};
pub use identity_record::{
    BootIdentity, EndpointKey, EndpointRecord, RecordError, RecordScope, RelayRef, parse_boot_list,
};
pub use identity_transport::{IdentityTransport, RelayRoleConfig};
pub use jsonrpc::{
    ALPN_A2A, ALPN_A2A_PQ, ALPN_MCP, ALPN_MCP_PQ, ALPN_MOE, ALPN_MOE_PQ, DeferredJsonRpcDispatcher,
    DeferredMcpHandler, JsonRpcDispatcher, JsonRpcProtocol, MAX_FRAME_BYTES, McpProtocol,
    McpStreamHandler, call as jsonrpc_call,
};
pub use pq_endpoint::{MachinePqKey, PqChannel};
pub use reachability::{Connectivity, NatKind, Reachability};
pub use request::{
    ALPN_AGENT_KEY, ALPN_AGENT_TOKEN, ALPN_DA_COMMITTEE, ALPN_INFER, ALPN_KV_CHECKPOINT,
    DeferredRequestHandler, MAX_AGENT_KEY_REQUEST, MAX_INFER_BYTES, MAX_KV_CHECKPOINT_REQUEST,
    MAX_STORE_REQUEST, Reply, ReplyBody, RequestHandler, RequestProtocol, Response, request,
};
pub use resolver::{IrohBackedResolver, IrohResolver};
pub use state_sync::{
    ALPN_STATE_SYNC, DeferredSnapshotDirectory, SnapshotDirectory, merge_peers, parse_peer,
};
pub use tpm_sign::{
    ALPN_TPM_SIGN, TpmSignProtocol, TpmSignServer, endpoint_id_of, serve_tpm_sign,
    tpm_sign_request, tpm_sign_request_once,
};

// Re-export the parsed URI type so downstream crates only need to import
// `tenzro_iroh::TenzroUri` rather than reaching into `tenzro_types`.
pub use tenzro_types::tenzro_uri::{TenzroUri, TenzroUriError};

// Re-export the iroh QUIC stream halves so downstream crates that
// implement [`McpStreamHandler`] (notably `tenzro-node`) can name them
// without taking a direct dependency on `iroh`. Keeps the iroh runtime
// surface in exactly one place — this crate.
pub use iroh::endpoint::{Connection, RecvStream, SendStream};

// Re-export `EndpointId` so `tenzro-node` can parse provider-advertised
// iroh endpoint ids (e.g. MoE expert holders) and dial them via
// [`jsonrpc::call`] without a direct `iroh` dependency.
pub use iroh::{EndpointAddr, EndpointId};

// Re-export `Endpoint` so `tenzro-node`'s consensus can dial peers on the
// shared endpoint without a direct `iroh` dependency.
pub use iroh::Endpoint;
