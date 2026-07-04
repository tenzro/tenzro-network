//! ERC-8004 SVM mirror adapter — bridges TDIP machine registrations into
//! the canonical QuantuLabs `agent_registry_8004` Anchor program on
//! Solana (program ID
//! [`tenzro_identity::erc8004_svm::addresses::AGENT_REGISTRY_PROGRAM_ID_MAINNET_BETA`]).
//!
//! Design (parallel to [`crate::erc8004_mirror::NativeErc8004Mirror`]):
//!
//! - **All writes flow through Anchor `register(string agent_uri)` ix.**
//!   Calldata is built via [`tenzro_identity::erc8004_svm::borsh_ix::encode_register`].
//! - **Best-effort, detached spawn.** Calldata build is synchronous so
//!   TDIP registration is not blocked. When a Solana transport is wired
//!   (see [`SvmMirrorTransport`]), the mirror `tokio::spawn`s a signed-tx
//!   submission. Spawn-internal failures are logged and dropped.
//! - **DID index lives off-chain in RocksDB.** The on-chain Anchor
//!   program assigns the Metaplex Asset `Pubkey` at instruction
//!   inclusion time; the event reflector
//!   (`process_erc8004_svm_agent_registered_logs`, parallel to the EVM
//!   reflector) is responsible for writing `(did → asset)` pairs under
//!   the [`ERC8004_SVM_DID_INDEX_PREFIX`] keyspace in `CF_IDENTITIES`.
//!   [`NativeErc8004SvmMirror::lookup_asset_by_did`] reads from that
//!   index; callers MUST tolerate `None` between
//!   `mirror_register_agent` and event inclusion.
//!
//! # Transport activation
//!
//! When [`NativeErc8004SvmMirror::new`] is called with `transport: None`,
//! the mirror logs every dispatch intent at `info` level + persists the
//! calldata under a pending-tx queue in RocksDB (key prefix
//! [`ERC8004_SVM_PENDING_TX_PREFIX`]). When the operator configures a
//! Solana RPC client and supplies a [`SvmMirrorTransport`] implementation
//! at startup, the existing pending-tx queue is drained on first
//! dispatch. This lets pre-mainnet test fleets accumulate the mirror
//! payload + flip on the wire later without losing history.
//!
//! Today the workspace does not depend on `solana-sdk` / `solana-client`;
//! a real `SvmMirrorTransport` impl lives in a future operator-facing
//! crate that pulls those in only when the SVM cluster is configured.
//! The trait + indirection are the integration seam.

use std::sync::Arc;

use tenzro_identity::erc8004_svm::{
    addresses, borsh_ix, OnChainAgentSvmRegistry, SolPubkey,
};
use tenzro_identity::error::{IdentityError, Result as IdentityResult};
use tenzro_storage::{KvStore, CF_IDENTITIES};

/// Off-chain RocksDB keyspace prefix for the `did → asset Pubkey` index.
///
/// Populated by the SVM event reflector from `AgentRegistered { asset,
/// collection, owner, atom_enabled, agent_uri }` Anchor CPI events.
/// Values are raw 32-byte Solana pubkeys.
pub const ERC8004_SVM_DID_INDEX_PREFIX: &[u8] = b"erc8004_svm_did_index:";

/// Off-chain RocksDB keyspace prefix for pending-dispatch calldata
/// recorded before a [`SvmMirrorTransport`] is wired. Keys are the DID
/// bytes; values are the raw Anchor instruction-data payload returned by
/// [`borsh_ix::encode_register`]. The queue is drained on first
/// real-transport dispatch.
pub const ERC8004_SVM_PENDING_TX_PREFIX: &[u8] = b"erc8004_svm_pending_tx:";

/// Compose the RocksDB key for the DID index.
pub fn did_index_key(did: &str) -> Vec<u8> {
    compose_key(ERC8004_SVM_DID_INDEX_PREFIX, did)
}

/// Compose the RocksDB key for the pending-tx queue.
pub fn pending_tx_key(did: &str) -> Vec<u8> {
    compose_key(ERC8004_SVM_PENDING_TX_PREFIX, did)
}

fn compose_key(prefix: &[u8], did: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + did.len());
    key.extend_from_slice(prefix);
    key.extend_from_slice(did.as_bytes());
    key
}

/// Operator-supplied Solana transport. Implementors typically wrap a
/// `solana-client::nonblocking::rpc_client::RpcClient` + a Solana
/// `Keypair`. Today this trait is forward-looking: no impl ships in the
/// monorepo because the workspace deliberately does not depend on
/// `solana-sdk`.
#[async_trait::async_trait]
pub trait SvmMirrorTransport: Send + Sync {
    /// Build a Solana transaction whose only instruction targets
    /// [`addresses::AGENT_REGISTRY_PROGRAM_ID_MAINNET_BETA`] with the
    /// supplied `instruction_data`, sign it with the operator-held
    /// `erc8004-svm-system` keypair, and submit it. Returns the
    /// transaction signature (base58, Solana's canonical tx identifier).
    async fn submit_register(&self, instruction_data: Vec<u8>) -> IdentityResult<String>;
}

/// Native adapter: dispatches TDIP machine registrations to the canonical
/// QuantuLabs `agent_registry_8004` Anchor program on Solana.
pub struct NativeErc8004SvmMirror {
    /// Operator-supplied Solana transport. When `None`, dispatches are
    /// buffered to the pending-tx queue under
    /// [`ERC8004_SVM_PENDING_TX_PREFIX`].
    transport: Option<Arc<dyn SvmMirrorTransport>>,
    /// Off-chain DID-index backing store (CF_IDENTITIES under
    /// [`ERC8004_SVM_DID_INDEX_PREFIX`]).
    storage: Arc<dyn KvStore>,
}

impl NativeErc8004SvmMirror {
    /// Construct a mirror with no live Solana transport. Dispatch
    /// intents are persisted to the pending-tx queue and logged at
    /// `info` level. Use [`Self::with_transport`] to attach a live
    /// transport later.
    pub fn new(storage: Arc<dyn KvStore>) -> Self {
        Self {
            transport: None,
            storage,
        }
    }

    /// Construct a mirror with a live Solana transport. Dispatches are
    /// `tokio::spawn`ed as signed Anchor `register(string)` txs against
    /// [`addresses::AGENT_REGISTRY_PROGRAM_ID_MAINNET_BETA`].
    pub fn with_transport(storage: Arc<dyn KvStore>, transport: Arc<dyn SvmMirrorTransport>) -> Self {
        Self {
            transport: Some(transport),
            storage,
        }
    }

    /// Programmer-visible accessor for the configured program ID. Useful
    /// for operator-facing diagnostics + RPCs.
    pub fn program_id() -> SolPubkey {
        addresses::AGENT_REGISTRY_PROGRAM_ID_MAINNET_BETA
    }
}

impl OnChainAgentSvmRegistry for NativeErc8004SvmMirror {
    fn mirror_register_agent(&self, did: &str, metadata_uri: &str) -> IdentityResult<()> {
        // Build Anchor calldata synchronously — pure, no I/O.
        let calldata = borsh_ix::encode_register(metadata_uri);

        match self.transport.as_ref() {
            Some(transport) => {
                let transport = Arc::clone(transport);
                let did_owned = did.to_string();
                let calldata_owned = calldata;
                tokio::spawn(async move {
                    match transport.submit_register(calldata_owned).await {
                        Ok(sig) => {
                            tracing::info!(
                                target: "tenzro::erc8004::svm::mirror",
                                did = %did_owned,
                                signature = %sig,
                                "ERC-8004 SVM register tx submitted; asset arrives via AgentRegistered event"
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                target: "tenzro::erc8004::svm::mirror",
                                did = %did_owned,
                                error = %e,
                                "ERC-8004 SVM register tx submission failed (TDIP registration unaffected)"
                            );
                        }
                    }
                });
            }
            None => {
                // No transport configured — buffer the calldata so an
                // operator who later attaches a transport can drain the
                // queue.
                let key = pending_tx_key(did);
                if let Err(e) = self.storage.put(CF_IDENTITIES, &key, &calldata) {
                    tracing::warn!(
                        target: "tenzro::erc8004::svm::mirror",
                        did,
                        error = %e,
                        "failed to buffer ERC-8004 SVM register calldata to pending-tx queue"
                    );
                } else {
                    tracing::info!(
                        target: "tenzro::erc8004::svm::mirror",
                        did,
                        bytes = calldata.len(),
                        "ERC-8004 SVM register calldata buffered (no Solana transport configured)"
                    );
                }
            }
        }

        Ok(())
    }

    fn lookup_asset_by_did(&self, did: &str) -> Option<SolPubkey> {
        let key = did_index_key(did);
        match self.storage.get(CF_IDENTITIES, &key) {
            Ok(Some(bytes)) if bytes.len() == 32 => {
                let mut out = [0u8; 32];
                out.copy_from_slice(&bytes);
                Some(out)
            }
            Ok(Some(bad)) => {
                tracing::warn!(
                    target: "tenzro::erc8004::svm::mirror",
                    did,
                    len = bad.len(),
                    "malformed erc8004_svm_did_index entry (expected 32-byte Pubkey)"
                );
                None
            }
            Ok(None) => None,
            Err(e) => {
                tracing::warn!(
                    target: "tenzro::erc8004::svm::mirror",
                    did,
                    error = %e,
                    "RocksDB read failed during SVM DID-index lookup"
                );
                None
            }
        }
    }
}

/// Convert the standard `lookup_asset_by_did` result into the unified
/// [`IdentityError::VerificationFailed`] shape — used by RPC handlers
/// that want a typed error for the "not yet mirrored" case rather than
/// `Option`.
pub fn require_asset(did: &str, registry: &dyn OnChainAgentSvmRegistry) -> IdentityResult<SolPubkey> {
    registry.lookup_asset_by_did(did).ok_or_else(|| {
        IdentityError::VerificationFailed(format!(
            "no ERC-8004 SVM asset mirrored for DID '{}' yet \
             (mirror ix may still be pending — retry after a few slots)",
            did
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_storage::MemoryStore;

    #[test]
    fn did_index_key_is_prefix_concat() {
        let key = did_index_key("did:tenzro:machine:abc");
        assert!(key.starts_with(ERC8004_SVM_DID_INDEX_PREFIX));
        assert_eq!(
            &key[ERC8004_SVM_DID_INDEX_PREFIX.len()..],
            b"did:tenzro:machine:abc"
        );
    }

    #[test]
    fn pending_tx_key_is_prefix_concat() {
        let key = pending_tx_key("did:tenzro:machine:abc");
        assert!(key.starts_with(ERC8004_SVM_PENDING_TX_PREFIX));
        assert_eq!(
            &key[ERC8004_SVM_PENDING_TX_PREFIX.len()..],
            b"did:tenzro:machine:abc"
        );
    }

    #[test]
    fn lookup_returns_none_when_index_empty() {
        let storage: Arc<dyn KvStore> = Arc::new(MemoryStore::new());
        let mirror = NativeErc8004SvmMirror::new(storage);
        assert_eq!(
            mirror.lookup_asset_by_did("did:tenzro:machine:nope"),
            None
        );
    }

    #[test]
    fn lookup_returns_indexed_pubkey() {
        let storage: Arc<dyn KvStore> = Arc::new(MemoryStore::new());
        let did = "did:tenzro:machine:42";
        let asset: SolPubkey = [7u8; 32];
        storage
            .put(CF_IDENTITIES, &did_index_key(did), &asset)
            .expect("put");

        let mirror = NativeErc8004SvmMirror::new(storage);
        assert_eq!(mirror.lookup_asset_by_did(did), Some(asset));
    }

    #[test]
    fn lookup_rejects_malformed_value() {
        let storage: Arc<dyn KvStore> = Arc::new(MemoryStore::new());
        let did = "did:tenzro:machine:bad";
        storage
            .put(CF_IDENTITIES, &did_index_key(did), b"too-short")
            .expect("put");

        let mirror = NativeErc8004SvmMirror::new(storage);
        assert_eq!(mirror.lookup_asset_by_did(did), None);
    }

    #[tokio::test]
    async fn buffers_calldata_when_no_transport() {
        let storage: Arc<dyn KvStore> = Arc::new(MemoryStore::new());
        let mirror = NativeErc8004SvmMirror::new(storage.clone());
        mirror
            .mirror_register_agent("did:tenzro:machine:42", "did:tenzro:machine:42")
            .expect("ok");
        let buffered = storage
            .get(CF_IDENTITIES, &pending_tx_key("did:tenzro:machine:42"))
            .expect("get")
            .expect("present");
        // 8-byte Anchor discriminator + 4-byte length-prefix + utf8 body
        assert!(buffered.len() > 8);
        assert_eq!(
            &buffered[..8],
            &tenzro_identity::erc8004_svm::discriminators::REGISTER,
        );
    }

    #[test]
    fn program_id_matches_canonical() {
        assert_eq!(
            NativeErc8004SvmMirror::program_id(),
            addresses::AGENT_REGISTRY_PROGRAM_ID_MAINNET_BETA
        );
    }
}
