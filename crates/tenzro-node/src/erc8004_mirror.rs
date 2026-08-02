//! ERC-8004 mirror adapter — bridges TDIP machine registrations into the
//! canonical on-chain `IdentityRegistry` proxy at
//! [`tenzro_identity::erc8004::addresses::IDENTITY_REGISTRY`].
//!
//! Design (locked 2026-05-29 — see `project_erc8004_evm_architecture` memory):
//!
//! - **All writes flow through standard EVM transactions** against the
//!   canonical OpenZeppelin-ERC721-based proxy predeployed at genesis.
//! - **System-key signed tx, detached spawn.** The TDIP `IdentityRegistry`
//!   register path is synchronous; we cannot block on an async eth_send
//!   round-trip. [`NativeErc8004Mirror::mirror_register_agent`] builds the
//!   `register(string agentURI)` calldata, then `tokio::spawn`s an EIP-1559
//!   signed-tx submission via [`EvmTransactionSigner`] pointed at the
//!   node's own loopback JSON-RPC. Returns immediately.
//! - **DID index lives off-chain in RocksDB.** The on-chain contract has
//!   no DID concept. The event listener in
//!   [`crate::erc8004_event_listener`] subscribes to
//!   `Registered(uint256 indexed agentId, string agentURI, address indexed owner)`
//!   and writes `(did → agentId)` pairs under the `erc8004_did_index:`
//!   prefix in `CF_IDENTITIES`. [`NativeErc8004Mirror::lookup_agent_id_by_did`]
//!   reads from that index; callers MUST tolerate `None` between
//!   `mirror_register_agent` and event inclusion.
//!
//! The mirror is best-effort: a build-time error returns `Err` to the
//! caller, but spawn-internal failures (rpc unreachable, signing error,
//! revert) are logged and dropped — TDIP registration is never blocked by
//! the on-chain mirror.

use std::sync::Arc;

use tenzro_bridge::evm_signer::EvmTransactionSigner;
use tenzro_identity::erc8004::{EthAddress, OnChainAgentRegistry, abi, addresses, selectors};
use tenzro_identity::error::{IdentityError, Result as IdentityResult};
use tenzro_storage::{CF_IDENTITIES, KvStore};

/// Off-chain RocksDB keyspace prefix for the `did → agentId` index.
///
/// Populated by [`crate::erc8004_event_listener`] from
/// `Registered(uint256 indexed agentId, string agentURI, address indexed owner)`
/// events on the canonical `IdentityRegistry`. Values are 8-byte
/// big-endian `u64` agent ids.
pub const ERC8004_DID_INDEX_PREFIX: &[u8] = b"erc8004_did_index:";

/// Compose the RocksDB key for a given DID.
pub fn did_index_key(did: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(ERC8004_DID_INDEX_PREFIX.len() + did.len());
    key.extend_from_slice(ERC8004_DID_INDEX_PREFIX);
    key.extend_from_slice(did.as_bytes());
    key
}

/// Prefix for the reverse owner-address → agentId index in `CF_IDENTITIES`.
/// Populated from the `address indexed owner` topic of the same
/// `Registered` event. Lets address-keyed callers (the autonomous-agent
/// bootstrap paymaster) answer "is this smart account a registered agent?"
/// without a DID round-trip. Values are 8-byte big-endian `u64` agent ids.
pub const ERC8004_OWNER_INDEX_PREFIX: &[u8] = b"erc8004_owner_index:";

/// Compose the RocksDB key for a given owner address (20-byte EVM address).
pub fn owner_index_key(owner: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(ERC8004_OWNER_INDEX_PREFIX.len() + owner.len());
    key.extend_from_slice(ERC8004_OWNER_INDEX_PREFIX);
    key.extend_from_slice(owner);
    key
}

/// Native adapter: dispatches TDIP machine registrations to the canonical
/// on-chain ERC-8004 IdentityRegistry proxy via signed EIP-1559 transactions
/// using a node-held `erc8004-system` secp256k1 key.
pub struct NativeErc8004Mirror {
    /// EIP-1559 signer for the node's `erc8004-system` key. Loopback RPC
    /// URL (the node's own JSON-RPC server).
    signer: Arc<EvmTransactionSigner>,
    /// Off-chain DID-index backing store (CF_IDENTITIES under
    /// [`ERC8004_DID_INDEX_PREFIX`]).
    storage: Arc<dyn KvStore>,
}

impl NativeErc8004Mirror {
    /// Construct a mirror wired to a signed-tx submitter + DID-index store.
    pub fn new(signer: Arc<EvmTransactionSigner>, storage: Arc<dyn KvStore>) -> Self {
        Self { signer, storage }
    }

    /// Format the canonical IDENTITY_REGISTRY address as a `0x`-prefixed
    /// hex string (the shape `EvmTransactionSigner::send_transaction`
    /// expects).
    fn identity_registry_hex() -> String {
        let mut s = String::with_capacity(2 + 40);
        s.push_str("0x");
        s.push_str(&hex::encode(addresses::IDENTITY_REGISTRY));
        s
    }
}

impl OnChainAgentRegistry for NativeErc8004Mirror {
    fn mirror_register_agent(
        &self,
        did: &str,
        _agent_address: &EthAddress,
        metadata_uri: &str,
    ) -> IdentityResult<()> {
        // Build calldata synchronously — pure, no I/O. This is the only
        // step that can fail in-line; everything else moves to the spawn.
        //
        // The canonical `register(string agentURI)` overload allocates a
        // fresh `agentId` for `msg.sender`. Note that `msg.sender` from
        // the contract's perspective is the `erc8004-system` key's
        // address, NOT `agent_address` — the caller-supplied address is
        // intentionally ignored here. To rebind the controller, callers
        // must additionally invoke `setAgentWallet` (with the agent's
        // owner-signed EIP-712 consent) once the agentId is known.
        let calldata = abi::encode_register_with_uri(selectors::REGISTER_WITH_URI, metadata_uri);

        let signer = Arc::clone(&self.signer);
        let to = Self::identity_registry_hex();
        let did_owned = did.to_string();

        tokio::spawn(async move {
            match signer.send_transaction(&to, &calldata, 0).await {
                Ok(tx_hash) => {
                    tracing::info!(
                        target: "tenzro::erc8004::mirror",
                        did = %did_owned,
                        tx_hash = %tx_hash,
                        "ERC-8004 register tx submitted; agentId arrives via Registered event"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        target: "tenzro::erc8004::mirror",
                        did = %did_owned,
                        error = %e,
                        "ERC-8004 register tx submission failed (TDIP registration unaffected)"
                    );
                }
            }
        });

        Ok(())
    }

    fn lookup_agent_id_by_did(&self, did: &str) -> Option<u64> {
        let key = did_index_key(did);
        match self.storage.get(CF_IDENTITIES, &key) {
            Ok(Some(bytes)) if bytes.len() == 8 => {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&bytes);
                Some(u64::from_be_bytes(buf))
            }
            Ok(Some(bad)) => {
                tracing::warn!(
                    target: "tenzro::erc8004::mirror",
                    did,
                    len = bad.len(),
                    "malformed erc8004_did_index entry (expected 8-byte BE u64)"
                );
                None
            }
            Ok(None) => None,
            Err(e) => {
                tracing::warn!(
                    target: "tenzro::erc8004::mirror",
                    did,
                    error = %e,
                    "RocksDB read failed during DID-index lookup"
                );
                None
            }
        }
    }
}

/// Address-keyed ERC-8004 registration lookup for the autonomous-agent
/// bootstrap paymaster.
///
/// Bridges [`tenzro_vm::AgentRegistryLookup`] (which asks "is this smart
/// account a registered agent?") onto the off-chain `erc8004_owner_index:`
/// keyspace in `CF_IDENTITIES`, populated from the `Registered` event's
/// `address indexed owner` topic by the event listener. Presence of an
/// index entry means the address owns a mirrored ERC-8004 agent id — i.e.
/// the account is registered and in good standing.
///
/// Kept in the node layer so `tenzro-vm` does not depend on
/// `tenzro-identity` / `tenzro-storage`.
pub struct Erc8004OwnerRegistryLookup {
    storage: Arc<dyn KvStore>,
}

impl Erc8004OwnerRegistryLookup {
    pub fn new(storage: Arc<dyn KvStore>) -> Self {
        Self { storage }
    }
}

impl tenzro_vm::AgentRegistryLookup for Erc8004OwnerRegistryLookup {
    fn is_registered(&self, agent_address: &[u8]) -> bool {
        matches!(
            self.storage
                .get(CF_IDENTITIES, &owner_index_key(agent_address)),
            Ok(Some(_))
        )
    }
}

/// Convert the standard `lookup_agent_id_by_did` result into the unified
/// [`IdentityError::VerificationFailed`] shape — used by RPC handlers that
/// want a typed error for the "not yet mirrored" case rather than
/// `Option`.
pub fn require_agent_id(did: &str, registry: &dyn OnChainAgentRegistry) -> IdentityResult<u64> {
    registry.lookup_agent_id_by_did(did).ok_or_else(|| {
        IdentityError::VerificationFailed(format!(
            "no ERC-8004 agentId mirrored for DID '{}' yet \
             (mirror tx may still be pending — retry after a few blocks)",
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
        assert!(key.starts_with(ERC8004_DID_INDEX_PREFIX));
        assert_eq!(
            &key[ERC8004_DID_INDEX_PREFIX.len()..],
            b"did:tenzro:machine:abc"
        );
    }

    #[test]
    fn lookup_returns_none_when_index_empty() {
        let storage: Arc<dyn KvStore> = Arc::new(MemoryStore::new());
        // We don't need a real signer for this test — but the type requires
        // one. Stub it via a dummy 0x01..01 key + loopback URL; we never
        // call mirror_register_agent here.
        let signer = Arc::new(
            EvmTransactionSigner::new(&[1u8; 32], 1337, "http://127.0.0.1:1".to_string())
                .expect("dev signer"),
        );
        let mirror = NativeErc8004Mirror::new(signer, storage);
        assert_eq!(
            mirror.lookup_agent_id_by_did("did:tenzro:machine:nope"),
            None
        );
    }

    #[test]
    fn lookup_returns_indexed_id() {
        let storage: Arc<dyn KvStore> = Arc::new(MemoryStore::new());
        let did = "did:tenzro:machine:42";
        storage
            .put(CF_IDENTITIES, &did_index_key(did), &42u64.to_be_bytes())
            .expect("put");

        let signer = Arc::new(
            EvmTransactionSigner::new(&[1u8; 32], 1337, "http://127.0.0.1:1".to_string())
                .expect("dev signer"),
        );
        let mirror = NativeErc8004Mirror::new(signer, storage);
        assert_eq!(mirror.lookup_agent_id_by_did(did), Some(42));
    }

    #[test]
    fn lookup_rejects_malformed_value() {
        let storage: Arc<dyn KvStore> = Arc::new(MemoryStore::new());
        let did = "did:tenzro:machine:bad";
        storage
            .put(CF_IDENTITIES, &did_index_key(did), b"not-eight-bytes")
            .expect("put");

        let signer = Arc::new(
            EvmTransactionSigner::new(&[1u8; 32], 1337, "http://127.0.0.1:1".to_string())
                .expect("dev signer"),
        );
        let mirror = NativeErc8004Mirror::new(signer, storage);
        assert_eq!(mirror.lookup_agent_id_by_did(did), None);
    }
}
