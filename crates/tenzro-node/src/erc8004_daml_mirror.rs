//! ERC-8004 DAML mirror adapter — bridges TDIP machine registrations into
//! the in-tree Canton/DAML port of the canonical ERC-8004 registries
//! (see `vendor/erc8004-daml/daml/Tenzro/Erc8004/`).
//!
//! Design (parallel to [`crate::erc8004_mirror::NativeErc8004Mirror`] for
//! EVM and [`crate::erc8004_svm_mirror::NativeErc8004SvmMirror`] for SVM):
//!
//! - **All writes flow through `RegistryAdmin.Register`.** The Canton v2
//!   JSON command body is built via
//!   [`tenzro_identity::erc8004_daml::commands::build_register`].
//! - **Best-effort, detached spawn.** Command build is synchronous so
//!   TDIP registration is not blocked. When a [`DamlMirrorTransport`] is
//!   wired, the mirror `tokio::spawn`s a `submit-and-wait` round-trip;
//!   spawn-internal failures are logged and dropped.
//! - **DID index lives off-chain in RocksDB.** The DAML
//!   `RegistryAdmin.Register` choice allocates the `agentId` from an
//!   admin-controlled counter at submit-and-wait inclusion time; the
//!   event reflector (`process_erc8004_daml_registered_events`, parallel
//!   to the EVM + SVM reflectors) is responsible for writing
//!   `(did → agentId)` pairs under the [`ERC8004_DAML_DID_INDEX_PREFIX`]
//!   keyspace in `CF_IDENTITIES`. [`NativeErc8004DamlMirror::
//!   lookup_agent_id_by_did`] reads from that index; callers MUST
//!   tolerate `None` between `mirror_register_agent` and event inclusion.
//!
//! # Transport activation
//!
//! When [`NativeErc8004DamlMirror::new`] is called without a transport,
//! the mirror serializes the full Canton command JSON to RocksDB under
//! the pending-tx queue (key prefix [`ERC8004_DAML_PENDING_TX_PREFIX`])
//! and logs the dispatch at `info` level. When the operator configures a
//! Canton JSON Ledger API endpoint + admin auth token and supplies a
//! [`DamlMirrorTransport`] impl at startup, the existing pending-tx
//! queue can be drained on first dispatch. This lets pre-mainnet test
//! fleets accumulate the mirror payload + flip on the wire later
//! without losing history.
//!
//! Today the workspace does not depend on `tonic` or any Canton client
//! crate; a real `DamlMirrorTransport` impl lives in a future
//! operator-facing crate that pulls those in only when a Canton
//! participant is configured. The trait + indirection are the
//! integration seam.

use std::sync::Arc;

use serde_json::Value;
use tenzro_identity::erc8004_daml::{DamlPackageIds, OnChainAgentDamlRegistry, commands};
use tenzro_identity::error::Result as IdentityResult;
use tenzro_storage::{CF_IDENTITIES, KvStore};

/// Off-chain RocksDB keyspace prefix for the `did → agentId` index,
/// populated by the DAML event reflector from `Registered` CreatedEvent
/// payloads. Values are 8-byte little-endian `u64`.
pub const ERC8004_DAML_DID_INDEX_PREFIX: &[u8] = b"erc8004_daml_did_index:";

/// Off-chain RocksDB keyspace prefix for pending-dispatch commands
/// recorded before a [`DamlMirrorTransport`] is wired. Keys are the DID
/// bytes; values are the canonical Canton v2 command JSON produced by
/// [`commands::build_register`], serialized via `serde_json::to_vec`.
/// The queue is drained on first real-transport dispatch.
pub const ERC8004_DAML_PENDING_TX_PREFIX: &[u8] = b"erc8004_daml_pending_tx:";

/// Compose the RocksDB key for the DID index.
pub fn did_index_key(did: &str) -> Vec<u8> {
    compose_key(ERC8004_DAML_DID_INDEX_PREFIX, did)
}

/// Compose the RocksDB key for the pending-tx queue.
pub fn pending_tx_key(did: &str) -> Vec<u8> {
    compose_key(ERC8004_DAML_PENDING_TX_PREFIX, did)
}

fn compose_key(prefix: &[u8], did: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + did.len());
    key.extend_from_slice(prefix);
    key.extend_from_slice(did.as_bytes());
    key
}

/// Operator-supplied Canton transport. Implementors typically wrap a
/// `reqwest::Client` against the participant's JSON Ledger API at
/// `/v2/commands/submit-and-wait` plus the admin party's auth token.
/// Today this trait is forward-looking: no impl exists in the monorepo
/// because the workspace deliberately does not depend on `tonic` or any
/// Canton client crate.
#[async_trait::async_trait]
pub trait DamlMirrorTransport: Send + Sync {
    /// Submit the supplied Canton v2 `submit-and-wait` command body and
    /// return the resulting transaction id. Implementations are
    /// expected to deserialize the response, extract the resulting
    /// `Registered` contract's `agentId`, and write it to the off-chain
    /// DID index keyspace as a side effect — the keyspace mechanics are
    /// owned by the mirror adapter, not by this trait.
    async fn submit_and_wait(&self, command_json: Value) -> IdentityResult<String>;
}

/// Bundled operator configuration captured at mirror construction. The
/// admin party + contract id + admin DAR package id are all
/// participant-side identifiers and so are unknown to `tenzro-identity`
/// — the node passes them in at startup.
#[derive(Debug, Clone)]
pub struct DamlMirrorConfig {
    /// Package ids of the compiled `Tenzro.Erc8004.*` DAR. Same package
    /// id covers all three modules (Identity / Reputation / Validation)
    /// because they are packaged in a single DAR.
    pub package_ids: DamlPackageIds,
    /// The Tenzro Network admin party id allocated on the target
    /// Canton participant (e.g. `TenzroAdmin::123abc...`).
    pub admin_party: String,
    /// Contract id of the single long-lived `RegistryAdmin` contract
    /// held by the admin party. Allocated once at participant setup.
    pub admin_contract_id: String,
    /// The default controller party id used when a TDIP machine
    /// registration has no Canton-side party binding (the common case
    /// today — Canton parties are operator-allocated, not
    /// per-machine). Future: per-machine party allocation flows
    /// through here.
    pub default_controller_party: String,
}

/// Native adapter: dispatches TDIP machine registrations to the
/// in-tree DAML port of the canonical ERC-8004 IdentityRegistry.
pub struct NativeErc8004DamlMirror {
    /// Operator-supplied Canton transport. When `None`, dispatches are
    /// buffered to the pending-tx queue under
    /// [`ERC8004_DAML_PENDING_TX_PREFIX`].
    transport: Option<Arc<dyn DamlMirrorTransport>>,
    /// Off-chain DID-index backing store (CF_IDENTITIES under
    /// [`ERC8004_DAML_DID_INDEX_PREFIX`]).
    storage: Arc<dyn KvStore>,
    /// Captured operator config.
    config: DamlMirrorConfig,
}

impl NativeErc8004DamlMirror {
    /// Construct a mirror with no live Canton transport. Dispatch
    /// intents are persisted to the pending-tx queue and logged at
    /// `info` level. Use [`Self::with_transport`] to attach a live
    /// transport later.
    pub fn new(storage: Arc<dyn KvStore>, config: DamlMirrorConfig) -> Self {
        Self {
            transport: None,
            storage,
            config,
        }
    }

    /// Construct a mirror with a live Canton transport. Dispatches are
    /// `tokio::spawn`ed as signed `RegistryAdmin.Register` exercises
    /// against the configured admin contract id.
    pub fn with_transport(
        storage: Arc<dyn KvStore>,
        config: DamlMirrorConfig,
        transport: Arc<dyn DamlMirrorTransport>,
    ) -> Self {
        Self {
            transport: Some(transport),
            storage,
            config,
        }
    }

    /// Programmer-visible accessor for the configured package ids.
    /// Useful for operator-facing diagnostics + RPCs.
    pub fn package_ids(&self) -> &DamlPackageIds {
        &self.config.package_ids
    }
}

impl OnChainAgentDamlRegistry for NativeErc8004DamlMirror {
    fn mirror_register_agent(&self, did: &str, metadata_uri: &str) -> IdentityResult<()> {
        // Build the Canton command JSON synchronously — pure, no I/O.
        let command = commands::build_register(
            &self.config.package_ids,
            &self.config.admin_contract_id,
            &self.config.admin_party,
            &self.config.default_controller_party,
            metadata_uri,
            did,
        );

        match self.transport.as_ref() {
            Some(transport) => {
                let transport = Arc::clone(transport);
                let did_owned = did.to_string();
                let command_owned = command;
                tokio::spawn(async move {
                    match transport.submit_and_wait(command_owned).await {
                        Ok(tx_id) => {
                            tracing::info!(
                                target: "tenzro::erc8004::daml::mirror",
                                did = %did_owned,
                                tx_id = %tx_id,
                                "ERC-8004 DAML Register command committed; agentId arrives via CreatedEvent reflector"
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                target: "tenzro::erc8004::daml::mirror",
                                did = %did_owned,
                                error = %e,
                                "ERC-8004 DAML Register command submission failed (TDIP registration unaffected)"
                            );
                        }
                    }
                });
            }
            None => {
                // No transport configured — buffer the command JSON so an
                // operator who later attaches a transport can drain the
                // queue.
                let key = pending_tx_key(did);
                match serde_json::to_vec(&command) {
                    Ok(bytes) => {
                        if let Err(e) = self.storage.put(CF_IDENTITIES, &key, &bytes) {
                            tracing::warn!(
                                target: "tenzro::erc8004::daml::mirror",
                                did,
                                error = %e,
                                "failed to buffer ERC-8004 DAML Register command to pending-tx queue"
                            );
                        } else {
                            tracing::info!(
                                target: "tenzro::erc8004::daml::mirror",
                                did,
                                bytes = bytes.len(),
                                "ERC-8004 DAML Register command buffered (no Canton transport configured)"
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            target: "tenzro::erc8004::daml::mirror",
                            did,
                            error = %e,
                            "failed to serialize ERC-8004 DAML Register command for buffering"
                        );
                    }
                }
            }
        }

        Ok(())
    }

    fn lookup_agent_id_by_did(&self, did: &str) -> Option<u64> {
        let key = did_index_key(did);
        match self.storage.get(CF_IDENTITIES, &key) {
            Ok(Some(bytes)) if bytes.len() == 8 => {
                let mut out = [0u8; 8];
                out.copy_from_slice(&bytes);
                Some(u64::from_le_bytes(out))
            }
            Ok(Some(bad)) => {
                tracing::warn!(
                    target: "tenzro::erc8004::daml::mirror",
                    did,
                    len = bad.len(),
                    "malformed erc8004_daml_did_index entry (expected 8-byte LE u64)"
                );
                None
            }
            Ok(None) => None,
            Err(e) => {
                tracing::warn!(
                    target: "tenzro::erc8004::daml::mirror",
                    did,
                    error = %e,
                    "RocksDB read failed during DAML DID-index lookup"
                );
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_storage::MemoryStore;

    fn cfg() -> DamlMirrorConfig {
        DamlMirrorConfig {
            package_ids: DamlPackageIds::new_single(
                "1122334455667788112233445566778811223344556677881122334455667788",
            ),
            admin_party: "TenzroAdmin::test".to_string(),
            admin_contract_id: "00cid".to_string(),
            default_controller_party: "DefaultController::test".to_string(),
        }
    }

    #[test]
    fn did_index_key_is_prefix_concat() {
        let key = did_index_key("did:tenzro:machine:abc");
        assert!(key.starts_with(ERC8004_DAML_DID_INDEX_PREFIX));
        assert_eq!(
            &key[ERC8004_DAML_DID_INDEX_PREFIX.len()..],
            b"did:tenzro:machine:abc"
        );
    }

    #[test]
    fn pending_tx_key_is_prefix_concat() {
        let key = pending_tx_key("did:tenzro:machine:abc");
        assert!(key.starts_with(ERC8004_DAML_PENDING_TX_PREFIX));
        assert_eq!(
            &key[ERC8004_DAML_PENDING_TX_PREFIX.len()..],
            b"did:tenzro:machine:abc"
        );
    }

    #[test]
    fn lookup_returns_none_when_index_empty() {
        let storage: Arc<dyn KvStore> = Arc::new(MemoryStore::new());
        let mirror = NativeErc8004DamlMirror::new(storage, cfg());
        assert_eq!(
            mirror.lookup_agent_id_by_did("did:tenzro:machine:nope"),
            None
        );
    }

    #[test]
    fn lookup_returns_indexed_agent_id() {
        let storage: Arc<dyn KvStore> = Arc::new(MemoryStore::new());
        let did = "did:tenzro:machine:42";
        let agent_id: u64 = 1337;
        storage
            .put(CF_IDENTITIES, &did_index_key(did), &agent_id.to_le_bytes())
            .expect("put");

        let mirror = NativeErc8004DamlMirror::new(storage, cfg());
        assert_eq!(mirror.lookup_agent_id_by_did(did), Some(agent_id));
    }

    #[test]
    fn lookup_rejects_malformed_value() {
        let storage: Arc<dyn KvStore> = Arc::new(MemoryStore::new());
        let did = "did:tenzro:machine:bad";
        storage
            .put(CF_IDENTITIES, &did_index_key(did), b"too-short")
            .expect("put");

        let mirror = NativeErc8004DamlMirror::new(storage, cfg());
        assert_eq!(mirror.lookup_agent_id_by_did(did), None);
    }

    #[tokio::test]
    async fn buffers_command_json_when_no_transport() {
        let storage: Arc<dyn KvStore> = Arc::new(MemoryStore::new());
        let mirror = NativeErc8004DamlMirror::new(storage.clone(), cfg());
        mirror
            .mirror_register_agent("did:tenzro:machine:42", "did:tenzro:machine:42")
            .expect("ok");
        let buffered = storage
            .get(CF_IDENTITIES, &pending_tx_key("did:tenzro:machine:42"))
            .expect("get")
            .expect("present");
        // Parses back as Canton v2 command JSON.
        let parsed: Value = serde_json::from_slice(&buffered).expect("valid JSON");
        let ex = &parsed["commands"][0]["ExerciseCommand"];
        assert_eq!(ex["choice"].as_str(), Some("Register"));
        assert!(
            ex["templateId"]
                .as_str()
                .unwrap()
                .ends_with(":Tenzro.Erc8004.Identity:RegistryAdmin")
        );
        assert_eq!(
            ex["choiceArgument"]["metadataUri"].as_str(),
            Some("did:tenzro:machine:42")
        );
    }

    #[test]
    fn package_ids_accessor_returns_configured_value() {
        let storage: Arc<dyn KvStore> = Arc::new(MemoryStore::new());
        let mirror = NativeErc8004DamlMirror::new(storage, cfg());
        assert_eq!(
            mirror.package_ids().tenzro_erc8004,
            "1122334455667788112233445566778811223344556677881122334455667788"
        );
    }
}
