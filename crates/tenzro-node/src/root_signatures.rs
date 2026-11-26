//! Records signed with the node's identity key, and their check against the
//! chain's identity key histories.
//!
//! A machine's identity key (Ed25519 + ML-DSA-65) is derived per version
//! from its hardware root, and the chain records which version is in force
//! with an identity key change. Once `feature.root_signatures` is live and
//! the chain records the key this machine derives at its latest version, the
//! node signs its jurisdiction receipts with that key: each receipt is a
//! batch of one whose root the key signs. Until then, or while the chain
//! records another key, receipts carry the hardware record signature.
//!
//! Verifiers check such a receipt against [`ChainLedgerView`], the chain
//! state this node holds: the key the receipt's machine had at the version
//! it names, whether that key was declared compromised, and whether the
//! machine revoked the signature. A receipt is judged by the key in force
//! when it was made, so a rotation does not retire receipts made before it;
//! a compromise declaration does.

use std::sync::Arc;

use serde_json::{Value, json};
use tenzro_device_key::batch_signer::{RootSignature, RootSigner};
use tenzro_device_key::delegation::{
    DelegationError, DelegationResult, IssuerResolver, SystemClock, VerifyParams,
};
use tenzro_device_key::issuer_chain::{
    ChainIssuerResolver, IdentityHistory, KeyEpoch, LedgerView, ResolverParams,
};
use tenzro_storage::{BlockStore, BlockStoreImpl, KvStore, RocksDbStore};
use tenzro_vm::VmState;
use tenzro_vm::native::identity_keys::{ROOT_SIGNATURES_GATE, ROOT_SIGNATURES_MAX_GAP_PARAM};

use crate::keygen::NodeKeys;
use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;

/// The chain state this node holds, as an identity key verifier reads it.
pub struct ChainLedgerView {
    storage: Arc<RocksDbStore>,
}

impl ChainLedgerView {
    pub fn new(storage: Arc<RocksDbStore>) -> Self {
        Self { storage }
    }

    fn state(&self) -> tenzro_vm::StateAdapter {
        tenzro_vm::StateAdapter::with_storage(self.storage.clone() as Arc<dyn KvStore>)
    }
}

/// `identity`'s key history as `state` records it.
fn history_in(state: &dyn VmState, identity: &str) -> IdentityHistory {
    IdentityHistory {
        epochs: tenzro_vm::native::read_identity_keys(state, identity)
            .epochs
            .into_iter()
            .map(|e| KeyEpoch {
                version: e.version,
                ed25519: e.ed25519,
                ml_dsa: e.ml_dsa,
                effective_from_ms: e.effective_from_ms,
                compromised_from_ms: e.compromised_from_ms,
                next_commitment: e.next_commitment,
            })
            .collect(),
    }
}

impl LedgerView for ChainLedgerView {
    fn history(&self, identity: &str) -> DelegationResult<IdentityHistory> {
        Ok(history_in(&self.state(), identity))
    }

    fn revoked_at_ms(&self, identity: &str, delegation_id: &[u8; 32]) -> Option<u64> {
        tenzro_vm::native::delegation_revoked_at_ms(&self.state(), identity, delegation_id)
    }

    fn head_time_ms(&self) -> u64 {
        // The block store reads storage synchronously behind its async
        // interface, so the future completes without a runtime.
        let Ok(blocks) = BlockStoreImpl::new(self.storage.clone()) else {
            return 0;
        };
        futures::executor::block_on(blocks.latest_block())
            .ok()
            .flatten()
            .and_then(|b| u64::try_from(b.header.timestamp.as_millis()).ok())
            .unwrap_or(0)
    }
}

/// A resolver over the node's chain state, and the tolerance in force;
/// `None` without chain storage.
pub fn chain_keys(
    storage: Option<&Arc<RocksDbStore>>,
) -> Option<(Arc<dyn IssuerResolver>, VerifyParams)> {
    let storage = storage?.clone();
    let view = ChainLedgerView::new(storage);
    let gap_ms = tenzro_vm::native::network_param(&view.state(), ROOT_SIGNATURES_MAX_GAP_PARAM);
    let resolver = ChainIssuerResolver::new(
        Arc::new(view),
        Arc::new(SystemClock),
        ResolverParams {
            // A record is judged by the key in force when it was made.
            overlap_ms: u64::MAX,
            max_staleness_ms: gap_ms,
            history_ttl_ms: 0,
        },
    );
    Some((Arc::new(resolver), VerifyParams { skew_ms: gap_ms }))
}

/// The machine's identity key at one version, signing batch roots for it.
struct IdentityRootSigner {
    keys: NodeKeys,
    identity: String,
    version: u64,
    ed25519: [u8; 32],
    ml_dsa: Vec<u8>,
}

impl RootSigner for IdentityRootSigner {
    fn sign_root(
        &self,
        root: &[u8; 32],
        count: u32,
        now_ms: u64,
    ) -> DelegationResult<RootSignature> {
        let mut sig = RootSignature {
            identity: self.identity.clone(),
            issuer_version: self.version,
            issuer_ed25519: self.ed25519,
            issuer_ml_dsa: self.ml_dsa.clone(),
            signed_at_ms: now_ms,
            count,
            root: *root,
            ed_signature: [0; 64],
            ml_dsa_signature: Vec::new(),
        };
        let (ed, ml) = self
            .keys
            .sign_with_identity_key(self.version, &sig.statement())
            .map_err(|e| DelegationError::Provider(e.to_string()))?;
        sig.ed_signature = ed;
        sig.ml_dsa_signature = ml;
        Ok(sig)
    }
}

/// The jurisdiction signer that signs with this machine's identity key, when
/// root signatures are live and the chain records, at its latest version,
/// the key this machine derives for that version. `None` otherwise, and the
/// node signs with its record signer.
pub fn identity_key_jurisdiction_signer(
    node: &TenzroNode,
) -> Option<tenzro_model::SharedJurisdictionSigner> {
    let state = node.chain_state()?;
    let hardware = node.records()?.identity().clone();
    let keys = NodeKeys::open(&node.config().data_dir).ok()?;
    let root = identity_root_signer(&state, &hardware, keys)?;
    Some(Arc::new(tenzro_model::IdentityKeyJurisdictionSigner::new(
        Arc::new(root),
        hardware,
    )))
}

/// The identity key `keys` derive at the latest version `state` records for
/// the machine of `hardware`, when root signatures are live there, the key
/// matches, and it was not declared compromised.
fn identity_root_signer(
    state: &dyn VmState,
    hardware: &tenzro_crypto::composite::CompositePublicKey,
    keys: NodeKeys,
) -> Option<IdentityRootSigner> {
    if !tenzro_vm::feature_gate::is_live_now(state, ROOT_SIGNATURES_GATE) {
        return None;
    }
    let identity = tenzro_types::did_derivation::machine_did(&hardware.p256);
    let latest = tenzro_vm::native::read_identity_keys(state, &identity)
        .epochs
        .pop()?;
    if latest.compromised_from_ms.is_some() {
        return None;
    }
    let (ed25519, ml_dsa) = keys.identity_key(latest.version).ok()?;
    if ed25519 != latest.ed25519 || ml_dsa != latest.ml_dsa {
        tracing::warn!(
            version = latest.version,
            "the chain records another identity key for this machine; jurisdiction receipts \
             keep the record signature"
        );
        return None;
    }
    Some(IdentityRootSigner {
        keys,
        identity,
        version: latest.version,
        ed25519,
        ml_dsa,
    })
}

/// The identity key change that records this machine's identity key at
/// `version`, committing to the key at the version after it.
pub fn identity_key_update(
    keys: &NodeKeys,
    version: u64,
) -> tenzro_keygen::Result<tenzro_native_ops::identity_keys::IdentityKeyChange> {
    let (ed25519, ml_dsa) = keys.identity_key(version)?;
    let (next_ed, next_ml) = keys.identity_key(version + 1)?;
    Ok(
        tenzro_native_ops::identity_keys::IdentityKeyChange::Update {
            version,
            ed25519,
            ml_dsa,
            next_commitment: Some(tenzro_crypto::identity_key::next_key_commitment(
                &next_ed, &next_ml,
            )),
        },
    )
}

/// `tenzro_verifyJurisdictionReceipt { receipt }` → `{ valid, error?, form,
/// machine_did, registered, ... }`: the receipt's signature in either form,
/// the identity key form against this node's chain state, and whether the
/// hardware key it names is the one registered for its machine.
pub(crate) fn handle_verify_jurisdiction_receipt(
    node: &TenzroNode,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let receipt: tenzro_types::JurisdictionReceipt = params
        .and_then(|p| p.get("receipt").cloned())
        .ok_or_else(|| bad("missing receipt"))
        .and_then(|v| {
            serde_json::from_value(v).map_err(|e| bad(format!("receipt does not parse: {e}")))
        })?;
    let form = match receipt
        .batched
        .as_deref()
        .and_then(tenzro_device_key::batch_signer::Member::from_json)
    {
        Some(_) => "identity_key",
        None => "record",
    };
    let machine_did = tenzro_types::did_derivation::machine_did(&receipt.signer_public_key);
    let registered = crate::identity_bootstrap::registered_identity_key(
        &node.identity_registry_slot(),
        &machine_did,
    )
    .is_some_and(|k| k.p256 == receipt.signer_public_key && k.pq == receipt.signer_pq_key);
    let chain = chain_keys(node.storage());
    let verdict = tenzro_model::verify_receipt(
        &receipt,
        chain
            .as_ref()
            .map(|(resolver, params)| tenzro_model::IdentityKeyCheck {
                resolver: resolver.as_ref(),
                now_ms: tenzro_crypto::session::now_ms(),
                params: *params,
            }),
    );
    let mut out = json!({
        "valid": verdict.is_ok(),
        "form": form,
        "machine_did": machine_did,
        "registered": registered,
        "provider": receipt.provider,
        "model_id": receipt.model_id,
        "country": receipt.jurisdiction.country,
        "blocs": receipt.jurisdiction.blocs,
        "signed_at_ms": receipt.signed_at.as_millis(),
    });
    if let Err(e) = verdict {
        out["error"] = json!(e.to_string());
    }
    Ok(out)
}

fn bad(message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32602,
        message: message.into(),
        data: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tenzro_crypto::batch::ImmediateRecordSigner;
    use tenzro_crypto::composite::HybridSigner as _;
    use tenzro_crypto::composite::testing::TestHybridSigner;
    use tenzro_model::JurisdictionSigner as _;
    use tenzro_native_ops::identity_keys::{
        IdentityKeyEpoch, IdentityKeyHistory, delegation_revoked_slot, identity_keys_slot,
    };
    use tenzro_types::primitives::Address;
    use tenzro_vm::native::SYSTEM_ADDRESS;

    const AT_MS: u64 = 1_700_000_000_000;

    /// A chain state a verifier reads, at a head time.
    struct StateView(Mutex<tenzro_vm::StateAdapter>, u64);

    impl LedgerView for StateView {
        fn history(&self, identity: &str) -> DelegationResult<IdentityHistory> {
            Ok(history_in(&*self.0.lock().unwrap(), identity))
        }
        fn revoked_at_ms(&self, identity: &str, id: &[u8; 32]) -> Option<u64> {
            tenzro_vm::native::delegation_revoked_at_ms(&*self.0.lock().unwrap(), identity, id)
        }
        fn head_time_ms(&self) -> u64 {
            self.1
        }
    }

    fn set_gate(state: &mut tenzro_vm::StateAdapter, epoch: u64) {
        state.set_storage(
            &SYSTEM_ADDRESS,
            tenzro_vm::native::governed_param_key(ROOT_SIGNATURES_GATE).as_bytes(),
            epoch.to_le_bytes().to_vec(),
        );
    }

    /// The chain records `keys`' identity key at version 1 for `hardware`'s
    /// machine.
    fn record_key(
        state: &mut tenzro_vm::StateAdapter,
        hardware: &tenzro_crypto::composite::CompositePublicKey,
        keys: &NodeKeys,
        compromised: bool,
    ) {
        let (ed25519, ml_dsa) = keys.identity_key(1).unwrap();
        let history = IdentityKeyHistory {
            epochs: vec![IdentityKeyEpoch {
                version: 1,
                ed25519,
                ml_dsa,
                effective_from_ms: AT_MS - 60_000,
                compromised_from_ms: compromised.then_some(AT_MS - 1_000),
                next_commitment: None,
            }],
        };
        let did = tenzro_types::did_derivation::machine_did(&hardware.p256);
        state.set_storage(
            &SYSTEM_ADDRESS,
            identity_keys_slot(&did).as_bytes(),
            serde_json::to_vec(&history).unwrap(),
        );
    }

    fn keys(dir: &std::path::Path) -> NodeKeys {
        NodeKeys::open(dir).unwrap()
    }

    /// Dormant, nothing is signed with the identity key; live, a machine
    /// whose recorded key is its own signs with it, and one whose recorded
    /// key is another's or declared compromised does not.
    #[test]
    fn the_identity_key_signs_only_once_live_and_recorded_as_this_machines() {
        let dir = tempfile::tempdir().unwrap();
        let hardware = TestHybridSigner::hybrid(51).public_key().clone();
        let mut state = tenzro_vm::StateAdapter::new();
        record_key(&mut state, &hardware, &keys(dir.path()), false);
        assert!(identity_root_signer(&state, &hardware, keys(dir.path())).is_none());

        set_gate(&mut state, 0);
        let signer = identity_root_signer(&state, &hardware, keys(dir.path())).unwrap();
        assert_eq!(signer.version, 1);

        let other = tempfile::tempdir().unwrap();
        assert!(identity_root_signer(&state, &hardware, keys(other.path())).is_none());

        record_key(&mut state, &hardware, &keys(dir.path()), true);
        assert!(identity_root_signer(&state, &hardware, keys(dir.path())).is_none());
    }

    /// A receipt signed with the recorded identity key verifies against the
    /// chain state, stops verifying once the machine revokes its signature,
    /// and a receipt in the record form still verifies beside it.
    #[test]
    fn a_receipt_signed_with_the_identity_key_verifies_against_chain_state() {
        let dir = tempfile::tempdir().unwrap();
        let records = ImmediateRecordSigner::new(Arc::new(TestHybridSigner::hybrid(52)));
        let hardware = records.identity().clone();
        let mut state = tenzro_vm::StateAdapter::new();
        record_key(&mut state, &hardware, &keys(dir.path()), false);
        set_gate(&mut state, 0);
        let root = identity_root_signer(&state, &hardware, keys(dir.path())).unwrap();
        let claim = tenzro_types::JurisdictionClaim {
            country: "DE".into(),
            blocs: vec!["EU".into()],
            attestation_hash: None,
            declared_at: tenzro_types::primitives::Timestamp::new(0),
        };
        let receipt = tenzro_model::IdentityKeyJurisdictionSigner::new(Arc::new(root), hardware)
            .sign(b"in", b"out", "m", Address::default(), &claim)
            .unwrap();
        let old = tenzro_model::Ed25519JurisdictionSigner::new(Arc::new(records))
            .sign(b"in", b"out", "m", Address::default(), &claim)
            .unwrap();

        let now = u64::try_from(receipt.signed_at.as_millis()).unwrap() + 1_000;
        let view = Arc::new(StateView(Mutex::new(state), now));
        let check = |view: &Arc<StateView>| {
            let resolver = ChainIssuerResolver::new(
                view.clone(),
                Arc::new(SystemClock),
                ResolverParams {
                    overlap_ms: u64::MAX,
                    max_staleness_ms: 60_000,
                    history_ttl_ms: 0,
                },
            );
            tenzro_model::verify_receipt(
                &receipt,
                Some(tenzro_model::IdentityKeyCheck {
                    resolver: &resolver,
                    now_ms: now,
                    params: VerifyParams { skew_ms: 60_000 },
                }),
            )
        };
        check(&view).unwrap();
        tenzro_model::verify_receipt(&old, None).unwrap();

        let member =
            tenzro_device_key::batch_signer::Member::from_json(receipt.batched.as_deref().unwrap())
                .unwrap()
                .unwrap();
        view.0.lock().unwrap().set_storage(
            &SYSTEM_ADDRESS,
            delegation_revoked_slot(&member.signature.identity, &member.signature.id()).as_bytes(),
            now.to_be_bytes().to_vec(),
        );
        assert!(check(&view).is_err());
    }

    /// The change printed for an operator records the key this machine
    /// derives and commits to the next one.
    #[test]
    fn the_printed_key_change_records_this_machines_key_and_commits_to_the_next() {
        let dir = tempfile::tempdir().unwrap();
        let k = keys(dir.path());
        let tenzro_native_ops::identity_keys::IdentityKeyChange::Update {
            version,
            ed25519,
            next_commitment,
            ..
        } = identity_key_update(&k, 2).unwrap()
        else {
            panic!("an update");
        };
        assert_eq!(version, 2);
        assert_eq!(ed25519, k.identity_key(2).unwrap().0);
        let (ed3, ml3) = k.identity_key(3).unwrap();
        assert_eq!(
            next_commitment,
            Some(tenzro_crypto::identity_key::next_key_commitment(&ed3, &ml3))
        );
    }
}
