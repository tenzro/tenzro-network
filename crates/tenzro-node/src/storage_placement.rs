//! Where a buyer's constrained object is held, and the receipts that say so.
//!
//! A buyer may constrain an object to holders in named countries, run by
//! named operators, or both ([`tenzro_storage_provider::PlacementConstraint`]).
//! The origin refuses the object unless it is inside the constraint itself,
//! and announces it on its own gossip topic signed with the constraint.
//! A holder ranks for its shards only when it is inside the constraint,
//! among candidates inside it, and keeps a [`HoldingRecord`] in
//! `CF_SETTLEMENTS` under `storage_holding:<object id>`.
//!
//! `tenzro_getStorageHoldingReceipt { object_id }` answers with a
//! [`StorageHoldingReceipt`] for the shards this node holds now, signed by
//! its record signer: the holder, its operator, the region it declares and
//! its jurisdiction claim, the constraint's digest and the shard
//! commitments. A region and a claim are what the operator declares, bound
//! to a TEE attestation only on a TEE node: a locality claim, not a
//! geolocation.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tenzro_storage::{CF_SETTLEMENTS, KvStore};
use tenzro_storage_provider::PlacementConstraint;

use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;

const HOLDING_PREFIX: &str = "storage_holding:";

/// Domain tag of [`StorageHoldingReceipt::canonical_preimage`].
const RECEIPT_DOMAIN: &[u8] = b"tenzro/storage/holding-receipt/v1";

/// One shard a holder took.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeldShard {
    /// BLAKE3 hex of the shard bytes, its blob identity.
    pub blob_hash: String,
    /// SHA-256 hex commitment of the shard bytes.
    pub commitment: String,
}

/// What this node took of one constrained object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HoldingRecord {
    pub object_id: String,
    /// The node that announced the object.
    pub origin_endpoint_id: String,
    /// The buyer's constraint the object was announced under.
    pub constraint: PlacementConstraint,
    /// The shards this node ranked for and pinned.
    pub shards: Vec<HeldShard>,
    /// When they were pinned (unix ms).
    pub pinned_at_ms: i64,
}

fn holding_key(object_id: &str) -> Vec<u8> {
    format!("{HOLDING_PREFIX}{object_id}").into_bytes()
}

/// Keeps `record`, replacing an earlier one for the same object.
pub fn record_holding(store: &dyn KvStore, record: &HoldingRecord) -> Result<(), String> {
    let value = serde_json::to_vec(record).map_err(|e| e.to_string())?;
    store
        .put(CF_SETTLEMENTS, &holding_key(&record.object_id), &value)
        .map_err(|e| e.to_string())
}

/// The holding record of `object_id`, when this node took any of it.
pub fn read_holding(store: &dyn KvStore, object_id: &str) -> Result<Option<HoldingRecord>, String> {
    store
        .get(CF_SETTLEMENTS, &holding_key(object_id))
        .map_err(|e| e.to_string())?
        .map(|b| serde_json::from_slice(&b).map_err(|e| e.to_string()))
        .transpose()
}

/// Key prefix (in `CF_SETTLEMENTS`) of the constraint an object this node
/// originated was stored under.
const ORIGIN_CONSTRAINT_PREFIX: &str = "storage_origin_constraint:";

/// Keeps the constraint `object_id` was stored under, so repair announces it
/// again with the same constraint.
pub fn record_origin_constraint(
    store: &dyn KvStore,
    object_id: &str,
    constraint: &PlacementConstraint,
) -> Result<(), String> {
    let value = serde_json::to_vec(constraint).map_err(|e| e.to_string())?;
    store
        .put(
            CF_SETTLEMENTS,
            format!("{ORIGIN_CONSTRAINT_PREFIX}{object_id}").as_bytes(),
            &value,
        )
        .map_err(|e| e.to_string())
}

/// The constraint `object_id` was stored under here, if any.
pub fn read_origin_constraint(
    store: &dyn KvStore,
    object_id: &str,
) -> Result<Option<PlacementConstraint>, String> {
    store
        .get(
            CF_SETTLEMENTS,
            format!("{ORIGIN_CONSTRAINT_PREFIX}{object_id}").as_bytes(),
        )
        .map_err(|e| e.to_string())?
        .map(|b| serde_json::from_slice(&b).map_err(|e| e.to_string()))
        .transpose()
}

/// How often this node announces again the shards of the objects it
/// originated.
pub const STORAGE_REPAIR_INTERVAL_SECS: u64 = 60 * 60;

/// One repair pass: announces again the shards of every object this node
/// stored, under the constraint it was stored with. Holders self-select from
/// the membership and standings of now, so a shard whose holder left gets a
/// new one, and one held by a provider whose record fell is placed on a
/// better one: repair and re-tiering by the same ranking as the first
/// placement. A holder that still has a shard pins it again at no cost.
pub(crate) fn run_storage_repair_pass(node: &Arc<TenzroNode>) -> usize {
    let Some(runtime) = node.storage_runtime() else {
        return 0;
    };
    let store = node.storage().map(|s| s.clone() as Arc<dyn KvStore>);
    let descriptors = runtime.store().descriptors();
    for descriptor in &descriptors {
        let constraint = store.as_ref().and_then(|s| {
            read_origin_constraint(s.as_ref(), &descriptor.object_id)
                .ok()
                .flatten()
        });
        crate::rpc::broadcast_shard_replication(node, descriptor, constraint.as_ref());
    }
    descriptors.len()
}

/// Drives [`run_storage_repair_pass`] on a timer. Nodes that store nothing
/// return at once each pass.
pub fn spawn_storage_repair_loop(node: Arc<TenzroNode>) {
    tokio::spawn(async move {
        let mut ticker =
            tokio::time::interval(std::time::Duration::from_secs(STORAGE_REPAIR_INTERVAL_SECS));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The first placement just happened at store time.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let objects = run_storage_repair_pass(&node);
            if objects > 0 {
                tracing::debug!(objects, "Storage repair pass announced held objects again");
            }
        }
    });
}

/// A holder's signed statement that it holds shards of an object, where it
/// declares it is, and which constraint it took them under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageHoldingReceipt {
    pub object_id: String,
    /// Commitments of the shards held when the receipt was signed.
    pub commitments: Vec<String>,
    /// The holder's machine DID.
    pub holder_did: String,
    /// The operator account running the holder, hex without `0x`.
    pub operator: String,
    /// The coarse region the holder declares, as its announcements carry it.
    pub region: Option<String>,
    /// The holder's jurisdiction claim, when it declares one.
    pub jurisdiction: Option<tenzro_types::JurisdictionClaim>,
    /// Hex of [`PlacementConstraint::digest`].
    pub constraint_digest: String,
    /// When it was signed (unix ms).
    pub signed_at_ms: u64,
    /// The signer's P-256 key, and its ML-DSA-65 key when it has one.
    pub signer_public_key: Vec<u8>,
    pub signer_pq_key: Option<Vec<u8>>,
    /// The batched record signature, JSON.
    pub batched: Option<Vec<u8>>,
}

impl StorageHoldingReceipt {
    /// The signed bytes: a domain tag and every field above the signer's
    /// keys, each length-prefixed.
    pub fn canonical_preimage(&self) -> Vec<u8> {
        let mut out = RECEIPT_DOMAIN.to_vec();
        let mut field = |bytes: &[u8]| {
            out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(bytes);
        };
        field(self.object_id.as_bytes());
        field(&(self.commitments.len() as u32).to_le_bytes());
        for c in &self.commitments {
            field(c.as_bytes());
        }
        field(self.holder_did.as_bytes());
        field(self.operator.as_bytes());
        field(self.region.as_deref().unwrap_or("").as_bytes());
        let claim = self
            .jurisdiction
            .as_ref()
            .map(|c| serde_json::to_vec(c).unwrap_or_default())
            .unwrap_or_default();
        field(&claim);
        field(self.constraint_digest.as_bytes());
        field(&self.signed_at_ms.to_le_bytes());
        out
    }

    /// Signs the receipt with `signer`, filling the signer's keys first so
    /// they are what a verifier checks against.
    pub fn sign(&mut self, signer: &dyn tenzro_crypto::batch::RecordSigner) -> Result<(), String> {
        self.signer_public_key = signer.identity().p256.clone();
        self.signer_pq_key = signer.identity().pq.clone();
        self.batched = None;
        let signed = signer
            .sign_record(&self.canonical_preimage())
            .map_err(|e| e.to_string())?;
        self.batched = Some(serde_json::to_vec(&signed.batched).map_err(|e| e.to_string())?);
        Ok(())
    }

    /// Checks the signature against the keys the receipt names. Whether
    /// those keys are the holder's is checked against the identity
    /// registered for `holder_did`.
    pub fn verify(&self) -> Result<(), String> {
        let identity = tenzro_crypto::composite::CompositePublicKey::new(
            self.signer_public_key.clone(),
            self.signer_pq_key.clone(),
        )
        .map_err(|e| e.to_string())?;
        let sig: tenzro_crypto::batch::BatchedSignature = self
            .batched
            .as_deref()
            .and_then(|raw| serde_json::from_slice(raw).ok())
            .ok_or("the receipt carries no signature")?;
        tenzro_crypto::batch::RecordSignature::batched(sig)
            .verify_record_at(&identity, &self.canonical_preimage(), self.signed_at_ms)
            .map_err(|e| e.to_string())
    }
}

/// This node's declared region and operator account (hex without `0x`), as
/// its provider announcements carry them.
pub fn own_placement(node: &TenzroNode) -> (Option<String>, String) {
    let region = node
        .config()
        .region
        .as_deref()
        .and_then(|r| tenzro_types::provider_listing::coarse_region(r).ok());
    let operator = node
        .operator_payee()
        .map(|a| hex::encode(a.as_bytes()))
        .unwrap_or_default();
    (region, operator)
}

/// A constraint from store parameters: `placement: { jurisdiction: [..],
/// operators: [..] }`, or `None` when the parameters name none.
pub(crate) fn constraint_param(
    params: &Value,
) -> Result<Option<PlacementConstraint>, JsonRpcError> {
    let Some(p) = params.get("placement").filter(|p| !p.is_null()) else {
        return Ok(None);
    };
    let list = |key: &str| -> Result<Vec<String>, JsonRpcError> {
        match p.get(key) {
            None | Some(Value::Null) => Ok(Vec::new()),
            Some(Value::Array(a)) => a
                .iter()
                .map(|v| v.as_str().map(str::to_string).ok_or_else(|| bad(key)))
                .collect(),
            Some(_) => Err(bad(key)),
        }
    };
    PlacementConstraint::new(&list("jurisdiction")?, &list("operators")?)
        .map(Some)
        .map_err(|e| JsonRpcError {
            code: -32602,
            message: format!("placement: {e}"),
            data: None,
        })
}

fn bad(key: &str) -> JsonRpcError {
    JsonRpcError {
        code: -32602,
        message: format!("placement.{key} is a list of strings"),
        data: None,
    }
}

/// `tenzro_getStorageHoldingReceipt { object_id }`: a receipt signed by this
/// node for the shards of `object_id` it holds now, or `null` when it holds
/// none under a constraint.
pub(crate) async fn handle_holding_receipt(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = crate::rpc::unwrap_param_object(params);
    let object_id = params
        .get("object_id")
        .and_then(Value::as_str)
        .ok_or_else(|| JsonRpcError {
            code: -32602,
            message: "object_id is required".into(),
            data: None,
        })?;
    let internal = |message: String| JsonRpcError {
        code: -32603,
        message,
        data: None,
    };
    let store = node
        .storage()
        .ok_or_else(|| internal("storage not initialized".into()))?;
    let Some(record) = read_holding(store.as_ref(), object_id).map_err(internal)? else {
        return Ok(Value::Null);
    };
    let (Some(resolver), Some(signer)) = (node.iroh_resolver(), node.records()) else {
        return Err(internal(
            "this node has no blob store or no record signer".into(),
        ));
    };
    let local = resolver
        .local_blob_hashes()
        .await
        .map_err(|e| internal(e.to_string()))?;
    let commitments: Vec<String> = record
        .shards
        .iter()
        .filter(|s| local.contains(&s.blob_hash))
        .map(|s| s.commitment.clone())
        .collect();
    if commitments.is_empty() {
        return Ok(Value::Null);
    }
    let (region, operator) = own_placement(node);
    let mut receipt = StorageHoldingReceipt {
        object_id: record.object_id,
        commitments,
        holder_did: crate::event_loop::AnnounceIdentity::new(signer.clone())
            .machine_did()
            .to_string(),
        operator,
        region,
        jurisdiction: node.jurisdiction_claim().cloned(),
        constraint_digest: hex::encode(record.constraint.digest()),
        signed_at_ms: chrono::Utc::now().timestamp_millis().max(0) as u64,
        signer_public_key: Vec::new(),
        signer_pq_key: None,
        batched: None,
    };
    receipt.sign(signer.as_ref()).map_err(internal)?;
    Ok(json!({ "receipt": receipt, "constraint": record.constraint }))
}

/// One storage provider this node has heard announce storage.
struct Announced<'a> {
    endpoint_id: &'a str,
    provider_address: &'a str,
    region: Option<&'a str>,
}

/// The providers in `announced`, best record first: standing descending,
/// providers no verdict has judged after those with a record of the same
/// standing, endpoint id last so the order is stable.
fn ranking(
    announced: &[Announced<'_>],
    record_of: impl Fn(&str) -> Option<crate::provider_standing::Record>,
) -> Vec<Value> {
    let mut rows: Vec<(u64, bool, &Announced<'_>)> = announced
        .iter()
        .map(|a| {
            let r = record_of(a.provider_address);
            (r.map_or(0, |r| r.standing), r.is_some_and(|r| r.judged), a)
        })
        .collect();
    rows.sort_by(|x, y| {
        y.0.cmp(&x.0)
            .then(y.1.cmp(&x.1))
            .then(x.2.endpoint_id.cmp(y.2.endpoint_id))
    });
    rows.into_iter()
        .map(|(standing, judged, a)| {
            json!({
                "endpoint_id": a.endpoint_id,
                "provider_address": a.provider_address,
                "region": a.region,
                "standing": standing,
                "judged": judged,
            })
        })
        .collect()
}

/// `tenzro_listStorageProviders`: the storage providers this node has heard
/// announce, ranked by what consensus state records about them (the same
/// standing shard placement favours), with the share of replicas placement
/// reserves for providers no verdict has judged yet.
pub(crate) async fn handle_list_storage_providers(
    node: &Arc<TenzroNode>,
) -> Result<Value, JsonRpcError> {
    let chain = crate::rpc::chain_state(node)?;
    let now = crate::calendar::now_ms() as i64;
    let snapshot = node.network_providers_snapshot();
    let announced: Vec<Announced<'_>> = snapshot
        .iter()
        .map(|e| &e.announcement)
        .filter(|a| a.capabilities.iter().any(|c| c == "storage") && !a.iroh_endpoint_id.is_empty())
        .map(|a| Announced {
            endpoint_id: &a.iroh_endpoint_id,
            provider_address: &a.provider_address,
            region: a.region.as_deref(),
        })
        .collect();
    let providers = ranking(&announced, |address| {
        hex::decode(address.trim_start_matches("0x"))
            .ok()
            .map(|account| crate::provider_standing::record(&chain, &account, now))
    });
    Ok(json!({
        "providers": providers,
        "standing_max": crate::provider_standing::STANDING_MAX,
        "new_provider_share_bps": tenzro_vm::native::network_param(
            &chain,
            tenzro_vm::governance::STORAGE_NEW_PROVIDER_SHARE_PARAM,
        ),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receipt() -> StorageHoldingReceipt {
        StorageHoldingReceipt {
            object_id: "obj".into(),
            commitments: vec!["c1".into(), "c2".into()],
            holder_did: "did:tenzro:machine:holder".into(),
            operator: "ab".repeat(32),
            region: Some("DE".into()),
            jurisdiction: None,
            constraint_digest: "00".repeat(32),
            signed_at_ms: 1_700_000_000_000,
            signer_public_key: Vec::new(),
            signer_pq_key: None,
            batched: None,
        }
    }

    fn signer() -> tenzro_crypto::batch::ImmediateRecordSigner {
        tenzro_crypto::batch::ImmediateRecordSigner::new(Arc::new(
            tenzro_crypto::testing::TestHybridSigner::random(),
        ))
    }

    #[test]
    fn a_signed_receipt_verifies_and_any_change_breaks_it() {
        let mut r = receipt();
        r.sign(&signer()).unwrap();
        r.verify().unwrap();
        let tampers: [fn(&mut StorageHoldingReceipt); 6] = [
            |r| r.object_id = "other".into(),
            |r| r.commitments.truncate(1),
            |r| r.region = Some("US".into()),
            |r| r.operator = "cd".repeat(32),
            |r| r.constraint_digest = "11".repeat(32),
            |r| r.signed_at_ms += 1,
        ];
        for tamper in tampers {
            let mut t = r.clone();
            tamper(&mut t);
            assert!(t.verify().is_err());
        }
        let mut unsigned = receipt();
        unsigned.signer_public_key = r.signer_public_key.clone();
        assert!(unsigned.verify().is_err(), "no signature");
    }

    #[test]
    fn a_holding_record_is_kept_per_object() {
        let store = tenzro_storage::MemoryStore::new();
        assert_eq!(read_holding(&store, "obj").unwrap(), None);
        let record = HoldingRecord {
            object_id: "obj".into(),
            origin_endpoint_id: "e".into(),
            constraint: PlacementConstraint::new(&["DE".into()], &[]).unwrap(),
            shards: vec![HeldShard {
                blob_hash: "b".into(),
                commitment: "c".into(),
            }],
            pinned_at_ms: 5,
        };
        record_holding(&store, &record).unwrap();
        assert_eq!(read_holding(&store, "obj").unwrap(), Some(record));
    }

    #[test]
    fn a_placement_parameter_reads_into_a_constraint() {
        assert_eq!(constraint_param(&json!({})).unwrap(), None);
        assert_eq!(
            constraint_param(&json!({ "placement": null })).unwrap(),
            None
        );
        let c = constraint_param(&json!({ "placement": { "jurisdiction": ["de"] } }))
            .unwrap()
            .unwrap();
        assert_eq!(c.jurisdiction, vec!["DE".to_string()]);
        assert!(
            constraint_param(&json!({ "placement": {} })).is_err(),
            "empty"
        );
        assert!(constraint_param(&json!({ "placement": { "jurisdiction": "DE" } })).is_err());
        assert!(constraint_param(&json!({ "placement": { "operators": [7] } })).is_err());
    }

    #[test]
    fn providers_are_ranked_by_record_with_unjudged_after_equals() {
        use crate::provider_standing::Record;
        let announced = [
            Announced {
                endpoint_id: "c",
                provider_address: "0c",
                region: None,
            },
            Announced {
                endpoint_id: "a",
                provider_address: "0a",
                region: Some("EU"),
            },
            Announced {
                endpoint_id: "b",
                provider_address: "0b",
                region: None,
            },
            Announced {
                endpoint_id: "d",
                provider_address: "zz",
                region: None,
            },
        ];
        let rows = ranking(&announced, |address| match address {
            "0a" => Some(Record {
                standing: 6_500,
                judged: false,
            }),
            "0b" => Some(Record {
                standing: 6_500,
                judged: true,
            }),
            "0c" => Some(Record {
                standing: 9_000,
                judged: true,
            }),
            _ => None,
        });
        let order: Vec<&str> = rows
            .iter()
            .map(|r| r["endpoint_id"].as_str().unwrap())
            .collect();
        assert_eq!(order, ["c", "b", "a", "d"]);
        assert_eq!(rows[2]["region"], "EU");
        assert_eq!(rows[3]["standing"], 0);
        assert_eq!(rows[3]["judged"], false);
    }

    #[test]
    fn an_origin_constraint_is_kept_for_repair() {
        let store = tenzro_storage::MemoryStore::new();
        assert_eq!(read_origin_constraint(&store, "o").unwrap(), None);
        let constraint = PlacementConstraint::new(&["DE".into()], &[]).unwrap();
        record_origin_constraint(&store, "o", &constraint).unwrap();
        assert_eq!(
            read_origin_constraint(&store, "o").unwrap(),
            Some(constraint)
        );
        assert_eq!(read_origin_constraint(&store, "other").unwrap(), None);
    }
}
