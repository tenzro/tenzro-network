//! Capacity measured with verifiable work, and the possession proof a bond
//! that delivers storage claims owes.
//!
//! A probe carries work the validator can check rather than a number the
//! machine reports:
//!
//! - **Inference**: greedy inference on a named model, for a prompt derived
//!   from the probe's nonce. The provider returns a TOPLOC commitment over its
//!   logits. The validator checks the emitted tokens follow from those logits
//!   and stores the commitment, so anyone holding the weights can dispute it
//!   through an inference challenge. Capacity is output tokens per second on
//!   the validator's clock.
//! - **Matrix product**: the product of two matrices derived from the nonce,
//!   committed row by row and checked on the rows the commitment selects with
//!   Freivalds' test ([`tenzro_model::freivalds`]). Capacity is million
//!   multiply-adds per second on the validator's clock.
//! - **State reads**: proofs of state entries at keys derived from the nonce,
//!   each verified against the validator's own state root at the probe's
//!   height. Capacity is verified reads per second on the validator's clock.
//! - **Possession**: proofs, at positions the nonce selects, for objects held
//!   under storage claims due this hour.
//!
//! The per-epoch figure is the median of this validator's measurements; the
//! chain freezes the stake-weighted median across attesters with the SLA
//! verdict.

use std::sync::Arc;

use tenzro_model::{
    CapacityResult, CapacityWork, MAX_PROBE_TOKENS, STATE_READ_NAMESPACE, SlaProbe, SlaResponse,
    StateReadEntry, inference_prompt, state_read_keys,
};
use tenzro_storage::{KvStore, StateTrie};
use tenzro_vm::traits::VmState;
use tracing::debug;

use crate::inference_challenge::ChallengeManager;
use crate::inference_receipt::SamplingParams;

/// Tokens an inference capacity probe asks for.
pub const PROBE_TOKENS: u32 = 64;

/// Matrix dimension a compute capacity probe asks for.
pub const PROBE_MATRIX_DIMENSION: u32 = 512;

/// Product rows a compute capacity probe opens.
pub const PROBE_OPENED_ROWS: u32 = 32;

/// State entries a state-read capacity probe asks the provider to prove.
pub const PROBE_STATE_READS: u32 = 16;

/// How far behind this validator's latest committed state a state-read probe
/// asks for, so a provider a few blocks behind can still answer.
pub const STATE_READ_LAG: u64 = 4;

/// The work a probe of `did` carries: possession of the objects a bond that
/// delivers storage claims this hour has to prove. `None` otherwise.
pub fn probe_work(chain: &dyn VmState, did: &str) -> Option<CapacityWork> {
    let now = chrono::Utc::now().timestamp_millis();
    if !tenzro_vm::native::compute_claim::storage_claims_due(chain, did, now).is_empty() {
        return Some(CapacityWork::Possession {
            samples: tenzro_vm::native::network_param(
                chain,
                tenzro_vm::native::compute_claim::POSSESSION_PROBE_SAMPLES_PARAM,
            ) as u32,
        });
    }
    None
}

/// The sampling an inference probe runs under: greedy, so the emitted tokens
/// are fixed by the logits.
pub(crate) fn probe_sampling(max_tokens: u32) -> SamplingParams {
    SamplingParams {
        seed: 0,
        temperature: 0.0,
        top_p: 1.0,
        top_k: None,
        min_p: None,
        max_output_tokens: max_tokens,
        keyed_sampler: false,
    }
}

/// Units of verified work per second between `issued_at_ms` and
/// `received_at_ms`, on the validator's clock.
fn per_second(units: u64, issued_at_ms: i64, received_at_ms: i64) -> u64 {
    let elapsed = (received_at_ms - issued_at_ms).max(1) as u64;
    units.saturating_mul(1_000) / elapsed
}

/// The capacity a response shows, once its work checks out. `None` when the
/// probe asked for no work or the work does not verify, in which case the
/// probe measured nothing.
pub fn measure(
    probe: &SlaProbe,
    response: &SlaResponse<impl tenzro_model::SlaSignature>,
    issued_at_ms: i64,
    received_at_ms: i64,
    trie: &StateTrie,
    commitments: Option<&ChallengeManager>,
) -> Option<u64> {
    match (probe.work.as_ref()?, response.result.as_ref()?) {
        (
            CapacityWork::Inference {
                model_id,
                max_tokens,
            },
            CapacityResult::Inference {
                commitment,
                output_tokens,
            },
        ) => {
            let commitment: tenzro_model::toploc::InferenceCommitment =
                bincode::deserialize(commitment).ok()?;
            if *output_tokens == 0
                || *output_tokens > (*max_tokens).min(MAX_PROBE_TOKENS)
                || commitment.steps.len() != *output_tokens as usize
            {
                return None;
            }
            // The tokens must follow from the committed logits under greedy
            // sampling; whether the logits are the model's is what an
            // inference challenge settles.
            let check =
                crate::decode_check::check_decode(&commitment, &probe_sampling(*max_tokens));
            if check.pass != Some(true) {
                debug!(provider = %probe.provider_did, ?check, "inference probe decode inconsistent");
                return None;
            }
            if let Some(store) = commitments
                && let Err(e) = store.store_commitment(model_id, &probe.provider_did, &commitment)
            {
                debug!(provider = %probe.provider_did, error = %e, "could not keep probe commitment");
                return None;
            }
            Some(per_second(
                *output_tokens as u64,
                issued_at_ms,
                received_at_ms,
            ))
        }
        (
            CapacityWork::StateReads { height, count },
            CapacityResult::StateReads { root, entries },
        ) => {
            let ours = trie.root_at(*height).ok()??;
            let scheme = trie.scheme_at(*height).ok()?;
            if ours.as_bytes() != root.as_slice() {
                return None;
            }
            let keys = state_read_keys(&probe.challenge_nonce, *count);
            if keys.is_empty() || entries.len() != keys.len() {
                return None;
            }
            let all_verify = keys.iter().zip(entries).all(|(key, entry)| {
                bincode::deserialize::<tenzro_storage::StateProof>(&entry.proof)
                    .ok()
                    .is_some_and(|proof| {
                        tenzro_storage::verify_state_proof(
                            scheme,
                            root,
                            STATE_READ_NAMESPACE,
                            key,
                            entry.value.as_deref(),
                            &proof,
                        )
                        .is_ok()
                    })
            });
            all_verify.then(|| per_second(keys.len() as u64, issued_at_ms, received_at_ms))
        }
        (CapacityWork::Matmul { n, rows }, CapacityResult::Matmul(proof)) => {
            if !tenzro_model::freivalds::verify(&probe.challenge_nonce, *n, *rows, proof) {
                return None;
            }
            Some(
                per_second(
                    tenzro_model::freivalds::work_units(*n),
                    issued_at_ms,
                    received_at_ms,
                ) / 1_000_000,
            )
        }
        _ => None,
    }
}

/// Whether a proof that arrived `answered_in_ms` after its probe went out
/// is in time for `claim`: within the deadline of the storage class the
/// claim sold. A claim with no class deadline in force, and an answer this
/// validator kept no issue time for, are held to the probe window alone:
/// a record this validator lost is not the holder's lateness.
fn in_class_time(
    chain: &dyn VmState,
    claim: &tenzro_vm::native::compute_claim::ClaimRecord,
    answered_in_ms: Option<i64>,
) -> bool {
    tenzro_vm::native::storage_class::response_deadline_ms(chain, claim)
        .is_none_or(|deadline| answered_in_ms.is_none_or(|ms| ms <= deadline as i64))
}

/// The storage claims due from `probe`'s bond at `at_ms` that `deals`
/// proves: the descriptor matches the one the claim committed, the proof
/// answers this probe's nonce for that claim, and it arrived within the
/// claim's class deadline.
fn proven_claims(
    chain: &dyn VmState,
    probe: &SlaProbe,
    deals: &[tenzro_model::PossessionDeal],
    samples: u32,
    at_ms: i64,
    answered_in_ms: Option<i64>,
) -> Vec<(
    tenzro_vm::native::compute_claim::ClaimRecord,
    tenzro_storage_provider::DescriptorShards,
)> {
    use sha2::Digest;
    let due =
        tenzro_vm::native::compute_claim::storage_claims_due(chain, &probe.provider_did, at_ms);
    let mut out = Vec::new();
    for claim in due {
        if !in_class_time(chain, &claim, answered_in_ms) {
            continue;
        }
        let Some(deal) = deals
            .iter()
            .take(tenzro_model::MAX_POSSESSION_DEALS)
            .find(|d| d.claim_id == claim.claim_id)
        else {
            continue;
        };
        if claim.storage_descriptor.as_deref()
            != Some(hex::encode(sha2::Sha256::digest(&deal.descriptor)).as_str())
        {
            continue;
        }
        let (Ok(descriptor), Ok(pdp)) = (
            bincode::deserialize::<tenzro_storage_provider::DescriptorShards>(&deal.descriptor),
            bincode::deserialize::<tenzro_storage_provider::PdpProof>(&deal.proof),
        ) else {
            continue;
        };
        let challenge = tenzro_storage_provider::PdpChallenge {
            object_id: descriptor.object_id.clone(),
            nonce: tenzro_model::possession_nonce(&probe.challenge_nonce, &claim.claim_id),
            samples: samples as usize,
        };
        if tenzro_storage_provider::verify(
            &descriptor.object_id,
            &descriptor.shards,
            &challenge,
            &pdp,
        )
        .is_ok()
        {
            out.push((claim, descriptor));
        }
    }
    out
}

/// Whether a response keeps every storage claim `probe`'s bond delivers this
/// hour: each due object is proven, within the deadline of the class it was
/// sold in when the response took `answered_in_ms` from the probe going out.
/// A bond that delivers storage is found available only while it does.
pub fn possession_kept(
    chain: &dyn VmState,
    probe: &SlaProbe,
    response: &SlaResponse<impl tenzro_model::SlaSignature>,
    at_ms: i64,
    answered_in_ms: Option<i64>,
) -> bool {
    let due =
        tenzro_vm::native::compute_claim::storage_claims_due(chain, &probe.provider_did, at_ms);
    if due.is_empty() {
        return true;
    }
    let (Some(CapacityWork::Possession { samples }), Some(CapacityResult::Possession { deals })) =
        (probe.work.as_ref(), response.result.as_ref())
    else {
        return false;
    };
    proven_claims(chain, probe, deals, *samples, at_ms, answered_in_ms).len()
        == due.len().min(tenzro_model::MAX_POSSESSION_DEALS)
}

/// The retrieval rate a possession response shows once the storage class
/// rule is live: chunks proven in time per second, on the validator's clock
/// from the probe going out. The chain freezes the stake-weighted median
/// with the hour's verdict, which is the holder's measured record. `None`
/// while the rule is dormant or when nothing was proven.
pub fn possession_rate(
    chain: &dyn VmState,
    probe: &SlaProbe,
    response: &SlaResponse<impl tenzro_model::SlaSignature>,
    issued_at_ms: i64,
    received_at_ms: i64,
) -> Option<u64> {
    if !tenzro_vm::feature_gate::is_live_now(chain, tenzro_vm::native::storage_class::KEY) {
        return None;
    }
    let (CapacityWork::Possession { samples }, CapacityResult::Possession { deals }) =
        (probe.work.as_ref()?, response.result.as_ref()?)
    else {
        return None;
    };
    let proven = proven_claims(
        chain,
        probe,
        deals,
        *samples,
        received_at_ms,
        Some(received_at_ms - issued_at_ms),
    )
    .len() as u64;
    (proven > 0).then(|| {
        per_second(
            proven.saturating_mul(u64::from(*samples)),
            issued_at_ms,
            received_at_ms,
        )
    })
}

/// Work a burst challenge asks a claimed compute unit for: a matrix
/// product cheap to verify and expensive enough to compute that one real
/// accelerator cannot produce it for more claimed units than it actually
/// has within a single SLA window.
pub fn burst_work() -> CapacityWork {
    CapacityWork::Matmul {
        n: PROBE_MATRIX_DIMENSION,
        rows: PROBE_OPENED_ROWS,
    }
}

/// Whether a response's content backs the provider's availability for
/// `probe`, given its signature and timing already checked out under
/// [`tenzro_model::SlaManager::score_response`]. A probe that asked for no
/// work needs nothing more than that. One that asked for possessed storage
/// is available only while [`possession_kept`] holds. Any other verifiable
/// work — the matrix product a burst challenge asks a compute bond for, in
/// particular — is available only while `measured` carries a value: a
/// provider that signs on time but returns nothing genuine for the work
/// itself is not running what it claims, even though the signature alone
/// would otherwise count it available.
pub fn capacity_kept(
    chain: &dyn VmState,
    probe: &SlaProbe,
    response: &SlaResponse<impl tenzro_model::SlaSignature>,
    at_ms: i64,
    answered_in_ms: Option<i64>,
    measured: Option<u64>,
) -> bool {
    match probe.work.as_ref() {
        None => true,
        Some(CapacityWork::Possession { .. }) => {
            possession_kept(chain, probe, response, at_ms, answered_in_ms)
        }
        Some(_) => measured.is_some(),
    }
}

/// Provider side: do the work a probe asks for, with this node's model
/// runtime and committed state. `None` when this node cannot, which the
/// validator scores as no capacity measured. The light build has no model
/// runtime, so it answers no inference work.
pub async fn perform(
    #[cfg(feature = "inference")] runtime: Option<&Arc<tenzro_model::ModelRuntime>>,
    storage: Option<&Arc<dyn KvStore>>,
    storage_runtime: Option<&Arc<crate::storage_provider_runtime::StorageProviderRuntime>>,
    probe: &SlaProbe,
) -> Option<CapacityResult> {
    match probe.work.as_ref()? {
        CapacityWork::Inference {
            model_id,
            max_tokens,
        } => {
            #[cfg(feature = "inference")]
            {
                let runtime = runtime?;
                let config = tenzro_model::GenerationConfig {
                    max_tokens: (*max_tokens).min(MAX_PROBE_TOKENS),
                    temperature: 0.0,
                    commitment_k: Some(tenzro_model::DEFAULT_COMMITMENT_K),
                    ..Default::default()
                };
                let result = runtime
                    .generate(model_id, &inference_prompt(&probe.challenge_nonce), &config)
                    .await
                    .ok()?;
                let commitment = result.commitment?;
                Some(CapacityResult::Inference {
                    output_tokens: commitment.steps.len() as u32,
                    commitment: bincode::serialize(&commitment).ok()?,
                })
            }
            #[cfg(not(feature = "inference"))]
            {
                let _ = (model_id, max_tokens);
                None
            }
        }
        CapacityWork::Matmul { n, rows } => {
            if *n > tenzro_model::freivalds::MAX_DIMENSION
                || *rows > tenzro_model::freivalds::MAX_OPENED_ROWS
            {
                return None;
            }
            let (nonce, n, rows) = (probe.challenge_nonce, *n, *rows);
            let proof = tokio::task::spawn_blocking(move || {
                tenzro_model::freivalds::prove(&nonce, n, rows)
            })
            .await
            .ok()?;
            Some(CapacityResult::Matmul(proof))
        }
        CapacityWork::Possession { samples } => {
            // Possession of data already held is answered whether or not the
            // storage role is served now: its deals and claims still stand.
            let runtime = storage_runtime?;
            let chain = tenzro_vm::StateAdapter::with_storage(storage?.clone());
            let now = chrono::Utc::now().timestamp_millis();
            let mut deals = Vec::new();
            for claim in tenzro_vm::native::compute_claim::storage_claims_due(
                &chain,
                &probe.provider_did,
                now,
            )
            .into_iter()
            .take(tenzro_model::MAX_POSSESSION_DEALS)
            {
                let Some(digest) = claim.storage_descriptor.as_deref() else {
                    continue;
                };
                let Some((descriptor, encoded)) = runtime.descriptor_by_digest(digest) else {
                    continue;
                };
                let challenge = tenzro_storage_provider::PdpChallenge {
                    object_id: descriptor.object_id.clone(),
                    nonce: tenzro_model::possession_nonce(&probe.challenge_nonce, &claim.claim_id),
                    samples: *samples as usize,
                };
                let Some(proof) = runtime.prove_possession(&descriptor, &challenge).await else {
                    continue;
                };
                deals.push(tenzro_model::PossessionDeal {
                    claim_id: claim.claim_id,
                    descriptor: encoded,
                    proof: bincode::serialize(&proof).ok()?,
                });
            }
            Some(CapacityResult::Possession { deals })
        }
        CapacityWork::StateReads { height, count } => {
            let trie = StateTrie::new(storage?.clone());
            let root = trie.root_at(*height).ok()??;
            let mut entries = Vec::new();
            for key in state_read_keys(&probe.challenge_nonce, *count) {
                let (value, proof) = trie.prove(*height, STATE_READ_NAMESPACE, &key).ok()?;
                entries.push(StateReadEntry {
                    value,
                    proof: bincode::serialize(&proof).ok()?,
                });
            }
            let mut root_bytes = [0u8; 32];
            root_bytes.copy_from_slice(root.as_bytes());
            Some(CapacityResult::StateReads {
                root: root_bytes,
                entries,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The sample count a possession probe carries at genesis.
    const POSSESSION_SAMPLES: u32 =
        tenzro_vm::native::compute_claim::DEFAULT_POSSESSION_PROBE_SAMPLES as u32;

    #[test]
    fn the_largest_possession_answer_fits_one_gossip_message() {
        // Worst case: every sample's shard is 2^32 chunks deep, every deal
        // carries a descriptor of 8 KiB, and the answer carries the most
        // deals a probe may; 64 KiB stays for the rest of the envelope.
        let samples = tenzro_vm::native::compute_claim::MAX_POSSESSION_PROBE_SAMPLES as usize;
        let proof = tenzro_storage_provider::PdpProof {
            object_id: "o".repeat(64),
            items: (0..samples)
                .map(|i| tenzro_storage_provider::PdpItem {
                    shard: i,
                    chunk: i as u64,
                    bytes: vec![0; tenzro_storage_provider::pdp::CHUNK_SIZE],
                    path: vec![[0; 32]; 32],
                })
                .collect(),
        };
        let deals: Vec<tenzro_model::PossessionDeal> = (0..tenzro_model::MAX_POSSESSION_DEALS)
            .map(|i| tenzro_model::PossessionDeal {
                claim_id: format!("{i:064}"),
                descriptor: vec![0; 8 * 1024],
                proof: bincode::serialize(&proof).unwrap(),
            })
            .collect();
        let size = bincode::serialize(&deals).unwrap().len();
        assert!(
            size + 64 * 1024 <= tenzro_iroh::gossip::MAX_GOSSIP_MESSAGE,
            "{size} bytes"
        );
    }

    #[test]
    fn throughput_is_measured_on_the_validators_clock() {
        assert_eq!(per_second(64, 1_000, 2_000), 64);
        assert_eq!(per_second(16, 0, 500), 32);
        // A response stamped before the probe went out cannot divide by zero.
        assert_eq!(per_second(10, 5_000, 4_000), 10_000);
    }

    const HOUR: i64 = tenzro_vm::native::MARKET_EPOCH_MS;

    async fn claim_tx(
        executor: &tenzro_vm::NativeExecutor,
        chain: &mut tenzro_vm::StateAdapter,
        from: &[u8],
        op: tenzro_types::transaction::ComputeClaimOp,
    ) {
        use tenzro_vm::VmExecutor as _;
        let mut data = tenzro_vm::native::SELECTOR_COMPUTE_CLAIM.to_vec();
        data.extend(serde_json::to_vec(&op).unwrap());
        let mut tx = tenzro_vm::types::VmTransaction::new(
            from.to_vec(),
            None,
            0,
            data,
            1_000_000,
            0,
            0,
            tenzro_vm::VmType::Tenzro,
            1337,
        );
        tx.block_timestamp_ms = Some(5 * HOUR);
        let result = executor.execute_transaction(&tx, chain).await.unwrap();
        assert!(result.success, "{op:?}");
    }

    /// A plaintext object of four shards and its descriptor.
    fn stored_object() -> (Vec<Vec<u8>>, tenzro_storage_provider::ObjectDescriptor) {
        let shards: Vec<Vec<u8>> = (0..4u8)
            .map(|i| (0..5000u32).map(|b| (b as u8).wrapping_add(i)).collect())
            .collect();
        let descriptor = tenzro_storage_provider::ObjectDescriptor {
            object_id: "obj".into(),
            owner_hex: "00".into(),
            size_bytes: 20_000,
            scheme: tenzro_storage_provider::RedundancyScheme::erasure(2, 2).unwrap(),
            shards: shards
                .iter()
                .enumerate()
                .map(|(index, bytes)| {
                    let (chunk_root, chunk_count) =
                        tenzro_storage_provider::pdp::chunk_commitment(bytes);
                    tenzro_storage_provider::ShardRef {
                        index,
                        uri: format!("tenzro://blob/{index}"),
                        commitment: String::new(),
                        chunk_root,
                        chunk_count,
                    }
                })
                .collect(),
            access_policy: tenzro_types::access_policy::AccessPolicy::OwnerOnly {
                owner_did: "did:tenzro:human:owner".into(),
            },
            confidential: None,
        };
        (shards, descriptor)
    }

    /// A storage claim for `descriptor` in `unit` (a gibibyte of it when
    /// given), written by the bond `did:store` and bought, delivering from
    /// hour 10, and its claim id.
    async fn held_storage_claim(
        descriptor: &tenzro_storage_provider::ObjectDescriptor,
        unit: Option<&str>,
    ) -> (tenzro_vm::StateAdapter, String) {
        use sha2::Digest;
        use tenzro_vm::VmState as _;
        let digest = hex::encode(sha2::Sha256::digest(
            bincode::serialize(descriptor).unwrap(),
        ));
        let executor = tenzro_vm::NativeExecutor::new(tenzro_vm::VmConfig::default()).unwrap();
        let mut chain = tenzro_vm::StateAdapter::new();
        let (writer, buyer) = ([1u8; 32], [2u8; 32]);
        chain.set_balance(&writer, 1_000_000);
        chain.set_balance(&buyer, 1_000_000);
        chain.set_storage(
            &tenzro_vm::native::SYSTEM_ADDRESS,
            b"compute_bond:did:store",
            serde_json::to_vec(&serde_json::json!({ "provider_address": hex::encode(writer) }))
                .unwrap(),
        );
        let offer = tenzro_types::transaction::ComputeClaimOp::Offer {
            hardware_class: 3,
            region: String::new(),
            delivery_start_ms: 10 * HOUR,
            epochs: 3,
            strike_per_epoch: 100,
            collateral: 150,
            provider_did: "did:store".into(),
            storage_descriptor: Some(digest),
            unit: unit.map(str::to_string),
            units_per_epoch: if unit.is_some() { 1 << 30 } else { 0 },
        };
        claim_tx(&executor, &mut chain, &writer, offer).await;
        let claim_id = tenzro_vm::native::compute_claim::claim_id_for(&writer, 0);
        let accept = tenzro_types::transaction::ComputeClaimOp::Accept {
            claim_id: claim_id.clone(),
            max_total: 300,
            placement: None,
        };
        claim_tx(&executor, &mut chain, &buyer, accept).await;
        (chain, claim_id)
    }

    /// A possession probe of `did:store` and the holder's signed answer, as
    /// [`perform`] builds it: the descriptor's bincode bytes and a proof of
    /// the object at the probe's positions.
    fn possession_answer(
        claim_id: &str,
        shards: &[Vec<u8>],
        descriptor: &tenzro_storage_provider::ObjectDescriptor,
        at_ms: i64,
    ) -> (SlaProbe, SlaResponse) {
        let mgr = tenzro_model::SlaManager::new(
            tenzro_crypto::keys::Address::new([1u8; 20]),
            tenzro_crypto::vrf::VrfSecretKey([9u8; 32]),
        );
        let probe = mgr
            .issue_probe(
                None,
                "did:store",
                0,
                0,
                at_ms + 60_000,
                Some(CapacityWork::Possession {
                    samples: POSSESSION_SAMPLES,
                }),
            )
            .unwrap();
        let challenge = tenzro_storage_provider::PdpChallenge {
            object_id: descriptor.object_id.clone(),
            nonce: tenzro_model::possession_nonce(&probe.challenge_nonce, claim_id),
            samples: POSSESSION_SAMPLES as usize,
        };
        let proof = tenzro_storage_provider::prove(&challenge, &descriptor.shards, |i| {
            Ok(shards[i].clone())
        })
        .unwrap();
        let deals = vec![tenzro_model::PossessionDeal {
            claim_id: claim_id.into(),
            descriptor: bincode::serialize(descriptor).unwrap(),
            proof: bincode::serialize(&proof).unwrap(),
        }];
        let signer = tenzro_crypto::batch::ImmediateRecordSigner::new(std::sync::Arc::new(
            tenzro_crypto::testing::TestHybridSigner::random(),
        ));
        let response = tenzro_model::SlaManager::build_response(
            &probe,
            tenzro_types::primitives::Address::new([2u8; 32]),
            &signer,
            at_ms,
            Some(CapacityResult::Possession { deals }),
        )
        .unwrap();
        (probe, response)
    }

    /// A holder that proves the object its storage claim commits to keeps
    /// the hour, and one that answers with another object's proof does not.
    /// The validator reads the proof against the descriptor's shards; it
    /// cannot read the whole descriptor back from its bincode bytes.
    #[tokio::test]
    async fn a_proven_object_keeps_its_storage_claim() {
        let (shards, descriptor) = stored_object();
        let encoded = bincode::serialize(&descriptor).unwrap();
        assert!(
            bincode::deserialize::<tenzro_storage_provider::ObjectDescriptor>(&encoded).is_err(),
            "the whole descriptor does not read back from bincode"
        );
        let (chain, claim_id) = held_storage_claim(&descriptor, None).await;
        let at = 10 * HOUR + 1_000;
        let (probe, response) = possession_answer(&claim_id, &shards, &descriptor, at);
        assert!(possession_kept(&chain, &probe, &response, at, None));
        assert!(capacity_kept(&chain, &probe, &response, at, None, None));

        let mut other = descriptor.clone();
        other.shards[0].chunk_root = "00".repeat(32);
        let (probe, response) = possession_answer(&claim_id, &shards, &other, at);
        assert!(
            !possession_kept(&chain, &probe, &response, at, None),
            "a descriptor the claim did not commit to proves nothing"
        );
    }

    fn storage_claim(unit: Option<&str>) -> tenzro_vm::native::compute_claim::ClaimRecord {
        tenzro_vm::native::compute_claim::ClaimRecord {
            claim_id: "claim".into(),
            writer: String::new(),
            holder: None,
            hardware_class: 1,
            region: String::new(),
            delivery_start_ms: 0,
            epochs: 1,
            strike_per_epoch: 1,
            provider_did: "did:store".into(),
            storage_descriptor: Some("ab".repeat(32)),
            unit: unit.map(str::to_string),
            units_per_epoch: 1 << 30,
            epochs_settled: 0,
            collateral: 0,
            payment: 0,
            placement: None,
            state: tenzro_vm::native::compute_claim::ClaimState::Held,
        }
    }

    fn set_param(chain: &mut tenzro_vm::StateAdapter, key: &str, value: u64) {
        chain.set_storage(
            &tenzro_vm::native::SYSTEM_ADDRESS,
            tenzro_vm::native::governed_param_key(key).as_bytes(),
            value.to_le_bytes().to_vec(),
        );
    }

    /// A proof for a hot claim that arrives after the hot deadline counts
    /// while the class rule is dormant and stops counting once it is live;
    /// the same delay still meets the cold deadline, and a claim with no
    /// class is held to the probe window alone on both sides.
    #[test]
    fn a_late_proof_misses_its_class_only_once_the_rule_is_live() {
        use tenzro_vm::native::storage_class::{KEY, StorageClass};
        let (hot, cold, classless) = (
            storage_claim(Some("stored_bytes@hot")),
            storage_claim(Some("stored_bytes@cold")),
            storage_claim(None),
        );
        let mut chain = tenzro_vm::StateAdapter::new();
        set_param(&mut chain, StorageClass::Hot.deadline_param(), 2_000);
        set_param(&mut chain, StorageClass::Cold.deadline_param(), 20_000);
        let late = Some(5_000);

        for claim in [&hot, &cold, &classless] {
            assert!(in_class_time(&chain, claim, late), "dormant");
            assert!(in_class_time(&chain, claim, None), "dormant, untimed");
        }

        set_param(&mut chain, KEY, 0);
        assert!(in_class_time(&chain, &hot, Some(2_000)), "on the deadline");
        assert!(!in_class_time(&chain, &hot, late), "past the hot deadline");
        assert!(
            in_class_time(&chain, &hot, None),
            "an answer this validator kept no issue time for is held to the window alone"
        );
        assert!(in_class_time(&chain, &cold, late));
        assert!(in_class_time(&chain, &classless, late));
        assert!(in_class_time(&chain, &classless, None));
    }

    /// An object of a hot claim proven in time keeps the hour; the same
    /// proof past the hot deadline loses it once the rule is live, and keeps
    /// it while the rule is dormant; the rate is reported only once live,
    /// and only for what was proven in time.
    #[tokio::test]
    async fn a_hot_claim_is_kept_only_by_a_proof_inside_its_deadline() {
        use tenzro_vm::native::storage_class::{KEY, StorageClass};
        let (shards, descriptor) = stored_object();
        let (mut chain, claim_id) = held_storage_claim(&descriptor, Some("stored_bytes@hot")).await;
        let at = 10 * HOUR + 1_000;
        let (probe, response) = possession_answer(&claim_id, &shards, &descriptor, at);
        set_param(&mut chain, StorageClass::Hot.deadline_param(), 5_000);

        assert!(
            possession_kept(&chain, &probe, &response, at, Some(6_000)),
            "dormant"
        );
        assert_eq!(
            possession_rate(&chain, &probe, &response, at - 2_000, at),
            None
        );

        set_param(&mut chain, KEY, 0);
        assert!(possession_kept(&chain, &probe, &response, at, Some(2_000)));
        assert!(possession_kept(&chain, &probe, &response, at, Some(5_000)));
        assert!(!possession_kept(&chain, &probe, &response, at, Some(6_000)));
        assert!(
            possession_kept(&chain, &probe, &response, at, None),
            "untimed"
        );
        assert_eq!(
            possession_rate(&chain, &probe, &response, at - 2_000, at),
            Some(per_second(POSSESSION_SAMPLES.into(), at - 2_000, at))
        );
        assert_eq!(
            possession_rate(&chain, &probe, &response, at - 6_000, at),
            None
        );
    }

    /// The same delay meets the cold deadline.
    #[tokio::test]
    async fn a_cold_claim_is_kept_by_a_proof_a_hot_one_would_lose() {
        use tenzro_vm::native::storage_class::{KEY, StorageClass};
        let (shards, descriptor) = stored_object();
        let (mut chain, claim_id) =
            held_storage_claim(&descriptor, Some("stored_bytes@cold")).await;
        let at = 10 * HOUR + 1_000;
        let (probe, response) = possession_answer(&claim_id, &shards, &descriptor, at);
        set_param(&mut chain, StorageClass::Cold.deadline_param(), 20_000);
        set_param(&mut chain, KEY, 0);
        assert!(possession_kept(&chain, &probe, &response, at, Some(6_000)));
        assert!(!possession_kept(
            &chain,
            &probe,
            &response,
            at,
            Some(21_000)
        ));
    }

    fn matmul_probe_and_signer() -> (
        tenzro_model::SlaManager,
        tenzro_model::SlaProbe,
        tenzro_crypto::batch::ImmediateRecordSigner,
        tenzro_types::primitives::Address,
    ) {
        use tenzro_crypto::testing::TestHybridSigner;
        use tenzro_crypto::vrf::VrfSecretKey;

        let mgr = tenzro_model::SlaManager::new(
            tenzro_crypto::keys::Address::new([1u8; 20]),
            VrfSecretKey([9u8; 32]),
        );
        let probe = mgr
            .issue_probe(None, "unit-0", 0, 0, 10_000, Some(burst_work()))
            .unwrap();
        let signer = tenzro_crypto::batch::ImmediateRecordSigner::new(std::sync::Arc::new(
            TestHybridSigner::random(),
        ));
        let provider_address = tenzro_types::primitives::Address::new([2u8; 32]);
        (mgr, probe, signer, provider_address)
    }

    fn empty_trie() -> tenzro_storage::StateTrie {
        let store: std::sync::Arc<dyn tenzro_storage::KvStore> =
            std::sync::Arc::new(tenzro_storage::MemoryStore::new());
        tenzro_storage::StateTrie::new(store)
    }

    /// A provider that signs its burst challenge on time but returns no
    /// genuine matrix proof — the shape of a device backing more claimed
    /// units than it has, once it runs out of real capacity to answer with
    /// — still counted as available before this gate existed: possession
    /// checking has nothing to say about compute work, so the old gate
    /// waved it through on the signature alone.
    #[test]
    fn a_response_with_no_capacity_result_is_not_kept() {
        let (_mgr, probe, signer, addr) = matmul_probe_and_signer();
        let response =
            tenzro_model::SlaManager::build_response(&probe, addr, &signer, 2_000, None).unwrap();
        let trie = empty_trie();
        let measured = measure(&probe, &response, 0, 2_000, &trie, None);
        assert_eq!(measured, None, "no work was returned, so none verifies");

        let chain = tenzro_vm::StateAdapter::new();
        assert!(
            possession_kept(&chain, &probe, &response, 2_000, None),
            "the old storage-only gate has nothing due and waves this through"
        );
        assert!(
            !capacity_kept(&chain, &probe, &response, 2_000, None, measured),
            "the new gate requires the work itself to verify"
        );
    }

    /// A bogus matrix proof — signed on time, wrong content — is caught the
    /// same way as no proof at all.
    #[test]
    fn a_bogus_matmul_proof_is_not_kept() {
        let (_mgr, probe, signer, addr) = matmul_probe_and_signer();
        let bogus = tenzro_model::CapacityResult::Matmul(tenzro_model::freivalds::MatmulProof {
            root: [0u8; 32],
            rows: Vec::new(),
        });
        let response =
            tenzro_model::SlaManager::build_response(&probe, addr, &signer, 2_000, Some(bogus))
                .unwrap();
        let trie = empty_trie();
        let measured = measure(&probe, &response, 0, 2_000, &trie, None);
        assert_eq!(measured, None, "a bogus proof must not verify");

        let chain = tenzro_vm::StateAdapter::new();
        assert!(possession_kept(&chain, &probe, &response, 2_000, None));
        assert!(!capacity_kept(
            &chain, &probe, &response, 2_000, None, measured
        ));
    }

    /// A genuine matrix proof keeps the provider available, exactly as
    /// before this gate existed — the fix changes nothing for a provider
    /// that actually does the work.
    #[test]
    fn a_genuine_matmul_proof_is_kept() {
        let (_mgr, probe, signer, addr) = matmul_probe_and_signer();
        let CapacityWork::Matmul { n, rows } = probe.work.clone().unwrap() else {
            unreachable!()
        };
        let proof = tenzro_model::freivalds::prove(&probe.challenge_nonce, n, rows);
        let response = tenzro_model::SlaManager::build_response(
            &probe,
            addr,
            &signer,
            2_000,
            Some(tenzro_model::CapacityResult::Matmul(proof)),
        )
        .unwrap();
        let trie = empty_trie();
        let measured = measure(&probe, &response, 0, 2_000, &trie, None);
        assert!(measured.is_some(), "a genuine proof verifies");

        let chain = tenzro_vm::StateAdapter::new();
        assert!(capacity_kept(
            &chain, &probe, &response, 2_000, None, measured
        ));
    }

    /// The scenario a burst challenge exists for: one operator claims `n +
    /// k` units but only `n` are genuinely separate accelerators. All get
    /// the same matrix challenge in the same round under the same
    /// deadline. The `n` real ones each answer their own; the `k`
    /// over-claimed ones, once the single device behind them has spent
    /// itself on the real units, have nothing genuine left to answer with.
    /// Tallied the same way `execute_sla_attest` reads outcomes, the real
    /// units come back available and the over-claimed ones do not.
    #[test]
    fn a_burst_separates_real_units_from_over_claimed_ones() {
        use tenzro_crypto::testing::TestHybridSigner;
        use tenzro_crypto::vrf::VrfSecretKey;

        let mgr = tenzro_model::SlaManager::new(
            tenzro_crypto::keys::Address::new([1u8; 20]),
            VrfSecretKey([9u8; 32]),
        );
        let chain = tenzro_vm::StateAdapter::new();
        let trie = empty_trie();
        let tally = crate::sla_attest::SlaTally::default();
        let (real_units, over_claimed) = (2usize, 2usize);
        let epoch = 0u64;
        let deadline = 5_000i64;

        for i in 0..(real_units + over_claimed) {
            let did = format!("unit-{i}");
            let probe = mgr
                .issue_probe(None, &did, epoch, 0, deadline, Some(burst_work()))
                .unwrap();
            let signer = tenzro_crypto::batch::ImmediateRecordSigner::new(std::sync::Arc::new(
                TestHybridSigner::random(),
            ));
            let addr = tenzro_types::primitives::Address::new([i as u8; 32]);
            let result = if i < real_units {
                let CapacityWork::Matmul { n, rows } = probe.work.clone().unwrap() else {
                    unreachable!()
                };
                Some(tenzro_model::CapacityResult::Matmul(
                    tenzro_model::freivalds::prove(&probe.challenge_nonce, n, rows),
                ))
            } else {
                None
            };
            let response =
                tenzro_model::SlaManager::build_response(&probe, addr, &signer, 2_000, result)
                    .unwrap();
            let score = tenzro_model::SlaManager::score_response(
                &probe,
                Some(&response),
                2_000,
                Some(signer.identity()),
            );
            assert_eq!(
                score,
                tenzro_model::SlaResult::Ok,
                "signature and timing are fine regardless of claimed unit count"
            );
            let measured = measure(&probe, &response, 0, 2_000, &trie, None);
            assert!(
                possession_kept(&chain, &probe, &response, 2_000, None),
                "the old gate is blind to compute content and keeps every unit"
            );
            let kept = capacity_kept(&chain, &probe, &response, 2_000, None, measured);
            tally.record(&did, epoch, !score.is_failure() && kept);
        }

        let outcomes = tally.take_epoch(epoch, &|_| None, &crate::sla_attest::majority);
        for i in 0..real_units {
            let did = format!("unit-{i}");
            assert!(
                outcomes
                    .iter()
                    .find(|o| o.provider_did == did)
                    .unwrap()
                    .available,
                "a genuinely separate unit passes the burst"
            );
        }
        for i in real_units..(real_units + over_claimed) {
            let did = format!("unit-{i}");
            assert!(
                !outcomes
                    .iter()
                    .find(|o| o.provider_did == did)
                    .unwrap()
                    .available,
                "an over-claimed unit fails the burst and, through take_epoch, the verdict"
            );
        }
    }
}
