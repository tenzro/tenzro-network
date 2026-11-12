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

/// Chunks proven per object in a possession probe.
pub const PROBE_POSSESSION_SAMPLES: u32 = 8;

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
            samples: PROBE_POSSESSION_SAMPLES,
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

/// The storage claims due from `probe`'s bond at `at_ms` that `deals`
/// proves: the descriptor matches the one the claim committed and the proof
/// answers this probe's nonce for that claim.
fn proven_claims(
    chain: &dyn VmState,
    probe: &SlaProbe,
    deals: &[tenzro_model::PossessionDeal],
    samples: u32,
    at_ms: i64,
) -> Vec<(
    tenzro_vm::native::compute_claim::ClaimRecord,
    tenzro_storage_provider::ObjectDescriptor,
)> {
    use sha2::Digest;
    let due =
        tenzro_vm::native::compute_claim::storage_claims_due(chain, &probe.provider_did, at_ms);
    let mut out = Vec::new();
    for claim in due {
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
            bincode::deserialize::<tenzro_storage_provider::ObjectDescriptor>(&deal.descriptor),
            bincode::deserialize::<tenzro_storage_provider::PdpProof>(&deal.proof),
        ) else {
            continue;
        };
        let challenge = tenzro_storage_provider::PdpChallenge {
            object_id: descriptor.object_id.clone(),
            nonce: tenzro_model::possession_nonce(&probe.challenge_nonce, &claim.claim_id),
            samples: samples as usize,
        };
        if tenzro_storage_provider::verify(&descriptor, &challenge, &pdp).is_ok() {
            out.push((claim, descriptor));
        }
    }
    out
}

/// Whether a response keeps every storage claim `probe`'s bond delivers this
/// hour: each due object is proven. A bond that delivers storage is found
/// available only while it does.
pub fn possession_kept(
    chain: &dyn VmState,
    probe: &SlaProbe,
    response: &SlaResponse<impl tenzro_model::SlaSignature>,
    at_ms: i64,
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
    proven_claims(chain, probe, deals, *samples, at_ms).len()
        == due.len().min(tenzro_model::MAX_POSSESSION_DEALS)
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
    measured: Option<u64>,
) -> bool {
    match probe.work.as_ref() {
        None => true,
        Some(CapacityWork::Possession { .. }) => possession_kept(chain, probe, response, at_ms),
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

    #[test]
    fn throughput_is_measured_on_the_validators_clock() {
        assert_eq!(per_second(64, 1_000, 2_000), 64);
        assert_eq!(per_second(16, 0, 500), 32);
        // A response stamped before the probe went out cannot divide by zero.
        assert_eq!(per_second(10, 5_000, 4_000), 10_000);
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
            .issue_probe("unit-0", 0, 0, 10_000, Some(burst_work()))
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
            possession_kept(&chain, &probe, &response, 2_000),
            "the old storage-only gate has nothing due and waves this through"
        );
        assert!(
            !capacity_kept(&chain, &probe, &response, 2_000, measured),
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
        assert!(possession_kept(&chain, &probe, &response, 2_000));
        assert!(!capacity_kept(&chain, &probe, &response, 2_000, measured));
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
        assert!(capacity_kept(&chain, &probe, &response, 2_000, measured));
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
                .issue_probe(&did, epoch, 0, deadline, Some(burst_work()))
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
                possession_kept(&chain, &probe, &response, 2_000),
                "the old gate is blind to compute content and keeps every unit"
            );
            let kept = capacity_kept(&chain, &probe, &response, 2_000, measured);
            tally.record(&did, epoch, !score.is_failure() && kept);
        }

        let outcomes = tally.take_epoch(epoch, &|_| None);
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
