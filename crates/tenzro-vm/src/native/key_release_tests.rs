//! Attestation-bound key release end to end: a provider's encrypted
//! weights, its broker, an operator's attested environment (a TPM-admitted
//! machine with a GPU) and the chain that records and can stop releases.

use super::hardware_level_tests::{NOW_MS, machine};
use super::key_release::{SELECTOR_KEY_RELEASE, read_event, read_model};
use super::*;
use crate::VmType;
use crate::state_adapter::StateAdapter;
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use tenzro_crypto::encryption::SymmetricKey;
use tenzro_crypto::hybrid_seal::HybridSecretKey;
use tenzro_tee::key_release::{ContentKeyHolder, KeyReleaseBroker, ReleaseLedger, Zeroizing};
use tenzro_tee::nvidia_device::testgpu::{MEASUREMENT, SoftGpu};
use tenzro_tee::tpm_attest::tests::{SoftTpm, evidence};
use tenzro_tee::tpm_attest::{TpmEvidence, verify_quote};
use tenzro_types::hardware_level::GpuReferenceValue;
use tenzro_types::key_release::{
    GpuEvidence, KeyReleaseOp, KeyReleasePolicy, ReleaseEvent, ReleaseEvidence, ReleaseRequest,
};

const OWNER: [u8; 32] = [0x70; 32];
const MODEL: &str = "acme/private-7b";
const WEIGHTS: &[u8] = b"private weights: every tensor of the provider's model";

/// The provider's content key, as its hardware-held envelope opens it.
struct Holder([u8; 32]);

impl ContentKeyHolder for Holder {
    fn content_key(&self, _model_id: &str) -> tenzro_tee::Result<Zeroizing<[u8; 32]>> {
        Ok(Zeroizing::new(self.0))
    }
}

/// The chain as the provider's broker sees it: reads from state, and a
/// release recorded by sending the owner's transaction.
struct Chain<'a> {
    ex: &'a NativeExecutor,
    state: &'a mut StateAdapter,
    nonce: u64,
}

fn tx(data: Vec<u8>, nonce: u64) -> VmTransaction {
    let mut t = VmTransaction::new(
        OWNER.to_vec(),
        None,
        0,
        data,
        5_000_000,
        0,
        nonce,
        VmType::Tenzro,
        1337,
    );
    t.block_timestamp_ms = Some(NOW_MS);
    t
}

fn op_data(op: &KeyReleaseOp) -> Vec<u8> {
    let mut d = SELECTOR_KEY_RELEASE.to_vec();
    d.extend(serde_json::to_vec(op).unwrap());
    d
}

impl Chain<'_> {
    async fn send(&mut self, op: &KeyReleaseOp) -> std::result::Result<(), String> {
        let r = self
            .ex
            .execute_transaction(&tx(op_data(op), self.nonce), self.state)
            .await
            .map_err(|e| e.to_string())?;
        if r.success {
            self.nonce += 1;
            Ok(())
        } else {
            Err(r.revert_reason.unwrap_or_default())
        }
    }
}

#[async_trait]
impl ReleaseLedger for Chain<'_> {
    async fn policy(&self, model_id: &str) -> tenzro_tee::Result<Option<(KeyReleasePolicy, bool)>> {
        Ok(read_model(self.state, model_id).map(|m| (m.policy, m.revoked_at_ms.is_some())))
    }

    async fn admitted(&self, operator_did: &str) -> tenzro_tee::Result<TpmEvidence> {
        funding::machine_attestation(self.state, operator_did)
            .map(|a| a.evidence)
            .map_err(tenzro_tee::TeeError::AttestationVerificationFailed)
    }

    async fn gpu_governance(
        &self,
    ) -> tenzro_tee::Result<(Vec<tenzro_tee::x509::Cert>, Vec<(u8, Vec<Vec<u8>>)>)> {
        key_release::gpu_governance(self.state)
            .map_err(tenzro_tee::TeeError::AttestationVerificationFailed)
    }

    async fn record(&mut self, request: &ReleaseRequest) -> tenzro_tee::Result<ReleaseEvent> {
        self.send(&KeyReleaseOp::Release {
            request: request.clone(),
        })
        .await
        .map_err(tenzro_tee::TeeError::AttestationVerificationFailed)?;
        let m = read_model(self.state, &request.model_id).unwrap();
        Ok(read_event(self.state, &request.model_id, m.releases - 1).unwrap())
    }
}

/// The operator's attested environment: its machine's TPM, its GPU, and the
/// release key it made in memory.
struct Environment {
    tpm: SoftTpm,
    gpu: SoftGpu,
    did: String,
    key: HybridSecretKey,
}

impl Environment {
    fn request(&self, challenge: [u8; 32], terms: &[u8]) -> ReleaseRequest {
        let mut request = ReleaseRequest {
            model_id: MODEL.to_string(),
            challenge,
            terms_digest: Sha256::digest(terms).into(),
            release_key: self.key.public().clone(),
            evidence: ReleaseEvidence {
                operator_did: self.did.clone(),
                quote: Vec::new(),
                quote_signature: Vec::new(),
                cvm: None,
                gpu: None,
            },
        };
        let binding = request.binding();
        let (ev, _) = evidence(&self.tpm, &binding);
        request.evidence.quote = ev.quote;
        request.evidence.quote_signature = ev.quote_signature;
        request.evidence.gpu = Some(GpuEvidence {
            report: self.gpu.report(&binding),
            chain: self.gpu.chain.clone(),
        });
        request
    }
}

struct World {
    ex: NativeExecutor,
    state: StateAdapter,
    env: Environment,
    content_key: [u8; 32],
    encrypted: Vec<u8>,
    pcr_digest: String,
}

/// Governance recognises the test GPU root and its one reference value; the
/// operator's machine is admitted with its TPM; the provider encrypts its
/// weights under a fresh content key.
fn world() -> World {
    let mut state = StateAdapter::new();
    let tpm = SoftTpm::new(41);
    let (_, did) = machine(&mut state, 41, &tpm, None);
    let gpu = SoftGpu::new(61, 62);
    let mut changes = Vec::new();
    hardware_level::set_gpu_roots(
        &mut state,
        std::slice::from_ref(&gpu.root_pem),
        &mut changes,
    )
    .unwrap();
    hardware_level::set_gpu_references(
        &mut state,
        &[GpuReferenceValue {
            index: MEASUREMENT.0,
            values: vec![hex::encode(MEASUREMENT.1)],
        }],
        &mut changes,
    )
    .unwrap();
    state.set_balance(&OWNER, 1_000_000_000_000_000_000_000);
    let (probe, _) = evidence(&tpm, &[0; 32]);
    let pcr_digest = hex::encode(verify_quote(&probe, &[0; 32]).unwrap().pcr_digest);
    let content_key = SymmetricKey::generate().to_bytes();
    let encrypted = SymmetricKey::from_bytes(&content_key)
        .unwrap()
        .encrypt(WEIGHTS)
        .unwrap();
    World {
        ex: NativeExecutor::new(crate::config::VmConfig::default()).unwrap(),
        state,
        env: Environment {
            tpm,
            gpu,
            did,
            key: HybridSecretKey::generate(),
        },
        content_key,
        encrypted,
        pcr_digest,
    }
}

fn policy(w: &World, pcr_digest: &str) -> KeyReleasePolicy {
    KeyReleasePolicy {
        manifest_hash: hex::encode(Sha256::digest(&w.encrypted)),
        pcr_digests: vec![pcr_digest.to_string()],
        cvm_measurements: vec![],
        require_gpu: true,
    }
}

async fn register(w: &mut World, policy: KeyReleasePolicy) -> u64 {
    let mut chain = Chain {
        ex: &w.ex,
        state: &mut w.state,
        nonce: 0,
    };
    chain
        .send(&KeyReleaseOp::Register {
            model_id: MODEL.into(),
            policy,
        })
        .await
        .unwrap();
    chain.nonce
}

#[tokio::test]
async fn a_key_is_released_to_a_verifying_environment_and_opens_the_weights() {
    let mut w = world();
    let p = policy(&w, &w.pcr_digest.clone());
    let nonce = register(&mut w, p).await;
    let broker = KeyReleaseBroker::new(Holder(w.content_key));
    let request = w.env.request([7; 32], b"job terms: 1000 completions");
    let mut chain = Chain {
        ex: &w.ex,
        state: &mut w.state,
        nonce,
    };
    let released = broker
        .release(&mut chain, &request, (NOW_MS / 1000) as u64)
        .await
        .expect("a verifying environment gets the key");

    // The release is on chain, bound to the operator, the job's terms and
    // the environment's key.
    let event = read_event(&w.state, MODEL, 0).unwrap();
    assert_eq!(event, released.event);
    assert_eq!(event.operator_did, w.env.did);
    assert_eq!(event.terms_digest, hex::encode(request.terms_digest));
    assert_eq!(
        event.release_key,
        hex::encode(w.env.key.public().fingerprint())
    );
    assert!(event.gpu_device.is_some());
    assert_eq!(read_model(&w.state, MODEL).unwrap().releases, 1);

    // Only the environment's in-memory key opens it, and it opens the
    // weights.
    let key = w
        .env
        .key
        .open(&released.sealed, &request.binding())
        .unwrap();
    let weights = SymmetricKey::from_bytes(&key)
        .unwrap()
        .decrypt(&w.encrypted)
        .unwrap();
    assert_eq!(weights, WEIGHTS);
    assert!(
        HybridSecretKey::generate()
            .open(&released.sealed, &request.binding())
            .is_err()
    );

    // The same binding is not recorded twice.
    let mut chain = Chain {
        ex: &w.ex,
        state: &mut w.state,
        nonce: nonce + 1,
    };
    assert!(
        broker
            .release(&mut chain, &request, (NOW_MS / 1000) as u64)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn a_non_matching_measurement_is_refused() {
    // The operator's measured boot is not the one the policy pins.
    let mut w = world();
    let p = policy(&w, &"00".repeat(32));
    let nonce = register(&mut w, p).await;
    let broker = KeyReleaseBroker::new(Holder(w.content_key));
    let request = w.env.request([7; 32], b"terms");
    let mut chain = Chain {
        ex: &w.ex,
        state: &mut w.state,
        nonce,
    };
    let err = broker
        .release(&mut chain, &request, (NOW_MS / 1000) as u64)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("measured boot"), "{err}");
    // Sent straight to the chain, it is refused there too.
    let refused = chain
        .send(&KeyReleaseOp::Release {
            request: request.clone(),
        })
        .await
        .unwrap_err();
    assert!(refused.contains("measured boot"), "{refused}");
    assert_eq!(read_model(&w.state, MODEL).unwrap().releases, 0);

    // The GPU's measurement is not one governance recognises.
    let mut w = world();
    let p = policy(&w, &w.pcr_digest.clone());
    let nonce = register(&mut w, p).await;
    let mut changes = Vec::new();
    hardware_level::set_gpu_references(
        &mut w.state,
        &[GpuReferenceValue {
            index: MEASUREMENT.0,
            values: vec!["01020304".into()],
        }],
        &mut changes,
    )
    .unwrap();
    let request = w.env.request([8; 32], b"terms");
    let mut chain = Chain {
        ex: &w.ex,
        state: &mut w.state,
        nonce,
    };
    let err = broker
        .release(&mut chain, &request, (NOW_MS / 1000) as u64)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("reference values"), "{err}");
    assert!(
        chain
            .send(&KeyReleaseOp::Release { request })
            .await
            .is_err()
    );
    assert_eq!(read_model(&w.state, MODEL).unwrap().releases, 0);
}

#[tokio::test]
async fn evidence_for_another_operator_or_key_is_refused() {
    let mut w = world();
    let p = policy(&w, &w.pcr_digest.clone());
    let nonce = register(&mut w, p).await;
    let broker = KeyReleaseBroker::new(Holder(w.content_key));
    let mut chain = Chain {
        ex: &w.ex,
        state: &mut w.state,
        nonce,
    };
    // Evidence made for the environment's key, presented with another key.
    let mut swapped = w.env.request([9; 32], b"terms");
    swapped.release_key = HybridSecretKey::generate().public().clone();
    assert!(
        broker
            .release(&mut chain, &swapped, (NOW_MS / 1000) as u64)
            .await
            .is_err()
    );
    // A quote by a TPM that is not the operator's admitted one.
    let mut foreign = w.env.request([10; 32], b"terms");
    let (other, _) = evidence(&SoftTpm::new(77), &foreign.binding());
    foreign.evidence.quote = other.quote;
    foreign.evidence.quote_signature = other.quote_signature;
    assert!(
        broker
            .release(&mut chain, &foreign, (NOW_MS / 1000) as u64)
            .await
            .is_err()
    );
    // A model that never opted in is never released.
    let mut unlisted = w.env.request([11; 32], b"terms");
    unlisted.model_id = "acme/other".into();
    assert!(
        broker
            .release(&mut chain, &unlisted, (NOW_MS / 1000) as u64)
            .await
            .is_err()
    );
    assert_eq!(read_model(&w.state, MODEL).unwrap().releases, 0);
}

#[tokio::test]
async fn no_key_is_released_after_revocation() {
    let mut w = world();
    let p = policy(&w, &w.pcr_digest.clone());
    let nonce = register(&mut w, p.clone()).await;
    let broker = KeyReleaseBroker::new(Holder(w.content_key));
    let mut chain = Chain {
        ex: &w.ex,
        state: &mut w.state,
        nonce,
    };
    broker
        .release(
            &mut chain,
            &w.env.request([1; 32], b"terms"),
            (NOW_MS / 1000) as u64,
        )
        .await
        .expect("released before revocation");
    chain
        .send(&KeyReleaseOp::Revoke {
            model_id: MODEL.into(),
            reason: "operator contract ended".into(),
        })
        .await
        .unwrap();

    let request = w.env.request([2; 32], b"terms");
    let err = broker
        .release(&mut chain, &request, (NOW_MS / 1000) as u64)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("revoked"), "{err}");
    let refused = chain
        .send(&KeyReleaseOp::Release { request })
        .await
        .unwrap_err();
    assert!(refused.contains("revoked"), "{refused}");
    // Revocation is final: the policy cannot be registered back.
    assert!(
        chain
            .send(&KeyReleaseOp::Register {
                model_id: MODEL.into(),
                policy: p,
            })
            .await
            .is_err()
    );
    let m = read_model(&w.state, MODEL).unwrap();
    assert_eq!(m.releases, 1);
    assert!(m.revoked_at_ms.is_some());
}

#[tokio::test]
async fn only_the_policy_owner_records_releases_or_revokes() {
    let mut w = world();
    let p = policy(&w, &w.pcr_digest.clone());
    register(&mut w, p.clone()).await;
    for (n, op) in [
        KeyReleaseOp::Release {
            request: w.env.request([3; 32], b"terms"),
        },
        KeyReleaseOp::Revoke {
            model_id: MODEL.into(),
            reason: "takeover".into(),
        },
        KeyReleaseOp::Register {
            model_id: MODEL.into(),
            policy: p.clone(),
        },
    ]
    .iter()
    .enumerate()
    {
        // A fresh account for each, so no refusal is a nonce mismatch.
        let intruder = [0x71 + n as u8; 32];
        w.state.set_balance(&intruder, 1_000_000_000_000_000_000);
        let mut t = tx(op_data(op), 0);
        t.from = intruder.to_vec();
        let r = w.ex.execute_transaction(&t, &mut w.state).await;
        assert!(
            !matches!(r, Ok(ref r) if r.success),
            "another account's {op:?} is refused"
        );
    }
    assert_eq!(
        read_model(&w.state, MODEL).unwrap().owner,
        hex::encode(OWNER)
    );
}
