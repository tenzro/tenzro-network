//! The node's batch signing: its machine identity key, in hardware, signs
//! the Merkle root of the records waiting for a signature (see
//! `tenzro_crypto::batch`). A timer thread drives the flush interval; no
//! private key is held in this process.

use std::sync::{Arc, Weak};
use std::time::Duration;

use tenzro_crypto::batch::{BatchParams, BatchService};
use tenzro_crypto::composite::HybridSigner;
use std::sync::atomic::Ordering;
use tracing::{error, info, warn};

/// What bounds batch signing. Governed by node configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchSigningParams {
    /// A batch of this many records is signed at once.
    pub max_batch: usize,
    /// A non-empty batch is signed when its oldest record has waited this long.
    pub flush_interval_ms: u64,
    /// The least time between two immediate (unbatched) hardware signatures.
    pub immediate_min_interval_ms: u64,
    /// How long a caller waits, beyond the flush interval, for the hardware
    /// to answer. A hardware TPM takes seconds per signature.
    pub hardware_budget_ms: u64,
    /// The governed moment (`records.pq_leg_required_from_ms`, ms since the
    /// Unix epoch) from which the identity key must carry a native ML-DSA-65
    /// leg. The node reads it from chain state, or from the genesis before
    /// there is any. The highest value means never.
    pub pq_required_from_ms: u64,
}

impl Default for BatchSigningParams {
    fn default() -> Self {
        Self {
            max_batch: 32,
            flush_interval_ms: 2_000,
            immediate_min_interval_ms: 1_000,
            hardware_budget_ms: 15_000,
            pq_required_from_ms: u64::MAX,
        }
    }
}

impl BatchSigningParams {
    /// How long a record waits for its batch signature.
    pub fn receipt_wait(&self) -> Duration {
        Duration::from_millis(
            self.flush_interval_ms
                .saturating_add(self.hardware_budget_ms),
        )
    }
}

/// Opens a machine identity key: `label` in hardware, as the platform or the
/// key holder (and through it the providers' TPMs) hands it out.
pub type IdentityOpener = Box<dyn FnOnce(&str) -> Result<Arc<dyn HybridSigner>, String> + Send>;

/// Why batch signing cannot start. A node that gets one refuses to start; it
/// does not run with unsigned records.
pub fn refusal_no_identity() -> String {
    "this node has no machine identity key in hardware and no provider set to hold it. A \
     TPM-less machine reaches its key in a provider's TPM through the key holder \
     (`tenzro-node tpm key-holder`, then `--tpm-key-holder`); a machine with a TPM 2.0 or \
     Secure Enclave opens its own. There is no keyless mode: records are never left unsigned."
        .to_string()
}

pub fn refusal_no_post_quantum_leg() -> String {
    "the machine identity key has no ML-DSA-65 leg. Tenzro signs every record with both a \
     classical and a post-quantum signature, so that a break of either leaves the signature \
     standing; a key with only P-256 cannot do that. Provision the hardware ML-DSA-65 key \
     (`tenzro-node tpm provision`) or use a provider whose TPM derives one."
        .to_string()
}

/// Builds the batch service from the identity openers, tried in order: the
/// first that opens is used (a provider that is down is skipped). `has_local`
/// is whether this machine has a TPM or Secure Enclave, `provider_set`
/// whether a provider set holds the key instead.
pub fn build_batch_service(
    label: &str,
    params: BatchSigningParams,
    has_local: bool,
    provider_set: bool,
    openers: Vec<IdentityOpener>,
) -> Result<Arc<BatchService>, String> {
    if !has_local && !provider_set {
        return Err(refusal_no_identity());
    }
    let mut why = Vec::new();
    let mut identity = None;
    for open in openers {
        match open(label) {
            Ok(i) => {
                identity = Some(i);
                break;
            }
            Err(e) => why.push(e),
        }
    }
    let Some(identity) = identity else {
        return Err(format!(
            "the machine identity key does not open ({}); a node does not start without it",
            if why.is_empty() {
                "no provider configured".to_string()
            } else {
                why.join("; ")
            }
        ));
    };
    // The native ML-DSA-65 leg is required from the governed moment on. Before
    // it a node signs with the classical leg its hardware holds, and with the
    // ML-DSA leg when the hardware provides one; a software key never stands
    // in for it.
    if identity.public_key().pq.is_none() {
        if tenzro_crypto::session::now_ms() >= params.pq_required_from_ms {
            return Err(refusal_no_post_quantum_leg());
        }
        warn!(
            "the machine identity key has no ML-DSA-65 leg; records carry the classical \
             signature alone until records.pq_leg_required_from_ms"
        );
    }
    tenzro_crypto::batch::set_pq_leg_required_from_ms(params.pq_required_from_ms);
    let service = BatchService::new(
        identity,
        BatchParams {
            max_batch: params.max_batch,
            flush_interval_ms: params.flush_interval_ms,
        },
        params.immediate_min_interval_ms,
    )
    .map(Arc::new)
    .map_err(|e| format!("batch signing cannot start: {e}"))?;
    spawn_ticker(Arc::downgrade(&service), params);
    info!(
        max_batch = params.max_batch,
        flush_interval_ms = params.flush_interval_ms,
        "batch signing started"
    );
    Ok(service)
}

/// The node's batch service over the machine identity key `label`: opened in
/// this machine's hardware, or at the providers through the key holder when
/// the machine has no TPM. Every batch root is signed by that hardware.
pub fn open_batch_service(
    label: &str,
    params: BatchSigningParams,
) -> Result<Arc<BatchService>, String> {
    // The unit tests of this crate start whole nodes on machines that have no
    // TPM (CI, a device-hidden sandbox); they open a test signer, and this
    // branch does not exist in a build without `cfg(test)`.
    #[cfg(test)]
    {
        return build_batch_service(
            label,
            params,
            true,
            false,
            vec![Box::new(|_| {
                Ok(
                    Arc::new(tenzro_crypto::composite::testing::TestHybridSigner::hybrid(
                        7,
                    )) as Arc<dyn HybridSigner>,
                )
            })],
        );
    }
    #[cfg(not(test))]
    build_batch_service(
        label,
        params,
        tenzro_device_key::signer::platform_backend().is_some(),
        crate::identity_bootstrap::remote_tpm_configured(),
        vec![Box::new(|label| {
            tenzro_device_key::HardwareHybridSigner::open_or_create(label)
                .map(|s| Arc::new(s) as Arc<dyn HybridSigner>)
                .map_err(|e| e.to_string())
        })],
    )
}

static SIGNING_REFUSED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Whether this node's identity key is refused for signing because it lacks
/// the ML-DSA leg the network requires (a health flag for the node).
pub fn signing_refused() -> bool {
    SIGNING_REFUSED.load(Ordering::Relaxed)
}

fn spawn_ticker(service: Weak<BatchService>, params: BatchSigningParams) {
    let every = Duration::from_millis((params.flush_interval_ms / 4).max(50));
    let _ = std::thread::Builder::new()
        .name("batch-tick".into())
        .spawn(move || {
            let mut reported = false;
            loop {
                std::thread::sleep(every);
                let Some(svc) = service.upgrade() else { return };
                match svc.tick(tenzro_crypto::session::now_ms()) {
                    Ok(_) => {
                        if reported || SIGNING_REFUSED.swap(false, Ordering::Relaxed) {
                            info!("batch signing: signing again");
                        }
                        reported = false;
                    }
                    Err(e) if svc.refused() => {
                        // Reported once; retrying would not help, the key
                        // lacks the leg the network requires.
                        SIGNING_REFUSED.store(true, Ordering::Relaxed);
                        if !reported {
                            error!(error = %e, "batch signing refused: this node signs nothing");
                            reported = true;
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "batch signing: the hardware did not sign; will retry")
                    }
                }
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_crypto::composite::testing::TestHybridSigner;

    fn ok(seed: u8, hybrid: bool) -> IdentityOpener {
        Box::new(move |_| {
            let s: Arc<dyn HybridSigner> = Arc::new(if hybrid {
                TestHybridSigner::hybrid(seed)
            } else {
                TestHybridSigner::p256_only(seed)
            });
            Ok(s)
        })
    }
    fn down(why: &'static str) -> IdentityOpener {
        Box::new(move |_| Err(why.to_string()))
    }
    const P: BatchSigningParams = BatchSigningParams {
        max_batch: 2,
        flush_interval_ms: 1_000,
        immediate_min_interval_ms: 0,
        hardware_budget_ms: 1_000,
        pq_required_from_ms: u64::MAX,
    };
    const REQUIRED: BatchSigningParams = BatchSigningParams {
        pq_required_from_ms: 0,
        ..P
    };

    #[test]
    fn a_local_hardware_key_signs_batches() {
        let svc = build_batch_service("l", P, true, false, vec![ok(61, true)]).unwrap();
        let now = tenzro_crypto::session::now_ms();
        let a = svc.submit(b"a".to_vec(), now).unwrap();
        let b = svc.submit(b"b".to_vec(), now).unwrap();
        for (t, m) in [(a, b"a"), (b, b"b")] {
            t.wait(std::time::Duration::from_millis(100))
                .unwrap()
                .verify(svc.identity(), m, now, 0)
                .unwrap();
        }
    }

    #[test]
    fn a_tpmless_node_uses_the_second_provider_when_the_first_is_down() {
        let svc = build_batch_service(
            "l",
            P,
            false,
            true,
            vec![down("provider 1: did not answer"), ok(62, true)],
        )
        .unwrap();
        let now = tenzro_crypto::session::now_ms();
        let s = svc.sign_now(b"x".to_vec(), now).unwrap();
        s.verify(svc.identity(), b"x", now, 0).unwrap();
        // Every provider down: refused, naming each reason.
        let err = build_batch_service(
            "l",
            P,
            false,
            true,
            vec![down("provider 1: down"), down("provider 2: down")],
        )
        .err()
        .unwrap();
        assert!(
            err.contains("provider 1") && err.contains("provider 2"),
            "{err}"
        );
    }

    #[test]
    fn no_key_and_no_provider_is_refused_at_start_up() {
        let err = build_batch_service("l", P, false, false, vec![ok(63, true)])
            .err()
            .unwrap();
        assert!(
            err.contains("no provider set") && err.contains("never left unsigned"),
            "{err}"
        );
    }

    #[test]
    fn a_key_without_the_ml_dsa_leg_is_refused_once_the_governed_moment_has_come() {
        let err = build_batch_service("l", REQUIRED, true, false, vec![ok(64, false)])
            .err()
            .unwrap();
        assert!(
            err.contains("ML-DSA-65") && err.contains("post-quantum"),
            "{err}"
        );
        // A moment still ahead does not refuse.
        let later = BatchSigningParams {
            pq_required_from_ms: tenzro_crypto::session::now_ms() + 3_600_000,
            ..P
        };
        build_batch_service("l", later, true, false, vec![ok(64, false)])
            .expect("not yet required");
    }

    #[test]
    fn a_key_without_the_ml_dsa_leg_starts_and_signs_while_the_leg_is_not_required() {
        let svc = build_batch_service("l", P, true, false, vec![ok(65, false)]).unwrap();
        let now = tenzro_crypto::session::now_ms();
        let sig = svc.sign_now(b"x".to_vec(), now).unwrap();
        // The classical-only root verifies before the activation and not from it.
        sig.verify_under(svc.identity(), b"x", now, 0, u64::MAX)
            .unwrap();
        assert!(sig.verify_under(svc.identity(), b"x", now, 0, now).is_err());
        assert!(sig.verify_under(svc.identity(), b"x", now, 0, 0).is_err());
    }

    #[test]
    fn a_hybrid_root_verifies_before_and_after_the_activation_and_a_stripped_leg_never_does() {
        let svc = build_batch_service("l", P, true, false, vec![ok(66, true)]).unwrap();
        let now = tenzro_crypto::session::now_ms();
        let sig = svc.sign_now(b"y".to_vec(), now).unwrap();
        for from in [0, now, u64::MAX] {
            sig.verify_under(svc.identity(), b"y", now, 0, from)
                .unwrap();
        }
        // Dropping the ML-DSA leg of a root signed by a key that has one fails whatever the moment.
        let mut stripped = sig.clone();
        stripped.root.signature.pq = None;
        for from in [0, now, u64::MAX] {
            assert!(
                stripped
                    .verify_under(svc.identity(), b"y", now, 0, from)
                    .is_err()
            );
        }
        // A root is judged by its own date: signed before the moment, it stands after it.
        assert!(sig.root.signed_at_ms < now + 1);
        sig.verify_under(svc.identity(), b"y", now, 0, now + 1)
            .unwrap();
    }

    #[test]
    fn a_replayed_classical_root_cannot_be_moved_across_the_activation() {
        let svc = build_batch_service("l", P, true, false, vec![ok(67, false)]).unwrap();
        let now = tenzro_crypto::session::now_ms();
        let sig = svc.sign_now(b"z".to_vec(), now).unwrap();
        // Changing the signing date to dodge the requirement breaks the signature.
        let mut moved = sig.clone();
        moved.root.signed_at_ms = now.saturating_sub(10_000);
        assert!(
            moved
                .verify_under(svc.identity(), b"z", now, 60_000, u64::MAX)
                .is_err()
        );
        // Presenting it under another message fails.
        assert!(
            sig.verify_under(svc.identity(), b"other", now, 0, u64::MAX)
                .is_err()
        );
    }
}

/// A record signer that waits for its hardware batch without stalling the
/// async runtime thread it is called from.
#[derive(Clone)]
pub struct RuntimeSigner(Arc<dyn tenzro_crypto::batch::RecordSigner>);

impl RuntimeSigner {
    pub fn new(inner: Arc<dyn tenzro_crypto::batch::RecordSigner>) -> Self {
        Self(inner)
    }

    /// The identity key the signatures verify under.
    pub fn identity(&self) -> &tenzro_crypto::composite::CompositePublicKey {
        self.0.identity()
    }
}

impl tenzro_crypto::batch::RecordSigner for RuntimeSigner {
    fn identity(&self) -> &tenzro_crypto::composite::CompositePublicKey {
        self.0.identity()
    }
    fn sign_record(
        &self,
        message: &[u8],
    ) -> tenzro_crypto::Result<tenzro_crypto::batch::RecordSignature> {
        match tokio::runtime::Handle::try_current().map(|h| h.runtime_flavor()) {
            Ok(tokio::runtime::RuntimeFlavor::MultiThread) => {
                tokio::task::block_in_place(|| self.0.sign_record(message))
            }
            _ => self.0.sign_record(message),
        }
    }
}

/// Test support: a record signer over a hardware batch that signs at once.
#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::Arc;
    use tenzro_crypto::batch::{BatchParams, BatchService, RecordSignature, RecordSigner};
    use tenzro_crypto::composite::CompositePublicKey;
    use tenzro_crypto::composite::testing::TestHybridSigner;

    pub struct Immediate(pub Arc<BatchService>);

    impl Immediate {
        pub fn new(seed: u8) -> Self {
            Self(Arc::new(
                BatchService::new(
                    Arc::new(TestHybridSigner::hybrid(seed)),
                    BatchParams {
                        max_batch: 8,
                        flush_interval_ms: 1_000,
                    },
                    0,
                )
                .unwrap(),
            ))
        }
    }

    impl RecordSigner for Immediate {
        fn identity(&self) -> &CompositePublicKey {
            self.0.identity()
        }
        fn sign_record(&self, m: &[u8]) -> tenzro_crypto::Result<RecordSignature> {
            self.0
                .sign_now(m.to_vec(), tenzro_crypto::session::now_ms())
                .map(RecordSignature::batched)
        }
    }
}
