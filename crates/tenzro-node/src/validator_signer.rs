//! The validator's consensus key, held by this machine's hardware.
//!
//! The key is a composite of the scheme [`HardwareValidatorSigner::open_for`]
//! is asked for. An ML-DSA-87 / ECDSA-P384 key is two keys created in and
//! held by the TPM, which must implement ML-DSA (TPM 2.0 library v1.85) and
//! NIST P-384; there is no derived or software leg of that scheme.
//!
//! The default key is a composite ML-DSA-65 + P-256 key. The P-256 leg is a key in
//! the TPM or Secure Enclave, which signs with it directly. No TPM or enclave
//! in use holds ML-DSA-65 natively, so that leg is derived from the machine's
//! [`DerivationRoot`] for each signature and wiped when the signature is
//! made: it exists in memory only for that call and is never stored, sealed,
//! exported or passed anywhere.
//!
//! A derived signature costs several hardware commands (about a second on a
//! TPM), so the key signs only what ties a key to it: the registration proof,
//! once per boot the announcement that certifies the session key for channel
//! handshakes, and once per epoch the certificate of the session key for
//! checkpoint votes. The session key signs the votes and handshakes, and
//! everything else a validator sends travels on the channels those
//! handshakes key.

use tenzro_consensus::validator_key::{
    CompositeSignature, SignatureScheme, ValidatorPublicKey, ValidatorSigner,
    message_representative, message_representative_for, ml_dsa_context,
};
use tenzro_consensus::{ConsensusError, Result};
use tenzro_device_key::derive::DerivationRoot;
use tenzro_device_key::signer::{HardwareMlDsaSigner, HardwareP384Signer, HardwareSigner};

/// Label of both legs of the consensus key. The P-256 leg is the machine's
/// identity key, so a validator's consensus key names its machine DID.
pub const CONSENSUS_KEY_LABEL: &str = tenzro_types::did_derivation::MACHINE_KEY_LABEL;

fn unavailable(what: impl std::fmt::Display) -> ConsensusError {
    ConsensusError::HardwareKeyUnavailable(what.to_string())
}

/// The hardware legs of a consensus key.
enum Legs {
    /// ML-DSA-65 derived from the derivation root; P-256 the identity key.
    MlDsa65P256 {
        p256: Box<dyn HardwareSigner>,
        root: DerivationRoot,
    },
    /// ML-DSA-87 and ECDSA-P384, both created in and held by the TPM.
    MlDsa87P384 {
        ml_dsa: Box<dyn HardwareMlDsaSigner>,
        p384: Box<dyn HardwareP384Signer>,
    },
}

/// The consensus key of this machine.
pub struct HardwareValidatorSigner {
    legs: Legs,
    public: ValidatorPublicKey,
}

impl HardwareValidatorSigner {
    /// Opens this machine's ML-DSA-65 / P-256 consensus key, creating the
    /// hardware keys on first use. Refuses on a machine without a TPM 2.0 or
    /// Secure Enclave, or whose derivation root is not provisioned: such a
    /// machine runs as a follower.
    pub fn open() -> Result<Self> {
        Self::open_for(SignatureScheme::MlDsa65P256)
    }

    /// Opens this machine's consensus key of `scheme`, creating its hardware
    /// keys on first use. An ML-DSA-87 / ECDSA-P384 key is refused, with the
    /// reason, on a machine whose TPM does not implement ML-DSA or P-384; the
    /// ML-DSA leg is opened first, so such a TPM is left with no key of the
    /// scheme.
    pub fn open_for(scheme: SignatureScheme) -> Result<Self> {
        match scheme {
            SignatureScheme::MlDsa65P256 => {
                let root = DerivationRoot::open_or_create()
                    .map_err(|e| unavailable(format!("the derivation root: {e}")))?;
                Self::ml_dsa65_p256(root)
            }
            SignatureScheme::MlDsa87P384 => {
                let ml_dsa = tenzro_device_key::signer::open_or_create_ml_dsa(
                    &format!("{CONSENSUS_KEY_LABEL}/ml-dsa-87"),
                    scheme,
                )
                .map_err(|e| unavailable(format!("the ML-DSA-87 consensus key: {e}")))?;
                let p384 = tenzro_device_key::signer::open_or_create_p384(&format!(
                    "{CONSENSUS_KEY_LABEL}/ecdsa-p384"
                ))
                .map_err(|e| unavailable(format!("the P-384 consensus key: {e}")))?;
                let ml_dsa_pk = ml_dsa
                    .verifying_key()
                    .map_err(|e| unavailable(format!("the ML-DSA-87 public key: {e}")))?;
                let sec1 = p384
                    .public_key_sec1()
                    .map_err(|e| unavailable(format!("the P-384 public key: {e}")))?;
                let public = ValidatorPublicKey::new(scheme.tag(&ml_dsa_pk), sec1.to_vec())?;
                Ok(Self {
                    legs: Legs::MlDsa87P384 { ml_dsa, p384 },
                    public,
                })
            }
        }
    }

    /// The ML-DSA-65 / P-256 key whose ML-DSA leg `root` derives.
    fn ml_dsa65_p256(root: DerivationRoot) -> Result<Self> {
        let p256 = tenzro_device_key::signer::open_or_create(CONSENSUS_KEY_LABEL)
            .map_err(|e| unavailable(format!("the P-256 consensus key: {e}")))?;
        let ml_dsa = root
            .ml_dsa65_public(CONSENSUS_KEY_LABEL)
            .map_err(|e| unavailable(format!("the ML-DSA-65 consensus key: {e}")))?;
        let sec1 = p256
            .public_key_sec1()
            .map_err(|e| unavailable(format!("the P-256 public key: {e}")))?;
        let public = ValidatorPublicKey::new(ml_dsa, sec1.to_vec())?;
        Ok(Self {
            legs: Legs::MlDsa65P256 { p256, root },
            public,
        })
    }

    /// This machine's key registered as `registered`, when the machine
    /// still holds it. `None` when the machine holds no such key.
    pub fn open_registered(registered: &ValidatorPublicKey) -> Result<Option<Self>> {
        let scheme = registered.scheme();
        if let Ok(key) = Self::open_for(scheme)
            && key.public == *registered
        {
            return Ok(Some(key));
        }
        Ok(None)
    }

    /// The scheme of this key.
    pub fn scheme(&self) -> SignatureScheme {
        self.public.scheme()
    }
}

impl ValidatorSigner for HardwareValidatorSigner {
    fn public_key(&self) -> &ValidatorPublicKey {
        &self.public
    }

    fn sign(&self, domain: &[u8], message: &[u8]) -> Result<CompositeSignature> {
        // Votes and blocks go ahead of announcement signatures at the TPM.
        let _priority = tenzro_device_key::tpm_exec::high_priority();
        let long = || ConsensusError::InvalidValidatorKey("domain longer than 255 bytes".into());
        match &self.legs {
            Legs::MlDsa65P256 { p256, root } => {
                let rep = message_representative(domain, message).ok_or_else(long)?;
                let ml_dsa = root
                    .ml_dsa65_sign(CONSENSUS_KEY_LABEL, ml_dsa_context(), &rep)
                    .map_err(|e| unavailable(format!("ML-DSA-65 signing: {e}")))?;
                let p256 = p256
                    .sign(&rep)
                    .map_err(|e| unavailable(format!("P-256 signing: {e}")))?;
                Ok(CompositeSignature {
                    ml_dsa,
                    p256: p256.to_vec(),
                })
            }
            Legs::MlDsa87P384 { ml_dsa, p384 } => {
                let scheme = SignatureScheme::MlDsa87P384;
                let rep = message_representative_for(scheme, domain, message).ok_or_else(long)?;
                let bare = ml_dsa
                    .sign(scheme.label(), &rep)
                    .map_err(|e| unavailable(format!("ML-DSA-87 signing: {e}")))?;
                let ecdsa = p384
                    .sign(&rep)
                    .map_err(|e| unavailable(format!("P-384 signing: {e}")))?;
                Ok(CompositeSignature {
                    ml_dsa: scheme.tag(&bare),
                    p256: ecdsa.to_vec(),
                })
            }
        }
    }
}

/// The consensus key of the scheme the node config selects, opened with
/// `open`.
/// `open` for `scheme`. A machine that cannot hold a key of the default
/// scheme follows the chain; one that cannot hold a key of a scheme the
/// operator selected is refused, naming the scheme and the reason, and never
/// validates under another scheme instead.
pub fn open_configured<S>(
    scheme: SignatureScheme,
    open: impl FnOnce(SignatureScheme) -> Result<S>,
) -> std::result::Result<Option<S>, String> {
    match open(scheme) {
        Ok(s) => Ok(Some(s)),
        Err(e) if scheme == SignatureScheme::default() => {
            tracing::warn!(
                error = %e,
                "No hardware validator key: this node follows the chain and does not \
                 validate. A validator key needs a TPM 2.0 or a Secure Enclave."
            );
            Ok(None)
        }
        Err(e) => Err(format!(
            "the node config selects {} consensus keys, and this machine cannot hold one: {e}",
            String::from_utf8_lossy(scheme.label())
        )),
    }
}

/// The keys a validator signs with.
pub struct ValidatorKeys {
    /// The key in force: it signs for every epoch whose committee seats it.
    pub in_force: std::sync::Arc<dyn ValidatorSigner>,
    /// The configured key a rotation seats, when it is not the key in force:
    /// it signs from the first epoch whose committee seats it.
    pub incoming: Option<std::sync::Arc<dyn ValidatorSigner>>,
}

/// The keys of a validator whose config selects `configured` and whose
/// registered key is `registered`. When the two differ and this machine
/// still holds the registered key (`open_registered`), that key stays in
/// force and the configured key is incoming, so the validator keeps signing
/// up to the epoch boundary that seats its rotation and signs with the new
/// key from there, with no restart. Otherwise the configured key is the only
/// key, and the validator follows until a committee seats it.
pub fn validator_keys(
    configured: std::sync::Arc<dyn ValidatorSigner>,
    registered: Option<&ValidatorPublicKey>,
    open_registered: impl FnOnce(
        &ValidatorPublicKey,
    ) -> Result<Option<std::sync::Arc<dyn ValidatorSigner>>>,
) -> ValidatorKeys {
    let only = |configured| ValidatorKeys {
        in_force: configured,
        incoming: None,
    };
    let Some(registered) = registered.filter(|r| *r != configured.public_key()) else {
        return only(configured);
    };
    match open_registered(registered) {
        Ok(Some(held)) if held.public_key() == registered => ValidatorKeys {
            in_force: held,
            incoming: Some(configured),
        },
        Ok(_) => {
            tracing::info!(
                "this machine no longer holds the registered validator key; it follows until \
                 the configured key is seated"
            );
            only(configured)
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "the registered validator key could not be opened; this node follows until \
                 the configured key is seated"
            );
            only(configured)
        }
    }
}

/// The registered key of a validator and the key rotation it has asked for.
pub struct RegisteredKey<'a> {
    /// The ML-DSA and ECDSA legs of the key in force.
    pub key: (&'a [u8], &'a [u8]),
    /// The legs of a rotation already requested, if any.
    pub pending: Option<(&'a [u8], &'a [u8])>,
}

/// The `RotateValidatorKey` transaction that moves `address` to the key of
/// `configured`, with that key's proof of possession over `address` and its
/// registered `node_key`; `None` when that key is already in force or
/// already requested.
pub fn key_rotation(
    registered: RegisteredKey<'_>,
    configured: &dyn ValidatorSigner,
    address: &[u8],
    node_key: &[u8; 32],
) -> Result<Option<tenzro_types::transaction::TransactionType>> {
    let key = configured.public_key();
    let is_configured = |(ml_dsa, ecdsa): (&[u8], &[u8])| {
        ml_dsa == key.ml_dsa.as_slice() && ecdsa == key.p256.as_slice()
    };
    if is_configured(registered.key) || registered.pending.is_some_and(is_configured) {
        return Ok(None);
    }
    let proof_of_possession =
        tenzro_consensus::validator_key::prove_registration(configured, address, node_key)?;
    Ok(Some(
        tenzro_types::transaction::TransactionType::RotateValidatorKey {
            ml_dsa_pubkey: key.ml_dsa.clone(),
            p256_pubkey: key.p256.clone(),
            proof_of_possession,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A node configured for ML-DSA-87 / ECDSA-P384 opens that key; on a
    /// machine that cannot hold it the node refuses to start, naming the
    /// scheme and the hardware reason, rather than validating under another
    /// scheme. The default scheme on a machine without one follows.
    #[test]
    fn a_configured_scheme_is_opened_or_refused_with_its_reason() {
        use tenzro_consensus::validator_key::test_signer::SoftwareTestSigner;
        let scheme = SignatureScheme::MlDsa87P384;
        let opened = open_configured(scheme, |s| {
            Ok(SoftwareTestSigner::from_seed_with_scheme(1, s))
        })
        .expect("opens")
        .expect("a key");
        assert_eq!(opened.public_key().scheme(), scheme);

        let refused = open_configured(scheme, |_| -> Result<SoftwareTestSigner> {
            Err(unavailable(
                "this TPM does not implement ML-DSA (TPM 2.0 library v1.85)",
            ))
        })
        .err()
        .expect("refused");
        assert!(refused.contains("COMPSIG-MLDSA87-ECDSA-P384"), "{refused}");
        assert!(refused.contains("does not implement ML-DSA"), "{refused}");

        let follower = open_configured(
            SignatureScheme::MlDsa65P256,
            |_| -> Result<SoftwareTestSigner> { Err(unavailable("no TPM")) },
        )
        .expect("the default scheme follows");
        assert!(follower.is_none());
    }

    /// A validator whose registered key is ML-DSA-65 / P-256 and whose
    /// config selects ML-DSA-87 / ECDSA-P384 asks to rotate to its new key,
    /// with a proof of possession the chain accepts; once the rotation is
    /// requested or in force it asks nothing more.
    #[test]
    fn a_validator_configured_for_the_second_scheme_rotates_to_it() {
        use tenzro_consensus::validator_key::test_signer::SoftwareTestSigner;
        use tenzro_types::transaction::TransactionType;
        let old = SoftwareTestSigner::from_seed(7);
        let new = SoftwareTestSigner::from_seed_with_scheme(8, SignatureScheme::MlDsa87P384);
        let address = [5u8; 32];
        let node_key = [6u8; 32];
        let old_key = old.public_key();
        let tx = key_rotation(
            RegisteredKey {
                key: (&old_key.ml_dsa, &old_key.p256),
                pending: None,
            },
            &new,
            &address,
            &node_key,
        )
        .expect("builds")
        .expect("a rotation");
        let TransactionType::RotateValidatorKey {
            ml_dsa_pubkey,
            p256_pubkey,
            proof_of_possession,
        } = tx
        else {
            panic!("not a key rotation");
        };
        let key = ValidatorPublicKey::new(ml_dsa_pubkey, p256_pubkey).expect("a key");
        assert_eq!(key.scheme(), SignatureScheme::MlDsa87P384);
        assert_eq!(&key, new.public_key());
        tenzro_consensus::validator_key::verify_registration(
            &address,
            &key,
            &node_key,
            &proof_of_possession,
        )
        .expect("the chain accepts the proof");

        let new_key = new.public_key();
        for registered in [
            RegisteredKey {
                key: (&new_key.ml_dsa, &new_key.p256),
                pending: None,
            },
            RegisteredKey {
                key: (&old_key.ml_dsa, &old_key.p256),
                pending: Some((&new_key.ml_dsa, &new_key.p256)),
            },
        ] {
            assert!(
                key_rotation(registered, &new, &address, &node_key)
                    .expect("builds")
                    .is_none()
            );
        }
    }

    /// A validator whose registered key is not its configured key (a Mac
    /// moved to the hidden enclave root, or a validator configured for the
    /// second scheme) keeps the registered key in force while it holds it,
    /// with the configured key incoming, and asks for the rotation with the
    /// configured key under the same address: the validator rotates its key
    /// and stays the same validator. One that no longer holds its registered
    /// key, or whose keys agree, has the configured key alone.
    #[test]
    fn a_validator_holding_its_registered_key_signs_with_it_until_the_rotation_seats() {
        use std::sync::Arc;
        use tenzro_consensus::validator_key::test_signer::SoftwareTestSigner;
        let registered: Arc<dyn ValidatorSigner> = Arc::new(SoftwareTestSigner::from_seed(11));
        let configured: Arc<dyn ValidatorSigner> = Arc::new(SoftwareTestSigner::from_seed(12));
        let registered_key = registered.public_key().clone();

        let held = registered.clone();
        let keys = validator_keys(configured.clone(), Some(&registered_key), move |k| {
            assert_eq!(k, held.public_key());
            Ok(Some(held))
        });
        assert_eq!(keys.in_force.public_key(), &registered_key);
        assert_eq!(
            keys.incoming.as_ref().expect("incoming").public_key(),
            configured.public_key()
        );

        let address = [9u8; 32];
        let node_key = [10u8; 32];
        let tx = key_rotation(
            RegisteredKey {
                key: (&registered_key.ml_dsa, &registered_key.p256),
                pending: None,
            },
            &**keys.incoming.as_ref().unwrap(),
            &address,
            &node_key,
        )
        .expect("builds")
        .expect("a rotation");
        let tenzro_types::transaction::TransactionType::RotateValidatorKey {
            ml_dsa_pubkey,
            p256_pubkey,
            proof_of_possession,
        } = tx
        else {
            panic!("not a key rotation");
        };
        let rotated = ValidatorPublicKey::new(ml_dsa_pubkey, p256_pubkey).expect("a key");
        tenzro_consensus::validator_key::verify_registration(
            &address,
            &rotated,
            &node_key,
            &proof_of_possession,
        )
        .expect("the same validator address accepts the rotated key");

        let gone = validator_keys(configured.clone(), Some(&registered_key), |_| Ok(None));
        assert_eq!(gone.in_force.public_key(), configured.public_key());
        assert!(gone.incoming.is_none());
        let unopenable = validator_keys(configured.clone(), Some(&registered_key), |_| {
            Err(unavailable("no enclave"))
        });
        assert!(unopenable.incoming.is_none());
        let same = validator_keys(configured.clone(), Some(configured.public_key()), |_| {
            panic!("nothing to open when the keys agree")
        });
        assert!(same.incoming.is_none());
    }

    /// The node config names the scheme by its composite name.
    #[test]
    fn the_node_config_selects_the_scheme_by_its_composite_name() {
        for name in [
            "COMPSIG-MLDSA87-ECDSA-P384",
            "COMPSIG-MLDSA87-ECDSA-P384-SHA512",
        ] {
            let c: crate::config::NodeConfig =
                toml::from_str(&format!("consensus_key_scheme = \"{name}\"\n")).expect(name);
            assert_eq!(c.consensus_key_scheme, SignatureScheme::MlDsa87P384);
        }
        let c: crate::config::NodeConfig = toml::from_str("").unwrap();
        assert_eq!(c.consensus_key_scheme, SignatureScheme::MlDsa65P256);
        assert!(
            toml::from_str::<crate::config::NodeConfig>("consensus_key_scheme = \"MLDSA44\"\n")
                .is_err()
        );
    }

    /// What a checkpoint vote costs on this machine's real TPM: open once,
    /// then sign `TDC_SIGN_ITERS` votes (default 40), one composite
    /// signature each. Prints one `GATE {json}` line. Needs a TPM this user
    /// can open, provisioned (`tenzro-node tpm provision`), and
    /// `TENZRO_DEVICE_KEY_DIR` pointing at a scratch directory. Run with `--ignored --nocapture
    /// --test-threads 1`.
    #[test]
    #[ignore]
    fn gate_hardware_composite_signing() {
        let iters: usize = std::env::var("TDC_SIGN_ITERS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(40);
        let start = std::time::Instant::now();
        let signer = HardwareValidatorSigner::open().expect("hardware consensus key");
        let open_ms = start.elapsed().as_secs_f64() * 1e3;
        let Legs::MlDsa65P256 {
            p256: leg_p256,
            root,
        } = &signer.legs
        else {
            unreachable!("open gives the default scheme")
        };
        let domain = b"tenzro/consensus/checkpoint/vote";
        let (mut total, mut ml_dsa, mut p256) = (
            Vec::with_capacity(iters),
            Vec::with_capacity(iters),
            Vec::with_capacity(iters),
        );
        let elapsed_ms = |t: std::time::Instant| t.elapsed().as_secs_f64() * 1e3;
        for i in 0..iters {
            let msg = (i as u64).to_be_bytes();
            let t = std::time::Instant::now();
            let sig = signer.sign(domain, &msg).expect("signs");
            total.push(elapsed_ms(t));
            assert!(
                signer.public_key().verify(domain, &msg, &sig),
                "signature {i} verifies"
            );
            // Each leg on its own: the derived ML-DSA-65 leg (TPM derivation,
            // then signing in memory) and the P-256 leg (signed in the TPM).
            let rep = message_representative(domain, &msg).expect("short domain");
            let t = std::time::Instant::now();
            root.ml_dsa65_sign(CONSENSUS_KEY_LABEL, ml_dsa_context(), &rep)
                .expect("ML-DSA leg");
            ml_dsa.push(elapsed_ms(t));
            let t = std::time::Instant::now();
            leg_p256.sign(&rep).expect("P-256 leg");
            p256.push(elapsed_ms(t));
        }
        let pct = |v: &mut Vec<f64>, q: f64| {
            v.sort_by(f64::total_cmp);
            v[((v.len() - 1) as f64 * q).round() as usize]
        };
        let total_s: f64 = total.iter().sum::<f64>() / 1e3;
        println!(
            "GATE {{\"gate\":\"hardware_composite_signing\",\"iters\":{iters},\"open_ms\":{open_ms:.1},\
             \"p50_ms\":{:.1},\"p99_ms\":{:.1},\"ml_dsa_leg_p50_ms\":{:.1},\"p256_leg_p50_ms\":{:.1},\
             \"signatures_per_s\":{:.2}}}",
            pct(&mut total, 0.5),
            pct(&mut total, 0.99),
            pct(&mut ml_dsa, 0.5),
            pct(&mut p256, 0.5),
            iters as f64 / total_s
        );
    }

    /// The ML-DSA-87 / ECDSA-P384 consensus key on this machine's TPM: where
    /// the TPM implements ML-DSA, both legs are made and sign there and the
    /// composite verifies; where it does not, the key is refused naming
    /// ML-DSA, and no P-384 key is created for it. Needs a provisioned TPM
    /// and `TENZRO_DEVICE_KEY_DIR` pointing at a scratch directory. Run with
    /// `--ignored --test-threads 1`.
    #[test]
    #[ignore]
    fn hardware_ml_dsa_87_p384_consensus_key() {
        use tenzro_device_key::signer::{MlDsaSupport, ml_dsa_support};
        let scheme = SignatureScheme::MlDsa87P384;
        match HardwareValidatorSigner::open_for(scheme) {
            Ok(signer) => {
                assert!(matches!(ml_dsa_support(), MlDsaSupport::Hardware(_)));
                assert_eq!(signer.scheme(), scheme);
                let domain = b"tenzro/consensus/checkpoint/vote";
                let sig = signer.sign(domain, b"m").expect("signs");
                assert!(signer.public_key().verify(domain, b"m", &sig));
                assert!(!signer.public_key().verify(domain, b"n", &sig));
            }
            Err(e) => {
                assert!(
                    !matches!(ml_dsa_support(), MlDsaSupport::Hardware(_)),
                    "a TPM with ML-DSA must give the key: {e}"
                );
                assert!(e.to_string().contains("does not implement ML-DSA"), "{e}");
                let dir = std::env::var("TENZRO_DEVICE_KEY_DIR").expect("scratch key dir");
                let made = std::fs::read_dir(&dir)
                    .map(|d| {
                        d.flatten()
                            .any(|f| f.file_name().to_string_lossy().contains(".p384."))
                    })
                    .unwrap_or(false);
                assert!(!made, "no P-384 key is made for a refused scheme");
            }
        }
    }

    /// A node configured for ML-DSA-87 / ECDSA-P384 on this machine: where
    /// the TPM implements ML-DSA it gets the key; where it does not, startup
    /// is refused naming the scheme and the missing ML-DSA. Needs a
    /// provisioned TPM and `TENZRO_DEVICE_KEY_DIR` pointing at a scratch
    /// directory. Run with `--ignored --test-threads 1`.
    #[test]
    #[ignore]
    fn hardware_node_configured_for_ml_dsa_87_p384() {
        use tenzro_device_key::signer::{MlDsaSupport, ml_dsa_support};
        let scheme = SignatureScheme::MlDsa87P384;
        match open_configured(scheme, HardwareValidatorSigner::open_for) {
            Ok(Some(signer)) => {
                assert!(matches!(ml_dsa_support(), MlDsaSupport::Hardware(_)));
                assert_eq!(signer.scheme(), scheme);
            }
            Ok(None) => panic!("a selected scheme is never left to follow"),
            Err(e) => {
                assert!(
                    !matches!(ml_dsa_support(), MlDsaSupport::Hardware(_)),
                    "{e}"
                );
                assert!(e.contains("COMPSIG-MLDSA87-ECDSA-P384"), "{e}");
                assert!(e.contains("does not implement ML-DSA"), "{e}");
                eprintln!("refused: {e}");
            }
        }
    }
}
