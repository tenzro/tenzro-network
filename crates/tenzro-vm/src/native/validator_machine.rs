//! The machine identity a validator names on chain.
//!
//! A validator whose consensus key is ML-DSA-65 / P-256 names its machine by
//! that key: the P-256 leg is the machine key its identity derives from. A
//! validator of another scheme (ML-DSA-87 / P-384) holds its consensus key
//! apart from its machine key, so peers would otherwise learn the ML-DSA key
//! its machine binds its endpoint records with only from the first record
//! they see. Registering the machine identity here lets them hold the
//! validator's machine to that key from its first record.
//!
//! Both machine keys sign the registration, so a validator cannot name a
//! machine that is not its own (which would let it have that machine's
//! records refused). The registration is behind a governance lever, so no
//! node meets it before the network has upgraded.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tenzro_types::signature_scheme::SignatureScheme;

use super::funding::{read_json, refuse, write_json};
use super::staking::bonded_stake_of;
use super::*;

/// Gas for one registration.
pub const GAS_VALIDATOR_MACHINE: u64 = 150_000;
/// Topic of the log a registration emits.
pub const VALIDATOR_MACHINE_TOPIC: &[u8] = b"ValidatorMachine";
/// Governance lever of machine registrations. Paused at genesis.
pub const MACHINE_IDENTITY_STATUS: &str = "staking.validator_machine_identity.status";
/// Domain of the message both machine keys sign.
pub const MACHINE_PROOF_DOMAIN: &[u8] = b"tenzro/validator/machine-identity/v1";
/// FIPS 204 context of the ML-DSA-65 signature.
pub const MACHINE_PROOF_CONTEXT: &[u8] = b"tenzro/validator/machine-identity";

const P256_SEC1_LEN: usize = 65;

/// A validator's machine identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorMachine {
    /// The machine's hardware P-256 key, uncompressed SEC1: its DID derives
    /// from it.
    #[serde(with = "hex::serde")]
    pub p256: Vec<u8>,
    /// The ML-DSA-65 key the machine binds its endpoint records with.
    #[serde(with = "hex::serde")]
    pub ml_dsa: Vec<u8>,
}

impl ValidatorMachine {
    /// The machine's DID.
    pub fn did(&self) -> String {
        tenzro_types::did_derivation::machine_did(&self.p256)
    }

    /// The ML-DSA key tagged with its scheme, as endpoint bindings name it.
    pub fn tagged_ml_dsa(&self) -> Vec<u8> {
        SignatureScheme::MlDsa65P256.tag(&self.ml_dsa)
    }
}

/// What a registration carries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineRegistration {
    /// The machine named.
    #[serde(flatten)]
    pub machine: ValidatorMachine,
    /// The machine P-256 key's signature over the SHA-256 of
    /// [`proof_message`], `r || s`.
    #[serde(with = "hex::serde")]
    pub p256_signature: Vec<u8>,
    /// The ML-DSA-65 key's signature over [`proof_message`] under
    /// [`MACHINE_PROOF_CONTEXT`].
    #[serde(with = "hex::serde")]
    pub ml_dsa_signature: Vec<u8>,
}

fn machine_key(addr: &[u8]) -> String {
    format!("validator_machine:{}", hex::encode(addr))
}

/// The message both machine keys sign to name `validator` as the account
/// they serve.
pub fn proof_message(validator: &[u8], p256: &[u8], ml_dsa: &[u8]) -> Vec<u8> {
    let mut m = MACHINE_PROOF_DOMAIN.to_vec();
    for part in [validator, p256, ml_dsa] {
        m.extend_from_slice(&(part.len() as u32).to_le_bytes());
        m.extend_from_slice(part);
    }
    m
}

/// The machine identity `addr` registered, if any.
pub fn machine_of(state: &dyn VmState, addr: &[u8]) -> Option<ValidatorMachine> {
    read_json(state, &machine_key(addr))
}

/// Checks both machine signatures in `r` for `validator`.
pub fn check_registration(validator: &[u8], r: &MachineRegistration) -> Result<()> {
    let m = &r.machine;
    if m.p256.len() != P256_SEC1_LEN || m.p256[0] != 0x04 {
        return Err(refuse(
            "the machine key must be an uncompressed SEC1 P-256 key",
        ));
    }
    if m.ml_dsa.len() != tenzro_crypto::pq::ML_DSA_65_VK_LEN {
        return Err(refuse("the machine's ML-DSA key must be an ML-DSA-65 key"));
    }
    let message = proof_message(validator, &m.p256, &m.ml_dsa);
    let verifier = tenzro_crypto::p256::P256Verifier::from_sec1_bytes(&m.p256)
        .map_err(|e| refuse(format!("the machine key: {e}")))?;
    let sig = tenzro_crypto::p256::P256Signature::from_slice(&r.p256_signature)
        .map_err(|e| refuse(format!("the machine key's signature: {e}")))?;
    let digest: [u8; 32] = Sha256::digest(&message).into();
    verifier
        .verify_prehash(&digest, &sig)
        .map_err(|_| refuse("the machine key did not sign this registration"))?;
    tenzro_crypto::pq::ml_dsa_verify(
        &m.ml_dsa,
        MACHINE_PROOF_CONTEXT,
        &message,
        &r.ml_dsa_signature,
    )
    .map_err(|_| refuse("the machine's ML-DSA key did not sign this registration"))?;
    Ok(())
}

/// Records the machine identity the sending validator names.
pub(super) fn register(
    state: &mut dyn VmState,
    from: &[u8],
    payload: &[u8],
) -> Result<(Vec<StateChange>, Vec<Log>)> {
    require_lever_enabled(
        state,
        MACHINE_IDENTITY_STATUS,
        "Registering a validator's machine",
    )?;
    let r: MachineRegistration = serde_json::from_slice(payload)
        .map_err(|e| refuse(format!("Invalid machine registration: {e}")))?;
    let marker = format!("validator_register:{}", hex::encode(from));
    if state
        .get_storage(&SYSTEM_ADDRESS, marker.as_bytes())
        .filter(|b| !b.is_empty())
        .is_none()
    {
        return Err(refuse("the sender is not a registered validator"));
    }
    if bonded_stake_of(state, from) == 0 {
        return Err(refuse("the sender has no bond"));
    }
    check_registration(from, &r)?;
    let mut changes = Vec::new();
    write_json(state, &machine_key(from), &r.machine, &mut changes)?;
    let log = Log::new(
        SYSTEM_ADDRESS.to_vec(),
        vec![VALIDATOR_MACHINE_TOPIC.to_vec()],
        serde_json::to_vec(&serde_json::json!({
            "validator": hex::encode(from),
            "machine_did": r.machine.did(),
        }))
        .map_err(|e| VmError::Internal(format!("encode machine log: {e}")))?,
    );
    Ok((changes, vec![log]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_adapter::StateAdapter;
    use ::p256::ecdsa::signature::hazmat::PrehashSigner;
    use tenzro_crypto::pq::MlDsaSigningKey;

    struct Machine {
        p256: ::p256::ecdsa::SigningKey,
        ml_dsa: MlDsaSigningKey,
    }

    impl Machine {
        fn new(seed: u8) -> Self {
            Self {
                p256: ::p256::ecdsa::SigningKey::from_bytes(&[seed; 32].into()).unwrap(),
                ml_dsa: MlDsaSigningKey::generate(),
            }
        }

        fn sec1(&self) -> Vec<u8> {
            self.p256
                .verifying_key()
                .to_sec1_point(false)
                .as_bytes()
                .to_vec()
        }

        fn registration(&self, validator: &[u8]) -> MachineRegistration {
            let p256 = self.sec1();
            let ml_dsa = self.ml_dsa.verifying_key_bytes().to_vec();
            let message = proof_message(validator, &p256, &ml_dsa);
            let digest: [u8; 32] = Sha256::digest(&message).into();
            let sig: ::p256::ecdsa::Signature = self.p256.sign_prehash(&digest).unwrap();
            MachineRegistration {
                machine: ValidatorMachine { p256, ml_dsa },
                p256_signature: sig.to_bytes().to_vec(),
                ml_dsa_signature: self.ml_dsa.sign(MACHINE_PROOF_CONTEXT, &message),
            }
        }
    }

    fn validator(state: &mut StateAdapter, who: [u8; 32]) {
        state.set_storage(
            &SYSTEM_ADDRESS,
            format!("validator_register:{}", hex::encode(who)).as_bytes(),
            b"{}".to_vec(),
        );
        let floor = super::super::role_stake::stake_ladder(state).validator;
        super::super::staking::add_bond(state, &who, floor.max(1), 0).unwrap();
    }

    fn enable(state: &mut StateAdapter) {
        state.set_storage(
            &SYSTEM_ADDRESS,
            governed_param_key(MACHINE_IDENTITY_STATUS).as_bytes(),
            0u64.to_le_bytes().to_vec(),
        );
    }

    /// A bonded validator names a machine whose two keys signed for it, once
    /// governance enables it; the machine is then readable by its address.
    /// Before that, or for a machine that did not sign for this validator,
    /// for a registration with either signature missing, or from an account
    /// that is not a validator, nothing is recorded.
    #[test]
    fn a_validator_names_a_machine_that_signed_for_it() {
        let mut state = StateAdapter::new();
        let who = [4u8; 32];
        let machine = Machine::new(9);
        let r = machine.registration(&who);
        let payload = serde_json::to_vec(&r).unwrap();
        validator(&mut state, who);

        assert!(
            register(&mut state, &who, &payload).is_err(),
            "registered while paused"
        );
        enable(&mut state);

        let elsewhere = serde_json::to_vec(&machine.registration(&[5u8; 32])).unwrap();
        assert!(register(&mut state, &who, &elsewhere).is_err());
        let mut no_pq = r.clone();
        no_pq.ml_dsa_signature[0] ^= 1;
        assert!(register(&mut state, &who, &serde_json::to_vec(&no_pq).unwrap()).is_err());
        let mut no_p256 = r.clone();
        no_p256.p256_signature[5] ^= 1;
        assert!(register(&mut state, &who, &serde_json::to_vec(&no_p256).unwrap()).is_err());
        let mut swapped = r.clone();
        swapped.machine.ml_dsa = MlDsaSigningKey::generate().verifying_key_bytes().to_vec();
        assert!(register(&mut state, &who, &serde_json::to_vec(&swapped).unwrap()).is_err());
        assert!(register(&mut state, &[6u8; 32], &payload).is_err());
        assert!(machine_of(&state, &who).is_none());

        let (_, logs) = register(&mut state, &who, &payload).unwrap();
        let m = machine_of(&state, &who).unwrap();
        assert_eq!(m, r.machine);
        assert_eq!(
            m.did(),
            tenzro_types::did_derivation::machine_did(&machine.sec1())
        );
        assert_eq!(
            m.tagged_ml_dsa(),
            SignatureScheme::MlDsa65P256.tag(&r.machine.ml_dsa)
        );
        assert_eq!(logs[0].topics[0], VALIDATOR_MACHINE_TOPIC);
    }
}
