//! TPM attestation of a machine identity whose key another machine holds.
//!
//! A machine with no TPM keeps its identity key in the TPM of a machine the
//! same operator owns (`tenzro_device_key::remote`). That TPM is the
//! hardware the identity rests on, so it is the one that attests: the
//! holding machine answers two requests about a key it holds, and builds
//! what its TPM signs from that key itself.
//!
//! - Admission: credential activation and a quote over the admission
//!   challenge of the machine root the key derives, for the nonce asked.
//! - Possession: a quote over that machine root's possession challenge of a
//!   reward epoch.
//!
//! Both statements name the machine root of the held key, so a client gets
//! no quote about another identity and none the holding machine's own
//! identity could be shown with. The asking machine checks each answer
//! before it uses it.

use tenzro_device_key::DeviceKeyError;
use tenzro_types::did_derivation::machine_did;
use tenzro_types::hardware_level::possession_challenge;

use crate::error::{Result, TeeError};
use crate::tpm_attest::{MachineAttestation, TpmEvidence, admission_challenge, verify_quote};

const REQUEST_ADMISSION: u8 = 1;
const REQUEST_POSSESSION: u8 = 2;

fn fail(msg: impl Into<String>) -> TeeError {
    TeeError::AttestationVerificationFailed(msg.into())
}

/// The TPM a holding machine attests with.
pub trait AttestingTpm: Send + Sync {
    /// Credential activation and a quote over the admission challenge of
    /// `did`, `key` and `nonce`.
    fn admit(&self, did: &str, key: &[u8], nonce: [u8; 32]) -> Result<MachineAttestation>;

    /// A quote over `challenge` by the attestation key.
    fn quote(&self, challenge: &[u8; 32]) -> Result<TpmEvidence>;
}

/// This machine's TPM.
#[cfg(any(target_os = "linux", windows))]
pub struct LocalTpm;

#[cfg(any(target_os = "linux", windows))]
impl AttestingTpm for LocalTpm {
    fn admit(&self, did: &str, key: &[u8], nonce: [u8; 32]) -> Result<MachineAttestation> {
        crate::tpm_attest::attest_local_machine_over(Some(did), key, Some(nonce)).map(|(_, a)| a)
    }

    fn quote(&self, challenge: &[u8; 32]) -> Result<TpmEvidence> {
        crate::tpm_attest::quote_local_machine(challenge).map(|(_, e)| e)
    }
}

/// Answers a client's attestation requests about the key held for it.
pub struct HolderAttestor<T>(pub T);

impl<T: AttestingTpm> HolderAttestor<T> {
    /// The answer to `request` about the held key `key` (uncompressed SEC1).
    pub fn answer(&self, key: &[u8], request: &[u8]) -> Result<Vec<u8>> {
        let encode = |e: serde_json::Error| fail(e.to_string());
        let did = machine_did(key);
        match request.split_first() {
            Some((&REQUEST_ADMISSION, nonce)) if nonce.len() == 32 => {
                let nonce: [u8; 32] = nonce.try_into().expect("32 bytes");
                serde_json::to_vec(&self.0.admit(&did, key, nonce)?).map_err(encode)
            }
            Some((&REQUEST_POSSESSION, draw)) if draw.len() == 48 => {
                let epoch = u64::from_be_bytes(draw[..8].try_into().expect("8 bytes"));
                let round = u64::from_be_bytes(draw[8..16].try_into().expect("8 bytes"));
                let mix: [u8; 32] = draw[16..].try_into().expect("32 bytes");
                let challenge = possession_challenge(&did, epoch, round, &mix);
                serde_json::to_vec(&self.0.quote(&challenge)?).map_err(encode)
            }
            _ => Err(fail("not an admission or possession attestation request")),
        }
    }
}

impl<T: AttestingTpm> tenzro_device_key::remote::Attestor for HolderAttestor<T> {
    fn attest(&self, key: &[u8; 65], request: &[u8]) -> tenzro_device_key::Result<Vec<u8>> {
        self.answer(key, request)
            .map_err(|e| DeviceKeyError::Tpm(e.to_string()))
    }
}

/// The admission attestation, for `nonce`, of the machine root `key`
/// (uncompressed SEC1) derives, from the machine whose TPM holds the key:
/// `ask` carries the request to it. The answer is checked to record an
/// activation and to quote the admission challenge of that root and nonce.
pub fn admission(
    ask: impl FnOnce(&[u8]) -> std::result::Result<Vec<u8>, String>,
    key: &[u8],
    nonce: [u8; 32],
) -> Result<MachineAttestation> {
    let request = [&[REQUEST_ADMISSION][..], &nonce].concat();
    let answer = ask(&request).map_err(|e| fail(format!("the key's holder: {e}")))?;
    let att: MachineAttestation = serde_json::from_slice(&answer)
        .map_err(|e| fail(format!("the holder's attestation does not parse: {e}")))?;
    if !att.activated || att.nonce != nonce {
        return Err(fail(
            "the holder's attestation records no activation or answers another nonce",
        ));
    }
    verify_quote(
        &att.evidence,
        &admission_challenge(&machine_did(key), key, &nonce),
    )?;
    Ok(att)
}

/// The possession quote of reward epoch `epoch`, whose challenge is drawn
/// from beacon round `round` and its value `mix`, for the machine root `key`
/// derives, from the machine whose TPM holds the key. The answer is checked
/// to quote that challenge.
pub fn possession(
    ask: impl FnOnce(&[u8]) -> std::result::Result<Vec<u8>, String>,
    key: &[u8],
    epoch: u64,
    round: u64,
    mix: &[u8; 32],
) -> Result<TpmEvidence> {
    let request = [
        &[REQUEST_POSSESSION][..],
        &epoch.to_be_bytes(),
        &round.to_be_bytes(),
        mix,
    ]
    .concat();
    let answer = ask(&request).map_err(|e| fail(format!("the key's holder: {e}")))?;
    let evidence: TpmEvidence = serde_json::from_slice(&answer)
        .map_err(|e| fail(format!("the holder's quote does not parse: {e}")))?;
    verify_quote(
        &evidence,
        &possession_challenge(&machine_did(key), epoch, round, mix),
    )?;
    Ok(evidence)
}

#[cfg(any(test, feature = "test-ca"))]
impl AttestingTpm for crate::tpm_attest::tests::SoftTpm {
    fn admit(&self, did: &str, key: &[u8], nonce: [u8; 32]) -> Result<MachineAttestation> {
        let (evidence, _) =
            crate::tpm_attest::tests::evidence(self, &admission_challenge(did, key, &nonce));
        Ok(MachineAttestation {
            evidence,
            nonce: nonce.to_vec(),
            activated: true,
        })
    }

    fn quote(&self, challenge: &[u8; 32]) -> Result<TpmEvidence> {
        Ok(crate::tpm_attest::tests::evidence(self, challenge).0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tpm_attest::tests::SoftTpm;
    use tenzro_device_key::remote::Attestor;

    fn key(seed: u8) -> [u8; 65] {
        p256::ecdsa::SigningKey::from_slice(&[seed; 32])
            .unwrap()
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .try_into()
            .unwrap()
    }

    /// The holder answering for the key `held`.
    fn holder(held: [u8; 65]) -> impl Fn(&[u8]) -> std::result::Result<Vec<u8>, String> {
        move |request| {
            HolderAttestor(SoftTpm::new(70))
                .attest(&held, request)
                .map_err(|e| e.to_string())
        }
    }

    #[test]
    fn the_holders_tpm_attests_the_machine_root_of_the_key_it_holds() {
        let key = key(33);
        let att = admission(holder(key), &key, [4; 32]).unwrap();
        assert!(crate::identity_evidence::tpm_evidence_binds(
            &machine_did(&key),
            &key,
            &att
        ));
        let quoted = possession(holder(key), &key, 6, 11, &[5; 32]).unwrap();
        assert_eq!(quoted.ak_public, att.evidence.ak_public);
        verify_quote(
            &quoted,
            &possession_challenge(&machine_did(&key), 6, 11, &[5; 32]),
        )
        .unwrap();
    }

    /// Whatever a client asks, the holder's TPM signs statements about the
    /// key it holds for that client: an answer about another key's machine
    /// root does not pass as one about this client's.
    #[test]
    fn an_answer_about_another_key_is_refused() {
        let (mine, other) = (key(33), key(34));
        admission(holder(other), &mine, [4; 32]).unwrap_err();
        possession(holder(other), &mine, 6, 11, &[5; 32]).unwrap_err();
    }

    #[test]
    fn an_answer_to_another_nonce_or_epoch_is_refused() {
        let key = key(33);
        let stale = admission(holder(key), &key, [4; 32]).unwrap();
        let replay = |_: &[u8]| Ok(serde_json::to_vec(&stale).unwrap());
        admission(replay, &key, [9; 32]).unwrap_err();
        let old = possession(holder(key), &key, 6, 11, &[5; 32]).unwrap();
        let replay = |_: &[u8]| Ok(serde_json::to_vec(&old).unwrap());
        possession(replay, &key, 7, 11, &[5; 32]).unwrap_err();
    }

    #[test]
    fn a_request_that_is_neither_kind_is_refused() {
        let attestor = HolderAttestor(SoftTpm::new(70));
        attestor.attest(&key(33), &[]).unwrap_err();
        attestor.attest(&key(33), &[3; 33]).unwrap_err();
        attestor
            .attest(&key(33), &[REQUEST_ADMISSION; 20])
            .unwrap_err();
    }
}
