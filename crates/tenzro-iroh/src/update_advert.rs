//! The software a machine says it runs, inside its signed endpoint record.
//!
//! An [`UpdateAdvert`] states the machine's binary version, the SHA-256 of
//! the binary it runs (the platform digest, for P0 the file's own hash) and
//! its update state. The machine's hardware key signs it
//! ([`EndpointRecord::attach_update`]), bound to the record's own signature, so
//! a relay cannot move an advert onto another record or another machine.
//!
//! The advert is not part of the P-256 signed record message, like the ML-DSA
//! binding in [`crate::pq_endpoint`]: a node that does not read it still
//! verifies the record, so a fleet can roll out the advert one node at a
//! time without any node refusing another's record.

use serde::{Deserialize, Serialize};
use tenzro_device_key::signer::{HardwareSigner, verify_p256};
pub use tenzro_onboarding_types::update_state::UpdateState;

use crate::error::{IrohError, IrohResult};
use crate::identity_record::{EndpointRecord, RecordError};

/// Domain separator of an update advert signature.
pub const UPDATE_ADVERT_DOMAIN: &[u8] = b"tenzro/transport/update-advert";

/// Longest binary version string a record may carry.
pub const MAX_VERSION_LEN: usize = 64;

/// What a machine says it runs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateAdvert {
    /// The binary's version, e.g. `0.2.1`.
    pub binary_version: String,
    /// Hex SHA-256 identifying the binary for this machine's platform.
    pub platform_digest: String,
    /// Whether this machine is running its newest binary, has another staged, or is restarting onto one.
    pub state: UpdateState,
}

/// An [`UpdateAdvert`] and the machine key's signature over it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedUpdateAdvert {
    /// The advertisement that was signed.
    pub advert: UpdateAdvert,
    /// ECDSA P-256 over SHA-256 of [`advert_message`], hex `r || s`.
    pub signature: String,
}

impl UpdateAdvert {
    fn check_shape(&self) -> Result<(), RecordError> {
        let digest_ok = self.platform_digest.len() == 64
            && self
                .platform_digest
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase());
        if self.binary_version.is_empty()
            || self.binary_version.len() > MAX_VERSION_LEN
            || !self
                .binary_version
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+'))
            || !digest_ok
        {
            return Err(RecordError::Malformed("update advert"));
        }
        Ok(())
    }
}

fn put(m: &mut Vec<u8>, b: &[u8]) {
    m.extend_from_slice(&(b.len() as u32).to_be_bytes());
    m.extend_from_slice(b);
}

/// What the machine signs: the domain, the record's own signature, then the advert.
fn advert_message(record: &EndpointRecord, advert: &UpdateAdvert) -> Vec<u8> {
    let mut m = Vec::with_capacity(256);
    put(&mut m, UPDATE_ADVERT_DOMAIN);
    put(&mut m, &record.signature);
    put(&mut m, advert.binary_version.as_bytes());
    put(&mut m, advert.platform_digest.as_bytes());
    put(&mut m, advert.state.as_str().as_bytes());
    m
}

impl EndpointRecord {
    /// States `advert` in this record, signed by the machine's hardware key.
    /// Call it after [`EndpointRecord::sign`]; the record's own signature is
    /// left as it is.
    pub fn attach_update(
        &mut self,
        signer: &dyn HardwareSigner,
        advert: UpdateAdvert,
    ) -> IrohResult<()> {
        advert
            .check_shape()
            .map_err(|e| IrohError::Backend(e.to_string()))?;
        let signature = signer.sign(&advert_message(self, &advert)).map_err(|e| {
            IrohError::Backend(format!(
                "machine key refused to sign the update advert: {e}"
            ))
        })?;
        self.update = Some(SignedUpdateAdvert {
            advert,
            signature: hex::encode(signature),
        });
        Ok(())
    }

    /// The advert this record states, once its signature verifies under the
    /// record's machine key. `Ok(None)` for a record that states none.
    pub fn verified_update(&self) -> Result<Option<&UpdateAdvert>, RecordError> {
        let Some(s) = &self.update else {
            return Ok(None);
        };
        s.advert.check_shape()?;
        let sig = hex::decode(&s.signature)
            .map_err(|_| RecordError::Malformed("update advert signature"))?;
        if !verify_p256(&self.machine_key, &advert_message(self, &s.advert), &sig) {
            return Err(RecordError::BadUpdateAdvert);
        }
        Ok(Some(&s.advert))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity_record::tests::TestMachineKey;
    use crate::identity_record::{EndpointKey, RecordScope};

    const NOW: u64 = 1_900_000_000_000;

    fn record(machine: &TestMachineKey, sequence: u64) -> EndpointRecord {
        EndpointRecord::sign(
            machine,
            EndpointKey {
                transport: "test/ed25519".into(),
                key: vec![sequence as u8; 32],
            },
            Vec::new(),
            Vec::new(),
            None,
            RecordScope::Network,
            Vec::new(),
            sequence,
            NOW,
        )
        .unwrap()
    }

    fn advert() -> UpdateAdvert {
        UpdateAdvert {
            binary_version: "0.2.1".into(),
            platform_digest: "ab".repeat(32),
            state: UpdateState::Running,
        }
    }

    #[test]
    fn a_signed_advert_verifies_and_survives_a_json_round_trip() {
        let m = TestMachineKey::from_seed(1);
        let mut r = record(&m, 1);
        assert_eq!(r.verified_update().unwrap(), None);
        r.attach_update(&m, advert()).unwrap();
        let back: EndpointRecord =
            serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
        assert_eq!(back.verified_update().unwrap(), Some(&advert()));
        // The record itself still verifies as it did before the advert.
        back.check_signed().unwrap();
    }

    #[test]
    fn a_node_that_never_heard_of_the_advert_still_accepts_the_record() {
        let m = TestMachineKey::from_seed(1);
        let mut r = record(&m, 1);
        r.attach_update(&m, advert()).unwrap();
        let mut json: serde_json::Value = serde_json::to_value(&r).unwrap();
        // An older node's EndpointRecord has no such field: simulate by removing it.
        json.as_object_mut().unwrap().remove("update");
        let old_view: EndpointRecord = serde_json::from_value(json).unwrap();
        old_view.check_signed().unwrap();
    }

    #[test]
    fn a_forged_or_moved_advert_is_refused() {
        let m = TestMachineKey::from_seed(1);
        let mut r = record(&m, 1);
        r.attach_update(&m, advert()).unwrap();
        let mut forged = r.clone();
        forged.update.as_mut().unwrap().advert.binary_version = "9.9.9".into();
        assert!(matches!(
            forged.verified_update(),
            Err(RecordError::BadUpdateAdvert)
        ));
        // The same advert moved onto a later record of the same machine.
        let mut other = record(&m, 2);
        other.update = r.update.clone();
        assert!(matches!(
            other.verified_update(),
            Err(RecordError::BadUpdateAdvert)
        ));
        // Signed by another machine.
        let mut theirs = record(&m, 1);
        theirs
            .attach_update(&TestMachineKey::from_seed(2), advert())
            .unwrap();
        assert!(matches!(
            theirs.verified_update(),
            Err(RecordError::BadUpdateAdvert)
        ));
    }

    #[test]
    fn a_malformed_advert_is_not_signed() {
        let m = TestMachineKey::from_seed(1);
        let mut r = record(&m, 1);
        let mut a = advert();
        a.platform_digest = "xyz".into();
        assert!(r.attach_update(&m, a).is_err());
        assert!(r.update.is_none());
    }
}
