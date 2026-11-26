//! Checking a node's A2A agent card before trusting the node with a task.
//!
//! A card is served with detached signatures: each is a JWS whose payload is
//! the RFC 8785 canonical form of the card without its `signatures`, signed
//! with ES256 by the key in the signature's protected header. That alone
//! proves only that the card matches a key the card itself names. The key
//! is a machine's hardware identity key, and a machine DID is derived from
//! exactly that key, so the check that matters is the last one here: the DID
//! the signing key derives must be the DID the caller meant to reach.
//!
//! A card that does not pass is refused. There is no unverified fallback.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::signature::hazmat::PrehashVerifier as _;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::error::{SdkError, SdkResult};

/// Domain of a machine DID derived from its device key.
const MACHINE_DEVICE_DOMAIN: &[u8] = b"tenzro/machine-did/device-key";

fn refused(why: impl std::fmt::Display) -> SdkError {
    SdkError::AuthenticationError(format!("agent card refused: {why}"))
}

/// The machine DID of a hardware P-256 key `x || y`: the key's uncompressed
/// SEC1 form, length-prefixed, hashed under the machine DID domain.
pub fn machine_did(p256_xy: &[u8; 64]) -> String {
    let mut h = Sha256::new();
    h.update(MACHINE_DEVICE_DOMAIN);
    h.update(65u32.to_be_bytes());
    h.update([0x04]);
    h.update(p256_xy);
    format!("did:tenzro:machine:{}", hex::encode(h.finalize()))
}

/// The key of one card signature, after its signature verified over `card`.
fn signing_key(card: &Value, signature: &Value) -> SdkResult<[u8; 64]> {
    let text = |v: &Value, name: &str| -> SdkResult<String> {
        v.get(name)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| refused(format!("a signature has no {name}")))
    };
    let protected = text(signature, "protected")?;
    let header: Value = URL_SAFE_NO_PAD
        .decode(&protected)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .ok_or_else(|| refused("a signature's protected header cannot be read"))?;
    if header.get("alg").and_then(Value::as_str) != Some("ES256") {
        return Err(refused("a signature is not ES256"));
    }
    let jwk = header
        .get("jwk")
        .ok_or_else(|| refused("a signature names no key"))?;
    if jwk.get("kty").and_then(Value::as_str) != Some("EC")
        || jwk.get("crv").and_then(Value::as_str) != Some("P-256")
    {
        return Err(refused("the signing key is not a P-256 key"));
    }
    let mut xy = [0u8; 64];
    for (name, half) in [("x", 0), ("y", 32)] {
        let bytes = URL_SAFE_NO_PAD
            .decode(text(jwk, name)?)
            .ok()
            .filter(|b| b.len() == 32)
            .ok_or_else(|| refused(format!("the signing key's {name} is not 32 bytes")))?;
        xy[half..half + 32].copy_from_slice(&bytes);
    }
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..].copy_from_slice(&xy);
    let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
        .map_err(|_| refused("the signing key is not a point on P-256"))?;
    let raw = URL_SAFE_NO_PAD
        .decode(text(signature, "signature")?)
        .map_err(|_| refused("a signature is not base64url"))?;
    let sig = p256::ecdsa::Signature::from_slice(&raw)
        .map_err(|_| refused("a signature is not 64 bytes r || s"))?;
    // A hardware key returns either of a signature's two forms.
    let sig = sig.normalize_s().unwrap_or(sig);

    let mut unsigned = card.clone();
    unsigned
        .as_object_mut()
        .ok_or_else(|| refused("the card is not a JSON object"))?
        .remove("signatures");
    let payload = crate::a2a_envelope::canonical_json(&unsigned)
        .map_err(|e| refused(format!("the card has no canonical form: {e}")))?;
    let input = format!("{protected}.{}", URL_SAFE_NO_PAD.encode(payload.as_bytes()));
    key.verify_prehash(&Sha256::digest(input.as_bytes()), &sig)
        .map_err(|_| refused("a signature does not verify over the card"))?;
    // The header's own name for the key must be the DID the key derives.
    let did = machine_did(&xy);
    let kid = text(&header, "kid")?;
    if kid != did && !kid.starts_with(&format!("{did}#")) {
        return Err(refused(format!(
            "a signature claims the key of {kid}, but its key is {did}'s"
        )));
    }
    Ok(xy)
}

/// Check that `card` is signed, that every signature on it verifies, and that
/// one of them is by the hardware key `expected_machine_did` derives from.
///
/// # Errors
/// [`SdkError::AuthenticationError`] naming what failed: an unsigned card, a
/// signature that does not verify, a signature whose key is not the one its
/// header names, or a card signed only by other machines.
pub fn verify_agent_card(card: &Value, expected_machine_did: &str) -> SdkResult<()> {
    let signatures = card
        .get("signatures")
        .and_then(Value::as_array)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| refused("it carries no signature"))?;
    let mut signers = Vec::with_capacity(signatures.len());
    for signature in signatures {
        signers.push(machine_did(&signing_key(card, signature)?));
    }
    if signers.iter().any(|did| did == expected_machine_did) {
        Ok(())
    } else {
        Err(refused(format!(
            "it is signed by {}, not by {expected_machine_did}",
            signers.join(", ")
        )))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use p256::ecdsa::signature::hazmat::PrehashSigner as _;

    pub(crate) fn key(seed: u8) -> p256::ecdsa::SigningKey {
        p256::ecdsa::SigningKey::from_slice(&[seed; 32]).expect("key")
    }

    pub(crate) fn did_of(key: &p256::ecdsa::SigningKey) -> String {
        let point = key.verifying_key().to_encoded_point(false);
        machine_did(point.as_bytes()[1..].try_into().expect("x || y"))
    }

    /// `card` signed by `key`, whose header claims to be `claimed`'s key.
    pub(crate) fn sign_as(mut card: Value, key: &p256::ecdsa::SigningKey, claimed: &str) -> Value {
        card.as_object_mut().unwrap().remove("signatures");
        let point = key.verifying_key().to_encoded_point(false);
        let (x, y) = point.as_bytes()[1..].split_at(32);
        let header = serde_json::json!({
            "alg": "ES256",
            "typ": "JOSE",
            "kid": format!("{claimed}#hardware-key"),
            "jwk": { "kty": "EC", "crv": "P-256", "x": URL_SAFE_NO_PAD.encode(x), "y": URL_SAFE_NO_PAD.encode(y) },
        });
        let protected =
            URL_SAFE_NO_PAD.encode(crate::a2a_envelope::canonical_json(&header).unwrap());
        let payload = crate::a2a_envelope::canonical_json(&card).unwrap();
        let input = format!("{protected}.{}", URL_SAFE_NO_PAD.encode(payload));
        let sig: p256::ecdsa::Signature =
            key.sign_prehash(&Sha256::digest(input.as_bytes())).unwrap();
        card["signatures"] = serde_json::json!([{
            "protected": protected,
            "signature": URL_SAFE_NO_PAD.encode(sig.to_bytes()),
        }]);
        card
    }

    pub(crate) fn sign(card: Value, key: &p256::ecdsa::SigningKey) -> Value {
        let did = did_of(key);
        sign_as(card, key, &did)
    }

    pub(crate) fn card() -> Value {
        serde_json::json!({
            "name": "Tenzro Network Agent",
            "version": "0.2.2",
            "supportedInterfaces": [{"url": "https://a2a.example", "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}],
            "capabilities": {"streaming": true, "pushNotifications": false},
            "skills": [{"id": "wallet", "name": "Wallet Operations", "tags": ["wallet"]}],
        })
    }

    #[test]
    fn the_machine_did_matches_the_vector_the_ledgers_derivation_is_held_to() {
        let v: Value =
            serde_json::from_str(include_str!("../../fixtures/machine-did/vector.json")).unwrap();
        let xy: [u8; 64] = hex::decode(v["p256_xy"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(machine_did(&xy), v["machine_did"].as_str().unwrap());
    }

    #[test]
    fn the_machine_did_is_the_hash_of_the_keys_sec1_form_under_its_domain() {
        let k = key(5);
        let point = k.verifying_key().to_encoded_point(false);
        let mut h = Sha256::new();
        h.update(b"tenzro/machine-did/device-key");
        h.update([0, 0, 0, 65]);
        h.update(point.as_bytes());
        assert_eq!(
            did_of(&k),
            format!("did:tenzro:machine:{}", hex::encode(h.finalize()))
        );
        assert_ne!(did_of(&k), did_of(&key(6)));
    }

    #[test]
    fn a_card_signed_by_the_machine_the_caller_named_is_accepted() {
        let k = key(5);
        let signed = sign(card(), &k);
        verify_agent_card(&signed, &did_of(&k)).expect("a good card");
        // What is signed is the canonical form, so the card as it comes back
        // off the wire verifies the same.
        let wire: Value =
            serde_json::from_str(&serde_json::to_string_pretty(&signed).unwrap()).unwrap();
        verify_agent_card(&wire, &did_of(&k)).unwrap();
    }

    #[test]
    fn a_card_signed_by_another_key_is_refused() {
        let (ours, theirs) = (key(5), key(6));
        // Honestly signed by another machine: every signature verifies, but
        // none is by the machine the caller named.
        let err = verify_agent_card(&sign(card(), &theirs), &did_of(&ours)).unwrap_err();
        assert!(
            err.to_string().contains("not by did:tenzro:machine:"),
            "{err}"
        );
        // Signed by another key under the named machine's DID: the header's
        // name for the key is not the DID that key derives.
        let forged = sign_as(card(), &theirs, &did_of(&ours));
        let err = verify_agent_card(&forged, &did_of(&ours)).unwrap_err();
        assert!(err.to_string().contains("claims the key of"), "{err}");
    }

    #[test]
    fn a_card_naming_another_identity_is_refused() {
        let k = key(5);
        let signed = sign(card(), &k);
        let other = did_of(&key(9));
        let err = verify_agent_card(&signed, &other).unwrap_err();
        assert!(matches!(err, SdkError::AuthenticationError(_)), "{err}");
        assert!(err.to_string().contains(&other), "{err}");
    }

    #[test]
    fn an_unsigned_or_altered_card_is_refused() {
        let k = key(5);
        let did = did_of(&k);
        assert!(verify_agent_card(&card(), &did).is_err(), "unsigned");
        let mut empty = card();
        empty["signatures"] = serde_json::json!([]);
        assert!(verify_agent_card(&empty, &did).is_err(), "no signatures");
        let mut moved = sign(card(), &k);
        moved["supportedInterfaces"][0]["url"] = "https://elsewhere.example".into();
        let err = verify_agent_card(&moved, &did).unwrap_err();
        assert!(err.to_string().contains("does not verify"), "{err}");
        let mut added = sign(card(), &k);
        added["skills"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({"id": "inference"}));
        assert!(
            verify_agent_card(&added, &did).is_err(),
            "a skill was added"
        );
        // One good signature does not carry a bad one beside it.
        let mut two = sign(card(), &k);
        let bad = sign(card(), &key(6))["signatures"][0].clone();
        let mut broken = bad.clone();
        broken["signature"] = URL_SAFE_NO_PAD.encode([7u8; 64]).into();
        two["signatures"].as_array_mut().unwrap().push(broken);
        assert!(verify_agent_card(&two, &did).is_err());
        let mut both = sign(card(), &k);
        both["signatures"].as_array_mut().unwrap().push(bad);
        verify_agent_card(&both, &did).expect("two machines may sign one card");
    }
}
