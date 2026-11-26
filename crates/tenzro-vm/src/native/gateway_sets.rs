//! Sets governance puts on chain for what a node reads from outside the
//! chain: the key set NVIDIA's attestation tokens are verified under, the
//! machine identities a node dials to find the network, and the release keys
//! a signed update notice must verify under.
//!
//! Each set is replaced whole by a policy update and refused until its own
//! gate is in force. A node reads the set from chain state; a node with no
//! chain state yet (a fresh one) reads what its genesis file names.

use super::funding::{read_json, write_json};
use super::*;

/// The gate of [`tenzro_types::token::PolicyUpdate::NrasJwksSet`].
pub const NRAS_JWKS_GATE: &str = "feature.nras_jwks.activation_epoch";

/// The gate of [`tenzro_types::token::PolicyUpdate::BootNodesSet`].
pub const BOOT_NODES_GATE: &str = "feature.boot_nodes.activation_epoch";

/// The gate of [`tenzro_types::token::PolicyUpdate::UpdateNoticeKeysSet`].
pub const UPDATE_NOTICE_KEYS_GATE: &str = "feature.update_notice_keys.activation_epoch";

/// Where the governed NVIDIA attestation key set (JWKS JSON) is kept.
pub const NRAS_JWKS_KEY: &str = "nras_jwks";

/// Where the governed boot node identities are kept.
pub const BOOT_NODES_KEY: &str = "boot_nodes";

/// Where the governed update notice keys (hex SEC1 P-256) are kept.
pub const UPDATE_NOTICE_KEYS_KEY: &str = "update_notice_keys";

/// Largest key set document a proposal may carry, in bytes.
pub const MAX_JWKS_BYTES: usize = 64 * 1024;

/// Most boot node identities a proposal may name.
pub const MAX_BOOT_NODES: usize = 64;

/// Most update notice keys a proposal may name.
pub const MAX_UPDATE_NOTICE_KEYS: usize = 16;

/// The prefix of a machine identity.
const MACHINE_DID_PREFIX: &str = "did:tenzro:machine:";

/// Why a set is not acceptable.
pub fn check_nras_jwks(jwks_json: &str) -> std::result::Result<(), String> {
    if jwks_json.is_empty() {
        return Ok(());
    }
    if jwks_json.len() > MAX_JWKS_BYTES {
        return Err(format!("a key set is at most {MAX_JWKS_BYTES} bytes"));
    }
    let doc: serde_json::Value =
        serde_json::from_str(jwks_json).map_err(|e| format!("the key set is not JSON: {e}"))?;
    let keys = doc
        .get("keys")
        .and_then(|k| k.as_array())
        .filter(|k| !k.is_empty())
        .ok_or("the key set names no keys")?;
    let mut ids = std::collections::BTreeSet::new();
    for key in keys {
        let text = |field: &str| {
            key.get(field)
                .and_then(|v| v.as_str())
                .filter(|v| !v.is_empty())
        };
        let kid = text("kid").ok_or("a key in the set has no `kid`")?;
        if !ids.insert(kid.to_string()) {
            return Err(format!("the key id {kid:?} appears twice"));
        }
        // The key material a signature is checked with: a set whose keys
        // carry none would make every GPU report fail.
        let material: &[&str] = match text("kty") {
            Some("EC") => &["crv", "x", "y"],
            Some("RSA") => &["n", "e"],
            Some(other) => {
                return Err(format!(
                    "key {kid:?} has a type {other:?} NVIDIA does not sign with"
                ));
            }
            None => return Err(format!("key {kid:?} has no `kty`")),
        };
        for field in material {
            if text(field).is_none() {
                return Err(format!("key {kid:?} has no `{field}`"));
            }
        }
    }
    Ok(())
}

/// Why a boot node list is not acceptable.
pub fn check_boot_nodes(identities: &[String]) -> std::result::Result<(), String> {
    if identities.len() > MAX_BOOT_NODES {
        return Err(format!("name at most {MAX_BOOT_NODES} boot nodes"));
    }
    let mut seen = std::collections::BTreeSet::new();
    for identity in identities {
        if !seen.insert(identity.as_str()) {
            return Err(format!("{identity:?} is named twice"));
        }
        let rest = identity
            .strip_prefix(MACHINE_DID_PREFIX)
            .ok_or_else(|| format!("{identity:?} is not a machine identity"))?;
        let (id, relay) = match rest.split_once('@') {
            Some((id, relay)) => (id, Some(relay)),
            None => (rest, None),
        };
        if id.is_empty() || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return Err(format!("{identity:?} names no machine"));
        }
        if relay.is_some_and(|r| !r.starts_with("https://") || r.len() <= "https://".len()) {
            return Err(format!(
                "{identity:?} names a relay that is not an https URL"
            ));
        }
    }
    Ok(())
}

/// Why an update notice key list is not acceptable.
pub fn check_update_notice_keys(keys_hex: &[String]) -> std::result::Result<(), String> {
    if keys_hex.is_empty() || keys_hex.len() > MAX_UPDATE_NOTICE_KEYS {
        return Err(format!(
            "name between 1 and {MAX_UPDATE_NOTICE_KEYS} release keys"
        ));
    }
    for key in keys_hex {
        let bytes = hex::decode(key).map_err(|e| format!("a release key is not hex: {e}"))?;
        p256::ecdsa::VerifyingKey::from_sec1_bytes(&bytes)
            .map_err(|_| "a release key is not a SEC1 P-256 point".to_string())?;
    }
    Ok(())
}

/// The NVIDIA attestation key set governance put in force, if any.
pub fn nras_jwks(state: &dyn VmState) -> Option<String> {
    read_json::<String>(state, NRAS_JWKS_KEY).filter(|s| !s.is_empty())
}

/// The key set a block verifies NVIDIA reports under, once
/// `feature.nras_jwks.activation_epoch` is in force: the chain's set alone,
/// and none (every GPU report refused) when it holds none. `None` before the
/// gate: the rule has not started and blocks keep the behaviour they had.
pub fn nras_jwks_for_block(state: &dyn VmState) -> Option<Option<String>> {
    crate::feature_gate::is_live_now(state, NRAS_JWKS_GATE).then(|| nras_jwks(state))
}

/// The boot node identities governance put in force. Empty when none were.
pub fn boot_nodes(state: &dyn VmState) -> Vec<String> {
    read_json(state, BOOT_NODES_KEY).unwrap_or_default()
}

/// The update notice keys (hex SEC1 P-256) governance put in force. Empty
/// when none were.
pub fn update_notice_keys(state: &dyn VmState) -> Vec<String> {
    read_json(state, UPDATE_NOTICE_KEYS_KEY).unwrap_or_default()
}

/// Replace the NVIDIA attestation key set.
pub(crate) fn set_nras_jwks(
    state: &mut dyn VmState,
    jwks_json: &str,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    write_json(state, NRAS_JWKS_KEY, &jwks_json.to_string(), changes).map(|_| ())
}

/// Replace the boot node identities.
pub(super) fn set_boot_nodes(
    state: &mut dyn VmState,
    identities: &[String],
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    write_json(state, BOOT_NODES_KEY, &identities.to_vec(), changes).map(|_| ())
}

/// Replace the update notice keys.
pub(super) fn set_update_notice_keys(
    state: &mut dyn VmState,
    keys_hex: &[String],
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    write_json(state, UPDATE_NOTICE_KEYS_KEY, &keys_hex.to_vec(), changes).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StateAdapter;

    /// A policy update travels as its variant's index in bincode, so the
    /// order of `PolicyUpdate`'s variants is part of the wire format: these
    /// three were appended after `WebauthnRootsSet` and must stay where they
    /// are, and nothing may be inserted before them.
    #[test]
    fn the_three_sets_keep_their_variant_indexes() {
        use tenzro_types::token::PolicyUpdate as P;
        let index = |update: &P| {
            let bytes = bincode::serialize(update).unwrap();
            u32::from_le_bytes(bytes[..4].try_into().unwrap())
        };
        assert_eq!(index(&P::WebauthnRootsSet { roots_pem: vec![] }), 13);
        assert_eq!(
            index(&P::NrasJwksSet {
                jwks_json: String::new()
            }),
            14
        );
        assert_eq!(index(&P::BootNodesSet { identities: vec![] }), 15);
        assert_eq!(index(&P::UpdateNoticeKeysSet { keys_hex: vec![] }), 16);
    }

    #[test]
    fn a_key_set_names_keys_each_with_a_type_and_an_id() {
        assert!(check_nras_jwks("").is_ok());
        let ec = r#"{"kty":"EC","kid":"a","crv":"P-384","x":"AA","y":"BB"}"#;
        assert!(check_nras_jwks(&format!(r#"{{"keys":[{ec}]}}"#)).is_ok());
        assert!(
            check_nras_jwks(r#"{"keys":[{"kty":"RSA","kid":"r","n":"AA","e":"AQAB"}]}"#).is_ok()
        );
        assert!(check_nras_jwks(r#"{"keys":[]}"#).is_err());
        assert!(check_nras_jwks(r#"{"keys":[{"kty":"EC"}]}"#).is_err());
        // Only a type and an id: no key to check a signature with.
        assert!(check_nras_jwks(r#"{"keys":[{"kty":"EC","kid":"a"}]}"#).is_err());
        assert!(check_nras_jwks(&format!(r#"{{"keys":[{ec},{ec}]}}"#)).is_err());
        assert!(check_nras_jwks(r#"{"keys":[{"kty":"oct","kid":"a","k":"AA"}]}"#).is_err());
        assert!(check_nras_jwks("not json").is_err());
        assert!(check_nras_jwks(&"x".repeat(MAX_JWKS_BYTES + 1)).is_err());
    }

    #[test]
    fn a_boot_node_is_a_machine_identity_with_an_optional_https_relay() {
        let ok = vec![
            "did:tenzro:machine:abc123".to_string(),
            "did:tenzro:machine:abc123@https://relay.example/".to_string(),
        ];
        assert!(check_boot_nodes(&ok).is_ok());
        assert!(check_boot_nodes(&[]).is_ok());
        for bad in [
            "did:tenzro:human:abc",
            "did:tenzro:machine:",
            "did:tenzro:machine:abc@http://relay.example/",
            "did:tenzro:machine:abc@https://",
            "did:tenzro:machine:a b",
        ] {
            assert!(check_boot_nodes(&[bad.to_string()]).is_err(), "{bad}");
        }
        let many: Vec<String> = (0..=MAX_BOOT_NODES)
            .map(|i| format!("did:tenzro:machine:m{i}"))
            .collect();
        assert!(check_boot_nodes(&many).is_err());
        let twice = vec!["did:tenzro:machine:a".to_string(); 2];
        assert!(check_boot_nodes(&twice).is_err());
    }

    #[test]
    fn an_update_key_is_a_p256_point_and_the_list_is_never_empty() {
        let key = p256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap();
        let sec1 = hex::encode(key.verifying_key().to_sec1_point(false).as_bytes());
        assert!(check_update_notice_keys(&[sec1]).is_ok());
        assert!(check_update_notice_keys(&[]).is_err());
        assert!(check_update_notice_keys(&["zz".to_string()]).is_err());
        assert!(check_update_notice_keys(&["04".repeat(65)]).is_err());
    }

    #[test]
    fn a_set_is_read_back_as_written() {
        let mut state = StateAdapter::new();
        let mut changes = Vec::new();
        assert_eq!(nras_jwks(&state), None);
        assert!(boot_nodes(&state).is_empty());
        assert!(update_notice_keys(&state).is_empty());
        set_nras_jwks(&mut state, r#"{"keys":[]}"#, &mut changes).unwrap();
        set_boot_nodes(
            &mut state,
            &["did:tenzro:machine:a".to_string()],
            &mut changes,
        )
        .unwrap();
        set_update_notice_keys(&mut state, &["04".to_string()], &mut changes).unwrap();
        assert_eq!(nras_jwks(&state).as_deref(), Some(r#"{"keys":[]}"#));
        assert_eq!(boot_nodes(&state), vec!["did:tenzro:machine:a".to_string()]);
        assert_eq!(update_notice_keys(&state), vec!["04".to_string()]);
        set_nras_jwks(&mut state, "", &mut changes).unwrap();
        assert_eq!(nras_jwks(&state), None);
    }
}
