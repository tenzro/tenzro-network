//! How a `did:tenzro` identifier is derived from the key that roots it.
//!
//! Every Tenzro DID is a one-way function of a public key. Nothing is random
//! and nothing is a stored mapping: given the key, anyone recomputes the DID;
//! given the DID, only the key's holder can prove control. This module is the
//! single definition of those functions, shared by the identity registry that
//! mints DIDs and by the consensus rule that refuses a registration whose DID
//! does not derive from its key.
//!
//! | DID form | Derived from |
//! |---|---|
//! | `did:tenzro:human:{id}` | the passkey credential public key |
//! | `did:tenzro:machine:{id}` | the machine's own key (for a TPM-admitted machine, its attestation key) |
//! | `did:tenzro:machine:{controller}:{id}` | the controller id and the machine's device key |
//! | `did:tenzro:institution:{lei}:{id}` | the LEI and the institution's controller key |
//! | `did:tenzro:cluster:{id}` | the operator's DID and the cluster name |
//!
//! A cluster DID is the one form not rooted in a key: it names a group of
//! machines under one operator, so it derives from the operator's DID, and
//! it never signs anything. Every signature in a cluster is made by the
//! operator (its membership list) or by an individual machine.
//!
//! The identifier is the full SHA-256 of a domain tag and the length-prefixed
//! inputs, lowercase hex (64 characters), so identifiers carry 256 bits and a
//! collision cannot be searched for.

use sha2::{Digest, Sha256};

const HUMAN_DOMAIN: &[u8] = b"tenzro/human-did";
const MACHINE_DEVICE_DOMAIN: &[u8] = b"tenzro/machine-did/device-key";
const DELEGATED_DOMAIN: &[u8] = b"tenzro/machine-did/delegated";
const INSTITUTION_DOMAIN: &[u8] = b"tenzro/institution-did";
const CLUSTER_DOMAIN: &[u8] = b"tenzro/cluster-did";

/// Prefix of every cluster DID.
pub const CLUSTER_DID_PREFIX: &str = "did:tenzro:cluster:";

fn derive(domain: &[u8], parts: &[&[u8]]) -> String {
    let mut h = Sha256::new();
    h.update(domain);
    for p in parts {
        h.update((p.len() as u32).to_be_bytes());
        h.update(p);
    }
    hex::encode(h.finalize())
}

/// Identifier of a human DID rooted in `passkey_public_key`.
pub fn human_id(passkey_public_key: &[u8]) -> String {
    derive(HUMAN_DOMAIN, &[passkey_public_key])
}

/// Identifier of an autonomous machine DID rooted in its own key.
pub fn machine_device_id(device_public_key: &[u8]) -> String {
    derive(MACHINE_DEVICE_DOMAIN, &[device_public_key])
}

/// Label of the hardware P-256 key a node's network identity derives from.
///
/// The key lives in the machine's TPM 2.0 or Secure Enclave. It is also the
/// P-256 leg of a validator's consensus key, so a genesis validator entry,
/// which carries that key, names the validator's machine identity.
pub const MACHINE_KEY_LABEL: &str = "tenzro/consensus/validator";

/// Label of a machine's wallet key in its TPM 2.0 or Secure Enclave: the
/// P-256 key that names the machine's ledger account.
pub const MACHINE_WALLET_KEY_LABEL: &str = "machine/wallet";

/// The autonomous machine DID, `did:tenzro:machine:{id}`, of
/// `device_public_key`.
pub fn machine_did(device_public_key: &[u8]) -> String {
    format!(
        "did:tenzro:machine:{}",
        machine_device_id(device_public_key)
    )
}

/// Identifier of a machine delegated by `controller_id`, rooted in the
/// machine's own device key. Two machines under one controller have two
/// keys and therefore two DIDs; the same machine re-registering keeps its DID.
pub fn delegated_machine_id(controller_id: &str, device_public_key: &[u8]) -> String {
    derive(
        DELEGATED_DOMAIN,
        &[controller_id.as_bytes(), device_public_key],
    )
}

/// Identifier of an institution DID for `lei`, rooted in the institution's
/// controller key.
pub fn institution_id(lei: &str, controller_public_key: &[u8]) -> String {
    derive(INSTITUTION_DOMAIN, &[lei.as_bytes(), controller_public_key])
}

/// Identifier of the cluster `name` operated by `operator_did`. The same
/// operator naming the same cluster always gets the same identifier, and no
/// one else can: the operator's DID is an input.
pub fn cluster_id(operator_did: &str, name: &str) -> String {
    derive(CLUSTER_DOMAIN, &[operator_did.as_bytes(), name.as_bytes()])
}

/// The full DID of the cluster `name` operated by `operator_did`.
pub fn cluster_did(operator_did: &str, name: &str) -> String {
    format!("{CLUSTER_DID_PREFIX}{}", cluster_id(operator_did, name))
}

/// Whether `did` is the DID `key` derives in any form: human, autonomous
/// machine, delegated machine or institution. A cluster DID derives from no
/// key, so no key controls it.
pub fn did_derives_from_key(did: &str, key: &[u8]) -> bool {
    let Some(rest) = did.strip_prefix("did:tenzro:") else {
        return false;
    };
    if key.is_empty() {
        return false;
    }
    if let Some(id) = rest.strip_prefix("human:") {
        return id == human_id(key);
    }
    if let Some(rest) = rest.strip_prefix("machine:") {
        return match rest.split_once(':') {
            None => rest == machine_device_id(key),
            Some((controller, id)) => id == delegated_machine_id(controller, key),
        };
    }
    if let Some(rest) = rest.strip_prefix("institution:") {
        return match rest.split_once(':') {
            Some((lei, id)) => id == institution_id(lei, key),
            None => false,
        };
    }
    false
}

/// The CAIP-10 ids of `did`'s accounts on `chains`: the
/// `blockchainAccountId` of each in its DID document. A chain whose
/// deployment does not fit it is skipped.
pub fn blockchain_account_ids(
    did: &str,
    chains: &[crate::omni_account::AgentAccountChain],
) -> Vec<String> {
    chains
        .iter()
        .filter_map(|c| crate::omni_account::omni_address(did, &c.caip2, &c.deployment).ok())
        .map(|a| a.caip10())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_form_derives_only_from_its_own_key() {
        let k = [7u8; 65];
        let other = [8u8; 65];
        let human = format!("did:tenzro:human:{}", human_id(&k));
        assert!(did_derives_from_key(&human, &k));
        assert!(!did_derives_from_key(&human, &other));
        let machine = format!("did:tenzro:machine:{}", machine_device_id(&k));
        assert_eq!(machine, machine_did(&k));
        assert!(did_derives_from_key(&machine, &k));
        assert!(!did_derives_from_key(&machine, &other));
        let delegated = format!(
            "did:tenzro:machine:ctrl:{}",
            delegated_machine_id("ctrl", &k)
        );
        assert!(did_derives_from_key(&delegated, &k));
        assert!(!did_derives_from_key(&delegated, &other));
        let moved = format!(
            "did:tenzro:machine:ctrl2:{}",
            delegated_machine_id("ctrl", &k)
        );
        assert!(
            !did_derives_from_key(&moved, &k),
            "a DID cannot be moved under another controller"
        );
        let inst = format!("did:tenzro:institution:LEI:{}", institution_id("LEI", &k));
        assert!(did_derives_from_key(&inst, &k));
        assert!(!did_derives_from_key(&inst, &other));
    }

    #[test]
    fn identifiers_carry_the_full_digest() {
        assert_eq!(human_id(&[1; 65]).len(), 64);
        assert_ne!(
            human_id(&[1; 65]),
            machine_device_id(&[1; 65]),
            "domains are separated"
        );
    }

    #[test]
    fn two_machines_under_one_controller_get_two_dids() {
        assert_ne!(
            delegated_machine_id("c", &[1; 65]),
            delegated_machine_id("c", &[2; 65])
        );
    }

    #[test]
    fn a_cluster_did_derives_from_its_operator_and_name_and_from_no_key() {
        let op = format!("did:tenzro:human:{}", human_id(&[7; 65]));
        let other_op = format!("did:tenzro:human:{}", human_id(&[8; 65]));
        let did = cluster_did(&op, "lab");
        assert!(did.starts_with(CLUSTER_DID_PREFIX));
        assert_eq!(did, cluster_did(&op, "lab"));
        assert_ne!(did, cluster_did(&op, "lab2"));
        assert_ne!(did, cluster_did(&other_op, "lab"));
        assert!(!did_derives_from_key(&did, &[7; 65]));
    }

    #[test]
    fn a_random_identifier_derives_from_nothing() {
        let did = format!("did:tenzro:human:{}", uuid::Uuid::new_v4());
        assert!(!did_derives_from_key(&did, &[7u8; 65]));
    }
}
