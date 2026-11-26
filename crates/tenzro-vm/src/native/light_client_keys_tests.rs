//! The light client proves an identity's record and its revocation marker by
//! their state keys. It builds those keys itself, so they are held here to
//! the keys the executor writes.

use super::*;

/// The state key account storage is committed under.
fn committed_key(address: &[u8], slot: &[u8]) -> Vec<u8> {
    format!("storage:{}:{}", hex::encode(address), hex::encode(slot)).into_bytes()
}

#[test]
fn the_light_client_reads_the_slots_the_executor_writes() {
    let did = "did:tenzro:human:7f1c";
    assert_eq!(
        tenzro_light::identity::STATE_NAMESPACE,
        tenzro_storage::CF_STATE
    );
    assert_eq!(
        tenzro_light::identity::system_slot(&tenzro_types::identity::identity_slot(did)),
        committed_key(&SYSTEM_ADDRESS, &identity_storage_key(did)),
    );
    assert_eq!(
        tenzro_light::identity::system_slot(&tenzro_light::identity::revocation_slot(did)),
        committed_key(&SYSTEM_ADDRESS, &identity_revocation_key(did)),
    );
}
