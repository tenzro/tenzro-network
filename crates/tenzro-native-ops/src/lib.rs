//! The operations a `NativeCall` transaction carries.
//!
//! A `NativeCall { selector, data }` names one native operation by its
//! 4-byte selector and carries its payload as JSON. This crate holds each
//! operation's selector, payload type and stateless check, so a client
//! builds and a node checks the same bytes; the rules that run in consensus
//! are in `tenzro-vm`, which lists the selectors a `NativeCall` may reach. A
//! new operation lands here and in `tenzro-vm`, and the transaction format
//! itself (`tenzro-types`) does not change.

pub mod bond_with_stable;
pub mod build_attestation;
pub mod gateway_delivery;
pub mod identity_keys;
pub mod identity_succession;
pub mod provider_presence;
pub mod rpc_provider;
pub mod zk_verdict;

use serde::Serialize;

// Every operation's selector, one value each. A new operation takes the
// next value in this list, declares its constant below and adds it to the
// distinctness test.
//
//   0x010000DE  identity key change
//   0x010000DF  identity succession
//   0x010000E0  build attestation
//   0x010000E1  provider presence
//   0x010000E2  RPC provider naming
//   0x010000E3  gateway delivery
//   0x010000E4  bond with stable
//   0x010000E5  enrol storage challenger
//   0x010000E6  storage challenge report
//   0x010000E7  ZK verdict
//   0x010000E8  machine controller record
//
// 0x010000F0 is the wrapper selector the VM reads a NativeCall under.

/// An identity's key change ([`identity_keys::IdentityKeyOp`]).
pub const SELECTOR_IDENTITY_KEYS: [u8; 4] = [0x01, 0x00, 0x00, 0xDE];

/// A root revoked in favour of a successor
/// ([`identity_succession::IdentitySuccessionOp`]).
pub const SELECTOR_IDENTITY_SUCCESSION: [u8; 4] = [0x01, 0x00, 0x00, 0xDF];

/// A builder's attestation of a release binary
/// ([`build_attestation::BuildAttestationOp`]).
pub const SELECTOR_BUILD_ATTESTATION: [u8; 4] = [0x01, 0x00, 0x00, 0xE0];

/// A compute provider stops or resumes serving
/// ([`provider_presence::ProviderPresenceOp`]).
pub const SELECTOR_PROVIDER_PRESENCE: [u8; 4] = [0x01, 0x00, 0x00, 0xE1];
/// A validator's verdict that a proof verifies
/// ([`zk_verdict::ZkVerdictOp`]).
pub const SELECTOR_ZK_VERDICT: [u8; 4] = [0x01, 0x00, 0x00, 0xE7];

/// A payee naming the validator that validates on its behalf
/// ([`rpc_provider::RpcProviderOp`]).
pub const SELECTOR_RPC_PROVIDER: [u8; 4] = [0x01, 0x00, 0x00, 0xE2];

/// A validator bond bought with a stable settlement asset
/// ([`bond_with_stable::BondWithStableOp`]).
pub const SELECTOR_BOND_WITH_STABLE: [u8; 4] = [0x01, 0x00, 0x00, 0xE4];

/// The delivery of an ERC-7786 gateway message
/// ([`gateway_delivery::GatewayDeliveryOp`]).
pub const SELECTOR_GATEWAY_DELIVERY: [u8; 4] = [0x01, 0x00, 0x00, 0xE3];

/// The payload of `op` as a `NativeCall` carries it.
pub fn encode(op: &impl Serialize) -> Vec<u8> {
    serde_json::to_vec(op).expect("an operation serializes to JSON")
}

/// Check `data` as the payload of the operation `selector` names, without
/// chain state: it decodes and its fields are well formed.
pub fn check(selector: [u8; 4], data: &[u8]) -> Result<(), String> {
    fn decode<T: serde::de::DeserializeOwned>(data: &[u8]) -> Result<T, String> {
        serde_json::from_slice(data).map_err(|e| format!("the payload does not decode: {e}"))
    }
    match selector {
        SELECTOR_IDENTITY_KEYS => decode::<identity_keys::IdentityKeyOp>(data)?
            .validate()
            .map_err(str::to_string),
        SELECTOR_IDENTITY_SUCCESSION => decode::<identity_succession::IdentitySuccessionOp>(data)?
            .validate()
            .map_err(str::to_string),
        SELECTOR_BUILD_ATTESTATION => decode::<build_attestation::BuildAttestationOp>(data)?
            .validate()
            .map_err(str::to_string),
        SELECTOR_PROVIDER_PRESENCE => decode::<provider_presence::ProviderPresenceOp>(data)?
            .validate()
            .map_err(str::to_string),
        SELECTOR_RPC_PROVIDER => decode::<rpc_provider::RpcProviderOp>(data)?
            .validate()
            .map_err(str::to_string),
        SELECTOR_ZK_VERDICT => decode::<zk_verdict::ZkVerdictOp>(data)?
            .validate()
            .map_err(str::to_string),
        SELECTOR_BOND_WITH_STABLE => decode::<bond_with_stable::BondWithStableOp>(data)?
            .validate()
            .map_err(str::to_string),
        SELECTOR_GATEWAY_DELIVERY => decode::<gateway_delivery::GatewayDeliveryOp>(data)?
            .validate()
            .map_err(str::to_string),
        other => Err(format!("{} names no native operation", hex::encode(other))),
    }
}

/// `Option<[u8; 32]>` as optional lowercase hex.
pub(crate) mod hex_array32_opt {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Option<[u8; 32]>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(b) => s.serialize_some(&hex::encode(b)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 32]>, D::Error> {
        Option::<String>::deserialize(d)?
            .map(|s| {
                hex::decode(s.trim_start_matches("0x"))
                    .map_err(serde::de::Error::custom)?
                    .try_into()
                    .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
            })
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selectors_are_distinct_and_others_name_nothing() {
        let all = [
            SELECTOR_IDENTITY_KEYS,
            SELECTOR_IDENTITY_SUCCESSION,
            SELECTOR_BUILD_ATTESTATION,
            SELECTOR_PROVIDER_PRESENCE,
            SELECTOR_ZK_VERDICT,
            SELECTOR_RPC_PROVIDER,
            SELECTOR_BOND_WITH_STABLE,
            SELECTOR_GATEWAY_DELIVERY,
        ];
        for (i, a) in all.iter().enumerate() {
            assert!(all[i + 1..].iter().all(|b| a != b));
        }
        assert!(check([0x01, 0x00, 0x00, 0x01], b"{}").is_err());
        assert!(check(SELECTOR_BUILD_ATTESTATION, b"not json").is_err());
    }

    #[test]
    fn a_provider_presence_round_trips_and_is_checked() {
        let op = provider_presence::ProviderPresenceOp {
            provider_did: "did:tenzro:machine:gpu".into(),
            online: false,
        };
        check(SELECTOR_PROVIDER_PRESENCE, &encode(&op)).unwrap();
        for did in ["", "gpu", &format!("did:{}", "x".repeat(253))] {
            let bad = provider_presence::ProviderPresenceOp {
                provider_did: did.to_string(),
                ..op.clone()
            };
            assert!(
                check(SELECTOR_PROVIDER_PRESENCE, &encode(&bad)).is_err(),
                "{did}"
            );
        }
        assert!(check(SELECTOR_PROVIDER_PRESENCE, b"{\"provider_did\":\"did:x\"}").is_err());
    }

    #[test]
    fn a_gateway_delivery_round_trips_and_is_checked() {
        let op = gateway_delivery::GatewayDeliveryOp {
            adapter: tenzro_types::bridge_route::BridgeRouteAdapter::Ccip,
            source_chain: "ethereum".into(),
            delivery: vec![1, 2, 3],
        };
        check(SELECTOR_GATEWAY_DELIVERY, &encode(&op)).unwrap();
        let empty = gateway_delivery::GatewayDeliveryOp {
            delivery: vec![],
            ..op.clone()
        };
        assert!(check(SELECTOR_GATEWAY_DELIVERY, &encode(&empty)).is_err());
        let unnamed = gateway_delivery::GatewayDeliveryOp {
            source_chain: String::new(),
            ..op
        };
        assert!(check(SELECTOR_GATEWAY_DELIVERY, &encode(&unnamed)).is_err());
    }

    #[test]
    fn a_build_attestation_round_trips_and_is_checked() {
        let op = build_attestation::BuildAttestationOp {
            version: "0.2.2".into(),
            platform: "x86_64-unknown-linux-gnu".into(),
            code_hash: vec![7; 32],
        };
        check(SELECTOR_BUILD_ATTESTATION, &encode(&op)).unwrap();
        let short = build_attestation::BuildAttestationOp {
            code_hash: vec![7; 31],
            ..op.clone()
        };
        assert!(check(SELECTOR_BUILD_ATTESTATION, &encode(&short)).is_err());
        let platform = build_attestation::BuildAttestationOp {
            platform: "X86".into(),
            ..op
        };
        assert!(check(SELECTOR_BUILD_ATTESTATION, &encode(&platform)).is_err());
    }

    #[test]
    fn a_zk_verdict_names_two_commitments_and_a_system() {
        let op = zk_verdict::ZkVerdictOp {
            statement: vec![1; 32],
            proof: vec![2; 32],
            system: "koala-bear-sha256-fri".into(),
        };
        check(SELECTOR_ZK_VERDICT, &encode(&op)).unwrap();
        let short = zk_verdict::ZkVerdictOp {
            proof: vec![2; 31],
            ..op.clone()
        };
        assert!(check(SELECTOR_ZK_VERDICT, &encode(&short)).is_err());
        let unnamed = zk_verdict::ZkVerdictOp {
            system: String::new(),
            ..op.clone()
        };
        assert!(check(SELECTOR_ZK_VERDICT, &encode(&unnamed)).is_err());
        let long = zk_verdict::ZkVerdictOp {
            system: "x".repeat(65),
            ..op
        };
        assert!(check(SELECTOR_ZK_VERDICT, &encode(&long)).is_err());
    }

    #[test]
    fn an_rpc_provider_is_named_by_a_full_account() {
        for len in [20, 32] {
            let op = rpc_provider::RpcProviderOp {
                provider: vec![3; len],
            };
            check(SELECTOR_RPC_PROVIDER, &encode(&op)).unwrap();
            assert!(!op.clears());
        }
        let short = rpc_provider::RpcProviderOp {
            provider: vec![3; 31],
        };
        assert!(check(SELECTOR_RPC_PROVIDER, &encode(&short)).is_err());
        assert!(
            rpc_provider::RpcProviderOp {
                provider: vec![0; 32]
            }
            .clears()
        );
    }
}
