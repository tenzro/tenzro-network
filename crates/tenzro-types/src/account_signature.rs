//! The wire form of a signature by an account, guardian or machine identity:
//! a P-256 leg from a TPM, the Secure Enclave or a passkey, and an optional
//! hardware ML-DSA-65 leg. Verification lives in `tenzro_crypto::composite`.

/// Storage key, under the system account, of the ML-DSA-65 verifying key the
/// account with 32-byte slot `account_slot` (`tenzro_crypto::account_slot` of
/// its P-256 key) has enrolled. Every verifier takes an account's ML-DSA-65 key from
/// here, never from the record it verifies, and once one is enrolled the
/// account's signatures must carry the ML-DSA-65 leg.
pub fn enrolled_pq_key_storage_key(account_slot: &[u8; 32]) -> String {
    format!("account_pq_key:{}", hex::encode(account_slot))
}

/// The P-256 leg of a signature, in the form the hardware produced it.
///
/// Human-readable encodings (JSON) tag the form (`"form": "raw"` or
/// `"web_authn"`) and hex the bytes; binary encodings are positional, so a
/// signature inside a block or a consensus vertex round-trips.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClassicalProof {
    /// `r || s` (64 bytes, or DER) from a TPM or Secure Enclave, ECDSA with
    /// SHA-256 over `M'`.
    Raw {
        /// The signature bytes.
        signature: Vec<u8>,
    },
    /// A passkey assertion whose challenge is `tenzro_crypto::composite::webauthn_challenge`.
    WebAuthn {
        /// `authenticatorData` as the authenticator returned it.
        authenticator_data: Vec<u8>,
        /// `clientDataJSON` exactly as the client produced it.
        client_data_json: Vec<u8>,
        /// The assertion signature (DER or `r || s`).
        signature: Vec<u8>,
    },
}

/// A signature: the P-256 leg and, when the signer holds one, the hardware
/// ML-DSA-65 leg.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompositeSignature {
    /// The P-256 leg.
    pub classical: ClassicalProof,
    /// The ML-DSA-65 leg (3309 bytes), when present.
    pub pq: Option<Vec<u8>>,
}

impl Default for CompositeSignature {
    /// No signature: the P-256 leg is empty. For a record whose signature is
    /// carried in another field.
    fn default() -> Self {
        Self {
            classical: ClassicalProof::Raw {
                signature: Vec::new(),
            },
            pq: None,
        }
    }
}

impl CompositeSignature {
    /// A P-256-only signature.
    pub fn classical(classical: ClassicalProof) -> Self {
        Self {
            classical,
            pq: None,
        }
    }

    /// Whether the P-256 leg carries signature bytes.
    pub fn has_classical_leg(&self) -> bool {
        match &self.classical {
            ClassicalProof::Raw { signature } => !signature.is_empty(),
            ClassicalProof::WebAuthn { signature, .. } => !signature.is_empty(),
        }
    }

    /// A hybrid signature.
    pub fn hybrid(classical: ClassicalProof, pq: Vec<u8>) -> Self {
        Self {
            classical,
            pq: Some(pq),
        }
    }
}

/// Length of an ML-DSA-65 verifying key.
pub const ML_DSA_65_PUBLIC_KEY_LEN: usize = 1952;

/// An operation on the keys of the sending account.
///
/// The sender's P-256 key names the account and never changes. Its ML-DSA-65
/// key is enrolled here and can afterwards only be replaced, never removed,
/// so a signature without the ML-DSA-65 leg is refused for good.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountKeysOp {
    /// Enroll `ml_dsa_public_key` as the account's ML-DSA-65 key, or replace
    /// the enrolled one. The transaction carries both legs: the ML-DSA-65
    /// leg verifies against the enrolled key, or against this key when none
    /// is enrolled yet. `possession` is this key's ML-DSA-65 signature, for
    /// context `PqKeyEnrollment`, over [`pq_enrollment_message`].
    EnrollPqKey {
        /// The hardware ML-DSA-65 verifying key.
        #[serde(with = "crate::remote_grant::hex_bytes")]
        ml_dsa_public_key: Vec<u8>,
        /// Proof the hardware holds the key.
        #[serde(with = "crate::remote_grant::hex_bytes")]
        possession: Vec<u8>,
    },
    /// Retire the P-256 leg. From here the account's signatures need only
    /// the ML-DSA-65 leg, verified against the enrolled key; a P-256 leg they
    /// carry counts for nothing, and the P-256 key alone still spends
    /// nothing. The P-256 key keeps naming the account. Refused unless an
    /// ML-DSA-65 key is enrolled; signed with both legs; never undone.
    RetireP256 {},
    /// Require the ML-DSA-65 leg of every key that acts for the account: its
    /// own key, a passkey its keystore links, a recovery signer approving a
    /// change to it. From here a key with no ML-DSA-65 key enrolled signs
    /// nothing for the account, so a break of P-256 alone moves nothing from
    /// it. Sent by a key that acts for the account and has an ML-DSA-65 key
    /// enrolled, with both legs; never undone. Accounts that do not send it
    /// keep accepting P-256 alone from keys without an ML-DSA-65 key.
    RequirePqLeg {},
    /// Require the ML-DSA-65 leg of every serving node's signature for the
    /// agent `agent_did`, whose wallet this account's identity controls:
    /// each action and voucher a node signs for the agent must carry, beside
    /// its P-256 signature, an ML-DSA-65 signature by the key `nodes` names
    /// for it, so a break of a node's P-256 key moves nothing from the agent
    /// wallet. `nodes` covers every serving node of the agent's current
    /// terms, each with the node's proof that it holds the key. Sent by the
    /// controller with both legs; sending it again replaces the keys, and the
    /// requirement is never undone.
    RequireAgentPqLeg {
        /// The agent.
        agent_did: String,
        /// Each serving node's ML-DSA-65 key for the agent.
        nodes: Vec<AgentNodePqKey>,
    },
}

/// A serving node's ML-DSA-65 key for one agent.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AgentNodePqKey {
    /// The node's machine identity.
    pub machine_did: String,
    /// The node's ML-DSA-65 verifying key for the agent.
    #[serde(with = "crate::remote_grant::hex_bytes")]
    pub ml_dsa_public_key: Vec<u8>,
    /// The key's ML-DSA-65 signature, for context
    /// [`AGENT_NODE_PQ_POSSESSION_CONTEXT`], over
    /// [`agent_node_pq_possession_message`].
    #[serde(with = "crate::remote_grant::hex_bytes")]
    pub possession: Vec<u8>,
}

/// Most serving nodes one [`AccountKeysOp::RequireAgentPqLeg`] names.
pub const MAX_AGENT_PQ_NODES: usize = 32;

/// FIPS 204 context of a serving node's ML-DSA-65 signature over an agent
/// action's or voucher's digest.
pub const AGENT_NODE_PQ_CONTEXT: &[u8] = b"tenzro/agent/node-ml-dsa-65";

/// FIPS 204 context of a serving node's proof that it holds its ML-DSA-65
/// key for an agent.
pub const AGENT_NODE_PQ_POSSESSION_CONTEXT: &[u8] = b"tenzro/agent/node-ml-dsa-65/possession";

/// What a serving node's ML-DSA-65 key signs to prove possession: the agent,
/// the node and the key, each length-prefixed.
pub fn agent_node_pq_possession_message(agent_did: &str, machine_did: &str, key: &[u8]) -> Vec<u8> {
    let mut m = Vec::new();
    for part in [agent_did.as_bytes(), machine_did.as_bytes(), key] {
        m.extend_from_slice(&(part.len() as u32).to_be_bytes());
        m.extend_from_slice(part);
    }
    m
}

/// Storage key, under the system account, of the serving nodes' ML-DSA-65
/// keys for the agent whose wallet is `wallet` (20 bytes).
pub fn agent_pq_keys_storage_key(wallet: &[u8; 20]) -> String {
    format!("agent_pq_keys:{}", hex::encode(wallet))
}

impl AccountKeysOp {
    /// Stateless checks.
    pub fn validate(&self) -> Result<(), &'static str> {
        match self {
            Self::EnrollPqKey {
                ml_dsa_public_key,
                possession,
            } => {
                if crate::signature_scheme::SignatureScheme::split_public_key(ml_dsa_public_key)
                    .is_none_or(|(s, _)| s != crate::signature_scheme::SignatureScheme::default())
                {
                    return Err("an account's ML-DSA key is a 1952-byte ML-DSA-65 key");
                }
                if possession.is_empty() {
                    return Err("enrolling an ML-DSA-65 key needs its proof of possession");
                }
            }
            Self::RetireP256 {} | Self::RequirePqLeg {} => {}
            Self::RequireAgentPqLeg { agent_did, nodes } => {
                if agent_did.is_empty() || nodes.is_empty() || nodes.len() > MAX_AGENT_PQ_NODES {
                    return Err("an agent's ML-DSA keys name the agent and 1 to 32 serving nodes");
                }
                let mut seen = std::collections::BTreeSet::new();
                for n in nodes {
                    if n.ml_dsa_public_key.len() != ML_DSA_65_PUBLIC_KEY_LEN {
                        return Err("a serving node's ML-DSA key is a 1952-byte ML-DSA-65 key");
                    }
                    if n.possession.is_empty() || !seen.insert(n.machine_did.as_str()) {
                        return Err(
                            "each serving node is named once, with its proof of possession",
                        );
                    }
                }
            }
        }
        Ok(())
    }
}

/// Storage key, under the system account, marking that the account with
/// 32-byte slot `account_slot` has retired its P-256 leg.
pub fn retired_p256_storage_key(account_slot: &[u8; 32]) -> String {
    format!("account_p256_retired:{}", hex::encode(account_slot))
}

/// Storage key, under the system account, marking that the account
/// `account` (20 bytes) requires the ML-DSA-65 leg of every key acting for
/// it (see [`AccountKeysOp::RequirePqLeg`]).
pub fn pq_required_storage_key(account: &[u8; 20]) -> String {
    format!("account_pq_required:{}", hex::encode(account))
}

/// What the new key signs to prove possession: the account slot of the
/// sender's P-256 key followed by the new key, so the proof enrolls that key
/// for that account and nothing else.
pub fn pq_enrollment_message(account_slot: &[u8; 32], ml_dsa_public_key: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(32 + ml_dsa_public_key.len());
    m.extend_from_slice(account_slot);
    m.extend_from_slice(ml_dsa_public_key);
    m
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(b: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(b))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(s.trim_start_matches("0x")).map_err(serde::de::Error::custom)
    }
}

mod opt_hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(b: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match b {
            Some(b) => s.serialize_str(&hex::encode(b)),
            None => s.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        Option::<String>::deserialize(d)?
            .map(|s| hex::decode(s.trim_start_matches("0x")).map_err(serde::de::Error::custom))
            .transpose()
    }
}

/// The two encodings of [`ClassicalProof`] and [`CompositeSignature`].
mod repr {
    use super::{ClassicalProof, CompositeSignature, hex_bytes, opt_hex_bytes};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Serialize, Deserialize)]
    #[serde(tag = "form", rename_all = "snake_case")]
    enum ProofText {
        Raw {
            #[serde(with = "hex_bytes")]
            signature: Vec<u8>,
        },
        WebAuthn {
            #[serde(with = "hex_bytes")]
            authenticator_data: Vec<u8>,
            #[serde(with = "hex_bytes")]
            client_data_json: Vec<u8>,
            #[serde(with = "hex_bytes")]
            signature: Vec<u8>,
        },
    }

    #[derive(Serialize, Deserialize)]
    enum ProofBin {
        Raw {
            signature: Vec<u8>,
        },
        WebAuthn {
            authenticator_data: Vec<u8>,
            client_data_json: Vec<u8>,
            signature: Vec<u8>,
        },
    }

    #[derive(Serialize, Deserialize)]
    struct SigText {
        classical: ClassicalProof,
        #[serde(
            default,
            with = "opt_hex_bytes",
            skip_serializing_if = "Option::is_none"
        )]
        pq: Option<Vec<u8>>,
    }

    #[derive(Serialize, Deserialize)]
    struct SigBin {
        classical: ClassicalProof,
        pq: Option<Vec<u8>>,
    }

    impl Serialize for ClassicalProof {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            let (text, bin) = match self.clone() {
                ClassicalProof::Raw { signature } => (
                    ProofText::Raw {
                        signature: signature.clone(),
                    },
                    ProofBin::Raw { signature },
                ),
                ClassicalProof::WebAuthn {
                    authenticator_data,
                    client_data_json,
                    signature,
                } => (
                    ProofText::WebAuthn {
                        authenticator_data: authenticator_data.clone(),
                        client_data_json: client_data_json.clone(),
                        signature: signature.clone(),
                    },
                    ProofBin::WebAuthn {
                        authenticator_data,
                        client_data_json,
                        signature,
                    },
                ),
            };
            if s.is_human_readable() {
                text.serialize(s)
            } else {
                bin.serialize(s)
            }
        }
    }

    impl<'de> Deserialize<'de> for ClassicalProof {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            if d.is_human_readable() {
                Ok(match ProofText::deserialize(d)? {
                    ProofText::Raw { signature } => ClassicalProof::Raw { signature },
                    ProofText::WebAuthn {
                        authenticator_data,
                        client_data_json,
                        signature,
                    } => ClassicalProof::WebAuthn {
                        authenticator_data,
                        client_data_json,
                        signature,
                    },
                })
            } else {
                Ok(match ProofBin::deserialize(d)? {
                    ProofBin::Raw { signature } => ClassicalProof::Raw { signature },
                    ProofBin::WebAuthn {
                        authenticator_data,
                        client_data_json,
                        signature,
                    } => ClassicalProof::WebAuthn {
                        authenticator_data,
                        client_data_json,
                        signature,
                    },
                })
            }
        }
    }

    impl Serialize for CompositeSignature {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            let (classical, pq) = (self.classical.clone(), self.pq.clone());
            if s.is_human_readable() {
                SigText { classical, pq }.serialize(s)
            } else {
                SigBin { classical, pq }.serialize(s)
            }
        }
    }

    impl<'de> Deserialize<'de> for CompositeSignature {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            let (classical, pq) = if d.is_human_readable() {
                let t = SigText::deserialize(d)?;
                (t.classical, t.pq)
            } else {
                let b = SigBin::deserialize(d)?;
                (b.classical, b.pq)
            };
            Ok(CompositeSignature { classical, pq })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn samples() -> Vec<CompositeSignature> {
        vec![
            CompositeSignature::classical(ClassicalProof::Raw {
                signature: vec![1; 64],
            }),
            CompositeSignature::hybrid(
                ClassicalProof::WebAuthn {
                    authenticator_data: vec![2; 37],
                    client_data_json: b"{}".to_vec(),
                    signature: vec![3; 70],
                },
                vec![4; 3309],
            ),
        ]
    }

    #[test]
    fn signatures_round_trip_through_bincode_and_json() {
        for sig in samples() {
            let bin = bincode::serialize(&sig).unwrap();
            assert_eq!(
                bincode::deserialize::<CompositeSignature>(&bin).unwrap(),
                sig
            );
            let json = serde_json::to_value(&sig).unwrap();
            assert_eq!(
                serde_json::from_value::<CompositeSignature>(json).unwrap(),
                sig
            );
        }
        let json = serde_json::to_value(&samples()[0]).unwrap();
        assert_eq!(json["classical"]["form"], "raw");
        assert!(json.get("pq").is_none());
    }
}
