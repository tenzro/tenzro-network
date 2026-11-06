//! Agents' accounts on other chains, and the grants that bound them.
//!
//! [`omni_address`] derives an agent's account on a chain from its DID and
//! the chain's deployment of the agent account code, as every Tenzro node
//! does. [`AgentAccountsClient`] reads accounts, grants and their proofs from
//! a node, asks the agent's serving node for grants and action signatures,
//! and builds the transaction that settles an account's report.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sha3::{Keccak256, Sha3_256};

use crate::error::{SdkError, SdkResult};
use crate::rpc::RpcClient;

/// Domain of the per-DID salt.
pub const SALT_DOMAIN: &[u8] = b"tenzro/omni-account/v1";
/// Domain of the digest serving nodes sign for an action.
pub const ACT_DOMAIN: &[u8] = b"tenzro/agent-act/v1";

/// Where the agent account code is deployed on one chain, as the node's
/// `tenzro_agentAccounts` and the network's configuration name it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "family", rename_all = "snake_case")]
pub enum AccountDeployment {
    Eip155 {
        factory: [u8; 20],
        init_code_hash: [u8; 32],
    },
    Solana {
        program_id: [u8; 32],
    },
    Sui {
        registry: [u8; 32],
    },
    Aptos {
        creator: [u8; 32],
    },
    Stellar {
        network_passphrase: String,
        factory: [u8; 32],
    },
    Cosmos {
        hrp: String,
        factory: Vec<u8>,
        code_checksum: [u8; 32],
    },
    Tvm {
        workchain: i8,
        code_hash: [u8; 32],
        code_depth: u16,
    },
}

/// An agent's account on one chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OmniAddress {
    pub caip2: String,
    pub address: String,
    #[serde(with = "hex_bytes")]
    pub raw: Vec<u8>,
}

mod hex_bytes {
    pub fn serialize<S: serde::Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s: String = serde::Deserialize::deserialize(d)?;
        hex::decode(s.trim_start_matches("0x")).map_err(serde::de::Error::custom)
    }
}

impl OmniAddress {
    /// CAIP-10: `namespace:reference:address`.
    pub fn caip10(&self) -> String {
        format!("{}:{}", self.caip2, self.address)
    }

    /// The ERC-7930 interoperable address, for EVM and Solana accounts.
    pub fn to_erc7930(&self) -> Option<Vec<u8>> {
        let (ns, reference) = self.caip2.split_once(':')?;
        let (chain_type, chain_ref): ([u8; 2], Vec<u8>) = match ns {
            "eip155" => {
                let id: u64 = reference.parse().ok()?;
                let b = id.to_be_bytes();
                let first = b.iter().position(|x| *x != 0).unwrap_or(7);
                ([0x00, 0x00], b[first..].to_vec())
            }
            "solana" => ([0x00, 0x02], bs58::decode(reference).into_vec().ok()?),
            _ => return None,
        };
        let mut out = vec![0x00, 0x01];
        out.extend_from_slice(&chain_type);
        out.push(u8::try_from(chain_ref.len()).ok()?);
        out.extend_from_slice(&chain_ref);
        out.push(u8::try_from(self.raw.len()).ok()?);
        out.extend_from_slice(&self.raw);
        Some(out)
    }
}

/// The per-DID salt.
pub fn salt(did: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(SALT_DOMAIN);
    h.update(did.as_bytes());
    h.finalize().into()
}

fn agent_hash(did: &str) -> [u8; 32] {
    Sha256::digest(did.as_bytes()).into()
}

/// The state tree key of the grant of `did` on `caip2`.
pub fn grant_tree_key(did: &str, caip2: &str) -> [u8; 32] {
    let key = format!(
        "storage:{}:{}",
        "f".repeat(40),
        hex::encode(format!("agent_grant:{did}:{caip2}"))
    );
    let mut h = Sha256::new();
    h.update(b"tenzro.state-trie.key");
    h.update(5u16.to_le_bytes());
    h.update(b"state");
    h.update(key.as_bytes());
    h.finalize().into()
}

/// The account of `did` on `caip2` under `deployment`.
pub fn omni_address(
    did: &str,
    caip2: &str,
    deployment: &AccountDeployment,
) -> SdkResult<OmniAddress> {
    let ns = caip2
        .split_once(':')
        .map(|(n, _)| n)
        .ok_or_else(|| SdkError::InvalidParameter(format!("{caip2} is not CAIP-2")))?;
    let family_ok = matches!(
        (ns, deployment),
        ("eip155", AccountDeployment::Eip155 { .. })
            | ("solana", AccountDeployment::Solana { .. })
            | ("sui", AccountDeployment::Sui { .. })
            | ("aptos", AccountDeployment::Aptos { .. })
            | ("stellar", AccountDeployment::Stellar { .. })
            | ("cosmos", AccountDeployment::Cosmos { .. })
            | ("tvm", AccountDeployment::Tvm { .. })
    );
    if !family_ok {
        return Err(SdkError::InvalidParameter(format!(
            "the deployment is not for {caip2}"
        )));
    }
    let s = salt(did);
    let (address, raw) = match deployment {
        AccountDeployment::Eip155 {
            factory,
            init_code_hash,
        } => {
            let mut h = Keccak256::new();
            h.update([0xff]);
            h.update(factory);
            h.update(s);
            h.update(init_code_hash);
            let raw = h.finalize()[12..].to_vec();
            (eip55(&raw), raw)
        }
        AccountDeployment::Solana { program_id } => {
            let seed = Sha256::digest(did.as_bytes());
            let raw = solana_pda(&[b"agent", &seed], program_id)
                .ok_or_else(|| SdkError::InvalidParameter("no program address".into()))?;
            (bs58::encode(raw).into_string(), raw.to_vec())
        }
        AccountDeployment::Sui { registry } => {
            let raw = sui_derived_address(registry, &s);
            (format!("0x{}", hex::encode(raw)), raw.to_vec())
        }
        AccountDeployment::Aptos { creator } => {
            let mut h = Sha3_256::new();
            h.update(creator);
            h.update(s);
            h.update([0xfe]);
            let raw: [u8; 32] = h.finalize().into();
            (format!("0x{}", hex::encode(raw)), raw.to_vec())
        }
        AccountDeployment::Stellar {
            network_passphrase,
            factory,
        } => {
            let raw = stellar_contract_id(network_passphrase, factory, &s);
            (stellar_strkey(0x10, &raw), raw.to_vec())
        }
        AccountDeployment::Cosmos {
            hrp,
            factory,
            code_checksum,
        } => {
            let raw = instantiate2(code_checksum, factory, &s);
            let hrp = bech32::Hrp::parse(hrp)
                .map_err(|_| SdkError::InvalidParameter("bech32 prefix".into()))?;
            let text = bech32::encode::<bech32::Bech32>(hrp, &raw)
                .map_err(|_| SdkError::InvalidParameter("bech32".into()))?;
            (text, raw.to_vec())
        }
        AccountDeployment::Tvm {
            workchain,
            code_hash,
            code_depth,
        } => {
            let raw = ton_state_init_hash(
                code_hash,
                *code_depth,
                &agent_hash(did),
                &grant_tree_key(did, caip2),
            );
            (format!("{workchain}:{}", hex::encode(raw)), raw.to_vec())
        }
    };
    Ok(OmniAddress {
        caip2: caip2.to_string(),
        address,
        raw,
    })
}

/// An action of an agent account, encoded as its digest covers it: target
/// and selector (u16-prefixed), amount and relay refund (u128), data
/// (u32-prefixed), big-endian.
pub fn encode_action(
    target: &[u8],
    selector: &[u8],
    amount: u128,
    relay_refund: u128,
    data: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(target.len() as u16).to_be_bytes());
    out.extend_from_slice(target);
    out.extend_from_slice(&(selector.len() as u16).to_be_bytes());
    out.extend_from_slice(selector);
    out.extend_from_slice(&amount.to_be_bytes());
    out.extend_from_slice(&relay_refund.to_be_bytes());
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
    out
}

/// The digest serving nodes sign for action `nonce` under grant `seq` of
/// `account` (left-padded to 32 bytes) on the chain `caip2`.
pub fn act_digest(
    caip2: &str,
    account: &[u8; 32],
    seq: u64,
    nonce: u64,
    action: &[u8],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(ACT_DOMAIN);
    h.update(Sha256::digest(caip2.as_bytes()));
    h.update(account);
    h.update(seq.to_be_bytes());
    h.update(nonce.to_be_bytes());
    h.update(action);
    h.finalize().into()
}

/// Domain tag of a channel voucher an agent's account pays.
pub const CHANNEL_DOMAIN: &[u8] = b"tenzro/agent-channel/v1";

/// The digest a serving node signs for a voucher paying `cumulative` on
/// channel `channel_id` of `account` (left-padded to 32 bytes) on `caip2`.
pub fn channel_voucher_digest(
    caip2: &str,
    account: &[u8; 32],
    channel_id: u64,
    cumulative: u128,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(CHANNEL_DOMAIN);
    h.update(Sha256::digest(caip2.as_bytes()));
    h.update(account);
    h.update(channel_id.to_be_bytes());
    h.update(cumulative.to_be_bytes());
    h.finalize().into()
}

/// The 104 bytes a paying action carries: the Tenzro payee, the request and
/// quote digests it bought, and the USD price (micro-units, big-endian). The
/// account reports them with the amount for Tenzro to record the payment.
pub fn pay_data(
    payee: &[u8; 32],
    request_digest: &[u8; 32],
    quote_digest: &[u8; 32],
    usd_e6: u64,
) -> [u8; 104] {
    let mut out = [0u8; 104];
    out[..32].copy_from_slice(payee);
    out[32..64].copy_from_slice(request_digest);
    out[64..96].copy_from_slice(quote_digest);
    out[96..].copy_from_slice(&usd_e6.to_be_bytes());
    out
}

/// Reads agents' accounts and grants, and asks serving nodes for grants and
/// action signatures (with the agent's access token on the transport).
#[derive(Clone)]
pub struct AgentAccountsClient {
    rpc: Arc<RpcClient>,
}

impl AgentAccountsClient {
    pub(crate) fn new(rpc: Arc<RpcClient>) -> Self {
        Self { rpc }
    }

    /// The agent's account on every configured chain.
    pub async fn accounts(&self, did: &str) -> SdkResult<serde_json::Value> {
        self.rpc
            .call("tenzro_agentAccounts", serde_json::json!({ "did": did }))
            .await
    }

    /// Issue a grant on `chain` as the agent.
    pub async fn request_grant(
        &self,
        chain: &str,
        grant: serde_json::Value,
        step_up: Option<serde_json::Value>,
    ) -> SdkResult<serde_json::Value> {
        let mut p = serde_json::json!({ "chain": chain, "grant": grant });
        if let Some(s) = step_up {
            p["step_up"] = s;
        }
        self.rpc.call("tenzro_requestRemoteGrant", p).await
    }

    /// The agent's grant on `chain` and its state proof.
    pub async fn grant_proof(
        &self,
        did: &str,
        chain: &str,
        checkpoint: Option<u64>,
    ) -> SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_getAgentGrantProof",
                serde_json::json!({ "did": did, "chain": chain, "checkpoint": checkpoint }),
            )
            .await
    }

    /// The digest of an action and the proofs the account checks.
    pub async fn build_action(
        &self,
        did: &str,
        chain: &str,
        nonce: u64,
        action: serde_json::Value,
    ) -> SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_buildRemoteAction",
                serde_json::json!({ "did": did, "chain": chain, "nonce": nonce, "action": action }),
            )
            .await
    }

    /// The consent that makes the agent's account on an EVM `chain` the
    /// `agentWallet` of ERC-8004 entry `agent_id` owned by `owner`: the
    /// registry's EIP-712 digest, the `approveHash` action approving it (sign
    /// it with [`Self::sign_action`]) and the `setAgentWallet` calldata the
    /// owner sends. `registry` is the canonical registry when `None`.
    pub async fn wallet_consent(
        &self,
        did: &str,
        chain: &str,
        agent_id: u64,
        owner: &str,
        deadline: u64,
        registry: Option<&str>,
    ) -> SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_agentWalletConsent",
                serde_json::json!({
                    "did": did, "chain": chain, "agent_id": agent_id,
                    "owner": owner, "deadline": deadline, "registry": registry,
                }),
            )
            .await
    }

    /// The serving node's signature over an action, as the agent.
    pub async fn sign_action(
        &self,
        chain: &str,
        nonce: u64,
        action: serde_json::Value,
    ) -> SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_signRemoteAction",
                serde_json::json!({ "chain": chain, "nonce": nonce, "action": action }),
            )
            .await
    }

    /// The serving node's signature over a voucher on a channel the agent's
    /// account holds on `chain`, as the agent.
    pub async fn sign_channel_voucher(
        &self,
        chain: &str,
        channel_id: u64,
        cumulative: u128,
    ) -> SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_signRemoteChannelVoucher",
                serde_json::json!({ "chain": chain, "channel_id": channel_id, "cumulative_amount": cumulative.to_string() }),
            )
            .await
    }

    /// The `Payment` transaction type that records one payment the agent's
    /// account on `chain` reported, for any signer to submit.
    pub fn prove(agent_did: &str, chain: &str, delivery: &[u8]) -> serde_json::Value {
        serde_json::json!({ "Payment": { "op": { "proven": { "agent_did": agent_did, "chain": chain, "delivery": hex::encode(delivery) } } } })
    }

    /// The `RemoteGrantSettle` transaction type that settles one report of
    /// the agent's account on `chain`, for any signer to submit.
    pub fn relay(agent_did: &str, chain: &str, delivery: &[u8]) -> serde_json::Value {
        serde_json::json!({ "RemoteGrantSettle": { "agent_did": agent_did, "chain": chain, "delivery": hex::encode(delivery) } })
    }
}

/// The EIP-55 mixed-case form of a 20-byte address.
pub fn eip55(raw: &[u8]) -> String {
    let lower = hex::encode(raw);
    let hash = Keccak256::digest(lower.as_bytes());
    let mut out = String::from("0x");
    for (i, c) in lower.chars().enumerate() {
        let nibble = (hash[i / 2] >> (if i % 2 == 0 { 4 } else { 0 })) & 0xf;
        out.push(if c.is_ascii_alphabetic() && nibble >= 8 {
            c.to_ascii_uppercase()
        } else {
            c
        });
    }
    out
}

/// A Solana program address: the first bump from 255 down whose hash is off
/// the Ed25519 curve.
fn solana_pda(seeds: &[&[u8]], program_id: &[u8; 32]) -> Option<[u8; 32]> {
    for bump in (0..=255u8).rev() {
        let mut h = Sha256::new();
        for s in seeds {
            h.update(s);
        }
        h.update([bump]);
        h.update(program_id);
        h.update(b"ProgramDerivedAddress");
        let candidate: [u8; 32] = h.finalize().into();
        if curve25519_dalek::edwards::CompressedEdwardsY(candidate)
            .decompress()
            .is_none()
        {
            return Some(candidate);
        }
    }
    None
}

/// A Sui derived object's address: the dynamic field id of the key
/// `0x2::derived_object::DerivedObjectKey<vector<u8>>(key)` under `parent`.
fn sui_derived_address(parent: &[u8; 32], key: &[u8; 32]) -> [u8; 32] {
    use blake2::digest::consts::U32;
    use blake2::{Blake2b, Digest as _};
    // BCS of the key: a vector<u8> of 32 bytes.
    let mut key_bcs = vec![32u8];
    key_bcs.extend_from_slice(key);
    // BCS of its type tag.
    let mut tag = vec![7u8];
    let mut framework = [0u8; 32];
    framework[31] = 2;
    tag.extend_from_slice(&framework);
    for ident in ["derived_object", "DerivedObjectKey"] {
        tag.push(ident.len() as u8);
        tag.extend_from_slice(ident.as_bytes());
    }
    tag.extend_from_slice(&[1, 6, 1]);
    let mut h = Blake2b::<U32>::new();
    h.update([0xf0]);
    h.update(parent);
    h.update((key_bcs.len() as u64).to_le_bytes());
    h.update(&key_bcs);
    h.update(&tag);
    h.finalize().into()
}

/// A Soroban contract id deployed by `deployer` with `salt`: SHA-256 of the
/// XDR `HashIdPreimage::ContractId` from that address.
fn stellar_contract_id(network_passphrase: &str, deployer: &[u8; 32], salt: &[u8; 32]) -> [u8; 32] {
    let network_id = Sha256::digest(network_passphrase.as_bytes());
    let mut h = Sha256::new();
    h.update(8i32.to_be_bytes()); // ENVELOPE_TYPE_CONTRACT_ID
    h.update(network_id);
    h.update(0i32.to_be_bytes()); // CONTRACT_ID_PREIMAGE_FROM_ADDRESS
    h.update(1i32.to_be_bytes()); // SC_ADDRESS_TYPE_CONTRACT
    h.update(deployer);
    h.update(salt);
    h.finalize().into()
}

/// A Stellar StrKey: base32 of the version byte, the payload and its
/// CRC16-XModem (little-endian).
pub fn stellar_strkey(version: u8, payload: &[u8; 32]) -> String {
    let mut b = vec![version];
    b.extend_from_slice(payload);
    let mut crc: u16 = 0;
    for byte in &b {
        crc ^= (*byte as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    b.extend_from_slice(&crc.to_le_bytes());
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for byte in b {
        acc = (acc << 8) | byte as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// CosmWasm's instantiate2 address for code `checksum`, instantiated by
/// `creator` with `salt` and no message binding.
fn instantiate2(checksum: &[u8; 32], creator: &[u8], salt: &[u8; 32]) -> [u8; 32] {
    let mut key = b"wasm\0".to_vec();
    for part in [checksum.as_slice(), creator, salt.as_slice(), &[]] {
        key.extend_from_slice(&(part.len() as u64).to_be_bytes());
        key.extend_from_slice(part);
    }
    let typ = Sha256::digest(b"module");
    let mut h = Sha256::new();
    h.update(typ);
    h.update(key);
    h.finalize().into()
}

/// The representation hash of a TON `StateInit` with the account code and
/// the data cell `agent || tree_key` (512 bits, no refs).
fn ton_state_init_hash(
    code_hash: &[u8; 32],
    code_depth: u16,
    agent: &[u8; 32],
    tree_key: &[u8; 32],
) -> [u8; 32] {
    let mut d = Sha256::new();
    d.update([0u8, 128]);
    d.update(agent);
    d.update(tree_key);
    let data_hash: [u8; 32] = d.finalize().into();
    // StateInit: no split depth, not special, code and data present, no
    // library: bits 0 0 1 1 0, padded with a 1 and zeros.
    let mut h = Sha256::new();
    h.update([2u8, 1, 0b0011_0100]);
    h.update(code_depth.to_be_bytes());
    h.update(0u16.to_be_bytes());
    h.update(code_hash);
    h.update(data_hash);
    h.finalize().into()
}
