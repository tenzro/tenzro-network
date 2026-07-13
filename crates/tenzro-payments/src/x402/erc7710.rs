//! ERC-7710 delegation redemption verification.
//!
//! Implements EIP-712 typed-data hashing and signature recovery for the
//! MetaMask Delegation Framework `Delegation` struct, off-chain delegation
//! chain verification (root authority → nested authority linkage), caveat
//! enforcement for payment-relevant enforcer types, and `redeemDelegations`
//! calldata construction for on-chain settlement.
//!
//! Wire format: the redemption proof travels as base64-encoded JSON of
//! [`RedemptionProof`] — a root-first chain of [`SignedDelegation`] plus a
//! Tenzro-domain-separated binding hash tying the proof to the specific
//! challenge (credential form) or authorization nonce (payload form).
//!
//! Caveat enforcement is fail-closed: a caveat whose enforcer address is not
//! registered on the verifier rejects the redemption.

use std::collections::HashMap;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::{Digest as Sha3Digest, Keccak256};

use crate::error::{PaymentError, Result};
use crate::types::{PaymentChallenge, PaymentCredential};
use crate::x402::payment_payload::X402PaymentPayload;
use crate::x402::payment_required::X402PaymentRequirement;
use crate::x402::scheme::DelegationVerifier;

/// Domain tag for the Tenzro-side redemption binding preimage. Parallel to
/// `tenzro/x402/upto` and `tenzro/x402/batch-voucher`.
pub const ERC7710_PREIMAGE_DOMAIN: &str = "tenzro/x402/erc7710";

/// Root authority marker: a delegation with this authority is signed
/// directly by the delegator (the payer), not derived from a parent.
pub const ROOT_AUTHORITY: [u8; 32] = [0u8; 32];

/// ERC-20 `transfer(address,uint256)` selector — the method a payment
/// redemption executes against the asset contract.
pub const ERC20_TRANSFER_SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];

// EIP-712 type strings per the MetaMask Delegation Framework. The Caveat
// hash covers only (enforcer, terms) — args are runtime inputs and are
// excluded from the signed preimage.
const EIP712_DOMAIN_TYPE: &str =
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
const DELEGATION_TYPE: &str = "Delegation(address delegate,address delegator,bytes32 authority,Caveat[] caveats,uint256 salt)Caveat(address enforcer,bytes terms)";
const CAVEAT_TYPE: &str = "Caveat(address enforcer,bytes terms)";

/// A single caveat on a delegation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Caveat {
    /// Enforcer contract address (`0x` + 40 hex).
    pub enforcer: String,
    /// Enforcement terms (`0x` hex bytes), covered by the EIP-712 hash.
    pub terms: String,
    /// Runtime arguments (`0x` hex bytes), NOT covered by the EIP-712 hash.
    #[serde(default)]
    pub args: String,
}

/// ERC-7710 `Delegation` struct (unsigned part).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Delegation {
    /// Address permitted to redeem (`0x` + 40 hex).
    pub delegate: String,
    /// Address granting authority (`0x` + 40 hex).
    pub delegator: String,
    /// `0x` + 64 hex: [`ROOT_AUTHORITY`] for a root delegation, otherwise
    /// the EIP-712 struct hash of the parent delegation.
    pub authority: String,
    /// Caveats restricting the delegation.
    pub caveats: Vec<Caveat>,
    /// uint256 salt — decimal string or `0x` hex (≤ 32 bytes).
    pub salt: String,
}

/// A delegation plus its 65-byte secp256k1 signature (`r || s || v` hex).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SignedDelegation {
    pub delegation: Delegation,
    /// `0x` + 130 hex — signature over the EIP-712 digest of `delegation`.
    pub signature: String,
}

/// The redemption proof carried on the x402 wire (base64-encoded JSON).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RedemptionProof {
    /// Delegation chain, root-first: `chain[0].authority == ROOT_AUTHORITY`,
    /// `chain[i].authority == eip712_hash(chain[i-1])`.
    pub chain: Vec<SignedDelegation>,
    /// `0x` + 64 hex — [`compute_redemption_binding`] over the challenge id
    /// (credential form) or authorization nonce (payload form).
    pub binding: String,
}

/// Payment-relevant caveat enforcer semantics. The verifier maps on-chain
/// enforcer addresses to these kinds; unrecognized addresses reject.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaveatEnforcerKind {
    /// Terms: N × 20-byte addresses. The redemption target (asset contract)
    /// must be in the list.
    AllowedTargets,
    /// Terms: N × 4-byte selectors. The redemption method selector must be
    /// in the list.
    AllowedMethods,
    /// Terms: 32-byte big-endian uint256 ceiling. The redemption amount
    /// must be `<=` the ceiling.
    MaxAmount,
    /// Terms: 32 bytes = `after (u128 BE, 16) || before (u128 BE, 16)`.
    /// Zero means unbounded on that side; otherwise
    /// `after <= now < before`.
    TimestampWindow,
}

/// The facts a redemption is checked against when enforcing caveats.
#[derive(Debug, Clone)]
pub struct RedemptionContext {
    /// Call target of the redemption execution (the asset contract for
    /// ERC-20 payments). `None` when the requirement's asset is a symbol —
    /// an `AllowedTargets` caveat then rejects.
    pub target: Option<[u8; 20]>,
    /// Method selector of the redemption execution.
    pub selector: [u8; 4],
    /// Payment amount in the asset's smallest unit.
    pub amount: u128,
    /// Verification-time unix timestamp (seconds).
    pub timestamp: u64,
}

/// EIP-712 delegation-chain verifier for the `erc7710` x402 scheme.
#[derive(Debug)]
pub struct Erc7710DelegationVerifier {
    chain_id: u64,
    delegation_manager: [u8; 20],
    domain_name: String,
    domain_version: String,
    enforcers: HashMap<[u8; 20], CaveatEnforcerKind>,
}

impl Default for Erc7710DelegationVerifier {
    /// Tenzro testnet chain id with an unset (zero) delegation manager.
    /// Signatures produced against a real manager's domain will not verify
    /// until the operator constructs the verifier with the deployed
    /// manager address — the scheme stays discoverable but fail-closed.
    fn default() -> Self {
        Self {
            chain_id: 1337,
            delegation_manager: [0u8; 20],
            domain_name: "DelegationManager".to_string(),
            domain_version: "1".to_string(),
            enforcers: HashMap::new(),
        }
    }
}

impl Erc7710DelegationVerifier {
    /// Creates a verifier bound to a chain id and DelegationManager address.
    pub fn new(chain_id: u64, delegation_manager: &str) -> Result<Self> {
        Ok(Self {
            chain_id,
            delegation_manager: parse_address(delegation_manager)?,
            ..Self::default()
        })
    }

    /// Overrides the EIP-712 domain name/version (defaults:
    /// `DelegationManager` / `1`).
    pub fn with_domain(
        mut self,
        name: impl Into<String>,
        version: impl Into<String>,
    ) -> Self {
        self.domain_name = name.into();
        self.domain_version = version.into();
        self
    }

    /// Registers a caveat enforcer address with its payment semantics.
    pub fn with_enforcer(mut self, address: &str, kind: CaveatEnforcerKind) -> Result<Self> {
        self.enforcers.insert(parse_address(address)?, kind);
        Ok(self)
    }

    /// EIP-712 domain separator for this verifier's manager binding.
    pub fn domain_separator(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(32 * 5);
        buf.extend_from_slice(&keccak256(EIP712_DOMAIN_TYPE.as_bytes()));
        buf.extend_from_slice(&keccak256(self.domain_name.as_bytes()));
        buf.extend_from_slice(&keccak256(self.domain_version.as_bytes()));
        buf.extend_from_slice(&uint256_from_u128(self.chain_id as u128));
        buf.extend_from_slice(&address_word(&self.delegation_manager));
        keccak256(&buf)
    }

    /// EIP-712 signing digest (`\x19\x01 || domain || struct_hash`) for a
    /// delegation under this verifier's domain.
    pub fn delegation_digest(&self, delegation: &Delegation) -> Result<[u8; 32]> {
        let struct_hash = delegation_hash(delegation)?;
        let mut buf = Vec::with_capacity(2 + 64);
        buf.extend_from_slice(&[0x19, 0x01]);
        buf.extend_from_slice(&self.domain_separator());
        buf.extend_from_slice(&struct_hash);
        Ok(keccak256(&buf))
    }

    /// Verifies a root-first delegation chain: root authority, authority
    /// linkage, per-delegation EIP-712 signature recovery against the
    /// delegator, and caveat enforcement on every link. Returns the EIP-712
    /// struct hash of the leaf delegation.
    pub fn verify_chain(
        &self,
        chain: &[SignedDelegation],
        context: &RedemptionContext,
    ) -> Result<[u8; 32]> {
        if chain.is_empty() {
            return Err(PaymentError::VerificationFailed(
                "erc7710 redemption proof carries an empty delegation chain".to_string(),
            ));
        }

        let mut parent_hash: Option<[u8; 32]> = None;
        let mut parent_delegate: Option<[u8; 20]> = None;
        let mut leaf_hash = [0u8; 32];

        for (i, signed) in chain.iter().enumerate() {
            let d = &signed.delegation;
            let authority = parse_bytes32(&d.authority)?;

            match (&parent_hash, &parent_delegate) {
                (None, None) => {
                    if authority != ROOT_AUTHORITY {
                        return Err(PaymentError::VerificationFailed(
                            "erc7710 root delegation authority is not ROOT_AUTHORITY"
                                .to_string(),
                        ));
                    }
                }
                (Some(ph), Some(pd)) => {
                    if authority != *ph {
                        return Err(PaymentError::VerificationFailed(format!(
                            "erc7710 delegation {} authority does not match parent hash",
                            i
                        )));
                    }
                    if parse_address(&d.delegator)? != *pd {
                        return Err(PaymentError::VerificationFailed(format!(
                            "erc7710 delegation {} delegator is not the parent delegate",
                            i
                        )));
                    }
                }
                _ => unreachable!("parent hash and delegate are set together"),
            }

            let digest = self.delegation_digest(d)?;
            let signer = recover_signer(&digest, &parse_hex_bytes(&signed.signature)?)?;
            if signer != parse_address(&d.delegator)? {
                return Err(PaymentError::VerificationFailed(format!(
                    "erc7710 delegation {} signature does not recover to the delegator",
                    i
                )));
            }

            for caveat in &d.caveats {
                self.enforce_caveat(caveat, context)?;
            }

            leaf_hash = delegation_hash(d)?;
            parent_hash = Some(leaf_hash);
            parent_delegate = Some(parse_address(&d.delegate)?);
        }

        Ok(leaf_hash)
    }

    /// Fail-closed caveat enforcement: unknown enforcer addresses reject.
    fn enforce_caveat(&self, caveat: &Caveat, context: &RedemptionContext) -> Result<()> {
        let enforcer = parse_address(&caveat.enforcer)?;
        let kind = self.enforcers.get(&enforcer).ok_or_else(|| {
            PaymentError::VerificationFailed(format!(
                "erc7710 caveat enforcer {} is not recognized by this verifier",
                caveat.enforcer
            ))
        })?;
        let terms = parse_hex_bytes(&caveat.terms)?;

        match kind {
            CaveatEnforcerKind::AllowedTargets => {
                if terms.is_empty() || terms.len() % 20 != 0 {
                    return Err(PaymentError::VerificationFailed(
                        "erc7710 allowed-targets caveat terms are not N x 20 bytes"
                            .to_string(),
                    ));
                }
                let target = context.target.ok_or_else(|| {
                    PaymentError::VerificationFailed(
                        "erc7710 allowed-targets caveat present but redemption target is unknown"
                            .to_string(),
                    )
                })?;
                if !terms.chunks(20).any(|c| c == target) {
                    return Err(PaymentError::VerificationFailed(
                        "erc7710 redemption target is not in the allowed-targets caveat"
                            .to_string(),
                    ));
                }
            }
            CaveatEnforcerKind::AllowedMethods => {
                if terms.is_empty() || terms.len() % 4 != 0 {
                    return Err(PaymentError::VerificationFailed(
                        "erc7710 allowed-methods caveat terms are not N x 4 bytes".to_string(),
                    ));
                }
                if !terms.chunks(4).any(|c| c == context.selector) {
                    return Err(PaymentError::VerificationFailed(
                        "erc7710 redemption selector is not in the allowed-methods caveat"
                            .to_string(),
                    ));
                }
            }
            CaveatEnforcerKind::MaxAmount => {
                if terms.len() != 32 {
                    return Err(PaymentError::VerificationFailed(
                        "erc7710 max-amount caveat terms are not 32 bytes".to_string(),
                    ));
                }
                // Ceilings above u128::MAX cannot constrain a u128 amount.
                if terms[..16].iter().all(|b| *b == 0) {
                    let mut ceiling = [0u8; 16];
                    ceiling.copy_from_slice(&terms[16..]);
                    if context.amount > u128::from_be_bytes(ceiling) {
                        return Err(PaymentError::VerificationFailed(
                            "erc7710 redemption amount exceeds the max-amount caveat"
                                .to_string(),
                        ));
                    }
                }
            }
            CaveatEnforcerKind::TimestampWindow => {
                if terms.len() != 32 {
                    return Err(PaymentError::VerificationFailed(
                        "erc7710 timestamp caveat terms are not 32 bytes".to_string(),
                    ));
                }
                let mut after = [0u8; 16];
                after.copy_from_slice(&terms[..16]);
                let mut before = [0u8; 16];
                before.copy_from_slice(&terms[16..]);
                let after = u128::from_be_bytes(after);
                let before = u128::from_be_bytes(before);
                let now = context.timestamp as u128;
                if after != 0 && now < after {
                    return Err(PaymentError::VerificationFailed(
                        "erc7710 redemption is before the timestamp caveat window".to_string(),
                    ));
                }
                if before != 0 && now >= before {
                    return Err(PaymentError::VerificationFailed(
                        "erc7710 redemption is after the timestamp caveat window".to_string(),
                    ));
                }
            }
        }
        Ok(())
    }
}

#[async_trait]
impl DelegationVerifier for Erc7710DelegationVerifier {
    async fn verify_redemption(
        &self,
        challenge: &PaymentChallenge,
        credential: &PaymentCredential,
    ) -> Result<()> {
        let proof_b64 = credential
            .extra
            .get("redemption_proof")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                PaymentError::CredentialError(
                    "erc7710 credential missing extra.redemption_proof".to_string(),
                )
            })?;
        let proof = decode_redemption_proof(proof_b64)?;

        let declared_leaf = credential
            .extra
            .get("delegation_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                PaymentError::CredentialError(
                    "erc7710 credential missing extra.delegation_id".to_string(),
                )
            })
            .and_then(parse_bytes32)?;

        let context = RedemptionContext {
            target: evm_address_opt(&challenge.asset).or_else(|| {
                challenge
                    .extra
                    .get("settlement_target")
                    .and_then(|v| v.as_str())
                    .and_then(evm_address_opt)
            }),
            selector: ERC20_TRANSFER_SELECTOR,
            amount: credential.amount,
            timestamp: chrono::Utc::now().timestamp() as u64,
        };

        let leaf_hash = self.verify_chain(&proof.chain, &context)?;
        if leaf_hash != declared_leaf {
            return Err(PaymentError::VerificationFailed(
                "erc7710 delegation_id does not match the leaf delegation hash".to_string(),
            ));
        }

        let root = &proof.chain[0].delegation;
        if parse_address(&root.delegator)? != parse_address(&credential.payer_address)? {
            return Err(PaymentError::VerificationFailed(
                "erc7710 root delegator does not match the credential payer".to_string(),
            ));
        }

        let expected =
            compute_redemption_binding(&challenge.challenge_id, &leaf_hash, credential.amount);
        if parse_bytes32(&proof.binding)? != expected {
            return Err(PaymentError::VerificationFailed(
                "erc7710 redemption binding does not commit to this challenge".to_string(),
            ));
        }
        Ok(())
    }

    async fn verify_payload_redemption(
        &self,
        requirement: &X402PaymentRequirement,
        payload: &X402PaymentPayload,
    ) -> Result<()> {
        let auth = &payload.payload.authorization;
        let proof = decode_redemption_proof(&payload.payload.signature)?;

        let now = chrono::Utc::now().timestamp() as u64;
        if now < auth.valid_after || now >= auth.valid_before {
            return Err(PaymentError::VerificationFailed(
                "erc7710 authorization validity window has not started or has expired"
                    .to_string(),
            ));
        }

        let amount: u128 = auth.value.parse().map_err(|_| {
            PaymentError::VerificationFailed(format!(
                "erc7710 authorization.value is not a valid u128: '{}'",
                auth.value
            ))
        })?;

        let context = RedemptionContext {
            target: evm_address_opt(&requirement.asset),
            selector: ERC20_TRANSFER_SELECTOR,
            amount,
            timestamp: now,
        };

        let leaf_hash = self.verify_chain(&proof.chain, &context)?;

        let root = &proof.chain[0].delegation;
        if parse_address(&root.delegator)? != parse_address(&auth.from)? {
            return Err(PaymentError::VerificationFailed(
                "erc7710 root delegator does not match authorization.from".to_string(),
            ));
        }

        let expected = compute_redemption_binding(&auth.nonce, &leaf_hash, amount);
        if parse_bytes32(&proof.binding)? != expected {
            return Err(PaymentError::VerificationFailed(
                "erc7710 redemption binding does not commit to this authorization".to_string(),
            ));
        }
        Ok(())
    }
}

/// Tenzro-side binding preimage hash: commits a delegation chain's leaf to
/// one specific challenge (or authorization nonce) and amount, so a proof
/// blob cannot be resubmitted against a different challenge unnoticed.
pub fn compute_redemption_binding(
    context_id: &str,
    leaf_hash: &[u8; 32],
    amount: u128,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ERC7710_PREIMAGE_DOMAIN.as_bytes());
    hasher.update(context_id.as_bytes());
    hasher.update(leaf_hash);
    hasher.update(amount.to_le_bytes());
    hasher.finalize().into()
}

/// Decodes the base64 JSON [`RedemptionProof`] wire blob.
pub fn decode_redemption_proof(encoded: &str) -> Result<RedemptionProof> {
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)
        .map_err(|e| {
            PaymentError::VerificationFailed(format!(
                "erc7710 redemption proof is not valid base64: {}",
                e
            ))
        })?;
    serde_json::from_slice(&bytes).map_err(|e| {
        PaymentError::VerificationFailed(format!(
            "erc7710 redemption proof is not valid JSON: {}",
            e
        ))
    })
}

/// EIP-712 struct hash of a caveat: covers (enforcer, keccak(terms)) only.
pub fn caveat_hash(caveat: &Caveat) -> Result<[u8; 32]> {
    let mut buf = Vec::with_capacity(32 * 3);
    buf.extend_from_slice(&keccak256(CAVEAT_TYPE.as_bytes()));
    buf.extend_from_slice(&address_word(&parse_address(&caveat.enforcer)?));
    buf.extend_from_slice(&keccak256(&parse_hex_bytes(&caveat.terms)?));
    Ok(keccak256(&buf))
}

/// EIP-712 struct hash of a delegation.
pub fn delegation_hash(delegation: &Delegation) -> Result<[u8; 32]> {
    let mut caveats_buf = Vec::with_capacity(32 * delegation.caveats.len());
    for caveat in &delegation.caveats {
        caveats_buf.extend_from_slice(&caveat_hash(caveat)?);
    }

    let mut buf = Vec::with_capacity(32 * 6);
    buf.extend_from_slice(&keccak256(DELEGATION_TYPE.as_bytes()));
    buf.extend_from_slice(&address_word(&parse_address(&delegation.delegate)?));
    buf.extend_from_slice(&address_word(&parse_address(&delegation.delegator)?));
    buf.extend_from_slice(&parse_bytes32(&delegation.authority)?);
    buf.extend_from_slice(&keccak256(&caveats_buf));
    buf.extend_from_slice(&parse_uint256(&delegation.salt)?);
    Ok(keccak256(&buf))
}

/// Recovers the EVM signer address from a 65-byte `r || s || v` secp256k1
/// signature over `digest` (`v` in `{0,1}` or legacy `{27,28}`).
pub fn recover_signer(digest: &[u8; 32], signature: &[u8]) -> Result<[u8; 20]> {
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

    if signature.len() != 65 {
        return Err(PaymentError::VerificationFailed(format!(
            "erc7710 signature must be 65 bytes, got {}",
            signature.len()
        )));
    }
    let sig = Signature::from_slice(&signature[..64]).map_err(|e| {
        PaymentError::VerificationFailed(format!("erc7710 signature is malformed: {}", e))
    })?;
    let v = signature[64];
    let recid_byte = if v >= 27 { v - 27 } else { v };
    let recid = RecoveryId::from_byte(recid_byte).ok_or_else(|| {
        PaymentError::VerificationFailed(format!("erc7710 recovery id {} is invalid", v))
    })?;
    let vk = VerifyingKey::recover_from_prehash(digest, &sig, recid).map_err(|e| {
        PaymentError::VerificationFailed(format!("erc7710 signature recovery failed: {}", e))
    })?;
    Ok(evm_address_from_verifying_key(&vk))
}

/// Derives the 20-byte EVM address from a secp256k1 verifying key.
pub fn evm_address_from_verifying_key(vk: &k256::ecdsa::VerifyingKey) -> [u8; 20] {
    let point = vk.to_sec1_point(false);
    let bytes = point.as_bytes();
    let hashed: [u8; 32] = Keccak256::digest(&bytes[1..]).into();
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hashed[12..]);
    addr
}

// ─── redeemDelegations calldata ────────────────────────────────────────────

/// Builds `DelegationManager.redeemDelegations(bytes[],bytes32[],bytes[])`
/// calldata for a single redemption: one permission context (the delegation
/// chain, leaf-first per the framework's on-chain ordering — this function
/// takes the root-first wire order and reverses it), the single-execution
/// mode code (`bytes32(0)`), and one ERC-7579 single-execution calldata blob
/// (`target(20) || value(32) || calldata`).
pub fn build_redeem_delegations_calldata(
    chain: &[SignedDelegation],
    target: &str,
    value: u128,
    execution_calldata: &[u8],
) -> Result<Vec<u8>> {
    if chain.is_empty() {
        return Err(PaymentError::SettlementError(
            "erc7710 cannot build redeemDelegations calldata for an empty chain".to_string(),
        ));
    }

    let leaf_first: Vec<&SignedDelegation> = chain.iter().rev().collect();
    let permission_context = abi_encode_delegation_array(&leaf_first)?;

    let mut execution = Vec::with_capacity(20 + 32 + execution_calldata.len());
    execution.extend_from_slice(&parse_address(target)?);
    execution.extend_from_slice(&uint256_from_u128(value));
    execution.extend_from_slice(execution_calldata);

    let contexts = abi_encode_bytes_array(&[permission_context]);
    let modes = abi_encode_bytes32_array(&[[0u8; 32]]);
    let executions = abi_encode_bytes_array(&[execution]);

    let selector: [u8; 32] =
        Keccak256::digest(b"redeemDelegations(bytes[],bytes32[],bytes[])").into();

    let mut calldata = Vec::new();
    calldata.extend_from_slice(&selector[..4]);
    // Head: three offsets into the args block for the dynamic params.
    let head_len = 32 * 3;
    calldata.extend_from_slice(&uint256_from_u128(head_len as u128));
    calldata.extend_from_slice(&uint256_from_u128((head_len + contexts.len()) as u128));
    calldata.extend_from_slice(&uint256_from_u128(
        (head_len + contexts.len() + modes.len()) as u128,
    ));
    calldata.extend_from_slice(&contexts);
    calldata.extend_from_slice(&modes);
    calldata.extend_from_slice(&executions);
    Ok(calldata)
}

/// ABI-encodes ERC-20 `transfer(to, amount)` calldata for the redemption
/// execution.
pub fn encode_erc20_transfer(to: &str, amount: u128) -> Result<Vec<u8>> {
    let mut calldata = Vec::with_capacity(4 + 64);
    calldata.extend_from_slice(&ERC20_TRANSFER_SELECTOR);
    calldata.extend_from_slice(&address_word(&parse_address(to)?));
    calldata.extend_from_slice(&uint256_from_u128(amount));
    Ok(calldata)
}

// Tuple layout: (address enforcer, bytes terms, bytes args) — 3 head words,
// terms/args in the tail.
fn abi_encode_caveat(caveat: &Caveat) -> Result<Vec<u8>> {
    let terms = abi_encode_bytes(&parse_hex_bytes(&caveat.terms)?);
    let args = abi_encode_bytes(&parse_hex_bytes(&caveat.args)?);

    let head_len = 32 * 3;
    let mut out = Vec::new();
    out.extend_from_slice(&address_word(&parse_address(&caveat.enforcer)?));
    out.extend_from_slice(&uint256_from_u128(head_len as u128));
    out.extend_from_slice(&uint256_from_u128((head_len + terms.len()) as u128));
    out.extend_from_slice(&terms);
    out.extend_from_slice(&args);
    Ok(out)
}

// Tuple layout matches the on-chain struct, which includes the signature:
// (address delegate, address delegator, bytes32 authority, Caveat[] caveats,
//  uint256 salt, bytes signature) — 6 head words.
fn abi_encode_signed_delegation(signed: &SignedDelegation) -> Result<Vec<u8>> {
    let d = &signed.delegation;
    let caveats = abi_encode_caveat_array(&d.caveats)?;
    let signature = abi_encode_bytes(&parse_hex_bytes(&signed.signature)?);

    let head_len = 32 * 6;
    let mut out = Vec::new();
    out.extend_from_slice(&address_word(&parse_address(&d.delegate)?));
    out.extend_from_slice(&address_word(&parse_address(&d.delegator)?));
    out.extend_from_slice(&parse_bytes32(&d.authority)?);
    out.extend_from_slice(&uint256_from_u128(head_len as u128));
    out.extend_from_slice(&parse_uint256(&d.salt)?);
    out.extend_from_slice(&uint256_from_u128((head_len + caveats.len()) as u128));
    out.extend_from_slice(&caveats);
    out.extend_from_slice(&signature);
    Ok(out)
}

fn abi_encode_caveat_array(caveats: &[Caveat]) -> Result<Vec<u8>> {
    let encoded: Vec<Vec<u8>> = caveats
        .iter()
        .map(abi_encode_caveat)
        .collect::<Result<_>>()?;
    Ok(abi_encode_dynamic_array(&encoded))
}

fn abi_encode_delegation_array(chain: &[&SignedDelegation]) -> Result<Vec<u8>> {
    let encoded: Vec<Vec<u8>> = chain
        .iter()
        .map(|s| abi_encode_signed_delegation(s))
        .collect::<Result<_>>()?;
    Ok(abi_encode_dynamic_array(&encoded))
}

fn abi_encode_bytes_array(items: &[Vec<u8>]) -> Vec<u8> {
    let encoded: Vec<Vec<u8>> = items.iter().map(|b| abi_encode_bytes(b)).collect();
    abi_encode_dynamic_array(&encoded)
}

fn abi_encode_bytes32_array(items: &[[u8; 32]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 * (1 + items.len()));
    out.extend_from_slice(&uint256_from_u128(items.len() as u128));
    for item in items {
        out.extend_from_slice(item);
    }
    out
}

// Dynamic array of already-encoded dynamic elements: length word, then
// per-element offsets relative to the start of the data area (after the
// length word), then the elements.
fn abi_encode_dynamic_array(encoded_elements: &[Vec<u8>]) -> Vec<u8> {
    let n = encoded_elements.len();
    let mut out = Vec::new();
    out.extend_from_slice(&uint256_from_u128(n as u128));
    let mut offset = 32 * n;
    for element in encoded_elements {
        out.extend_from_slice(&uint256_from_u128(offset as u128));
        offset += element.len();
    }
    for element in encoded_elements {
        out.extend_from_slice(element);
    }
    out
}

fn abi_encode_bytes(data: &[u8]) -> Vec<u8> {
    let padded_len = data.len().div_ceil(32) * 32;
    let mut out = Vec::with_capacity(32 + padded_len);
    out.extend_from_slice(&uint256_from_u128(data.len() as u128));
    out.extend_from_slice(data);
    out.resize(32 + padded_len, 0);
    out
}

// ─── parsing / word helpers ────────────────────────────────────────────────

fn keccak256(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(data).into()
}

fn address_word(addr: &[u8; 20]) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(addr);
    word
}

fn uint256_from_u128(value: u128) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[16..].copy_from_slice(&value.to_be_bytes());
    word
}

fn parse_address(s: &str) -> Result<[u8; 20]> {
    let hex_part = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(hex_part).map_err(|e| {
        PaymentError::VerificationFailed(format!("erc7710 invalid address '{}': {}", s, e))
    })?;
    if bytes.len() != 20 {
        return Err(PaymentError::VerificationFailed(format!(
            "erc7710 address '{}' is not 20 bytes",
            s
        )));
    }
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&bytes);
    Ok(addr)
}

fn parse_bytes32(s: &str) -> Result<[u8; 32]> {
    let hex_part = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(hex_part).map_err(|e| {
        PaymentError::VerificationFailed(format!("erc7710 invalid bytes32 '{}': {}", s, e))
    })?;
    if bytes.len() != 32 {
        return Err(PaymentError::VerificationFailed(format!(
            "erc7710 value '{}' is not 32 bytes",
            s
        )));
    }
    let mut word = [0u8; 32];
    word.copy_from_slice(&bytes);
    Ok(word)
}

fn parse_hex_bytes(s: &str) -> Result<Vec<u8>> {
    let hex_part = s.strip_prefix("0x").unwrap_or(s);
    if hex_part.is_empty() {
        return Ok(Vec::new());
    }
    hex::decode(hex_part).map_err(|e| {
        PaymentError::VerificationFailed(format!("erc7710 invalid hex bytes '{}': {}", s, e))
    })
}

// Salt accepts decimal (u128 range) or 0x-hex (up to 32 bytes, left-padded).
fn parse_uint256(s: &str) -> Result<[u8; 32]> {
    if let Some(hex_part) = s.strip_prefix("0x") {
        let bytes = hex::decode(hex_part).map_err(|e| {
            PaymentError::VerificationFailed(format!("erc7710 invalid uint256 '{}': {}", s, e))
        })?;
        if bytes.len() > 32 {
            return Err(PaymentError::VerificationFailed(format!(
                "erc7710 uint256 '{}' exceeds 32 bytes",
                s
            )));
        }
        let mut word = [0u8; 32];
        word[32 - bytes.len()..].copy_from_slice(&bytes);
        return Ok(word);
    }
    let value: u128 = s.parse().map_err(|_| {
        PaymentError::VerificationFailed(format!("erc7710 invalid uint256 '{}'", s))
    })?;
    Ok(uint256_from_u128(value))
}

fn evm_address_opt(s: &str) -> Option<[u8; 20]> {
    parse_address(s).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use k256::ecdsa::SigningKey;

    fn test_key(seed: u8) -> SigningKey {
        let mut bytes = [0u8; 32];
        bytes[31] = seed;
        SigningKey::from_slice(&bytes).unwrap()
    }

    fn key_address(key: &SigningKey) -> String {
        format!(
            "0x{}",
            hex::encode(evm_address_from_verifying_key(key.verifying_key()))
        )
    }

    fn verifier() -> Erc7710DelegationVerifier {
        Erc7710DelegationVerifier::new(1337, "0x00000000000000000000000000000000000010ab")
            .unwrap()
            .with_enforcer(ENFORCER_TARGETS, CaveatEnforcerKind::AllowedTargets)
            .unwrap()
            .with_enforcer(ENFORCER_METHODS, CaveatEnforcerKind::AllowedMethods)
            .unwrap()
            .with_enforcer(ENFORCER_AMOUNT, CaveatEnforcerKind::MaxAmount)
            .unwrap()
            .with_enforcer(ENFORCER_TIME, CaveatEnforcerKind::TimestampWindow)
            .unwrap()
    }

    const ENFORCER_TARGETS: &str = "0x0000000000000000000000000000000000000e01";
    const ENFORCER_METHODS: &str = "0x0000000000000000000000000000000000000e02";
    const ENFORCER_AMOUNT: &str = "0x0000000000000000000000000000000000000e03";
    const ENFORCER_TIME: &str = "0x0000000000000000000000000000000000000e04";
    const TOKEN: &str = "0x00000000000000000000000000000000000000cc";

    fn sign_delegation(
        v: &Erc7710DelegationVerifier,
        key: &SigningKey,
        delegation: Delegation,
    ) -> SignedDelegation {
        let digest = v.delegation_digest(&delegation).unwrap();
        let (sig, recid) = key.sign_prehash_recoverable(&digest).unwrap();
        let mut bytes = sig.to_bytes().to_vec();
        bytes.push(recid.to_byte());
        SignedDelegation {
            delegation,
            signature: format!("0x{}", hex::encode(bytes)),
        }
    }

    fn root_delegation(delegator: &SigningKey, delegate: &str, caveats: Vec<Caveat>) -> Delegation {
        Delegation {
            delegate: delegate.to_string(),
            delegator: key_address(delegator),
            authority: format!("0x{}", hex::encode(ROOT_AUTHORITY)),
            caveats,
            salt: "7".to_string(),
        }
    }

    fn context(amount: u128) -> RedemptionContext {
        RedemptionContext {
            target: Some(parse_address(TOKEN).unwrap()),
            selector: ERC20_TRANSFER_SELECTOR,
            amount,
            timestamp: 1_700_000_000,
        }
    }

    #[test]
    fn caveat_hash_excludes_args() {
        let a = Caveat {
            enforcer: ENFORCER_AMOUNT.to_string(),
            terms: "0x00".to_string(),
            args: "0x".to_string(),
        };
        let b = Caveat {
            args: "0xdeadbeef".to_string(),
            ..a.clone()
        };
        assert_eq!(caveat_hash(&a).unwrap(), caveat_hash(&b).unwrap());
    }

    #[test]
    fn delegation_digest_binds_domain() {
        let key = test_key(1);
        let d = root_delegation(&key, TOKEN, vec![]);
        let v1 = verifier();
        let v2 = Erc7710DelegationVerifier::new(
            9999,
            "0x00000000000000000000000000000000000010ab",
        )
        .unwrap();
        assert_ne!(
            v1.delegation_digest(&d).unwrap(),
            v2.delegation_digest(&d).unwrap()
        );
    }

    #[test]
    fn root_chain_verifies_and_returns_leaf_hash() {
        let payer = test_key(1);
        let v = verifier();
        let d = root_delegation(&payer, "0x0000000000000000000000000000000000000d01", vec![]);
        let expected = delegation_hash(&d).unwrap();
        let signed = sign_delegation(&v, &payer, d);
        let leaf = v.verify_chain(&[signed], &context(100)).unwrap();
        assert_eq!(leaf, expected);
    }

    #[test]
    fn wrong_signer_is_rejected() {
        let payer = test_key(1);
        let intruder = test_key(2);
        let v = verifier();
        let d = root_delegation(&payer, "0x0000000000000000000000000000000000000d01", vec![]);
        let signed = sign_delegation(&v, &intruder, d);
        let err = v.verify_chain(&[signed], &context(100)).unwrap_err();
        assert!(matches!(err, PaymentError::VerificationFailed(_)));
    }

    #[test]
    fn non_root_authority_on_first_link_is_rejected() {
        let payer = test_key(1);
        let v = verifier();
        let mut d = root_delegation(&payer, "0x0000000000000000000000000000000000000d01", vec![]);
        d.authority = format!("0x{}", hex::encode([1u8; 32]));
        let signed = sign_delegation(&v, &payer, d);
        let err = v.verify_chain(&[signed], &context(100)).unwrap_err();
        assert!(err.to_string().contains("ROOT_AUTHORITY"));
    }

    #[test]
    fn nested_chain_links_authority_and_delegate() {
        let payer = test_key(1);
        let intermediate = test_key(2);
        let v = verifier();

        let root = root_delegation(&payer, &key_address(&intermediate), vec![]);
        let root_hash = delegation_hash(&root).unwrap();
        let child = Delegation {
            delegate: "0x0000000000000000000000000000000000000d02".to_string(),
            delegator: key_address(&intermediate),
            authority: format!("0x{}", hex::encode(root_hash)),
            caveats: vec![],
            salt: "8".to_string(),
        };
        let child_hash = delegation_hash(&child).unwrap();

        let chain = vec![
            sign_delegation(&v, &payer, root),
            sign_delegation(&v, &intermediate, child),
        ];
        assert_eq!(v.verify_chain(&chain, &context(100)).unwrap(), child_hash);
    }

    #[test]
    fn nested_chain_rejects_delegator_not_parent_delegate() {
        let payer = test_key(1);
        let intermediate = test_key(2);
        let stranger = test_key(3);
        let v = verifier();

        let root = root_delegation(&payer, &key_address(&intermediate), vec![]);
        let root_hash = delegation_hash(&root).unwrap();
        // Signed correctly by its own delegator, but that delegator was
        // never delegated to by the parent.
        let child = Delegation {
            delegate: "0x0000000000000000000000000000000000000d02".to_string(),
            delegator: key_address(&stranger),
            authority: format!("0x{}", hex::encode(root_hash)),
            caveats: vec![],
            salt: "8".to_string(),
        };
        let chain = vec![
            sign_delegation(&v, &payer, root),
            sign_delegation(&v, &stranger, child),
        ];
        let err = v.verify_chain(&chain, &context(100)).unwrap_err();
        assert!(err.to_string().contains("parent delegate"));
    }

    #[test]
    fn unknown_enforcer_fails_closed() {
        let payer = test_key(1);
        let v = verifier();
        let caveat = Caveat {
            enforcer: "0x0000000000000000000000000000000000000eff".to_string(),
            terms: "0x00".to_string(),
            args: String::new(),
        };
        let d = root_delegation(&payer, TOKEN, vec![caveat]);
        let signed = sign_delegation(&v, &payer, d);
        let err = v.verify_chain(&[signed], &context(100)).unwrap_err();
        assert!(err.to_string().contains("not recognized"));
    }

    #[test]
    fn max_amount_caveat_enforced() {
        let payer = test_key(1);
        let v = verifier();
        let caveat = Caveat {
            enforcer: ENFORCER_AMOUNT.to_string(),
            terms: format!("0x{}", hex::encode(uint256_from_u128(500))),
            args: String::new(),
        };
        let d = root_delegation(&payer, TOKEN, vec![caveat]);
        let signed = sign_delegation(&v, &payer, d);

        v.verify_chain(std::slice::from_ref(&signed), &context(500))
            .unwrap();
        let err = v
            .verify_chain(std::slice::from_ref(&signed), &context(501))
            .unwrap_err();
        assert!(err.to_string().contains("max-amount"));
    }

    #[test]
    fn allowed_targets_caveat_enforced() {
        let payer = test_key(1);
        let v = verifier();
        let caveat = Caveat {
            enforcer: ENFORCER_TARGETS.to_string(),
            terms: format!("0x{}", hex::encode(parse_address(TOKEN).unwrap())),
            args: String::new(),
        };
        let d = root_delegation(&payer, TOKEN, vec![caveat]);
        let signed = sign_delegation(&v, &payer, d);

        v.verify_chain(std::slice::from_ref(&signed), &context(1))
            .unwrap();

        let mut wrong_target = context(1);
        wrong_target.target =
            Some(parse_address("0x00000000000000000000000000000000000000dd").unwrap());
        let err = v
            .verify_chain(std::slice::from_ref(&signed), &wrong_target)
            .unwrap_err();
        assert!(err.to_string().contains("allowed-targets"));

        let mut no_target = context(1);
        no_target.target = None;
        let err = v
            .verify_chain(std::slice::from_ref(&signed), &no_target)
            .unwrap_err();
        assert!(err.to_string().contains("target is unknown"));
    }

    #[test]
    fn allowed_methods_caveat_enforced() {
        let payer = test_key(1);
        let v = verifier();
        let caveat = Caveat {
            enforcer: ENFORCER_METHODS.to_string(),
            terms: format!("0x{}", hex::encode(ERC20_TRANSFER_SELECTOR)),
            args: String::new(),
        };
        let d = root_delegation(&payer, TOKEN, vec![caveat]);
        let signed = sign_delegation(&v, &payer, d);

        v.verify_chain(std::slice::from_ref(&signed), &context(1))
            .unwrap();

        let mut wrong_selector = context(1);
        wrong_selector.selector = [0x11, 0x22, 0x33, 0x44];
        let err = v
            .verify_chain(std::slice::from_ref(&signed), &wrong_selector)
            .unwrap_err();
        assert!(err.to_string().contains("allowed-methods"));
    }

    #[test]
    fn timestamp_window_caveat_enforced() {
        let payer = test_key(1);
        let v = verifier();
        let mut terms = Vec::with_capacity(32);
        terms.extend_from_slice(&1_600_000_000u128.to_be_bytes());
        terms.extend_from_slice(&1_800_000_000u128.to_be_bytes());
        let caveat = Caveat {
            enforcer: ENFORCER_TIME.to_string(),
            terms: format!("0x{}", hex::encode(terms)),
            args: String::new(),
        };
        let d = root_delegation(&payer, TOKEN, vec![caveat]);
        let signed = sign_delegation(&v, &payer, d);

        v.verify_chain(std::slice::from_ref(&signed), &context(1))
            .unwrap();

        let mut early = context(1);
        early.timestamp = 1_500_000_000;
        assert!(v
            .verify_chain(std::slice::from_ref(&signed), &early)
            .is_err());

        let mut late = context(1);
        late.timestamp = 1_900_000_000;
        assert!(v
            .verify_chain(std::slice::from_ref(&signed), &late)
            .is_err());
    }

    #[tokio::test]
    async fn credential_form_verifies_bound_proof() {
        let payer = test_key(1);
        let v = verifier();
        let d = root_delegation(&payer, "0x0000000000000000000000000000000000000d01", vec![]);
        let leaf_hash = delegation_hash(&d).unwrap();
        let signed = sign_delegation(&v, &payer, d);

        let amount = 1_000u128;
        let challenge_id = "ch-erc7710";
        let binding = compute_redemption_binding(challenge_id, &leaf_hash, amount);
        let proof = RedemptionProof {
            chain: vec![signed],
            binding: format!("0x{}", hex::encode(binding)),
        };
        let proof_b64 = base64::engine::general_purpose::STANDARD
            .encode(serde_json::to_vec(&proof).unwrap());

        let challenge = PaymentChallenge {
            challenge_id: challenge_id.to_string(),
            protocol: "x402".to_string(),
            resource: "/paid".to_string(),
            amount,
            asset: TOKEN.to_string(),
            recipient: "0xrecipient".to_string(),
            chain: "tenzro-mainnet".to_string(),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
            extra: HashMap::new(),
        };
        let mut extra = HashMap::new();
        extra.insert(
            "delegation_id".to_string(),
            serde_json::json!(format!("0x{}", hex::encode(leaf_hash))),
        );
        extra.insert("redemption_proof".to_string(), serde_json::json!(proof_b64));
        let credential = PaymentCredential {
            credential_id: "cred-1".to_string(),
            challenge_id: challenge_id.to_string(),
            protocol: "x402".to_string(),
            payer_did: "did:tenzro:machine:agent".to_string(),
            payer_address: key_address(&payer),
            amount,
            asset: TOKEN.to_string(),
            signature: vec![],
            pq_signature: vec![],
            pq_public_key: vec![],
            extra,
        };

        v.verify_redemption(&challenge, &credential).await.unwrap();

        // Same proof against a different challenge id: binding check fails.
        let mut other = challenge.clone();
        other.challenge_id = "ch-other".to_string();
        let err = v.verify_redemption(&other, &credential).await.unwrap_err();
        assert!(err.to_string().contains("binding"));
    }

    #[test]
    fn redeem_delegations_calldata_layout() {
        let payer = test_key(1);
        let v = verifier();
        let d = root_delegation(&payer, "0x0000000000000000000000000000000000000d01", vec![]);
        let signed = sign_delegation(&v, &payer, d);

        let transfer = encode_erc20_transfer("0x00000000000000000000000000000000000000aa", 42)
            .unwrap();
        assert_eq!(&transfer[..4], &ERC20_TRANSFER_SELECTOR);
        assert_eq!(transfer.len(), 4 + 64);

        let calldata =
            build_redeem_delegations_calldata(&[signed], TOKEN, 0, &transfer).unwrap();

        let expected_selector: [u8; 32] =
            Keccak256::digest(b"redeemDelegations(bytes[],bytes32[],bytes[])").into();
        assert_eq!(&calldata[..4], &expected_selector[..4]);
        // First head word points past the 3-word head.
        assert_eq!(&calldata[4..36], &uint256_from_u128(96));
        // Everything after the selector is word-aligned.
        assert_eq!((calldata.len() - 4) % 32, 0);
    }

    #[test]
    fn abi_encode_bytes_pads_to_words() {
        let enc = abi_encode_bytes(&[0xaa; 5]);
        assert_eq!(enc.len(), 64);
        assert_eq!(&enc[..32], &uint256_from_u128(5));
        assert_eq!(&enc[32..37], &[0xaa; 5]);
        assert!(enc[37..].iter().all(|b| *b == 0));
    }

    #[test]
    fn default_verifier_fails_closed_on_garbage_proof() {
        let v = Erc7710DelegationVerifier::default();
        assert!(decode_redemption_proof("not-base64!").is_err());
        assert!(v.verify_chain(&[], &context(1)).is_err());
    }
}
