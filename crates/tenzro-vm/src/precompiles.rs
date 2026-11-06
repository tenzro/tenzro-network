//! Tenzro precompiled contracts.
//!
//! The standard Ethereum precompiles (0x01-0x11) are served by revm itself.
//! This module holds the Tenzro set, which revm reaches through
//! [`crate::evm::precompile_host`]: each one runs inside the EVM call frame
//! that invoked it, sees the frame's real `msg.sender` and `msg.value`, and
//! reads and writes state only through revm's journal. Nothing here holds
//! state of its own, so every validator executing the same block computes
//! the same result, and a read-only call can never persist a write.
//!
//! | Address  | Precompile        |
//! |----------|-------------------|
//! | `0x0100` | P256VERIFY (EIP-7951) |
//! | `0x1001` | wTNZO pointer (ERC-20 view of native TNZO) |
//! | `0x1002` | Token factory     |
//! | `0x1006` | NFT factory       |
//! | `0x1007` | VRF_VERIFY        |
//! | `0x1009` | RANDOMNESS_BEACON |
//! | `0x1010` | TEE_VERIFY        |
//! | `0x1011` | ZK_VERIFY         |

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::evm::precompile_host::{PrecompileCall, slot_key};
use crate::{VmError, error::Result};

/// Precompile address type
pub type PrecompileAddress = [u8; 20];

/// A 20-byte address whose numeric value is `hi << 8 | lo`.
pub const fn short_address(hi: u8, lo: u8) -> PrecompileAddress {
    let mut a = [0u8; 20];
    a[18] = hi;
    a[19] = lo;
    a
}

/// EIP-7951 P256VERIFY: secp256r1 ECDSA verification at the canonical
/// Ethereum address `0x100`.
pub const PRECOMPILE_P256VERIFY: PrecompileAddress = short_address(0x01, 0x00);
/// wTNZO pointer: the ERC-20 interface over native TNZO balances.
pub const PRECOMPILE_TNZO_BRIDGE: PrecompileAddress = short_address(0x10, 0x01);
/// Token factory: ERC-20 tokens whose ledger lives in this precompile's storage.
pub const PRECOMPILE_TOKEN_FACTORY: PrecompileAddress = short_address(0x10, 0x02);
/// NFT factory: ERC-721 / ERC-1155 collections.
pub const PRECOMPILE_NFT_FACTORY: PrecompileAddress = short_address(0x10, 0x06);
/// ECVRF-EDWARDS25519-SHA512-TAI proof verification (RFC 9381).
pub const PRECOMPILE_VRF_VERIFY: PrecompileAddress = short_address(0x10, 0x07);
/// Randomness derived from finalized chain state.
pub const PRECOMPILE_RANDOMNESS_BEACON: PrecompileAddress = short_address(0x10, 0x09);
/// TEE attestation report verification.
pub const PRECOMPILE_TEE_VERIFY: PrecompileAddress = short_address(0x10, 0x10);
/// ZK proof commitment lookup against the attestations recorded in state.
pub const PRECOMPILE_ZK_VERIFY: PrecompileAddress = short_address(0x10, 0x11);

/// Precompile execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrecompileResult {
    /// Output data
    pub output: Vec<u8>,

    /// Gas used, on top of whatever state access already charged
    pub gas_used: u64,

    /// Whether execution succeeded. `false` reverts the call frame.
    pub success: bool,
}

impl PrecompileResult {
    /// Create a success result
    pub fn success(output: Vec<u8>, gas_used: u64) -> Self {
        Self {
            output,
            gas_used,
            success: true,
        }
    }

    /// Create a revert result with ABI-encoded reason data
    pub fn revert(output: Vec<u8>, gas_used: u64) -> Self {
        Self {
            output,
            gas_used,
            success: false,
        }
    }

    /// Create a failure result with no output
    pub fn failed(gas_used: u64) -> Self {
        Self {
            output: Vec::new(),
            gas_used,
            success: false,
        }
    }
}

/// Precompile function signature.
pub type PrecompileFn =
    Arc<dyn Fn(&mut PrecompileCall<'_>) -> Result<PrecompileResult> + Send + Sync>;

/// Length of a ZK commitment hash (SHA-256 digest).
pub const ZK_COMMITMENT_HASH_LEN: usize = 32;

/// A 32-byte SHA-256 commitment over a Plonky3 proof envelope.
pub type ZkCommitmentHash = [u8; ZK_COMMITMENT_HASH_LEN];

/// Compute the canonical SHA-256 commitment for a Plonky3 proof envelope.
///
/// `commitment = SHA-256(circuit_id || proof_bytes || Σ (len_le(pi) || pi))`
///
/// The 4-byte little-endian length prefix on each public input prevents
/// ambiguity when public inputs vary in width. `circuit_id` is the raw UTF-8
/// bytes; every AIR has a fixed-length circuit_id so no prefix is needed.
pub fn compute_zk_commitment(proof: &tenzro_zk::Proof) -> ZkCommitmentHash {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(proof.circuit_id.as_bytes());
    hasher.update(&proof.proof_bytes);
    for pi in &proof.public_inputs {
        hasher.update((pi.len() as u32).to_le_bytes());
        hasher.update(pi);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; ZK_COMMITMENT_HASH_LEN];
    out.copy_from_slice(&digest);
    out
}

/// Storage slot of [`PRECOMPILE_ZK_VERIFY`] that records an attested proof
/// commitment. The attestation transaction writes a non-zero word here after
/// verifying the proof in block execution; the precompile reads it.
pub fn zk_attestation_slot(commitment: &ZkCommitmentHash) -> [u8; 32] {
    slot_key(b"tenzro/zk/attested", &[commitment])
}

/// Storage slot of [`PRECOMPILE_ZK_VERIFY`] marking that `statement` has an
/// attested proof in proof system `system`.
pub fn zk_statement_system_slot(statement: &[u8; 32], system: &str) -> [u8; 32] {
    slot_key(
        b"tenzro/zk/statement-system",
        &[statement, system.as_bytes()],
    )
}

/// Storage slot of [`PRECOMPILE_ZK_VERIFY`] counting the distinct proof
/// systems in which `statement` has an attested proof.
pub fn zk_statement_count_slot(statement: &[u8; 32]) -> [u8; 32] {
    slot_key(b"tenzro/zk/statement-count", &[statement])
}

/// `statementSystems(bytes32 statement) returns (uint256)`: the number of
/// distinct proof systems in which `statement` has an attested proof.
pub const SELECTOR_STATEMENT_SYSTEMS: [u8; 4] = [0xcf, 0x1e, 0x47, 0x1d];

/// Read whether `commitment` is attested, from any [`crate::VmState`].
pub fn zk_commitment_attested(
    state: &dyn crate::traits::VmState,
    commitment: &ZkCommitmentHash,
) -> bool {
    state
        .get_storage(&PRECOMPILE_ZK_VERIFY, &zk_attestation_slot(commitment))
        .is_some_and(|v| v.iter().any(|b| *b != 0))
}

/// Registry of Tenzro precompiles, keyed by address.
pub struct PrecompileRegistry {
    precompiles: DashMap<PrecompileAddress, PrecompileFn>,
    stateless: dashmap::DashSet<PrecompileAddress>,
}

impl PrecompileRegistry {
    /// Build the registry with every Tenzro precompile.
    pub fn new() -> Self {
        let registry = Self {
            precompiles: DashMap::new(),
            stateless: dashmap::DashSet::new(),
        };
        registry.register_stateless(PRECOMPILE_P256VERIFY, precompile_p256verify);
        registry.register_stateless(PRECOMPILE_VRF_VERIFY, precompile_vrf_verify);
        registry.register(
            PRECOMPILE_RANDOMNESS_BEACON,
            Arc::new(precompile_randomness_beacon),
        );
        registry.register(PRECOMPILE_TEE_VERIFY, Arc::new(precompile_tee_verify));
        registry.register(PRECOMPILE_ZK_VERIFY, Arc::new(precompile_zk_verify));
        registry.register(
            PRECOMPILE_NFT_FACTORY,
            Arc::new(crate::evm::nft_factory::nft_factory_precompile),
        );
        registry.register(
            PRECOMPILE_TNZO_BRIDGE,
            Arc::new(crate::evm::tnzo_bridge::wtnzo_pointer_precompile),
        );
        registry.register(
            PRECOMPILE_TOKEN_FACTORY,
            Arc::new(crate::evm::token_factory::token_factory_precompile),
        );
        registry
    }

    fn register(&self, address: PrecompileAddress, func: PrecompileFn) {
        self.precompiles.insert(address, func);
    }

    fn register_stateless(
        &self,
        address: PrecompileAddress,
        f: fn(&[u8], u64) -> Result<PrecompileResult>,
    ) {
        self.stateless.insert(address);
        self.register(address, pure(f));
    }

    /// Whether the precompile at `address` reads and writes no state, so it
    /// answers the same under `DELEGATECALL` and `CALLCODE` as under `CALL`.
    pub fn is_stateless(&self, address: &PrecompileAddress) -> bool {
        self.stateless.contains(address)
    }

    /// The precompile at `address`, if any.
    pub fn get(&self, address: &PrecompileAddress) -> Option<PrecompileFn> {
        if let Some(p) = self.precompiles.get(address) {
            return Some(p.value().clone());
        }
        crate::evm::token_factory::is_facade_address(address)
            .then(|| Arc::new(crate::evm::token_factory::token_facade_precompile) as PrecompileFn)
    }

    /// Whether `address` is a Tenzro precompile or a token facade.
    pub fn is_precompile(&self, address: &[u8]) -> bool {
        <[u8; 20]>::try_from(address).is_ok_and(|a| {
            self.precompiles.contains_key(&a) || crate::evm::token_factory::is_facade_address(&a)
        })
    }
}

impl Default for PrecompileRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Adapt a stateless precompile to the registry signature.
fn pure(f: fn(&[u8], u64) -> Result<PrecompileResult>) -> PrecompileFn {
    Arc::new(move |call: &mut PrecompileCall<'_>| f(call.input, call.gas_limit))
}

/// Gas per input byte for precompiles that parse variable-size input.
const GAS_PER_INPUT_BYTE: u64 = 16;

/// Output word for `true` / `false`.
fn bool_word(v: bool) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    out[31] = v as u8;
    out
}

// ---------------------------------------------------------------------------
// ZK_VERIFY (0x1011)
// ---------------------------------------------------------------------------

/// Answers how strongly a statement is proven on chain.
///
/// `statementSystems(bytes32 statement)` returns, as a uint256, the number of
/// distinct proof systems in which `statement`
/// (`tenzro_zk::statement_commitment(circuit_id, public_inputs)`) has an
/// attested proof; 0 means none. The records are written by the
/// `AttestZkProof` native transaction, which runs the full verifier during
/// block execution, so every validator answers the same way from state. A
/// contract that wants agreement of k independent proof systems requires the
/// answer to be at least k. The precompile never parses a proof: proofs are
/// megabytes, and verifying one belongs in the attestation transaction.
///
/// Gas: 3,000 plus the storage read.
fn precompile_zk_verify(call: &mut PrecompileCall<'_>) -> Result<PrecompileResult> {
    call.charge(3_000)?;
    if call.input.len() != 36 || call.input[..4] != SELECTOR_STATEMENT_SYSTEMS {
        return Ok(PrecompileResult::revert(
            crate::evm::precompile_host::abi_error_string("expected statementSystems(bytes32)"),
            0,
        ));
    }
    let mut statement = [0u8; 32];
    statement.copy_from_slice(&call.input[4..]);
    let count = call.sload(zk_statement_count_slot(&statement))?;
    Ok(PrecompileResult::success(count.to_vec(), 0))
}

// ---------------------------------------------------------------------------
// TEE_VERIFY (0x1010)
// ---------------------------------------------------------------------------

/// Input of the TEE verification precompile.
#[derive(serde::Deserialize)]
struct TeeVerifyInput {
    report: tenzro_types::AttestationReport,
    /// What the caller requires the report to commit to (its own challenge
    /// or binding), packed for the report's vendor before the comparison.
    expected_binding: Vec<u8>,
}

/// Verifies a TEE attestation report.
///
/// Input: JSON `{ "report": AttestationReport, "expected_binding": [bytes] }`.
/// Output: a 32-byte word, 1 if the report passes `tenzro_tee::verify_report`
/// with its hardware-signed user data equal to the vendor packing of
/// `expected_binding`, evaluated at the block timestamp so every validator
/// reaches the same answer; else 0. The caller decides what the report must
/// commit to, so a genuine report made for anything else is refused.
///
/// Gas: 100,000 + 16 per input byte, charged before parsing.
fn precompile_tee_verify(call: &mut PrecompileCall<'_>) -> Result<PrecompileResult> {
    call.charge(
        100_000u64.saturating_add(GAS_PER_INPUT_BYTE.saturating_mul(call.input.len() as u64)),
    )?;
    let parsed: TeeVerifyInput = match serde_json::from_slice(call.input) {
        Ok(p) => p,
        Err(_) => return Ok(PrecompileResult::success(bool_word(false), 0)),
    };
    Ok(PrecompileResult::success(
        bool_word(tee_report_acceptable(
            &parsed.report,
            &parsed.expected_binding,
            call.env.block_timestamp,
        )),
        0,
    ))
}

/// Whether TEE_VERIFY accepts `report` bound to `expected_binding` in a block
/// with timestamp `block_secs`.
pub(crate) fn tee_report_acceptable(
    report: &tenzro_types::AttestationReport,
    expected_binding: &[u8],
    block_secs: u64,
) -> bool {
    let expected = tenzro_types::tee::pack_user_data_for_vendor(report.vendor, expected_binding);
    let mut policy = tenzro_tee::VerifyPolicy::now(expected);
    policy.now = block_secs;
    tenzro_tee::verify_report(report, &policy).is_ok()
}

// ---------------------------------------------------------------------------
// RANDOMNESS_BEACON (0x1009)
// ---------------------------------------------------------------------------

/// `random(bytes32 seed) returns (bytes32)`: keccak256("random(bytes32)")[..4].
pub const SELECTOR_RANDOM: [u8; 4] = [0xd4, 0xce, 0x54, 0x5a];

/// Domain tag of beacon outputs.
const BEACON_DOMAIN: &[u8] = b"tenzro/randomness-beacon";

/// Randomness derived from finalized chain state.
///
/// `random(bytes32 seed)` returns
/// `keccak256(domain || hash(block N-1) || N || caller || counter || seed)`
/// where N is the executing block and `counter` counts the caller's previous
/// requests (it advances on every state-changing call, so two calls in one
/// block differ). Every input is fixed by the time the transaction executes
/// and none is chosen by the caller except `seed`, which only diversifies.
/// The proposer of block N-1 can influence its hash, so this suits
/// applications whose stakes are below the value of withholding a block;
/// commit to a request in one block and read the beacon in a later one to
/// keep the requester from seeing the output before committing.
///
/// Gas: 5,000 plus state access.
fn precompile_randomness_beacon(call: &mut PrecompileCall<'_>) -> Result<PrecompileResult> {
    call.charge(5_000)?;
    if call.input.len() != 36 || call.input[..4] != SELECTOR_RANDOM {
        return Ok(PrecompileResult::revert(
            crate::evm::precompile_host::abi_error_string("expected random(bytes32)"),
            0,
        ));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&call.input[4..36]);
    let caller = call.env.caller;
    let out = beacon_output(call, &caller, &seed)?;
    Ok(PrecompileResult::success(out.to_vec(), 0))
}

/// Draw one beacon output for `requester`, advancing its counter when the
/// call may write. Shared with the NFT factory's random mint.
pub fn beacon_output(
    call: &mut PrecompileCall<'_>,
    requester: &[u8; 20],
    seed: &[u8; 32],
) -> Result<[u8; 32]> {
    use sha3::{Digest, Keccak256};
    let beacon = PRECOMPILE_RANDOMNESS_BEACON;
    let counter_slot = slot_key(b"tenzro/beacon/counter", &[requester]);
    let counter =
        crate::evm::precompile_host::word_to_u128(&call.state.sload(beacon, counter_slot)?);
    if call.env.can_write() {
        call.state.sstore(
            beacon,
            counter_slot,
            crate::evm::precompile_host::u128_to_word(counter.saturating_add(1)),
        )?;
    }
    let number = call.env.block_number;
    let parent = call.state.block_hash(number.saturating_sub(1))?;
    let mut h = Keccak256::new();
    h.update(BEACON_DOMAIN);
    h.update(parent);
    h.update(number.to_be_bytes());
    h.update(requester);
    h.update(counter.to_be_bytes());
    h.update(seed);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    Ok(out)
}

// ---------------------------------------------------------------------------
// EIP-7951 P256VERIFY (0x100) — secp256r1 ECDSA signature verification
// ---------------------------------------------------------------------------

/// P256VERIFY precompile (EIP-7951, Fusaka Dec 2025, address 0x100).
///
/// Verifies a secp256r1 (NIST P-256) ECDSA signature. Enables on-chain
/// verification of WebAuthn / FIDO2 / Apple Secure Enclave / Android
/// Keystore signatures, which is foundational for Tenzro's TDIP human
/// identity flows and machine passkeys.
///
/// **Input** — exactly 160 bytes, big-endian:
/// | offset | length | field            |
/// |--------|--------|------------------|
/// |   0    |   32   | message hash     |
/// |  32    |   32   | signature `r`    |
/// |  64    |   32   | signature `s`    |
/// |  96    |   32   | public key `x`   |
/// | 128    |   32   | public key `y`   |
///
/// **Output:**
/// - Valid signature → 32-byte big-endian `1` (`0x00…0001`).
/// - Invalid signature, malformed input, or wrong length → empty bytes
///   (`0x`). The precompile does NOT revert; callers must check the
///   return-data length, matching go-ethereum semantics.
///
/// **Gas cost:** flat 6900, input-independent.
fn precompile_p256verify(input: &[u8], gas_limit: u64) -> Result<PrecompileResult> {
    use p256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};

    const GAS_COST: u64 = 6900;
    if gas_limit < GAS_COST {
        return Err(VmError::OutOfGas);
    }

    // Wrong length is failure-with-empty-output, NOT a revert.
    if input.len() != 160 {
        return Ok(PrecompileResult::success(Vec::new(), GAS_COST));
    }

    let hash = &input[0..32];
    let r = &input[32..64];
    let s = &input[64..96];
    let pk_x = &input[96..128];
    let pk_y = &input[128..160];

    // Reassemble (r, s) as a fixed-array DER-free signature and (x, y) as an
    // uncompressed SEC1 point with the 0x04 prefix.
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(r);
    sig_bytes[32..].copy_from_slice(s);
    let signature = match Signature::from_slice(&sig_bytes) {
        Ok(sig) => sig,
        Err(_) => return Ok(PrecompileResult::success(Vec::new(), GAS_COST)),
    };

    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..33].copy_from_slice(pk_x);
    sec1[33..].copy_from_slice(pk_y);
    let vk = match VerifyingKey::from_sec1_bytes(&sec1) {
        Ok(k) => k,
        Err(_) => return Ok(PrecompileResult::success(Vec::new(), GAS_COST)),
    };

    match vk.verify_prehash(hash, &signature) {
        Ok(()) => {
            // 32-byte big-endian `1`.
            let mut out = [0u8; 32];
            out[31] = 1;
            Ok(PrecompileResult::success(out.to_vec(), GAS_COST))
        }
        Err(_) => Ok(PrecompileResult::success(Vec::new(), GAS_COST)),
    }
}

/// VRF proof verification precompile (0x1007)
///
/// Verifies an ECVRF-EDWARDS25519-SHA512-TAI proof (RFC 9381 §5.4.1.1) and, on
/// success, returns the 64-byte VRF output (beta). Callers such as the NFT
/// factory can use this output to pick a deterministic but unpredictable
/// token_id, trait, or rarity tier that third parties can later re-verify.
///
/// Input layout (flat, big-endian):
///   pubkey      :  32 bytes  (Ed25519 compressed public key)
///   proof       :  80 bytes  (Gamma(32) || c(16) || s(32))
///   alpha_len   :  32 bytes  (uint256, big-endian length of alpha)
///   alpha       :  alpha_len bytes (VRF input — block hash, mint nonce, ...)
///
/// Output (on valid proof):
///   status      :  32 bytes  (uint256, 1 = valid)
///   output      :  64 bytes  (VRF beta / hash output)
///
/// Output (on invalid proof or malformed input):
///   status      :  32 bytes  (uint256, 0 = invalid)
///
/// Gas cost: 50,000 base + 3 * alpha_len (amortizes SHA-512 + curve ops).
fn precompile_vrf_verify(input: &[u8], gas_limit: u64) -> Result<PrecompileResult> {
    use tenzro_crypto::vrf;

    const BASE_GAS: u64 = 50_000;
    const GAS_PER_ALPHA_BYTE: u64 = 3;
    const HEADER_LEN: usize = 32 + vrf::PROOF_LEN + 32; // pk + proof + alpha_len
    const INVALID: [u8; 32] = [0u8; 32];
    const VALID_STATUS: [u8; 32] = {
        let mut s = [0u8; 32];
        s[31] = 1;
        s
    };

    // Reject oversized inputs cheaply.
    if input.len() < HEADER_LEN {
        return Ok(PrecompileResult::success(
            INVALID.to_vec(),
            BASE_GAS.min(gas_limit),
        ));
    }

    // Parse pubkey
    let mut pk_bytes = [0u8; 32];
    pk_bytes.copy_from_slice(&input[0..32]);

    // Parse proof
    let mut proof_bytes = [0u8; vrf::PROOF_LEN];
    proof_bytes.copy_from_slice(&input[32..32 + vrf::PROOF_LEN]);

    // Parse alpha length (uint256 big-endian); reject lengths that exceed u32.
    let len_bytes = &input[32 + vrf::PROOF_LEN..HEADER_LEN];
    for b in &len_bytes[..28] {
        if *b != 0 {
            return Ok(PrecompileResult::success(
                INVALID.to_vec(),
                BASE_GAS.min(gas_limit),
            ));
        }
    }
    let alpha_len =
        u32::from_be_bytes([len_bytes[28], len_bytes[29], len_bytes[30], len_bytes[31]]) as usize;

    if input.len() < HEADER_LEN + alpha_len {
        return Ok(PrecompileResult::success(
            INVALID.to_vec(),
            BASE_GAS.min(gas_limit),
        ));
    }
    let alpha = &input[HEADER_LEN..HEADER_LEN + alpha_len];

    // Gas accounting — fail cleanly if caller didn't supply enough gas.
    let gas_used = BASE_GAS.saturating_add(GAS_PER_ALPHA_BYTE.saturating_mul(alpha_len as u64));
    if gas_used > gas_limit {
        return Err(crate::error::VmError::OutOfGas);
    }

    let pk = vrf::VrfPublicKey(pk_bytes);
    let proof = vrf::VrfProof(proof_bytes);

    match vrf::verify(&pk, alpha, &proof) {
        Ok(output) => {
            let mut out = Vec::with_capacity(32 + vrf::OUTPUT_LEN);
            out.extend_from_slice(&VALID_STATUS);
            out.extend_from_slice(&output.0);
            tracing::debug!(alpha_len = alpha_len, "VRF precompile: proof verified");
            Ok(PrecompileResult::success(out, gas_used))
        }
        Err(e) => {
            tracing::debug!("VRF precompile: verification failed: {}", e);
            Ok(PrecompileResult::success(INVALID.to_vec(), gas_used))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- P256VERIFY (EIP-7951, 0x100) ----

    #[test]
    fn test_p256verify_round_trip_valid_signature() {
        use ::p256::elliptic_curve::Generate;
        use getrandom_0_4::{SysRng, rand_core::UnwrapErr};
        use p256::ecdsa::{SigningKey, signature::hazmat::PrehashSigner};
        use sha2::{Digest, Sha256};

        let signing_key = SigningKey::generate_from_rng(&mut UnwrapErr(SysRng));
        let verifying_key = signing_key.verifying_key();
        let hash = Sha256::digest(b"tenzro-eip7951-roundtrip");
        let signature: p256::ecdsa::Signature = signing_key.sign_prehash(&hash).unwrap();

        let encoded = verifying_key.to_sec1_point(false);
        let bytes = encoded.as_bytes();
        assert_eq!(bytes[0], 0x04);

        let mut input = Vec::with_capacity(160);
        input.extend_from_slice(&hash);
        input.extend_from_slice(&signature.to_bytes());
        input.extend_from_slice(&bytes[1..]); // x || y, 64 bytes

        let result = precompile_p256verify(&input, 10_000).unwrap();
        assert!(result.success);
        assert_eq!(result.gas_used, 6900);
        assert_eq!(result.output.len(), 32);
        assert_eq!(result.output[31], 1);
    }

    #[test]
    fn test_p256verify_wrong_length_returns_empty() {
        let result = precompile_p256verify(&[0u8; 100], 10_000).unwrap();
        assert!(result.success);
        assert_eq!(result.output, Vec::<u8>::new());
        assert_eq!(result.gas_used, 6900);
    }

    #[test]
    fn test_p256verify_invalid_signature_returns_empty() {
        let input = vec![0xFFu8; 160];
        let result = precompile_p256verify(&input, 10_000).unwrap();
        assert!(result.success);
        assert_eq!(result.output, Vec::<u8>::new());
    }

    #[test]
    fn test_p256verify_out_of_gas() {
        let result = precompile_p256verify(&[0u8; 160], 100);
        assert!(matches!(result, Err(VmError::OutOfGas)));
    }

    // ============================================================
    // VRF precompile tests (0x1007)
    // ============================================================

    fn vrf_build_input(pk: &[u8; 32], proof: &[u8; 80], alpha: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(32 + 80 + 32 + alpha.len());
        v.extend_from_slice(pk);
        v.extend_from_slice(proof);
        let mut len_be = [0u8; 32];
        let bytes = (alpha.len() as u32).to_be_bytes();
        len_be[28..32].copy_from_slice(&bytes);
        v.extend_from_slice(&len_be);
        v.extend_from_slice(alpha);
        v
    }

    #[test]
    fn test_vrf_precompile_valid_proof_returns_output() {
        use tenzro_crypto::vrf::{VrfSecretKey, prove};

        let sk = VrfSecretKey([7u8; 32]);
        let pk = sk.public_key();
        let alpha = b"tenzro-nft-mint-42";
        let proof = prove(&sk, alpha).unwrap();

        let input = vrf_build_input(&pk.0, &proof.0, alpha);
        let out = precompile_vrf_verify(&input, 1_000_000).unwrap();

        assert_eq!(out.output.len(), 32 + 64);
        // First 32 bytes = uint256(1)
        assert_eq!(out.output[31], 1);
        for b in &out.output[0..31] {
            assert_eq!(*b, 0);
        }
        // Output bytes must be non-trivial
        assert!(out.output[32..].iter().any(|b| *b != 0));
    }

    #[test]
    fn test_vrf_precompile_tampered_proof_rejected() {
        use tenzro_crypto::vrf::{VrfSecretKey, prove};

        let sk = VrfSecretKey([7u8; 32]);
        let pk = sk.public_key();
        let alpha = b"tenzro-nft-mint-42";
        let mut proof = prove(&sk, alpha).unwrap();
        proof.0[0] ^= 0x01;

        let input = vrf_build_input(&pk.0, &proof.0, alpha);
        let out = precompile_vrf_verify(&input, 1_000_000).unwrap();
        // Only 32-byte zero status on failure
        assert_eq!(out.output, vec![0u8; 32]);
    }

    #[test]
    fn test_vrf_precompile_wrong_alpha_rejected() {
        use tenzro_crypto::vrf::{VrfSecretKey, prove};

        let sk = VrfSecretKey([9u8; 32]);
        let pk = sk.public_key();
        let proof = prove(&sk, b"hello").unwrap();

        let input = vrf_build_input(&pk.0, &proof.0, b"world");
        let out = precompile_vrf_verify(&input, 1_000_000).unwrap();
        assert_eq!(out.output, vec![0u8; 32]);
    }

    #[test]
    fn test_vrf_precompile_short_input() {
        let input = vec![0u8; 50]; // too short
        let out = precompile_vrf_verify(&input, 1_000_000).unwrap();
        assert_eq!(out.output, vec![0u8; 32]);
    }

    #[test]
    fn test_vrf_precompile_insufficient_gas() {
        use tenzro_crypto::vrf::{VrfSecretKey, prove};
        let sk = VrfSecretKey([3u8; 32]);
        let pk = sk.public_key();
        let alpha = b"abc";
        let proof = prove(&sk, alpha).unwrap();
        let input = vrf_build_input(&pk.0, &proof.0, alpha);
        let err = precompile_vrf_verify(&input, 1_000); // way below 50k base
        assert!(matches!(err, Err(crate::error::VmError::OutOfGas)));
    }

    #[test]
    fn test_vrf_precompile_huge_length_rejected() {
        // alpha_len with top bits set -> rejected as invalid
        let mut input = vec![0u8; 32 + 80 + 32];
        // set a byte in the high 28 bytes of length encoding
        input[32 + 80] = 0x01;
        let out = precompile_vrf_verify(&input, 1_000_000).unwrap();
        assert_eq!(out.output, vec![0u8; 32]);
    }
}
