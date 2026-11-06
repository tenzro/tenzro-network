//! Transactions signed by external wallets.
//!
//! An external wallet holds its own key: secp256k1 for an EVM account,
//! Ed25519 for an SVM account. Tenzro only verifies. These accounts are
//! plain ledger accounts with no agent authority; the sender is whatever
//! the signature recovers to, and nothing else.
//!
//! The ledger has one account per key. An EVM sender `a20` is the ledger
//! account `a20 || 0^12` (the form `Address::evm_address` reads back); an
//! SVM signer is its 32-byte public key. Both are visible to every VM view
//! through the shared token ledger.

use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use rlp::{Rlp, RlpStream};
use sha3::{Digest, Keccak256};
use tenzro_types::transaction::{CallVm, VmCall};

use crate::VmType;
use crate::account_abstraction::Eip7702Authorization;
use crate::error::VmError;
use crate::traits::VmState;
use crate::types::VmTransaction;
use revm::primitives::U256;

fn bad(msg: impl Into<String>) -> VmError {
    VmError::InvalidTransaction(msg.into())
}

fn keccak(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Keccak256::digest(data));
    out
}

/// secp256k1n / 2, big-endian. Signatures with a larger `s` are malleable
/// and refused, as on Ethereum.
const SECP256K1_HALF_N: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

/// Intrinsic gas of an EVM transaction under the EVM's own rules (Prague):
/// the larger of the initial gas and the EIP-7623 calldata floor.
pub fn intrinsic_gas(
    data: &[u8],
    is_create: bool,
    access_list: &[([u8; 20], Vec<[u8; 32]>)],
    authorizations: usize,
) -> u64 {
    let access_list: Vec<revm::primitives::AccessListItem> = access_list
        .iter()
        .map(|(a, keys)| revm::primitives::AccessListItem {
            address: revm::primitives::Address::from(*a),
            storage_keys: keys
                .iter()
                .map(|k| revm::primitives::B256::from(*k))
                .collect(),
        })
        .collect();
    let g = revm::interpreter::gas::calculate_initial_tx_gas(
        revm::primitives::SpecId::PRAGUE,
        data,
        is_create,
        &access_list,
        authorizations as u64,
    );
    g.initial_gas.max(g.floor_gas)
}

/// Recovers the EVM address that signed `prehash` (`r || s` plus parity).
/// The single secp256k1 recovery used for transactions and EIP-7702
/// authorizations.
pub fn ecrecover(
    prehash: &[u8; 32],
    r: &[u8; 32],
    s: &[u8; 32],
    y_parity: u8,
) -> Result<[u8; 20], VmError> {
    if y_parity > 1 || s.as_slice() > SECP256K1_HALF_N.as_slice() {
        return Err(VmError::InvalidSignature);
    }
    let mut rs = [0u8; 64];
    rs[..32].copy_from_slice(r);
    rs[32..].copy_from_slice(s);
    let sig = Signature::from_bytes(&rs.into()).map_err(|_| VmError::InvalidSignature)?;
    let rid = RecoveryId::try_from(y_parity).map_err(|_| VmError::InvalidSignature)?;
    let key = VerifyingKey::recover_from_prehash(prehash, &sig, rid)
        .map_err(|_| VmError::InvalidSignature)?;
    let point = key.to_sec1_point(false);
    let hash = keccak(&point.as_bytes()[1..]);
    let mut out = [0u8; 20];
    out.copy_from_slice(&hash[12..]);
    Ok(out)
}

/// The ledger account of an EVM address.
pub fn evm_account(a: [u8; 20]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..20].copy_from_slice(&a);
    out
}

/// EVM transaction envelope kinds accepted from external wallets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvmTxKind {
    /// Untyped transaction with EIP-155 replay protection (pre-155
    /// signatures refused).
    Eip155,
    /// EIP-2930.
    AccessList,
    /// EIP-1559.
    DynamicFee,
    /// EIP-7702.
    SetCode,
}

/// A decoded, signature-verified EVM transaction.
#[derive(Debug, Clone)]
pub struct ExternalEvmTx {
    pub kind: EvmTxKind,
    pub chain_id: u64,
    pub nonce: u64,
    /// EIP-155 and 2930: the gas price. 1559 and 7702: the fee cap.
    pub max_fee_per_gas: u128,
    /// EIP-155 and 2930: equal to the gas price.
    pub max_priority_fee_per_gas: u128,
    pub gas_limit: u64,
    pub to: Option<[u8; 20]>,
    pub value: u128,
    pub data: Vec<u8>,
    pub authorizations: Vec<Eip7702Authorization>,
    /// EIP-2930 access list: addresses and their storage keys.
    pub access_list: Vec<([u8; 20], Vec<[u8; 32]>)>,
    /// Recovered sender.
    pub from: [u8; 20],
    /// keccak256 of the raw envelope; the hash wallets look up.
    pub hash: [u8; 32],
    /// `r || s || y_parity`.
    pub signature: [u8; 65],
}

fn uint(item: &Rlp<'_>, max_len: usize, what: &str) -> Result<Vec<u8>, VmError> {
    if item.is_list() {
        return Err(bad(format!("{what}: expected a number")));
    }
    let d = item.data().map_err(|e| bad(format!("{what}: {e}")))?;
    if d.len() > max_len || d.first() == Some(&0) {
        return Err(bad(format!("{what}: non-canonical or too large")));
    }
    Ok(d.to_vec())
}

fn u64_at(r: &Rlp<'_>, i: usize, what: &str) -> Result<u64, VmError> {
    let d = uint(&r.at(i).map_err(|e| bad(format!("{what}: {e}")))?, 8, what)?;
    Ok(d.iter().fold(0u64, |a, b| (a << 8) | u64::from(*b)))
}

fn u128_at(r: &Rlp<'_>, i: usize, what: &str) -> Result<u128, VmError> {
    let d = uint(&r.at(i).map_err(|e| bad(format!("{what}: {e}")))?, 16, what)?;
    Ok(d.iter().fold(0u128, |a, b| (a << 8) | u128::from(*b)))
}

fn word_at(r: &Rlp<'_>, i: usize, what: &str) -> Result<[u8; 32], VmError> {
    let d = uint(&r.at(i).map_err(|e| bad(format!("{what}: {e}")))?, 32, what)?;
    let mut out = [0u8; 32];
    out[32 - d.len()..].copy_from_slice(&d);
    Ok(out)
}

fn bytes_at(r: &Rlp<'_>, i: usize, what: &str) -> Result<Vec<u8>, VmError> {
    let item = r.at(i).map_err(|e| bad(format!("{what}: {e}")))?;
    if item.is_list() {
        return Err(bad(format!("{what}: expected bytes")));
    }
    item.data()
        .map(<[u8]>::to_vec)
        .map_err(|e| bad(format!("{what}: {e}")))
}

fn to_at(r: &Rlp<'_>, i: usize) -> Result<Option<[u8; 20]>, VmError> {
    let d = bytes_at(r, i, "to")?;
    match d.len() {
        0 => Ok(None),
        20 => {
            let mut a = [0u8; 20];
            a.copy_from_slice(&d);
            Ok(Some(a))
        }
        _ => Err(bad("to: must be empty or 20 bytes")),
    }
}

fn access_list_at(r: &Rlp<'_>, i: usize) -> Result<Vec<([u8; 20], Vec<[u8; 32]>)>, VmError> {
    let list = r.at(i).map_err(|e| bad(format!("accessList: {e}")))?;
    if !list.is_list() {
        return Err(bad("accessList: expected a list"));
    }
    let mut out = Vec::new();
    for entry in list.iter() {
        let address: [u8; 20] = (entry.item_count().ok() == Some(2))
            .then(|| bytes_at(&entry, 0, "accessList address").ok())
            .flatten()
            .and_then(|a| a.try_into().ok())
            .ok_or_else(|| bad("accessList: malformed entry"))?;
        let keys = entry.at(1).map_err(|e| bad(format!("accessList: {e}")))?;
        if !keys.is_list() {
            return Err(bad("accessList: storage keys must be a list"));
        }
        let keys = keys
            .iter()
            .map(|k| k.data().ok().and_then(|d| <[u8; 32]>::try_from(d).ok()))
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| bad("accessList: storage keys must be 32 bytes"))?;
        out.push((address, keys));
    }
    Ok(out)
}

fn authorizations_at(r: &Rlp<'_>, i: usize) -> Result<Vec<Eip7702Authorization>, VmError> {
    let list = r
        .at(i)
        .map_err(|e| bad(format!("authorizationList: {e}")))?;
    if !list.is_list() {
        return Err(bad("authorizationList: expected a list"));
    }
    let mut out = Vec::new();
    for a in list.iter() {
        if a.item_count().ok() != Some(6) {
            return Err(bad("authorizationList: malformed entry"));
        }
        let address = bytes_at(&a, 1, "authorization address")?;
        if address.len() != 20 {
            return Err(bad("authorization address must be 20 bytes"));
        }
        // y_parity is a uint8 on the wire; a value above 1 does not
        // recover, so execution skips that authorization (EIP-7702).
        let y = u8::try_from(u64_at(&a, 3, "authorization y_parity")?)
            .map_err(|_| bad("authorization y_parity exceeds 8 bits"))?;
        let mut signature = word_at(&a, 4, "authorization r")?.to_vec();
        signature.extend_from_slice(&word_at(&a, 5, "authorization s")?);
        signature.push(y);
        out.push(Eip7702Authorization {
            chain_id: U256::from_be_bytes(word_at(&a, 0, "authorization chain_id")?),
            delegate_address: address,
            nonce: u64_at(&a, 2, "authorization nonce")?,
            signature,
        });
    }
    if out.is_empty() {
        return Err(bad(
            "authorizationList: EIP-7702 requires at least one authorization",
        ));
    }
    Ok(out)
}

/// RLP list of the first `n` items of `r`, re-using their exact encoding.
fn prefix_list(r: &Rlp<'_>, n: usize, tail: &[&[u8]]) -> Result<Vec<u8>, VmError> {
    let mut s = RlpStream::new_list(n + tail.len());
    for i in 0..n {
        s.append_raw(r.at(i).map_err(|e| bad(e.to_string()))?.as_raw(), 1);
    }
    for t in tail {
        s.append(t);
    }
    Ok(s.out().to_vec())
}

/// Decodes a raw signed EVM transaction (`eth_sendRawTransaction` bytes),
/// recovers its sender and checks it is bound to `chain_id`.
pub fn decode_evm_raw(raw: &[u8], chain_id: u64) -> Result<ExternalEvmTx, VmError> {
    let first = *raw.first().ok_or_else(|| bad("empty transaction"))?;
    let (kind, body) = match first {
        0x01 => (EvmTxKind::AccessList, &raw[1..]),
        0x02 => (EvmTxKind::DynamicFee, &raw[1..]),
        0x04 => (EvmTxKind::SetCode, &raw[1..]),
        b if b >= 0xc0 => (EvmTxKind::Eip155, raw),
        b => return Err(bad(format!("unsupported transaction type 0x{b:02x}"))),
    };
    let r = Rlp::new(body);
    if !r.is_list() || r.as_raw().len() != body.len() {
        return Err(bad("transaction is not one RLP list"));
    }
    let count = r.item_count().map_err(|e| bad(e.to_string()))?;
    let expected = match kind {
        EvmTxKind::Eip155 => 9,
        EvmTxKind::AccessList => 11,
        EvmTxKind::DynamicFee => 12,
        EvmTxKind::SetCode => 13,
    };
    if count != expected {
        return Err(bad(format!("expected {expected} fields, got {count}")));
    }

    let (
        tx_chain,
        nonce,
        max_fee,
        prio,
        gas_limit,
        to,
        value,
        data,
        auths,
        access_list,
        y,
        sighash,
    );
    match kind {
        EvmTxKind::Eip155 => {
            nonce = u64_at(&r, 0, "nonce")?;
            max_fee = u128_at(&r, 1, "gasPrice")?;
            prio = max_fee;
            gas_limit = u64_at(&r, 2, "gas")?;
            to = to_at(&r, 3)?;
            value = u128_at(&r, 4, "value")?;
            data = bytes_at(&r, 5, "data")?;
            auths = Vec::new();
            access_list = Vec::new();
            let v = u64_at(&r, 6, "v")?;
            if v < 35 {
                return Err(bad(
                    "legacy transaction without EIP-155 chain id is refused",
                ));
            }
            tx_chain = (v - 35) / 2;
            y = ((v - 35) % 2) as u8;
            let mut cid = tx_chain.to_be_bytes().to_vec();
            while cid.first() == Some(&0) {
                cid.remove(0);
            }
            sighash = keccak(&prefix_list(&r, 6, &[&cid, &[], &[]])?);
        }
        _ => {
            tx_chain = u64_at(&r, 0, "chainId")?;
            nonce = u64_at(&r, 1, "nonce")?;
            let fee_fields = if kind == EvmTxKind::AccessList { 1 } else { 2 };
            if fee_fields == 1 {
                max_fee = u128_at(&r, 2, "gasPrice")?;
                prio = max_fee;
            } else {
                prio = u128_at(&r, 2, "maxPriorityFeePerGas")?;
                max_fee = u128_at(&r, 3, "maxFeePerGas")?;
                if prio > max_fee {
                    return Err(bad("maxPriorityFeePerGas exceeds maxFeePerGas"));
                }
            }
            let b = 2 + fee_fields;
            gas_limit = u64_at(&r, b, "gas")?;
            to = to_at(&r, b + 1)?;
            value = u128_at(&r, b + 2, "value")?;
            data = bytes_at(&r, b + 3, "data")?;
            access_list = access_list_at(&r, b + 4)?;
            let mut n = b + 5;
            if kind == EvmTxKind::SetCode {
                if to.is_none() {
                    return Err(bad("EIP-7702 transaction cannot create a contract"));
                }
                auths = authorizations_at(&r, n)?;
                n += 1;
            } else {
                auths = Vec::new();
            }
            let yp = u64_at(&r, n, "yParity")?;
            if yp > 1 {
                return Err(VmError::InvalidSignature);
            }
            y = yp as u8;
            let mut pre = vec![first];
            pre.extend_from_slice(&prefix_list(&r, n, &[])?);
            sighash = keccak(&pre);
        }
    }
    if tx_chain != chain_id {
        return Err(bad(format!(
            "chain id {tx_chain} does not match this network ({chain_id})"
        )));
    }
    let rr = word_at(&r, count - 2, "r")?;
    let ss = word_at(&r, count - 1, "s")?;
    let from = ecrecover(&sighash, &rr, &ss, y)?;
    let mut signature = [0u8; 65];
    signature[..32].copy_from_slice(&rr);
    signature[32..64].copy_from_slice(&ss);
    signature[64] = y;
    Ok(ExternalEvmTx {
        kind,
        chain_id: tx_chain,
        nonce,
        max_fee_per_gas: max_fee,
        max_priority_fee_per_gas: prio,
        gas_limit,
        to,
        value,
        data,
        authorizations: auths,
        access_list,
        from,
        hash: keccak(raw),
        signature,
    })
}

impl ExternalEvmTx {
    /// Price per gas paid at `base_fee`, in the EVM's native unit. Refused
    /// when the fee cap is below the base fee.
    pub fn effective_gas_price(&self, base_fee: u128) -> Result<u128, VmError> {
        if self.max_fee_per_gas < base_fee {
            return Err(bad("maxFeePerGas below the current base fee"));
        }
        Ok(self
            .max_fee_per_gas
            .min(base_fee.saturating_add(self.max_priority_fee_per_gas)))
    }

    /// Intrinsic gas (Prague): the base cost, calldata, access list and
    /// `PER_EMPTY_ACCOUNT_COST` per authorization, or the EIP-7623 calldata
    /// floor when that is higher. A gas limit below it can never execute,
    /// so admission refuses the transaction.
    pub fn intrinsic_gas(&self) -> u64 {
        intrinsic_gas(
            &self.data,
            self.to.is_none(),
            &self.access_list,
            self.authorizations.len(),
        )
    }

    /// The VM transaction this executes as: an EVM transaction from the
    /// recovered sender, already verified, carrying its EIP-7702
    /// authorizations.
    pub fn to_vm_transaction(&self, base_fee: u128) -> Result<VmTransaction, VmError> {
        let mut tx = VmTransaction::new(
            self.from.to_vec(),
            self.to.map(|a| a.to_vec()),
            self.value,
            self.data.clone(),
            self.gas_limit,
            self.effective_gas_price(base_fee)?,
            self.nonce,
            VmType::Evm,
            self.chain_id,
        )
        .with_authorization_list(self.authorizations.clone())
        .with_access_list(self.access_list.clone());
        tx.block_base_fee = Some(base_fee);
        Ok(tx)
    }
}

fn shortvec(b: &[u8], off: &mut usize) -> Result<usize, VmError> {
    let mut v = 0usize;
    for i in 0..3 {
        let byte = *b.get(*off).ok_or_else(|| bad("truncated length"))?;
        *off += 1;
        v |= usize::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            return Ok(v);
        }
    }
    Err(bad("length prefix too long"))
}

fn take<'a>(b: &'a [u8], off: &mut usize, n: usize) -> Result<&'a [u8], VmError> {
    let end = off
        .checked_add(n)
        .filter(|e| *e <= b.len())
        .ok_or_else(|| bad("truncated transaction"))?;
    let s = &b[*off..end];
    *off = end;
    Ok(s)
}

/// One instruction of a Solana message, with its accounts resolved.
#[derive(Debug, Clone)]
pub struct SvmInstruction {
    pub program_id: [u8; 32],
    pub accounts: Vec<[u8; 32]>,
    pub data: Vec<u8>,
}

/// A decoded, signature-verified Solana wire transaction.
#[derive(Debug, Clone)]
pub struct ExternalSvmTx {
    /// Signers in order; the first pays the fee.
    pub signers: Vec<[u8; 32]>,
    pub recent_blockhash: [u8; 32],
    pub instructions: Vec<SvmInstruction>,
    /// The first signature; the transaction id wallets look up.
    pub signature: [u8; 64],
}

/// Decodes a Solana wire transaction (legacy or v0 message) and verifies
/// every required Ed25519 signature over the message bytes. Address table
/// lookups are refused: every account must be in the message.
pub fn decode_svm_wire(raw: &[u8]) -> Result<ExternalSvmTx, VmError> {
    use ed25519_dalek::{Signature as EdSig, VerifyingKey as EdKey};
    let mut off = 0;
    let nsig = shortvec(raw, &mut off)?;
    let mut sigs = Vec::with_capacity(nsig.min(raw.len().saturating_sub(off) / 64));
    for _ in 0..nsig {
        let mut s = [0u8; 64];
        s.copy_from_slice(take(raw, &mut off, 64)?);
        sigs.push(s);
    }
    let msg = &raw[off..];
    let mut m = 0;
    let versioned = msg.first().is_some_and(|b| b & 0x80 != 0);
    if versioned {
        let v = msg[0] & 0x7f;
        if v != 0 {
            return Err(bad(format!("unsupported message version {v}")));
        }
        m = 1;
    }
    let header = take(msg, &mut m, 3)?;
    let required = usize::from(header[0]);
    let nkeys = shortvec(msg, &mut m)?;
    let mut keys = Vec::with_capacity(nkeys.min(msg.len().saturating_sub(m) / 32));
    for _ in 0..nkeys {
        let mut k = [0u8; 32];
        k.copy_from_slice(take(msg, &mut m, 32)?);
        keys.push(k);
    }
    if required == 0 || required != nsig || required > nkeys {
        return Err(bad("signature count does not match the message header"));
    }
    let mut recent_blockhash = [0u8; 32];
    recent_blockhash.copy_from_slice(take(msg, &mut m, 32)?);
    let nix = shortvec(msg, &mut m)?;
    // Each instruction is at least a program index and two empty lengths.
    let mut instructions = Vec::with_capacity(nix.min(msg.len().saturating_sub(m) / 3));
    let key_at = |i: usize| {
        keys.get(i)
            .copied()
            .ok_or_else(|| bad("account index out of range"))
    };
    for _ in 0..nix {
        let pid = usize::from(take(msg, &mut m, 1)?[0]);
        let nacc = shortvec(msg, &mut m)?;
        let accounts = take(msg, &mut m, nacc)?
            .iter()
            .map(|i| key_at(usize::from(*i)))
            .collect::<Result<Vec<_>, _>>()?;
        let dlen = shortvec(msg, &mut m)?;
        let data = take(msg, &mut m, dlen)?.to_vec();
        instructions.push(SvmInstruction {
            program_id: key_at(pid)?,
            accounts,
            data,
        });
    }
    if versioned && shortvec(msg, &mut m)? != 0 {
        return Err(bad("address table lookups are not supported"));
    }
    if m != msg.len() {
        return Err(bad("trailing bytes after the message"));
    }
    for (sig, key) in sigs.iter().zip(&keys) {
        let vk = EdKey::from_bytes(key).map_err(|_| VmError::InvalidSignature)?;
        vk.verify_strict(msg, &EdSig::from_bytes(sig))
            .map_err(|_| VmError::InvalidSignature)?;
    }
    Ok(ExternalSvmTx {
        signers: keys[..required].to_vec(),
        recent_blockhash,
        instructions,
        signature: sigs[0],
    })
}

impl ExternalSvmTx {
    /// The SVM calls this executes as, atomically, from the fee payer:
    /// each instruction's data is `[n][n account keys][instruction data]`.
    pub fn to_vm_calls(&self) -> Result<Vec<VmCall>, VmError> {
        let payer = self.signers.first().ok_or_else(|| bad("no fee payer"))?;
        self.instructions
            .iter()
            .map(|ix| {
                if ix.program_id == SYSTEM_PROGRAM_ID {
                    return system_transfer_call(payer, ix);
                }
                let n = u8::try_from(ix.accounts.len()).map_err(|_| bad("too many accounts"))?;
                let mut data = vec![n];
                for a in &ix.accounts {
                    data.extend_from_slice(a);
                }
                data.extend_from_slice(&ix.data);
                Ok(VmCall {
                    vm: CallVm::Svm,
                    to: ix.program_id.to_vec(),
                    value: 0,
                    data,
                })
            })
            .collect()
    }
}

/// The Solana System Program.
pub const SYSTEM_PROGRAM_ID: [u8; 32] = [0u8; 32];

/// A System Program transfer (instruction 2: `u32` discriminant, `u64`
/// lamports; accounts `[from, to]`) as the wrapped-TNZO SPL transfer over the
/// same native balance, at the same 9-decimal unit. The calls of a
/// transaction execute from its fee payer, so a transfer from any other
/// account is refused, as is every other System Program instruction.
fn system_transfer_call(payer: &[u8; 32], ix: &SvmInstruction) -> Result<VmCall, VmError> {
    let d = &ix.data;
    if d.len() != 12 || d[..4] != 2u32.to_le_bytes() {
        return Err(bad("only System Program transfers are supported"));
    }
    let [from, to] = ix.accounts.as_slice() else {
        return Err(bad("a System Program transfer names two accounts"));
    };
    if from != payer {
        return Err(bad("a System Program transfer must be from the fee payer"));
    }
    let mut data = vec![3u8];
    for account in [from, to, from] {
        data.extend_from_slice(account);
    }
    data.push(3u8);
    data.extend_from_slice(&d[4..12]);
    Ok(VmCall {
        vm: CallVm::Svm,
        to: crate::svm::spl_adapter::SPL_TOKEN_PROGRAM_ID.to_vec(),
        value: 0,
        data,
    })
}

/// Gas an external Solana transaction executes with. The wallet signs no
/// gas terms, so every validator applies this one limit and the block's base
/// fee rather than values a relayer could choose.
pub const SVM_GAS_LIMIT: u64 = 1_400_000;

impl ExternalSvmTx {
    /// The VM transaction this executes as: the instructions as one atomic
    /// call list from the fee payer, at `nonce`, priced at the block base fee.
    pub fn to_vm_transaction(
        &self,
        nonce: u64,
        base_fee: u128,
        chain_id: u64,
    ) -> Result<VmTransaction, VmError> {
        let payer = self.signers.first().ok_or_else(|| bad("no fee payer"))?;
        let mut data = crate::native::SELECTOR_CONTRACT_CALL.to_vec();
        data.extend_from_slice(&VmCall::encode_list(&self.to_vm_calls()?));
        let mut tx = VmTransaction::new(
            payer.to_vec(),
            Some(payer.to_vec()),
            0,
            data,
            SVM_GAS_LIMIT,
            base_fee,
            nonce,
            VmType::Tenzro,
            chain_id,
        );
        tx.block_base_fee = Some(base_fee);
        Ok(tx)
    }
}

const SVM_ALIAS_PREFIX: &[u8] = b"svm_evm_alias:";

/// The EVM address a Solana account is known by: the last 20 bytes of
/// keccak256 of its Ed25519 public key.
pub fn svm_evm_alias(pubkey: &[u8; 32]) -> [u8; 20] {
    let hash = Keccak256::digest(pubkey);
    let mut out = [0u8; 20];
    out.copy_from_slice(&hash[12..]);
    out
}

/// System storage key of the record for an EVM alias.
pub(crate) fn svm_alias_key(alias: &[u8]) -> Vec<u8> {
    let mut key = SVM_ALIAS_PREFIX.to_vec();
    key.extend_from_slice(alias);
    key
}

/// Records the EVM alias of a Solana account the first time the account
/// signs; later calls leave the record unchanged.
pub fn record_svm_alias(state: &mut dyn VmState, pubkey: &[u8; 32]) {
    let key = svm_alias_key(&svm_evm_alias(pubkey));
    if state
        .get_storage(&crate::native::SYSTEM_ADDRESS, &key)
        .is_none()
    {
        state.set_storage(&crate::native::SYSTEM_ADDRESS, &key, pubkey.to_vec());
    }
}

/// The Solana account an EVM alias was recorded for, if any.
pub fn svm_alias_owner(state: &dyn VmState, alias: &[u8; 20]) -> Option<[u8; 32]> {
    state
        .get_storage(&crate::native::SYSTEM_ADDRESS, &svm_alias_key(alias))?
        .try_into()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The EIP-155 specification example: chain 1, key 0x4646..46.
    #[test]
    fn the_eip155_reference_transaction_recovers_its_sender() {
        let raw = hex(
            "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83",
        );
        let tx = decode_evm_raw(&raw, 1).unwrap();
        assert_eq!(tx.kind, EvmTxKind::Eip155);
        assert_eq!(
            tx.from.to_vec(),
            hex("9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f")
        );
        assert_eq!(tx.nonce, 9);
        assert_eq!(tx.value, 1_000_000_000_000_000_000);
        assert!(
            decode_evm_raw(&raw, 1337).is_err(),
            "replay on another chain id"
        );
    }

    fn address_of(k: &SigningKey) -> [u8; 20] {
        let p = k.verifying_key().to_sec1_point(false);
        let h = keccak(&p.as_bytes()[1..]);
        let mut a = [0u8; 20];
        a.copy_from_slice(&h[12..]);
        a
    }

    /// Signs `fields` as a typed transaction the way a wallet does.
    fn sign_typed(k: &SigningKey, ty: u8, fields: impl Fn(&mut RlpStream), n: usize) -> Vec<u8> {
        let mut s = RlpStream::new_list(n);
        fields(&mut s);
        let mut pre = vec![ty];
        pre.extend_from_slice(&s.out());
        let (sig, rid) = k.sign_prehash_recoverable(&keccak(&pre)).unwrap();
        let b = sig.to_bytes();
        let mut s = RlpStream::new_list(n + 3);
        fields(&mut s);
        s.append(&u64::from(rid.to_byte()));
        s.append(&strip(&b[..32]));
        s.append(&strip(&b[32..]));
        let mut raw = vec![ty];
        raw.extend_from_slice(&s.out());
        raw
    }

    fn strip(b: &[u8]) -> Vec<u8> {
        b.iter().skip_while(|x| **x == 0).copied().collect()
    }

    #[test]
    fn an_eip1559_transaction_from_an_external_key_recovers_and_converts() {
        let k = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let to = [0x11u8; 20];
        let raw = sign_typed(
            &k,
            2,
            |s| {
                s.append(&1337u64)
                    .append(&3u64)
                    .append(&2_000_000_000u64)
                    .append(&50_000_000_000u64);
                s.append(&21_000u64)
                    .append(&to.to_vec())
                    .append(&5u64)
                    .append(&Vec::<u8>::new());
                s.begin_list(0);
            },
            9,
        );
        let tx = decode_evm_raw(&raw, 1337).unwrap();
        assert_eq!(tx.kind, EvmTxKind::DynamicFee);
        assert_eq!(tx.from, address_of(&k));
        assert_eq!(
            tx.effective_gas_price(10_000_000_000).unwrap(),
            12_000_000_000
        );
        assert!(tx.effective_gas_price(60_000_000_000).is_err());
        let vm = tx.to_vm_transaction(1).unwrap();
        assert_eq!(vm.from, address_of(&k).to_vec());
        assert_eq!(vm.nonce, 3);
        let mut tampered = raw.clone();
        let last = tampered.len() - 40;
        tampered[last] ^= 1;
        assert!(
            decode_evm_raw(&tampered, 1337)
                .map(|t| t.from != tx.from)
                .unwrap_or(true)
        );
    }

    #[test]
    fn eip2930_and_eip7702_transactions_recover() {
        let k = SigningKey::from_slice(&[9u8; 32]).unwrap();
        let to = [0x22u8; 20];
        let raw = sign_typed(
            &k,
            1,
            |s| {
                s.append(&1337u64)
                    .append(&0u64)
                    .append(&1_000u64)
                    .append(&30_000u64);
                s.append(&to.to_vec()).append(&0u64).append(&vec![1u8, 2]);
                s.begin_list(1)
                    .begin_list(2)
                    .append(&to.to_vec())
                    .begin_list(1)
                    .append(&vec![0u8; 32]);
            },
            8,
        );
        assert_eq!(decode_evm_raw(&raw, 1337).unwrap().from, address_of(&k));

        let auth = Eip7702Authorization {
            chain_id: U256::from(1337u64),
            delegate_address: to.to_vec(),
            nonce: 1,
            signature: vec![],
        };
        let (asig, arid) = k.sign_prehash_recoverable(&auth.signing_hash()).unwrap();
        let ab = asig.to_bytes();
        let raw = sign_typed(
            &k,
            4,
            |s| {
                s.append(&1337u64)
                    .append(&0u64)
                    .append(&1u64)
                    .append(&2u64)
                    .append(&60_000u64);
                s.append(&to.to_vec())
                    .append(&0u64)
                    .append(&Vec::<u8>::new());
                s.begin_list(0);
                s.begin_list(1)
                    .begin_list(6)
                    .append(&1337u64)
                    .append(&to.to_vec())
                    .append(&1u64)
                    .append(&u64::from(arid.to_byte()))
                    .append(&strip(&ab[..32]))
                    .append(&strip(&ab[32..]));
            },
            10,
        );
        let tx = decode_evm_raw(&raw, 1337).unwrap();
        assert_eq!(tx.kind, EvmTxKind::SetCode);
        assert_eq!(tx.from, address_of(&k));
        assert_eq!(tx.authorizations.len(), 1);
    }

    /// An authorization that cannot apply (y_parity 2, a chain id past 64
    /// bits) is still a valid list entry: the transaction decodes and
    /// carries it, and execution skips it (EIP-7702).
    #[test]
    fn an_unusable_authorization_still_decodes() {
        let k = SigningKey::from_slice(&[9u8; 32]).unwrap();
        let to = [0x22u8; 20];
        let mut wide = vec![1u8];
        wide.extend_from_slice(&[0u8; 8]);
        let raw = sign_typed(
            &k,
            4,
            |s| {
                s.append(&1337u64)
                    .append(&0u64)
                    .append(&1u64)
                    .append(&2u64)
                    .append(&80_000u64);
                s.append(&to.to_vec())
                    .append(&0u64)
                    .append(&Vec::<u8>::new());
                s.begin_list(0);
                s.begin_list(1)
                    .begin_list(6)
                    .append(&wide)
                    .append(&to.to_vec())
                    .append(&0u64)
                    .append(&2u64)
                    .append(&vec![1u8; 32])
                    .append(&vec![1u8; 32]);
            },
            10,
        );
        let tx = decode_evm_raw(&raw, 1337).unwrap();
        assert_eq!(tx.authorizations[0].chain_id, U256::from(1u8) << 64usize);
        assert!(tx.authorizations[0].recovered().authority().is_none());
        assert_eq!(tx.intrinsic_gas(), 21_000 + 25_000);
    }

    #[test]
    fn a_pre_eip155_legacy_signature_is_refused() {
        let mut s = RlpStream::new_list(9);
        s.append(&0u64)
            .append(&1u64)
            .append(&21_000u64)
            .append(&vec![0x33u8; 20])
            .append(&0u64);
        s.append(&Vec::<u8>::new())
            .append(&27u64)
            .append(&vec![1u8; 32])
            .append(&vec![1u8; 32]);
        assert!(decode_evm_raw(&s.out(), 1).is_err());
    }

    fn svm_wire(
        signer: &ed25519_dalek::SigningKey,
        program: [u8; 32],
        ix: &[u8],
        v0: bool,
    ) -> Vec<u8> {
        use ed25519_dalek::Signer;
        let mut msg = Vec::new();
        if v0 {
            msg.push(0x80);
        }
        msg.extend_from_slice(&[1, 0, 1, 2]);
        msg.extend_from_slice(signer.verifying_key().as_bytes());
        msg.extend_from_slice(&program);
        msg.extend_from_slice(&[0xab; 32]);
        msg.extend_from_slice(&[1, 1, 1, 0, ix.len() as u8]);
        msg.extend_from_slice(ix);
        if v0 {
            msg.push(0);
        }
        let mut raw = vec![1];
        raw.extend_from_slice(&signer.sign(&msg).to_bytes());
        raw.extend_from_slice(&msg);
        raw
    }

    #[test]
    fn a_solana_wire_transaction_from_an_external_key_verifies() {
        let k = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]);
        for v0 in [false, true] {
            let raw = svm_wire(&k, [0x44; 32], &[2, 0, 0, 0], v0);
            let tx = decode_svm_wire(&raw).unwrap();
            assert_eq!(tx.signers, vec![*k.verifying_key().as_bytes()]);
            let calls = tx.to_vm_calls().unwrap();
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].to, vec![0x44; 32]);
            assert_eq!(calls[0].data[0], 1);
            let mut bad = raw.clone();
            *bad.last_mut().unwrap() ^= 1;
            assert!(decode_svm_wire(&bad).is_err());
        }
    }

    fn svm_tx(accounts: Vec<[u8; 32]>, data: Vec<u8>) -> ExternalSvmTx {
        ExternalSvmTx {
            signers: vec![[1u8; 32]],
            recent_blockhash: [0u8; 32],
            instructions: vec![SvmInstruction {
                program_id: SYSTEM_PROGRAM_ID,
                accounts,
                data,
            }],
            signature: [0u8; 64],
        }
    }

    #[test]
    fn a_system_transfer_moves_value_from_the_fee_payer() {
        let mut data = 2u32.to_le_bytes().to_vec();
        data.extend_from_slice(&7u64.to_le_bytes());
        let calls = svm_tx(vec![[1u8; 32], [2u8; 32]], data.clone())
            .to_vm_calls()
            .unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0].to,
            crate::svm::spl_adapter::SPL_TOKEN_PROGRAM_ID.to_vec()
        );
        assert_eq!(calls[0].value, 0);
        let mut expected = vec![3u8];
        for a in [[1u8; 32], [2u8; 32], [1u8; 32]] {
            expected.extend_from_slice(&a);
        }
        expected.push(3);
        expected.extend_from_slice(&7u64.to_le_bytes());
        assert_eq!(calls[0].data, expected);

        // From an account that is not the fee payer: refused.
        assert!(
            svm_tx(vec![[3u8; 32], [2u8; 32]], data)
                .to_vm_calls()
                .is_err()
        );
        // Any other System Program instruction: refused, never a silent no-op.
        let mut create = 0u32.to_le_bytes().to_vec();
        create.extend_from_slice(&[0u8; 8]);
        assert!(
            svm_tx(vec![[1u8; 32], [2u8; 32]], create)
                .to_vm_calls()
                .is_err()
        );
    }
}
