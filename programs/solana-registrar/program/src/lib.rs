//! Tenzro registrar: registers an agent in `agent_registry_8004` on behalf
//! of a P-256 key.
//!
//! The P-256 key (a TPM or Secure Enclave key, or a passkey) never signs
//! the Solana transaction. The instruction immediately before `register`
//! must be a secp256r1 signature-verify instruction for exactly one
//! signature, whose key, signature and message all sit inside that
//! instruction. The runtime rejects the transaction if that signature does
//! not verify; this program reads the verified key and message back through
//! the instructions sysvar and checks that the message approves exactly
//! this registration.
//!
//! The approved registration is then carried out by a call to the
//! registry's `register`, signed by two program-derived addresses:
//! - the owner, `["owner", key_id]`, which becomes the agent's owner;
//! - the new Metaplex Core asset, `["asset", key_id, nonce]`.
//!
//! An approval names the cluster it is for by genesis hash; the registrar
//! accepts only the cluster it was built for ([`CLUSTER_GENESIS`], Solana
//! mainnet-beta unless `TENZRO_SVM_CLUSTER_GENESIS` names another at build
//! time).
//!
//! `key_id` is SHA-256 of the compressed P-256 key. Each owner has a nonce
//! account, `["nonce", key_id]`, holding the next nonce it will accept, so an
//! approval registers at most once.
//!
//! Each owner also has a vault, `["vault", key_id]`: a system-owned address
//! with no data that anyone can fund with a plain transfer, and that only
//! this program can spend from, only inside a registration the key approved.
//! The vault pays the nonce account's rent and lends the owner address the
//! rent for the new accounts; whatever the registry does not spend goes back
//! to the vault in the same instruction. The fee payer lends nothing: the
//! vault pays it the rebate the approval names, so any account can send an
//! approved registration at no cost to itself. The vault must keep at least
//! the rent-exempt minimum of an empty account.
//!
//! Instruction data (`register`, tag 0):
//! `tag u8 | mode u8 | nonce u64 | fund_lamports u64 | payer_rebate u64
//! | cluster_genesis [u8; 32] | uri_len u16 | uri`
//! and, for mode 1 (passkey),
//! `| auth_data_len u16 | auth_data | client_data_len u16 | client_data_json`.
//!
//! Accounts: `[payer (signer, w), owner (w), nonce (w), vault (w), asset (w),
//! agent_account (w), collection (w), root_config, registry_config,
//! system_program, mpl_core_program, registry_program, instructions_sysvar]`.

use solana_program::{
    account_info::{AccountInfo, next_account_info},
    entrypoint::ProgramResult,
    hash::hashv,
    instruction::{AccountMeta, Instruction},
    program::invoke_signed,
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    sysvar::{Sysvar, instructions as ix_sysvar},
};
use solana_system_interface::{instruction as system_instruction, program as system_program};

solana_program::declare_id!("TnzroSvmRegistrar11111111111111111111111111");

solana_program::entrypoint!(process_instruction);

include!(concat!(env!("OUT_DIR"), "/cluster.rs"));

/// The secp256r1 signature-verify program.
pub const SECP256R1_PROGRAM_ID: Pubkey =
    solana_program::pubkey!("Secp256r1SigVerify1111111111111111111111111");

const REGISTER_DOMAIN: &[u8] = b"tenzro/svm-registrar/register";
const TAG_REGISTER: u8 = 0;
const MODE_HARDWARE_KEY: u8 = 0;
const MODE_PASSKEY: u8 = 1;
const P256_COMPRESSED_LEN: usize = 33;
const NONCE_ACCOUNT_LEN: usize = 8 + P256_COMPRESSED_LEN;
/// `sha256("global:register")[..8]`, the registry's `register` discriminator.
const REGISTRY_REGISTER: [u8; 8] = [0xd3, 0x7c, 0x43, 0x0f, 0xd3, 0xc2, 0xb2, 0xf0];

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_BE: u8 = 0x08;
const AUTH_DATA_FLAGS: usize = 32;
const AUTH_DATA_MIN_LEN: usize = 37;

/// Why a registration was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum RegistrarError {
    /// No secp256r1 instruction immediately before this one.
    MissingSignatureInstruction = 0,
    /// The instruction before this one is not the secp256r1 program.
    NotSecp256r1 = 1,
    /// The secp256r1 instruction is not one signature over data it holds itself.
    MalformedSignatureInstruction = 2,
    /// The verified message does not approve this registration.
    MessageMismatch = 3,
    /// The owner account is not the address derived from the verified key.
    WrongOwnerAddress = 4,
    /// The asset account is not the address derived from the key and nonce.
    WrongAssetAddress = 5,
    /// The nonce account is not the address derived from the verified key.
    WrongNonceAccount = 6,
    /// The approval is for a nonce other than the one the owner is at.
    NonceMismatch = 7,
    /// The instruction data does not parse.
    BadInstructionData = 8,
    /// The passkey assertion lacks user presence or verification, or is a
    /// synced credential.
    PasskeyFlags = 9,
    /// The passkey assertion is not a `webauthn.get` over this registration.
    PasskeyChallenge = 10,
    /// An account the registrar calls is not the program it must be.
    WrongProgram = 11,
    /// The fee payer did not sign.
    PayerNotSigner = 12,
    /// The approval is for another cluster.
    WrongCluster = 13,
    /// The vault account is not the owner's vault.
    WrongVault = 14,
}

impl From<RegistrarError> for ProgramError {
    fn from(e: RegistrarError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], RegistrarError> {
        if self.0.len() < n {
            return Err(RegistrarError::BadInstructionData);
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }
    fn u8(&mut self) -> Result<u8, RegistrarError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, RegistrarError> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }
    fn u64(&mut self) -> Result<u64, RegistrarError> {
        let mut out = [0u8; 8];
        out.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(out))
    }
    fn prefixed(&mut self) -> Result<&'a [u8], RegistrarError> {
        let n = self.u16()? as usize;
        self.take(n)
    }
}

enum Approval<'a> {
    HardwareKey,
    Passkey {
        auth_data: &'a [u8],
        client_data_json: &'a [u8],
    },
}

struct Register<'a> {
    nonce: u64,
    fund_lamports: u64,
    payer_rebate: u64,
    cluster_genesis: &'a [u8],
    agent_uri: &'a [u8],
    approval: Approval<'a>,
}

fn parse(data: &[u8]) -> Result<Register<'_>, RegistrarError> {
    let mut r = Reader(data);
    if r.u8()? != TAG_REGISTER {
        return Err(RegistrarError::BadInstructionData);
    }
    let mode = r.u8()?;
    let nonce = r.u64()?;
    let fund_lamports = r.u64()?;
    let payer_rebate = r.u64()?;
    let cluster_genesis = r.take(32)?;
    let agent_uri = r.prefixed()?;
    let approval = match mode {
        MODE_HARDWARE_KEY => Approval::HardwareKey,
        MODE_PASSKEY => Approval::Passkey {
            auth_data: r.prefixed()?,
            client_data_json: r.prefixed()?,
        },
        _ => return Err(RegistrarError::BadInstructionData),
    };
    if !r.0.is_empty() {
        return Err(RegistrarError::BadInstructionData);
    }
    Ok(Register {
        nonce,
        fund_lamports,
        payer_rebate,
        cluster_genesis,
        agent_uri,
        approval,
    })
}

/// The key and message of the one signature the preceding secp256r1
/// instruction verified. Every offset must point into that instruction
/// (index `0xFFFF`), so the bytes read here are the bytes that verified.
fn verified_signature(
    sysvar: &AccountInfo,
) -> Result<([u8; P256_COMPRESSED_LEN], Vec<u8>), ProgramError> {
    let current = ix_sysvar::load_current_index_checked(sysvar)? as usize;
    if current == 0 {
        return Err(RegistrarError::MissingSignatureInstruction.into());
    }
    let ix = ix_sysvar::load_instruction_at_checked(current - 1, sysvar)?;
    if ix.program_id != SECP256R1_PROGRAM_ID {
        return Err(RegistrarError::NotSecp256r1.into());
    }
    let malformed = || ProgramError::from(RegistrarError::MalformedSignatureInstruction);
    let d = &ix.data;
    if d.len() < 16 || d[0] != 1 {
        return Err(malformed());
    }
    let field = |i: usize| u16::from_le_bytes([d[2 + 2 * i], d[3 + 2 * i]]) as usize;
    let (sig_off, sig_ix, pk_off, pk_ix, msg_off, msg_len, msg_ix) = (
        field(0),
        field(1),
        field(2),
        field(3),
        field(4),
        field(5),
        field(6),
    );
    let this = u16::MAX as usize;
    if sig_ix != this || pk_ix != this || msg_ix != this {
        return Err(malformed());
    }
    if sig_off.checked_add(64).is_none_or(|end| end > d.len()) {
        return Err(malformed());
    }
    let pk = d
        .get(pk_off..pk_off + P256_COMPRESSED_LEN)
        .ok_or_else(malformed)?;
    let msg = d.get(msg_off..msg_off + msg_len).ok_or_else(malformed)?;
    let mut key = [0u8; P256_COMPRESSED_LEN];
    key.copy_from_slice(pk);
    Ok((key, msg.to_vec()))
}

fn operation_digest(
    cluster_genesis: &[u8],
    registry_program: &Pubkey,
    collection: &Pubkey,
    owner_key: &[u8; P256_COMPRESSED_LEN],
    nonce: u64,
    payer_rebate: u64,
    agent_uri: &[u8],
) -> [u8; 32] {
    hashv(&[
        REGISTER_DOMAIN,
        cluster_genesis,
        id().as_ref(),
        registry_program.as_ref(),
        collection.as_ref(),
        owner_key,
        &nonce.to_le_bytes(),
        &payer_rebate.to_le_bytes(),
        &(agent_uri.len() as u16).to_le_bytes(),
        agent_uri,
    ])
    .to_bytes()
}

const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn base64url(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        let chars = chunk.len() + 1;
        for i in 0..chars {
            out.push(B64URL[(n >> (18 - 6 * i) & 63) as usize]);
        }
    }
    out
}

/// Check that `message` approves `digest`.
fn check_approval(
    approval: &Approval,
    message: &[u8],
    digest: &[u8; 32],
) -> Result<(), RegistrarError> {
    match approval {
        Approval::HardwareKey => {
            if message != digest {
                return Err(RegistrarError::MessageMismatch);
            }
        }
        Approval::Passkey {
            auth_data,
            client_data_json,
        } => {
            if auth_data.len() < AUTH_DATA_MIN_LEN {
                return Err(RegistrarError::BadInstructionData);
            }
            let flags = auth_data[AUTH_DATA_FLAGS];
            if flags & FLAG_UP == 0 || flags & FLAG_UV == 0 || flags & FLAG_BE != 0 {
                return Err(RegistrarError::PasskeyFlags);
            }
            // WebAuthn serializes client data with `type` then `challenge`
            // first, so the prefix pins both.
            let mut prefix = b"{\"type\":\"webauthn.get\",\"challenge\":\"".to_vec();
            prefix.extend_from_slice(&base64url(digest));
            prefix.push(b'"');
            if !client_data_json.starts_with(&prefix) {
                return Err(RegistrarError::PasskeyChallenge);
            }
            let client_hash = hashv(&[client_data_json]).to_bytes();
            if message.len() != auth_data.len() + 32
                || &message[..auth_data.len()] != *auth_data
                || message[auth_data.len()..] != client_hash
            {
                return Err(RegistrarError::MessageMismatch);
            }
        }
    }
    Ok(())
}

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let it = &mut accounts.iter();
    let payer = next_account_info(it)?;
    let owner = next_account_info(it)?;
    let nonce_account = next_account_info(it)?;
    let vault = next_account_info(it)?;
    let asset = next_account_info(it)?;
    let agent_account = next_account_info(it)?;
    let collection = next_account_info(it)?;
    let root_config = next_account_info(it)?;
    let registry_config = next_account_info(it)?;
    let system = next_account_info(it)?;
    let mpl_core = next_account_info(it)?;
    let registry = next_account_info(it)?;
    let sysvar = next_account_info(it)?;

    if !payer.is_signer {
        return Err(RegistrarError::PayerNotSigner.into());
    }
    if *system.key != system_program::ID {
        return Err(RegistrarError::WrongProgram.into());
    }

    let req = parse(data)?;
    if req.cluster_genesis != CLUSTER_GENESIS {
        return Err(RegistrarError::WrongCluster.into());
    }
    let (owner_key, message) = verified_signature(sysvar)?;
    let digest = operation_digest(
        req.cluster_genesis,
        registry.key,
        collection.key,
        &owner_key,
        req.nonce,
        req.payer_rebate,
        req.agent_uri,
    );
    check_approval(&req.approval, &message, &digest)?;

    let key_id = hashv(&[&owner_key]).to_bytes();
    let nonce_le = req.nonce.to_le_bytes();
    let (owner_addr, owner_bump) = Pubkey::find_program_address(&[b"owner", &key_id], program_id);
    if *owner.key != owner_addr {
        return Err(RegistrarError::WrongOwnerAddress.into());
    }
    let (nonce_addr, nonce_bump) = Pubkey::find_program_address(&[b"nonce", &key_id], program_id);
    if *nonce_account.key != nonce_addr {
        return Err(RegistrarError::WrongNonceAccount.into());
    }
    let (vault_addr, vault_bump) = Pubkey::find_program_address(&[b"vault", &key_id], program_id);
    if *vault.key != vault_addr {
        return Err(RegistrarError::WrongVault.into());
    }
    let (asset_addr, asset_bump) =
        Pubkey::find_program_address(&[b"asset", &key_id, &nonce_le], program_id);
    if *asset.key != asset_addr {
        return Err(RegistrarError::WrongAssetAddress.into());
    }
    let owner_seeds: &[&[u8]] = &[b"owner", &key_id, &[owner_bump]];
    let nonce_seeds: &[&[u8]] = &[b"nonce", &key_id, &[nonce_bump]];
    let vault_seeds: &[&[u8]] = &[b"vault", &key_id, &[vault_bump]];
    let asset_seeds: &[&[u8]] = &[b"asset", &key_id, &nonce_le, &[asset_bump]];

    // Consume the nonce. A first registration creates the nonce account;
    // lamports someone sent to the address beforehand do not block that.
    if nonce_account.owner == &system_program::ID && nonce_account.data_is_empty() {
        if req.nonce != 0 {
            return Err(RegistrarError::NonceMismatch.into());
        }
        let need = Rent::get()?.minimum_balance(NONCE_ACCOUNT_LEN);
        let have = nonce_account.lamports();
        if have < need {
            invoke_signed(
                &system_instruction::transfer(vault.key, nonce_account.key, need - have),
                &[vault.clone(), nonce_account.clone(), system.clone()],
                &[vault_seeds],
            )?;
        }
        invoke_signed(
            &system_instruction::allocate(nonce_account.key, NONCE_ACCOUNT_LEN as u64),
            &[nonce_account.clone(), system.clone()],
            &[nonce_seeds],
        )?;
        invoke_signed(
            &system_instruction::assign(nonce_account.key, program_id),
            &[nonce_account.clone(), system.clone()],
            &[nonce_seeds],
        )?;
    } else {
        if nonce_account.owner != program_id || nonce_account.data_len() != NONCE_ACCOUNT_LEN {
            return Err(RegistrarError::WrongNonceAccount.into());
        }
        let stored = nonce_account.try_borrow_data()?;
        let mut next = [0u8; 8];
        next.copy_from_slice(&stored[..8]);
        if u64::from_le_bytes(next) != req.nonce {
            return Err(RegistrarError::NonceMismatch.into());
        }
    }
    {
        let next = req
            .nonce
            .checked_add(1)
            .ok_or(RegistrarError::NonceMismatch)?;
        let mut stored = nonce_account.try_borrow_mut_data()?;
        stored[..8].copy_from_slice(&next.to_le_bytes());
        stored[8..].copy_from_slice(&owner_key);
    }

    if req.fund_lamports > 0 {
        invoke_signed(
            &system_instruction::transfer(vault.key, owner.key, req.fund_lamports),
            &[vault.clone(), owner.clone(), system.clone()],
            &[vault_seeds],
        )?;
    }

    // Metaplex Core creates the asset with `create_account`, which fails on
    // an address that already holds lamports. Anyone can send lamports to
    // the asset address once an approval is public; the registrar signs for
    // that address, so it moves them to the vault and the create goes
    // through.
    let stray = asset.lamports();
    if stray > 0 && asset.owner == &system_program::ID && asset.data_is_empty() {
        invoke_signed(
            &system_instruction::transfer(asset.key, vault.key, stray),
            &[asset.clone(), vault.clone(), system.clone()],
            &[asset_seeds],
        )?;
    }

    let mut register_data = Vec::with_capacity(8 + 4 + req.agent_uri.len());
    register_data.extend_from_slice(&REGISTRY_REGISTER);
    register_data.extend_from_slice(&(req.agent_uri.len() as u32).to_le_bytes());
    register_data.extend_from_slice(req.agent_uri);
    let register = Instruction {
        program_id: *registry.key,
        accounts: vec![
            AccountMeta::new_readonly(*root_config.key, false),
            AccountMeta::new_readonly(*registry_config.key, false),
            AccountMeta::new(*agent_account.key, false),
            AccountMeta::new(*asset.key, true),
            AccountMeta::new(*collection.key, false),
            AccountMeta::new(*owner.key, true),
            AccountMeta::new_readonly(system_program::ID, false),
            AccountMeta::new_readonly(*mpl_core.key, false),
        ],
        data: register_data,
    };
    invoke_signed(
        &register,
        &[
            root_config.clone(),
            registry_config.clone(),
            agent_account.clone(),
            asset.clone(),
            collection.clone(),
            owner.clone(),
            system.clone(),
            mpl_core.clone(),
            registry.clone(),
        ],
        &[owner_seeds, asset_seeds],
    )?;

    // Return what the registry did not spend.
    let left = owner.lamports();
    if left > 0 {
        invoke_signed(
            &system_instruction::transfer(owner.key, vault.key, left),
            &[owner.clone(), vault.clone(), system.clone()],
            &[owner_seeds],
        )?;
    }

    if req.payer_rebate > 0 {
        invoke_signed(
            &system_instruction::transfer(vault.key, payer.key, req.payer_rebate),
            &[vault.clone(), payer.clone(), system.clone()],
            &[vault_seeds],
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_matches_known_vectors() {
        assert_eq!(base64url(b""), b"");
        assert_eq!(base64url(b"f"), b"Zg");
        assert_eq!(base64url(b"fo"), b"Zm8");
        assert_eq!(base64url(b"foo"), b"Zm9v");
        assert_eq!(base64url(&[0xfb, 0xff]), b"-_8");
        assert_eq!(base64url(&[0u8; 32]).len(), 43);
    }

    #[test]
    fn trailing_bytes_are_refused() {
        let mut data = vec![TAG_REGISTER, MODE_HARDWARE_KEY];
        data.extend_from_slice(&0u64.to_le_bytes());
        data.extend_from_slice(&0u64.to_le_bytes());
        data.extend_from_slice(&0u64.to_le_bytes());
        data.extend_from_slice(&[0u8; 32]);
        data.extend_from_slice(&1u16.to_le_bytes());
        data.push(b'x');
        assert!(parse(&data).is_ok());
        data.push(0);
        assert!(matches!(parse(&data), Err(RegistrarError::BadInstructionData)));
    }
}
