//! Transactions for the Tenzro registrar program on Solana.
//!
//! The registrar program registers an agent in the `agent_registry_8004`
//! program on behalf of a P-256 key. The key never signs the Solana
//! transaction. It signs a 32-byte operation digest, the transaction
//! carries that signature in a secp256r1 signature-verify instruction, and
//! the registrar program reads the verified instruction back through the
//! instructions sysvar. The registrar then calls `register` with two
//! program-derived addresses as signers: the owner address (derived from
//! the P-256 key) and the new Metaplex Core asset (derived from the key and
//! the owner's nonce).
//!
//! Every lamport the registration spends comes from the owner's vault,
//! `["vault", key_id]`, a program-derived address only the registrar can
//! move lamports out of, and only for a registration the P-256 key approved.
//! The only Ed25519 signature on the transaction is the fee payer's: any
//! account may send it, lends nothing, and is paid back the rebate the key
//! approved. Anyone may fund a vault with a plain transfer.
//!
//! This file depends only on `sha2` and `curve25519-dalek`. The registrar
//! program's tests compile the same file, so the bytes the node produces
//! are the bytes the program is tested against.

use curve25519_dalek::edwards::CompressedEdwardsY;
use sha2::{Digest, Sha256};

/// A 32-byte Solana address.
pub type Address = [u8; 32];

/// The Tenzro registrar program, `TnzroSvmRegistrar11111111111111111111111111`.
pub const REGISTRAR_PROGRAM_ID: Address = [
    0x06, 0xdd, 0x1c, 0x53, 0x49, 0x9e, 0xce, 0xef, 0xa9, 0x65, 0x74, 0x0f, 0x44, 0x20, 0x44, 0xc4,
    0x02, 0x9c, 0x38, 0x31, 0xf1, 0x4c, 0x11, 0xae, 0x14, 0x45, 0xc1, 0xd2, 0x7c, 0x00, 0x00, 0x00,
];

/// The secp256r1 signature-verify program,
/// `Secp256r1SigVerify1111111111111111111111111`.
pub const SECP256R1_PROGRAM_ID: Address = [
    0x06, 0x92, 0x0d, 0xec, 0x2f, 0xea, 0x71, 0xb5, 0xb7, 0x23, 0x81, 0x4d, 0x74, 0x2d, 0xa9, 0x03,
    0x1c, 0x83, 0xe7, 0x5f, 0xdb, 0x79, 0x5d, 0x56, 0x8e, 0x75, 0x47, 0x80, 0x20, 0x00, 0x00, 0x00,
];

/// The instructions sysvar, `Sysvar1nstructions1111111111111111111111111`.
pub const INSTRUCTIONS_SYSVAR_ID: Address = [
    0x06, 0xa7, 0xd5, 0x17, 0x18, 0x7b, 0xd1, 0x66, 0x35, 0xda, 0xd4, 0x04, 0x55, 0xfd, 0xc2, 0xc0,
    0xc1, 0x24, 0xc6, 0x8f, 0x21, 0x56, 0x75, 0xa5, 0xdb, 0xba, 0xcb, 0x5f, 0x08, 0x00, 0x00, 0x00,
];

/// The System Program.
pub const SYSTEM_PROGRAM_ID: Address = [0u8; 32];

/// Metaplex Core, `CoREENxT6tW1HoK8ypY1SxRMZTcVPm7R94rH4PZNhX7d`.
pub const MPL_CORE_PROGRAM_ID: Address = [
    0xaf, 0x54, 0xab, 0x10, 0xbd, 0x97, 0xa5, 0x42, 0xa0, 0x9e, 0xf7, 0xb3, 0x98, 0x89, 0xdd, 0x0c,
    0xd3, 0x94, 0xa4, 0xcc, 0xe9, 0xdf, 0xa6, 0xcd, 0xc9, 0x7e, 0xbe, 0x2d, 0x23, 0x5b, 0xa7, 0x48,
];

/// Genesis hash of Solana mainnet-beta,
/// `5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d`. An approval names the
/// cluster it is for; the registrar refuses one for any other cluster.
pub const MAINNET_BETA_GENESIS_HASH: [u8; 32] = [
    0x45, 0x29, 0x69, 0x98, 0xa6, 0xf8, 0xe2, 0xa7, 0x84, 0xdb, 0x5d, 0x9f, 0x95, 0xe1, 0x8f, 0xc2,
    0x3f, 0x70, 0x44, 0x1a, 0x10, 0x39, 0x44, 0x68, 0x01, 0x08, 0x98, 0x79, 0xb0, 0x8c, 0x7e, 0xf0,
];

/// Domain separation for the operation digest.
pub const REGISTER_DOMAIN: &[u8] = b"tenzro/svm-registrar/register";

/// Registrar instruction tag for `register`.
pub const TAG_REGISTER: u8 = 0;

/// The secp256r1 message is the operation digest itself (a TPM or Secure
/// Enclave key).
pub const MODE_HARDWARE_KEY: u8 = 0;

/// The secp256r1 message is `authenticatorData || SHA-256(clientDataJSON)`
/// from a WebAuthn assertion whose challenge is the operation digest.
pub const MODE_PASSKEY: u8 = 1;

/// Length of a SEC1 compressed P-256 key.
pub const P256_COMPRESSED_LEN: usize = 33;

/// The P-256 group order `n`.
const P256_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

/// `n / 2`, the largest `s` the secp256r1 program accepts.
const P256_HALF_ORDER: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
];

/// Solana's legacy transaction size limit.
pub const MAX_TRANSACTION_LEN: usize = 1232;

/// Why a registration could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistrarError {
    /// The public key is not an uncompressed or compressed SEC1 P-256 key.
    BadPublicKey,
    /// The signature is not 64 bytes of `r || s`.
    BadSignature,
    /// The agent URI is longer than a `u16` length prefix can carry.
    UriTooLong,
    /// The transaction exceeds Solana's size limit.
    TransactionTooLarge(usize),
}

impl std::fmt::Display for RegistrarError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadPublicKey => write!(f, "not a SEC1 P-256 public key"),
            Self::BadSignature => write!(f, "not a 64-byte P-256 signature"),
            Self::UriTooLong => write!(f, "agent URI too long"),
            Self::TransactionTooLarge(n) => {
                write!(
                    f,
                    "transaction is {n} bytes, over the {MAX_TRANSACTION_LEN}-byte limit"
                )
            }
        }
    }
}

impl std::error::Error for RegistrarError {}

/// SEC1 compressed form of a P-256 public key. Accepts the 65-byte
/// uncompressed form (`0x04 || x || y`) or an already compressed key.
pub fn compress_p256(sec1: &[u8]) -> Result<[u8; P256_COMPRESSED_LEN], RegistrarError> {
    let mut out = [0u8; P256_COMPRESSED_LEN];
    match sec1 {
        [0x04, rest @ ..] if rest.len() == 64 => {
            out[0] = if rest[63] & 1 == 1 { 0x03 } else { 0x02 };
            out[1..].copy_from_slice(&rest[..32]);
            Ok(out)
        }
        [0x02 | 0x03, rest @ ..] if rest.len() == 32 => {
            out.copy_from_slice(sec1);
            Ok(out)
        }
        _ => Err(RegistrarError::BadPublicKey),
    }
}

/// The low-S form of a raw `r || s` P-256 signature. `(r, s)` and
/// `(r, n - s)` verify alike; the secp256r1 program accepts only
/// `s <= n / 2`, and hardware returns either.
pub fn low_s(signature: &[u8]) -> Result<[u8; 64], RegistrarError> {
    let sig: [u8; 64] = signature
        .try_into()
        .map_err(|_| RegistrarError::BadSignature)?;
    let mut s = [0u8; 32];
    s.copy_from_slice(&sig[32..]);
    if s <= P256_HALF_ORDER {
        return Ok(sig);
    }
    // n - s, big-endian with borrow. s < n for any valid signature, so the
    // result is in (0, n / 2].
    let mut out = sig;
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let mut d = P256_ORDER[i] as i16 - s[i] as i16 - borrow;
        borrow = if d < 0 {
            d += 256;
            1
        } else {
            0
        };
        out[32 + i] = d as u8;
    }
    Ok(out)
}

/// The identifier every registrar address is derived from:
/// SHA-256 of the compressed P-256 key.
pub fn key_id(owner_key: &[u8; P256_COMPRESSED_LEN]) -> [u8; 32] {
    Sha256::digest(owner_key).into()
}

/// Solana's `find_program_address`: the first bump, counting down from
/// 255, whose derived address is off the Ed25519 curve.
pub fn find_program_address(seeds: &[&[u8]], program_id: &Address) -> (Address, u8) {
    for bump in (0..=255u8).rev() {
        let mut h = Sha256::new();
        for seed in seeds {
            h.update(seed);
        }
        h.update([bump]);
        h.update(program_id);
        h.update(b"ProgramDerivedAddress");
        let candidate: Address = h.finalize().into();
        if CompressedEdwardsY(candidate).decompress().is_none() {
            return (candidate, bump);
        }
    }
    unreachable!("a program address exists for every seed set with overwhelming probability")
}

/// Owner address: `["owner", key_id]` under the registrar.
pub fn owner_address(key_id: &[u8; 32]) -> (Address, u8) {
    find_program_address(&[b"owner", key_id], &REGISTRAR_PROGRAM_ID)
}

/// Nonce account: `["nonce", key_id]` under the registrar.
pub fn nonce_address(key_id: &[u8; 32]) -> (Address, u8) {
    find_program_address(&[b"nonce", key_id], &REGISTRAR_PROGRAM_ID)
}

/// Vault: `["vault", key_id]` under the registrar. It holds the lamports
/// the owner's registrations spend and is system-owned with no data, so it
/// must keep at least the rent-exempt minimum for an empty account.
pub fn vault_address(key_id: &[u8; 32]) -> (Address, u8) {
    find_program_address(&[b"vault", key_id], &REGISTRAR_PROGRAM_ID)
}

/// Asset address for the owner's `nonce`-th registration:
/// `["asset", key_id, nonce_le]` under the registrar.
pub fn asset_address(key_id: &[u8; 32], nonce: u64) -> (Address, u8) {
    find_program_address(
        &[b"asset", key_id, &nonce.to_le_bytes()],
        &REGISTRAR_PROGRAM_ID,
    )
}

/// The registry's accounts for a `register` of `asset` into `collection`.
pub struct RegistryAccounts {
    pub root_config: Address,
    pub registry_config: Address,
    pub agent_account: Address,
}

/// Derive the `agent_registry_8004` accounts `register` needs.
pub fn registry_accounts(
    registry_program: &Address,
    collection: &Address,
    asset: &Address,
) -> RegistryAccounts {
    RegistryAccounts {
        root_config: find_program_address(&[b"root_config"], registry_program).0,
        registry_config: find_program_address(&[b"registry_config", collection], registry_program)
            .0,
        agent_account: find_program_address(&[b"agent", asset], registry_program).0,
    }
}

/// What the owner's key approves: registering `agent_uri` as the owner's
/// `nonce`-th agent in `collection` of `registry_program`, through this
/// registrar, on the cluster with genesis hash `cluster_genesis`, and paying
/// whoever sends it `payer_rebate` lamports from the owner's vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterOperation {
    pub cluster_genesis: [u8; 32],
    pub registry_program: Address,
    pub collection: Address,
    pub owner_key: [u8; P256_COMPRESSED_LEN],
    pub nonce: u64,
    pub payer_rebate: u64,
    pub agent_uri: String,
}

impl RegisterOperation {
    /// SHA-256 over the domain, the cluster genesis hash, the registrar,
    /// the registry, the collection, the owner key, the nonce, the payer
    /// rebate and the length-prefixed URI.
    pub fn digest(&self) -> Result<[u8; 32], RegistrarError> {
        let uri_len: u16 = self
            .agent_uri
            .len()
            .try_into()
            .map_err(|_| RegistrarError::UriTooLong)?;
        let mut h = Sha256::new();
        h.update(REGISTER_DOMAIN);
        h.update(self.cluster_genesis);
        h.update(REGISTRAR_PROGRAM_ID);
        h.update(self.registry_program);
        h.update(self.collection);
        h.update(self.owner_key);
        h.update(self.nonce.to_le_bytes());
        h.update(self.payer_rebate.to_le_bytes());
        h.update(uri_len.to_le_bytes());
        h.update(self.agent_uri.as_bytes());
        Ok(h.finalize().into())
    }
}

/// secp256r1 signature-verify instruction data for one signature, with
/// every offset pointing into this instruction (index `0xFFFF`).
pub fn secp256r1_instruction_data(
    signature: &[u8; 64],
    owner_key: &[u8; P256_COMPRESSED_LEN],
    message: &[u8],
) -> Vec<u8> {
    const HEADER: usize = 2 + 14;
    let pk_off = HEADER;
    let sig_off = pk_off + P256_COMPRESSED_LEN;
    let msg_off = sig_off + 64;
    let mut data = Vec::with_capacity(msg_off + message.len());
    data.push(1); // one signature
    data.push(0); // padding
    for field in [
        sig_off as u16,
        u16::MAX,
        pk_off as u16,
        u16::MAX,
        msg_off as u16,
        message.len() as u16,
        u16::MAX,
    ] {
        data.extend_from_slice(&field.to_le_bytes());
    }
    data.extend_from_slice(owner_key);
    data.extend_from_slice(signature);
    data.extend_from_slice(message);
    data
}

/// Registrar `register` instruction data for a hardware-key signature.
pub fn register_instruction_data(
    nonce: u64,
    fund_lamports: u64,
    payer_rebate: u64,
    cluster_genesis: &[u8; 32],
    agent_uri: &str,
) -> Vec<u8> {
    let mut data = Vec::with_capacity(1 + 1 + 8 + 8 + 8 + 32 + 2 + agent_uri.len());
    data.push(TAG_REGISTER);
    data.push(MODE_HARDWARE_KEY);
    data.extend_from_slice(&nonce.to_le_bytes());
    data.extend_from_slice(&fund_lamports.to_le_bytes());
    data.extend_from_slice(&payer_rebate.to_le_bytes());
    data.extend_from_slice(cluster_genesis);
    data.extend_from_slice(&(agent_uri.len() as u16).to_le_bytes());
    data.extend_from_slice(agent_uri.as_bytes());
    data
}

/// A registration the owner's key has approved, ready for any fee payer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRegistration {
    pub operation: RegisterOperation,
    /// Low-S `r || s` over SHA-256 of the operation digest.
    pub signature: [u8; 64],
}

/// Lamports the vault lends the owner address for the two new accounts'
/// rent. Whatever the registry does not spend goes back to the vault in the
/// same instruction.
pub const DEFAULT_FUND_LAMPORTS: u64 = 20_000_000;

fn compact_u16(out: &mut Vec<u8>, mut v: u16) {
    loop {
        let mut byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return;
        }
        byte |= 0x80;
        out.push(byte);
    }
}

impl SignedRegistration {
    /// The account list of the registration transaction, in message order.
    /// Index 0 is the fee payer, the only signer.
    pub fn account_keys(&self, fee_payer: &Address) -> Vec<Address> {
        let kid = key_id(&self.operation.owner_key);
        let asset = asset_address(&kid, self.operation.nonce).0;
        let reg = registry_accounts(
            &self.operation.registry_program,
            &self.operation.collection,
            &asset,
        );
        vec![
            // signer, writable
            *fee_payer,
            // writable
            owner_address(&kid).0,
            nonce_address(&kid).0,
            vault_address(&kid).0,
            asset,
            reg.agent_account,
            self.operation.collection,
            // read-only
            reg.root_config,
            reg.registry_config,
            SYSTEM_PROGRAM_ID,
            MPL_CORE_PROGRAM_ID,
            self.operation.registry_program,
            INSTRUCTIONS_SYSVAR_ID,
            SECP256R1_PROGRAM_ID,
            REGISTRAR_PROGRAM_ID,
        ]
    }

    /// The serialized legacy message the fee payer signs.
    pub fn message(
        &self,
        fee_payer: &Address,
        recent_blockhash: &[u8; 32],
        fund_lamports: u64,
    ) -> Result<Vec<u8>, RegistrarError> {
        let keys = self.account_keys(fee_payer);
        let digest = self.operation.digest()?;
        let secp = secp256r1_instruction_data(&self.signature, &self.operation.owner_key, &digest);
        let reg = register_instruction_data(
            self.operation.nonce,
            fund_lamports,
            self.operation.payer_rebate,
            &self.operation.cluster_genesis,
            &self.operation.agent_uri,
        );
        let mut m = Vec::with_capacity(MAX_TRANSACTION_LEN);
        // 1 required signature, 0 read-only signed, 8 read-only unsigned.
        m.extend_from_slice(&[1, 0, 8]);
        compact_u16(&mut m, keys.len() as u16);
        for k in &keys {
            m.extend_from_slice(k);
        }
        m.extend_from_slice(recent_blockhash);
        compact_u16(&mut m, 2);
        // secp256r1 verify: program index 13, no accounts.
        m.push(13);
        compact_u16(&mut m, 0);
        compact_u16(&mut m, secp.len() as u16);
        m.extend_from_slice(&secp);
        // registrar register: program index 14, accounts 0..=12.
        m.push(14);
        compact_u16(&mut m, 13);
        m.extend(0u8..13);
        compact_u16(&mut m, reg.len() as u16);
        m.extend_from_slice(&reg);
        Ok(m)
    }

    /// The transaction with an empty fee-payer signature slot: the payer
    /// signs [`Self::message`] and writes its signature over bytes 1..65.
    pub fn unsigned_transaction(
        &self,
        fee_payer: &Address,
        recent_blockhash: &[u8; 32],
        fund_lamports: u64,
    ) -> Result<Vec<u8>, RegistrarError> {
        let message = self.message(fee_payer, recent_blockhash, fund_lamports)?;
        let mut tx = Vec::with_capacity(1 + 64 + message.len());
        compact_u16(&mut tx, 1);
        tx.extend_from_slice(&[0u8; 64]);
        tx.extend_from_slice(&message);
        if tx.len() > MAX_TRANSACTION_LEN {
            return Err(RegistrarError::TransactionTooLarge(tx.len()));
        }
        Ok(tx)
    }
}

#[cfg(test)]
mod registrar_tests {
    use super::*;

    #[test]
    fn low_s_leaves_a_low_signature_alone_and_flips_a_high_one() {
        let mut low = [0u8; 64];
        low[63] = 5;
        assert_eq!(low_s(&low).unwrap(), low);

        let mut high = [0u8; 64];
        high[32..].copy_from_slice(&P256_ORDER);
        high[63] -= 5; // s = n - 5
        let flipped = low_s(&high).unwrap();
        let mut expect = [0u8; 32];
        expect[31] = 5;
        assert_eq!(&flipped[32..], &expect);
        assert_eq!(&flipped[..32], &high[..32]);
    }

    #[test]
    fn compression_takes_the_parity_of_y() {
        let mut even = [0u8; 65];
        even[0] = 0x04;
        even[1] = 0xaa;
        even[64] = 0x10;
        assert_eq!(compress_p256(&even).unwrap()[0], 0x02);
        let mut odd = even;
        odd[64] = 0x11;
        let c = compress_p256(&odd).unwrap();
        assert_eq!(c[0], 0x03);
        assert_eq!(c[1], 0xaa);
        assert_eq!(compress_p256(&c).unwrap(), c);
        assert_eq!(
            compress_p256(&[0x04; 10]),
            Err(RegistrarError::BadPublicKey)
        );
    }

    #[test]
    fn the_digest_binds_every_field() {
        let base = RegisterOperation {
            cluster_genesis: MAINNET_BETA_GENESIS_HASH,
            registry_program: [1; 32],
            collection: [2; 32],
            owner_key: [3; 33],
            nonce: 7,
            payer_rebate: 10_000,
            agent_uri: "did:tenzro:machine:a".into(),
        };
        let d = base.digest().unwrap();
        let mut v = base.clone();
        v.cluster_genesis = [9; 32];
        assert_ne!(v.digest().unwrap(), d);
        let mut v = base.clone();
        v.registry_program = [9; 32];
        assert_ne!(v.digest().unwrap(), d);
        let mut v = base.clone();
        v.collection = [9; 32];
        assert_ne!(v.digest().unwrap(), d);
        let mut v = base.clone();
        v.owner_key = [9; 33];
        assert_ne!(v.digest().unwrap(), d);
        let mut v = base.clone();
        v.nonce = 8;
        assert_ne!(v.digest().unwrap(), d);
        let mut v = base.clone();
        v.payer_rebate = 10_001;
        assert_ne!(v.digest().unwrap(), d);
        let mut v = base.clone();
        v.agent_uri.push('x');
        assert_ne!(v.digest().unwrap(), d);
    }

    #[test]
    fn program_addresses_are_off_curve() {
        let (addr, _) = owner_address(&[4; 32]);
        assert!(CompressedEdwardsY(addr).decompress().is_none());
        let (vault, _) = vault_address(&[4; 32]);
        assert!(CompressedEdwardsY(vault).decompress().is_none());
        assert_ne!(vault, addr);
    }

    #[test]
    fn a_registration_fits_one_transaction() {
        let reg = SignedRegistration {
            operation: RegisterOperation {
                cluster_genesis: MAINNET_BETA_GENESIS_HASH,
                registry_program: [1; 32],
                collection: [2; 32],
                owner_key: [3; 33],
                nonce: 0,
                payer_rebate: 10_000,
                agent_uri: "x".repeat(250),
            },
            signature: [5; 64],
        };
        let tx = reg
            .unsigned_transaction(&[6; 32], &[7; 32], DEFAULT_FUND_LAMPORTS)
            .expect("a 250-byte URI fits");
        assert_eq!(tx[0], 1);
        assert_eq!(&tx[1..65], &[0u8; 64]);
        assert_eq!(&tx[65..68], &[1, 0, 8]);
    }
}
