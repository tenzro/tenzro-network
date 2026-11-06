//! The registrar program against the real `agent_registry_8004` and
//! Metaplex Core programs, in LiteSVM with the secp256r1 program enabled.
//!
//! The three program binaries come from the environment:
//! `REGISTRAR_SO`, `REGISTRY_SO` (agent_registry_8004 built from
//! `vendor/erc8004-solana`) and `MPL_CORE_SO`.
//!
//! The P-256 keys here are software keys standing in for a TPM, a Secure
//! Enclave or a passkey authenticator; only the signature they produce
//! matters to the program.

#[path = "../../../../crates/tenzro-identity/src/erc8004_svm_registrar.rs"]
mod registrar;

use base64::Engine;
use litesvm::LiteSVM;
use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
use sha2::{Digest, Sha256};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_instruction_error::InstructionError;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_transaction::versioned::VersionedTransaction;
use solana_transaction_error::TransactionError;

use registrar::{
    RegisterOperation, SignedRegistration, compress_p256, low_s, key_id, owner_address,
    nonce_address, asset_address, vault_address,
};

/// The registry's program id as declared by the vendored source.
const REGISTRY_ID: &str = "8oo4dC4JvBLwy5tGgiH3WwK4B9PWxL9Z4XjA2jzkQMbQ";

// Registrar error codes (`RegistrarError` in the program).
const MISSING_SIGNATURE_INSTRUCTION: u32 = 0;
const NOT_SECP256R1: u32 = 1;
const MALFORMED_SIGNATURE_INSTRUCTION: u32 = 2;
const MESSAGE_MISMATCH: u32 = 3;
const WRONG_OWNER_ADDRESS: u32 = 4;
const NONCE_MISMATCH: u32 = 7;
const PASSKEY_FLAGS: u32 = 9;
const PASSKEY_CHALLENGE: u32 = 10;
const WRONG_CLUSTER: u32 = 13;
const WRONG_VAULT: u32 = 14;

/// What each approval here pays its sender: the fee for the payer's
/// signature and the P-256 signature the secp256r1 program verifies.
const REBATE: u64 = 2 * 5_000;

/// What a test tops an owner's vault up to before sending.
const VAULT_FUNDING: u64 = 1_000_000_000;

fn addr(bytes: [u8; 32]) -> Address {
    Address::new_from_array(bytes)
}

fn so(var: &str) -> Vec<u8> {
    let path = std::env::var(var).unwrap_or_else(|_| panic!("{var} must name the program binary"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{var}={path}: {e}"))
}

fn anchor_discriminator(name: &str) -> [u8; 8] {
    let h = Sha256::digest(format!("global:{name}").as_bytes());
    h[..8].try_into().unwrap()
}

struct Env {
    svm: LiteSVM,
    registry: Address,
    collection: Address,
    /// Top up the owner's vault before each send.
    fund_vaults: bool,
}

impl Env {
    fn new() -> Self {
        let mut svm = LiteSVM::new();
        let registry: Address = REGISTRY_ID.parse().unwrap();
        svm.add_program(addr(registrar::REGISTRAR_PROGRAM_ID), &so("REGISTRAR_SO"))
            .unwrap();
        svm.add_program(registry, &so("REGISTRY_SO")).unwrap();
        svm.add_program(addr(registrar::MPL_CORE_PROGRAM_ID), &so("MPL_CORE_SO"))
            .unwrap();

        // `initialize` may only be called by the registry's upgrade
        // authority, so give the loaded program one.
        let authority = Keypair::new();
        svm.airdrop(&authority.pubkey(), 10_000_000_000).unwrap();
        let loader = solana_sdk_ids_upgradeable();
        let (program_data, _) = Address::find_program_address(&[registry.as_ref()], &loader);
        let mut pd = svm.get_account(&program_data).unwrap();
        pd.data[12] = 1;
        pd.data[13..45].copy_from_slice(authority.pubkey().as_ref());
        svm.set_account(program_data, pd).unwrap();

        let collection = Keypair::new();
        let (root_config, _) = Address::find_program_address(&[b"root_config"], &registry);
        let (registry_config, _) = Address::find_program_address(
            &[b"registry_config", collection.pubkey().as_ref()],
            &registry,
        );
        let init = Instruction {
            program_id: registry,
            accounts: vec![
                AccountMeta::new(root_config, false),
                AccountMeta::new(registry_config, false),
                AccountMeta::new(collection.pubkey(), true),
                AccountMeta::new(authority.pubkey(), true),
                AccountMeta::new_readonly(program_data, false),
                AccountMeta::new_readonly(addr(registrar::SYSTEM_PROGRAM_ID), false),
                AccountMeta::new_readonly(addr(registrar::MPL_CORE_PROGRAM_ID), false),
            ],
            data: anchor_discriminator("initialize").to_vec(),
        };
        let bh = svm.latest_blockhash();
        let tx = Transaction::new(
            &[&authority, &collection],
            Message::new_with_blockhash(&[init], Some(&authority.pubkey()), &bh),
            bh,
        );
        svm.send_transaction(tx).expect("registry initializes");
        Env {
            svm,
            registry,
            collection: collection.pubkey(),
            fund_vaults: true,
        }
    }

    fn vault(owner_key: &[u8; 33]) -> Address {
        addr(vault_address(&key_id(owner_key)).0)
    }

    /// Bring the owner's vault up to [`VAULT_FUNDING`].
    fn top_up(&mut self, owner_key: &[u8; 33]) {
        if !self.fund_vaults {
            return;
        }
        let vault = Self::vault(owner_key);
        let have = self.svm.get_balance(&vault).unwrap_or(0);
        if have < VAULT_FUNDING {
            self.svm.airdrop(&vault, VAULT_FUNDING - have).unwrap();
        }
    }

    fn payer(&mut self) -> Keypair {
        let payer = Keypair::new();
        self.svm.airdrop(&payer.pubkey(), 1_000_000_000).unwrap();
        payer
    }

    fn operation(&self, key: &SigningKey, nonce: u64, uri: &str) -> RegisterOperation {
        RegisterOperation {
            cluster_genesis: registrar::MAINNET_BETA_GENESIS_HASH,
            registry_program: self.registry.to_bytes(),
            collection: self.collection.to_bytes(),
            owner_key: owner_key(key),
            nonce,
            payer_rebate: REBATE,
            agent_uri: uri.to_string(),
        }
    }

    /// Send the transaction exactly as the node builds it: the shared
    /// builder's bytes, with the payer's signature written into the slot.
    fn send_built(&mut self, reg: &SignedRegistration, payer: &Keypair) -> Result<(), TransactionError> {
        self.top_up(&reg.operation.owner_key);
        let bh = self.svm.latest_blockhash().to_bytes();
        let fee_payer = payer.pubkey().to_bytes();
        let mut tx = reg
            .unsigned_transaction(&fee_payer, &bh, registrar::DEFAULT_FUND_LAMPORTS)
            .unwrap();
        let message = reg
            .message(&fee_payer, &bh, registrar::DEFAULT_FUND_LAMPORTS)
            .unwrap();
        let sig = payer.sign_message(&message);
        tx[1..65].copy_from_slice(sig.as_ref());
        let tx: VersionedTransaction = bincode::deserialize(&tx).expect("the node's bytes parse");
        self.svm.send_transaction(tx).map(|_| ()).map_err(|e| e.err)
    }

    fn send(&mut self, payer: &Keypair, ixs: &[Instruction]) -> Result<(), TransactionError> {
        let bh = self.svm.latest_blockhash();
        let tx = Transaction::new(
            &[payer],
            Message::new_with_blockhash(ixs, Some(&payer.pubkey()), &bh),
            bh,
        );
        self.svm.send_transaction(tx).map(|_| ()).map_err(|e| e.err)
    }
}

fn solana_sdk_ids_upgradeable() -> Address {
    "BPFLoaderUpgradeab1e11111111111111111111111".parse().unwrap()
}

fn signing_key(seed: u8) -> SigningKey {
    let mut bytes = [0u8; 32];
    bytes[31] = seed;
    bytes[0] = 0x11;
    SigningKey::from_bytes(&bytes.into()).unwrap()
}

fn owner_key(key: &SigningKey) -> [u8; 33] {
    let point = key.verifying_key().to_encoded_point(false);
    compress_p256(point.as_bytes()).unwrap()
}

/// ECDSA-P256 over SHA-256(`message`), low-S, as a hardware key returns it
/// after normalization.
fn p256_sign(key: &SigningKey, message: &[u8]) -> [u8; 64] {
    let sig: Signature = key.sign(message);
    low_s(&sig.to_bytes()).unwrap()
}

fn sign(key: &SigningKey, op: RegisterOperation) -> SignedRegistration {
    let signature = p256_sign(key, &op.digest().unwrap());
    SignedRegistration {
        operation: op,
        signature,
    }
}

fn secp_ix(signature: &[u8; 64], key: &[u8; 33], message: &[u8]) -> Instruction {
    Instruction {
        program_id: addr(registrar::SECP256R1_PROGRAM_ID),
        accounts: vec![],
        data: registrar::secp256r1_instruction_data(signature, key, message),
    }
}

/// The registrar instruction for `reg`, with its account list.
fn register_ix(reg: &SignedRegistration, payer: &Keypair, data: Vec<u8>) -> Instruction {
    let keys = reg.account_keys(&payer.pubkey().to_bytes());
    let mut accounts = vec![AccountMeta::new(addr(keys[0]), true)];
    for k in &keys[1..7] {
        accounts.push(AccountMeta::new(addr(*k), false));
    }
    for k in &keys[7..13] {
        accounts.push(AccountMeta::new_readonly(addr(*k), false));
    }
    Instruction {
        program_id: addr(registrar::REGISTRAR_PROGRAM_ID),
        accounts,
        data,
    }
}

fn hardware_data(reg: &SignedRegistration) -> Vec<u8> {
    registrar::register_instruction_data(
        reg.operation.nonce,
        registrar::DEFAULT_FUND_LAMPORTS,
        reg.operation.payer_rebate,
        &reg.operation.cluster_genesis,
        &reg.operation.agent_uri,
    )
}

fn refused(result: Result<(), TransactionError>, code: u32) {
    assert_eq!(
        result,
        Err(TransactionError::InstructionError(1, InstructionError::Custom(code))),
    );
}

fn refused_by_signature_check(result: Result<(), TransactionError>) {
    match result {
        Err(TransactionError::InstructionError(0, _)) => {}
        other => panic!("expected the secp256r1 instruction to fail, got {other:?}"),
    }
}

#[test]
fn a_hardware_key_registers_an_agent_paid_from_its_vault_and_the_sender_is_paid_back() {
    let mut env = Env::new();
    let key = signing_key(1);
    let payer = env.payer();
    let before = env.svm.get_balance(&payer.pubkey()).unwrap();

    let reg = sign(&key, env.operation(&key, 0, "did:tenzro:machine:alpha"));
    env.send_built(&reg, &payer).expect("registers");

    let kid = key_id(&reg.operation.owner_key);
    let owner = addr(owner_address(&kid).0);
    let asset = addr(asset_address(&kid, 0).0);
    let (agent, _) = Address::find_program_address(&[b"agent", asset.as_ref()], &env.registry);

    let asset_acc = env.svm.get_account(&asset).expect("asset created");
    assert_eq!(asset_acc.owner, addr(registrar::MPL_CORE_PROGRAM_ID));
    assert_eq!(&asset_acc.data[1..33], owner.as_ref(), "the owner address owns the asset");

    let agent_acc = env.svm.get_account(&agent).expect("agent account created");
    assert_eq!(agent_acc.owner, env.registry);
    assert_eq!(&agent_acc.data[72..104], owner.as_ref());
    assert_eq!(&agent_acc.data[104..136], asset.as_ref());

    let nonce_acc = env.svm.get_account(&addr(nonce_address(&kid).0)).unwrap();
    assert_eq!(nonce_acc.owner, addr(registrar::REGISTRAR_PROGRAM_ID));
    assert_eq!(&nonce_acc.data[..8], &1u64.to_le_bytes());
    assert_eq!(&nonce_acc.data[8..], &reg.operation.owner_key);

    // The owner address keeps nothing. The vault paid exactly the rent of
    // the three new accounts and the approved rebate; the sender paid the
    // fee for two signatures (its own and the P-256 signature the secp256r1
    // program verified) and got the rebate, so it is out nothing.
    assert_eq!(env.svm.get_balance(&owner).unwrap_or(0), 0);
    let rent = asset_acc.lamports + agent_acc.lamports + nonce_acc.lamports;
    let vault = Env::vault(&reg.operation.owner_key);
    assert_eq!(
        env.svm.get_balance(&vault).unwrap(),
        VAULT_FUNDING - rent - REBATE
    );
    let after = env.svm.get_balance(&payer.pubkey()).unwrap();
    assert_eq!(after, before - 2 * 5_000 + REBATE);
}

#[test]
fn an_empty_vault_pays_nothing_and_leaves_the_approval_usable() {
    let mut env = Env::new();
    let key = signing_key(21);
    let payer = env.payer();
    let reg = sign(&key, env.operation(&key, 0, "did:tenzro:machine:unfunded"));
    env.fund_vaults = false;
    assert!(env.send_built(&reg, &payer).is_err(), "nothing pays for it");
    let kid = key_id(&reg.operation.owner_key);
    assert!(
        env.svm.get_account(&addr(nonce_address(&kid).0)).is_none(),
        "the nonce was not consumed"
    );
    env.fund_vaults = true;
    // A fresh blockhash, so the resent transaction is not a duplicate.
    env.svm.expire_blockhash();
    env.send_built(&reg, &payer)
        .expect("the same approval registers once the vault is funded");
}

#[test]
fn a_rebate_other_than_the_approved_one_is_refused() {
    let mut env = Env::new();
    let key = signing_key(22);
    let payer = env.payer();
    let reg = sign(&key, env.operation(&key, 0, "did:tenzro:machine:rebate"));
    env.top_up(&reg.operation.owner_key);
    let digest = reg.operation.digest().unwrap();
    let data = registrar::register_instruction_data(
        reg.operation.nonce,
        registrar::DEFAULT_FUND_LAMPORTS,
        REBATE * 100,
        &reg.operation.cluster_genesis,
        &reg.operation.agent_uri,
    );
    let ixs = [
        secp_ix(&reg.signature, &reg.operation.owner_key, &digest),
        register_ix(&reg, &payer, data),
    ];
    refused(env.send(&payer, &ixs), MESSAGE_MISMATCH);
}

#[test]
fn another_owners_vault_is_refused() {
    let mut env = Env::new();
    let key = signing_key(23);
    let other = signing_key(24);
    let payer = env.payer();
    let reg = sign(&key, env.operation(&key, 0, "did:tenzro:machine:vault"));
    env.top_up(&owner_key(&other));
    let digest = reg.operation.digest().unwrap();
    let mut ix = register_ix(&reg, &payer, hardware_data(&reg));
    ix.accounts[3] = AccountMeta::new(Env::vault(&owner_key(&other)), false);
    let ixs = [secp_ix(&reg.signature, &reg.operation.owner_key, &digest), ix];
    refused(env.send(&payer, &ixs), WRONG_VAULT);
}

#[test]
fn the_next_registration_takes_the_next_nonce_and_any_payer_can_send_it() {
    let mut env = Env::new();
    let key = signing_key(2);
    let first = env.payer();
    let second = env.payer();
    env.send_built(&sign(&key, env.operation(&key, 0, "did:a")), &first)
        .expect("first");
    env.send_built(&sign(&key, env.operation(&key, 1, "did:b")), &second)
        .expect("second, paid by someone else");
    let kid = key_id(&owner_key(&key));
    let nonce_acc = env.svm.get_account(&addr(nonce_address(&kid).0)).unwrap();
    assert_eq!(&nonce_acc.data[..8], &2u64.to_le_bytes());
}

#[test]
fn a_replayed_approval_is_refused() {
    let mut env = Env::new();
    let key = signing_key(3);
    let payer = env.payer();
    let reg = sign(&key, env.operation(&key, 0, "did:tenzro:machine:once"));
    env.send_built(&reg, &payer).expect("first use");
    env.svm.expire_blockhash();
    let other = env.payer();
    refused(env.send_built(&reg, &other), NONCE_MISMATCH);
}

#[test]
fn an_approval_for_a_later_nonce_is_refused() {
    let mut env = Env::new();
    let key = signing_key(4);
    let payer = env.payer();
    refused(
        env.send_built(&sign(&key, env.operation(&key, 1, "did:x")), &payer),
        NONCE_MISMATCH,
    );
}

#[test]
fn a_forged_signature_is_refused() {
    let mut env = Env::new();
    let key = signing_key(5);
    let payer = env.payer();
    let mut reg = sign(&key, env.operation(&key, 0, "did:forged"));
    reg.signature[10] ^= 0x01;
    refused_by_signature_check(env.send_built(&reg, &payer));
}

#[test]
fn a_signature_by_another_key_is_refused() {
    let mut env = Env::new();
    let victim = signing_key(6);
    let attacker = signing_key(7);
    let payer = env.payer();

    // The victim's key in the signature instruction, the attacker's signature.
    let op = env.operation(&victim, 0, "did:victim");
    let reg = SignedRegistration {
        signature: p256_sign(&attacker, &op.digest().unwrap()),
        operation: op,
    };
    refused_by_signature_check(env.send_built(&reg, &payer));

    // The attacker's own valid signature, aimed at the victim's owner and
    // asset addresses.
    let theirs = sign(&attacker, env.operation(&attacker, 0, "did:victim"));
    let victims = sign(&victim, env.operation(&victim, 0, "did:victim"));
    let digest = theirs.operation.digest().unwrap();
    let ixs = [
        secp_ix(&theirs.signature, &theirs.operation.owner_key, &digest),
        register_ix(&victims, &payer, hardware_data(&theirs)),
    ];
    refused(env.send(&payer, &ixs), WRONG_OWNER_ADDRESS);
}

#[test]
fn a_registration_without_the_signature_instruction_is_refused() {
    let mut env = Env::new();
    let key = signing_key(8);
    let payer = env.payer();
    let reg = sign(&key, env.operation(&key, 0, "did:none"));

    let alone = register_ix(&reg, &payer, hardware_data(&reg));
    assert_eq!(
        env.send(&payer, &[alone.clone()]),
        Err(TransactionError::InstructionError(
            0,
            InstructionError::Custom(MISSING_SIGNATURE_INSTRUCTION)
        )),
    );

    // Something other than the signature check right before it.
    let other = solana_system_interface::instruction::transfer(&payer.pubkey(), &payer.pubkey(), 1);
    refused(env.send(&payer, &[other, alone]), NOT_SECP256R1);
}

#[test]
fn a_signature_over_a_different_registration_is_refused() {
    let mut env = Env::new();
    let key = signing_key(9);
    let payer = env.payer();
    let signed = sign(&key, env.operation(&key, 0, "did:approved"));
    let digest = signed.operation.digest().unwrap();
    let swapped = SignedRegistration {
        operation: env.operation(&key, 0, "did:swapped"),
        signature: signed.signature,
    };
    let ixs = [
        secp_ix(&signed.signature, &signed.operation.owner_key, &digest),
        register_ix(&swapped, &payer, hardware_data(&swapped)),
    ];
    refused(env.send(&payer, &ixs), MESSAGE_MISMATCH);

    // Approved for another collection.
    let mut elsewhere = env.operation(&key, 0, "did:approved");
    elsewhere.collection = [0x42; 32];
    let e = sign(&key, elsewhere);
    let ixs = [
        secp_ix(&e.signature, &e.operation.owner_key, &e.operation.digest().unwrap()),
        register_ix(&signed, &payer, hardware_data(&signed)),
    ];
    refused(env.send(&payer, &ixs), MESSAGE_MISMATCH);
}

#[test]
fn a_signature_instruction_reading_another_instruction_is_refused() {
    let mut env = Env::new();
    let key = signing_key(10);
    let payer = env.payer();
    let reg = sign(&key, env.operation(&key, 0, "did:offsets"));
    let digest = reg.operation.digest().unwrap();
    let mut secp = secp_ix(&reg.signature, &reg.operation.owner_key, &digest);
    // Point the message at instruction 0 by absolute index instead of
    // "this instruction".
    secp.data[14..16].copy_from_slice(&0u16.to_le_bytes());
    let ixs = [secp, register_ix(&reg, &payer, hardware_data(&reg))];
    refused(env.send(&payer, &ixs), MALFORMED_SIGNATURE_INSTRUCTION);
}

#[test]
fn lamports_sent_to_the_nonce_address_do_not_block_the_first_registration() {
    let mut env = Env::new();
    let key = signing_key(11);
    let payer = env.payer();
    let kid = key_id(&owner_key(&key));
    let exempt = env.svm.minimum_balance_for_rent_exemption(0);
    env.svm.airdrop(&addr(nonce_address(&kid).0), exempt).unwrap();
    env.send_built(&sign(&key, env.operation(&key, 0, "did:prefunded")), &payer)
        .expect("registers");
}

#[test]
fn an_approval_for_another_cluster_is_refused() {
    let mut env = Env::new();
    let key = signing_key(16);
    let payer = env.payer();
    // Devnet, EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG: a valid owner
    // signature, for the wrong cluster.
    let mut op = env.operation(&key, 0, "did:tenzro:machine:devnet");
    op.cluster_genesis = [
        0xce, 0x59, 0xdb, 0x50, 0x80, 0xfc, 0x2c, 0x6d, 0x3b, 0xcf, 0x7c, 0xa9, 0x07, 0x12, 0xd3,
        0xc2, 0xe5, 0xe6, 0xc2, 0x8f, 0x27, 0xf0, 0xdf, 0xbb, 0x99, 0x53, 0xbd, 0xb0, 0x89, 0x4c,
        0x03, 0xab,
    ];
    refused(env.send_built(&sign(&key, op), &payer), WRONG_CLUSTER);
}

#[test]
fn lamports_sent_to_the_asset_address_do_not_block_the_registration() {
    let mut env = Env::new();
    let key = signing_key(15);
    let payer = env.payer();
    let reg = sign(&key, env.operation(&key, 0, "did:tenzro:machine:griefed"));
    let kid = key_id(&reg.operation.owner_key);
    let asset = addr(asset_address(&kid, 0).0);
    let stray = env.svm.minimum_balance_for_rent_exemption(0);
    env.svm.airdrop(&asset, stray).unwrap();

    let before = env.svm.get_balance(&payer.pubkey()).unwrap();
    env.send_built(&reg, &payer).expect("registers despite the pre-funded asset address");

    let asset_acc = env.svm.get_account(&asset).expect("asset created");
    assert_eq!(asset_acc.owner, addr(registrar::MPL_CORE_PROGRAM_ID));
    let (agent, _) = Address::find_program_address(&[b"agent", asset.as_ref()], &env.registry);
    let agent_acc = env.svm.get_account(&agent).unwrap();
    let nonce_acc = env.svm.get_account(&addr(nonce_address(&kid).0)).unwrap();
    assert_eq!(&nonce_acc.data[..8], &1u64.to_le_bytes());
    // The stray lamports went to the vault; the sender is out nothing.
    let rent = asset_acc.lamports + agent_acc.lamports + nonce_acc.lamports;
    let vault = Env::vault(&reg.operation.owner_key);
    assert_eq!(
        env.svm.get_balance(&vault).unwrap(),
        VAULT_FUNDING + stray - rent - REBATE
    );
    assert_eq!(env.svm.get_balance(&payer.pubkey()).unwrap(), before);
}

// --- Passkey approvals -------------------------------------------------------

fn passkey_parts(flags: u8, challenge_of: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let mut auth_data = Sha256::digest(b"example.org").to_vec();
    auth_data.push(flags);
    auth_data.extend_from_slice(&7u32.to_be_bytes());
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge_of);
    let client = format!(
        "{{\"type\":\"webauthn.get\",\"challenge\":\"{challenge}\",\"origin\":\"https://example.org\",\"crossOrigin\":false}}"
    );
    (auth_data, client.into_bytes())
}

fn passkey_data(reg: &RegisterOperation, auth_data: &[u8], client: &[u8]) -> Vec<u8> {
    let mut data = vec![registrar::TAG_REGISTER, registrar::MODE_PASSKEY];
    data.extend_from_slice(&reg.nonce.to_le_bytes());
    data.extend_from_slice(&registrar::DEFAULT_FUND_LAMPORTS.to_le_bytes());
    data.extend_from_slice(&reg.payer_rebate.to_le_bytes());
    data.extend_from_slice(&reg.cluster_genesis);
    data.extend_from_slice(&(reg.agent_uri.len() as u16).to_le_bytes());
    data.extend_from_slice(reg.agent_uri.as_bytes());
    data.extend_from_slice(&(auth_data.len() as u16).to_le_bytes());
    data.extend_from_slice(auth_data);
    data.extend_from_slice(&(client.len() as u16).to_le_bytes());
    data.extend_from_slice(client);
    data
}

fn send_passkey(
    env: &mut Env,
    key: &SigningKey,
    payer: &Keypair,
    op: RegisterOperation,
    flags: u8,
    challenge_of: Option<[u8; 32]>,
) -> Result<(), TransactionError> {
    env.top_up(&op.owner_key);
    let digest = op.digest().unwrap();
    let (auth_data, client) = passkey_parts(flags, &challenge_of.unwrap_or(digest));
    let mut message = auth_data.clone();
    message.extend_from_slice(&Sha256::digest(&client));
    let signature = p256_sign(key, &message);
    let reg = SignedRegistration {
        operation: op,
        signature,
    };
    let ixs = [
        secp_ix(&signature, &reg.operation.owner_key, &message),
        register_ix(&reg, payer, passkey_data(&reg.operation, &auth_data, &client)),
    ];
    env.send(payer, &ixs)
}

const UP_UV: u8 = 0x01 | 0x04;

#[test]
fn a_passkey_assertion_over_the_registration_registers() {
    let mut env = Env::new();
    let key = signing_key(12);
    let payer = env.payer();
    let op = env.operation(&key, 0, "did:tenzro:human:p");
    send_passkey(&mut env, &key, &payer, op, UP_UV, None).expect("registers");
}

#[test]
fn a_passkey_assertion_for_another_challenge_is_refused() {
    let mut env = Env::new();
    let key = signing_key(13);
    let payer = env.payer();
    let op = env.operation(&key, 0, "did:tenzro:human:q");
    refused(
        send_passkey(&mut env, &key, &payer, op, UP_UV, Some([0x55; 32])),
        PASSKEY_CHALLENGE,
    );
}

#[test]
fn a_passkey_assertion_without_user_verification_or_from_a_synced_credential_is_refused() {
    let mut env = Env::new();
    let key = signing_key(14);
    let payer = env.payer();
    let op = env.operation(&key, 0, "did:tenzro:human:r");
    refused(
        send_passkey(&mut env, &key, &payer, op.clone(), 0x01, None),
        PASSKEY_FLAGS,
    );
    refused(
        send_passkey(&mut env, &key, &payer, op, UP_UV | 0x08, None),
        PASSKEY_FLAGS,
    );
}

#[test]
fn builder_addresses_match_the_runtime_derivation() {
    let kid = [9u8; 32];
    let program = addr(registrar::REGISTRAR_PROGRAM_ID);
    for (ours, seeds) in [
        (owner_address(&kid), vec![b"owner".to_vec(), kid.to_vec()]),
        (nonce_address(&kid), vec![b"nonce".to_vec(), kid.to_vec()]),
        (vault_address(&kid), vec![b"vault".to_vec(), kid.to_vec()]),
        (
            asset_address(&kid, 3),
            vec![b"asset".to_vec(), kid.to_vec(), 3u64.to_le_bytes().to_vec()],
        ),
    ] {
        let seed_refs: Vec<&[u8]> = seeds.iter().map(|s| s.as_slice()).collect();
        let (theirs, bump) = Address::find_program_address(&seed_refs, &program);
        assert_eq!(ours.0, theirs.to_bytes());
        assert_eq!(ours.1, bump);
    }
}
