//! Passkey account keystores in consensus state: the first change anchored
//! by the account's first passkey, any linked passkey acting for the account,
//! the spending floor and its wait, removal, replay, recovery, agent roots
//! and payments from the shared account.

use tenzro_crypto::composite::testing::TestHybridSigner;
use tenzro_crypto::composite::{CompositeSignature, HybridSigner, SignatureContext};
use tenzro_types::keystore::{
    ADD_DEVICE_WAIT_MS, KeystoreAnchor, KeystoreApproval, KeystoreCredential, KeystoreOp,
    KeystoreRecord, KeystoreUpdate, RecoveryCodeCommitment, RecoveryRole, RecoverySigner,
    SecondFactorPolicy, recovery_code_claim, recovery_code_commitment, smart_account_address,
};
use tenzro_vm::keystore::{
    SELECTOR_KEYSTORE_UPDATE, check_passkey_root, read_record, resolve_credential,
};
use tenzro_vm::traits::VmState;
use tenzro_vm::{MultiVmRuntime, StateAdapter, VmConfig, VmTransaction, VmType};

const ONE_TNZO: u128 = 1_000_000_000_000_000_000;
const UP_UV: u8 = 0x05;
const BE_BS: u8 = 0x18;
const T0: i64 = 1_800_000_000_000;
const GAS_PRICE: u128 = 1_000_000_000;
/// The chain every network here runs, unless a test names another.
const CHAIN: u64 = 1337;

/// A passkey: its key, where it lives and the wallet provider it is
/// registered with.
struct Device {
    signer: TestHybridSigner,
    credential_id: Vec<u8>,
    aaguid: u8,
    synced: bool,
    rp_id: &'static str,
}

impl Device {
    fn synced(seed: u8, provider: u8) -> Self {
        Self {
            signer: TestHybridSigner::hybrid(seed),
            credential_id: vec![seed; 16],
            aaguid: provider,
            synced: true,
            rp_id: "tenzro.com",
        }
    }
    fn bound(seed: u8) -> Self {
        Self {
            aaguid: 0xcb,
            synced: false,
            ..Self::synced(seed, 0)
        }
    }
    /// The same kind of passkey, registered with another wallet provider.
    fn at(self, rp_id: &'static str) -> Self {
        Self { rp_id, ..self }
    }
    fn key(&self) -> Vec<u8> {
        self.signer.public_key().p256.clone()
    }
    fn flags(&self) -> u8 {
        if self.synced { UP_UV | BE_BS } else { UP_UV }
    }
    fn assert(&self, context: SignatureContext, msg: &[u8]) -> CompositeSignature {
        self.assert_at(self.rp_id, &format!("https://{}", self.rp_id), context, msg)
    }
    /// An assertion claiming the relying party `rp_id`, made at `origin`.
    fn assert_at(
        &self,
        rp_id: &str,
        origin: &str,
        context: SignatureContext,
        msg: &[u8],
    ) -> CompositeSignature {
        let mut sig = CompositeSignature::classical(self.signer.sign_passkey_at(
            rp_id,
            origin,
            self.flags(),
            context,
            msg,
        ));
        sig.pq = self.signer.sign(context, msg).unwrap().pq;
        sig
    }
    fn credential(&self) -> KeystoreCredential {
        KeystoreCredential {
            rp_id: self.rp_id.to_string(),
            credential_id: self.credential_id.clone(),
            public_key: self.key(),
            aaguid: vec![self.aaguid; 16],
            backup_eligible: self.synced,
            backup_state: self.synced,
            counts_as_root_from_ms: 0,
            label: String::new(),
            added_at_ms: 0,
        }
    }
    fn anchor(&self) -> KeystoreAnchor {
        KeystoreAnchor {
            rp_id: self.rp_id.to_string(),
            credential_id: self.credential_id.clone(),
            public_key: self.key(),
            aaguid: vec![self.aaguid; 16],
            backup_eligible: self.synced,
            backup_state: self.synced,
            salt: 0,
        }
    }
    fn account(&self) -> Vec<u8> {
        smart_account_address(&self.key(), &self.credential_id, 0).to_vec()
    }
    fn approve(&self, update: &KeystoreUpdate) -> KeystoreApproval {
        KeystoreApproval {
            public_key: self.key(),
            signature: self.assert(SignatureContext::AccountOwner, &update.digest()),
        }
    }
}

fn slot(account: &[u8]) -> Vec<u8> {
    let mut s = account.to_vec();
    s.resize(32, 0);
    s
}

fn signed_tx(
    from: &[u8],
    key: &[u8],
    sig: CompositeSignature,
    data: Vec<u8>,
    to: Option<Vec<u8>>,
    value: u128,
    nonce: u64,
    at: i64,
) -> VmTransaction {
    let mut tx = VmTransaction::new(
        from.to_vec(),
        to,
        value,
        data,
        500_000,
        GAS_PRICE,
        nonce,
        VmType::Tenzro,
        VmConfig::default().chain_id,
    );
    tx.signature = Some(sig);
    tx.public_key = Some(key.to_vec());
    tx.signing_digest = Some(vec![nonce as u8 ^ 0x5a; 32]);
    tx.block_timestamp_ms = Some(at);
    tx.valid_until_ms = Some(at + 60_000);
    tx
}

/// A keystore change sent and paid for by `payer`, an ordinary account.
fn relayed(
    payer: &TestHybridSigner,
    update: &KeystoreUpdate,
    nonce: u64,
    at: i64,
) -> VmTransaction {
    let mut data = SELECTOR_KEYSTORE_UPDATE.to_vec();
    data.extend_from_slice(&serde_json::to_vec(update).unwrap());
    let digest = vec![nonce as u8 ^ 0x5a; 32];
    let sig = payer.sign(SignatureContext::Transaction, &digest).unwrap();
    let system = tenzro_vm::native::SYSTEM_ADDRESS.to_vec();
    let mut tx = signed_tx(
        payer.address().as_bytes(),
        &payer.public_key().p256,
        sig,
        data,
        Some(system),
        0,
        nonce,
        at,
    );
    tx.signing_digest = Some(digest);
    tx
}

/// A keystore change sent by the passkey account itself, signed by `device`.
fn sent_by_account(
    device: &Device,
    account: &[u8],
    update: &KeystoreUpdate,
    nonce: u64,
    at: i64,
) -> VmTransaction {
    let mut data = SELECTOR_KEYSTORE_UPDATE.to_vec();
    data.extend_from_slice(&serde_json::to_vec(update).unwrap());
    let digest = vec![nonce as u8 ^ 0x5a; 32];
    let sig = device.assert(SignatureContext::Transaction, &digest);
    let system = tenzro_vm::native::SYSTEM_ADDRESS.to_vec();
    signed_tx(
        &slot(account),
        &device.key(),
        sig,
        data,
        Some(system),
        0,
        nonce,
        at,
    )
}

/// A transfer from the passkey account, signed by one of its passkeys.
fn transfer(device: &Device, account: &[u8], to: &[u8], nonce: u64, at: i64) -> VmTransaction {
    let digest = vec![nonce as u8 ^ 0x5a; 32];
    let sig = device.assert(SignatureContext::Transaction, &digest);
    signed_tx(
        &slot(account),
        &device.key(),
        sig,
        Vec::new(),
        Some(to.to_vec()),
        ONE_TNZO,
        nonce,
        at,
    )
}

fn update(
    account: &[u8],
    state: &StateAdapter,
    anchor: Option<KeystoreAnchor>,
    op: KeystoreOp,
) -> KeystoreUpdate {
    let previous = match read_record(state, account) {
        Some(r) => r.commitment(),
        None => KeystoreRecord::genesis(anchor.as_ref().unwrap()).commitment(),
    };
    KeystoreUpdate {
        chain_id: CHAIN,
        account: account.to_vec(),
        anchor,
        previous_commitment: previous.to_vec(),
        op,
        approvals: Vec::new(),
        possession: None,
    }
}

fn add(
    state: &StateAdapter,
    account: &[u8],
    anchor: Option<KeystoreAnchor>,
    approver: &Device,
    new: &Device,
) -> KeystoreUpdate {
    let mut u = update(
        account,
        state,
        anchor,
        KeystoreOp::AddCredential {
            credential: new.credential(),
        },
    );
    u.possession = Some(new.assert(SignatureContext::AccountOwner, &u.digest()));
    u.approvals = vec![approver.approve(&u)];
    u
}

/// Records the ML-DSA-65 key of every test signer `TestHybridSigner::hybrid`
/// makes (seeds 1 to 255) as the one enrolled for its P-256 key.
fn enroll_test_keys(state: &mut StateAdapter) {
    for seed in 1..=255u8 {
        let key = TestHybridSigner::hybrid(seed).public_key().clone();
        tenzro_vm::account_keys::set_enrolled_pq_key(
            state,
            &key.p256,
            key.pq.clone().unwrap(),
            &mut Vec::new(),
        );
    }
}

struct Net {
    runtime: MultiVmRuntime,
    state: StateAdapter,
    payer: TestHybridSigner,
    chain_id: u64,
}

impl Net {
    async fn new() -> Self {
        Self::on_chain(CHAIN).await
    }
    /// A network with its own chain id, starting from the same state.
    async fn on_chain(chain_id: u64) -> Self {
        let payer = TestHybridSigner::hybrid(200);
        let mut state = StateAdapter::new();
        enroll_test_keys(&mut state);
        state.set_balance(payer.address().as_bytes(), 100 * ONE_TNZO);
        state.set_storage(
            &tenzro_vm::native::SYSTEM_ADDRESS,
            tenzro_vm::native::NETWORK_CHAIN_ID_KEY.as_bytes(),
            chain_id.to_le_bytes().to_vec(),
        );
        Self {
            runtime: MultiVmRuntime::new(VmConfig::default().with_chain_id(chain_id))
                .await
                .unwrap(),
            state,
            payer,
            chain_id,
        }
    }
    async fn send(&mut self, u: &KeystoreUpdate, at: i64) -> Result<(), String> {
        let mut tx = relayed(
            &self.payer,
            u,
            self.state.get_nonce(self.payer.address().as_bytes()),
            at,
        );
        tx.chain_id = self.chain_id;
        let r = self
            .runtime
            .execute_transaction(&tx, &mut self.state)
            .await
            .map_err(|e| e.to_string())?;
        if r.success {
            Ok(())
        } else {
            Err("execution failed".to_string())
        }
    }
    /// The next nonce of the passkey account `account`: a refused
    /// transaction may already have consumed one.
    fn nonce(&self, account: &[u8]) -> u64 {
        self.state.get_nonce(&slot(account))
    }
    async fn run(&mut self, mut tx: VmTransaction) -> Result<(), String> {
        tx.chain_id = self.chain_id;
        let r = self
            .runtime
            .execute_transaction(&tx, &mut self.state)
            .await
            .map_err(|e| e.to_string())?;
        if r.success {
            Ok(())
        } else {
            Err("execution failed".to_string())
        }
    }
}

#[tokio::test]
async fn the_first_change_is_anchored_by_the_passkey_that_derives_the_account() {
    let mut net = Net::new().await;
    let phone = Device::synced(1, 0xaa);
    let laptop = Device::synced(2, 0xbb);
    let account = phone.account();

    // Without the anchor there is nothing to change.
    let mut u = add(&net.state, &account, Some(phone.anchor()), &phone, &laptop);
    let mut no_anchor = u.clone();
    no_anchor.anchor = None;
    assert!(net.send(&no_anchor, T0).await.is_err());

    // An anchor that does not derive the account is refused.
    let stranger = Device::synced(3, 0xaa);
    let mut forged = add(
        &net.state,
        &account,
        Some(stranger.anchor()),
        &stranger,
        &laptop,
    );
    forged.previous_commitment = KeystoreRecord::genesis(&phone.anchor())
        .commitment()
        .to_vec();
    assert!(net.send(&forged, T0).await.is_err());

    // An approval by a passkey the account does not hold is refused.
    let mut wrong = u.clone();
    wrong.approvals = vec![stranger.approve(&u)];
    assert!(net.send(&wrong, T0).await.is_err());

    net.send(&u, T0).await.unwrap();
    let record = read_record(&net.state, &account).unwrap();
    assert_eq!(record.version, 1);
    assert_eq!(record.credentials.len(), 2);
    assert_eq!(
        resolve_credential(&net.state, "tenzro.com", &laptop.credential_id),
        vec![hex::encode(&account)]
    );

    // The same approval cannot apply twice: the commitment moved.
    u.anchor = None;
    assert!(net.send(&u, T0).await.is_err());
}

#[tokio::test]
async fn any_linked_passkey_spends_once_the_account_holds_two_independent_roots() {
    let mut net = Net::new().await;
    let phone = Device::synced(10, 0xaa);
    let key = Device::bound(11);
    let account = phone.account();
    net.state.set_balance(&slot(&account), 10 * ONE_TNZO);
    let to = vec![0x77u8; 20];

    // One root: the first passkey cannot spend.
    assert!(
        net.run(transfer(&phone, &account, &to, net.nonce(&account), T0))
            .await
            .is_err()
    );

    // A device-bound key added below two roots waits before it counts.
    let u = add(&net.state, &account, Some(phone.anchor()), &phone, &key);
    net.send(&u, T0).await.unwrap();
    assert!(
        net.run(transfer(&key, &account, &to, net.nonce(&account), T0 + 1))
            .await
            .is_err()
    );

    // After the wait, either device spends from the one account.
    let later = T0 + ADD_DEVICE_WAIT_MS as i64;
    net.run(transfer(&key, &account, &to, net.nonce(&account), later))
        .await
        .unwrap();
    net.run(transfer(&phone, &account, &to, net.nonce(&account), later))
        .await
        .unwrap();
    assert_eq!(net.state.get_balance(&to), 2 * ONE_TNZO);

    // A passkey of another account cannot.
    let stranger = Device::synced(12, 0xcc);
    assert!(
        net.run(transfer(
            &stranger,
            &account,
            &to,
            net.nonce(&account),
            later
        ))
        .await
        .is_err()
    );
}

#[tokio::test]
async fn an_unlinked_passkey_stops_acting_and_the_last_one_stays() {
    let mut net = Net::new().await;
    let phone = Device::synced(20, 0xaa);
    let key = Device::bound(21);
    let laptop = Device::synced(22, 0xbb);
    let account = phone.account();
    net.state.set_balance(&slot(&account), 10 * ONE_TNZO);
    net.send(
        &add(&net.state, &account, Some(phone.anchor()), &phone, &key),
        T0,
    )
    .await
    .unwrap();
    let later = T0 + ADD_DEVICE_WAIT_MS as i64;
    net.send(&add(&net.state, &account, None, &key, &laptop), later)
        .await
        .unwrap();

    // The laptop, acting alone, unlinks the phone.
    let mut u = update(
        &account,
        &net.state,
        None,
        KeystoreOp::RemoveCredential {
            credential_id: phone.credential_id.clone(),
        },
    );
    u.approvals = vec![laptop.approve(&u)];
    net.send(&u, later).await.unwrap();
    assert!(
        net.run(transfer(
            &phone,
            &account,
            &[9; 20],
            net.nonce(&account),
            later
        ))
        .await
        .is_err()
    );
    assert!(resolve_credential(&net.state, "tenzro.com", &phone.credential_id).is_empty());

    let mut u = update(
        &account,
        &net.state,
        None,
        KeystoreOp::RemoveCredential {
            credential_id: laptop.credential_id.clone(),
        },
    );
    u.approvals = vec![key.approve(&u)];
    net.send(&u, later).await.unwrap();
    let mut u = update(
        &account,
        &net.state,
        None,
        KeystoreOp::RemoveCredential {
            credential_id: key.credential_id.clone(),
        },
    );
    u.approvals = vec![key.approve(&u)];
    assert!(
        net.send(&u, later).await.is_err(),
        "the last passkey cannot be unlinked"
    );
}

#[tokio::test]
async fn the_two_passkey_policy_needs_two_approvals_and_stops_lone_spending() {
    let mut net = Net::new().await;
    let phone = Device::synced(30, 0xaa);
    let key = Device::bound(31);
    let account = phone.account();
    net.state.set_balance(&slot(&account), 10 * ONE_TNZO);
    net.send(
        &add(&net.state, &account, Some(phone.anchor()), &phone, &key),
        T0,
    )
    .await
    .unwrap();
    let later = T0 + ADD_DEVICE_WAIT_MS as i64;

    let mut u = update(
        &account,
        &net.state,
        None,
        KeystoreOp::SetPolicy {
            policy: SecondFactorPolicy::TwoCredentials,
        },
    );
    u.approvals = vec![phone.approve(&u)];
    assert!(net.send(&u, later).await.is_err());
    u.approvals.push(key.approve(&u));
    net.send(&u, later).await.unwrap();
    assert!(
        net.run(transfer(
            &phone,
            &account,
            &[9; 20],
            net.nonce(&account),
            later
        ))
        .await
        .is_err()
    );

    let laptop = Device::synced(32, 0xbb);
    let one = add(&net.state, &account, None, &phone, &laptop);
    assert!(net.send(&one, later).await.is_err());
    let mut two = one.clone();
    two.approvals.push(key.approve(&one));
    net.send(&two, later).await.unwrap();
}

#[tokio::test]
async fn recovery_waits_and_any_passkey_can_cancel_it() {
    let mut net = Net::new().await;
    let phone = Device::synced(40, 0xaa);
    let backup = TestHybridSigner::hybrid(41);
    let account = phone.account();
    let signer = RecoverySigner {
        rp_id: String::new(),
        public_key: backup.public_key().p256.clone(),
        aaguid: vec![0; 16],
        backup_eligible: false,
        backup_state: false,
        role: RecoveryRole::RecoveryKey,
        label: "Backup key".to_string(),
    };
    let mut u = update(
        &account,
        &net.state,
        Some(phone.anchor()),
        KeystoreOp::SetRecovery {
            signers: vec![signer],
            threshold: 1,
        },
    );
    u.approvals = vec![phone.approve(&u)];
    net.send(&u, T0).await.unwrap();

    let newphone = Device::synced(42, 0xbb);
    let start = |state: &StateAdapter| {
        let mut u = update(
            &account,
            state,
            None,
            KeystoreOp::StartRecovery {
                credential: newphone.credential(),
            },
        );
        u.possession = Some(newphone.assert(SignatureContext::AccountOwner, &u.digest()));
        u.approvals = vec![KeystoreApproval {
            public_key: backup.public_key().p256.clone(),
            signature: backup
                .sign(SignatureContext::RecoveryApproval, &u.digest())
                .unwrap(),
        }];
        u
    };

    // Started, then cancelled by the phone the owner still has.
    net.send(&start(&net.state), T0).await.unwrap();
    let mut cancel = update(&account, &net.state, None, KeystoreOp::CancelRecovery);
    cancel.approvals = vec![phone.approve(&cancel)];
    net.send(&cancel, T0 + 1).await.unwrap();
    assert!(
        read_record(&net.state, &account)
            .unwrap()
            .pending_recovery
            .is_none()
    );

    // Started again, this time by the account itself, paid from its own
    // balance and signed by the joining passkey; it completes only after its
    // wait, sent the same way.
    net.state.set_balance(&slot(&account), ONE_TNZO);
    let stranger = Device::synced(43, 0xcc);
    assert!(
        net.run(sent_by_account(
            &stranger,
            &account,
            &start(&net.state),
            net.nonce(&account),
            T0 + 2
        ))
        .await
        .is_err()
    );
    net.run(sent_by_account(
        &newphone,
        &account,
        &start(&net.state),
        net.nonce(&account),
        T0 + 2,
    ))
    .await
    .unwrap();
    // A recovery key alone serves the governed key wait, 48 h at genesis.
    assert_eq!(
        read_record(&net.state, &account)
            .unwrap()
            .pending_recovery
            .as_ref()
            .unwrap()
            .ready_at_ms,
        (T0 + 2) as u64 + tenzro_types::keystore::RECOVERY_WAIT_KEY_MS
    );
    let finish = update(&account, &net.state, None, KeystoreOp::FinishRecovery);
    assert!(net.send(&finish, T0 + 3).await.is_err());
    let ready = read_record(&net.state, &account)
        .unwrap()
        .pending_recovery
        .unwrap()
        .ready_at_ms as i64;
    net.run(sent_by_account(
        &newphone,
        &account,
        &finish,
        net.nonce(&account),
        ready,
    ))
    .await
    .unwrap();
    let record = read_record(&net.state, &account).unwrap();
    assert!(record.credential_by_key(&newphone.key()).is_some());
}

#[test]
fn a_linked_passkey_roots_agents_and_an_unlinked_one_stops() {
    let phone = Device::synced(50, 0xaa);
    let laptop = Device::synced(51, 0xbb);
    let did = tenzro_types::keystore::human_did(&phone.key());
    let mut state = StateAdapter::new();

    // Before the identity has a keystore, only the passkey its DID derives from.
    check_passkey_root(&state, &did, &phone.key(), T0 as u64).unwrap();
    assert!(check_passkey_root(&state, &did, &laptop.key(), T0 as u64).is_err());

    let mut record = KeystoreRecord::genesis(&phone.anchor());
    record.credentials.push(laptop.credential());
    record.version = 1;
    tenzro_vm::keystore::write_record(&mut state, None, &record, &mut Vec::new()).unwrap();
    check_passkey_root(&state, &did, &laptop.key(), T0 as u64).unwrap();

    let previous = record.clone();
    record.credentials.retain(|c| c.public_key != phone.key());
    record.version = 2;
    tenzro_vm::keystore::write_record(&mut state, Some(&previous), &record, &mut Vec::new())
        .unwrap();
    assert!(
        check_passkey_root(&state, &did, &phone.key(), T0 as u64).is_err(),
        "an unlinked first passkey no longer roots"
    );
    check_passkey_root(&state, &did, &laptop.key(), T0 as u64).unwrap();
}

/// Multiple wallet providers: a passkey registered with any provider's
/// domain joins an account with the approval of a passkey already on it,
/// and from then on approves and spends like any other, for its own
/// relying party and no other.
#[tokio::test]
async fn passkeys_from_two_wallet_providers_act_for_one_account() {
    let mut net = Net::new().await;
    let phone = Device::synced(60, 0xaa);
    let other = Device::bound(61).at("wallet.example.org");
    let account = phone.account();
    net.state.set_balance(&slot(&account), 10 * ONE_TNZO);

    // Linking the other provider's passkey with nobody's approval is refused.
    let mut unapproved = add(&net.state, &account, Some(phone.anchor()), &phone, &other);
    unapproved.approvals.clear();
    assert!(net.send(&unapproved, T0).await.is_err());

    net.send(
        &add(&net.state, &account, Some(phone.anchor()), &phone, &other),
        T0,
    )
    .await
    .unwrap();
    assert_eq!(
        resolve_credential(&net.state, "wallet.example.org", &other.credential_id),
        vec![hex::encode(&account)]
    );
    assert!(resolve_credential(&net.state, "tenzro.com", &other.credential_id).is_empty());
    // The chain records when each passkey joined: the first one with the
    // account's first change.
    let record = read_record(&net.state, &account).unwrap();
    assert_eq!(
        record.credential_by_key(&phone.key()).unwrap().added_at_ms,
        T0 as u64
    );
    assert_eq!(
        record.credential_by_key(&other.key()).unwrap().added_at_ms,
        T0 as u64
    );

    // It approves a change for its own relying party.
    let later = T0 + ADD_DEVICE_WAIT_MS as i64;
    let laptop = Device::synced(62, 0xbb);
    net.send(&add(&net.state, &account, None, &other, &laptop), later)
        .await
        .unwrap();

    // An assertion carrying another relying party, or made at a site that is
    // not its relying party, is refused.
    let key = Device::bound(63);
    let mut u = update(
        &account,
        &net.state,
        None,
        KeystoreOp::AddCredential {
            credential: key.credential(),
        },
    );
    u.possession = Some(key.assert(SignatureContext::AccountOwner, &u.digest()));
    for (rp, origin) in [
        ("tenzro.com", "https://tenzro.com"),
        ("wallet.example.org", "https://evil.example.net"),
    ] {
        let mut wrong = u.clone();
        wrong.approvals = vec![KeystoreApproval {
            public_key: other.key(),
            signature: other.assert_at(rp, origin, SignatureContext::AccountOwner, &u.digest()),
        }];
        assert!(
            net.send(&wrong, later).await.is_err(),
            "{rp} at {origin} must not approve"
        );
    }

    // Both providers' passkeys spend from the one account.
    let to = vec![0x55u8; 20];
    net.run(transfer(&phone, &account, &to, net.nonce(&account), later))
        .await
        .unwrap();
    net.run(transfer(&other, &account, &to, net.nonce(&account), later))
        .await
        .unwrap();
    let mut forged = transfer(&other, &account, &to, net.nonce(&account), later);
    forged.signature = Some(other.assert_at(
        "tenzro.com",
        "https://tenzro.com",
        SignatureContext::Transaction,
        forged.signing_digest.as_deref().unwrap(),
    ));
    assert!(
        net.run(forged).await.is_err(),
        "an assertion for another relying party does not spend"
    );
    assert_eq!(net.state.get_balance(&to), 2 * ONE_TNZO);
}

/// Recovery works from any wallet provider: an account whose passkeys,
/// guardian and new passkey are each registered with a different provider's
/// domain, none of them the network's own, recovers with the guardian's
/// approval for its own relying party, and the recovered passkey spends.
#[tokio::test]
async fn recovery_works_across_wallet_providers() {
    let mut net = Net::new().await;
    let phone = Device::synced(70, 0xaa).at("wallet.example.org");
    let guardian = Device::bound(71).at("guardians.example.net");
    let newphone = Device::synced(72, 0xbb).at("recover.example.com");
    let account = phone.account();
    let signer = RecoverySigner {
        rp_id: guardian.rp_id.to_string(),
        public_key: guardian.key(),
        aaguid: vec![guardian.aaguid; 16],
        backup_eligible: false,
        backup_state: false,
        role: RecoveryRole::Device,
        label: "Sam".to_string(),
    };
    let mut u = update(
        &account,
        &net.state,
        Some(phone.anchor()),
        KeystoreOp::SetRecovery {
            signers: vec![signer],
            threshold: 1,
        },
    );
    u.approvals = vec![phone.approve(&u)];
    net.send(&u, T0).await.unwrap();

    let start = |state: &StateAdapter, rp: &str, origin: &str| {
        let mut u = update(
            &account,
            state,
            None,
            KeystoreOp::StartRecovery {
                credential: newphone.credential(),
            },
        );
        u.possession = Some(newphone.assert(SignatureContext::AccountOwner, &u.digest()));
        u.approvals = vec![KeystoreApproval {
            public_key: guardian.key(),
            signature: guardian.assert_at(
                rp,
                origin,
                SignatureContext::RecoveryApproval,
                &u.digest(),
            ),
        }];
        u
    };
    net.state.set_balance(&slot(&account), 2 * ONE_TNZO);

    // A guardian approval made for another provider's relying party is refused.
    for (rp, origin) in [
        ("tenzro.com", "https://tenzro.com"),
        ("guardians.example.net", "https://evil.example.org"),
    ] {
        let refused = start(&net.state, rp, origin);
        assert!(
            net.run(sent_by_account(
                &newphone,
                &account,
                &refused,
                net.nonce(&account),
                T0 + 1
            ))
            .await
            .is_err(),
            "{rp} at {origin} must not approve"
        );
    }

    let approved = start(
        &net.state,
        "guardians.example.net",
        "https://guardians.example.net",
    );
    net.run(sent_by_account(
        &newphone,
        &account,
        &approved,
        net.nonce(&account),
        T0 + 1,
    ))
    .await
    .unwrap();
    let ready = read_record(&net.state, &account)
        .unwrap()
        .pending_recovery
        .unwrap()
        .ready_at_ms as i64;
    let finish = update(&account, &net.state, None, KeystoreOp::FinishRecovery);
    net.run(sent_by_account(
        &newphone,
        &account,
        &finish,
        net.nonce(&account),
        ready,
    ))
    .await
    .unwrap();
    assert_eq!(
        resolve_credential(&net.state, "recover.example.com", &newphone.credential_id),
        vec![hex::encode(&account)]
    );

    let to = vec![0x66u8; 20];
    let later = ready + ADD_DEVICE_WAIT_MS as i64;
    net.run(transfer(
        &newphone,
        &account,
        &to,
        net.nonce(&account),
        later,
    ))
    .await
    .unwrap();
    assert_eq!(net.state.get_balance(&to), ONE_TNZO);
}

fn service_change(
    device: &Device,
    account: &[u8],
    did: &str,
    version: u64,
    change: tenzro_types::did_services::DidServiceChange,
) -> tenzro_types::did_services::IdentityServiceOp {
    use tenzro_types::agent_terms::{AgentTermsApproval, custody_challenge_digest};
    use tenzro_types::did_services::{OP_DID_SERVICE, service_change_target};
    let nonce = [version as u8 + 1; 16];
    let target = service_change_target(did, version, &change);
    let digest = custody_challenge_digest(CHAIN, account, OP_DID_SERVICE, &target, &nonce);
    tenzro_types::did_services::IdentityServiceOp {
        did: did.to_string(),
        version,
        change,
        approval: AgentTermsApproval {
            account: account.to_vec(),
            nonce,
            root_public_key: device.key(),
            signature: device.assert(SignatureContext::AccountOwner, &digest),
        },
    }
}

fn services_tx(
    payer: &TestHybridSigner,
    op: &tenzro_types::did_services::IdentityServiceOp,
    nonce: u64,
    at: i64,
) -> VmTransaction {
    let mut data = tenzro_vm::native::SELECTOR_IDENTITY_SERVICES.to_vec();
    data.extend_from_slice(&serde_json::to_vec(op).unwrap());
    let digest = vec![nonce as u8 ^ 0x5a; 32];
    let sig = payer.sign(SignatureContext::Transaction, &digest).unwrap();
    let system = tenzro_vm::native::SYSTEM_ADDRESS.to_vec();
    let mut tx = signed_tx(
        payer.address().as_bytes(),
        &payer.public_key().p256,
        sig,
        data,
        Some(system),
        0,
        nonce,
        at,
    );
    tx.signing_digest = Some(digest);
    tx
}

/// A DID document's services are consensus state: any passkey the
/// identity's keystore links publishes or removes an entry for the current
/// version of the list, an unlinked one or a stale version is refused, and
/// two nodes applying the same transactions hold the same list.
#[tokio::test]
async fn did_services_are_consensus_state_approved_by_the_keystore() {
    use tenzro_types::did_services::{DidServiceChange, DidServiceEntry};
    let mut a = Net::new().await;
    let mut b = Net::new().await;
    let phone = Device::synced(80, 0xaa);
    let laptop = Device::bound(81).at("wallet.example.org");
    let stranger = Device::synced(82, 0xcc);
    let account = phone.account();
    let did = tenzro_types::keystore::human_did(&phone.key());
    let inbox = |endpoint: &str| DidServiceChange::Set {
        service: DidServiceEntry {
            id: "inbox".to_string(),
            service_type: "MessagingService".to_string(),
            endpoint: endpoint.to_string(),
        },
    };

    // Both nodes link the laptop, from another wallet provider, to the account.
    for net in [&mut a, &mut b] {
        let link = add(&net.state, &account, Some(phone.anchor()), &phone, &laptop);
        net.send(&link, T0).await.unwrap();
    }
    // The laptop is linked while the account holds a single root, so it
    // waits before it counts: until then it changes no service.
    let early = service_change(
        &laptop,
        &account,
        &did,
        0,
        inbox("https://inbox.example.org/early"),
    );
    let tx = services_tx(
        &a.payer,
        &early,
        a.state.get_nonce(a.payer.address().as_bytes()),
        T0 + 1,
    );
    assert!(a.run(tx).await.is_err());
    let later = T0 + ADD_DEVICE_WAIT_MS as i64;

    let ops = vec![
        service_change(
            &laptop,
            &account,
            &did,
            0,
            inbox("https://inbox.example.org/a"),
        ),
        service_change(
            &phone,
            &account,
            &did,
            1,
            inbox("https://inbox.example.org/b"),
        ),
    ];
    for net in [&mut a, &mut b] {
        for op in &ops {
            let tx = services_tx(
                &net.payer,
                op,
                net.state.get_nonce(net.payer.address().as_bytes()),
                later + 1,
            );
            net.run(tx).await.unwrap();
        }
    }
    let on_a = tenzro_vm::native::read_did_services(&a.state, &did);
    assert_eq!(
        on_a,
        tenzro_vm::native::read_did_services(&b.state, &did),
        "every node holds the same list"
    );
    assert_eq!(on_a.version, 2);
    assert_eq!(on_a.services.len(), 1);
    assert_eq!(on_a.services[0].endpoint, "https://inbox.example.org/b");

    // A replayed approval names a past version and is refused; so is a
    // passkey the keystore does not link.
    let replay = services_tx(
        &a.payer,
        &ops[0],
        a.state.get_nonce(a.payer.address().as_bytes()),
        later + 2,
    );
    assert!(a.run(replay).await.is_err());
    let foreign = service_change(
        &stranger,
        &account,
        &did,
        2,
        DidServiceChange::Remove {
            id: "inbox".to_string(),
        },
    );
    let tx = services_tx(
        &a.payer,
        &foreign,
        a.state.get_nonce(a.payer.address().as_bytes()),
        later + 2,
    );
    assert!(a.run(tx).await.is_err());

    let remove = service_change(
        &laptop,
        &account,
        &did,
        2,
        DidServiceChange::Remove {
            id: "inbox".to_string(),
        },
    );
    let tx = services_tx(
        &a.payer,
        &remove,
        a.state.get_nonce(a.payer.address().as_bytes()),
        later + 3,
    );
    a.run(tx).await.unwrap();
    assert!(
        tenzro_vm::native::read_did_services(&a.state, &did)
            .services
            .is_empty()
    );
}

/// No change is free: an account with no balance has its first keystore
/// change paid by a sponsor, who sends it from its own account. The
/// account's passkey authorizes the change through the approval it carries;
/// the sponsor's signature authorizes nothing about the keystore.
#[tokio::test]
async fn a_sponsor_pays_for_an_unfunded_account_and_cannot_change_it_alone() {
    let mut net = Net::new().await;
    let phone = Device::synced(90, 0xaa);
    let laptop = Device::bound(91);
    let account = phone.account();
    assert_eq!(net.state.get_balance(&slot(&account)), 0);
    let sponsor = net.payer.address().as_bytes().to_vec();
    let before = net.state.get_balance(&sponsor);

    // Without the account's approval the sponsor's transaction changes nothing.
    let mut unapproved = add(&net.state, &account, Some(phone.anchor()), &phone, &laptop);
    unapproved.approvals.clear();
    assert!(net.send(&unapproved, T0).await.is_err());
    assert!(read_record(&net.state, &account).is_none());

    net.send(
        &add(&net.state, &account, Some(phone.anchor()), &phone, &laptop),
        T0,
    )
    .await
    .unwrap();
    assert!(
        read_record(&net.state, &account)
            .unwrap()
            .credential_by_key(&laptop.key())
            .is_some()
    );
    assert_eq!(
        net.state.get_balance(&slot(&account)),
        0,
        "the account paid nothing"
    );
    assert!(
        net.state.get_balance(&sponsor) < before,
        "the sponsor paid the fee"
    );
}

/// The one-time recovery code: set by the account's passkey, claimed for a
/// new passkey by another account, revealed after the claim has aged, and
/// the new passkey joins after the recovery's wait. A claim from the locked
/// account itself, an early reveal, a wrong code, a reveal by someone who
/// saw the code but holds no claim of their own, and a second use are all
/// refused.
#[tokio::test]
async fn a_recovery_code_restores_access_once_after_its_claim_and_wait() {
    let mut net = Net::new().await;
    let phone = Device::synced(50, 0xaa);
    let account = phone.account();
    let code = [7u8; 32];
    let mut set = update(
        &account,
        &net.state,
        Some(phone.anchor()),
        KeystoreOp::SetRecoveryCode {
            commitment: Some(RecoveryCodeCommitment(
                recovery_code_commitment(CHAIN, &account, &code).to_vec(),
            )),
        },
    );
    set.approvals = vec![phone.approve(&set)];
    net.send(&set, T0).await.unwrap();

    let newphone = Device::synced(51, 0xbb);
    let claim = |state: &StateAdapter, who: &Device| {
        update(
            &account,
            state,
            None,
            KeystoreOp::ClaimRecoveryCode {
                claim: recovery_code_claim(CHAIN, &account, &code, &who.credential()).to_vec(),
            },
        )
    };
    // The locked account does not pay for claims.
    net.state.set_balance(&slot(&account), ONE_TNZO);
    assert!(
        net.run(sent_by_account(
            &phone,
            &account,
            &claim(&net.state, &newphone),
            net.nonce(&account),
            T0 + 1
        ))
        .await
        .is_err()
    );
    net.send(&claim(&net.state, &newphone), T0 + 1)
        .await
        .unwrap();

    let reveal = |state: &StateAdapter, who: &Device, code: [u8; 32]| {
        let mut u = update(
            &account,
            state,
            None,
            KeystoreOp::RecoverWithCode {
                code: code.to_vec(),
                credential: who.credential(),
            },
        );
        u.possession = Some(who.assert(SignatureContext::AccountOwner, &u.digest()));
        u
    };
    assert!(
        net.send(&reveal(&net.state, &newphone, code), T0 + 1_000)
            .await
            .is_err(),
        "too early"
    );
    assert!(
        net.send(&reveal(&net.state, &newphone, [8u8; 32]), T0 + 70_000)
            .await
            .is_err(),
        "wrong code"
    );
    let thief = Device::synced(52, 0xcc);
    assert!(
        net.send(&reveal(&net.state, &thief, code), T0 + 70_000)
            .await
            .is_err(),
        "no claim of its own"
    );
    net.send(&reveal(&net.state, &newphone, code), T0 + 70_000)
        .await
        .unwrap();
    let record = read_record(&net.state, &account).unwrap();
    assert!(record.recovery_code.is_none(), "the code is spent");
    let ready = record.pending_recovery.unwrap().ready_at_ms as i64;
    assert_eq!(ready, T0 + 70_000 + 7 * 24 * 60 * 60 * 1000);
    let finish = update(&account, &net.state, None, KeystoreOp::FinishRecovery);
    assert!(net.send(&finish, ready - 1).await.is_err());
    net.send(&finish, ready).await.unwrap();
    assert!(
        read_record(&net.state, &account)
            .unwrap()
            .credential_by_key(&newphone.key())
            .is_some()
    );
    // A second use finds no code.
    net.send(&claim(&net.state, &thief), ready + 1).await.err();
    assert!(
        net.send(&reveal(&net.state, &thief, code), ready + 70_000)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn a_passkey_still_waiting_to_count_approves_nothing() {
    let mut net = Net::new().await;
    let phone = Device::synced(90, 0xaa);
    let intruder = Device::synced(91, 0xbb);
    let account = phone.account();

    // One approval links a second passkey; the account holds one root, so
    // the new passkey waits before it counts.
    let u = add(
        &net.state,
        &account,
        Some(phone.anchor()),
        &phone,
        &intruder,
    );
    net.send(&u, T0).await.unwrap();
    let record = read_record(&net.state, &account).unwrap();
    assert!(
        !record
            .credential_by_key(&intruder.key())
            .unwrap()
            .counts_at(T0 as u64 + 1)
    );

    // While it waits, it cannot remove the passkey that counts, set the
    // recovery signers or code, change the policy or cancel anything.
    let backup = TestHybridSigner::hybrid(92);
    let ops = vec![
        KeystoreOp::RemoveCredential {
            credential_id: phone.credential_id.clone(),
        },
        KeystoreOp::SetRecovery {
            signers: vec![RecoverySigner {
                rp_id: String::new(),
                public_key: backup.public_key().p256.clone(),
                aaguid: vec![0; 16],
                backup_eligible: false,
                backup_state: false,
                role: RecoveryRole::RecoveryKey,
                label: String::new(),
            }],
            threshold: 1,
        },
        KeystoreOp::SetRecoveryCode {
            commitment: Some(RecoveryCodeCommitment(
                recovery_code_commitment(CHAIN, &account, &[9u8; 32]).to_vec(),
            )),
        },
    ];
    for op in ops {
        let mut u = update(&account, &net.state, None, op.clone());
        u.approvals = vec![intruder.approve(&u)];
        assert!(
            net.send(&u, T0 + 1).await.is_err(),
            "a waiting passkey approved {op:?}"
        );
    }
    // Sent by the account itself, signed by the waiting passkey: refused too.
    net.state.set_balance(&slot(&account), ONE_TNZO);
    let remove = update(
        &account,
        &net.state,
        None,
        KeystoreOp::RemoveCredential {
            credential_id: phone.credential_id.clone(),
        },
    );
    assert!(
        net.run(sent_by_account(
            &intruder,
            &account,
            &remove,
            net.nonce(&account),
            T0 + 1
        ))
        .await
        .is_err()
    );
    let record = read_record(&net.state, &account).unwrap();
    assert!(record.credential_by_key(&phone.key()).is_some());
    assert!(record.recovery_signers.is_empty() && record.recovery_code.is_none());

    // The passkey that counts removes the waiting one with its own approval.
    let mut cancel = update(
        &account,
        &net.state,
        None,
        KeystoreOp::RemoveCredential {
            credential_id: intruder.credential_id.clone(),
        },
    );
    cancel.approvals = vec![phone.approve(&cancel)];
    net.send(&cancel, T0 + 2).await.unwrap();
    assert!(
        read_record(&net.state, &account)
            .unwrap()
            .credential_by_key(&intruder.key())
            .is_none()
    );

    // Once its wait has passed, a linked passkey approves like any other.
    let laptop = Device::synced(93, 0xcc);
    let u = add(&net.state, &account, None, &phone, &laptop);
    net.send(&u, T0 + 3).await.unwrap();
    let later = T0 + 3 + ADD_DEVICE_WAIT_MS as i64;
    let mut set = update(
        &account,
        &net.state,
        None,
        KeystoreOp::SetRecoveryCode {
            commitment: Some(RecoveryCodeCommitment(
                recovery_code_commitment(CHAIN, &account, &[8u8; 32]).to_vec(),
            )),
        },
    );
    set.approvals = vec![laptop.approve(&set)];
    net.send(&set, later).await.unwrap();
}

#[tokio::test]
async fn a_recovery_counts_only_approvals_that_verify() {
    let mut net = Net::new().await;
    let phone = Device::synced(94, 0xaa);
    let backup = TestHybridSigner::hybrid(95);
    let forger = TestHybridSigner::hybrid(96);
    let account = phone.account();
    let mut u = update(
        &account,
        &net.state,
        Some(phone.anchor()),
        KeystoreOp::SetRecovery {
            signers: vec![RecoverySigner {
                rp_id: String::new(),
                public_key: backup.public_key().p256.clone(),
                aaguid: vec![0; 16],
                backup_eligible: false,
                backup_state: false,
                role: RecoveryRole::RecoveryKey,
                label: String::new(),
            }],
            threshold: 1,
        },
    );
    u.approvals = vec![phone.approve(&u)];
    net.send(&u, T0).await.unwrap();
    let before = read_record(&net.state, &account).unwrap();

    let thief = Device::synced(97, 0xbb);
    let base = |state: &StateAdapter| {
        let mut u = update(
            &account,
            state,
            None,
            KeystoreOp::StartRecovery {
                credential: thief.credential(),
            },
        );
        u.possession = Some(thief.assert(SignatureContext::AccountOwner, &u.digest()));
        u
    };
    let digest = base(&net.state).digest();
    let other = {
        let mut o = base(&net.state);
        o.op = KeystoreOp::StartRecovery {
            credential: Device::synced(98, 0xcc).credential(),
        };
        o.digest()
    };
    let mut garbage = backup
        .sign(SignatureContext::RecoveryApproval, &digest)
        .unwrap();
    if let tenzro_crypto::composite::ClassicalProof::Raw { signature } = &mut garbage.classical {
        for b in signature.iter_mut() {
            *b ^= 0xff;
        }
    }
    let refused: Vec<(&str, CompositeSignature)> = vec![
        ("altered bytes", garbage),
        (
            "another key",
            forger
                .sign(SignatureContext::RecoveryApproval, &digest)
                .unwrap(),
        ),
        (
            "another change",
            backup
                .sign(SignatureContext::RecoveryApproval, &other)
                .unwrap(),
        ),
        (
            "another context",
            backup
                .sign(SignatureContext::AccountOwner, &digest)
                .unwrap(),
        ),
    ];
    for (what, signature) in refused {
        let mut u = base(&net.state);
        // The same approval named twice does not count twice either.
        u.approvals = vec![
            KeystoreApproval {
                public_key: backup.public_key().p256.clone(),
                signature: signature.clone(),
            },
            KeystoreApproval {
                public_key: backup.public_key().p256.clone(),
                signature,
            },
        ];
        assert!(
            net.send(&u, T0 + 1).await.is_err(),
            "{what} approved a recovery"
        );
        assert_eq!(read_record(&net.state, &account).unwrap(), before, "{what}");
    }
    let finish = update(&account, &net.state, None, KeystoreOp::FinishRecovery);
    assert!(net.send(&finish, T0 + 2).await.is_err());
    assert_eq!(read_record(&net.state, &account).unwrap(), before);
}

#[tokio::test]
async fn a_stranger_cannot_spend_the_accounts_balance_on_refused_recoveries() {
    let mut net = Net::new().await;
    let phone = Device::synced(101, 0xaa);
    let account = phone.account();
    let backup = TestHybridSigner::hybrid(102);
    let mut u = update(
        &account,
        &net.state,
        Some(phone.anchor()),
        KeystoreOp::SetRecovery {
            signers: vec![RecoverySigner {
                rp_id: String::new(),
                public_key: backup.public_key().p256.clone(),
                aaguid: vec![0; 16],
                backup_eligible: false,
                backup_state: false,
                role: RecoveryRole::RecoveryKey,
                label: String::new(),
            }],
            threshold: 1,
        },
    );
    u.approvals = vec![phone.approve(&u)];
    net.send(&u, T0).await.unwrap();
    net.state.set_balance(&slot(&account), ONE_TNZO);
    let balance = net.state.get_balance(&slot(&account));
    let nonce = net.nonce(&account);

    // A stranger names their own passkey as the one joining, with no
    // recovery signer's approval and no recovery code, and sends it from the
    // account so the account would pay.
    let stranger = Device::synced(103, 0xcc);
    let mut start = update(
        &account,
        &net.state,
        None,
        KeystoreOp::StartRecovery {
            credential: stranger.credential(),
        },
    );
    start.possession = Some(stranger.assert(SignatureContext::AccountOwner, &start.digest()));
    let mut reveal = update(
        &account,
        &net.state,
        None,
        KeystoreOp::RecoverWithCode {
            code: vec![1u8; 32],
            credential: stranger.credential(),
        },
    );
    reveal.possession = Some(stranger.assert(SignatureContext::AccountOwner, &reveal.digest()));
    for (i, u) in [start, reveal].iter().enumerate() {
        let _ = net
            .run(sent_by_account(
                &stranger,
                &account,
                u,
                nonce + i as u64,
                T0 + 1,
            ))
            .await;
    }
    assert_eq!(
        net.state.get_balance(&slot(&account)),
        balance,
        "the account paid"
    );
    assert_eq!(net.nonce(&account), nonce, "the account's nonce moved");
}

#[test]
fn a_passkey_still_waiting_to_count_roots_no_agent() {
    let phone = Device::synced(104, 0xaa);
    let intruder = Device::synced(105, 0xbb);
    let did = tenzro_types::keystore::human_did(&phone.key());
    let mut state = StateAdapter::new();
    let mut record = KeystoreRecord::genesis(&phone.anchor());
    let mut waiting = intruder.credential();
    let counts_from = T0 as u64 + ADD_DEVICE_WAIT_MS;
    waiting.counts_as_root_from_ms = counts_from;
    record.credentials.push(waiting);
    record.version = 1;
    tenzro_vm::keystore::write_record(&mut state, None, &record, &mut Vec::new()).unwrap();
    assert!(
        check_passkey_root(&state, &did, &intruder.key(), counts_from - 1).is_err(),
        "a passkey inside its add-device wait approved as the human root"
    );
    // The passkey that counts is unaffected, and the new one roots once its
    // wait has passed.
    check_passkey_root(&state, &did, &phone.key(), T0 as u64).unwrap();
    check_passkey_root(&state, &did, &intruder.key(), counts_from).unwrap();
}

/// The same passkey derives the same account on every chain, and every
/// chain starts it from the same genesis record, so an approval must name
/// the chain it was made for: replayed on another chain it is refused.
#[tokio::test]
async fn a_keystore_approval_for_one_chain_is_refused_on_another() {
    let phone = Device::synced(1, 0xaa);
    let laptop = Device::synced(2, 0xbb);
    let account = phone.account();

    let mut testnet = Net::new().await;
    let u = add(
        &testnet.state,
        &account,
        Some(phone.anchor()),
        &phone,
        &laptop,
    );
    testnet.send(&u, T0).await.unwrap();
    assert!(
        read_record(&testnet.state, &account)
            .unwrap()
            .credential_by_key(&laptop.key())
            .is_some()
    );

    let mut mainnet = Net::on_chain(testnet.chain_id + 1).await;
    assert!(
        mainnet.send(&u, T0).await.is_err(),
        "an approval made for one chain changed the keystore on another"
    );
    assert!(read_record(&mainnet.state, &account).is_none());

    // Renaming the chain in the change breaks every signature over it.
    let mut renamed = u.clone();
    renamed.chain_id = mainnet.chain_id;
    assert!(mainnet.send(&renamed, T0).await.is_err());
    assert!(read_record(&mainnet.state, &account).is_none());

    // Made for that chain, the same change applies there.
    let mut fresh = update(
        &account,
        &mainnet.state,
        Some(phone.anchor()),
        KeystoreOp::AddCredential {
            credential: laptop.credential(),
        },
    );
    fresh.chain_id = mainnet.chain_id;
    fresh.possession = Some(laptop.assert(SignatureContext::AccountOwner, &fresh.digest()));
    fresh.approvals = vec![phone.approve(&fresh)];
    mainnet.send(&fresh, T0).await.unwrap();
    assert!(
        read_record(&mainnet.state, &account)
            .unwrap()
            .credential_by_key(&laptop.key())
            .is_some()
    );
}

/// Twenty years of one account. Every four years the owner moves its synced
/// passkey to a new wallet provider, linked by the passkeys it holds, and
/// unlinks the old one when that provider closes; at year eight the
/// device-bound key and the guardian are replaced too. At year twenty every
/// passkey is lost and the current guardian restores the account to a new
/// one. The account address and balance carry through every step, and a
/// passkey or guardian once replaced never acts again.
#[tokio::test]
async fn an_account_outlives_its_wallet_providers_and_a_lost_passkey_over_twenty_years() {
    const YEAR: i64 = 365 * 24 * 60 * 60 * 1000;
    let mut net = Net::new().await;
    let providers = [
        "wallet-a.example",
        "wallet-b.example",
        "wallet-c.example",
        "wallet-d.example",
        "wallet-e.example",
    ];
    let first = Device::synced(100, 0xa0).at(providers[0]);
    let account = first.account();
    net.state.set_balance(&slot(&account), 100 * ONE_TNZO);
    let to = vec![0x77u8; 20];
    let signer = |g: &Device| RecoverySigner {
        rp_id: g.rp_id.to_string(),
        public_key: g.key(),
        aaguid: vec![g.aaguid; 16],
        backup_eligible: false,
        backup_state: false,
        role: RecoveryRole::Device,
        label: "guardian".to_string(),
    };
    let old_guardian = Device::bound(110).at("guardians-1.example");
    let new_guardian = Device::bound(111).at("guardians-2.example");
    let unlink = |state: &StateAdapter, gone: &Device, by: &Device| {
        let mut u = update(
            &account,
            state,
            None,
            KeystoreOp::RemoveCredential {
                credential_id: gone.credential_id.clone(),
            },
        );
        u.approvals = vec![by.approve(&u)];
        u
    };

    // Year 0: a synced passkey and a device-bound key, and a guardian.
    let mut bound = Device::bound(130).at("keys.example");
    net.send(
        &add(&net.state, &account, Some(first.anchor()), &first, &bound),
        T0,
    )
    .await
    .unwrap();
    let mut u = update(
        &account,
        &net.state,
        None,
        KeystoreOp::SetRecovery {
            signers: vec![signer(&old_guardian)],
            threshold: 1,
        },
    );
    u.approvals = vec![first.approve(&u)];
    net.send(&u, T0).await.unwrap();

    let mut synced = first;
    let mut retired: Vec<Device> = Vec::new();
    let mut paid = 0u128;
    for (g, rp) in providers.iter().enumerate().skip(1) {
        let at = T0 + g as i64 * 4 * YEAR;
        let next = Device::synced(100 + g as u8, 0xa0 + g as u8).at(rp);
        net.send(&add(&net.state, &account, None, &bound, &next), at)
            .await
            .unwrap();
        let usable = at + ADD_DEVICE_WAIT_MS as i64;
        net.send(&unlink(&net.state, &synced, &next), usable)
            .await
            .unwrap();
        retired.push(std::mem::replace(&mut synced, next));
        if g == 2 {
            let key = Device::bound(131).at("keys-2.example");
            net.send(&add(&net.state, &account, None, &synced, &key), usable)
                .await
                .unwrap();
            net.send(&unlink(&net.state, &bound, &synced), usable)
                .await
                .unwrap();
            retired.push(std::mem::replace(&mut bound, key));
            let mut u = update(
                &account,
                &net.state,
                None,
                KeystoreOp::SetRecovery {
                    signers: vec![signer(&new_guardian)],
                    threshold: 1,
                },
            );
            u.approvals = vec![synced.approve(&u)];
            net.send(&u, usable).await.unwrap();
        }
        let spend_at = usable + ADD_DEVICE_WAIT_MS as i64;
        net.run(transfer(
            &synced,
            &account,
            &to,
            net.nonce(&account),
            spend_at,
        ))
        .await
        .unwrap();
        paid += ONE_TNZO;
        for old in &retired {
            assert!(
                net.run(transfer(old, &account, &to, net.nonce(&account), spend_at))
                    .await
                    .is_err(),
                "a passkey unlinked earlier spent in year {}",
                g * 4
            );
        }
    }
    assert_eq!(net.state.get_balance(&to), paid);

    // Year 20: every passkey is lost.
    let lost_at = T0 + 20 * YEAR;
    let restored = Device::synced(140, 0xc0).at("wallet-f.example");
    let start = |state: &StateAdapter, g: &Device| {
        let mut u = update(
            &account,
            state,
            None,
            KeystoreOp::StartRecovery {
                credential: restored.credential(),
            },
        );
        u.possession = Some(restored.assert(SignatureContext::AccountOwner, &u.digest()));
        u.approvals = vec![KeystoreApproval {
            public_key: g.key(),
            signature: g.assert(SignatureContext::RecoveryApproval, &u.digest()),
        }];
        u
    };
    let refused = start(&net.state, &old_guardian);
    assert!(
        net.run(sent_by_account(
            &restored,
            &account,
            &refused,
            net.nonce(&account),
            lost_at
        ))
        .await
        .is_err(),
        "the replaced guardian approves nothing"
    );
    let approved = start(&net.state, &new_guardian);
    net.run(sent_by_account(
        &restored,
        &account,
        &approved,
        net.nonce(&account),
        lost_at,
    ))
    .await
    .unwrap();
    let ready = read_record(&net.state, &account)
        .unwrap()
        .pending_recovery
        .unwrap()
        .ready_at_ms as i64;
    let finish = update(&account, &net.state, None, KeystoreOp::FinishRecovery);
    net.run(sent_by_account(
        &restored,
        &account,
        &finish,
        net.nonce(&account),
        ready,
    ))
    .await
    .unwrap();
    let later = ready + ADD_DEVICE_WAIT_MS as i64;
    net.run(transfer(
        &restored,
        &account,
        &to,
        net.nonce(&account),
        later,
    ))
    .await
    .unwrap();
    assert_eq!(net.state.get_balance(&to), paid + ONE_TNZO);
    assert_eq!(
        resolve_credential(&net.state, "wallet-f.example", &restored.credential_id),
        vec![hex::encode(&account)]
    );
    for old in &retired {
        assert!(resolve_credential(&net.state, old.rp_id, &old.credential_id).is_empty());
    }
}

/// A transaction from the passkey account `account`, signed by `device`
/// with `sig`, requiring the ML-DSA-65 leg of every key acting for it.
fn require_pq_leg(
    device: &Device,
    account: &[u8],
    nonce: u64,
    at: i64,
    sig: CompositeSignature,
) -> VmTransaction {
    let mut data = tenzro_vm::account_keys::SELECTOR_ACCOUNT_KEYS.to_vec();
    data.extend_from_slice(
        &serde_json::to_vec(&tenzro_types::account_signature::AccountKeysOp::RequirePqLeg {})
            .unwrap(),
    );
    signed_tx(
        &slot(account),
        &device.key(),
        sig,
        data,
        Some(tenzro_vm::native::SYSTEM_ADDRESS.to_vec()),
        0,
        nonce,
        at,
    )
}

/// The digest [`signed_tx`] signs for `nonce`.
fn tx_digest(nonce: u64) -> Vec<u8> {
    vec![nonce as u8 ^ 0x5a; 32]
}

/// `device`'s passkey assertion over `digest`, with the ML-DSA-65 leg of `pq`.
fn with_pq_leg(
    device: &Device,
    pq: &TestHybridSigner,
    context: SignatureContext,
    digest: &[u8],
) -> CompositeSignature {
    let mut sig = device.assert(context, digest);
    sig.pq = pq.sign(context, digest).unwrap().pq;
    sig
}

/// The ML-DSA-65 leg is required of every passkey acting for an account: a
/// linked passkey with no ML-DSA-65 key enrolled spends nothing, approves no
/// change and authorizes no payment for it, so a break of that passkey's
/// P-256 key moves nothing. Only a key that carries the leg turns the
/// per-account requirement on.
#[tokio::test]
async fn an_account_refuses_a_passkey_without_an_ml_dsa_key_and_a_p256_leg_alone() {
    use tenzro_types::account_signature::enrolled_pq_key_storage_key;
    use tenzro_vm::account_keys::pq_required;
    use tenzro_vm::keystore::account_signing_key;
    let mut net = Net::new().await;
    let phone = Device::synced(10, 0xaa);
    let key = Device::bound(11);
    let account = phone.account();
    net.state.set_balance(&slot(&account), 10 * ONE_TNZO);
    let to = vec![0x78u8; 20];
    let u = add(&net.state, &account, Some(phone.anchor()), &phone, &key);
    net.send(&u, T0).await.unwrap();
    let at = T0 + ADD_DEVICE_WAIT_MS as i64;

    // The phone's passkey has an ML-DSA-65 key enrolled; the device-bound
    // key has none.
    let phone_pq = TestHybridSigner::hybrid(10);
    let slot_of_key = tenzro_crypto::composite::account_slot(&key.key());
    net.state.set_storage(
        &tenzro_vm::native::SYSTEM_ADDRESS,
        enrolled_pq_key_storage_key(&slot_of_key).as_bytes(),
        Vec::new(),
    );

    // The device-bound key spends, approves and pays nothing.
    let before = net.state.get_balance(&to);
    assert!(
        net.run(transfer(&key, &account, &to, net.nonce(&account), at))
            .await
            .is_err()
    );
    let third = Device::bound(13);
    let u = add(&net.state, &account, None, &key, &third);
    assert!(net.send(&u, at).await.is_err());
    assert_eq!(net.state.get_balance(&to), before);

    // Nor can it turn the requirement on.
    let n = net.nonce(&account);
    let sig = key.assert(SignatureContext::Transaction, &tx_digest(n));
    assert!(
        net.run(require_pq_leg(&key, &account, n, at, sig))
            .await
            .is_err()
    );
    assert!(!pq_required(&net.state, &slot(&account)));

    // The phone with its P-256 leg alone cannot either.
    let n = net.nonce(&account);
    let mut sig = phone.assert(SignatureContext::Transaction, &tx_digest(n));
    sig.pq = None;
    assert!(
        net.run(require_pq_leg(&phone, &account, n, at, sig))
            .await
            .is_err()
    );
    assert!(!pq_required(&net.state, &slot(&account)));

    // The phone, with both legs, turns it on.
    let n = net.nonce(&account);
    let sig = with_pq_leg(
        &phone,
        &phone_pq,
        SignatureContext::Transaction,
        &tx_digest(n),
    );
    net.run(require_pq_leg(&phone, &account, n, at, sig))
        .await
        .unwrap();
    assert!(pq_required(&net.state, &slot(&account)));
    assert!(account_signing_key(&net.state, &key.key(), &slot(&account), at as u64).is_err());

    // The phone spends with both legs and not with P-256 alone.
    let n = net.nonce(&account);
    let mut alone = phone.assert(SignatureContext::Transaction, &tx_digest(n));
    alone.pq = None;
    assert!(
        net.run(signed_tx(
            &slot(&account),
            &phone.key(),
            alone,
            Vec::new(),
            Some(to.clone()),
            ONE_TNZO,
            n,
            at,
        ))
        .await
        .is_err()
    );
    let n = net.nonce(&account);
    let sig = with_pq_leg(
        &phone,
        &phone_pq,
        SignatureContext::Transaction,
        &tx_digest(n),
    );
    net.run(signed_tx(
        &slot(&account),
        &phone.key(),
        sig,
        Vec::new(),
        Some(to.clone()),
        ONE_TNZO,
        n,
        at,
    ))
    .await
    .unwrap();
    assert_eq!(net.state.get_balance(&to), before + ONE_TNZO);
    assert!(account_signing_key(&net.state, &phone.key(), &slot(&account), at as u64).is_ok());
}

// ---- outflow policy: the guardian is a passkey, not a key the owner holds --

use tenzro_types::agent_terms::{AgentTermsApproval, custody_challenge_digest};
use tenzro_vm::account_outflow::{
    OP_OUTFLOW_GUARDIAN, Op as OutflowOp, SELECTOR_ACCOUNT_OUTFLOW, approval_target,
};

/// An outflow operation sent and paid for by the net's payer, which is also
/// the account the policy protects (its key is the "owner key").
fn outflow_tx(net: &Net, op: &OutflowOp, at: i64) -> VmTransaction {
    let mut data = SELECTOR_ACCOUNT_OUTFLOW.to_vec();
    data.extend_from_slice(&serde_json::to_vec(op).unwrap());
    let nonce = net.state.get_nonce(net.payer.address().as_bytes());
    let digest = vec![nonce as u8 ^ 0x5a; 32];
    let sig = net
        .payer
        .sign(SignatureContext::Transaction, &digest)
        .unwrap();
    let mut tx = signed_tx(
        net.payer.address().as_bytes(),
        &net.payer.public_key().p256,
        sig,
        data,
        Some(tenzro_vm::native::SYSTEM_ADDRESS.to_vec()),
        0,
        nonce,
        at,
    );
    tx.signing_digest = Some(digest);
    tx
}

/// The guardian's passkey approval of `action` on release `id` at counter
/// `step`, optionally claiming another relying party or carrying the
/// ML-DSA-65 leg of `pq`.
fn guardian_approval(
    device: &Device,
    account: &[u8],
    action: &str,
    id: u64,
    step: u64,
    n: u8,
    pq: Option<&TestHybridSigner>,
    rp: Option<&str>,
) -> AgentTermsApproval {
    let nonce = [n; 16];
    let target = approval_target(account, action, id, step);
    let digest = custody_challenge_digest(CHAIN, account, OP_OUTFLOW_GUARDIAN, &target, &nonce);
    let mut signature = match rp {
        Some(r) => device.assert_at(
            r,
            &format!("https://{r}"),
            SignatureContext::AccountOwner,
            &digest,
        ),
        None => device.assert(SignatureContext::AccountOwner, &digest),
    };
    if let Some(p) = pq {
        signature.pq = p.sign(SignatureContext::AccountOwner, &digest).unwrap().pq;
    }
    AgentTermsApproval {
        account: account.to_vec(),
        nonce,
        root_public_key: device.key(),
        signature,
    }
}

/// With a guardian set, the owner's key alone cannot claim early or cancel;
/// the guardian's passkey assertion, on the right relying party, for exactly
/// that action and counter, with the ML-DSA-65 leg once enrolled, can; and
/// an approval is good once.
#[tokio::test]
async fn the_guardian_passkey_is_needed_to_claim_early_or_cancel() {
    use tenzro_vm::account_keys::set_enrolled_pq_key;
    let mut net = Net::new().await;
    let phone = Device::synced(21, 0xaa);
    let laptop = Device::bound(22).at("wallet.example.org");
    let stranger = Device::synced(23, 0xaa);
    let wallet = phone.account();
    let did = tenzro_types::keystore::human_did(&phone.key());
    net.send(
        &add(&net.state, &wallet, Some(phone.anchor()), &phone, &laptop),
        T0,
    )
    .await
    .unwrap();
    let later = T0 + ADD_DEVICE_WAIT_MS as i64 + 10;

    let owner = net.payer.address().as_bytes().to_vec();
    let shop = vec![0x78u8; 20];
    let policy = OutflowOp::Set {
        account: owner.clone(),
        window_ms: 86_400_000,
        cap: ONE_TNZO,
        hold_ms: 3_600_000,
        guardian: Some(did.clone()),
    };
    net.run(outflow_tx(&net, &policy, later)).await.unwrap();
    let request = |amount| OutflowOp::RequestRelease {
        account: owner.clone(),
        to: shop.clone(),
        amount,
    };
    net.run(outflow_tx(&net, &request(5 * ONE_TNZO), later + 1))
        .await
        .unwrap();
    let claim = |id, approval| OutflowOp::ClaimRelease {
        account: owner.clone(),
        id,
        approval,
    };
    let cancel = |id, approval| OutflowOp::CancelRelease {
        account: owner.clone(),
        id,
        approval,
    };
    let t = later + 2;

    // A compromised owner key alone: no early claim, no cancel.
    assert!(net.run(outflow_tx(&net, &claim(0, None), t)).await.is_err());
    assert!(
        net.run(outflow_tx(&net, &cancel(0, None), t))
            .await
            .is_err()
    );
    // An approval made for another action does not claim (wrong challenge).
    let wrong_action = guardian_approval(&phone, &owner, "cancel_release", 0, 0, 1, None, None);
    assert!(
        net.run(outflow_tx(&net, &claim(0, Some(wrong_action)), t))
            .await
            .is_err()
    );
    // Nor one made for another release, or at another counter.
    let wrong_id = guardian_approval(&phone, &owner, "claim_release", 7, 0, 2, None, None);
    assert!(
        net.run(outflow_tx(&net, &claim(0, Some(wrong_id)), t))
            .await
            .is_err()
    );
    let wrong_step = guardian_approval(&phone, &owner, "claim_release", 0, 5, 3, None, None);
    assert!(
        net.run(outflow_tx(&net, &claim(0, Some(wrong_step)), t))
            .await
            .is_err()
    );
    // An assertion claiming another relying party is refused.
    let wrong_rp = guardian_approval(
        &phone,
        &owner,
        "claim_release",
        0,
        0,
        4,
        None,
        Some("evil.example"),
    );
    assert!(
        net.run(outflow_tx(&net, &claim(0, Some(wrong_rp)), t))
            .await
            .is_err()
    );
    // A passkey that is not the guardian's is refused.
    let impostor = guardian_approval(&stranger, &owner, "claim_release", 0, 0, 5, None, None);
    assert!(
        net.run(outflow_tx(&net, &claim(0, Some(impostor)), t))
            .await
            .is_err()
    );
    assert_eq!(net.state.get_balance(&shop), 0, "nothing moved");

    // The guardian's approval needs both legs.
    let phone_pq = TestHybridSigner::hybrid(21);
    set_enrolled_pq_key(
        &mut net.state,
        &phone.key(),
        phone_pq.public_key().pq.clone().unwrap(),
        &mut Vec::new(),
    );
    let mut p256_only = guardian_approval(&phone, &owner, "claim_release", 0, 0, 6, None, None);
    p256_only.signature.pq = None;
    assert!(
        net.run(outflow_tx(&net, &claim(0, Some(p256_only)), t))
            .await
            .is_err(),
        "the P-256 leg alone no longer passes"
    );
    let both = guardian_approval(
        &phone,
        &owner,
        "claim_release",
        0,
        0,
        7,
        Some(&phone_pq),
        None,
    );
    net.run(outflow_tx(&net, &claim(0, Some(both.clone())), t))
        .await
        .unwrap();
    assert_eq!(net.state.get_balance(&shop), 5 * ONE_TNZO);
    // The same approval again is refused.
    assert!(
        net.run(outflow_tx(&net, &claim(0, Some(both)), t))
            .await
            .is_err()
    );

    // Two more releases. An approval signed for the counter before another
    // approval was used cannot be used after it (replay of a stale one).
    net.run(outflow_tx(&net, &request(ONE_TNZO), t + 1))
        .await
        .unwrap();
    net.run(outflow_tx(&net, &request(ONE_TNZO), t + 2))
        .await
        .unwrap();
    let step = 1; // one approval has been used
    let first = guardian_approval(
        &phone,
        &owner,
        "cancel_release",
        1,
        step,
        8,
        Some(&phone_pq),
        None,
    );
    let stale = guardian_approval(
        &phone,
        &owner,
        "cancel_release",
        2,
        step,
        9,
        Some(&phone_pq),
        None,
    );
    net.run(outflow_tx(&net, &cancel(1, Some(first)), t + 3))
        .await
        .unwrap();
    assert!(
        net.run(outflow_tx(&net, &cancel(2, Some(stale)), t + 4))
            .await
            .is_err(),
        "an approval made for a counter that has moved is refused"
    );
    // A passkey from another wallet provider, linked to the identity, also
    // approves, on its own relying party.
    let fresh = guardian_approval(
        &laptop,
        &owner,
        "cancel_release",
        2,
        step + 1,
        10,
        None,
        None,
    );
    let laptop_has_pq = net
        .run(outflow_tx(&net, &cancel(2, Some(fresh)), t + 5))
        .await;
    // The ML-DSA-65 key enrolled for the phone does not bind the laptop's.
    laptop_has_pq.unwrap();

    // The owner's key alone still claims a release once its hold has run out.
    net.run(outflow_tx(&net, &request(ONE_TNZO), t + 6))
        .await
        .unwrap();
    assert!(
        net.run(outflow_tx(&net, &claim(3, None), t + 7))
            .await
            .is_err(),
        "before the hold has run out"
    );
    net.run(outflow_tx(&net, &claim(3, None), t + 3_600_100))
        .await
        .unwrap();
}
