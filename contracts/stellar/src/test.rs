// SPDX-License-Identifier: Apache-2.0
extern crate std;

use k256::ecdsa::SigningKey;
use sha3::{Digest, Keccak256};
use soroban_sdk::testutils::{Address as _, Events as _};
use soroban_sdk::token::{StellarAssetClient, TokenClient};
use soroban_sdk::xdr::FromXdr;
use soroban_sdk::{Address, Bytes, BytesN, Env, Vec};

use crate::{Bridge, BridgeClient};

/// The record Tenzro's Stellar route decodes for the transfer sent in
/// `a_transfer_to_tenzro_emits_the_record_tenzro_decodes`.
const TRANSFER_OUT: &str = "000000000000000100000000000000650000000000001e61000000000000000000000000000000000000000000000000000000000000000b222222222222222222222222222222222222222222222222222222222222222244444444444444444444444444444444444444444444444444444444444444445555555555555555555555555555555555555555555555555555555555555555000000000000000029a2241af62c0000";

/// That transfer's contract event, in XDR.
const TRANSFER_OUT_EVENT: &str = "000000000000000133333333333333333333333333333333333333333333333333333333333333330000000100000000000000010000000f0000000c7472616e736665725f6f75740000000d000000a8000000000000000100000000000000650000000000001e61000000000000000000000000000000000000000000000000000000000000000b222222222222222222222222222222222222222222222222222222222222222244444444444444444444444444444444444444444444444444444444444444445555555555555555555555555555555555555555555555555555555555555555000000000000000029a2241af62c0000";

/// An outbound record Tenzro stores for the contract at `[0x33; 32]`, and
/// the digest its committee signs.
const OUTBOUND: &str = "00000000000000070000000000001e610000000000000065111111111111111111111111111111111111111111111111111111111111111122222222222222222222222222222222222222222222222222222222222222223333333333333333333333333333333333333333333333333333333333333333000000000000000000000000000000000000000000000000000000000000000b00000000000000004563918244f40000";
const OUTBOUND_DIGEST: &str = "62623cded6b64c9ef0ccea4a915698212ccce60b20d8f2f8ef648a0ba1c21700";

/// The digest that hands this contract over to set 2 of members
/// `[0x41; 20]`, `[0x42; 20]`, `[0x43; 20]`, threshold 2, expiring at Unix
/// second 2,000,000,000.
const HANDOVER_DIGEST: &str = "3b76ad26d675f4c705aca15d11557da4c9ad6d5ee1936de26e015485ae759a7e";

fn hex(b: &[u8]) -> std::string::String {
    b.iter().map(|x| std::format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> std::vec::Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32].into()).unwrap()
}

fn eth_address(env: &Env, k: &SigningKey) -> BytesN<20> {
    let point = k.verifying_key().to_encoded_point(false);
    let h = Keccak256::digest(&point.as_bytes()[1..]);
    BytesN::from_array(env, &h[12..].try_into().unwrap())
}

fn sign(env: &Env, seeds: &[u8], digest: &[u8; 32]) -> Vec<BytesN<65>> {
    let mut out = Vec::new(env);
    for s in seeds {
        let (sig, rid) = key(*s).sign_prehash_recoverable(digest).unwrap();
        let mut b = [0u8; 65];
        b[..64].copy_from_slice(&sig.to_bytes());
        b[64] = rid.to_byte();
        out.push_back(BytesN::from_array(env, &b));
    }
    out
}

fn account(env: &Env, key: [u8; 32]) -> Address {
    let mut x = std::vec![0, 0, 0, 18, 0, 0, 0, 0, 0, 0, 0, 0];
    x.extend_from_slice(&key);
    Address::from_xdr(env, &Bytes::from_slice(env, &x)).unwrap()
}

fn contract_at(env: &Env, id: [u8; 32]) -> Address {
    let mut x = std::vec![0, 0, 0, 18, 0, 0, 0, 1];
    x.extend_from_slice(&id);
    Address::from_xdr(env, &Bytes::from_slice(env, &x)).unwrap()
}

struct Setup {
    env: Env,
    id: Address,
    asset: Address,
    asset_xdr: soroban_sdk::xdr::Asset,
}

fn add_ledger_entry(env: &Env, key: soroban_sdk::xdr::LedgerKey, data: soroban_sdk::xdr::LedgerEntryData) {
    use soroban_sdk::xdr::{LedgerEntry, LedgerEntryExt};
    let entry = LedgerEntry { data, last_modified_ledger_seq: 0, ext: LedgerEntryExt::V0 };
    env.host().add_ledger_entry(&std::rc::Rc::new(key), &std::rc::Rc::new(entry), None).unwrap();
}

/// Give the account `a` a ledger entry and a trustline for the asset, as a
/// holder of a Stellar asset has.
fn hold(s: &Setup, a: &Address) {
    use soroban_sdk::xdr::*;
    let ScAddress::Account(account_id) = ScAddress::from(a) else { panic!("an account") };
    add_ledger_entry(
        &s.env,
        LedgerKey::Account(LedgerKeyAccount { account_id: account_id.clone() }),
        LedgerEntryData::Account(AccountEntry {
            account_id: account_id.clone(),
            balance: 0,
            flags: 0,
            home_domain: Default::default(),
            inflation_dest: None,
            num_sub_entries: 0,
            seq_num: SequenceNumber(0),
            thresholds: Thresholds([1; 4]),
            signers: VecM::default(),
            ext: AccountEntryExt::V0,
        }),
    );
    let asset = match s.asset_xdr.clone() {
        Asset::Native => TrustLineAsset::Native,
        Asset::CreditAlphanum4(x) => TrustLineAsset::CreditAlphanum4(x),
        Asset::CreditAlphanum12(x) => TrustLineAsset::CreditAlphanum12(x),
    };
    add_ledger_entry(
        &s.env,
        LedgerKey::Trustline(LedgerKeyTrustLine { account_id: account_id.clone(), asset: asset.clone() }),
        LedgerEntryData::Trustline(TrustLineEntry {
            account_id,
            asset,
            balance: 0,
            limit: i64::MAX,
            flags: TrustLineFlags::AuthorizedFlag as u32,
            ext: TrustLineEntryExt::V0,
        }),
    );
}

impl Setup {
    fn bridge(&self) -> BridgeClient<'_> {
        BridgeClient::new(&self.env, &self.id)
    }
}

fn setup() -> Setup {
    let env = Env::new_with_config(soroban_sdk::testutils::EnvTestConfig { capture_snapshot_at_drop: false });
    env.mock_all_auths();
    let id = contract_at(&env, [0x33; 32]);
    env.register_at(&id, Bridge, ());
    let issuer = Address::generate(&env);
    let sac = env.register_stellar_asset_contract_v2(issuer);
    let (asset, asset_xdr) = (sac.address(), sac.asset());
    StellarAssetClient::new(&env, &asset).set_admin(&id);
    let bridge = BridgeClient::new(&env, &id);
    let committee = Vec::from_array(&env, [eth_address(&env, &key(1)), eth_address(&env, &key(2)), eth_address(&env, &key(3))]);
    bridge.initialize(
        &asset,
        &1337,
        &Bytes::from_slice(&env, b"bridge_route:contract:stellar"),
        &101,
        &7777,
        &BytesN::from_array(&env, &[0x22; 32]),
        &BytesN::from_array(&env, &[0x44; 32]),
        &committee,
        &2,
        &1,
        &1_000_000,
    );
    Setup { env, id, asset, asset_xdr }
}

#[test]
fn a_transfer_to_tenzro_emits_the_record_tenzro_decodes() {
    let s = setup();
    let user = account(&s.env, {
        let mut k = [0u8; 32];
        k[31] = 0x0b;
        k
    });
    hold(&s, &user);
    StellarAssetClient::new(&s.env, &s.asset).mint(&user, &30_000_000);
    s.bridge().send_to_tenzro(&user, &30_000_000, &BytesN::from_array(&s.env, &[0x55; 32]));
    use soroban_sdk::xdr::{ContractEventBody, Limits, ScVal, WriteXdr};
    let events = s.env.events().all().filter_by_contract(&s.id);
    let event = events.events().last().unwrap().clone();
    let ContractEventBody::V0(body) = &event.body;
    assert_eq!(body.topics.len(), 1);
    let ScVal::Bytes(record) = &body.data else { panic!("the data is the record's bytes") };
    assert_eq!(record.as_slice(), unhex(TRANSFER_OUT).as_slice());
    // The event exactly as the ledger records it, which Tenzro's Stellar
    // route decodes.
    assert_eq!(hex(&event.to_xdr(Limits::none()).unwrap()), TRANSFER_OUT_EVENT);
    assert_eq!(TokenClient::new(&s.env, &s.asset).balance(&user), 0);
    assert_eq!(s.bridge().sequence(), 1);
}

#[test]
fn the_committee_digest_is_the_one_tenzro_computes() {
    let s = setup();
    let digest = s.bridge().outbound_digest(&Bytes::from_slice(&s.env, &unhex(OUTBOUND)));
    assert_eq!(digest.to_array().to_vec(), unhex(OUTBOUND_DIGEST));
}

#[test]
fn a_record_the_committee_signed_is_executed_once() {
    let s = setup();
    let record = Bytes::from_slice(&s.env, &unhex(OUTBOUND));
    let digest: [u8; 32] = unhex(OUTBOUND_DIGEST).try_into().unwrap();
    let mut k = [0u8; 32];
    k[31] = 0x0b;
    hold(&s, &account(&s.env, k));
    s.bridge().execute(&record, &sign(&s.env, &[1, 3], &digest));
    assert!(s.bridge().is_executed(&7));
    assert_eq!(TokenClient::new(&s.env, &s.asset).balance(&account(&s.env, k)), 50_000_000);
    assert!(s.bridge().try_execute(&record, &sign(&s.env, &[2, 3], &digest)).is_err());
}

#[test]
fn signatures_short_of_a_quorum_or_over_another_record_are_refused() {
    let s = setup();
    let record = Bytes::from_slice(&s.env, &unhex(OUTBOUND));
    let digest: [u8; 32] = unhex(OUTBOUND_DIGEST).try_into().unwrap();
    assert!(s.bridge().try_execute(&record, &sign(&s.env, &[2, 2], &digest)).is_err());
    assert!(s.bridge().try_execute(&record, &sign(&s.env, &[1, 9], &digest)).is_err());
    let mut tampered = unhex(OUTBOUND);
    tampered[150] ^= 1;
    assert!(s.bridge().try_execute(&Bytes::from_slice(&s.env, &tampered), &sign(&s.env, &[1, 2], &digest)).is_err());
    assert!(!s.bridge().is_executed(&7));
}

#[test]
fn the_handover_digest_is_the_one_tenzro_computes() {
    let s = setup();
    let members = Vec::from_array(&s.env, [0x41u8, 0x42, 0x43].map(|b| BytesN::from_array(&s.env, &[b; 20])));
    let digest = s.bridge().handover_digest(&2, &members, &2, &2_000_000_000);
    assert_eq!(hex(&digest.to_array()), HANDOVER_DIGEST);
}

#[test]
fn the_committee_hands_over_only_with_its_own_quorum_to_a_higher_set() {
    let s = setup();
    let next = Vec::from_array(&s.env, [eth_address(&s.env, &key(4)), eth_address(&s.env, &key(5)), eth_address(&s.env, &key(6))]);
    let digest = s.bridge().handover_digest(&2, &next, &2, &2_000_000).to_array();
    let mut m = b"tenzro/bridge/route-committee".to_vec();
    m.extend_from_slice(&1337u64.to_be_bytes());
    m.extend_from_slice(&(29u64).to_be_bytes());
    m.extend_from_slice(b"bridge_route:contract:stellar");
    m.extend_from_slice(&2u32.to_be_bytes());
    m.extend_from_slice(&3u32.to_be_bytes());
    for k in [4u8, 5, 6] {
        m.extend_from_slice(&eth_address(&s.env, &key(k)).to_array());
    }
    m.extend_from_slice(&2u32.to_be_bytes());
    m.extend_from_slice(&2_000_000u64.to_be_bytes());
    assert_eq!(digest, <[u8; 32]>::from(Keccak256::digest(&m)));
    assert!(s.bridge().try_rotate_committee(&2, &next, &2, &2_000_000, &sign(&s.env, &[4, 5], &digest)).is_err());
    let same = s.bridge().handover_digest(&1, &next, &2, &2_000_000).to_array();
    assert!(
        s.bridge().try_rotate_committee(&1, &next, &2, &2_000_000, &sign(&s.env, &[1, 2], &same)).is_err(),
        "the set index it already holds is refused"
    );
    s.bridge().rotate_committee(&2, &next, &2, &2_000_000, &sign(&s.env, &[1, 2], &digest));
    assert_eq!(s.bridge().committee_set(), (2, 2_000_000));
    // A replay of the same handover is stale.
    assert!(s.bridge().try_rotate_committee(&2, &next, &2, &2_000_000, &sign(&s.env, &[1, 2], &digest)).is_err());
    let mut k = [0u8; 32];
    k[31] = 0x0b;
    hold(&s, &account(&s.env, k));
    let record = Bytes::from_slice(&s.env, &unhex(OUTBOUND));
    let outbound: [u8; 32] = unhex(OUTBOUND_DIGEST).try_into().unwrap();
    assert!(s.bridge().try_execute(&record, &sign(&s.env, &[1, 2], &outbound)).is_err(), "the old committee no longer executes");
    s.bridge().execute(&record, &sign(&s.env, &[4, 6], &outbound));
}

#[test]
fn an_expired_committee_neither_executes_nor_hands_over() {
    use soroban_sdk::testutils::Ledger as _;
    let s = setup();
    s.env.ledger().with_mut(|l| l.timestamp = 1_000_001);
    let mut k = [0u8; 32];
    k[31] = 0x0b;
    hold(&s, &account(&s.env, k));
    let record = Bytes::from_slice(&s.env, &unhex(OUTBOUND));
    let outbound: [u8; 32] = unhex(OUTBOUND_DIGEST).try_into().unwrap();
    assert!(s.bridge().try_execute(&record, &sign(&s.env, &[1, 2], &outbound)).is_err());
    let next = Vec::from_array(&s.env, [eth_address(&s.env, &key(4)), eth_address(&s.env, &key(5)), eth_address(&s.env, &key(6))]);
    let digest = s.bridge().handover_digest(&2, &next, &2, &2_000_000).to_array();
    assert!(s.bridge().try_rotate_committee(&2, &next, &2, &2_000_000, &sign(&s.env, &[1, 2], &digest)).is_err());
}
