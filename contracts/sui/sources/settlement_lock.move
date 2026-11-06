// SPDX-License-Identifier: Apache-2.0
/// Tenzro settlement-plan legs on Sui.
///
/// A payer locks a coin as leg `index` of plan `plan_id`, payable to a
/// recipient. The leg settles once, on the plan's decision proven under the
/// state root of a final checkpoint held by Tenzro's finality client on Sui:
/// a commit pays the recipient, an abort refunds the payer. Without a proven
/// decision the payer reclaims the leg only after the escape horizon. No key
/// holds any authority here.
///
/// The decision commitment at `decision:<plan_id>` is
/// `version (1) || outcome (1: 1 commit, 2 abort) || decided_at_ms (8) || plan_id (32)`.
///
/// Every lock, release and refund folds into a running reconciliation hash;
/// `checkpoint` emits it with the entry count, for Tenzro to compare with its
/// own books.
module tenzro_bridge::settlement_lock;

use std::hash::sha2_256;
use std::type_name;
use sui::balance::Balance;
use sui::clock::Clock;
use sui::coin::{Self, Coin};
use sui::dynamic_field as df;
use sui::event;
use tenzro_bridge::agent_account::{Self, AgentAccount};
use tenzro_bridge::finality_client::{Self, FinalityClient};

const EWrongClient: u64 = 300;
const EAlreadyLocked: u64 = 301;
const ENotLocked: u64 = 302;
const EBadAmount: u64 = 303;
const EUnproven: u64 = 304;
const ETooEarly: u64 = 305;
const EBadPlanId: u64 = 306;
const ENotThisLock: u64 = 307;
const EBadLockData: u64 = 308;

const LOCKED: u8 = 1;
const RELEASED: u8 = 2;
const REFUNDED: u8 = 3;
const DECISION_LEN: u64 = 42;
const HEX: vector<u8> = b"0123456789abcdef";
const RECON_DOMAIN: vector<u8> = b"tenzro/settlement/recon/v1";

/// The lock: legs by leg id, bound to Tenzro's finality client.
public struct SettlementLock has key {
    id: UID,
    client: ID,
    escape_horizon_ms: u64,
    /// Entries recorded and the running reconciliation hash over them.
    recon_count: u64,
    recon_acc: vector<u8>,
}

public struct LegKey has copy, drop, store {
    leg_id: vector<u8>,
}

/// A locked leg of coin type `T`.
public struct Leg<phantom T> has store {
    payer: address,
    recipient: address,
    held: Balance<T>,
    amount: u64,
    escape_at_ms: u64,
    stage: u8,
}

public struct Locked has copy, drop {
    plan_id: vector<u8>,
    leg_id: vector<u8>,
    index: u8,
    payer: address,
    recipient: address,
    /// The coin type, `asset_id<T>()`.
    asset: address,
    amount: u64,
    escape_at_ms: u64,
}

/// The lock's reconciliation checkpoint.
public struct Accumulator has copy, drop {
    count: u64,
    acc: vector<u8>,
}

public struct Released has copy, drop {
    plan_id: vector<u8>,
    leg_id: vector<u8>,
    to: address,
    amount: u64,
}

public struct Refunded has copy, drop {
    plan_id: vector<u8>,
    leg_id: vector<u8>,
    to: address,
    amount: u64,
    escaped: bool,
}

/// Share a lock reading final state roots from `client`, letting an
/// undecided leg escape `escape_horizon_ms` after it was locked.
public fun create(client: &FinalityClient, escape_horizon_ms: u64, ctx: &mut TxContext): ID {
    let lock = SettlementLock {
        id: object::new(ctx),
        client: object::id(client),
        escape_horizon_ms,
        recon_count: 0,
        recon_acc: vector::tabulate!(32, |_| 0u8),
    };
    let id = object::id(&lock);
    transfer::share_object(lock);
    id
}

/// The id Tenzro gives leg `index` of `plan_id`.
public fun leg_id(plan_id: vector<u8>, index: u8): vector<u8> {
    assert!(plan_id.length() == 32, EBadPlanId);
    let mut b = b"tenzro/plan/leg/v1";
    b.append(plan_id);
    b.push_back(index);
    sha2_256(b)
}

/// The state tree key of `decision:<plan_id>`: VM system storage, keyed by
/// the hex of the record key.
public fun decision_tree_key(plan_id: vector<u8>): vector<u8> {
    let mut record = b"decision:";
    record.append(hex(&plan_id));
    let mut b = b"tenzro.state-trie.key";
    b.append(x"0500");
    b.append(b"state");
    b.append(b"storage:");
    let mut i = 0u64;
    while (i < 40) {
        b.push_back(0x66);
        i = i + 1;
    };
    b.push_back(0x3a);
    b.append(hex(&record));
    sha2_256(b)
}

fun hex(v: &vector<u8>): vector<u8> {
    let digits = HEX;
    let mut out = vector[];
    let mut i = 0;
    while (i < v.length()) {
        out.push_back(digits[((v[i] >> 4) as u64)]);
        out.push_back(digits[((v[i] & 15) as u64)]);
        i = i + 1;
    };
    out
}

/// The stage of leg `index` of `plan_id` (1 locked, 2 released, 3 refunded).
public fun stage<T>(lock: &SettlementLock, plan_id: vector<u8>, index: u8): u8 {
    let key = LegKey { leg_id: leg_id(plan_id, index) };
    assert!(df::exists(&lock.id, key), ENotLocked);
    df::borrow<LegKey, Leg<T>>(&lock.id, key).stage
}

/// How a `Locked` event names coin type `T`: SHA-256 of its type name with
/// defining ids, as an address. A Tenzro lock leg names its asset this way.
public fun asset_id<T>(): address {
    sui::address::from_bytes(sha2_256(type_name::with_defining_ids<T>().into_string().into_bytes()))
}

/// Lock `coin` as leg `index` of `plan_id`, payable to `recipient`.
public fun lock<T>(
    lock: &mut SettlementLock,
    plan_id: vector<u8>,
    index: u8,
    coin: Coin<T>,
    recipient: address,
    clock: &Clock,
    ctx: &TxContext,
) {
    lock_as<T>(lock, plan_id, index, coin, ctx.sender(), recipient, clock);
}

/// Lock a leg paid by agent account `account`: its signed action names this
/// lock as the target, `lock` as the selector, and plan id (32 bytes), leg
/// index (1 byte) and recipient (32 bytes) as the data. The account hands
/// over a coin of exactly the action's amount and is the leg's payer.
public fun lock_from_agent<T>(
    lock: &mut SettlementLock,
    account: &mut AgentAccount,
    clock: &Clock,
    action: vector<u8>,
    keys: vector<vector<u8>>,
    operators: vector<vector<u8>>,
    key_proofs: vector<vector<u8>>,
    signatures: vector<vector<u8>>,
    target_proof: vector<u8>,
    ctx: &mut TxContext,
) {
    let (target, selector, data, coin, payer) =
        agent_account::act_take<T>(account, clock, action, keys, operators, key_proofs, signatures, target_proof, ctx);
    lock_signed<T>(lock, target, selector, data, coin, payer, clock);
}

/// `lock_from_agent` for the one action of an exact grant.
public fun lock_exact_from_agent<T>(
    lock: &mut SettlementLock,
    account: &mut AgentAccount,
    clock: &Clock,
    action: vector<u8>,
    ctx: &mut TxContext,
) {
    let (target, selector, data, coin, payer) = agent_account::act_exact_take<T>(account, clock, action, ctx);
    lock_signed<T>(lock, target, selector, data, coin, payer, clock);
}

fun lock_signed<T>(
    lock: &mut SettlementLock,
    target: vector<u8>,
    selector: vector<u8>,
    data: vector<u8>,
    coin: Coin<T>,
    payer: address,
    clock: &Clock,
) {
    assert!(target == sui::address::to_bytes(object::id_address(lock)) && selector == b"lock", ENotThisLock);
    assert!(data.length() == 65, EBadLockData);
    let mut plan_id = vector[];
    let mut i = 0;
    while (i < 32) { plan_id.push_back(data[i]); i = i + 1; };
    let mut r = vector[];
    i = 33;
    while (i < 65) { r.push_back(data[i]); i = i + 1; };
    lock_as<T>(lock, plan_id, data[32], coin, payer, sui::address::from_bytes(r), clock);
}

fun lock_as<T>(
    lock: &mut SettlementLock,
    plan_id: vector<u8>,
    index: u8,
    coin: Coin<T>,
    payer: address,
    recipient: address,
    clock: &Clock,
) {
    let id = leg_id(plan_id, index);
    let key = LegKey { leg_id: id };
    assert!(!df::exists(&lock.id, key), EAlreadyLocked);
    let amount = coin.value();
    assert!(amount > 0, EBadAmount);
    let escape_at_ms = clock.timestamp_ms() + lock.escape_horizon_ms;
    let leg = Leg<T> { payer, recipient, held: coin.into_balance(), amount, escape_at_ms, stage: LOCKED };
    df::add(&mut lock.id, key, leg);
    record(lock, plan_id, id, LOCKED, amount);
    event::emit(Locked { plan_id, leg_id: id, index, payer, recipient, asset: asset_id<T>(), amount, escape_at_ms });
}

/// Settle leg `index` of `plan_id` on the decision at `decision:<plan_id>`,
/// proven by `proof` under final checkpoint `checkpoint`. Anyone may call.
public fun settle<T>(
    lock: &mut SettlementLock,
    client: &FinalityClient,
    plan_id: vector<u8>,
    index: u8,
    checkpoint: u64,
    decision: vector<u8>,
    proof: vector<u8>,
    ctx: &mut TxContext,
) {
    assert!(lock.client == object::id(client), EWrongClient);
    let id = leg_id(plan_id, index);
    let key = LegKey { leg_id: id };
    assert!(df::exists(&lock.id, key), ENotLocked);
    let root = finality_client::state_root(client, checkpoint);
    assert!(decision.length() == DECISION_LEN && decision[0] == 1, EUnproven);
    let mut i = 0;
    while (i < 32) {
        assert!(decision[10 + i] == plan_id[i], EUnproven);
        i = i + 1;
    };
    let outcome = decision[1];
    assert!(outcome == 1 || outcome == 2, EUnproven);
    assert!(agent_account::verify_at(&root, &decision_tree_key(plan_id), &decision, &proof), EUnproven);
    let leg = df::borrow_mut<LegKey, Leg<T>>(&mut lock.id, key);
    assert!(leg.stage == LOCKED, ENotLocked);
    let amount = leg.amount;
    let coin = coin::from_balance(leg.held.withdraw_all(), ctx);
    let stage = if (outcome == 1) RELEASED else REFUNDED;
    leg.stage = stage;
    let to = if (outcome == 1) leg.recipient else leg.payer;
    transfer::public_transfer(coin, to);
    record(lock, plan_id, id, stage, amount);
    if (outcome == 1) event::emit(Released { plan_id, leg_id: id, to, amount })
    else event::emit(Refunded { plan_id, leg_id: id, to, amount, escaped: false });
}

/// Reclaim an undecided leg once its escape horizon has passed.
public fun escape<T>(lock: &mut SettlementLock, plan_id: vector<u8>, index: u8, clock: &Clock, ctx: &mut TxContext) {
    let id = leg_id(plan_id, index);
    let key = LegKey { leg_id: id };
    assert!(df::exists(&lock.id, key), ENotLocked);
    let leg = df::borrow_mut<LegKey, Leg<T>>(&mut lock.id, key);
    assert!(leg.stage == LOCKED, ENotLocked);
    assert!(clock.timestamp_ms() >= leg.escape_at_ms, ETooEarly);
    leg.stage = REFUNDED;
    let amount = leg.amount;
    let to = leg.payer;
    transfer::public_transfer(coin::from_balance(leg.held.withdraw_all(), ctx), to);
    record(lock, plan_id, id, REFUNDED, amount);
    event::emit(Refunded { plan_id, leg_id: id, to, amount, escaped: true });
}

/// The entries recorded and the running reconciliation hash over them.
public fun reconciliation(lock: &SettlementLock): (u64, vector<u8>) {
    (lock.recon_count, lock.recon_acc)
}

/// Emit the running reconciliation hash and its entry count, for Tenzro to
/// prove and compare with its own books.
public fun checkpoint(lock: &SettlementLock) {
    event::emit(Accumulator { count: lock.recon_count, acc: lock.recon_acc });
}

/// Fold one entry into the running reconciliation hash:
/// `sha256(domain || acc || plan_id || leg_id || kind || amount)`, the
/// amount as a 32-byte big-endian word.
fun record(lock: &mut SettlementLock, plan_id: vector<u8>, leg_id: vector<u8>, kind: u8, amount: u64) {
    let mut b = RECON_DOMAIN;
    b.append(lock.recon_acc);
    b.append(plan_id);
    b.append(leg_id);
    b.push_back(kind);
    let mut i = 0;
    while (i < 24) {
        b.push_back(0);
        i = i + 1;
    };
    let mut shift = 56;
    loop {
        b.push_back(((amount >> shift) & 0xff) as u8);
        if (shift == 0) break;
        shift = shift - 8;
    };
    lock.recon_acc = sha2_256(b);
    lock.recon_count = lock.recon_count + 1;
}
