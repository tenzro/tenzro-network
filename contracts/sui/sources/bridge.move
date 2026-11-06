// SPDX-License-Identifier: Apache-2.0
/// Tenzro's bridge module on Sui.
///
/// TNZO on Sui is the coin `BRIDGE`, minted only against TNZO locked on
/// Tenzro and burned when it goes back. A transfer to Tenzro burns the coin
/// and emits `TransferOut`, the record Tenzro's Sui route decodes. A transfer
/// from Tenzro is the record Tenzro stored for it, executed once the route's
/// committee signed its digest: `threshold` distinct members, each recovered
/// from a secp256k1 signature over Keccak-256 of the outbound domain,
/// Tenzro's chain id, the route key and the record.
///
/// Tenzro draws each committee from its bonded attestors and numbers it with
/// a set index. The committee this module trusts hands it over to a later
/// one by signing that committee's set index, members, threshold and expiry
/// (`handover_preimage`); any relayer submits the handover, which is
/// accepted only for a higher set index. The module stops trusting a
/// committee at its expiry, so a committee whose members may have left their
/// bonds on Tenzro can never act here.
///
/// Amounts in records are TNZO's smallest unit (18 decimals); the coin has 9,
/// so a record's amount is the coin value times 10^9.
module tenzro_bridge::bridge;

use sui::bcs;
use sui::clock::Clock;
use sui::coin::{Self, Coin, TreasuryCap};
use sui::coin_registry;
use sui::ecdsa_k1;
use sui::event;
use sui::hash::keccak256;
use sui::table::{Self, Table};

/// Smallest TNZO units per coin unit.
const SCALE: u128 = 1_000_000_000;
const OUTBOUND_DOMAIN: vector<u8> = b"tenzro/bridge/route-outbound";
const COMMITTEE_DOMAIN: vector<u8> = b"tenzro/bridge/route-committee";
const KECCAK256: u8 = 0;

const ENotConfigured: u64 = 1;
const EBelowThreshold: u64 = 2;
const EWrongRoute: u64 = 3;
const EAlreadyExecuted: u64 = 4;
const EBadAmount: u64 = 5;
const EBadCommittee: u64 = 6;
const EMalformedRecord: u64 = 7;
const EExpired: u64 = 8;
const EStaleSet: u64 = 9;

/// The coin's one-time witness.
public struct BRIDGE has drop {}

/// Lets its holder configure the bridge once.
public struct AdminCap has key, store { id: UID }

/// The bridge: the coin's treasury, the route's identifiers and committee,
/// and the records already executed.
public struct Bridge has key {
    id: UID,
    treasury: TreasuryCap<BRIDGE>,
    configured: bool,
    /// Tenzro's chain id.
    tenzro_chain_id: u64,
    /// The route key Tenzro names this route by.
    route_key: vector<u8>,
    /// Sui's identifier on the route (the route's `source_chain_id`).
    sui_selector: u64,
    /// Tenzro's identifier on the route (the route's `local_selector`).
    tenzro_selector: u64,
    /// This package's address (the route's `ramp`).
    ramp: address,
    /// The coin's identity as the route names it (the route's `peer`).
    token: address,
    /// The Tenzro endpoint transfers are addressed to.
    tenzro_endpoint: address,
    /// The committee's Ethereum-style addresses.
    committee: vector<vector<u8>>,
    threshold: u64,
    /// The committee's set index on Tenzro.
    set_index: u32,
    /// Unix second after which the committee is no longer trusted.
    expires_at: u64,
    /// The last transfer sent to Tenzro.
    sequence: u64,
    /// Outbound records executed, by sequence.
    executed: Table<u64, bool>,
}

/// A transfer to Tenzro.
public struct TransferOut has copy, drop {
    sequence: u64,
    source_selector: u64,
    dest_selector: u64,
    sender: address,
    token: address,
    endpoint: address,
    recipient: address,
    amount: u128,
}

/// A transfer from Tenzro, executed.
public struct TransferIn has copy, drop {
    sequence: u64,
    recipient: address,
    amount: u128,
}

fun init(otw: BRIDGE, ctx: &mut TxContext) {
    let (init, treasury) = coin_registry::new_currency_with_otw(
        otw,
        9,
        b"TNZO".to_string(),
        b"Tenzro".to_string(),
        b"TNZO bridged from Tenzro".to_string(),
        b"".to_string(),
        ctx,
    );
    let metadata_cap = init.finalize(ctx);
    transfer::public_transfer(metadata_cap, ctx.sender());
    transfer::share_object(Bridge {
        id: object::new(ctx),
        treasury,
        configured: false,
        tenzro_chain_id: 0,
        route_key: vector[],
        sui_selector: 0,
        tenzro_selector: 0,
        ramp: @0x0,
        token: @0x0,
        tenzro_endpoint: @0x0,
        committee: vector[],
        threshold: 0,
        set_index: 0,
        expires_at: 0,
        sequence: 0,
        executed: table::new(ctx),
    });
    transfer::transfer(AdminCap { id: object::new(ctx) }, ctx.sender());
}

/// Set the route's identifiers and the committee Tenzro drew, with its set
/// index and expiry, consuming the cap: afterwards only the committee hands
/// itself over.
public fun configure(
    cap: AdminCap,
    bridge: &mut Bridge,
    tenzro_chain_id: u64,
    route_key: vector<u8>,
    sui_selector: u64,
    tenzro_selector: u64,
    ramp: address,
    token: address,
    tenzro_endpoint: address,
    committee: vector<vector<u8>>,
    threshold: u64,
    set_index: u32,
    expires_at: u64,
) {
    let AdminCap { id } = cap;
    id.delete();
    check_committee(&committee, threshold);
    bridge.tenzro_chain_id = tenzro_chain_id;
    bridge.route_key = route_key;
    bridge.sui_selector = sui_selector;
    bridge.tenzro_selector = tenzro_selector;
    bridge.ramp = ramp;
    bridge.token = token;
    bridge.tenzro_endpoint = tenzro_endpoint;
    bridge.committee = committee;
    bridge.threshold = threshold;
    bridge.set_index = set_index;
    bridge.expires_at = expires_at;
    bridge.configured = true;
}

fun check_committee(committee: &vector<vector<u8>>, threshold: u64) {
    let n = committee.length();
    assert!(n > 0 && threshold > n / 2 && threshold <= n, EBadCommittee);
    let mut i = 0;
    while (i < n) {
        assert!(committee[i].length() == 20, EBadCommittee);
        let mut j = i + 1;
        while (j < n) {
            assert!(committee[i] != committee[j], EBadCommittee);
            j = j + 1;
        };
        i = i + 1;
    };
}

/// Send `coin` to `recipient` on Tenzro: burn it and emit the record.
public fun send_to_tenzro(bridge: &mut Bridge, coin: Coin<BRIDGE>, recipient: address, ctx: &TxContext) {
    assert!(bridge.configured, ENotConfigured);
    let value = coin.value();
    assert!(value > 0, EBadAmount);
    coin::burn(&mut bridge.treasury, coin);
    bridge.sequence = bridge.sequence + 1;
    event::emit(TransferOut {
        sequence: bridge.sequence,
        source_selector: bridge.sui_selector,
        dest_selector: bridge.tenzro_selector,
        sender: ctx.sender(),
        token: bridge.token,
        endpoint: bridge.tenzro_endpoint,
        recipient,
        amount: (value as u128) * SCALE,
    });
}

/// The preimage whose Keccak-256 the committee signs for outbound `record`.
public fun outbound_preimage(bridge: &Bridge, record: &vector<u8>): vector<u8> {
    let mut m = OUTBOUND_DOMAIN;
    m.append(be_u64(bridge.tenzro_chain_id));
    m.append(be_u64(bridge.route_key.length()));
    m.append(bridge.route_key);
    m.append(*record);
    m
}

/// `v` as eight big-endian bytes.
fun be_u64(v: u64): vector<u8> {
    let mut out = bcs::to_bytes(&v);
    out.reverse();
    out
}

/// The Ethereum-style address of the key that signed Keccak-256 of
/// `preimage` with `signature` (`r || s || v`).
fun signer_of(preimage: &vector<u8>, signature: &vector<u8>): vector<u8> {
    let mut sig = *signature;
    assert!(sig.length() == 65, EBelowThreshold);
    let v = sig[64];
    if (v >= 27) { *vector::borrow_mut(&mut sig, 64) = v - 27; };
    let compressed = ecdsa_k1::secp256k1_ecrecover(&sig, preimage, KECCAK256);
    let full = ecdsa_k1::decompress_pubkey(&compressed);
    let mut key = vector[];
    let mut i = 1;
    while (i < 65) {
        key.push_back(full[i]);
        i = i + 1;
    };
    let hash = keccak256(&key);
    let mut addr = vector[];
    let mut j = 12;
    while (j < 32) {
        addr.push_back(hash[j]);
        j = j + 1;
    };
    addr
}

/// Require the committee to be trusted at `clock` and `threshold` distinct
/// members among the signers.
fun check_quorum(bridge: &Bridge, preimage: &vector<u8>, signatures: &vector<vector<u8>>, clock: &Clock) {
    assert!(clock.timestamp_ms() / 1000 <= bridge.expires_at, EExpired);
    let mut seen = vector[];
    let mut count = 0;
    let mut i = 0;
    while (i < signatures.length()) {
        let who = signer_of(preimage, &signatures[i]);
        if (bridge.committee.contains(&who) && !seen.contains(&who)) {
            seen.push_back(who);
            count = count + 1;
        };
        i = i + 1;
    };
    assert!(count >= bridge.threshold, EBelowThreshold);
}

/// Execute outbound `record` from Tenzro, signed by the committee: mint the
/// coin to its recipient, once.
public fun execute(bridge: &mut Bridge, record: vector<u8>, signatures: vector<vector<u8>>, clock: &Clock, ctx: &mut TxContext) {
    assert!(bridge.configured, ENotConfigured);
    let preimage = outbound_preimage(bridge, &record);
    check_quorum(bridge, &preimage, &signatures, clock);
    let mut r = bcs::new(record);
    let sequence = r.peel_u64();
    let source_selector = r.peel_u64();
    let dest_selector = r.peel_u64();
    let _sender = r.peel_address();
    let token = r.peel_address();
    let endpoint = r.peel_address();
    let recipient = r.peel_address();
    let amount = r.peel_u128();
    assert!(r.into_remainder_bytes().length() == 0, EMalformedRecord);
    assert!(
        source_selector == bridge.tenzro_selector && dest_selector == bridge.sui_selector
            && endpoint == bridge.ramp && token == bridge.token,
        EWrongRoute,
    );
    assert!(!bridge.executed.contains(sequence), EAlreadyExecuted);
    assert!(amount > 0 && amount % SCALE == 0 && amount / SCALE <= 18_446_744_073_709_551_615, EBadAmount);
    bridge.executed.add(sequence, true);
    let coin = coin::mint(&mut bridge.treasury, (amount / SCALE) as u64, ctx);
    transfer::public_transfer(coin, recipient);
    event::emit(TransferIn { sequence, recipient, amount });
}

/// `v` as four big-endian bytes.
fun be_u32(v: u32): vector<u8> {
    let mut out = bcs::to_bytes(&v);
    out.reverse();
    out
}

/// The preimage whose Keccak-256 the trusted committee signs to hand the
/// module over to committee `set_index`: the committee domain, Tenzro's
/// chain id, the route key, the set index, the member count, the members,
/// the threshold and the expiry.
public fun handover_preimage(
    bridge: &Bridge,
    set_index: u32,
    committee: &vector<vector<u8>>,
    threshold: u64,
    expires_at: u64,
): vector<u8> {
    let mut m = COMMITTEE_DOMAIN;
    m.append(be_u64(bridge.tenzro_chain_id));
    m.append(be_u64(bridge.route_key.length()));
    m.append(bridge.route_key);
    m.append(be_u32(set_index));
    m.append(be_u32(committee.length() as u32));
    let mut i = 0;
    while (i < committee.length()) {
        m.append(committee[i]);
        i = i + 1;
    };
    m.append(be_u32(threshold as u32));
    m.append(be_u64(expires_at));
    m
}

/// Hand the module over to committee `set_index`, signed by the committee
/// it trusts. Only a higher set index is accepted.
public fun rotate_committee(
    bridge: &mut Bridge,
    set_index: u32,
    committee: vector<vector<u8>>,
    threshold: u64,
    expires_at: u64,
    signatures: vector<vector<u8>>,
    clock: &Clock,
) {
    assert!(bridge.configured, ENotConfigured);
    assert!(set_index > bridge.set_index, EStaleSet);
    check_committee(&committee, threshold);
    let m = handover_preimage(bridge, set_index, &committee, threshold, expires_at);
    check_quorum(bridge, &m, &signatures, clock);
    bridge.committee = committee;
    bridge.threshold = threshold;
    bridge.set_index = set_index;
    bridge.expires_at = expires_at;
}

/// The trusted committee's set index.
public fun set_index(bridge: &Bridge): u32 { bridge.set_index }

/// When the trusted committee expires, Unix seconds.
public fun expires_at(bridge: &Bridge): u64 { bridge.expires_at }

/// The last transfer sent to Tenzro.
public fun sequence(bridge: &Bridge): u64 { bridge.sequence }

/// Whether outbound record `sequence` was executed.
public fun is_executed(bridge: &Bridge, sequence: u64): bool { bridge.executed.contains(sequence) }

#[test_only]
public fun init_for_testing(ctx: &mut TxContext) {
    init(BRIDGE {}, ctx);
}

#[test_only]
public fun mint_for_testing(bridge: &mut Bridge, value: u64, ctx: &mut TxContext): Coin<BRIDGE> {
    coin::mint(&mut bridge.treasury, value, ctx)
}
