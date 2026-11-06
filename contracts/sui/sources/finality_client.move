// SPDX-License-Identifier: Apache-2.0
/// Tenzro finality on Sui.
///
/// A finality proof is a Groth16 proof (BN254) that RISC Zero's recursion
/// circuit accepted a receipt of Tenzro's finality program. Its journal states
/// one checkpoint that the program verified under the committee of its epoch.
/// The client takes the seal and journal every chain's client takes (points in
/// the Ethereum precompile encoding), re-encodes the points for Sui's Groth16
/// verifier, and records the checkpoint's state root. A checkpoint that ends an
/// epoch hands over to the next committee.
#[allow(implicit_const_copy)]
module tenzro_bridge::finality_client;

use std::hash::sha2_256;
use sui::event;
use sui::groth16;
use sui::table::{Self, Table};

const EMalformedSeal: u64 = 100;
const EWrongSelector: u64 = 101;
const EInvalidProof: u64 = 102;
const EMalformedJournal: u64 = 103;
const EWrongChain: u64 = 104;
const EUnknownCommittee: u64 = 105;
const EAlreadyFinal: u64 = 106;
const EUnknownCheckpoint: u64 = 107;

/// Bytes of an encoded journal: thirteen words.
const JOURNAL_LEN: u64 = 416;
/// The seals this client accepts: RISC Zero's Groth16 verifier parameters.
const SELECTOR: vector<u8> = x"73c457ba";
const CONTROL_ROOT: vector<u8> = x"a54dc85ac99f851c92d7c96d7318af41dbe7c0194edfcc37eb4d422a998c1f56";
const BN254_CONTROL_ID: vector<u8> = x"04446e66d300eb7fb45c9726bb53c793dda407a62e9601618bb43c5c14657ac0";
/// The terminal state of a halted program.
const POST_STATE: vector<u8> = x"a3acc27117418996340b84e5a90f3ef4c49d22c79e44aad822ec9c313e1eb8e2";
/// The recursion circuit's verifying key, compressed as Sui's verifier reads it.
const VK: vector<u8> = x"e2f26dbea299f5223b646cb1fb33eadb059d9407559d7441dfd902e3a79a4d2dabb73dc17fbc13021e2471e0c08bd67d8401f52b73d6d07483794cad4778180e0c06f33bbc4c79a9cadef253a68084d382f17788f885c9afd176f7cb2f036789edf692d95cbdde46ddda5ef7d422436779445c5e66006a42761e1f12efde0018c212f3aeb785e49712e7a9353349aaf1255dfb31b7bf60723a480d9293938e1933033e7fea1f40604eaacf699d4be9aacc577054a0db22d9129a1728ff85a01a1c3af829b62bf4914c0bcf2c81a4bd577190eff5f194ee9bac95faefd53cb0030600000000000000e43bdc655d0f9d730535554d9caa611ddd152c081a06a932a8e1d5dc259aac123f42a188f683d869873ccc4c119442e57b056e03e2fa92f2028c97bc20b9078747c30f85444697fdf436e348711c011115963f855197243e4b39e6cbe236ca8ba7f2042e11f9255afbb6c6e2c3accb88e401f2aac21c097c92b3fbdb99f98a9b0dcd6c075ada6ed0ddfece1d4a2d005f61a7d5df0b75c18a5b2374d64e495fab93d4c4b1200394d5253cce2f25a59b862ee8e4cd43686603faa09d5d0d3c1c8f";
const ZERO16: vector<u8> = x"00000000000000000000000000000000";
const ZERO32: vector<u8> = x"0000000000000000000000000000000000000000000000000000000000000000";
/// The base field modulus.
const Q: u256 = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

/// What the client keeps of a final checkpoint.
public struct Checkpoint has copy, drop, store {
    digest: vector<u8>,
    state_root: vector<u8>,
    state_height: u64,
    last_height: u64,
    timestamp_ms: u64,
}

/// A client of one Tenzro chain.
public struct FinalityClient has key {
    id: UID,
    image_id: vector<u8>,
    chain_id: u64,
    genesis_hash: vector<u8>,
    /// Committee roots by epoch.
    committees: Table<u64, vector<u8>>,
    /// Final checkpoints by index.
    checkpoints: Table<u64, Checkpoint>,
    latest_index: u64,
}

public struct CheckpointFinalized has copy, drop {
    index: u64,
    epoch: u64,
    digest: vector<u8>,
    state_root: vector<u8>,
    state_height: u64,
}

public struct CommitteeHandedOver has copy, drop {
    epoch: u64,
    root: vector<u8>,
}

/// Share a client of the chain `chain_id` with genesis `genesis_hash`, whose
/// epoch-0 committee has root `genesis_committee_root`, accepting proofs of
/// the finality program `image_id`. Returns the client's id.
public fun create(
    image_id: vector<u8>,
    chain_id: u64,
    genesis_hash: vector<u8>,
    genesis_committee_root: vector<u8>,
    ctx: &mut TxContext,
): ID {
    assert!(image_id.length() == 32 && genesis_hash.length() == 32, EMalformedJournal);
    assert!(genesis_committee_root.length() == 32, EUnknownCommittee);
    let mut committees = table::new(ctx);
    committees.add(0, genesis_committee_root);
    let client = FinalityClient {
        id: object::new(ctx),
        image_id,
        chain_id,
        genesis_hash,
        committees,
        checkpoints: table::new(ctx),
        latest_index: 0,
    };
    let id = object::id(&client);
    transfer::share_object(client);
    id
}

/// Accept the checkpoint `journal` states, proven by `seal`. Returns its index.
public fun submit(client: &mut FinalityClient, journal: vector<u8>, seal: vector<u8>): u64 {
    assert!(journal.length() == JOURNAL_LEN, EMalformedJournal);
    let claim = claim_digest(&client.image_id, &sha2_256(journal));
    assert!(verify_seal(&seal, &claim), EInvalidProof);
    let chain_id = int(&journal, 0);
    let epoch = int(&journal, 2);
    let index = int(&journal, 4);
    assert!(chain_id == client.chain_id && word(&journal, 1) == client.genesis_hash, EWrongChain);
    assert!(client.committees.contains(epoch), EUnknownCommittee);
    let root = *client.committees.borrow(epoch);
    assert!(root == word(&journal, 3) && root != ZERO32, EUnknownCommittee);
    assert!(!client.checkpoints.contains(index), EAlreadyFinal);
    let checkpoint = Checkpoint {
        digest: word(&journal, 5),
        state_root: word(&journal, 8),
        state_height: int(&journal, 7),
        last_height: int(&journal, 6),
        timestamp_ms: int(&journal, 12),
    };
    client.checkpoints.add(index, checkpoint);
    if (index > client.latest_index) client.latest_index = index;
    event::emit(CheckpointFinalized {
        index,
        epoch,
        digest: checkpoint.digest,
        state_root: checkpoint.state_root,
        state_height: checkpoint.state_height,
    });
    let next = word(&journal, 11);
    if (next != ZERO32 && !client.committees.contains(epoch + 1)) {
        client.committees.add(epoch + 1, next);
        event::emit(CommitteeHandedOver { epoch: epoch + 1, root: next });
    };
    index
}

/// The state root of the final checkpoint `index`.
public fun state_root(client: &FinalityClient, index: u64): vector<u8> {
    assert!(client.checkpoints.contains(index), EUnknownCheckpoint);
    client.checkpoints.borrow(index).state_root
}

/// When the final checkpoint `index` was made, in milliseconds.
public fun timestamp_ms(client: &FinalityClient, index: u64): u64 {
    assert!(client.checkpoints.contains(index), EUnknownCheckpoint);
    client.checkpoints.borrow(index).timestamp_ms
}

public fun is_final(client: &FinalityClient, index: u64): bool {
    client.checkpoints.contains(index)
}

public fun latest_index(client: &FinalityClient): u64 {
    client.latest_index
}

public fun committee_root(client: &FinalityClient, epoch: u64): vector<u8> {
    assert!(client.committees.contains(epoch), EUnknownCommittee);
    *client.committees.borrow(epoch)
}

/// The digest of a successful receipt claim of `image_id` with journal digest
/// `journal_digest`.
public fun claim_digest(image_id: &vector<u8>, journal_digest: &vector<u8>): vector<u8> {
    let mut b = sha2_256(b"risc0.Output");
    b.append(*journal_digest);
    b.append(ZERO32);
    b.append(x"0200");
    let output = sha2_256(b);
    let mut b = sha2_256(b"risc0.ReceiptClaim");
    b.append(ZERO32);
    b.append(*image_id);
    b.append(POST_STATE);
    b.append(output);
    b.append(x"0000000000000000");
    b.append(x"0400");
    sha2_256(b)
}

/// Whether `seal` (selector, then the words of A, B and C) proves a receipt
/// with claim `claim`.
public fun verify_seal(seal: &vector<u8>, claim: &vector<u8>): bool {
    assert!(seal.length() == 4 + 8 * 32, EMalformedSeal);
    assert!(slice(seal, 0, 4) == SELECTOR, EWrongSelector);
    let mut points = g1_compressed(&seal_word(seal, 0), &seal_word(seal, 1));
    points.append(
        g2_compressed(&seal_word(seal, 2), &seal_word(seal, 3), &seal_word(seal, 4), &seal_word(seal, 5)),
    );
    points.append(g1_compressed(&seal_word(seal, 6), &seal_word(seal, 7)));
    let mut inputs = vector[];
    inputs.append(half_le(&CONTROL_ROOT, 0));
    inputs.append(half_le(&CONTROL_ROOT, 16));
    inputs.append(half_le(claim, 0));
    inputs.append(half_le(claim, 16));
    inputs.append(reversed(&BN254_CONTROL_ID));
    let curve = groth16::bn254();
    let pvk = groth16::prepare_verifying_key(&curve, &VK);
    groth16::verify_groth16_proof(
        &curve,
        &pvk,
        &groth16::public_proof_inputs_from_bytes(inputs),
        &groth16::proof_points_from_bytes(points),
    )
}

/// One half of a digest as a little-endian scalar: the digest's bytes
/// reversed, split into its low and high 128 bits.
fun half_le(d: &vector<u8>, from: u64): vector<u8> {
    let mut out = slice(d, from, from + 16);
    out.append(ZERO16);
    out
}

fun to_u256(be: &vector<u8>): u256 {
    let mut v: u256 = 0;
    let mut i = 0;
    while (i < be.length()) {
        v = (v << 8) | (be[i] as u256);
        i = i + 1;
    };
    v
}

fun neg(v: u256): u256 {
    if (v == 0) 0 else Q - v
}

/// A G1 point from its big-endian coordinates, compressed: x little-endian,
/// the top bit set when y is the larger of y and -y.
fun g1_compressed(x: &vector<u8>, y: &vector<u8>): vector<u8> {
    let mut out = reversed(x);
    let yv = to_u256(y);
    if (yv > neg(yv)) {
        let top = out[31];
        *&mut out[31] = top | 0x80;
    };
    out
}

/// A G2 point from the precompile encoding (x_im, x_re, y_im, y_re),
/// compressed: x_re then x_im little-endian, the top bit set when y is the
/// larger of y and -y (imaginary parts compared first).
fun g2_compressed(x_im: &vector<u8>, x_re: &vector<u8>, y_im: &vector<u8>, y_re: &vector<u8>): vector<u8> {
    let mut out = reversed(x_re);
    out.append(reversed(x_im));
    let (yi, yr) = (to_u256(y_im), to_u256(y_re));
    let larger = if (yi != neg(yi)) yi > neg(yi) else yr > neg(yr);
    if (larger) {
        let top = out[63];
        *&mut out[63] = top | 0x80;
    };
    out
}

fun reversed(v: &vector<u8>): vector<u8> {
    let mut out = *v;
    out.reverse();
    out
}

fun slice(v: &vector<u8>, from: u64, to: u64): vector<u8> {
    let mut out = vector[];
    let mut i = from;
    while (i < to) {
        out.push_back(v[i]);
        i = i + 1;
    };
    out
}

fun seal_word(seal: &vector<u8>, i: u64): vector<u8> {
    slice(seal, 4 + 32 * i, 36 + 32 * i)
}

fun word(journal: &vector<u8>, i: u64): vector<u8> {
    slice(journal, 32 * i, 32 * (i + 1))
}

/// A journal word holding an integer: right-aligned, at most 64 bits.
fun int(journal: &vector<u8>, i: u64): u64 {
    let w = word(journal, i);
    let mut j = 0;
    while (j < 24) {
        assert!(w[j] == 0, EMalformedJournal);
        j = j + 1;
    };
    (to_u256(&slice(&w, 24, 32)) as u64)
}

#[test_only]
/// Record a checkpoint without a proof, so accounts can be tested against a
/// state root of their own.
public fun record_for_testing(client: &mut FinalityClient, index: u64, state_root: vector<u8>, timestamp_ms: u64) {
    client.checkpoints.add(index, Checkpoint { digest: ZERO32, state_root, state_height: 0, last_height: 0, timestamp_ms });
    if (index > client.latest_index) client.latest_index = index;
}
