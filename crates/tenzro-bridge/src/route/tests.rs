use std::sync::Arc;

use super::canonical::Reader;
use super::evm::{EVM_CHAINS, Evm2AnyMessage, Evm2AnyTokenTransfer, RampHeader};
use super::solana::{
    SOLANA_SELECTOR, SolanaExecution, Svm2AnyMessage, Svm2AnyTokenTransfer, svm2any_message_id,
};
use super::state::read_supply;
use super::test_support::*;
use super::*;

const LOCAL_SELECTOR: u64 = 7_777;
const ENDPOINT: [u8; 32] = [0xAB; 32];
const POOL: [u8; 20] = [0x51; 20];
const ON_RAMP: [u8; 20] = [0x52; 20];
const REMOTE_TOKEN: [u8; 20] = [0x53; 20];
const RECIPIENT: [u8; 32] = [0x77; 32];
const EXPIRY: i64 = NOW_MS + 60_000;

fn pad(a: &[u8; 20]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(a);
    w
}

fn keys() -> Signers {
    Signers {
        committee: committee(1, 5, 3).0,
        blessing: committee(40, 5, 3).0,
    }
}

fn base_route(
    adapter: BridgeRouteAdapter,
    family: ChainFamily,
    chain: &str,
    id: u64,
) -> BridgeRoute {
    BridgeRoute {
        adapter,
        family,
        source_chain: chain.into(),
        source_chain_id: id,
        local_selector: LOCAL_SELECTOR,
        peer: pad(&POOL),
        ramp: pad(&ON_RAMP),
        local_endpoint: ENDPOINT,
        remote_token: pad(&REMOTE_TOKEN),
        verifiers: committee(1, 5, 3).1,
        blessing: (adapter == BridgeRouteAdapter::Ccip).then(|| committee(40, 5, 3).1),
        light_client: None,
        mint_limit: MintRateLimit {
            per_mint: 1_000,
            per_epoch: 1_500,
        },
        ibc: None,
        settlement_lock: None,
        native_asset: None,
        assets: Vec::new(),
        outflow: LaneRateLimit {
            capacity: 1_000_000,
            rate: 1_000,
        },
        lane_limits: (adapter == BridgeRouteAdapter::Ccip).then_some(CcipLane {
            version: CcipLaneVersion::V1_6,
            off_ramp: [0u8; 20],
            ccv_and_executor_hash: [0u8; 32],
            inbound: LaneRateLimit {
                capacity: 1_500,
                rate: 500,
            },
        }),
    }
}

fn evm_route(chain: &str) -> BridgeRoute {
    let c = EVM_CHAINS.iter().find(|c| c.name == chain).unwrap();
    base_route(
        BridgeRouteAdapter::Ccip,
        ChainFamily::Evm,
        chain,
        c.selector,
    )
}

fn solana_route() -> BridgeRoute {
    let mut r = base_route(
        BridgeRouteAdapter::Ccip,
        ChainFamily::Solana,
        "solana",
        SOLANA_SELECTOR,
    );
    r.peer = [0x61; 32];
    r.ramp = [0x62; 32];
    r.remote_token = [0x63; 32];
    r
}

fn evm_body(route: &BridgeRoute, seq: u64, amount: u128) -> Vec<u8> {
    evm_body_from(route, seq, amount, POOL, ENDPOINT.to_vec())
}

fn evm_body_from(
    route: &BridgeRoute,
    seq: u64,
    amount: u128,
    source_pool: [u8; 20],
    dest_token: Vec<u8>,
) -> Vec<u8> {
    let mut m = Evm2AnyMessage {
        header: RampHeader {
            message_id: [0u8; 32],
            source_selector: route.source_chain_id,
            dest_selector: LOCAL_SELECTOR,
            sequence: seq,
            nonce: 0,
        },
        sender: [0x99; 20],
        data: vec![],
        receiver: RECIPIENT.to_vec(),
        extra_args: vec![0x18, 0x1d, 0xcf, 0x10],
        fee_token: [0x44; 20],
        fee_token_amount: 5,
        fee_value_juels: 6,
        token_amounts: vec![Evm2AnyTokenTransfer {
            source_pool,
            dest_token,
            extra_data: vec![],
            amount,
            dest_exec_data: vec![0, 0, 0, 1],
        }],
    };
    m.header.message_id = m.hash(&ON_RAMP);
    m.encode()
}

fn solana_body(route: &BridgeRoute, seq: u64, amount: u128) -> Vec<u8> {
    let mut m = Svm2AnyMessage {
        message_id: [0u8; 32],
        source_selector: SOLANA_SELECTOR,
        dest_selector: LOCAL_SELECTOR,
        sequence: seq,
        nonce: 0,
        sender: [0x98; 32],
        data: vec![],
        receiver: RECIPIENT.to_vec(),
        extra_args: vec![],
        fee_token: [0x45; 32],
        token_amounts: vec![Svm2AnyTokenTransfer {
            source_pool: route.peer,
            dest_token: ENDPOINT.to_vec(),
            extra_data: vec![],
            amount,
            dest_exec_data: vec![],
        }],
        fee_token_amount: 1,
        fee_value_juels: 2,
    };
    m.message_id = svm2any_message_id(&m, &route.ramp);
    m.encode()
}

/// Lock `amount` on `route` through a real outbound transfer, so inbound
/// transfers have supply to release.
fn lock(f: &RouteFramework, s: &mut MemState, route: &BridgeRoute, amount: u128, to: Vec<u8>) {
    f.send_outbound(
        s,
        &route.source_chain,
        &OutboundTransfer {
            sender: RECIPIENT.to_vec(),
            recipient: to,
            amount,
            asset: None,
        },
    )
    .unwrap();
}

fn evm_setup(amount_locked: u128) -> (RouteFramework, MemState, BridgeRoute) {
    let route = evm_route("ethereum");
    let f = RouteFramework::new();
    let mut s = MemState::with(std::slice::from_ref(&route));
    if amount_locked > 0 {
        lock(&f, &mut s, &route, amount_locked, vec![0x12; 20]);
    }
    (f, s, route)
}

#[test]
fn each_evm_chain_round_trips_a_fixture_message() {
    for chain in EVM_CHAINS.iter().map(|c| c.name) {
        let route = evm_route(chain);
        let f = RouteFramework::new();
        let mut s = MemState::with(std::slice::from_ref(&route));
        let out = f
            .send_outbound(
                &mut s,
                chain,
                &OutboundTransfer {
                    sender: RECIPIENT.to_vec(),
                    recipient: vec![0x12; 20],
                    amount: 400,
                    asset: None,
                },
            )
            .unwrap();
        assert_eq!(out.message.sequence, 1);
        assert_eq!(out.message.token, route.remote_token);
        assert_eq!(
            out.supply,
            SupplyRecord {
                locked: 400,
                bridged: 400
            }
        );

        let d = deliver(
            &route,
            &keys(),
            3,
            9,
            EXPIRY,
            &evm_body(&route, 9, 250),
            &[],
        );
        let admitted = f
            .admit_inbound(&mut s, BridgeRouteAdapter::Ccip, chain, &d)
            .unwrap();
        assert_eq!(admitted.message.amount, 250);
        assert_eq!(admitted.message.receiver, RECIPIENT.to_vec());
        assert_eq!(
            admitted.supply,
            SupplyRecord {
                locked: 150,
                bridged: 150
            }
        );
    }
}

#[test]
fn each_evm_chain_refuses_forged_and_misrouted_messages() {
    let f = RouteFramework::new();
    for (i, c) in EVM_CHAINS.iter().enumerate() {
        let route = evm_route(c.name);
        assert_eq!(f.finality_depth(&route).unwrap(), c.finality_depth);
        let mut s = MemState::with(std::slice::from_ref(&route));
        lock(&f, &mut s, &route, 1_000, vec![0x12; 20]);

        // The message id is not the on-ramp's hash of what was delivered.
        let mut forged = evm_body(&route, 1, 10);
        forged[40] ^= 1;
        let d = deliver(&route, &keys(), 3, 1, EXPIRY, &forged, &[]);
        assert!(
            f.admit_inbound(&mut s, BridgeRouteAdapter::Ccip, c.name, &d)
                .is_err()
        );

        // A message emitted on another chain of the family.
        let other = &EVM_CHAINS[(i + 1) % EVM_CHAINS.len()];
        let mut foreign = evm_route(other.name);
        foreign.source_chain = c.name.into();
        let d = deliver(
            &route,
            &keys(),
            3,
            1,
            EXPIRY,
            &evm_body(&foreign, 1, 10),
            &[],
        );
        assert!(
            f.admit_inbound(&mut s, BridgeRouteAdapter::Ccip, c.name, &d)
                .is_err()
        );

        // A route that names the chain with another chain's selector.
        let mut s2 = MemState::with(std::slice::from_ref(&foreign));
        assert!(f.check_outbound(&s2, c.name, 1).is_ok());
        let err = f
            .send_outbound(
                &mut s2,
                c.name,
                &OutboundTransfer {
                    sender: RECIPIENT.to_vec(),
                    recipient: vec![0x12; 20],
                    amount: 1,
                    asset: None,
                },
            )
            .unwrap_err();
        assert!(err.to_string().contains("selector"), "{err}");

        // The well-formed message still passes: nothing above wrote state.
        let d = deliver(&route, &keys(), 3, 1, EXPIRY, &evm_body(&route, 1, 10), &[]);
        f.admit_inbound(&mut s, BridgeRouteAdapter::Ccip, c.name, &d)
            .unwrap();
    }
}

#[test]
fn solana_round_trips_a_fixture_message() {
    let route = solana_route();
    let f = RouteFramework::new();
    let mut s = MemState::with(std::slice::from_ref(&route));
    let out = f
        .send_outbound(
            &mut s,
            "solana",
            &OutboundTransfer {
                sender: RECIPIENT.to_vec(),
                recipient: vec![0x21; 32],
                amount: 300,
                asset: None,
            },
        )
        .unwrap();
    let mut r = Reader::new(&out.bytes);
    let back = super::solana::SolanaCcipAdapter
        .decode_outbound(&route, &mut r)
        .unwrap();
    r.finish().unwrap();
    assert_eq!(back, out.message);

    let d = deliver(
        &route,
        &keys(),
        3,
        4,
        EXPIRY,
        &solana_body(&route, 4, 300),
        &execution(),
    );
    let admitted = f
        .admit_inbound(&mut s, BridgeRouteAdapter::Ccip, "solana", &d)
        .unwrap();
    assert_eq!(admitted.message.amount, 300);
    assert_eq!(admitted.supply, SupplyRecord::default());
}

#[test]
fn a_malformed_payload_is_rejected() {
    let (f, mut s, route) = evm_setup(1_000);
    let body = evm_body(&route, 1, 10);

    // A trailing byte after the envelope.
    let mut d = deliver(&route, &keys(), 3, 1, EXPIRY, &body, &[]);
    d.push(0);
    assert!(
        f.admit_inbound(&mut s, BridgeRouteAdapter::Ccip, "ethereum", &d)
            .is_err()
    );

    // A trailing byte inside the attested body: the committee signed it, the
    // decoder still refuses it.
    let mut padded = body.clone();
    padded.push(0);
    let d = deliver(&route, &keys(), 3, 1, EXPIRY, &padded, &[]);
    let err = f
        .admit_inbound(&mut s, BridgeRouteAdapter::Ccip, "ethereum", &d)
        .unwrap_err();
    assert!(err.to_string().contains("trailing"), "{err}");

    // A truncated body.
    let d = deliver(&route, &keys(), 3, 1, EXPIRY, &body[..body.len() - 1], &[]);
    assert!(
        f.admit_inbound(&mut s, BridgeRouteAdapter::Ccip, "ethereum", &d)
            .is_err()
    );

    // A non-canonical ABI offset (the outer tuple moved one word on).
    let mut shifted = body.clone();
    shifted[31] = 0x40;
    let d = deliver(&route, &keys(), 3, 1, EXPIRY, &shifted, &[]);
    assert!(
        f.admit_inbound(&mut s, BridgeRouteAdapter::Ccip, "ethereum", &d)
            .is_err()
    );

    // A message whose id is not the on-ramp's hash.
    let mut forged = body.clone();
    forged[40] ^= 1;
    let d = deliver(&route, &keys(), 3, 1, EXPIRY, &forged, &[]);
    assert!(
        f.admit_inbound(&mut s, BridgeRouteAdapter::Ccip, "ethereum", &d)
            .is_err()
    );

    // Nothing was written by any refused delivery: the well-formed one passes.
    let d = deliver(&route, &keys(), 3, 1, EXPIRY, &body, &[]);
    f.admit_inbound(&mut s, BridgeRouteAdapter::Ccip, "ethereum", &d)
        .unwrap();
}

#[test]
fn a_replayed_nonce_is_rejected() {
    let (f, mut s, route) = evm_setup(1_000);
    let d = deliver(&route, &keys(), 3, 5, EXPIRY, &evm_body(&route, 5, 10), &[]);
    f.admit_inbound(&mut s, BridgeRouteAdapter::Ccip, "ethereum", &d)
        .unwrap();
    let err = f
        .admit_inbound(&mut s, BridgeRouteAdapter::Ccip, "ethereum", &d)
        .unwrap_err();
    assert!(matches!(err, BridgeError::ReplayAttack(_)), "{err}");
    // A fresh attestation over the same nonce is refused as well.
    let d = deliver(
        &route,
        &keys(),
        3,
        5,
        EXPIRY - 1,
        &evm_body(&route, 5, 10),
        &[],
    );
    assert!(
        f.admit_inbound(&mut s, BridgeRouteAdapter::Ccip, "ethereum", &d)
            .is_err()
    );
}

#[test]
fn an_attested_message_is_admitted_once_and_moves_no_supply() {
    let (f, mut s, route) = evm_setup(1_000);
    let before = read_supply(&s, &route);
    let body = br#"{"fill":1}"#.to_vec();
    let d = deliver(&route, &keys(), 3, 5, EXPIRY, &body, &[]);
    let (admitted, got) = f
        .admit_message(&mut s, BridgeRouteAdapter::Ccip, "ethereum", &d)
        .unwrap();
    assert_eq!(admitted.storage_key(), route.storage_key());
    assert_eq!(got, body);
    assert_eq!(read_supply(&s, &route), before);
    let err = f
        .admit_message(&mut s, BridgeRouteAdapter::Ccip, "ethereum", &d)
        .unwrap_err();
    assert!(matches!(err, BridgeError::ReplayAttack(_)), "{err}");
    // Below quorum it is refused like any delivery.
    let weak = deliver(&route, &keys(), 2, 6, EXPIRY, &body, &[]);
    assert!(
        f.admit_message(&mut s, BridgeRouteAdapter::Ccip, "ethereum", &weak)
            .is_err()
    );
    // Its nonce space is its own: transfer sequence 5 is still free.
    let t = deliver(&route, &keys(), 3, 5, EXPIRY, &evm_body(&route, 5, 10), &[]);
    f.admit_inbound(&mut s, BridgeRouteAdapter::Ccip, "ethereum", &t)
        .unwrap();
}

#[test]
fn an_outbound_message_is_sequenced_stored_and_held_by_the_breaker() {
    let (f, mut s, route) = evm_setup(1_000);
    let before = read_supply(&s, &route);
    let a = f.send_message(&mut s, "ethereum", b"record-a").unwrap();
    let b = f.send_message(&mut s, "ethereum", b"record-b").unwrap();
    assert_eq!((a.sequence, b.sequence), (1, 2));
    assert_ne!(a.message_id, b.message_id);
    assert_eq!(
        s.kv.get(&state::outbound_message_key(&route, 2)),
        Some(&b.bytes)
    );
    assert!(b.bytes.starts_with(ROUTE_MESSAGE_DOMAIN));
    assert_eq!(read_supply(&s, &route), before);
    assert!(f.send_message(&mut s, "ethereum", b"").is_err());
    s.modes.insert(route.storage_key(), BridgeRouteMode::Paused);
    assert!(f.send_message(&mut s, "ethereum", b"record-c").is_err());
}

#[test]
fn attestations_are_bound_to_chain_route_and_expiry() {
    let (f, mut s, route) = evm_setup(1_000);
    let body = evm_body(&route, 2, 10);

    let expired = deliver(&route, &keys(), 3, 2, NOW_MS, &body, &[]);
    assert!(
        f.admit_inbound(&mut s, BridgeRouteAdapter::Ccip, "ethereum", &expired)
            .is_err()
    );
    let far = deliver(
        &route,
        &keys(),
        3,
        2,
        NOW_MS + MAX_ATTESTATION_VALIDITY_MS + 1,
        &body,
        &[],
    );
    assert!(
        f.admit_inbound(&mut s, BridgeRouteAdapter::Ccip, "ethereum", &far)
            .is_err()
    );

    // Signed for another route: the digest names the route, so it fails.
    let other = evm_route("base");
    let d = deliver(&other, &keys(), 3, 2, EXPIRY, &body, &[]);
    assert!(
        f.admit_inbound(&mut s, BridgeRouteAdapter::Ccip, "ethereum", &d)
            .is_err()
    );

    // The attestation nonce must be the message's sequence number.
    let d = deliver(&route, &keys(), 3, 3, EXPIRY, &body, &[]);
    assert!(
        f.admit_inbound(&mut s, BridgeRouteAdapter::Ccip, "ethereum", &d)
            .is_err()
    );

    // Below threshold.
    let d = deliver(&route, &keys(), 2, 2, EXPIRY, &body, &[]);
    assert!(
        f.admit_inbound(&mut s, BridgeRouteAdapter::Ccip, "ethereum", &d)
            .is_err()
    );

    let d = deliver(&route, &keys(), 3, 2, EXPIRY, &body, &[]);
    f.admit_inbound(&mut s, BridgeRouteAdapter::Ccip, "ethereum", &d)
        .unwrap();
}

#[test]
fn a_mint_over_the_locked_supply_is_refused() {
    let (f, mut s, route) = evm_setup(0);
    // Nothing locked: a fully attested, well-formed delivery still mints
    // nothing.
    let d = deliver(&route, &keys(), 3, 1, EXPIRY, &evm_body(&route, 1, 10), &[]);
    let err = f
        .admit_inbound(&mut s, BridgeRouteAdapter::Ccip, "ethereum", &d)
        .unwrap_err();
    assert!(err.to_string().contains("supply invariant"), "{err}");

    lock(&f, &mut s, &route, 100, vec![0x12; 20]);
    let d = deliver(
        &route,
        &keys(),
        3,
        2,
        EXPIRY,
        &evm_body(&route, 2, 101),
        &[],
    );
    assert!(
        f.admit_inbound(&mut s, BridgeRouteAdapter::Ccip, "ethereum", &d)
            .is_err()
    );
    let d = deliver(
        &route,
        &keys(),
        3,
        3,
        EXPIRY,
        &evm_body(&route, 3, 100),
        &[],
    );
    f.admit_inbound(&mut s, BridgeRouteAdapter::Ccip, "ethereum", &d)
        .unwrap();
    assert_eq!(read_supply(&s, &route), SupplyRecord::default());
}

#[test]
fn caps_and_epoch_limits_bound_every_mint() {
    let (f, mut s, route) = evm_setup(1_000);
    lock(&f, &mut s, &route, 1_000, vec![0x12; 20]);
    let d = deliver(
        &route,
        &keys(),
        3,
        1,
        EXPIRY,
        &evm_body(&route, 1, 1_001),
        &[],
    );
    assert!(
        f.admit_inbound(&mut s, BridgeRouteAdapter::Ccip, "ethereum", &d)
            .is_err()
    );
    let d = deliver(
        &route,
        &keys(),
        3,
        2,
        EXPIRY,
        &evm_body(&route, 2, 1_000),
        &[],
    );
    f.admit_inbound(&mut s, BridgeRouteAdapter::Ccip, "ethereum", &d)
        .unwrap();
    let d = deliver(
        &route,
        &keys(),
        3,
        3,
        EXPIRY,
        &evm_body(&route, 3, 501),
        &[],
    );
    assert!(
        f.admit_inbound(&mut s, BridgeRouteAdapter::Ccip, "ethereum", &d)
            .is_err()
    );
    s.epoch += 1;
    s.elapsed_ms += 1_000;
    f.admit_inbound(&mut s, BridgeRouteAdapter::Ccip, "ethereum", &d)
        .unwrap();
    s.network = None;
    let d = deliver(&route, &keys(), 3, 4, EXPIRY, &evm_body(&route, 4, 1), &[]);
    assert!(
        f.admit_inbound(&mut s, BridgeRouteAdapter::Ccip, "ethereum", &d)
            .is_err()
    );
}

#[test]
fn a_breaker_trip_blocks_the_route() {
    let (f, mut s, route) = evm_setup(1_000);
    s.modes.insert(route.storage_key(), BridgeRouteMode::Paused);
    let d = deliver(&route, &keys(), 3, 1, EXPIRY, &evm_body(&route, 1, 10), &[]);
    let err = f
        .admit_inbound(&mut s, BridgeRouteAdapter::Ccip, "ethereum", &d)
        .unwrap_err();
    assert!(err.to_string().contains("is paused"), "{err}");
    let out = OutboundTransfer {
        sender: RECIPIENT.to_vec(),
        recipient: vec![0x12; 20],
        amount: 1,
        asset: None,
    };
    assert!(f.send_outbound(&mut s, "ethereum", &out).is_err());
    s.modes.clear();
    f.admit_inbound(&mut s, BridgeRouteAdapter::Ccip, "ethereum", &d)
        .unwrap();
}

/// A disabled route winds down: nothing new leaves over it, while TNZO it
/// already sent out comes back, so a transfer in flight when governance
/// disabled the route still completes.
#[test]
fn a_disabled_route_sends_nothing_new_but_takes_back_what_it_sent() {
    let (f, mut s, route) = evm_setup(1_000);
    let before = read_supply(&s, &route);
    s.modes
        .insert(route.storage_key(), BridgeRouteMode::Disabled);

    let out = OutboundTransfer {
        sender: RECIPIENT.to_vec(),
        recipient: vec![0x12; 20],
        amount: 1,
        asset: None,
    };
    let err = f.send_outbound(&mut s, "ethereum", &out).unwrap_err();
    assert!(err.to_string().contains("is disabled"), "{err}");
    assert!(f.send_message(&mut s, "ethereum", b"record").is_err());

    // The return of TNZO sent out before the route was disabled.
    let d = deliver(&route, &keys(), 3, 1, EXPIRY, &evm_body(&route, 1, 10), &[]);
    let admitted = f
        .admit_inbound(&mut s, BridgeRouteAdapter::Ccip, "ethereum", &d)
        .unwrap();
    assert_eq!(admitted.message.amount, 10);
    assert_eq!(read_supply(&s, &route).bridged, before.bridged - 10);

    // A pause stops the returns as well.
    s.modes.insert(route.storage_key(), BridgeRouteMode::Paused);
    let d = deliver(&route, &keys(), 3, 2, EXPIRY, &evm_body(&route, 2, 10), &[]);
    assert!(
        f.admit_inbound(&mut s, BridgeRouteAdapter::Ccip, "ethereum", &d)
            .is_err()
    );
}

#[test]
fn only_governed_routes_carry_traffic() {
    let route = evm_route("ethereum");
    let f = RouteFramework::new();
    let mut s = MemState::with(&[]);
    let d = deliver(&route, &keys(), 3, 1, EXPIRY, &evm_body(&route, 1, 10), &[]);
    assert!(
        f.admit_inbound(&mut s, BridgeRouteAdapter::Ccip, "ethereum", &d)
            .is_err()
    );

    // An installed route that no longer passes the rules is treated as absent.
    let mut broken = route.clone();
    broken.verifiers.threshold = 1;
    let mut s = MemState::with(&[broken]);
    assert!(
        f.admit_inbound(&mut s, BridgeRouteAdapter::Ccip, "ethereum", &d)
            .is_err()
    );

    // An EVM route whose selector is not its chain's carries nothing.
    let mut wrong = route.clone();
    wrong.source_chain_id = 1;
    let mut s = MemState::with(std::slice::from_ref(&wrong));
    let d = deliver(&wrong, &keys(), 3, 1, EXPIRY, &evm_body(&wrong, 1, 10), &[]);
    assert!(
        f.admit_inbound(&mut s, BridgeRouteAdapter::Ccip, "ethereum", &d)
            .is_err()
    );
}

mod ethereum_light_client {
    use super::super::ethereum_light_client::fixture::{self, Committee};
    use super::super::ethereum_light_client::{EthereumLightClient, SLOTS_PER_PERIOD};
    use super::super::evm::onramp_event_topic;
    use super::super::receipt_proof::{ReceiptLog, receipt_key, trie};
    use super::*;

    const ANCHOR_SLOT: u64 = 10 * SLOTS_PER_PERIOD + 32;

    /// A successful receipt carrying `logs`, as a typed (EIP-1559) receipt.
    fn receipt(logs: &[ReceiptLog]) -> Vec<u8> {
        let mut s = rlp::RlpStream::new_list(4);
        s.append(&1u8);
        s.append(&50_000u64);
        s.append(&vec![0u8; 256]);
        s.begin_list(logs.len());
        for l in logs {
            s.begin_list(3);
            s.append(&l.address.to_vec());
            s.begin_list(l.topics.len());
            for t in &l.topics {
                s.append(&t.to_vec());
            }
            s.append(&l.data);
        }
        let mut out = vec![2u8];
        out.extend_from_slice(&s.out());
        out
    }

    fn word(v: u64) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[24..].copy_from_slice(&v.to_be_bytes());
        w
    }

    /// The on-ramp's `CCIPMessageSent` log for `body`.
    fn sent(route: &BridgeRoute, seq: u64, body: &[u8]) -> ReceiptLog {
        ReceiptLog {
            address: ON_RAMP,
            topics: vec![
                onramp_event_topic(CcipLaneVersion::V1_6),
                word(route.local_selector),
                word(seq),
            ],
            data: body.to_vec(),
        }
    }

    /// A block's receipts with `log` in transaction 3, and the proof of it.
    fn receipts_with(log: ReceiptLog) -> ([u8; 32], Vec<Vec<u8>>) {
        let entries: Vec<_> = (0..6u32)
            .map(|i| {
                let other = ReceiptLog {
                    address: [i as u8; 20],
                    topics: vec![[i as u8; 32]],
                    data: vec![i as u8; 8],
                };
                let logs = if i == 3 {
                    vec![other, log.clone()]
                } else {
                    vec![other]
                };
                (receipt_key(i), receipt(&logs))
            })
            .collect();
        trie::build(&entries, &receipt_key(3))
    }

    struct Setup {
        f: RouteFramework,
        s: MemState,
        route: BridgeRoute,
        committee: Committee,
    }

    fn setup() -> Setup {
        let committee = Committee::new(1);
        let (anchor_header, _) = fixture::bootstrap(ANCHOR_SLOT, &committee);
        let mut route = evm_route("ethereum");
        route.light_client = Some(LightClientAnchor::EthereumSyncCommittee {
            genesis_validators_root: fixture::GVR,
            fork_version: fixture::FORK,
            trusted_block_root: anchor_header.root(),
        });
        let f = RouteFramework::new().with_light_client(Arc::new(EthereumLightClient::new()));
        let mut s = MemState::with(std::slice::from_ref(&route));
        lock(&f, &mut s, &route, 1_000, vec![0x12; 20]);
        Setup {
            f,
            s,
            route,
            committee,
        }
    }

    fn bootstrap(t: &mut Setup) {
        let (_, update) = fixture::bootstrap(ANCHOR_SLOT, &t.committee);
        t.f.advance_light_client(&mut t.s, BridgeRouteAdapter::Ccip, "ethereum", &update)
            .unwrap();
    }

    fn admit(
        t: &mut Setup,
        nonce: u64,
        body: &[u8],
        proof: &[u8],
    ) -> crate::Result<AdmittedTransfer> {
        let d = deliver(&t.route, &keys(), 3, nonce, EXPIRY, body, proof);
        t.f.admit_inbound(&mut t.s, BridgeRouteAdapter::Ccip, "ethereum", &d)
    }

    #[test]
    fn a_message_finalized_on_ethereum_is_admitted_with_its_proof() {
        let mut t = setup();
        let body = evm_body(&t.route, 1, 10);
        let (root, nodes) = receipts_with(sent(&t.route, 1, &body));
        let slot = ANCHOR_SLOT + 200;
        let proof = fixture::message_proof(slot, &t.committee, 400, false, root, 3, 1, &nodes);

        // The committees alone do not admit it, and neither does a proof
        // before the light client has been bootstrapped from the anchor.
        assert!(admit(&mut t, 1, &body, &[]).is_err());
        assert!(admit(&mut t, 1, &body, &proof).is_err());
        bootstrap(&mut t);
        admit(&mut t, 1, &body, &proof).unwrap();

        // A message in an older block, proven through the finalized state.
        let body = evm_body(&t.route, 2, 10);
        let (root, nodes) = receipts_with(sent(&t.route, 2, &body));
        let proof = fixture::message_proof(slot, &t.committee, 400, true, root, 3, 1, &nodes);
        admit(&mut t, 2, &body, &proof).unwrap();
    }

    #[test]
    fn a_header_without_a_valid_sync_committee_signature_is_refused() {
        let mut t = setup();
        bootstrap(&mut t);
        let body = evm_body(&t.route, 1, 10);
        let (root, nodes) = receipts_with(sent(&t.route, 1, &body));
        let slot = ANCHOR_SLOT + 200;

        // Signed by a committee the light client does not follow.
        let stranger = Committee::new(9);
        let forged = fixture::message_proof(slot, &stranger, 512, false, root, 3, 1, &nodes);
        assert!(admit(&mut t, 1, &body, &forged).is_err());

        // Signed by fewer than two thirds of the real committee.
        let thin = fixture::message_proof(slot, &t.committee, 341, false, root, 3, 1, &nodes);
        assert!(admit(&mut t, 1, &body, &thin).is_err());

        // A real signature with one participation bit flipped.
        let mut flipped =
            fixture::message_proof(slot, &t.committee, 400, false, root, 3, 1, &nodes);
        let bits_at = 112 + 112 + 7 * 32;
        flipped[bits_at + 50] ^= 0x01;
        assert!(admit(&mut t, 1, &body, &flipped).is_err());

        // The genuine proof is still admitted afterwards.
        let good = fixture::message_proof(slot, &t.committee, 342, false, root, 3, 1, &nodes);
        admit(&mut t, 1, &body, &good).unwrap();
    }

    #[test]
    fn a_proof_of_another_message_or_emitter_is_refused() {
        let mut t = setup();
        bootstrap(&mut t);
        let body = evm_body(&t.route, 1, 10);
        let slot = ANCHOR_SLOT + 200;

        // The receipt holds a different message.
        let other = evm_body(&t.route, 1, 11);
        let (root, nodes) = receipts_with(sent(&t.route, 1, &other));
        let p = fixture::message_proof(slot, &t.committee, 400, false, root, 3, 1, &nodes);
        assert!(admit(&mut t, 1, &body, &p).is_err());

        // The right data, emitted by some other contract.
        let mut log = sent(&t.route, 1, &body);
        log.address = [0x99; 20];
        let (root, nodes) = receipts_with(log);
        let p = fixture::message_proof(slot, &t.committee, 400, false, root, 3, 1, &nodes);
        assert!(admit(&mut t, 1, &body, &p).is_err());

        // The right data under another event.
        let mut log = sent(&t.route, 1, &body);
        log.topics[0] = [0x42; 32];
        let (root, nodes) = receipts_with(log);
        let p = fixture::message_proof(slot, &t.committee, 400, false, root, 3, 1, &nodes);
        assert!(admit(&mut t, 1, &body, &p).is_err());

        // The other log of the same receipt.
        let (root, nodes) = receipts_with(sent(&t.route, 1, &body));
        let p = fixture::message_proof(slot, &t.committee, 400, false, root, 3, 0, &nodes);
        assert!(admit(&mut t, 1, &body, &p).is_err());

        let p = fixture::message_proof(slot, &t.committee, 400, false, root, 3, 1, &nodes);
        admit(&mut t, 1, &body, &p).unwrap();
    }

    #[test]
    fn the_light_client_follows_a_signed_committee_handover() {
        let mut t = setup();
        bootstrap(&mut t);
        let next = Committee::new(2);

        // A bootstrap is accepted once, and only for the anchor's block.
        let (_, again) = fixture::bootstrap(ANCHOR_SLOT, &t.committee);
        assert!(
            t.f.advance_light_client(&mut t.s, BridgeRouteAdapter::Ccip, "ethereum", &again)
                .is_err()
        );

        // A handover signed by a stranger is refused.
        let stranger = Committee::new(9);
        let forged = fixture::handover(ANCHOR_SLOT + 300, &stranger, &next, 512);
        assert!(
            t.f.advance_light_client(&mut t.s, BridgeRouteAdapter::Ccip, "ethereum", &forged)
                .is_err()
        );

        // The current committee names its successor within its period...
        let learn = fixture::handover(ANCHOR_SLOT + 300, &t.committee, &next, 400);
        let head =
            t.f.advance_light_client(&mut t.s, BridgeRouteAdapter::Ccip, "ethereum", &learn)
                .unwrap();
        assert!(head.next_known);
        assert_eq!(head.period, 10);

        // ...which signs in the next period, and takes over once a header of
        // that period is final.
        let rotate = fixture::handover(11 * SLOTS_PER_PERIOD + 100, &next, &Committee::new(3), 400);
        let head =
            t.f.advance_light_client(&mut t.s, BridgeRouteAdapter::Ccip, "ethereum", &rotate)
                .unwrap();
        assert_eq!(head.period, 11);

        // Messages are now proven by the new committee, not the old one.
        let body = evm_body(&t.route, 1, 10);
        let (root, nodes) = receipts_with(sent(&t.route, 1, &body));
        let slot = 11 * SLOTS_PER_PERIOD + 500;
        let old = fixture::message_proof(slot, &t.committee, 512, false, root, 3, 1, &nodes);
        assert!(admit(&mut t, 1, &body, &old).is_err());
        let new = fixture::message_proof(slot, &next, 400, false, root, 3, 1, &nodes);
        admit(&mut t, 1, &body, &new).unwrap();
    }
}

#[test]
fn the_inbound_lane_bucket_binds_when_the_epoch_limit_does_not() {
    let (f, mut s, route) = evm_setup(1_000);
    lock(&f, &mut s, &route, 1_000, vec![0x12; 20]);
    let d = deliver(
        &route,
        &keys(),
        3,
        1,
        EXPIRY,
        &evm_body(&route, 1, 1_000),
        &[],
    );
    f.admit_inbound(&mut s, BridgeRouteAdapter::Ccip, "ethereum", &d)
        .unwrap();

    // A fresh epoch resets the epoch limit, but the lane bucket holds 500.
    s.epoch += 1;
    let d = deliver(
        &route,
        &keys(),
        3,
        2,
        EXPIRY,
        &evm_body(&route, 2, 600),
        &[],
    );
    let refused = f
        .admit_inbound(&mut s, BridgeRouteAdapter::Ccip, "ethereum", &d)
        .unwrap_err();
    assert!(refused.to_string().contains("inbound lane"), "{refused}");
    assert_eq!(read_supply(&s, &route).bridged, 1_000);

    // One second refills 500, and the same delivery is admitted.
    s.elapsed_ms += 1_000;
    f.admit_inbound(&mut s, BridgeRouteAdapter::Ccip, "ethereum", &d)
        .unwrap();
    let bucket = lane::lane_bucket(&s, &route, lane::LaneDirection::Inbound).unwrap();
    assert_eq!(bucket.tokens, 400);
}

#[test]
fn the_outbound_lane_bucket_bounds_what_leaves() {
    let mut route = evm_route("ethereum");
    route.lane_limits = Some(CcipLane {
        ..route.lane_limits.unwrap()
    });
    route.outflow = LaneRateLimit {
        capacity: 1_500,
        rate: 100,
    };
    let f = RouteFramework::new();
    let mut s = MemState::with(std::slice::from_ref(&route));
    lock(&f, &mut s, &route, 1_000, vec![0x12; 20]);

    let out = OutboundTransfer {
        sender: RECIPIENT.to_vec(),
        recipient: vec![0x12; 20],
        amount: 600,
        asset: None,
    };
    assert!(f.check_outbound(&s, "ethereum", 600).is_err());
    assert!(f.send_outbound(&mut s, "ethereum", &out).is_err());
    assert_eq!(read_supply(&s, &route).locked, 1_000);

    s.elapsed_ms += 1_000;
    f.check_outbound(&s, "ethereum", 600).unwrap();
    f.send_outbound(&mut s, "ethereum", &out).unwrap();
    assert_eq!(read_supply(&s, &route).locked, 1_600);
    let bucket = lane::lane_bucket(&s, &route, lane::LaneDirection::Outbound).unwrap();
    assert_eq!(bucket.tokens, 0);
}

#[test]
fn a_ccip_route_without_lane_limits_carries_nothing() {
    let mut route = evm_route("ethereum");
    route.lane_limits = None;
    let f = RouteFramework::new();
    let s = MemState::with(std::slice::from_ref(&route));
    assert!(f.check_outbound(&s, "ethereum", 1).is_err());
}

/// The execution record a Solana route's verifiers sign with a message.
fn execution() -> Vec<u8> {
    SolanaExecution {
        signature: [0x5a; 64],
        slot: 312_000_000,
    }
    .encode()
}

/// A Solana route with 300 locked for it, so 300 may come back.
fn solana_with_outstanding(route: &BridgeRoute) -> (RouteFramework, MemState) {
    let f = RouteFramework::new();
    let mut s = MemState::with(std::slice::from_ref(route));
    f.send_outbound(
        &mut s,
        "solana",
        &OutboundTransfer {
            sender: RECIPIENT.to_vec(),
            recipient: vec![0x21; 32],
            amount: 300,
            asset: None,
        },
    )
    .unwrap();
    (f, s)
}

#[test]
fn a_solana_message_without_independent_attestations_of_its_success_is_refused() {
    let mut route = solana_route();
    // Members 0 and 1 run under one operator: below the threshold, so the
    // route is valid, but their two signatures count once.
    route.verifiers.members[1].operator = route.verifiers.members[0].operator.clone();
    route.validate().unwrap();
    let all = committee(1, 5, 3).0;
    let blessing = committee(40, 5, 3).0;
    let body = solana_body(&route, 4, 300);
    let admit = |signers: Vec<usize>, nonce: u64, proof: &[u8]| {
        let (f, mut s) = solana_with_outstanding(&route);
        let keys = Signers {
            committee: signers.iter().map(|i| all[*i].clone()).collect(),
            blessing: blessing.clone(),
        };
        let mut body = body.clone();
        if nonce != 4 {
            body = solana_body(&route, nonce, 300);
        }
        let d = deliver(&route, &keys, 3, nonce, EXPIRY, &body, proof);
        f.admit_inbound(&mut s, BridgeRouteAdapter::Ccip, "solana", &d)
    };

    // No execution record: refused, however many verifiers signed.
    assert!(admit(vec![0, 2, 3], 4, &[]).is_err());
    // A record of a transaction that failed: refused.
    let mut failed = execution();
    *failed.last_mut().unwrap() = 0;
    assert!(admit(vec![0, 2, 3], 4, &failed).is_err());
    // A record with a trailing byte: refused.
    let mut long = execution();
    long.push(0);
    assert!(admit(vec![0, 2, 3], 4, &long).is_err());
    // Three signatures, but two from one operator: two independent, refused.
    let e = admit(vec![0, 1, 2], 4, &execution()).unwrap_err();
    assert!(e.to_string().contains("independent"), "{e}");
    // Three signatures from three operators on three RPC providers: admitted.
    let admitted = admit(vec![0, 2, 3], 4, &execution()).unwrap();
    assert_eq!(admitted.message.amount, 300);
}

#[test]
fn a_route_without_a_light_client_mints_under_the_lower_attested_limits() {
    let route = solana_route();
    let (f, mut s) = solana_with_outstanding(&route);
    s.network = Some(NetworkMintLimits {
        proven: MintRateLimit {
            per_mint: 1_000,
            per_epoch: 10_000,
        },
        attested: MintRateLimit {
            per_mint: 200,
            per_epoch: 2_000,
        },
        classical: MintRateLimit {
            per_mint: 1_000,
            per_epoch: 10_000,
        },
    });
    let d = deliver(
        &route,
        &keys(),
        3,
        4,
        EXPIRY,
        &solana_body(&route, 4, 300),
        &execution(),
    );
    // 300 is within the route's own cap and the proven-route cap, but over
    // the attested-route cap.
    assert!(
        f.admit_inbound(&mut s, BridgeRouteAdapter::Ccip, "solana", &d)
            .is_err()
    );
    let d = deliver(
        &route,
        &keys(),
        3,
        4,
        EXPIRY,
        &solana_body(&route, 4, 200),
        &execution(),
    );
    assert!(
        f.admit_inbound(&mut s, BridgeRouteAdapter::Ccip, "solana", &d)
            .is_ok()
    );

    // Governance cannot set attested limits that are not below the proven ones.
    let equal = NetworkMintLimits {
        proven: MintRateLimit {
            per_mint: 1_000,
            per_epoch: 10_000,
        },
        attested: MintRateLimit {
            per_mint: 1_000,
            per_epoch: 2_000,
        },
        classical: MintRateLimit {
            per_mint: 1_000,
            per_epoch: 2_000,
        },
    };
    assert_eq!(
        equal.validate(),
        Err(BridgeRouteError::AttestedLimitNotLower)
    );
}

/// The mainnet CCIP router program.
const SOLANA_ROUTER: &str = "Ccip842gzYHhvdDkSyi2YVCoAWPbYJoApMFzSxQroE9C";

fn recorded_solana_tx(name: &str) -> serde_json::Value {
    let text = match name {
        "token" => include_str!("../../tests/fixtures/solana/ccip_send_token.json"),
        _ => include_str!("../../tests/fixtures/solana/ccip_send_data.json"),
    };
    serde_json::from_str(text).unwrap()
}

/// A route whose lane is the one the recorded message was sent on.
fn recorded_lane_route(dest_selector: u64) -> BridgeRoute {
    let mut r = solana_route();
    r.ramp = bs58::decode(SOLANA_ROUTER)
        .into_vec()
        .unwrap()
        .try_into()
        .unwrap();
    r.local_selector = dest_selector;
    r
}

#[test]
fn a_recorded_mainnet_solana_message_is_attested_with_its_execution() {
    let tx = recorded_solana_tx("token");
    let route = recorded_lane_route(5_009_297_550_715_157_269);
    let (messages, execution) = super::solana::attest_transaction(&route, &tx).unwrap();
    let [m] = messages.as_slice() else {
        panic!("one message")
    };
    assert_eq!(m.sequence, 8035);
    assert_eq!(m.token_amounts.len(), 1);
    assert_eq!(m.token_amounts[0].amount, 200_000_000_000);
    assert_eq!(m.message_id, svm2any_message_id(m, &route.ramp));
    assert_eq!(execution.slot, tx["slot"].as_u64().unwrap());
    assert_eq!(
        SolanaExecution::decode(&execution.encode()).unwrap(),
        execution
    );

    // A data-only message on another lane decodes the same way.
    let data = recorded_solana_tx("data");
    let (messages, _) =
        super::solana::attest_transaction(&recorded_lane_route(3_461_204_551_265_785_888), &data)
            .unwrap();
    assert_eq!(messages[0].data.len(), 72);
}

#[test]
fn a_solana_transaction_is_attested_only_as_it_executed() {
    let tx = recorded_solana_tx("token");
    let route = recorded_lane_route(5_009_297_550_715_157_269);
    let attest =
        |tx: &serde_json::Value, route: &BridgeRoute| super::solana::attest_transaction(route, tx);

    // Another lane, or another router program: nothing to attest.
    assert!(attest(&tx, &recorded_lane_route(1)).is_err());
    let mut other_router = route.clone();
    other_router.ramp = [0x62; 32];
    assert!(attest(&tx, &other_router).is_err());

    // A failed transaction.
    let mut failed = tx.clone();
    failed["meta"]["err"] = serde_json::json!({ "InstructionError": [0, "Custom"] });
    assert!(attest(&failed, &route).is_err());

    // Truncated logs.
    let mut truncated = tx.clone();
    truncated["meta"]["logMessages"]
        .as_array_mut()
        .unwrap()
        .push("Log truncated".into());
    assert!(attest(&truncated, &route).is_err());

    // The event logged by another program than the router.
    let mut forged = tx.clone();
    let logs = forged["meta"]["logMessages"].as_array_mut().unwrap();
    let event = logs
        .iter()
        .position(|l| {
            use base64::Engine as _;
            use sha2::Digest as _;
            let disc = sha2::Sha256::digest(b"event:CCIPMessageSent");
            l.as_str()
                .unwrap()
                .strip_prefix("Program data: ")
                .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok())
                .is_some_and(|b| b.starts_with(&disc[..8]))
        })
        .unwrap();
    let line = logs[event].clone();
    let other = "11111111111111111111111111111111";
    logs.retain(|l| l != &line);
    logs.push(format!("Program {other} invoke [1]").into());
    logs.push(line);
    logs.push(format!("Program {other} success").into());
    assert!(attest(&forged, &route).is_err());

    // A tampered message no longer hashes to its id.
    let mut tampered = tx.clone();
    for l in tampered["meta"]["logMessages"].as_array_mut().unwrap() {
        let s = l.as_str().unwrap().to_string();
        if let Some(b64) = s.strip_prefix("Program data: ") {
            use base64::Engine as _;
            let mut b = base64::engine::general_purpose::STANDARD
                .decode(b64)
                .unwrap();
            if b.len() > 300 {
                let last = b.len() - 70;
                b[last] ^= 1;
                *l = format!(
                    "Program data: {}",
                    base64::engine::general_purpose::STANDARD.encode(b)
                )
                .into();
            }
        }
    }
    assert!(attest(&tampered, &route).is_err());
}

/// A `vector<u8>` constant of a Move test file, by name.
fn move_constant(src: &str, name: &str) -> Vec<u8> {
    let tag = format!("const {name}: vector<u8> = x\"");
    let start = src
        .find(&tag)
        .unwrap_or_else(|| panic!("no constant {name}"))
        + tag.len();
    let end = start + src[start..].find('"').unwrap();
    hex::decode(&src[start..end]).unwrap()
}

/// The bridge contract's own tests check these vectors against what it
/// emits and signs; Tenzro must read and compute the same.
fn contract_vectors_agree(src: &str, family: ChainFamily, chain: &str) {
    use super::move_event::MoveTransfer;
    let out = MoveTransfer::decode(&move_constant(src, "TRANSFER_OUT")).unwrap();
    assert_eq!(
        (out.sequence, out.source_selector, out.dest_selector),
        (1, 101, 7777)
    );
    assert_eq!(
        (out.token, out.endpoint, out.recipient),
        ([0x22; 32], [0x44; 32], [0x55; 32])
    );
    assert_eq!(out.amount, 3_000_000_000 * 1_000_000_000);
    let record = move_constant(src, "OUTBOUND");
    let back = MoveTransfer::decode(&record).unwrap();
    assert_eq!(back.encode(), record);
    let route = base_route(BridgeRouteAdapter::Contract, family, chain, 101);
    assert_eq!(
        super::attestation::outbound_digest(1337, &route, &record).to_vec(),
        move_constant(src, "OUTBOUND_DIGEST")
    );
}

#[test]
fn the_sui_bridge_module_and_tenzro_agree_on_records_and_digests() {
    contract_vectors_agree(
        include_str!("../../../../contracts/sui/tests/bridge_tests.move"),
        ChainFamily::Sui,
        "sui",
    );
}

#[test]
fn the_aptos_bridge_module_and_tenzro_agree_on_records_and_digests() {
    contract_vectors_agree(
        include_str!("../../../../contracts/aptos/tests/bridge_tests.move"),
        ChainFamily::Aptos,
        "aptos",
    );
}

/// A `&str` hex constant of a Rust test file, by name.
/// The handover every bridge contract's tests fix: set 2 of members
/// `[0x41; 20]`, `[0x42; 20]`, `[0x43; 20]`, threshold 2, expiring at Unix
/// second 2,000,000,000, on Tenzro chain 1337.
fn fixed_handover(family: ChainFamily, chain: &str) -> Vec<u8> {
    let route = base_route(BridgeRouteAdapter::Contract, family, chain, 101);
    super::attestation::committee_handover_digest(
        1337,
        &route,
        2,
        &[[0x41; 20], [0x42; 20], [0x43; 20]],
        2,
        2_000_000_000,
    )
    .to_vec()
}

#[test]
fn every_bridge_contract_and_tenzro_agree_on_the_committee_handover() {
    let stellar = include_str!("../../../../contracts/stellar/src/test.rs");
    assert_eq!(
        fixed_handover(ChainFamily::Stellar, "stellar"),
        rust_constant(stellar, "HANDOVER_DIGEST")
    );
    let sui = include_str!("../../../../contracts/sui/tests/bridge_tests.move");
    assert_eq!(
        fixed_handover(ChainFamily::Sui, "sui"),
        move_constant(sui, "HANDOVER_DIGEST")
    );
    let aptos = include_str!("../../../../contracts/aptos/tests/bridge_tests.move");
    assert_eq!(
        fixed_handover(ChainFamily::Aptos, "aptos"),
        move_constant(aptos, "HANDOVER_DIGEST")
    );
    let ton = include_str!("../../../../contracts/ton/tests/bridge.test.mjs");
    let tag = "const HANDOVER_DIGEST = '";
    let start = ton.find(tag).unwrap() + tag.len();
    let ton_digest = hex::decode(&ton[start..start + ton[start..].find('\'').unwrap()]).unwrap();
    assert_eq!(fixed_handover(ChainFamily::Ton, "ton"), ton_digest);
}

fn rust_constant(src: &str, name: &str) -> Vec<u8> {
    let tag = format!("const {name}: &str = \"");
    let start = src
        .find(&tag)
        .unwrap_or_else(|| panic!("no constant {name}"))
        + tag.len();
    let end = start + src[start..].find('"').unwrap();
    hex::decode(&src[start..end]).unwrap()
}

#[test]
fn the_stellar_bridge_contract_and_tenzro_agree_on_records_and_digests() {
    use super::move_event::MoveTransfer;
    use super::stellar::encode_record;
    let src = include_str!("../../../../contracts/stellar/src/test.rs");
    let mut user = [0u8; 32];
    user[31] = 0x0b;
    let out = MoveTransfer {
        sequence: 1,
        source_selector: 101,
        dest_selector: 7777,
        sender: user,
        token: [0x22; 32],
        endpoint: [0x44; 32],
        recipient: [0x55; 32],
        amount: 30_000_000 * 100_000_000_000,
    };
    assert_eq!(encode_record(&out), rust_constant(src, "TRANSFER_OUT"));
    let mut route = base_route(
        BridgeRouteAdapter::Contract,
        ChainFamily::Stellar,
        "stellar",
        101,
    );
    assert_eq!(
        super::attestation::outbound_digest(1337, &route, &rust_constant(src, "OUTBOUND")).to_vec(),
        rust_constant(src, "OUTBOUND_DIGEST")
    );
    // The contract event the Soroban host recorded decodes as that transfer.
    route.ramp = [0x33; 32];
    let event = rust_constant(src, "TRANSFER_OUT_EVENT");
    let mut r = Reader::new(&event);
    let m = super::stellar::StellarAdapter
        .decode_inbound(&route, &mut r)
        .unwrap();
    r.finish().unwrap();
    assert_eq!(
        (m.sequence, m.amount, m.receiver.as_slice()),
        (1, out.amount, &[0x55u8; 32][..])
    );
}

#[test]
fn the_ton_bridge_contract_and_tenzro_agree_on_records_and_digests() {
    let src = include_str!("../../../../contracts/ton/tests/bridge.test.mjs");
    let constant = |name: &str| {
        let tag = format!("const {name} = '");
        let start = src.find(&tag).unwrap() + tag.len();
        hex::decode(&src[start..start + src[start..].find('\'').unwrap()]).unwrap()
    };
    let record = constant("OUTBOUND");
    let t = super::move_event::MoveTransfer {
        sequence: 7,
        source_selector: 7777,
        dest_selector: 101,
        sender: [0x11; 32],
        token: [0x22; 32],
        endpoint: [0x33; 32],
        recipient: {
            let mut r = [0u8; 32];
            r[31] = 11;
            r
        },
        amount: 5 * 10u128.pow(18),
    };
    assert_eq!(super::stellar::encode_record(&t), record);
    let route = base_route(BridgeRouteAdapter::Contract, ChainFamily::Ton, "ton", 101);
    assert_eq!(
        super::attestation::outbound_digest(1337, &route, &record).to_vec(),
        constant("OUTBOUND_DIGEST")
    );
}

/// CCIP lanes of every on-ramp version: messages recorded from Ethereum
/// mainnet, and messages addressed to Tenzro carried through the framework.
mod ccip_lane_versions {
    use sha3::{Digest, Keccak256};

    use super::super::evm::{
        Field, abi_array, abi_bytes, abi_tuple, onramp_log_matches, read_onramp_message,
    };
    use super::*;

    const MAINNET: &str = include_str!("../../tests/fixtures/ccip/mainnet_onramp_logs.json");

    fn h(v: &serde_json::Value) -> Vec<u8> {
        hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
    }

    fn word(v: u128) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[16..].copy_from_slice(&v.to_be_bytes());
        w
    }

    fn keccak(parts: &[&[u8]]) -> [u8; 32] {
        let mut k = Keccak256::new();
        for p in parts {
            k.update(p);
        }
        k.finalize().into()
    }

    struct Recorded {
        version: CcipLaneVersion,
        topics: Vec<[u8; 32]>,
        data: Vec<u8>,
        route: BridgeRoute,
    }

    fn recorded() -> Vec<Recorded> {
        let f: serde_json::Value = serde_json::from_str(MAINNET).unwrap();
        f["logs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| {
                let version = CcipLaneVersion::parse(l["version"].as_str().unwrap()).unwrap();
                let topics: Vec<[u8; 32]> = l["topics"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|t| h(t).try_into().unwrap())
                    .collect();
                let dest = match l.get("dest_selector") {
                    Some(d) => d.as_str().unwrap().parse().unwrap(),
                    None => u64::from_be_bytes(topics[1][24..].try_into().unwrap()),
                };
                let mut route = evm_route("ethereum");
                route.ramp = pad(&h(&l["address"]).try_into().unwrap());
                route.local_selector = dest;
                route.lane_limits = Some(CcipLane {
                    version,
                    ..route.lane_limits.unwrap()
                });
                Recorded {
                    version,
                    topics,
                    data: h(&l["data"]),
                    route,
                }
            })
            .collect()
    }

    fn read(route: &BridgeRoute, data: &[u8]) -> Result<super::super::evm::OnRampMessage> {
        let mut r = Reader::new(data);
        let m = read_onramp_message(route, &mut r)?;
        r.finish()?;
        Ok(m)
    }

    #[test]
    fn each_lane_version_reads_its_recorded_mainnet_messages() {
        let logs = recorded();
        for version in CcipLaneVersion::ALL {
            assert!(
                logs.iter().any(|l| l.version == version),
                "no recorded {} message",
                version.as_str()
            );
        }
        for l in &logs {
            let m = read(&l.route, &l.data).unwrap();
            assert!(onramp_log_matches(l.version, &l.topics, &l.data, &l.route));
            assert_eq!(m.source_selector, l.route.source_chain_id);
            assert_eq!(m.dest_selector, l.route.local_selector);
            match l.version {
                // The event indexes the message id the encoded message hashes to.
                CcipLaneVersion::V2_0 => assert_eq!(m.message_id, l.topics[3]),
                // The event indexes the sequence number.
                CcipLaneVersion::V1_6 => assert_eq!(word(m.sequence as u128), l.topics[2]),
                CcipLaneVersion::V1_5 => assert!(m.token.is_some()),
            }
        }
        // The recorded 2.0.0 messages: a token transfer and a data message.
        let v2: Vec<_> = logs
            .iter()
            .filter(|l| l.version == CcipLaneVersion::V2_0)
            .map(|l| read(&l.route, &l.data).unwrap())
            .collect();
        assert!(
            v2.iter()
                .any(|m| m.token.as_ref().is_some_and(|t| t.amount > 0))
        );
        assert!(v2.iter().any(|m| m.token.is_none() && !m.data.is_empty()));
    }

    #[test]
    fn a_message_on_a_lane_of_another_version_is_refused() {
        for l in recorded() {
            for other in CcipLaneVersion::ALL.into_iter().filter(|v| *v != l.version) {
                let mut route = l.route.clone();
                route.lane_limits = Some(CcipLane {
                    version: other,
                    ..route.lane_limits.unwrap()
                });
                assert!(
                    read(&route, &l.data).is_err(),
                    "a {} message read on a {} lane",
                    l.version.as_str(),
                    other.as_str()
                );
                assert!(!onramp_log_matches(other, &l.topics, &l.data, &route));
            }
        }
    }

    #[test]
    fn an_altered_or_misrouted_mainnet_message_is_refused() {
        for l in recorded() {
            // Bytes the message id covers. In a 2.0.0 event that is the
            // encoded message, the third field's tail.
            let (from, to) = match l.version {
                CcipLaneVersion::V2_0 => {
                    let len =
                        u32::from_be_bytes(l.data[160 + 28..192].try_into().unwrap()) as usize;
                    (192, 192 + len)
                }
                _ => (32, l.data.len()),
            };
            for at in [from + 1, from + 9, (from + to) / 2, to - 1] {
                let mut bad = l.data.clone();
                bad[at] ^= 1;
                match (l.version, read(&l.route, &bad)) {
                    // A 2.0.0 message's id is the hash of its bytes: an
                    // altered message is another message, which the event's
                    // indexed id no longer names.
                    (CcipLaneVersion::V2_0, Ok(m)) => {
                        assert_ne!(m.message_id, l.topics[3], "byte {at}");
                        assert!(
                            !onramp_log_matches(l.version, &l.topics, &bad, &l.route),
                            "byte {at}"
                        );
                    }
                    (_, r) => assert!(r.is_err(), "{} byte {at}", l.version.as_str()),
                }
            }
            // The same message is not one of another on-ramp's lane.
            let mut other_ramp = l.route.clone();
            other_ramp.ramp[31] ^= 1;
            assert!(
                read(&other_ramp, &l.data).is_err(),
                "{}",
                l.version.as_str()
            );
            // A 1.5.0 on-ramp serves one destination, which only the message
            // id binds.
            if l.version == CcipLaneVersion::V1_5 {
                let mut other_dest = l.route.clone();
                other_dest.local_selector += 1;
                assert!(read(&other_dest, &l.data).is_err());
            }
        }
    }

    /// A `2.0.0` event for a transfer of `amount` to [`RECIPIENT`] on `route`.
    fn body_2_0(route: &BridgeRoute, seq: u64, amount: u128) -> Vec<u8> {
        let short = |out: &mut Vec<u8>, b: &[u8]| {
            out.push(b.len() as u8);
            out.extend_from_slice(b);
        };
        let mut token = vec![1u8];
        token.extend_from_slice(&word(amount));
        short(&mut token, &pad(&POOL));
        short(&mut token, &pad(&[0x61; 20]));
        short(&mut token, &ENDPOINT);
        short(&mut token, &RECIPIENT);
        token.extend_from_slice(&0u16.to_be_bytes());
        let mut m = vec![1u8];
        m.extend_from_slice(&route.source_chain_id.to_be_bytes());
        m.extend_from_slice(&route.local_selector.to_be_bytes());
        m.extend_from_slice(&seq.to_be_bytes());
        m.extend_from_slice(&[0u8; 4 + 4 + 4 + 32]);
        short(&mut m, &route.ramp);
        short(&mut m, &[0x62; 32]);
        short(&mut m, &pad(&[0x99; 20]));
        short(&mut m, &RECIPIENT);
        m.extend_from_slice(&0u16.to_be_bytes());
        m.extend_from_slice(&(token.len() as u16).to_be_bytes());
        m.extend_from_slice(&token);
        m.extend_from_slice(&0u16.to_be_bytes());
        let receipt = abi_tuple(&[
            Field::Word(pad(&[0x63; 20])),
            Field::Word(word(90_000)),
            Field::Word(word(32)),
            Field::Word(word(7)),
            Field::Tail(abi_bytes(&[])),
        ]);
        abi_tuple(&[
            Field::Word(pad(&[0x44; 20])),
            Field::Word(word(amount)),
            Field::Tail(abi_bytes(&m)),
            Field::Tail(abi_array(vec![receipt])),
            Field::Tail(abi_array(vec![abi_bytes(&[5, 6])])),
        ])
    }

    /// A `1.5.0` event for a transfer of `amount` to the 20-byte account
    /// `receiver` on `route`.
    fn body_1_5(route: &BridgeRoute, seq: u64, amount: u128, receiver: &[u8; 20]) -> Vec<u8> {
        let sender = pad(&[0x99; 20]);
        let fee_token = pad(&[0x44; 20]);
        let token_data = abi_tuple(&[Field::Tail(abi_tuple(&[
            Field::Tail(abi_bytes(&pad(&POOL))),
            Field::Tail(abi_bytes(&ENDPOINT)),
            Field::Tail(abi_bytes(&[])),
            Field::Word(word(90_000)),
        ]))]);
        let mut tokens = word(1).to_vec();
        tokens.extend_from_slice(&pad(&[0x61; 20]));
        tokens.extend_from_slice(&word(amount));
        let token_data_array = abi_array(vec![abi_bytes(&token_data)]);
        let metadata = keccak(&[
            &keccak(&[b"EVM2EVMMessageHashV2"]),
            &word(route.source_chain_id as u128),
            &word(route.local_selector as u128),
            &route.ramp,
        ]);
        let fixed = keccak(&[
            &sender,
            &pad(receiver),
            &word(seq as u128),
            &word(0),
            &word(0),
            &word(0),
            &fee_token,
            &word(3),
        ]);
        let id = keccak(&[
            &[0u8; 32],
            &metadata,
            &fixed,
            &keccak(&[&[]]),
            &keccak(&[&abi_tuple(&[Field::Tail(tokens.clone())])]),
            &keccak(&[&abi_tuple(&[Field::Tail(token_data_array.clone())])]),
        ]);
        abi_tuple(&[Field::Tail(abi_tuple(&[
            Field::Word(word(route.source_chain_id as u128)),
            Field::Word(sender),
            Field::Word(pad(receiver)),
            Field::Word(word(seq as u128)),
            Field::Word(word(0)),
            Field::Word(word(0)),
            Field::Word(word(0)),
            Field::Word(fee_token),
            Field::Word(word(3)),
            Field::Tail(abi_bytes(&[])),
            Field::Tail(tokens),
            Field::Tail(token_data_array),
            Field::Word(id),
        ]))])
    }

    #[test]
    fn every_lane_version_carries_a_transfer_through_the_framework() {
        let receiver_20 = [0x77; 20];
        let mut tenzro_receiver = receiver_20.to_vec();
        tenzro_receiver.extend_from_slice(&[0u8; 12]);
        for version in CcipLaneVersion::ALL {
            let mut route = evm_route("ethereum");
            route.lane_limits = Some(CcipLane {
                version,
                ..route.lane_limits.unwrap()
            });
            let f = RouteFramework::new();
            // The locked TNZO an inbound transfer releases left over a lane
            // Tenzro sends on; a 1.5.0 lane carries nothing out.
            let mut sending = route.clone();
            sending.lane_limits = Some(CcipLane {
                version: CcipLaneVersion::V1_6,
                ..route.lane_limits.unwrap()
            });
            let mut s = MemState::with(std::slice::from_ref(&sending));
            lock(&f, &mut s, &sending, 1_000, vec![0x12; 20]);
            s.routes.insert(route.storage_key(), route.clone());
            let mut bodies = vec![
                (
                    CcipLaneVersion::V2_0,
                    body_2_0(&route, 9, 250),
                    RECIPIENT.to_vec(),
                ),
                (
                    CcipLaneVersion::V1_6,
                    evm_body(&route, 9, 250),
                    RECIPIENT.to_vec(),
                ),
                (
                    CcipLaneVersion::V1_5,
                    body_1_5(&route, 9, 250, &receiver_20),
                    tenzro_receiver.clone(),
                ),
            ];
            // The lane's own version last, so every other one is refused on
            // its layout and not on a used nonce.
            bodies.sort_by_key(|(v, ..)| *v == version);
            for (body_version, body, receiver) in bodies {
                let d = deliver(&route, &keys(), 3, 9, EXPIRY, &body, &[]);
                let result = f.admit_inbound(&mut s, BridgeRouteAdapter::Ccip, "ethereum", &d);
                if body_version == version {
                    let admitted = result.unwrap();
                    assert_eq!(admitted.message.amount, 250);
                    assert_eq!(admitted.message.receiver, receiver);
                    assert_eq!(admitted.message.sequence, 9);
                } else {
                    assert!(
                        result.is_err(),
                        "a {} message admitted on a {} lane",
                        body_version.as_str(),
                        version.as_str()
                    );
                }
            }
        }
    }
}

mod ccip_outbound_versions {
    use sha3::{Digest, Keccak256};

    use super::super::evm::{MessageV1, TokenTransferV1};
    use super::*;

    const MAINNET: &str = include_str!("../../tests/fixtures/ccip/mainnet_onramp_logs.json");
    const OFF_RAMP: [u8; 20] = [0x0f; 20];
    const CCV_HASH: [u8; 32] = [0xcc; 32];

    fn lane_route(version: CcipLaneVersion) -> BridgeRoute {
        let mut route = evm_route("ethereum");
        route.lane_limits = Some(CcipLane {
            version,
            off_ramp: OFF_RAMP,
            ccv_and_executor_hash: CCV_HASH,
            ..route.lane_limits.unwrap()
        });
        route
    }

    /// The encoded messages of the recorded mainnet `2.0.0` sends.
    fn recorded_messages() -> Vec<Vec<u8>> {
        let f: serde_json::Value = serde_json::from_str(MAINNET).unwrap();
        f["logs"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|l| l["version"] == "2.0.0")
            .map(|l| {
                let data =
                    hex::decode(l["data"].as_str().unwrap().trim_start_matches("0x")).unwrap();
                let o = u64::from_be_bytes(data[88..96].try_into().unwrap()) as usize;
                let n = u64::from_be_bytes(data[o + 24..o + 32].try_into().unwrap()) as usize;
                data[o + 32..o + 32 + n].to_vec()
            })
            .collect()
    }

    #[test]
    fn the_message_codec_reproduces_recorded_mainnet_messages_byte_for_byte() {
        let messages = recorded_messages();
        assert!(!messages.is_empty());
        let mut with_token = 0;
        for bytes in messages {
            let m = MessageV1::read(&bytes).unwrap();
            assert_eq!(m.encode().unwrap(), bytes);
            if let Some(t) = &m.token_transfer {
                with_token += 1;
                // An EVM destination names its off-ramp, receiver and token
                // in 20 bytes; an EVM source its on-ramp and sender in 32.
                assert_eq!(
                    (m.off_ramp.len(), m.receiver.len(), t.dest_token.len()),
                    (20, 20, 20)
                );
                assert_eq!(
                    (m.on_ramp.len(), m.sender.len(), t.source_pool.len()),
                    (32, 32, 32)
                );
            }
        }
        assert!(with_token > 0);
    }

    #[test]
    fn a_2_0_lane_sends_the_message_its_off_ramp_executes() {
        let route = lane_route(CcipLaneVersion::V2_0);
        let f = RouteFramework::new();
        let mut s = MemState::with(std::slice::from_ref(&route));
        let receiver = vec![0x12; 20];
        let out = f
            .send_outbound(
                &mut s,
                "ethereum",
                &OutboundTransfer {
                    sender: RECIPIENT.to_vec(),
                    recipient: receiver.clone(),
                    amount: 250,
                    asset: None,
                },
            )
            .unwrap();
        let m = MessageV1::read(&out.bytes).unwrap();
        let id: [u8; 32] = Keccak256::digest(&out.bytes).into();
        assert_eq!(out.message.message_id, id);
        assert_eq!(m.off_ramp, OFF_RAMP.to_vec());
        assert_eq!(m.ccv_and_executor_hash, CCV_HASH);
        assert_eq!(m.on_ramp, route.local_endpoint.to_vec());
        assert_eq!(
            (m.source_selector, m.dest_selector),
            (route.local_selector, route.source_chain_id)
        );
        assert_eq!(m.sender, RECIPIENT.to_vec());
        assert_eq!(m.receiver, receiver);
        assert!(m.data.is_empty() && m.dest_blob.is_empty() && m.receive_gas_limit == 0);
        assert_eq!(
            m.token_transfer,
            Some(TokenTransferV1 {
                amount: 250,
                source_pool: route.local_endpoint.to_vec(),
                source_token: route.local_endpoint.to_vec(),
                dest_token: route.remote_token[12..].to_vec(),
                token_receiver: receiver,
                extra_data: Vec::new(),
            })
        );
    }

    #[test]
    fn a_2_0_outbound_message_reads_back_only_on_its_own_lane() {
        let route = lane_route(CcipLaneVersion::V2_0);
        let f = RouteFramework::new();
        let mut s = MemState::with(std::slice::from_ref(&route));
        lock(&f, &mut s, &route, 100, vec![0x12; 20]);
        let bytes = s
            .get(&state::outbound_key(&route, 1))
            .expect("stored outbound message");
        let adapter = super::super::evm::EvmCcipAdapter::new();
        let mut r = Reader::new(&bytes);
        adapter.decode_outbound(&route, &mut r).unwrap();

        // Another off-ramp, or a message carrying data, is not this lane's.
        let mut other = route.clone();
        other.lane_limits = Some(CcipLane {
            off_ramp: [0x0e; 20],
            ..route.lane_limits.unwrap()
        });
        assert!(
            adapter
                .decode_outbound(&other, &mut Reader::new(&bytes))
                .is_err()
        );
        let mut m = MessageV1::read(&bytes).unwrap();
        m.data = vec![1];
        let tampered = m.encode().unwrap();
        assert!(
            adapter
                .decode_outbound(&route, &mut Reader::new(&tampered))
                .is_err()
        );
    }

    #[test]
    fn a_1_5_lane_carries_nothing_out_of_tenzro() {
        let route = lane_route(CcipLaneVersion::V1_5);
        let f = RouteFramework::new();
        let mut s = MemState::with(std::slice::from_ref(&route));
        let out = OutboundTransfer {
            sender: RECIPIENT.to_vec(),
            recipient: vec![0x12; 20],
            amount: 10,
            asset: None,
        };
        assert!(f.send_outbound(&mut s, "ethereum", &out).is_err());
    }
}

#[test]
fn a_lock_is_attested_by_the_committee_only_on_a_route_with_a_settlement_lock() {
    let event = receipt_proof::LockEvent {
        plan_id: [1; 32],
        leg_id: [2; 32],
        index: 1,
        payer: [3; 32],
        recipient: [4; 32],
        asset: [0; 32],
        amount: 700,
        escape_at_ms: 1_801_209_600_000,
    };
    let (f, mut s, route) = evm_setup(0);
    let d = deliver(&route, &keys(), 3, 9, EXPIRY, &event.encode(), &[]);
    let err = f
        .prove_lock(&mut s, BridgeRouteAdapter::Ccip, "ethereum", &d)
        .unwrap_err();
    assert!(err.to_string().contains("no settlement lock"), "{err}");

    let mut locked = evm_route("ethereum");
    locked.settlement_lock = Some([7; 32]);
    let mut s = MemState::with(std::slice::from_ref(&locked));
    let d = deliver(&locked, &keys(), 3, 9, EXPIRY, &event.encode(), &[]);
    let (got, proven, digest) = f
        .prove_lock(&mut s, BridgeRouteAdapter::Ccip, "ethereum", &d)
        .unwrap();
    assert_eq!(got, receipt_proof::LockRecord::Locked(event.clone()));
    assert!(!proven, "a committee attests, it does not prove");
    use sha2::Digest as _;
    assert_eq!(digest, <[u8; 32]>::from(sha2::Sha256::digest(&d)));
    assert!(
        f.prove_lock(&mut s, BridgeRouteAdapter::Ccip, "ethereum", &d)
            .is_err(),
        "replayed"
    );
    let short = deliver(&locked, &keys(), 3, 10, EXPIRY, &event.encode()[1..], &[]);
    assert!(
        f.prove_lock(&mut s, BridgeRouteAdapter::Ccip, "ethereum", &short)
            .is_err(),
        "not a lock event"
    );
    // The lock's reconciliation checkpoint is attested the same way, as its
    // 40-byte canonical body: what the Solana lock's `checkpoint` returns
    // after the shared reconciliation sequence.
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../sdk/fixtures/settlement_lock/solana_accumulator_body.hex"
    );
    let body = hex::decode(std::fs::read_to_string(path).unwrap().trim()).unwrap();
    let mut acc = [0u8; 32];
    acc.copy_from_slice(
        &hex::decode("375111922b0be21f25ad54b505467229080fd12340e5b01e4f56220cb3ecb58a").unwrap(),
    );
    let cp = receipt_proof::LockCheckpoint { count: 6, acc };
    assert_eq!(cp.encode(), body);
    let d = deliver(&locked, &keys(), 3, 11, EXPIRY, &cp.encode(), &[]);
    let (got, proven, _) = f
        .prove_lock(&mut s, BridgeRouteAdapter::Ccip, "ethereum", &d)
        .unwrap();
    assert_eq!(got, receipt_proof::LockRecord::Checkpoint(cp));
    assert!(!proven);
    let odd = deliver(&locked, &keys(), 3, 12, EXPIRY, &cp.encode()[1..], &[]);
    assert!(
        f.prove_lock(&mut s, BridgeRouteAdapter::Ccip, "ethereum", &odd)
            .is_err(),
        "neither length"
    );
}

// Carried assets: a listed external token held in the route's vault on the
// external chain while its representation is issued on Tenzro.

const USDC_POOL: [u8; 20] = [0x61; 20];
const USDC_TOKEN: [u8; 20] = [0x62; 20];

fn usdc(transfer: AssetTransfer) -> CarriedAsset {
    CarriedAsset {
        symbol: "USDC".into(),
        name: "USD Coin (bridged)".into(),
        decimals: 6,
        pool: pad(&USDC_POOL),
        remote_token: pad(&USDC_TOKEN),
        caip19: "eip155:1/erc20:0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48".into(),
        transfer,
        mint_limit: MintRateLimit {
            per_mint: 1_000,
            per_epoch: 5_000,
        },
        outflow: LaneRateLimit {
            capacity: 4_000,
            rate: 100,
        },
        lane: Some(AssetLane {
            inbound: LaneRateLimit {
                capacity: 4_000,
                rate: 100,
            },
        }),
        max_outstanding: 1_500,
        enabled: true,
    }
}

fn usdc_route(transfer: AssetTransfer) -> BridgeRoute {
    let mut route = evm_route("base");
    route.assets = vec![usdc(transfer)];
    route
}

fn usdc_body(route: &BridgeRoute, seq: u64, amount: u128) -> Vec<u8> {
    evm_body_from(
        route,
        seq,
        amount,
        USDC_POOL,
        route.assets[0].representation_id().to_vec(),
    )
}

fn redeem(amount: u128) -> OutboundTransfer {
    OutboundTransfer {
        sender: RECIPIENT.to_vec(),
        recipient: vec![0x12; 20],
        amount,
        asset: Some("USDC".into()),
    }
}

#[test]
fn a_carried_asset_is_locked_there_issued_here_and_capped_per_vault() {
    let route = usdc_route(AssetTransfer::LockAndMint);
    route.validate().unwrap();
    let f = RouteFramework::new();
    let mut s = MemState::with(std::slice::from_ref(&route));
    let asset = &route.assets[0];

    let d = deliver(
        &route,
        &keys(),
        3,
        1,
        EXPIRY,
        &usdc_body(&route, 1, 1_000),
        &[],
    );
    let admitted = f
        .admit_inbound(&mut s, BridgeRouteAdapter::Ccip, "base", &d)
        .unwrap();
    assert_eq!(
        admitted.asset.as_ref().map(|a| a.symbol.as_str()),
        Some("USDC")
    );
    let supply = state::read_asset_supply(&s, &route, asset);
    assert_eq!((supply.locked, supply.bridged), (1_000, 1_000));
    // TNZO's own record is untouched.
    assert_eq!(read_supply(&s, &route), SupplyRecord::default());

    // The vault may back at most 1_500.
    let d = deliver(
        &route,
        &keys(),
        3,
        2,
        EXPIRY,
        &usdc_body(&route, 2, 600),
        &[],
    );
    let err = f
        .admit_inbound(&mut s, BridgeRouteAdapter::Ccip, "base", &d)
        .unwrap_err();
    assert!(err.to_string().contains("above its cap"), "{err}");

    // Redemption releases from the vault, never more than it backs.
    let out = f.send_outbound(&mut s, "base", &redeem(400)).unwrap();
    assert_eq!(out.asset.as_ref().map(|a| a.symbol.as_str()), Some("USDC"));
    assert_eq!(out.message.token, pad(&USDC_TOKEN));
    assert_eq!(state::read_asset_supply(&s, &route, asset).locked, 600);
    assert!(f.send_outbound(&mut s, "base", &redeem(700)).is_err());
    assert!(f.send_outbound(&mut s, "base", &redeem(1)).is_ok());
}

#[test]
fn a_carried_asset_ships_disabled_and_a_disabled_route_only_redeems() {
    let mut route = usdc_route(AssetTransfer::LockAndMint);
    route.assets[0].enabled = false;
    let f = RouteFramework::new();
    let mut s = MemState::with(std::slice::from_ref(&route));
    let d = deliver(
        &route,
        &keys(),
        3,
        1,
        EXPIRY,
        &usdc_body(&route, 1, 100),
        &[],
    );
    let err = f
        .admit_inbound(&mut s, BridgeRouteAdapter::Ccip, "base", &d)
        .unwrap_err();
    assert!(err.to_string().contains("not enabled"), "{err}");

    route.assets[0].enabled = true;
    let mut s = MemState::with(std::slice::from_ref(&route));
    f.admit_inbound(&mut s, BridgeRouteAdapter::Ccip, "base", &d)
        .unwrap();
    s.modes
        .insert(route.storage_key(), BridgeRouteMode::Disabled);
    let d = deliver(
        &route,
        &keys(),
        3,
        2,
        EXPIRY,
        &usdc_body(&route, 2, 100),
        &[],
    );
    let err = f
        .admit_inbound(&mut s, BridgeRouteAdapter::Ccip, "base", &d)
        .unwrap_err();
    assert!(err.to_string().contains("credits no new USDC"), "{err}");
    f.send_outbound(&mut s, "base", &redeem(50)).unwrap();
    s.modes.insert(route.storage_key(), BridgeRouteMode::Paused);
    assert!(f.send_outbound(&mut s, "base", &redeem(50)).is_err());
}

struct TestIssuer;

impl IssuerTransferHook for TestIssuer {
    fn protocol(&self) -> &str {
        "issuer-native"
    }
    fn verify_burn(
        &self,
        _: &BridgeRoute,
        asset: &CarriedAsset,
        message: &RouteMessage,
        _: &[u8],
    ) -> Result<()> {
        if message.token_pool != asset.pool {
            return Err(BridgeError::TransferFailed(
                "not the issuer's messenger".into(),
            ));
        }
        Ok(())
    }
    fn mint_instruction(
        &self,
        _: &BridgeRoute,
        _: &CarriedAsset,
        message: &RouteMessage,
    ) -> Result<Vec<u8>> {
        Ok([b"mint".as_slice(), &message.amount.to_be_bytes()].concat())
    }
}

#[test]
fn burn_and_mint_needs_the_issuers_hook_under_a_named_account() {
    let operator = hex::encode([0x42u8; 32]);
    let route = usdc_route(AssetTransfer::BurnAndMint {
        protocol: "issuer-native".into(),
        operator,
    });
    route.validate().unwrap();
    let d = deliver(
        &route,
        &keys(),
        3,
        1,
        EXPIRY,
        &usdc_body(&route, 1, 300),
        &[],
    );

    let bare = RouteFramework::new();
    let mut s = MemState::with(std::slice::from_ref(&route));
    let err = bare
        .admit_inbound(&mut s, BridgeRouteAdapter::Ccip, "base", &d)
        .unwrap_err();
    assert!(err.to_string().contains("no issuer transfer hook"), "{err}");

    let f = RouteFramework::new().with_issuer_hook(Arc::new(TestIssuer));
    f.admit_inbound(&mut s, BridgeRouteAdapter::Ccip, "base", &d)
        .unwrap();
    let out = f.send_outbound(&mut s, "base", &redeem(100)).unwrap();
    assert_eq!(
        out.bytes,
        [b"mint".as_slice(), &100u128.to_be_bytes()].concat()
    );

    let stranger = usdc_route(AssetTransfer::BurnAndMint {
        protocol: "issuer-native".into(),
        operator: "someone-else".into(),
    });
    assert!(stranger.validate().is_err());
}

#[test]
fn carried_assets_follow_the_asset_rules() {
    let ok = usdc_route(AssetTransfer::LockAndMint);
    let broken = |edit: &dyn Fn(&mut BridgeRoute)| {
        let mut r = ok.clone();
        edit(&mut r);
        r.validate().is_err()
    };
    assert!(broken(&|r| r.assets.push(r.assets[0].clone())));
    assert!(broken(&|r| r.assets[0].pool = r.peer));
    assert!(broken(&|r| r.assets[0].symbol = "TNZO".into()));
    assert!(broken(&|r| r.assets[0].symbol = "usdc".into()));
    assert!(broken(&|r| r.assets[0].max_outstanding = 0));
    assert!(broken(&|r| r.assets[0].lane = None));
    assert!(broken(&|r| r.assets[0].mint_limit.per_mint = 2_000));
    assert!(broken(&|r| r.assets[0].caip19 = "USDC".into()));
    assert!(broken(&|r| r.assets[0].caip19 = "eip155:1".into()));
    // Two assets, or an asset and the native coin, never share an id.
    assert!(broken(&|r| {
        let mut other = r.assets[0].clone();
        other.symbol = "OUSD".into();
        other.pool = [0x77; 32];
        other.remote_token = [0x78; 32];
        r.assets.push(other);
    }));
    assert!(broken(
        &|r| r.native_asset = Some(r.assets[0].caip19.clone())
    ));
    assert!(broken(&|r| r.native_asset = Some("ether".into())));
    // A locked leg's asset maps to its CAIP-19 id: the native coin for the
    // zero asset, a carried asset by its external token, nothing otherwise.
    let mut r = ok.clone();
    r.native_asset = Some("eip155:1/slip44:60".into());
    assert_eq!(r.validate(), Ok(()));
    assert_eq!(r.caip19_of(&[0; 32]), Some("eip155:1/slip44:60"));
    assert_eq!(
        r.caip19_of(&pad(&USDC_TOKEN)),
        Some(ok.assets[0].caip19.as_str())
    );
    assert_eq!(r.caip19_of(&[0x78; 32]), None);
    assert_eq!(ok.caip19_of(&[0; 32]), None);
    for id in [
        "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp/token:EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
        "bip122:000000000019d6689c085ae165831e93/slip44:0",
        "cosmos:cosmoshub-4/ibc:ABC123",
    ] {
        assert!(tenzro_types::bridge_route::is_caip19(id), "{id}");
    }
    for id in [
        "",
        "eip155:1/",
        "/slip44:60",
        "EIP155:1/slip44:60",
        "eip155:1/slip44:60/x",
    ] {
        assert!(!tenzro_types::bridge_route::is_caip19(id), "{id}");
    }
    // The same symbol on any route is one representation.
    let mut sol = solana_route();
    sol.assets = ok.assets.clone();
    assert_eq!(
        sol.assets[0].representation_id(),
        ok.assets[0].representation_id()
    );
}

#[test]
fn every_route_draws_on_its_outflow_bucket_and_the_network_outflow_cap() {
    let mut route = solana_route();
    route.outflow = LaneRateLimit {
        capacity: 500,
        rate: 1,
    };
    let f = RouteFramework::new();
    let mut s = MemState::with(std::slice::from_ref(&route));
    let out = |amount| OutboundTransfer {
        sender: RECIPIENT.to_vec(),
        recipient: vec![0x21; 32],
        amount,
        asset: None,
    };
    f.send_outbound(&mut s, "solana", &out(400)).unwrap();
    let err = f.send_outbound(&mut s, "solana", &out(200)).unwrap_err();
    assert!(err.to_string().contains("lane"), "{err}");
    let bucket = lane::lane_bucket(&s, &route, lane::LaneDirection::Outbound).unwrap();
    assert_eq!(bucket.tokens, 100);

    // The network-wide cap binds over every route together, per epoch.
    s.elapsed_ms += 1_000_000;
    s.outflow = Some(NetworkOutflowLimits {
        caps: vec![OutflowCap {
            unit: TNZO_UNIT.into(),
            per_epoch: 450,
        }],
    });
    let err = f.send_outbound(&mut s, "solana", &out(100)).unwrap_err();
    assert!(err.to_string().contains("outflow cap"), "{err}");
    f.send_outbound(&mut s, "solana", &out(50)).unwrap();
    s.epoch += 1;
    f.send_outbound(&mut s, "solana", &out(100)).unwrap();

    // A unit no cap names cannot leave.
    s.outflow = Some(NetworkOutflowLimits {
        caps: vec![OutflowCap {
            unit: "USDC".into(),
            per_epoch: 1_000,
        }],
    });
    assert!(f.check_outbound(&s, "solana", 1).is_err());
}

/// A signed delivery for the Ethereum route, decoded for tampering.
fn signed_evm_delivery(route: &BridgeRoute, nonce: u64) -> Delivery {
    let bytes = deliver(
        route,
        &keys(),
        3,
        nonce,
        EXPIRY,
        &evm_body(route, nonce, 10),
        &[],
    );
    Delivery::decode(&bytes).unwrap()
}

fn admit_err(f: &RouteFramework, s: &mut MemState, d: &Delivery) -> String {
    f.admit_inbound(s, BridgeRouteAdapter::Ccip, "ethereum", &d.encode())
        .unwrap_err()
        .to_string()
}

#[test]
fn a_delivery_carries_both_signature_legs_through_encoding() {
    let (_, _, route) = evm_setup(0);
    let d = signed_evm_delivery(&route, 5);
    assert_eq!(d.committee.len(), 3);
    assert_eq!(d.committee_pq.len(), 3);
    assert_eq!(d.blessing_pq.len(), 3);
    assert_eq!(Delivery::decode(&d.encode()).unwrap(), d);
}

#[test]
fn a_committee_attestation_forged_on_the_classical_leg_alone_is_refused() {
    let (f, mut s, route) = evm_setup(1_000);

    // A forger who breaks secp256k1 signs for three seats but holds no
    // ML-DSA-65 key of theirs.
    let mut d = signed_evm_delivery(&route, 5);
    d.committee_pq.clear();
    d.blessing_pq.clear();
    let err = admit_err(&f, &mut s, &d);
    assert!(err.contains("ML-DSA-65"), "{err}");

    // The forger supplies ML-DSA-65 signatures of their own key.
    let digest = attestation_digest(&route, &d);
    let forger = super::attestation::testing::pq_key(b"forger");
    let wrong_pq = |keys: &[k256::ecdsa::SigningKey]| {
        keys.iter()
            .take(3)
            .map(|k| super::attestation::testing::sign_pq(&forger, member_address(k), &digest))
            .collect::<Vec<_>>()
    };
    d.committee_pq = wrong_pq(&keys().committee);
    d.blessing_pq = wrong_pq(&keys().blessing);
    let err = admit_err(&f, &mut s, &d);
    assert!(err.contains("ML-DSA-65"), "{err}");

    // Valid ML-DSA-65 signatures with forged secp256k1 signatures fail too.
    let mut d = signed_evm_delivery(&route, 5);
    for (_, sig) in d.committee.iter_mut() {
        sig[10] ^= 0xFF;
    }
    assert!(admit_err(&f, &mut s, &d).contains("verifiers"));

    // Nothing was minted by any attempt, and the honest delivery still lands.
    let honest = signed_evm_delivery(&route, 5);
    f.admit_inbound(
        &mut s,
        BridgeRouteAdapter::Ccip,
        "ethereum",
        &honest.encode(),
    )
    .unwrap();
}

#[test]
fn a_member_counts_only_with_both_legs() {
    let (f, mut s, route) = evm_setup(1_000);
    // Three classical signatures, but only two members' ML-DSA-65 legs.
    let mut d = signed_evm_delivery(&route, 5);
    d.committee_pq.truncate(2);
    let err = admit_err(&f, &mut s, &d);
    assert!(err.contains("only 2 members signed with both"), "{err}");
    // Two classical signatures with all three ML-DSA-65 legs: short as well.
    let mut d = signed_evm_delivery(&route, 5);
    d.committee.truncate(2);
    assert!(admit_err(&f, &mut s, &d).contains("signatures < threshold"));
    // A tampered ML-DSA-65 signature drops that member.
    let mut d = signed_evm_delivery(&route, 5);
    d.committee_pq[0].1[100] ^= 0x01;
    assert!(admit_err(&f, &mut s, &d).contains("only 2 members signed with both"));
}

#[test]
fn a_committee_member_without_an_ml_dsa_key_cannot_sit_on_a_route() {
    let mut route = evm_route("ethereum");
    route.verifiers.members[0].pq_public_key.clear();
    assert!(matches!(
        route.validate(),
        Err(BridgeRouteError::MissingPqKey { .. })
    ));
}

#[test]
fn the_classical_ceiling_caps_every_route_whose_destination_verifies_classical_signatures() {
    let route = evm_route("ethereum");
    assert!(route.family.verification_is_classical());
    let limits = NetworkMintLimits {
        proven: MintRateLimit {
            per_mint: 10_000,
            per_epoch: 100_000,
        },
        attested: MintRateLimit {
            per_mint: 2_000,
            per_epoch: 20_000,
        },
        classical: MintRateLimit {
            per_mint: 500,
            per_epoch: 3_000,
        },
    };
    limits.validate().unwrap();
    assert_eq!(
        limits.for_route(&route),
        MintRateLimit {
            per_mint: 500,
            per_epoch: 3_000
        }
    );
    // Raising the ceiling is a bounded step like any other network limit.
    let mut raised = limits;
    raised.classical.per_mint = 5_000;
    assert!(raised.raised_within(&limits, 1_000).is_err());
}
