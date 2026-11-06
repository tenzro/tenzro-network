//! IBC routes of both versions through the framework: the classic
//! handshakes, packets out with their acknowledgement or timeout, and
//! packets in with their receipt and acknowledgement, each step proven
//! against the route's Tendermint light client.

use std::sync::Arc;

use sha2::{Digest, Sha256};
use tenzro_types::bridge_transfer::IbcMsg;

use super::ibc::{
    FungibleTokenPacketData, Packet, SUCCESS_ACK, ack_commitment, ack_key, receipt_key,
    receipt_value,
};
use super::ibc_core::{
    DELIVERED, EndState, REFUNDED, channel_end, channel_path, connection_end, connection_path,
    packet_status, status, store_key,
};
use super::state::read_supply;
use super::tendermint::TendermintLightClient;
use super::tendermint::fixtures::*;
use super::test_support::*;
use super::*;

const CHAIN: &str = "osmosis";
const CHAIN_ID: &str = "osmosis-1";
const CP_CLIENT: &str = "08-wasm-3";
const CP_CONNECTION: &str = "connection-12";
const CP_CHANNEL: &str = "channel-141";
const SENDER: [u8; 32] = [0x77; 32];
const NOW_S: u64 = (NOW_MS / 1000) as u64;
const TIMEOUT_SECS: u64 = 3_600;

struct T {
    f: RouteFramework,
    s: MemState,
    route: BridgeRoute,
    vals: Validators,
    version: IbcVersion,
}

fn ibc_route(version: IbcVersion) -> BridgeRoute {
    let ibc = IbcRoute {
        version,
        counterparty_client_id: CP_CLIENT.into(),
        counterparty_connection_id: (version == IbcVersion::Classic).then(|| CP_CONNECTION.into()),
        counterparty_channel_id: (version == IbcVersion::Classic).then(|| CP_CHANNEL.into()),
        packet_timeout_secs: TIMEOUT_SECS,
    };
    let mut ramp = [0u8; 32];
    ramp[..3].copy_from_slice(b"ibc");
    BridgeRoute {
        adapter: BridgeRouteAdapter::Ibc,
        family: ChainFamily::Cosmos,
        source_chain: CHAIN.into(),
        source_chain_id: 118,
        local_selector: 7_777,
        peer: IbcRoute::end_hash(ibc.counterparty_packet_id()),
        ramp,
        local_endpoint: IbcRoute::end_hash(&ibc.tenzro_packet_id(CHAIN)),
        remote_token: Sha256::digest(ibc.tnzo_trace().as_bytes()).into(),
        verifiers: committee(1, 5, 3).1,
        blessing: None,
        light_client: None,
        mint_limit: MintRateLimit {
            per_mint: 1_000,
            per_epoch: 1_500,
        },
        outflow: tenzro_types::bridge_route::LaneRateLimit {
            capacity: u128::MAX,
            rate: u128::MAX / 2,
        },
        lane_limits: None,
        ibc: Some(ibc),
        settlement_lock: None,
        native_asset: None,
        assets: Vec::new(),
    }
}

fn setup(version: IbcVersion) -> T {
    let vals = Validators::new(3, 4);
    let trusted = header(
        CHAIN_ID,
        100,
        NOW_S - 1_000,
        vals.hash(),
        vals.hash(),
        [0x21; 32],
    );
    let mut route = ibc_route(version);
    route.light_client = Some(LightClientAnchor::Tendermint {
        chain_id: CHAIN_ID.into(),
        trusted_height: 100,
        trusted_header_hash: trusted.hash(),
        trusting_period_secs: 14 * 24 * 3600,
    });
    route.validate().unwrap();
    let f = RouteFramework::new().with_light_client(Arc::new(TendermintLightClient));
    let mut s = MemState::with(std::slice::from_ref(&route));
    f.advance_light_client(&mut s, BridgeRouteAdapter::Ibc, CHAIN, &bootstrap(&trusted))
        .unwrap();
    T {
        f,
        s,
        route,
        vals,
        version,
    }
}

impl T {
    /// A header at `height` and `seconds` committing a store of `entries`,
    /// and the proof of `key` in it.
    fn prove_at(
        &mut self,
        height: u64,
        seconds: u64,
        entries: Vec<(Vec<u8>, Vec<u8>)>,
        key: &[u8],
    ) -> Vec<u8> {
        let store = StoreFixture::new("ibc", entries);
        let h = header(
            CHAIN_ID,
            height,
            seconds,
            self.vals.hash(),
            self.vals.hash(),
            store.app_hash,
        );
        let c = self.vals.commit(&h, 3);
        let set = self.vals.set();
        self.f
            .advance_light_client(
                &mut self.s,
                BridgeRouteAdapter::Ibc,
                CHAIN,
                &update(100, &h, &c, &set, &set),
            )
            .unwrap();
        store.proof(key, height).encode()
    }

    fn prove(&mut self, height: u64, entries: Vec<(Vec<u8>, Vec<u8>)>, key: &[u8]) -> Vec<u8> {
        self.prove_at(height, NOW_S - 500, entries, key)
    }

    fn ibc(&mut self, msg: IbcMsg) -> crate::Result<ibc_core::IbcOutcome> {
        self.f.handle_ibc(&mut self.s, CHAIN, &msg).map(|(_, o)| o)
    }

    fn send(&mut self, amount: u128) -> crate::Result<OutboundMessage> {
        self.f.send_outbound(
            &mut self.s,
            CHAIN,
            &OutboundTransfer {
                sender: SENDER.to_vec(),
                recipient: b"osmo1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5x".to_vec(),
                amount,
                asset: None,
            },
        )
    }

    fn get(&self, path: &[u8]) -> Option<Vec<u8>> {
        self.s.get(&store_key(path))
    }

    /// Run the classic handshakes to an open channel, proving each Cosmos end
    /// at the next of the heights after `base`.
    fn open(&mut self, base: u64) {
        if self.version == IbcVersion::V2 {
            return;
        }
        let tenzro_client = IbcRoute::tenzro_client_id(CHAIN);
        let tenzro_connection = IbcRoute::tenzro_connection_id(CHAIN);
        let tenzro_channel = IbcRoute::tenzro_channel_id(CHAIN);
        let cp_conn = connection_path(CP_CONNECTION);
        let cp_chan = channel_path(CP_CHANNEL);
        let p = self.prove(
            base + 1,
            vec![(
                cp_conn.clone(),
                connection_end(EndState::Init, CP_CLIENT, &tenzro_client, ""),
            )],
            &cp_conn,
        );
        self.ibc(IbcMsg::ConnectionOpenTry { proof: p }).unwrap();
        let p = self.prove(
            base + 2,
            vec![(
                cp_conn.clone(),
                connection_end(
                    EndState::Open,
                    CP_CLIENT,
                    &tenzro_client,
                    &tenzro_connection,
                ),
            )],
            &cp_conn,
        );
        self.ibc(IbcMsg::ConnectionOpenConfirm { proof: p })
            .unwrap();
        let p = self.prove(
            base + 3,
            vec![(
                cp_chan.clone(),
                channel_end(EndState::Init, "", CP_CONNECTION),
            )],
            &cp_chan,
        );
        self.ibc(IbcMsg::ChannelOpenTry { proof: p }).unwrap();
        let p = self.prove(
            base + 4,
            vec![(
                cp_chan.clone(),
                channel_end(EndState::Open, &tenzro_channel, CP_CONNECTION),
            )],
            &cp_chan,
        );
        self.ibc(IbcMsg::ChannelOpenConfirm { proof: p }).unwrap();
    }

    fn cp_id(&self) -> &'static str {
        match self.version {
            IbcVersion::Classic => CP_CHANNEL,
            IbcVersion::V2 => CP_CLIENT,
        }
    }
}

#[test]
fn the_classic_handshakes_open_the_channel_only_on_proofs_of_the_cosmos_ends() {
    let mut t = setup(IbcVersion::Classic);
    let tenzro_client = IbcRoute::tenzro_client_id(CHAIN);
    let tenzro_connection = IbcRoute::tenzro_connection_id(CHAIN);
    let tenzro_channel = IbcRoute::tenzro_channel_id(CHAIN);
    let cp_conn = connection_path(CP_CONNECTION);
    let cp_chan = channel_path(CP_CHANNEL);

    // Nothing travels before the channel is open.
    assert!(t.send(10).is_err());

    // A Cosmos end towards another client, or one that is already open, is
    // not the INIT end the handshake starts from.
    for (height, wrong) in [
        (
            101,
            connection_end(EndState::Init, CP_CLIENT, "07-tendermint-other", ""),
        ),
        (
            102,
            connection_end(EndState::Open, CP_CLIENT, &tenzro_client, ""),
        ),
        (
            103,
            connection_end(EndState::Init, "08-wasm-9", &tenzro_client, ""),
        ),
    ] {
        let p = t.prove(height, vec![(cp_conn.clone(), wrong)], &cp_conn);
        assert!(t.ibc(IbcMsg::ConnectionOpenTry { proof: p }).is_err());
    }
    // Nor does an absent Cosmos end.
    let p = t.prove(
        104,
        vec![(b"connections/connection-99".to_vec(), vec![1])],
        &cp_conn,
    );
    assert!(t.ibc(IbcMsg::ConnectionOpenTry { proof: p }).is_err());
    // A channel cannot open on a connection that is not open.
    let p = t.prove(
        105,
        vec![(
            cp_chan.clone(),
            channel_end(EndState::Init, "", CP_CONNECTION),
        )],
        &cp_chan,
    );
    assert!(t.ibc(IbcMsg::ChannelOpenTry { proof: p }).is_err());

    let init = connection_end(EndState::Init, CP_CLIENT, &tenzro_client, "");
    let p = t.prove(106, vec![(cp_conn.clone(), init)], &cp_conn);
    t.ibc(IbcMsg::ConnectionOpenTry { proof: p.clone() })
        .unwrap();
    assert_eq!(
        t.get(&connection_path(&tenzro_connection)),
        Some(connection_end(
            EndState::TryOpen,
            &tenzro_client,
            CP_CLIENT,
            CP_CONNECTION
        ))
    );
    assert!(
        t.ibc(IbcMsg::ConnectionOpenTry { proof: p }).is_err(),
        "a second try"
    );

    // Confirm needs the Cosmos end OPEN towards Tenzro's connection.
    let wrong = connection_end(
        EndState::Open,
        CP_CLIENT,
        &tenzro_client,
        "connection-other",
    );
    let p = t.prove(107, vec![(cp_conn.clone(), wrong)], &cp_conn);
    assert!(t.ibc(IbcMsg::ConnectionOpenConfirm { proof: p }).is_err());
    let open = connection_end(
        EndState::Open,
        CP_CLIENT,
        &tenzro_client,
        &tenzro_connection,
    );
    let p = t.prove(108, vec![(cp_conn.clone(), open)], &cp_conn);
    t.ibc(IbcMsg::ConnectionOpenConfirm { proof: p.clone() })
        .unwrap();
    assert!(
        t.ibc(IbcMsg::ConnectionOpenConfirm { proof: p }).is_err(),
        "a second confirm"
    );

    let p = t.prove(
        109,
        vec![(
            cp_chan.clone(),
            channel_end(EndState::Init, "", "connection-other"),
        )],
        &cp_chan,
    );
    assert!(t.ibc(IbcMsg::ChannelOpenTry { proof: p }).is_err());
    let p = t.prove(
        110,
        vec![(
            cp_chan.clone(),
            channel_end(EndState::Init, "", CP_CONNECTION),
        )],
        &cp_chan,
    );
    t.ibc(IbcMsg::ChannelOpenTry { proof: p }).unwrap();
    assert!(t.send(10).is_err(), "a channel in TRYOPEN carries nothing");
    let p = t.prove(
        111,
        vec![(
            cp_chan.clone(),
            channel_end(EndState::Open, "channel-other", CP_CONNECTION),
        )],
        &cp_chan,
    );
    assert!(t.ibc(IbcMsg::ChannelOpenConfirm { proof: p }).is_err());
    let p = t.prove(
        112,
        vec![(
            cp_chan.clone(),
            channel_end(EndState::Open, &tenzro_channel, CP_CONNECTION),
        )],
        &cp_chan,
    );
    t.ibc(IbcMsg::ChannelOpenConfirm { proof: p }).unwrap();

    let st = status(&t.s, &t.route).unwrap();
    assert_eq!(st.connection, Some((tenzro_connection, Some("OPEN"))));
    assert_eq!(st.channel, Some((tenzro_channel.clone(), Some("OPEN"))));

    // The open channel carries a packet, committed under its ICS-24 path.
    let out = t.send(10).unwrap();
    let p = Packet::decode(&out.bytes, IbcVersion::Classic).unwrap();
    let path =
        format!("commitments/ports/transfer/channels/{tenzro_channel}/sequences/1").into_bytes();
    assert_eq!(p.commitment_key(), path);
    assert_eq!(t.get(&path), Some(p.commitment().to_vec()));
    assert_eq!(p.timeout_timestamp, (NOW_S + TIMEOUT_SECS) * 1_000_000_000);
}

#[test]
fn a_v2_route_has_no_handshake() {
    let mut t = setup(IbcVersion::V2);
    let cp_conn = connection_path(CP_CONNECTION);
    let p = t.prove(101, vec![(cp_conn.clone(), vec![1])], &cp_conn);
    assert!(t.ibc(IbcMsg::ConnectionOpenTry { proof: p }).is_err());
    let out = t.send(10).unwrap();
    let p = Packet::decode(&out.bytes, IbcVersion::V2).unwrap();
    let mut key = IbcRoute::tenzro_client_id(CHAIN).into_bytes();
    key.push(1);
    key.extend_from_slice(&1u64.to_be_bytes());
    assert_eq!(p.commitment_key(), key);
    assert_eq!(t.get(&key), Some(p.commitment().to_vec()));
    assert_eq!(p.timeout_timestamp, NOW_S + TIMEOUT_SECS);
    assert_eq!(p.destination_channel, CP_CLIENT);
}

#[test]
fn an_acknowledgement_settles_a_packet_once_and_an_error_refunds_it() {
    for version in [IbcVersion::Classic, IbcVersion::V2] {
        let mut t = setup(version);
        t.open(100);
        t.send(600).unwrap();
        t.send(400).unwrap();
        assert_eq!(read_supply(&t.s, &t.route).locked, 1_000);
        let ack1 = ack_key(version, "transfer", t.cp_id(), 1);
        let ack2 = ack_key(version, "transfer", t.cp_id(), 2);
        let error_ack = match version {
            IbcVersion::Classic => {
                br#"{"error":"ABCI code: 1: error handling packet: see events for details"}"#
                    .to_vec()
            }
            IbcVersion::V2 => Sha256::digest(b"UNIVERSAL_ERROR_ACKNOWLEDGEMENT").to_vec(),
        };
        let entries = vec![
            (ack1.clone(), ack_commitment(version, SUCCESS_ACK).to_vec()),
            (ack2.clone(), ack_commitment(version, &error_ack).to_vec()),
        ];

        // An acknowledgement the Cosmos chain did not commit is refused.
        let p = t.prove(110, entries.clone(), &ack1);
        let forged = IbcMsg::Acknowledge {
            sequence: 1,
            acknowledgement: error_ack.clone(),
            proof: p.clone(),
        };
        assert!(t.ibc(forged).is_err());
        // Nor is the proof of one packet's acknowledgement taken for another.
        assert!(
            t.ibc(IbcMsg::Acknowledge {
                sequence: 2,
                acknowledgement: SUCCESS_ACK.to_vec(),
                proof: p.clone()
            })
            .is_err()
        );

        let o = t
            .ibc(IbcMsg::Acknowledge {
                sequence: 1,
                acknowledgement: SUCCESS_ACK.to_vec(),
                proof: p.clone(),
            })
            .unwrap();
        assert_eq!(
            (o.kind, o.sequence, o.refund),
            ("acknowledge", Some(1), None)
        );
        assert_eq!(packet_status(&t.s, &t.route, 1).unwrap(), "delivered");
        assert!(
            t.ibc(IbcMsg::Acknowledge {
                sequence: 1,
                acknowledgement: SUCCESS_ACK.to_vec(),
                proof: p
            })
            .is_err(),
            "settled once"
        );
        assert_eq!(
            read_supply(&t.s, &t.route).locked,
            1_000,
            "the TNZO stays out"
        );

        let p = t.prove(111, entries, &ack2);
        let o = t
            .ibc(IbcMsg::Acknowledge {
                sequence: 2,
                acknowledgement: error_ack,
                proof: p,
            })
            .unwrap();
        assert_eq!(o.refund, Some((SENDER, 400)));
        assert_eq!(packet_status(&t.s, &t.route, 2).unwrap(), "refunded");
        let supply = read_supply(&t.s, &t.route);
        assert_eq!((supply.locked, supply.bridged), (600, 600));
    }
}

#[test]
fn a_packet_times_out_only_on_proof_of_no_receipt_past_its_timeout() {
    for version in [IbcVersion::Classic, IbcVersion::V2] {
        let mut t = setup(version);
        t.open(100);
        t.send(500).unwrap();
        let receipt = receipt_key(version, "transfer", t.cp_id(), 1);
        let other = (b"zz-unrelated".to_vec(), vec![9u8]);

        // Absent, but at a block before the timeout.
        let p = t.prove(110, vec![other.clone()], &receipt);
        assert!(
            t.ibc(IbcMsg::Timeout {
                sequence: 1,
                proof: p
            })
            .is_err()
        );

        // Past the timeout, but the Cosmos chain received it.
        t.s.elapsed_ms = (TIMEOUT_SECS as i64 + 120) * 1000;
        let late = NOW_S + TIMEOUT_SECS + 60;
        let p = t.prove_at(
            111,
            late,
            vec![other.clone(), (receipt.clone(), receipt_value(version))],
            &receipt,
        );
        assert!(
            t.ibc(IbcMsg::Timeout {
                sequence: 1,
                proof: p
            })
            .is_err()
        );

        // Past the timeout and absent: refunded once.
        let p = t.prove_at(
            112,
            late + 1,
            vec![other.clone(), (b"aa-unrelated".to_vec(), vec![1])],
            &receipt,
        );
        let o = t
            .ibc(IbcMsg::Timeout {
                sequence: 1,
                proof: p.clone(),
            })
            .unwrap();
        assert_eq!(o.refund, Some((SENDER, 500)));
        assert_eq!(read_supply(&t.s, &t.route).locked, 0);
        assert!(
            t.ibc(IbcMsg::Timeout {
                sequence: 1,
                proof: p
            })
            .is_err(),
            "refunded once"
        );
        let path = Packet::decode(
            &t.s.get(&state::outbound_key(&t.route, 1)).unwrap(),
            version,
        )
        .unwrap()
        .commitment_key();
        assert_eq!(t.get(&path), Some(REFUNDED.to_vec()));
        assert_ne!(REFUNDED, DELIVERED);
    }
}

#[test]
fn an_absence_proof_must_enclose_the_key_between_adjacent_neighbours() {
    let mut t = setup(IbcVersion::V2);
    t.send(500).unwrap();
    t.s.elapsed_ms = (TIMEOUT_SECS as i64 + 120) * 1000;
    let late = NOW_S + TIMEOUT_SECS + 60;
    let receipt = receipt_key(IbcVersion::V2, "transfer", CP_CLIENT, 1);
    // Keys around the receipt's (`08-wasm-3...`): it lies between `07` and `09`.
    let entries: Vec<(Vec<u8>, Vec<u8>)> = [b"01", b"03", b"05", b"07", b"09", b"0b"]
        .iter()
        .map(|k| (k.to_vec(), vec![1]))
        .collect();
    let store = StoreFixture::new("ibc", entries.clone());
    let p = t.prove_at(110, late, entries, &receipt);
    // Neighbours on either side of the key that are not adjacent (a leaf
    // between them skipped) are refused.
    let mut proof = super::tendermint::EntryProof::decode(&p).unwrap();
    if let super::tendermint::StoreEntryProof::Absent { left, right, .. } = &mut proof.entry {
        assert_eq!(left.as_ref().unwrap().key, b"07");
        assert_eq!(right.as_ref().unwrap().key, b"09");
        *left = Some(store.existence(b"05"));
    }
    assert!(
        t.ibc(IbcMsg::Timeout {
            sequence: 1,
            proof: proof.encode()
        })
        .is_err()
    );
    // The honest proof passes.
    t.ibc(IbcMsg::Timeout {
        sequence: 1,
        proof: p,
    })
    .unwrap();
}

#[test]
fn a_received_packet_writes_its_receipt_and_acknowledgement() {
    for version in [IbcVersion::Classic, IbcVersion::V2] {
        let mut t = setup(version);
        let tenzro_id = t.route.ibc.as_ref().unwrap().tenzro_packet_id(CHAIN);
        let packet = Packet {
            version,
            sequence: 4,
            source_port: "transfer".into(),
            source_channel: t.cp_id().into(),
            destination_port: "transfer".into(),
            destination_channel: tenzro_id.clone(),
            data: FungibleTokenPacketData {
                amount: "250".into(),
                denom: format!("transfer/{}/atnzo", t.cp_id()),
                memo: String::new(),
                receiver: format!("0x{}", hex::encode(SENDER)),
                sender: "osmo1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5x".into(),
            }
            .encode(version),
            timeout_revision_number: 0,
            timeout_revision_height: 0,
            timeout_timestamp: match version {
                IbcVersion::Classic => (NOW_S + 600) * 1_000_000_000,
                IbcVersion::V2 => NOW_S + 600,
            },
        };
        let (app_hash, iavl, store) = packet_proofs(&packet, "ibc");
        let h = header(
            CHAIN_ID,
            120,
            NOW_S - 400,
            t.vals.hash(),
            t.vals.hash(),
            app_hash,
        );
        let c = t.vals.commit(&h, 3);
        let set = t.vals.set();
        t.f.advance_light_client(
            &mut t.s,
            BridgeRouteAdapter::Ibc,
            CHAIN,
            &update(100, &h, &c, &set, &set),
        )
        .unwrap();
        let proof = message_proof(120, &packet, &iavl, &store);
        let d = deliver(
            &t.route,
            &Signers {
                committee: committee(1, 5, 3).0,
                blessing: vec![],
            },
            3,
            4,
            NOW_MS + 60_000,
            &packet.encode(),
            &proof,
        );

        // Classic packets travel an open channel only.
        if version == IbcVersion::Classic {
            assert!(
                t.f.admit_inbound(&mut t.s, BridgeRouteAdapter::Ibc, CHAIN, &d)
                    .is_err()
            );
            t.open(130);
        }
        t.send(300).unwrap();
        let admitted =
            t.f.admit_inbound(&mut t.s, BridgeRouteAdapter::Ibc, CHAIN, &d)
                .unwrap();
        assert_eq!(admitted.message.amount, 250);
        assert_eq!(
            t.get(&receipt_key(version, "transfer", &tenzro_id, 4)),
            Some(receipt_value(version))
        );
        assert_eq!(
            t.get(&ack_key(version, "transfer", &tenzro_id, 4)),
            Some(ack_commitment(version, SUCCESS_ACK).to_vec())
        );
        // A packet of the other version's layout is not this route's.
        let other = if version == IbcVersion::Classic {
            IbcVersion::V2
        } else {
            IbcVersion::Classic
        };
        assert!(FungibleTokenPacketData::decode(&packet.data, other).is_err());
    }
}

#[test]
fn packet_data_and_commitments_follow_the_transfer_module_of_each_version() {
    let data = FungibleTokenPacketData {
        amount: "5".into(),
        denom: "atnzo".into(),
        memo: String::new(),
        receiver: "cosmos1abc".into(),
        sender: "0xab".into(),
    };
    assert_eq!(
        data.encode(IbcVersion::Classic),
        br#"{"amount":"5","denom":"atnzo","memo":"","receiver":"cosmos1abc","sender":"0xab"}"#
    );
    assert_eq!(
        data.encode(IbcVersion::V2),
        br#"{"denom":"atnzo","amount":"5","sender":"0xab","receiver":"cosmos1abc"}"#
    );
    let with_memo = FungibleTokenPacketData {
        memo: "m".into(),
        ..data
    };
    assert_eq!(
        with_memo.encode(IbcVersion::V2),
        br#"{"denom":"atnzo","amount":"5","sender":"0xab","receiver":"cosmos1abc","memo":"m"}"#
    );
    assert!(
        FungibleTokenPacketData::decode(
            br#"{"amount":"5","denom":"atnzo","sender":"0xab","receiver":"cosmos1abc"}"#,
            IbcVersion::V2
        )
        .is_err()
    );
}

/// Recorded from a local chain running ibc-go v10 with 08-wasm
/// (`scripts/ibc-round-trip.sh cosmos` then `record`): two of its headers
/// with the validators, and proofs of its IBC store after it opened its side
/// of the classic handshakes towards Tenzro's identifiers (client
/// `08-wasm-0`, connection `connection-0`, channel `channel-0`), registered
/// Tenzro as the v2 counterparty of client `08-wasm-1`, and sent one v2
/// packet towards Tenzro.
const LOCAL: &str = include_str!("../../tests/fixtures/cosmos_local_ibc.json");

fn local_route(
    f: &serde_json::Value,
    version: IbcVersion,
) -> (RouteFramework, MemState, BridgeRoute) {
    use super::tendermint::cometbft_rpc;
    let trusted = cometbft_rpc::header(&f["trusted"]).unwrap();
    let target = cometbft_rpc::header(&f["target"]).unwrap();
    let (name, client, connection, channel) = match version {
        IbcVersion::Classic => (
            f["classic_route"].as_str().unwrap(),
            "08-wasm-0",
            Some("connection-0"),
            Some("channel-0"),
        ),
        IbcVersion::V2 => (f["v2_route"].as_str().unwrap(), "08-wasm-1", None, None),
    };
    let ibc = IbcRoute {
        version,
        counterparty_client_id: client.into(),
        counterparty_connection_id: connection.map(Into::into),
        counterparty_channel_id: channel.map(Into::into),
        packet_timeout_secs: 600,
    };
    let mut route = ibc_route(version);
    route.source_chain = name.into();
    route.peer = IbcRoute::end_hash(ibc.counterparty_packet_id());
    route.local_endpoint = IbcRoute::end_hash(&ibc.tenzro_packet_id(name));
    route.remote_token = Sha256::digest(ibc.tnzo_trace().as_bytes()).into();
    route.ibc = Some(ibc);
    route.light_client = Some(LightClientAnchor::Tendermint {
        chain_id: f["chain_id"].as_str().unwrap().into(),
        trusted_height: trusted.height,
        trusted_header_hash: trusted.hash(),
        trusting_period_secs: 14 * 24 * 3600,
    });
    route.validate().unwrap();
    let fw = RouteFramework::new().with_light_client(Arc::new(TendermintLightClient));
    let mut s = MemState::with(std::slice::from_ref(&route));
    s.elapsed_ms = (target.time_seconds as i64) * 1000 + 30_000 - NOW_MS;
    fw.advance_light_client(
        &mut s,
        BridgeRouteAdapter::Ibc,
        name,
        &cometbft_rpc::bootstrap(&f["trusted"]).unwrap(),
    )
    .unwrap();
    let validators = cometbft_rpc::validators(f["target_validators"].as_array().unwrap()).unwrap();
    let trusted_next =
        cometbft_rpc::validators(f["trusted_next_validators"].as_array().unwrap()).unwrap();
    let update =
        cometbft_rpc::update(trusted.height, &f["target"], &validators, &trusted_next).unwrap();
    fw.advance_light_client(&mut s, BridgeRouteAdapter::Ibc, name, &update)
        .unwrap();
    (fw, s, route)
}

#[test]
fn a_local_ibc_go_chain_is_followed_and_its_ibc_store_proven_for_both_versions() {
    use super::tendermint::{cometbft_rpc, verify_store_entry};
    let f: serde_json::Value = serde_json::from_str(LOCAL).unwrap();
    let height = cometbft_rpc::header(&f["target"]).unwrap().height;

    // Classic: the chain's INIT connection end, as ibc-go wrote it, is the
    // one Tenzro expects, so connection_open_try writes Tenzro's end.
    let (fw, mut s, route) = local_route(&f, IbcVersion::Classic);
    let conn_key = connection_path("connection-0");
    let proof = cometbft_rpc::entry_proof(&f["connection"], &conn_key, height)
        .unwrap()
        .encode();
    let chain = route.source_chain.clone();
    let tenzro_client = IbcRoute::tenzro_client_id(&chain);
    let o = fw
        .handle_ibc(
            &mut s,
            &chain,
            &IbcMsg::ConnectionOpenTry {
                proof: proof.clone(),
            },
        )
        .unwrap()
        .1;
    assert_eq!(o.kind, "connection_open_try");
    assert_eq!(
        s.get(&store_key(&connection_path(
            &IbcRoute::tenzro_connection_id(&chain)
        ))),
        Some(connection_end(
            EndState::TryOpen,
            &tenzro_client,
            "08-wasm-0",
            "connection-0"
        ))
    );
    // The same proof does not open a connection the route does not name.
    let (fw2, mut s2, mut other) = local_route(&f, IbcVersion::Classic);
    other.ibc.as_mut().unwrap().counterparty_client_id = "08-wasm-1".into();
    s2.routes.insert(other.storage_key(), other.clone());
    assert!(
        fw2.handle_ibc(&mut s2, &chain, &IbcMsg::ConnectionOpenTry { proof })
            .is_err()
    );
    // Its INIT channel end is the one channel_open_try expects.
    let chan_key = channel_path("channel-0");
    let proof = cometbft_rpc::entry_proof(&f["channel"], &chan_key, height)
        .unwrap()
        .encode();
    verify_store_entry(
        &s,
        &route,
        &chan_key,
        Some(&channel_end(EndState::Init, "", "connection-0")),
        &proof,
    )
    .unwrap();
    assert!(
        verify_store_entry(
            &s,
            &route,
            &chan_key,
            Some(&channel_end(EndState::Open, "", "connection-0")),
            &proof
        )
        .is_err()
    );

    // v2: the packet the chain sent is committed exactly as Tenzro computes
    // an IBC v2 commitment, under the v2 key.
    let (_, s, route) = local_route(&f, IbcVersion::V2);
    let p = &f["v2_packet"];
    let packet = Packet {
        version: IbcVersion::V2,
        sequence: p["sequence"].as_u64().unwrap(),
        source_port: "transfer".into(),
        source_channel: p["source_client"].as_str().unwrap().into(),
        destination_port: "transfer".into(),
        destination_channel: p["destination_client"].as_str().unwrap().into(),
        data: p["value"].as_str().unwrap().as_bytes().to_vec(),
        timeout_revision_number: 0,
        timeout_revision_height: 0,
        timeout_timestamp: p["timeout_timestamp"].as_u64().unwrap(),
    };
    assert_eq!(
        packet.destination_channel,
        IbcRoute::tenzro_client_id(&route.source_chain)
    );
    let key = packet.commitment_key();
    let proof = cometbft_rpc::entry_proof(&f["v2_commitment"], &key, height)
        .unwrap()
        .encode();
    verify_store_entry(&s, &route, &key, Some(&packet.commitment()), &proof).unwrap();
    let mut other = packet.clone();
    other.timeout_timestamp += 1;
    assert!(verify_store_entry(&s, &route, &key, Some(&other.commitment()), &proof).is_err());

    // The chain holds no receipt of a packet it never received: a real
    // absence proof, between adjacent leaves.
    let receipt = receipt_key(IbcVersion::V2, "transfer", "08-wasm-1", 1);
    let proof = cometbft_rpc::entry_proof(&f["v2_receipt"], &receipt, height)
        .unwrap()
        .encode();
    verify_store_entry(&s, &route, &receipt, None, &proof).unwrap();
    assert!(
        verify_store_entry(
            &s,
            &route,
            &receipt,
            Some(&receipt_value(IbcVersion::V2)),
            &proof
        )
        .is_err()
    );
}

#[test]
fn a_cosmwasm_lock_is_proven_from_its_stored_leg() {
    use super::tendermint::{WASM_STORE, wasm_leg_key};
    const LOCK: [u8; 32] = [0x3c; 32];
    let plan_id = [0x11; 32];
    let leg_id = tenzro_types::settlement::leg_id(&plan_id, 1);
    let hrp = bech32::Hrp::parse("osmo").unwrap();
    let payer = bech32::encode::<bech32::Bech32>(hrp, &[0x0a; 20]).unwrap();
    let recipient = bech32::encode::<bech32::Bech32>(hrp, &[0x0b; 32]).unwrap();
    // The JSON the lock stores (asserted by its own test).
    let leg = |stage: &str| {
        format!(r#"{{"payer":"{payer}","recipient":"{recipient}","coin":{{"denom":"uosmo","amount":"700"}},"escape_at":1801209600,"stage":"{stage}"}}"#)
            .into_bytes()
    };

    let mut t = setup(IbcVersion::V2);
    t.route.settlement_lock = Some(LOCK);
    t.s = MemState::with(std::slice::from_ref(&t.route));
    let trusted = header(
        CHAIN_ID,
        100,
        NOW_S - 1_000,
        t.vals.hash(),
        t.vals.hash(),
        [0x21; 32],
    );
    t.f.advance_light_client(
        &mut t.s,
        BridgeRouteAdapter::Ibc,
        CHAIN,
        &bootstrap(&trusted),
    )
    .unwrap();
    let mut height = 110;
    let mut prove =
        |t: &mut T, key: Vec<u8>, value: Vec<u8>, store: &str, plan: Option<[u8; 32]>| {
            height += 1;
            let s = StoreFixture::new(
                store,
                vec![(key.clone(), value), (b"zz-other".to_vec(), vec![1])],
            );
            let h = header(
                CHAIN_ID,
                height,
                NOW_S - 500,
                t.vals.hash(),
                t.vals.hash(),
                s.app_hash,
            );
            let c = t.vals.commit(&h, 3);
            let set = t.vals.set();
            t.f.advance_light_client(
                &mut t.s,
                BridgeRouteAdapter::Ibc,
                CHAIN,
                &update(100, &h, &c, &set, &set),
            )
            .unwrap();
            let mut p = match plan {
                Some(plan) => [&[0u8][..], &plan, &[1]].concat(),
                None => vec![1],
            };
            p.extend(s.proof(&key, height).encode());
            t.f.prove_lock(&mut t.s, BridgeRouteAdapter::Ibc, CHAIN, &p)
        };
    let wasm = std::str::from_utf8(WASM_STORE).unwrap();
    let (got, proven, _) = prove(
        &mut t,
        wasm_leg_key(&LOCK, &leg_id),
        leg("locked"),
        wasm,
        Some(plan_id),
    )
    .unwrap();
    assert!(proven);
    let crate::route::receipt_proof::LockRecord::Locked(got) = got else {
        panic!("a leg's lock")
    };
    assert_eq!((got.plan_id, got.leg_id, got.index), (plan_id, leg_id, 1));
    let mut payer_w = [0u8; 32];
    payer_w[12..].copy_from_slice(&[0x0a; 20]);
    assert_eq!(got.payer, payer_w);
    assert_eq!(got.recipient, [0x0b; 32]);
    assert_eq!(got.asset, <[u8; 32]>::from(Sha256::digest(b"uosmo")));
    assert_eq!((got.amount, got.escape_at_ms), (700, 1_801_209_600_000));

    assert!(
        prove(
            &mut t,
            wasm_leg_key(&LOCK, &leg_id),
            leg("released"),
            wasm,
            Some(plan_id)
        )
        .is_err(),
        "settled"
    );
    assert!(
        prove(
            &mut t,
            wasm_leg_key(&[0x3d; 32], &leg_id),
            leg("locked"),
            wasm,
            Some(plan_id)
        )
        .is_err(),
        "another contract"
    );
    assert!(
        prove(
            &mut t,
            wasm_leg_key(&LOCK, &leg_id),
            leg("locked"),
            "ibc",
            Some(plan_id)
        )
        .is_err(),
        "another store"
    );
    assert!(
        prove(
            &mut t,
            wasm_leg_key(&LOCK, &leg_id),
            leg("locked"),
            wasm,
            Some([0x12; 32])
        )
        .is_err(),
        "another plan"
    );

    // The lock's stored reconciliation checkpoint after the shared sequence,
    // as the lock's own test writes it.
    use super::tendermint::wasm_recon_key;
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../sdk/fixtures/settlement_lock/cosmwasm_recon_entry.json"
    );
    let recon = std::fs::read_to_string(path)
        .unwrap()
        .trim()
        .as_bytes()
        .to_vec();
    let (got, proven, _) = prove(&mut t, wasm_recon_key(&LOCK), recon.clone(), wasm, None).unwrap();
    assert!(proven);
    let mut acc = [0u8; 32];
    acc.copy_from_slice(
        &hex::decode("375111922b0be21f25ad54b505467229080fd12340e5b01e4f56220cb3ecb58a").unwrap(),
    );
    let cp = crate::route::receipt_proof::LockCheckpoint { count: 6, acc };
    assert_eq!(got, crate::route::receipt_proof::LockRecord::Checkpoint(cp));
    assert!(
        prove(
            &mut t,
            wasm_recon_key(&[0x3d; 32]),
            recon.clone(),
            wasm,
            None
        )
        .is_err(),
        "another contract"
    );
    assert!(
        prove(
            &mut t,
            wasm_leg_key(&LOCK, &leg_id),
            recon.clone(),
            wasm,
            None
        )
        .is_err(),
        "a leg's key"
    );
    assert!(
        prove(&mut t, wasm_recon_key(&LOCK), recon, wasm, Some(plan_id)).is_err(),
        "framed as a leg"
    );
}
