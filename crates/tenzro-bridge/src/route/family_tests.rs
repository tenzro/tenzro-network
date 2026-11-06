//! Route tests for the Cosmos, Bitcoin, Stellar, Sui, Aptos and TON
//! adapters: a fixture round trip through the framework for each, and the
//! refusals that keep a forged or malformed message out.

use std::sync::Arc;

use super::state::read_supply;
use super::test_support::*;
use super::*;

const LOCAL_SELECTOR: u64 = 7_777;
const RECIPIENT: [u8; 32] = [0x77; 32];
const EXPIRY: i64 = NOW_MS + 60_000;
const NOW_S: u64 = (NOW_MS / 1000) as u64;

fn signers() -> Signers {
    Signers {
        committee: committee(1, 5, 3).0,
        blessing: vec![],
    }
}

fn route(adapter: BridgeRouteAdapter, family: ChainFamily, chain: &str, id: u64) -> BridgeRoute {
    BridgeRoute {
        adapter,
        family,
        source_chain: chain.into(),
        source_chain_id: id,
        local_selector: LOCAL_SELECTOR,
        peer: [0x51; 32],
        ramp: [0x52; 32],
        local_endpoint: [0xAB; 32],
        remote_token: [0x53; 32],
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
        ibc: None,
        settlement_lock: None,
        native_asset: None,
        assets: Vec::new(),
    }
}

fn send(
    f: &RouteFramework,
    s: &mut MemState,
    chain: &str,
    amount: u128,
    to: Vec<u8>,
) -> OutboundMessage {
    f.send_outbound(
        s,
        chain,
        &OutboundTransfer {
            sender: RECIPIENT.to_vec(),
            recipient: to,
            amount,
            asset: None,
        },
    )
    .unwrap()
}

fn refused<T>(r: crate::Result<T>, what: &str) {
    match r {
        Ok(_) => panic!("{what}: admitted"),
        Err(e) => eprintln!("{what}: {e}"),
    }
}

mod cosmos {
    use super::super::ibc::{FungibleTokenPacketData, Packet};
    use super::super::tendermint::fixtures::*;
    use super::super::tendermint::{Header, TendermintLightClient};
    use super::*;

    const CHAIN: &str = "cosmoshub";
    const CHAIN_ID: &str = "cosmoshub-4";

    struct Setup {
        f: RouteFramework,
        s: MemState,
        route: BridgeRoute,
        vals: Validators,
        trusted: Header,
    }

    fn setup() -> Setup {
        let vals = Validators::new(3, 4);
        let trusted = header(
            CHAIN_ID,
            100,
            NOW_S - 1_000,
            vals.hash(),
            vals.hash(),
            [0x21; 32],
        );
        let mut r = route(BridgeRouteAdapter::Ibc, ChainFamily::Cosmos, CHAIN, 118);
        let ibc = IbcRoute {
            version: IbcVersion::V2,
            counterparty_client_id: "08-wasm-141".into(),
            counterparty_connection_id: None,
            counterparty_channel_id: None,
            packet_timeout_secs: 3_600,
        };
        r.peer = IbcRoute::end_hash(ibc.counterparty_packet_id());
        r.local_endpoint = IbcRoute::end_hash(&ibc.tenzro_packet_id(CHAIN));
        r.ramp = channel_end_store("ibc");
        r.remote_token = <sha2::Sha256 as sha2::Digest>::digest(ibc.tnzo_trace().as_bytes()).into();
        r.ibc = Some(ibc);
        r.light_client = Some(LightClientAnchor::Tendermint {
            chain_id: CHAIN_ID.into(),
            trusted_height: 100,
            trusted_header_hash: trusted.hash(),
            trusting_period_secs: 14 * 24 * 3600,
        });
        r.validate().unwrap();
        let f = RouteFramework::new().with_light_client(Arc::new(TendermintLightClient));
        let mut s = MemState::with(std::slice::from_ref(&r));
        f.advance_light_client(&mut s, BridgeRouteAdapter::Ibc, CHAIN, &bootstrap(&trusted))
            .unwrap();
        Setup {
            f,
            s,
            route: r,
            vals,
            trusted,
        }
    }

    fn channel_end_store(name: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[..name.len()].copy_from_slice(name.as_bytes());
        out
    }

    fn returning(seq: u64, amount: &str) -> Packet {
        Packet {
            version: IbcVersion::V2,
            sequence: seq,
            source_port: "transfer".into(),
            source_channel: "08-wasm-141".into(),
            destination_port: "transfer".into(),
            destination_channel: IbcRoute::tenzro_client_id(CHAIN),
            data: FungibleTokenPacketData {
                amount: amount.into(),
                denom: "transfer/08-wasm-141/atnzo".into(),
                memo: String::new(),
                receiver: format!("0x{}", hex::encode(RECIPIENT)),
                sender: "cosmos1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5lzv7xu".into(),
            }
            .encode(IbcVersion::V2),
            timeout_revision_number: 0,
            timeout_revision_height: 0,
            timeout_timestamp: NOW_S + 3_600,
        }
    }

    /// Advance the client to `height` with a header whose app hash commits
    /// `packet`, signed by `signers` of the four validators.
    fn prove(
        t: &mut Setup,
        height: u64,
        packet: &Packet,
        signers: usize,
    ) -> crate::Result<Vec<u8>> {
        let (app_hash, iavl, store) = packet_proofs(packet, "ibc");
        let h = header(
            CHAIN_ID,
            height,
            NOW_S - 500,
            t.vals.hash(),
            t.vals.hash(),
            app_hash,
        );
        let c = t.vals.commit(&h, signers);
        let set = t.vals.set();
        t.f.advance_light_client(
            &mut t.s,
            BridgeRouteAdapter::Ibc,
            CHAIN,
            &update(100, &h, &c, &set, &set),
        )?;
        Ok(message_proof(height, packet, &iavl, &store))
    }

    fn admit(
        t: &mut Setup,
        nonce: u64,
        body: &[u8],
        proof: &[u8],
    ) -> crate::Result<AdmittedTransfer> {
        let d = deliver(&t.route, &signers(), 3, nonce, EXPIRY, body, proof);
        t.f.admit_inbound(&mut t.s, BridgeRouteAdapter::Ibc, CHAIN, &d)
    }

    #[test]
    fn cosmos_round_trips_a_fixture_message() {
        let mut t = setup();
        let receiver = b"cosmos1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5lzv7xu".to_vec();
        let out = send(&t.f, &mut t.s, CHAIN, 600, receiver.clone());
        let p = Packet::decode(&out.bytes, IbcVersion::V2).unwrap();
        assert_eq!(
            (p.source_channel.as_str(), p.destination_channel.as_str()),
            ("07-tendermint-1702979098369996577", "08-wasm-141")
        );
        assert_eq!(out.message.message_id, p.commitment());
        let data = FungibleTokenPacketData::decode(&p.data, IbcVersion::V2).unwrap();
        assert_eq!(
            (data.denom.as_str(), data.amount.as_str()),
            ("atnzo", "600")
        );
        assert_eq!(data.receiver.as_bytes(), receiver.as_slice());

        let packet = returning(7, "250");
        let proof = prove(&mut t, 105, &packet, 3).unwrap();
        let admitted = admit(&mut t, 7, &packet.encode(), &proof).unwrap();
        assert_eq!(admitted.message.amount, 250);
        assert_eq!(admitted.message.receiver, RECIPIENT.to_vec());
        assert_eq!(admitted.message.message_id, packet.commitment());
        assert_eq!(read_supply(&t.s, &t.route).bridged, 350);
        assert_eq!(
            t.f.light_client_head(&t.s, &t.route).unwrap().finalized,
            105
        );
        assert_eq!(t.f.finality_depth(&t.route).unwrap(), 0);
    }

    #[test]
    fn cosmos_refuses_forged_and_malformed_packets() {
        let mut t = setup();
        send(&t.f, &mut t.s, CHAIN, 1_000, b"cosmos1abc".to_vec());
        let packet = returning(8, "10");
        let proof = prove(&mut t, 105, &packet, 3).unwrap();

        // Packet data in a non-canonical spelling, signed by the committee.
        let mut spaced = packet.clone();
        spaced.data = String::from_utf8(packet.data.clone())
            .unwrap()
            .replace(",\"", ", \"")
            .into_bytes();
        refused(
            admit(&mut t, 8, &spaced.encode(), &proof),
            "non-canonical JSON",
        );

        // A denomination that is not TNZO coming home.
        let mut foreign = packet.clone();
        let mut d = FungibleTokenPacketData::decode(&packet.data, IbcVersion::V2).unwrap();
        d.denom = "uatom".into();
        foreign.data = d.encode(IbcVersion::V2);
        refused(
            admit(&mut t, 8, &foreign.encode(), &proof),
            "foreign denomination",
        );

        // A packet whose commitment the chain never stored: the proof is of
        // another packet.
        let inflated = returning(8, "999");
        refused(
            admit(&mut t, 8, &inflated.encode(), &proof),
            "packet the proof does not cover",
        );
        let mut lying = proof.clone();
        let at = lying.len() - 40;
        lying[at] ^= 1;
        refused(admit(&mut t, 8, &packet.encode(), &lying), "tampered proof");

        // A trailing byte in the attested body.
        let mut padded = packet.encode();
        padded.push(0);
        refused(admit(&mut t, 8, &padded, &proof), "trailing byte");

        // No proof at all on a light-client route.
        refused(admit(&mut t, 8, &packet.encode(), &[]), "missing proof");

        // The well-formed packet still passes once.
        admit(&mut t, 8, &packet.encode(), &proof).unwrap();
        refused(admit(&mut t, 8, &packet.encode(), &proof), "replay");
    }

    #[test]
    fn the_tendermint_client_accepts_only_headers_the_validators_signed() {
        let mut t = setup();
        let set = t.vals.set();
        let h = header(
            CHAIN_ID,
            110,
            NOW_S - 400,
            t.vals.hash(),
            t.vals.hash(),
            [0x31; 32],
        );

        // Two of four validators hold exactly half the power: not enough.
        let c = t.vals.commit(&h, 2);
        assert!(
            t.f.advance_light_client(
                &mut t.s,
                BridgeRouteAdapter::Ibc,
                CHAIN,
                &update(100, &h, &c, &set, &set)
            )
            .is_err()
        );

        // A forged signature.
        let mut c = t.vals.commit(&h, 4);
        c.signatures[0].signature[0] ^= 1;
        assert!(
            t.f.advance_light_client(
                &mut t.s,
                BridgeRouteAdapter::Ibc,
                CHAIN,
                &update(100, &h, &c, &set, &set)
            )
            .is_err()
        );

        // A commit for another header.
        let other = header(
            CHAIN_ID,
            110,
            NOW_S - 400,
            t.vals.hash(),
            t.vals.hash(),
            [0x32; 32],
        );
        let c = t.vals.commit(&other, 4);
        assert!(
            t.f.advance_light_client(
                &mut t.s,
                BridgeRouteAdapter::Ibc,
                CHAIN,
                &update(100, &h, &c, &set, &set)
            )
            .is_err()
        );

        // A validator set the trusted header never named, signing for itself.
        let rogue = Validators::new(90, 4);
        let rh = header(
            CHAIN_ID,
            110,
            NOW_S - 400,
            rogue.hash(),
            rogue.hash(),
            [0x31; 32],
        );
        let rc = rogue.commit(&rh, 4);
        assert!(
            t.f.advance_light_client(
                &mut t.s,
                BridgeRouteAdapter::Ibc,
                CHAIN,
                &update(100, &rh, &rc, &rogue.set(), &rogue.set())
            )
            .is_err()
        );
        assert!(
            t.f.advance_light_client(
                &mut t.s,
                BridgeRouteAdapter::Ibc,
                CHAIN,
                &update(100, &rh, &rc, &rogue.set(), &set)
            )
            .is_err()
        );

        // Another chain id.
        let wrong = header(
            "osmosis-1",
            110,
            NOW_S - 400,
            t.vals.hash(),
            t.vals.hash(),
            [0x31; 32],
        );
        let c = t.vals.commit(&wrong, 4);
        assert!(
            t.f.advance_light_client(
                &mut t.s,
                BridgeRouteAdapter::Ibc,
                CHAIN,
                &update(100, &wrong, &c, &set, &set)
            )
            .is_err()
        );

        // A bootstrap that is not the anchor's header.
        let mut fake = t.trusted.clone();
        fake.app_hash = vec![0x99; 32];
        assert!(
            t.f.advance_light_client(&mut t.s, BridgeRouteAdapter::Ibc, CHAIN, &bootstrap(&fake))
                .is_err()
        );

        // Three of four validators sign: accepted.
        let c = t.vals.commit(&h, 3);
        t.f.advance_light_client(
            &mut t.s,
            BridgeRouteAdapter::Ibc,
            CHAIN,
            &update(100, &h, &c, &set, &set),
        )
        .unwrap();

        // A conflicting header at an accepted height is refused.
        let c = t.vals.commit(&other, 4);
        assert!(
            t.f.advance_light_client(
                &mut t.s,
                BridgeRouteAdapter::Ibc,
                CHAIN,
                &update(100, &other, &c, &set, &set)
            )
            .is_err()
        );
    }

    #[test]
    fn a_timed_out_packet_or_an_expired_client_is_refused() {
        let mut t = setup();
        send(&t.f, &mut t.s, CHAIN, 1_000, b"cosmos1abc".to_vec());
        let mut packet = returning(9, "10");
        packet.timeout_timestamp = NOW_S - 1;
        let proof = prove(&mut t, 105, &packet, 3).unwrap();
        refused(admit(&mut t, 9, &packet.encode(), &proof), "timed out");

        let packet = returning(10, "10");
        let proof = prove(&mut t, 106, &packet, 3).unwrap();
        t.s.elapsed_ms = 15 * 24 * 3600 * 1000;
        let d = deliver(
            &t.route,
            &signers(),
            3,
            10,
            NOW_MS + t.s.elapsed_ms + 60_000,
            &packet.encode(),
            &proof,
        );
        refused(
            t.f.admit_inbound(&mut t.s, BridgeRouteAdapter::Ibc, CHAIN, &d),
            "expired client",
        );
    }
}

mod bitcoin {
    use sha2::{Digest, Sha256};

    use super::super::bitcoin::fixtures::*;
    use super::super::bitcoin::{
        BitcoinLightClient, BlockHeader, Deposit, Transaction, TxIn, TxOut, deposit_marker, target,
    };
    use super::*;

    const CHAIN: &str = "bitcoin";
    const BITS: u32 = 0x1f00_ffff;
    const ANCHOR_HEIGHT: u64 = 2016 * 400;
    use super::super::bitcoin_spend::{DepositDescriptor, Withdrawal};

    fn signer(seed: u8) -> k256::schnorr::SigningKey {
        k256::schnorr::SigningKey::from_bytes(&[seed; 32].into()).unwrap()
    }

    fn desc() -> DepositDescriptor {
        DepositDescriptor {
            signers: (1..=3u8)
                .map(|i| <[u8; 32]>::from(signer(i).verifying_key().to_bytes()))
                .collect(),
            threshold: 2,
        }
    }

    fn script() -> Vec<u8> {
        desc().script_pubkey().unwrap()
    }

    struct Setup {
        f: RouteFramework,
        s: MemState,
        route: BridgeRoute,
        anchor: BlockHeader,
    }

    fn setup() -> Setup {
        let anchor = mine([0x01; 32], [0x02; 32], (NOW_S - 100_000) as u32, BITS);
        let mut r = route(BridgeRouteAdapter::Deposit, ChainFamily::Bitcoin, CHAIN, 1);
        r.peer = Sha256::digest(script()).into();
        r.light_client = Some(LightClientAnchor::BitcoinHeaders {
            trusted_height: ANCHOR_HEIGHT,
            trusted_header_hash: anchor.hash(),
            confirmations: 6,
            signers: desc().signers,
            threshold: 2,
            fee_rate: 2,
        });
        r.mint_limit = MintRateLimit {
            per_mint: 100_000,
            per_epoch: 150_000,
        };
        r.validate().unwrap();
        let f = RouteFramework::new().with_light_client(Arc::new(BitcoinLightClient));
        let mut s = MemState::with(std::slice::from_ref(&r));
        f.advance_light_client(
            &mut s,
            BridgeRouteAdapter::Deposit,
            CHAIN,
            &bootstrap(&anchor),
        )
        .unwrap();
        Setup {
            f,
            s,
            route: r,
            anchor,
        }
    }

    fn deposit_tx(outputs: Vec<TxOut>) -> Vec<u8> {
        Transaction {
            version: 2,
            inputs: vec![TxIn {
                prevout: [0x33; 36],
                script_sig: vec![],
                sequence: u32::MAX,
            }],
            outputs,
            lock_time: 0,
        }
        .encode()
    }

    fn good_outputs(value: u64) -> Vec<TxOut> {
        vec![
            TxOut {
                value,
                script: script(),
            },
            TxOut {
                value: 0,
                script: deposit_marker(&RECIPIENT),
            },
            TxOut {
                value: 1_000,
                script: vec![
                    0x00, 0x14, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,
                    0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,
                ],
            },
        ]
    }

    /// Mine the deposit into the block after the anchor, then `more` blocks.
    fn mine_deposit(
        t: &Setup,
        tx: &[u8],
        more: usize,
    ) -> (Deposit, Vec<BlockHeader>, Vec<[u8; 32]>) {
        let deposit = Deposit {
            height: ANCHOR_HEIGHT + 1,
            index: 1,
            tx: tx.to_vec(),
        };
        let (root, branch) = merkle(&[[0x10; 32], deposit.txid(), [0x11; 32]], 1);
        let mut headers = vec![mine(t.anchor.hash(), root, (NOW_S - 90_000) as u32, BITS)];
        for i in 0..more {
            let prev = headers.last().unwrap().hash();
            headers.push(mine(
                prev,
                [i as u8; 32],
                (NOW_S - 89_000 + i as u64 * 600) as u32,
                BITS,
            ));
        }
        (deposit, headers, branch)
    }

    fn admit(
        t: &mut Setup,
        d: &Deposit,
        header: &BlockHeader,
        branch: &[[u8; 32]],
    ) -> crate::Result<AdmittedTransfer> {
        let delivery = deliver(
            &t.route,
            &signers(),
            3,
            d.sequence(),
            EXPIRY,
            &d.encode(),
            &proof(d, header, branch),
        );
        t.f.admit_inbound(&mut t.s, BridgeRouteAdapter::Deposit, CHAIN, &delivery)
    }

    #[test]
    fn bitcoin_round_trips_a_fixture_deposit() {
        let mut t = setup();
        let (d, headers, branch) = mine_deposit(&t, &deposit_tx(good_outputs(50_000)), 5);

        // Five confirmations: not yet.
        t.f.advance_light_client(
            &mut t.s,
            BridgeRouteAdapter::Deposit,
            CHAIN,
            &extend(ANCHOR_HEIGHT, &headers[..5]),
        )
        .unwrap();
        refused(
            admit(&mut t, &d, &headers[0], &branch),
            "five confirmations",
        );

        // Six.
        let head =
            t.f.advance_light_client(
                &mut t.s,
                BridgeRouteAdapter::Deposit,
                CHAIN,
                &extend(ANCHOR_HEIGHT + 5, &headers[5..]),
            )
            .unwrap();
        assert_eq!(head.finalized, ANCHOR_HEIGHT + 1);
        let admitted = admit(&mut t, &d, &headers[0], &branch).unwrap();
        assert_eq!(admitted.message.amount, 50_000);
        assert_eq!(admitted.message.receiver, RECIPIENT.to_vec());
        assert_eq!(admitted.message.message_id, d.txid());
        assert_eq!(
            admitted.supply,
            SupplyRecord {
                locked: 50_000,
                bridged: 50_000
            }
        );
        assert_eq!(t.f.finality_depth(&t.route).unwrap(), 6);

        // The same deposit is credited once.
        refused(admit(&mut t, &d, &headers[0], &branch), "replay");

        // A withdrawal spends the deposit's output: the recipient is paid
        // the amount less the fee, the change returns to the descriptor and
        // is tracked at once, and the representation is burned.
        let payee = [&[0x00, 0x14][..], &[0x77u8; 20]].concat();
        let send = |t: &mut Setup, recipient: &[u8], amount: u128| {
            t.f.send_outbound(
                &mut t.s,
                CHAIN,
                &OutboundTransfer {
                    sender: RECIPIENT.to_vec(),
                    recipient: recipient.to_vec(),
                    amount,
                    asset: None,
                },
            )
        };
        refused(
            send(&mut t, &script(), 30_000),
            "to the deposit script itself",
        );
        let out = send(&mut t, &payee, 30_000).unwrap();
        let w = Withdrawal::decode(&out.bytes).unwrap();
        assert_eq!(out.message.message_id, w.txid());
        assert_eq!(&w.tx.inputs[0].prevout[..32], &d.txid());
        assert_eq!(w.tx.outputs[1].value, 20_000);
        assert_eq!(w.tx.outputs[1].script, script());
        assert!(w.tx.outputs[0].value < 30_000 && w.tx.outputs[0].value > 29_000);
        assert_eq!(
            out.supply,
            SupplyRecord {
                locked: 20_000,
                bridged: 20_000
            }
        );
        let utxos = super::super::bitcoin::read_utxos(&t.s, &t.route).unwrap();
        assert_eq!(utxos.len(), 1);
        assert_eq!(
            (utxos[0].txid, utxos[0].vout, utxos[0].value),
            (w.txid(), 1, 20_000)
        );

        // Two of the three signers complete it; one does not.
        let sign = |seeds: &[u8]| -> Vec<Vec<([u8; 32], [u8; 64])>> {
            let digest = w.sighash(&desc(), 0).unwrap();
            vec![
                seeds
                    .iter()
                    .map(|s| {
                        (
                            desc().signers[*s as usize - 1],
                            signer(*s).sign_raw(&digest, &[0; 32]).unwrap().to_bytes(),
                        )
                    })
                    .collect(),
            ]
        };
        w.assemble(&desc(), &sign(&[1, 2])).unwrap();
        assert!(w.assemble(&desc(), &sign(&[3])).is_err());

        // The rest, the change, leaves too; then nothing is left to spend.
        send(&mut t, &payee, 20_000).unwrap();
        refused(send(&mut t, &payee, 1_000), "nothing left");
    }

    #[test]
    fn a_payment_to_any_script_is_proven_once_confirmed() {
        let mut t = setup();
        let payee = [&[0x00, 0x14][..], &[0x55u8; 20]].concat();
        let tx = deposit_tx(vec![TxOut {
            value: 70_000,
            script: payee.clone(),
        }]);
        let (d, headers, branch) = mine_deposit(&t, &tx, 5);
        let p = proof(&d, &headers[0], &branch);
        t.f.advance_light_client(
            &mut t.s,
            BridgeRouteAdapter::Deposit,
            CHAIN,
            &extend(ANCHOR_HEIGHT, &headers[..5]),
        )
        .unwrap();
        refused(
            t.f.prove_bitcoin_payment(&t.s, BridgeRouteAdapter::Deposit, CHAIN, &p),
            "five confirmations",
        );
        t.f.advance_light_client(
            &mut t.s,
            BridgeRouteAdapter::Deposit,
            CHAIN,
            &extend(ANCHOR_HEIGHT + 5, &headers[5..]),
        )
        .unwrap();
        let paid =
            t.f.prove_bitcoin_payment(&t.s, BridgeRouteAdapter::Deposit, CHAIN, &p)
                .unwrap();
        assert_eq!(paid.txid, d.txid());
        assert_eq!(paid.height, ANCHOR_HEIGHT + 1);
        assert_eq!(paid.block_time, headers[0].time);
        assert_eq!(
            (paid.tx.outputs[0].value, paid.tx.outputs[0].script.clone()),
            (70_000, payee)
        );
        // Not in the block it names.
        let elsewhere = proof(&d, &headers[1], &branch);
        refused(
            t.f.prove_bitcoin_payment(&t.s, BridgeRouteAdapter::Deposit, CHAIN, &elsewhere),
            "another block",
        );
        // Another transaction under the same branch.
        let other = Deposit {
            tx: deposit_tx(vec![TxOut {
                value: 1,
                script: vec![0x51],
            }]),
            ..d.clone()
        };
        refused(
            t.f.prove_bitcoin_payment(
                &t.s,
                BridgeRouteAdapter::Deposit,
                CHAIN,
                &proof(&other, &headers[0], &branch),
            ),
            "another transaction",
        );
    }

    /// A deposit last in a block with an odd number of transactions is
    /// paired with itself in the Merkle tree, so the same branch also
    /// reaches the root from the next, nonexistent position. That position
    /// is a different route sequence: admitting it would credit the one
    /// deposit twice.
    #[test]
    fn bitcoin_credits_a_deposit_once_at_its_one_position() {
        let mut t = setup();
        let tx = deposit_tx(good_outputs(50_000));
        let d = Deposit {
            height: ANCHOR_HEIGHT + 1,
            index: 2,
            tx,
        };
        let (root, branch) = merkle(&[[0x10; 32], [0x11; 32], d.txid()], 2);
        let mut headers = vec![mine(t.anchor.hash(), root, (NOW_S - 90_000) as u32, BITS)];
        for i in 0..5u8 {
            let prev = headers.last().unwrap().hash();
            headers.push(mine(
                prev,
                [i; 32],
                (NOW_S - 89_000 + u64::from(i) * 600) as u32,
                BITS,
            ));
        }
        t.f.advance_light_client(
            &mut t.s,
            BridgeRouteAdapter::Deposit,
            CHAIN,
            &extend(ANCHOR_HEIGHT, &headers),
        )
        .unwrap();
        admit(&mut t, &d, &headers[0], &branch).unwrap();
        let phantom = Deposit {
            index: 3,
            ..d.clone()
        };
        refused(
            admit(&mut t, &phantom, &headers[0], &branch),
            "the duplicated position",
        );
        assert_eq!(read_supply(&t.s, &t.route).bridged, 50_000);
    }

    #[test]
    fn bitcoin_refuses_forged_and_malformed_deposits() {
        let mut t = setup();
        let (d, headers, branch) = mine_deposit(&t, &deposit_tx(good_outputs(50_000)), 5);
        t.f.advance_light_client(
            &mut t.s,
            BridgeRouteAdapter::Deposit,
            CHAIN,
            &extend(ANCHOR_HEIGHT, &headers),
        )
        .unwrap();

        // No recipient marker, two deposit outputs, or a marker with value.
        let mut outs = good_outputs(50_000);
        outs.remove(1);
        let no_marker = Deposit {
            tx: deposit_tx(outs),
            ..d.clone()
        };
        refused(admit(&mut t, &no_marker, &headers[0], &branch), "no marker");
        let mut outs = good_outputs(50_000);
        outs.push(outs[0].clone());
        let twice = Deposit {
            tx: deposit_tx(outs),
            ..d.clone()
        };
        refused(
            admit(&mut t, &twice, &headers[0], &branch),
            "two deposit outputs",
        );

        // A deposit the block does not contain: the committee signed it,
        // the Merkle branch does not reach the header.
        let inflated = Deposit {
            tx: deposit_tx(good_outputs(5_000_000)),
            ..d.clone()
        };
        refused(
            admit(&mut t, &inflated, &headers[0], &branch),
            "transaction not in the block",
        );
        let mut bent = branch.clone();
        bent[0][0] ^= 1;
        refused(admit(&mut t, &d, &headers[0], &bent), "bent branch");
        let moved = Deposit {
            index: 0,
            ..d.clone()
        };
        refused(
            admit(&mut t, &moved, &headers[0], &branch),
            "wrong position",
        );

        // A block the client never accepted, though it has the transaction.
        let (root, side_branch) = merkle(&[[0x10; 32], d.txid(), [0x11; 32]], 1);
        let side = mine(t.anchor.hash(), root, (NOW_S - 90_001) as u32, BITS);
        refused(
            admit(&mut t, &d, &side, &side_branch),
            "block off the best chain",
        );

        // A trailing byte in the attested body.
        let mut padded = d.encode();
        padded.push(0);
        let delivery = deliver(
            &t.route,
            &signers(),
            3,
            d.sequence(),
            EXPIRY,
            &padded,
            &proof(&d, &headers[0], &branch),
        );
        refused(
            t.f.admit_inbound(&mut t.s, BridgeRouteAdapter::Deposit, CHAIN, &delivery),
            "trailing byte",
        );

        // A sequence that is not the deposit's position.
        let delivery = deliver(
            &t.route,
            &signers(),
            3,
            d.sequence() + 1,
            EXPIRY,
            &d.encode(),
            &proof(&d, &headers[0], &branch),
        );
        refused(
            t.f.admit_inbound(&mut t.s, BridgeRouteAdapter::Deposit, CHAIN, &delivery),
            "sequence mismatch",
        );

        admit(&mut t, &d, &headers[0], &branch).unwrap();
    }

    #[test]
    fn the_header_chain_needs_work_targets_and_the_most_work() {
        let mut t = setup();
        let (d, headers, branch) = mine_deposit(&t, &deposit_tx(good_outputs(50_000)), 5);
        let up = |t: &mut Setup, parent: u64, hs: &[BlockHeader]| {
            t.f.advance_light_client(
                &mut t.s,
                BridgeRouteAdapter::Deposit,
                CHAIN,
                &extend(parent, hs),
            )
        };

        // A header without its proof of work.
        let mut lazy = headers[0];
        let limit = target(BITS).unwrap();
        while ethnum::U256::from_le_bytes(lazy.hash()) <= limit {
            lazy.nonce += 1;
        }
        assert!(up(&mut t, ANCHOR_HEIGHT, &[lazy]).is_err());

        // A header with an easier target than its period's.
        let easy = mine(
            t.anchor.hash(),
            [0x09; 32],
            (NOW_S - 90_000) as u32,
            0x207f_ffff,
        );
        assert!(up(&mut t, ANCHOR_HEIGHT, &[easy]).is_err());

        // A header that does not build on the named parent.
        assert!(up(&mut t, ANCHOR_HEIGHT, &headers[1..2]).is_err());

        // The honest chain, then a longer fork from the anchor that drops
        // the deposit's block: the client follows the most work.
        up(&mut t, ANCHOR_HEIGHT, &headers).unwrap();
        let mut fork = vec![mine(
            t.anchor.hash(),
            [0x0f; 32],
            (NOW_S - 90_000) as u32,
            BITS,
        )];
        for i in 0..6u8 {
            let prev = fork.last().unwrap().hash();
            fork.push(mine(
                prev,
                [0xf0 | i; 32],
                (NOW_S - 80_000 + u64::from(i) * 600) as u32,
                BITS,
            ));
        }
        assert!(
            up(&mut t, ANCHOR_HEIGHT, &fork[..6]).is_err(),
            "equal work does not reorganise"
        );
        up(&mut t, ANCHOR_HEIGHT, &fork).unwrap();
        refused(
            admit(&mut t, &d, &headers[0], &branch),
            "deposit in an orphaned block",
        );

        // A bootstrap that is not the anchor's header.
        let other = setup();
        let mut s = MemState::with(std::slice::from_ref(&other.route));
        assert!(
            other
                .f
                .advance_light_client(
                    &mut s,
                    BridgeRouteAdapter::Deposit,
                    CHAIN,
                    &bootstrap(&headers[0])
                )
                .is_err()
        );
    }
}

/// The transfer record a Move bridge module emits for `amount` on `route`.
fn move_record(route: &BridgeRoute, seq: u64, amount: u128) -> super::move_event::MoveTransfer {
    super::move_event::MoveTransfer {
        sequence: seq,
        source_selector: route.source_chain_id,
        dest_selector: LOCAL_SELECTOR,
        sender: [0x31; 32],
        token: route.peer,
        endpoint: route.local_endpoint,
        recipient: RECIPIENT,
        amount,
    }
}

fn transfer_out_tag(ramp: [u8; 32]) -> super::move_event::StructTag {
    super::move_event::StructTag {
        address: ramp,
        module: "bridge".into(),
        name: "TransferOut".into(),
        type_args: 0,
    }
}

mod sui {
    use super::super::move_event::MoveTransfer;
    use super::super::sui::fixtures::*;
    use super::super::sui::{SuiEvent, SuiLightClient, digest};
    use super::*;

    const CHAIN: &str = "sui";
    const PACKAGE: [u8; 32] = [0x5a; 32];

    struct Setup {
        f: RouteFramework,
        s: MemState,
        route: BridgeRoute,
    }

    /// Epoch 5's committee, which the anchor names.
    fn committee5() -> Committee {
        Committee::new(10, 4)
    }

    fn setup() -> Setup {
        setup_with(None)
    }

    fn setup_with(settlement_lock: Option<[u8; 32]>) -> Setup {
        let c5 = committee5();
        let anchor = summary(4, 100, [0x0a; 32], Some(&c5));
        let mut r = route(BridgeRouteAdapter::Contract, ChainFamily::Sui, CHAIN, 2);
        r.ramp = PACKAGE;
        r.settlement_lock = settlement_lock;
        r.light_client = Some(LightClientAnchor::SuiCommittee {
            trusted_checkpoint_digest: digest("CheckpointSummary", &anchor),
        });
        r.validate().unwrap();
        let f = RouteFramework::new().with_light_client(Arc::new(SuiLightClient));
        let mut s = MemState::with(std::slice::from_ref(&r));
        f.advance_light_client(
            &mut s,
            BridgeRouteAdapter::Contract,
            CHAIN,
            &bootstrap(&anchor),
        )
        .unwrap();
        Setup { f, s, route: r }
    }

    fn event(route: &BridgeRoute, seq: u64, amount: u128) -> SuiEvent {
        SuiEvent {
            package_id: PACKAGE,
            module: "bridge".into(),
            sender: [0x31; 32],
            type_: transfer_out_tag(PACKAGE),
            contents: move_record(route, seq, amount).encode(),
        }
    }

    fn noise() -> SuiEvent {
        SuiEvent {
            package_id: [0x02; 32],
            module: "coin".into(),
            sender: [0x31; 32],
            type_: super::super::move_event::StructTag {
                address: [0x02; 32],
                module: "coin".into(),
                name: "Burned".into(),
                type_args: 0,
            },
            contents: vec![1, 2, 3],
        }
    }

    /// A checkpoint of `epoch` holding `events`, certified by `signers` of
    /// `committee`; returns the proof of event 1.
    fn checkpoint(
        committee: &Committee,
        epoch: u64,
        events: &[SuiEvent],
        signers: &[u16],
    ) -> Vec<u8> {
        checkpoint_at(committee, epoch, 150, events, signers)
    }

    /// [`checkpoint`] with sequence number `seq`.
    fn checkpoint_at(
        committee: &Committee,
        epoch: u64,
        seq: u64,
        events: &[SuiEvent],
        signers: &[u16],
    ) -> Vec<u8> {
        let (events_bcs, effects, contents) = transaction(events);
        let s = summary(epoch, seq, digest("CheckpointContents", &contents), None);
        let cert = committee.certify(epoch, &s, signers);
        proof(&s, &cert, &contents, 1, &effects, &events_bcs, 1)
    }

    fn admit(
        t: &mut Setup,
        nonce: u64,
        body: &[u8],
        proof: &[u8],
    ) -> crate::Result<AdmittedTransfer> {
        let d = deliver(&t.route, &signers(), 3, nonce, EXPIRY, body, proof);
        t.f.admit_inbound(&mut t.s, BridgeRouteAdapter::Contract, CHAIN, &d)
    }

    const LOCK: [u8; 32] = [0x10; 32];
    /// `settlement_lock::asset_id<SUI>()`, asserted by the Move test.
    const SUI_ASSET: &str = "be4507e04f555448ca05c0c9f8345c5ea9f3e40e8616a20f5d5c18b40ef399eb";

    fn locked(lock: [u8; 32], name: &str) -> (SuiEvent, crate::route::receipt_proof::LockEvent) {
        let ev = crate::route::receipt_proof::LockEvent {
            plan_id: [1; 32],
            leg_id: [2; 32],
            index: 1,
            payer: [3; 32],
            recipient: [4; 32],
            asset: hex::decode(SUI_ASSET).unwrap().try_into().unwrap(),
            amount: 700,
            escape_at_ms: 1_801_209_600_000,
        };
        let mut w = super::super::canonical::Writer::new();
        w.bcs_bytes(&ev.plan_id).bcs_bytes(&ev.leg_id).u8(ev.index);
        w.raw(&ev.payer).raw(&ev.recipient).raw(&ev.asset);
        w.u64_le(700).u64_le(ev.escape_at_ms);
        let e = SuiEvent {
            package_id: lock,
            module: "settlement_lock".into(),
            sender: [3; 32],
            type_: super::super::move_event::StructTag {
                address: lock,
                module: "settlement_lock".into(),
                name: name.into(),
                type_args: 0,
            },
            contents: w.into_bytes(),
        };
        (e, ev)
    }

    #[test]
    fn a_sui_lock_event_is_proven_only_from_the_routes_lock() {
        let mut t = setup_with(Some(LOCK));
        let c5 = committee5();
        let (e, want) = locked(LOCK, "Locked");
        let p = checkpoint(&c5, 5, &[noise(), e], &[0, 1, 2]);
        let (got, proven, _) =
            t.f.prove_lock(&mut t.s, BridgeRouteAdapter::Contract, CHAIN, &p)
                .unwrap();
        assert!(proven);
        assert_eq!(got, crate::route::receipt_proof::LockRecord::Locked(want));
        let lock = |t: &mut Setup, p: &[u8]| {
            t.f.prove_lock(&mut t.s, BridgeRouteAdapter::Contract, CHAIN, p)
        };
        assert!(
            lock(
                &mut t,
                &checkpoint(
                    &c5,
                    5,
                    &[noise(), locked([0x11; 32], "Locked").0],
                    &[0, 1, 2]
                )
            )
            .is_err(),
            "another lock"
        );
        assert!(
            lock(
                &mut t,
                &checkpoint(&c5, 5, &[noise(), locked(LOCK, "Released").0], &[0, 1, 2])
            )
            .is_err(),
            "another event"
        );
        assert!(
            lock(
                &mut t,
                &checkpoint(&c5, 5, &[noise(), locked(LOCK, "Locked").0], &[0, 1])
            )
            .is_err(),
            "half the stake"
        );
    }

    /// The BCS of the Move lock's `Accumulator` event after the shared
    /// reconciliation sequence, as the Move tests emit it.
    pub(super) fn move_accumulator() -> (Vec<u8>, crate::route::receipt_proof::LockRecord) {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../sdk/fixtures/settlement_lock/move_accumulator_event.hex"
        );
        let raw = hex::decode(std::fs::read_to_string(path).unwrap().trim()).unwrap();
        let mut acc = [0u8; 32];
        acc.copy_from_slice(
            &hex::decode("375111922b0be21f25ad54b505467229080fd12340e5b01e4f56220cb3ecb58a")
                .unwrap(),
        );
        let cp = crate::route::receipt_proof::LockCheckpoint { count: 6, acc };
        (raw, crate::route::receipt_proof::LockRecord::Checkpoint(cp))
    }

    #[test]
    fn a_sui_lock_checkpoint_is_proven_from_the_routes_lock() {
        let mut t = setup_with(Some(LOCK));
        let c5 = committee5();
        let (contents, want) = move_accumulator();
        let (mut e, _) = locked(LOCK, "Accumulator");
        e.contents = contents.clone();
        let (got, proven, _) =
            t.f.prove_lock(
                &mut t.s,
                BridgeRouteAdapter::Contract,
                CHAIN,
                &checkpoint(&c5, 5, &[noise(), e.clone()], &[0, 1, 2]),
            )
            .unwrap();
        assert!(proven);
        assert_eq!(got, want);
        let mut other = e.clone();
        other.type_.address = [0x11; 32];
        let p = checkpoint(&c5, 5, &[noise(), other], &[0, 1, 2]);
        assert!(
            t.f.prove_lock(&mut t.s, BridgeRouteAdapter::Contract, CHAIN, &p)
                .is_err(),
            "another lock"
        );
        let mut short = e;
        short.contents.pop();
        let p = checkpoint(&c5, 5, &[noise(), short], &[0, 1, 2]);
        assert!(
            t.f.prove_lock(&mut t.s, BridgeRouteAdapter::Contract, CHAIN, &p)
                .is_err(),
            "a short hash"
        );
    }

    #[test]
    fn sui_round_trips_a_fixture_message() {
        let mut t = setup();
        let c5 = committee5();
        let out = send(&t.f, &mut t.s, CHAIN, 600, vec![0x44; 32]);
        let record = MoveTransfer::decode(&out.bytes).unwrap();
        assert_eq!(record.amount, 600);
        assert_eq!(record.recipient, [0x44; 32]);
        assert_eq!(record.endpoint, PACKAGE);
        assert_eq!(record.token, t.route.remote_token);

        let e = event(&t.route, 7, 250);
        let p = checkpoint(&c5, 5, &[noise(), e.clone()], &[0, 1, 2]);
        let admitted = admit(&mut t, 7, &e.encode(), &p).unwrap();
        assert_eq!(admitted.message.amount, 250);
        assert_eq!(admitted.message.receiver, RECIPIENT.to_vec());
        assert_eq!(read_supply(&t.s, &t.route).bridged, 350);

        // The committee hands over to the next epoch's; its certificates
        // then prove messages, and the old committee's no longer move it.
        let c6 = Committee::new(60, 5);
        let end = summary(5, 200, [0x0b; 32], Some(&c6));
        let head =
            t.f.advance_light_client(
                &mut t.s,
                BridgeRouteAdapter::Contract,
                CHAIN,
                &handover(&end, &c5.certify(5, &end, &[1, 2, 3])),
            )
            .unwrap();
        assert_eq!((head.period, head.finalized), (6, 200));
        let e = event(&t.route, 8, 50);
        let p = checkpoint(&c6, 6, &[noise(), e.clone()], &[0, 1, 2, 3]);
        admit(&mut t, 8, &e.encode(), &p).unwrap();
        let again = summary(5, 201, [0x0b; 32], Some(&c6));
        assert!(
            t.f.advance_light_client(
                &mut t.s,
                BridgeRouteAdapter::Contract,
                CHAIN,
                &handover(&again, &c5.certify(5, &again, &[0, 1, 2]))
            )
            .is_err()
        );
    }

    /// Once the client has followed two handovers, a committee two epochs
    /// back proves nothing, and the epoch that just ended proves only
    /// checkpoints up to its last.
    #[test]
    fn sui_refuses_checkpoints_of_retired_committees() {
        let mut t = setup();
        let c5 = committee5();
        send(&t.f, &mut t.s, CHAIN, 1_000, vec![0x44; 32]);
        let c6 = Committee::new(60, 5);
        let c7 = Committee::new(70, 5);
        let end5 = summary(5, 200, [0x0b; 32], Some(&c6));
        let end6 = summary(6, 300, [0x0c; 32], Some(&c7));
        for (s, cert) in [
            (&end5, c5.certify(5, &end5, &[1, 2, 3])),
            (&end6, c6.certify(6, &end6, &[0, 1, 2, 3])),
        ] {
            t.f.advance_light_client(
                &mut t.s,
                BridgeRouteAdapter::Contract,
                CHAIN,
                &handover(s, &cert),
            )
            .unwrap();
        }
        let e = event(&t.route, 1, 10);
        let old = checkpoint_at(&c5, 5, 150, &[noise(), e.clone()], &[0, 1, 2]);
        assert!(
            admit(&mut t, 1, &e.encode(), &old).is_err(),
            "two epochs back"
        );
        let late = checkpoint_at(&c6, 6, 350, &[noise(), e.clone()], &[0, 1, 2, 3]);
        assert!(
            admit(&mut t, 1, &e.encode(), &late).is_err(),
            "past the ended epoch's last checkpoint"
        );
        let ended = checkpoint_at(&c6, 6, 250, &[noise(), e.clone()], &[0, 1, 2, 3]);
        admit(&mut t, 1, &e.encode(), &ended).unwrap();
    }

    #[test]
    fn sui_refuses_forged_and_malformed_messages() {
        let mut t = setup();
        let c5 = committee5();
        send(&t.f, &mut t.s, CHAIN, 1_000, vec![0x44; 32]);
        let e = event(&t.route, 9, 10);

        // Half the stake is not a quorum.
        refused(
            admit(
                &mut t,
                9,
                &e.encode(),
                &checkpoint(&c5, 5, &[noise(), e.clone()], &[0, 1]),
            ),
            "half the stake",
        );

        // A certificate by a committee the client does not follow.
        let rogue = Committee::new(90, 4);
        refused(
            admit(
                &mut t,
                9,
                &e.encode(),
                &checkpoint(&rogue, 5, &[noise(), e.clone()], &[0, 1, 2]),
            ),
            "rogue committee",
        );

        // The proof is of another event of the transaction.
        let p = checkpoint(&c5, 5, &[e.clone(), noise()], &[0, 1, 2]);
        refused(admit(&mut t, 9, &e.encode(), &p), "another event");

        // A TransferOut from another package, attested by the committee.
        let mut foreign = e.clone();
        foreign.package_id = [0x66; 32];
        foreign.type_.address = [0x66; 32];
        let p = checkpoint(&c5, 5, &[noise(), foreign.clone()], &[0, 1, 2]);
        refused(admit(&mut t, 9, &foreign.encode(), &p), "foreign package");

        // A delivered event inflated after the fact.
        let inflated = event(&t.route, 9, 10_000);
        let p = checkpoint(&c5, 5, &[noise(), e.clone()], &[0, 1, 2]);
        refused(admit(&mut t, 9, &inflated.encode(), &p), "inflated amount");

        // Tampered effects, and a signature flipped.
        let (events_bcs, effects, contents) = transaction(&[noise(), e.clone()]);
        let s = summary(5, 150, digest("CheckpointContents", &contents), None);
        let cert = c5.certify(5, &s, &[0, 1, 2]);
        let mut failed = effects.clone();
        failed[1] = 1;
        refused(
            admit(
                &mut t,
                9,
                &e.encode(),
                &proof(&s, &cert, &contents, 1, &failed, &events_bcs, 1),
            ),
            "tampered effects",
        );
        let mut bad_sig = cert.clone();
        bad_sig.signature[5] ^= 1;
        refused(
            admit(
                &mut t,
                9,
                &e.encode(),
                &proof(&s, &bad_sig, &contents, 1, &effects, &events_bcs, 1),
            ),
            "bad signature",
        );

        // A trailing byte in the event.
        let mut padded = e.encode();
        padded.push(0);
        refused(
            admit(
                &mut t,
                9,
                &padded,
                &proof(&s, &cert, &contents, 1, &effects, &events_bcs, 1),
            ),
            "trailing byte",
        );

        // The real one passes.
        admit(
            &mut t,
            9,
            &e.encode(),
            &proof(&s, &cert, &contents, 1, &effects, &events_bcs, 1),
        )
        .unwrap();

        // A handover the committee did not certify, and a bootstrap that is
        // not the anchor's.
        let c6 = Committee::new(60, 5);
        let end = summary(5, 200, [0x0b; 32], Some(&c6));
        assert!(
            t.f.advance_light_client(
                &mut t.s,
                BridgeRouteAdapter::Contract,
                CHAIN,
                &handover(&end, &rogue.certify(5, &end, &[0, 1, 2]))
            )
            .is_err()
        );
        let fresh = setup();
        let mut s = MemState::with(std::slice::from_ref(&fresh.route));
        assert!(
            fresh
                .f
                .advance_light_client(
                    &mut s,
                    BridgeRouteAdapter::Contract,
                    CHAIN,
                    &bootstrap(&end)
                )
                .is_err()
        );
    }
}

mod aptos {
    use super::super::aptos::fixtures::*;
    use super::super::aptos::{AptosLightClient, crypto_hash};
    use super::super::move_event::MoveTransfer;
    use super::*;

    const CHAIN: &str = "aptos";
    const MODULE_ADDRESS: [u8; 32] = [0x6a; 32];

    struct Setup {
        f: RouteFramework,
        s: MemState,
        route: BridgeRoute,
    }

    /// Epoch 8's validators, which the anchor names.
    fn validators8() -> Validators {
        Validators::new(20, 4)
    }

    fn setup() -> Setup {
        setup_with(None)
    }

    fn setup_with(settlement_lock: Option<[u8; 32]>) -> Setup {
        let v8 = validators8();
        let anchor = ledger_info(7, 1_000, [0x0d; 32], Some(&v8));
        let mut r = route(BridgeRouteAdapter::Contract, ChainFamily::Aptos, CHAIN, 3);
        r.ramp = MODULE_ADDRESS;
        r.settlement_lock = settlement_lock;
        r.light_client = Some(LightClientAnchor::AptosValidators {
            trusted_ledger_info_hash: crypto_hash("LedgerInfo", &anchor),
        });
        r.validate().unwrap();
        let f = RouteFramework::new().with_light_client(Arc::new(AptosLightClient));
        let mut s = MemState::with(std::slice::from_ref(&r));
        f.advance_light_client(
            &mut s,
            BridgeRouteAdapter::Contract,
            CHAIN,
            &update(0, &anchor),
        )
        .unwrap();
        Setup { f, s, route: r }
    }

    fn transfer_event(route: &BridgeRoute, seq: u64, amount: u128) -> Vec<u8> {
        event(
            MODULE_ADDRESS,
            "bridge",
            "TransferOut",
            &move_record(route, seq, amount).encode(),
        )
    }

    /// Prove `ev` as event 2 of a transaction at version 1_005, in a
    /// ledger info of `epoch` signed by `signers` of `v`.
    fn prove(v: &Validators, epoch: u64, ev: &[u8], proven: &[u8], signers: &[usize]) -> Vec<u8> {
        prove_at(v, epoch, 1_007, ev, proven, signers)
    }

    /// [`prove`] in a ledger info at `li_version`.
    fn prove_at(
        v: &Validators,
        epoch: u64,
        li_version: u64,
        ev: &[u8],
        proven: &[u8],
        signers: &[usize],
    ) -> Vec<u8> {
        let mut leaves = vec![
            [0x01; 32],
            [0x02; 32],
            crypto_hash("ContractEvent", ev),
            [0x04; 32],
        ];
        let (event_root, _) = accumulator("EventAccumulator", &leaves, 2);
        leaves[2] = crypto_hash("ContractEvent", proven);
        let (_, event_siblings) = accumulator("EventAccumulator", &leaves, 2);
        let info = transaction_info(event_root);
        let mut txns = vec![[0x11; 32]; 8];
        txns[5] = crypto_hash("TransactionInfo", &info);
        let (root, txn_siblings) = accumulator("TransactionAccumulator", &txns, 5);
        let signed = v.sign(&ledger_info(epoch, li_version, root, None), signers);
        Proof {
            signed: &signed,
            txn_info: &info,
            version: 5,
            txn_siblings: &txn_siblings,
            event: proven,
            event_index: 2,
            event_siblings: &event_siblings,
        }
        .encode()
    }

    fn admit(
        t: &mut Setup,
        nonce: u64,
        body: &[u8],
        proof: &[u8],
    ) -> crate::Result<AdmittedTransfer> {
        let d = deliver(&t.route, &signers(), 3, nonce, EXPIRY, body, proof);
        t.f.admit_inbound(&mut t.s, BridgeRouteAdapter::Contract, CHAIN, &d)
    }

    #[test]
    fn an_aptos_lock_checkpoint_is_proven_from_the_routes_lock() {
        const LOCK: [u8; 32] = [0x10; 32];
        let mut t = setup_with(Some(LOCK));
        let v8 = validators8();
        let (contents, want) = super::sui::move_accumulator();
        let ev = event(LOCK, "settlement_lock", "Accumulator", &contents);
        let (got, proven, _) =
            t.f.prove_lock(
                &mut t.s,
                BridgeRouteAdapter::Contract,
                CHAIN,
                &prove(&v8, 8, &ev, &ev, &[0, 1, 2]),
            )
            .unwrap();
        assert!(proven);
        assert_eq!(got, want);
        let mut lock = |ev: &[u8]| {
            t.f.prove_lock(
                &mut t.s,
                BridgeRouteAdapter::Contract,
                CHAIN,
                &prove(&v8, 8, ev, ev, &[0, 1, 2]),
            )
        };
        assert!(
            lock(&event(
                [0x11; 32],
                "settlement_lock",
                "Accumulator",
                &contents
            ))
            .is_err(),
            "another lock"
        );
        assert!(
            lock(&event(LOCK, "settlement_lock", "Released", &contents)).is_err(),
            "another event"
        );
        assert!(
            lock(&event(
                LOCK,
                "settlement_lock",
                "Accumulator",
                &contents[1..]
            ))
            .is_err(),
            "malformed"
        );
    }

    #[test]
    fn aptos_round_trips_a_fixture_message() {
        let mut t = setup();
        let v8 = validators8();
        let out = send(&t.f, &mut t.s, CHAIN, 600, vec![0x45; 32]);
        let record = MoveTransfer::decode(&out.bytes).unwrap();
        assert_eq!(
            (record.amount, record.recipient, record.endpoint),
            (600, [0x45; 32], MODULE_ADDRESS)
        );

        let ev = transfer_event(&t.route, 4, 250);
        let admitted = admit(&mut t, 4, &ev, &prove(&v8, 8, &ev, &ev, &[0, 1, 2])).unwrap();
        assert_eq!(admitted.message.amount, 250);
        assert_eq!(read_supply(&t.s, &t.route).bridged, 350);

        // Handover to epoch 9's validators.
        let v9 = Validators::new(70, 7);
        let end = ledger_info(8, 2_000, [0x0f; 32], Some(&v9));
        let head =
            t.f.advance_light_client(
                &mut t.s,
                BridgeRouteAdapter::Contract,
                CHAIN,
                &update(1, &v8.sign(&end, &[0, 1, 3])),
            )
            .unwrap();
        assert_eq!((head.period, head.finalized), (9, 2_000));
        let ev = transfer_event(&t.route, 5, 50);
        admit(&mut t, 5, &ev, &prove(&v9, 9, &ev, &ev, &[0, 1, 2, 3, 4])).unwrap();
    }

    /// Once the client has followed two handovers, a validator set two
    /// epochs back proves nothing, and the epoch that just ended proves only
    /// ledger infos up to its last version.
    #[test]
    fn aptos_refuses_ledger_infos_of_retired_validator_sets() {
        let mut t = setup();
        let v8 = validators8();
        send(&t.f, &mut t.s, CHAIN, 1_000, vec![0x45; 32]);
        let v9 = Validators::new(70, 7);
        let v10 = Validators::new(80, 4);
        let end8 = ledger_info(8, 2_000, [0x0f; 32], Some(&v9));
        let end9 = ledger_info(9, 3_000, [0x1f; 32], Some(&v10));
        for update_bytes in [
            update(1, &v8.sign(&end8, &[0, 1, 3])),
            update(1, &v9.sign(&end9, &[0, 1, 2, 3, 4])),
        ] {
            t.f.advance_light_client(&mut t.s, BridgeRouteAdapter::Contract, CHAIN, &update_bytes)
                .unwrap();
        }
        let ev = transfer_event(&t.route, 1, 10);
        let old = prove_at(&v8, 8, 1_007, &ev, &ev, &[0, 1, 2]);
        assert!(admit(&mut t, 1, &ev, &old).is_err(), "two epochs back");
        let late = prove_at(&v9, 9, 3_500, &ev, &ev, &[0, 1, 2, 3, 4]);
        assert!(
            admit(&mut t, 1, &ev, &late).is_err(),
            "past the ended epoch's last version"
        );
        let ended = prove_at(&v9, 9, 2_500, &ev, &ev, &[0, 1, 2, 3, 4]);
        admit(&mut t, 1, &ev, &ended).unwrap();
    }

    #[test]
    fn aptos_refuses_forged_and_malformed_messages() {
        let mut t = setup();
        let v8 = validators8();
        send(&t.f, &mut t.s, CHAIN, 1_000, vec![0x45; 32]);
        let ev = transfer_event(&t.route, 6, 10);

        // Two of four validators: not two thirds plus one.
        refused(
            admit(&mut t, 6, &ev, &prove(&v8, 8, &ev, &ev, &[0, 1])),
            "half the power",
        );
        // A validator set the client does not follow.
        let rogue = Validators::new(99, 4);
        refused(
            admit(&mut t, 6, &ev, &prove(&rogue, 8, &ev, &ev, &[0, 1, 2, 3])),
            "rogue validators",
        );
        // An event the transaction did not emit.
        let inflated = transfer_event(&t.route, 6, 10_000);
        refused(
            admit(
                &mut t,
                6,
                &inflated,
                &prove(&v8, 8, &ev, &inflated, &[0, 1, 2]),
            ),
            "event not emitted",
        );
        // A TransferOut of another module address.
        let foreign = event(
            [0x99; 32],
            "bridge",
            "TransferOut",
            &move_record(&t.route, 6, 10).encode(),
        );
        refused(
            admit(
                &mut t,
                6,
                &foreign,
                &prove(&v8, 8, &foreign, &foreign, &[0, 1, 2]),
            ),
            "foreign module",
        );
        // An unknown event encoding version.
        let mut legacy = ev.clone();
        legacy[0] = 0;
        refused(
            admit(
                &mut t,
                6,
                &legacy,
                &prove(&v8, 8, &legacy, &legacy, &[0, 1, 2]),
            ),
            "unknown event version",
        );
        // A trailing byte.
        let mut padded = ev.clone();
        padded.push(0);
        refused(
            admit(
                &mut t,
                6,
                &padded,
                &prove(&v8, 8, &padded, &padded, &[0, 1, 2]),
            ),
            "trailing byte",
        );

        admit(&mut t, 6, &ev, &prove(&v8, 8, &ev, &ev, &[0, 1, 2])).unwrap();

        // A handover signed by a minority, and a bootstrap that is not the
        // anchor's.
        let v9 = Validators::new(70, 7);
        let end = ledger_info(8, 2_000, [0x0f; 32], Some(&v9));
        assert!(
            t.f.advance_light_client(
                &mut t.s,
                BridgeRouteAdapter::Contract,
                CHAIN,
                &update(1, &v8.sign(&end, &[2]))
            )
            .is_err()
        );
        let fresh = setup();
        let mut s = MemState::with(std::slice::from_ref(&fresh.route));
        assert!(
            fresh
                .f
                .advance_light_client(
                    &mut s,
                    BridgeRouteAdapter::Contract,
                    CHAIN,
                    &update(0, &end)
                )
                .is_err()
        );
    }

    /// Recorded from Aptos mainnet's public backups: the ledger infos that
    /// ended epochs 17485 and 17486 with their validators' signatures, a
    /// ledger info of epoch 17487 signed by its 85-member validator set, a
    /// transaction's info with its accumulator proof to that ledger info,
    /// and one of the transaction's module events with its event proof.
    const MAINNET: &str = include_str!("../../tests/fixtures/aptos_mainnet.json");

    #[test]
    fn a_recorded_mainnet_event_is_proven_from_validator_signed_ledger_infos() {
        use super::super::aptos::AptosAdapter;
        use super::super::attestation::body_hash;
        use super::super::canonical::Reader;
        use super::super::light_client::LightClientVerifier;

        let f: serde_json::Value = serde_json::from_str(MAINNET).unwrap();
        let b = |k: &str| hex::decode(f[k].as_str().unwrap()).unwrap();
        let siblings = |k: &str| -> Vec<[u8; 32]> {
            f[k].as_array()
                .unwrap()
                .iter()
                .map(|s| {
                    hex::decode(s.as_str().unwrap())
                        .unwrap()
                        .try_into()
                        .unwrap()
                })
                .collect()
        };
        let bootstrap = unsigned(&b("epoch_17485"));
        let mut r = route(BridgeRouteAdapter::Contract, ChainFamily::Aptos, CHAIN, 1);
        let anchor = LightClientAnchor::AptosValidators {
            trusted_ledger_info_hash: crypto_hash("LedgerInfo", &bootstrap),
        };
        r.light_client = Some(anchor.clone());
        r.validate().unwrap();
        let fw = RouteFramework::new().with_light_client(Arc::new(AptosLightClient));
        let mut s = MemState::with(std::slice::from_ref(&r));

        // The handover is refused before the bootstrap, and a bootstrap the
        // anchor does not name is refused.
        assert!(
            fw.advance_light_client(
                &mut s,
                BridgeRouteAdapter::Contract,
                CHAIN,
                &update(1, &b("epoch_17486"))
            )
            .is_err()
        );
        assert!(
            fw.advance_light_client(
                &mut s,
                BridgeRouteAdapter::Contract,
                CHAIN,
                &update(0, &unsigned(&b("epoch_17486")))
            )
            .is_err()
        );
        let head = fw
            .advance_light_client(
                &mut s,
                BridgeRouteAdapter::Contract,
                CHAIN,
                &update(0, &bootstrap),
            )
            .unwrap();
        assert_eq!((head.period, head.finalized), (17_486, 7_445_526_830));

        // A handover with one flipped signature bit is refused; the real one
        // (epoch 17486's validators signing its end) hands over to 17487.
        let mut forged = b("epoch_17486");
        let at = forged.len() - 20;
        forged[at] ^= 1;
        assert!(
            fw.advance_light_client(
                &mut s,
                BridgeRouteAdapter::Contract,
                CHAIN,
                &update(1, &forged)
            )
            .is_err()
        );
        let head = fw
            .advance_light_client(
                &mut s,
                BridgeRouteAdapter::Contract,
                CHAIN,
                &update(1, &b("epoch_17486")),
            )
            .unwrap();
        assert_eq!((head.period, head.finalized), (17_487, 7_446_555_719));

        let event = b("event");
        let signed = b("signed_ledger_info");
        let info = b("transaction_info");
        let txn_siblings = siblings("transaction_siblings");
        let event_siblings = siblings("event_siblings");
        let proof = |signed: &[u8], version: u64| {
            Proof {
                signed,
                txn_info: &info,
                version,
                txn_siblings: &txn_siblings,
                event: &event,
                event_index: f["event_index"].as_u64().unwrap(),
                event_siblings: &event_siblings,
            }
            .encode()
        };
        let version = f["version"].as_u64().unwrap();
        let lc = AptosLightClient;
        let good = proof(&signed, version);
        lc.verify(&s, &r, &anchor, &body_hash(&event), &good)
            .unwrap();

        // Another body, another transaction position, an altered signature
        // or any altered proof byte is refused.
        assert!(lc.verify(&s, &r, &anchor, &[0; 32], &good).is_err());
        assert!(
            lc.verify(
                &s,
                &r,
                &anchor,
                &body_hash(&event),
                &proof(&signed, version + 1)
            )
            .is_err()
        );
        let mut bad_sig = signed.clone();
        let at = bad_sig.len() - 30;
        bad_sig[at] ^= 1;
        assert!(
            lc.verify(
                &s,
                &r,
                &anchor,
                &body_hash(&event),
                &proof(&bad_sig, version)
            )
            .is_err()
        );
        for at in [40, good.len() / 3, good.len() / 2, good.len() - 3] {
            let mut bad = good.clone();
            bad[at] ^= 1;
            assert!(
                lc.verify(&s, &r, &anchor, &body_hash(&event), &bad)
                    .is_err(),
                "byte {at}"
            );
        }

        // The event is a real module event but not the route's TransferOut,
        // so the adapter does not take it as a delivery.
        assert!(
            AptosAdapter
                .decode_inbound(&r, &mut Reader::new(&event))
                .is_err()
        );
    }
}

mod stellar {
    use ed25519_dalek::SigningKey;
    use sha2::{Digest, Sha256};

    use super::super::move_event::MoveTransfer;
    use super::super::stellar::fixtures::*;
    use super::super::stellar::{StellarLightClient, encode_record, transfer_event};
    use super::*;

    const CHAIN: &str = "stellar";
    const CONTRACT: [u8; 32] = [0x7c; 32];

    fn h(b: &[u8]) -> [u8; 32] {
        Sha256::digest(b).into()
    }

    fn setup() -> (RouteFramework, MemState, BridgeRoute, Vec<SigningKey>) {
        let vs = validators(30, 4);
        let mut r = route(BridgeRouteAdapter::Contract, ChainFamily::Stellar, CHAIN, 4);
        r.ramp = CONTRACT;
        r.light_client = Some(LightClientAnchor::StellarScp {
            network_id: NETWORK,
            validators: vs.iter().map(|k| k.verifying_key().to_bytes()).collect(),
            threshold: 3,
        });
        r.validate().unwrap();
        let f = RouteFramework::new().with_light_client(Arc::new(StellarLightClient));
        let s = MemState::with(std::slice::from_ref(&r));
        (f, s, r, vs)
    }

    fn event(route: &BridgeRoute, seq: u64, amount: u128) -> Vec<u8> {
        transfer_event(&CONTRACT, &encode_record(&move_record(route, seq, amount)))
    }

    struct Ledger {
        envelopes: Vec<Vec<u8>>,
        tx_set: Vec<u8>,
        header: Vec<u8>,
        results: Vec<u8>,
        preimage: Vec<u8>,
    }

    impl Ledger {
        /// Ledger 500 holding `events` from the invocation, externalized
        /// in slot 501 by `signers`.
        fn new(events: &[Vec<u8>], signers: &[&SigningKey]) -> Self {
            let preimage = preimage(events);
            let results = results(h(&preimage));
            let header = header(500, h(&results));
            let tx_set = tx_set(h(&header));
            let value = stellar_value_bytes(&h(&tx_set));
            Self {
                envelopes: signers.iter().map(|k| envelope(k, 501, &value)).collect(),
                tx_set,
                header,
                results,
                preimage,
            }
        }

        fn proof(&self, tx_index: u32, op_index: u32, event_index: u32) -> Vec<u8> {
            Proof {
                envelopes: &self.envelopes,
                tx_set: &self.tx_set,
                header: &self.header,
                results: &self.results,
                tx_index,
                op_index,
                preimage: &self.preimage,
                event_index,
            }
            .encode()
        }
    }

    fn admit(
        f: &RouteFramework,
        s: &mut MemState,
        r: &BridgeRoute,
        nonce: u64,
        body: &[u8],
        proof: &[u8],
    ) -> crate::Result<AdmittedTransfer> {
        let d = deliver(r, &signers(), 3, nonce, EXPIRY, body, proof);
        f.admit_inbound(s, BridgeRouteAdapter::Contract, CHAIN, &d)
    }

    /// The Locked event the Soroban lock emits in its own test.
    fn locked_vector() -> Vec<u8> {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../sdk/fixtures/settlement_lock/stellar_locked_event.hex"
        );
        hex::decode(std::fs::read_to_string(path).unwrap().trim()).unwrap()
    }

    #[test]
    fn a_stellar_lock_event_is_proven_only_from_the_routes_lock() {
        let raw = locked_vector();
        let (lock, record) = super::super::stellar::lock_record(&raw).unwrap();
        let crate::route::receipt_proof::LockRecord::Locked(want) = record else {
            panic!("a Locked event")
        };
        assert_eq!(want.index, 1);
        assert_eq!(want.amount, 700);
        assert_eq!(want.escape_at_ms, 1_801_209_600_000);
        assert_eq!(
            hex::encode(want.plan_id),
            "ff39945f610e67d55c8c0ec52e62f47d49dd7a293527cd1c5d17b8401f33a02c"
        );
        assert_eq!(
            hex::encode(want.leg_id),
            "9b8f9d7940481b44652dbd5f19da37b150bc1d43a38ef1215bcf159bea98782f"
        );

        let (f, _, mut r, vs) = setup();
        r.settlement_lock = Some(lock);
        let mut s = MemState::with(std::slice::from_ref(&r));
        let ledger = Ledger::new(&[noise_event(), raw.clone()], &[&vs[0], &vs[2], &vs[3]]);
        let (got, proven, _) = f
            .prove_lock(
                &mut s,
                BridgeRouteAdapter::Contract,
                CHAIN,
                &ledger.proof(2, 1, 1),
            )
            .unwrap();
        assert!(proven);
        assert_eq!(got, crate::route::receipt_proof::LockRecord::Locked(want));
        assert!(
            f.prove_lock(
                &mut s,
                BridgeRouteAdapter::Contract,
                CHAIN,
                &ledger.proof(2, 1, 0)
            )
            .is_err(),
            "not a Locked event"
        );
        let weak = Ledger::new(&[noise_event(), raw.clone()], &[&vs[0], &vs[2]]);
        assert!(
            f.prove_lock(
                &mut s,
                BridgeRouteAdapter::Contract,
                CHAIN,
                &weak.proof(2, 1, 1)
            )
            .is_err(),
            "below threshold"
        );
        r.settlement_lock = Some([0x11; 32]);
        let mut other = MemState::with(std::slice::from_ref(&r));
        assert!(
            f.prove_lock(
                &mut other,
                BridgeRouteAdapter::Contract,
                CHAIN,
                &ledger.proof(2, 1, 1)
            )
            .is_err(),
            "another lock"
        );
        let mut bad = raw;
        let at = bad.len() - 8 - 4 - 8 - 8;
        bad[at] = 0x80; // a negative amount
        assert!(super::super::stellar::lock_record(&bad).is_err());
    }

    #[test]
    fn a_stellar_lock_checkpoint_is_proven_from_the_routes_lock() {
        use crate::route::receipt_proof::{LockCheckpoint, LockRecord};
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../sdk/fixtures/settlement_lock/stellar_accumulator_event.hex"
        );
        let raw = hex::decode(std::fs::read_to_string(path).unwrap().trim()).unwrap();
        let (lock, record) = super::super::stellar::lock_record(&raw).unwrap();
        // The lock's state after the shared reconciliation sequence.
        let mut acc = [0u8; 32];
        acc.copy_from_slice(
            &hex::decode("375111922b0be21f25ad54b505467229080fd12340e5b01e4f56220cb3ecb58a")
                .unwrap(),
        );
        assert_eq!(
            record,
            LockRecord::Checkpoint(LockCheckpoint { count: 6, acc })
        );

        let (f, _, mut r, vs) = setup();
        r.settlement_lock = Some(lock);
        let mut s = MemState::with(std::slice::from_ref(&r));
        let ledger = Ledger::new(&[noise_event(), raw.clone()], &[&vs[0], &vs[2], &vs[3]]);
        let (got, proven, _) = f
            .prove_lock(
                &mut s,
                BridgeRouteAdapter::Contract,
                CHAIN,
                &ledger.proof(2, 1, 1),
            )
            .unwrap();
        assert!(proven);
        assert_eq!(got, record);
        r.settlement_lock = Some([0x11; 32]);
        let mut other = MemState::with(std::slice::from_ref(&r));
        assert!(
            f.prove_lock(
                &mut other,
                BridgeRouteAdapter::Contract,
                CHAIN,
                &ledger.proof(2, 1, 1)
            )
            .is_err(),
            "another lock"
        );
        let mut short = raw;
        short.pop();
        assert!(super::super::stellar::lock_record(&short).is_err());
    }

    #[test]
    fn stellar_round_trips_a_fixture_message() {
        let (f, mut s, r, vs) = setup();
        let out = send(&f, &mut s, CHAIN, 600, vec![0x46; 32]);
        assert_eq!(
            out.bytes,
            encode_record(&MoveTransfer::outbound(&r, &out.message).unwrap())
        );
        let ev = event(&r, 3, 250);
        let ledger = Ledger::new(&[noise_event(), ev.clone()], &[&vs[0], &vs[2], &vs[3]]);
        let admitted = admit(&f, &mut s, &r, 3, &ev, &ledger.proof(2, 1, 1)).unwrap();
        assert_eq!(admitted.message.amount, 250);
        assert_eq!(admitted.message.receiver, RECIPIENT.to_vec());
        assert_eq!(read_supply(&s, &r).bridged, 350);
        assert!(
            f.advance_light_client(&mut s, BridgeRouteAdapter::Contract, CHAIN, &[0])
                .is_err()
        );
    }

    #[test]
    fn stellar_refuses_forged_and_malformed_messages() {
        let (f, mut s, r, vs) = setup();
        send(&f, &mut s, CHAIN, 1_000, vec![0x46; 32]);
        let ev = event(&r, 4, 10);
        let events = [noise_event(), ev.clone()];

        // Below the threshold, the same validator three times, and keys
        // outside the quorum.
        let two = Ledger::new(&events, &[&vs[0], &vs[1]]);
        refused(
            admit(&f, &mut s, &r, 4, &ev, &two.proof(2, 1, 1)),
            "below threshold",
        );
        let same = Ledger::new(&events, &[&vs[0], &vs[0], &vs[0]]);
        refused(
            admit(&f, &mut s, &r, 4, &ev, &same.proof(2, 1, 1)),
            "one validator thrice",
        );
        let outsiders = validators(80, 3);
        let rogue = Ledger::new(&events, &[&outsiders[0], &outsiders[1], &outsiders[2]]);
        refused(
            admit(&f, &mut s, &r, 4, &ev, &rogue.proof(2, 1, 1)),
            "validators outside the quorum",
        );

        let ledger = Ledger::new(&events, &[&vs[0], &vs[1], &vs[2]]);
        // A forged signature, and a statement for another value.
        let mut forged = Ledger::new(&events, &[&vs[0], &vs[1], &vs[2]]);
        let last = forged.envelopes[0].len() - 1;
        forged.envelopes[0][last] ^= 1;
        refused(
            admit(&f, &mut s, &r, 4, &ev, &forged.proof(2, 1, 1)),
            "bad signature",
        );
        let mut split = Ledger::new(&events, &[&vs[0], &vs[1], &vs[2]]);
        split.envelopes[2] = envelope(&vs[2], 501, &stellar_value_bytes(&[0x77; 32]));
        refused(
            admit(&f, &mut s, &r, 4, &ev, &split.proof(2, 1, 1)),
            "split values",
        );

        // The failed transaction, the path payment, the other event.
        refused(
            admit(&f, &mut s, &r, 4, &ev, &ledger.proof(1, 0, 1)),
            "failed transaction",
        );
        refused(
            admit(&f, &mut s, &r, 4, &ev, &ledger.proof(2, 0, 1)),
            "not an invocation",
        );
        refused(
            admit(&f, &mut s, &r, 4, &ev, &ledger.proof(2, 1, 0)),
            "another event",
        );

        // An event of another contract, an inflated event, tampered
        // results, a trailing byte.
        let foreign = transfer_event(&[0x99; 32], &encode_record(&move_record(&r, 4, 10)));
        let other = Ledger::new(&[noise_event(), foreign.clone()], &[&vs[0], &vs[1], &vs[2]]);
        refused(
            admit(&f, &mut s, &r, 4, &foreign, &other.proof(2, 1, 1)),
            "foreign contract",
        );
        refused(
            admit(
                &f,
                &mut s,
                &r,
                4,
                &event(&r, 4, 10_000),
                &ledger.proof(2, 1, 1),
            ),
            "inflated",
        );
        let mut tampered = Ledger::new(&events, &[&vs[0], &vs[1], &vs[2]]);
        tampered.results[40] ^= 1;
        refused(
            admit(&f, &mut s, &r, 4, &ev, &tampered.proof(2, 1, 1)),
            "tampered results",
        );
        let mut padded = ev.clone();
        padded.push(0);
        refused(
            admit(&f, &mut s, &r, 4, &padded, &ledger.proof(2, 1, 1)),
            "trailing byte",
        );

        admit(&f, &mut s, &r, 4, &ev, &ledger.proof(2, 1, 1)).unwrap();
    }
}

mod ton {
    use super::super::move_event::MoveTransfer;
    use super::super::stellar::encode_record;
    use super::super::ton::encode_message;
    use super::*;

    const CHAIN: &str = "ton";
    const CONTRACT: [u8; 32] = [0x8d; 32];

    fn setup() -> (RouteFramework, MemState, BridgeRoute) {
        let mut r = route(BridgeRouteAdapter::Contract, ChainFamily::Ton, CHAIN, 5);
        r.ramp = CONTRACT;
        r.light_client = Some(LightClientAnchor::TonKeyBlock {
            trusted_seqno: 7,
            trusted_root_hash: [0x31; 32],
        });
        r.validate().unwrap();
        let f = RouteFramework::new().with_all_light_clients();
        let s = MemState::with(std::slice::from_ref(&r));
        (f, s, r)
    }

    #[test]
    fn ton_sends_the_record_its_contract_executes() {
        let (f, mut s, r) = setup();
        let out = send(&f, &mut s, CHAIN, 600, vec![0x47; 32]);
        assert_eq!(
            out.bytes,
            encode_record(&MoveTransfer::outbound(&r, &out.message).unwrap())
        );
        assert_eq!(f.finality_depth(&r).unwrap(), 1);
    }

    #[test]
    fn ton_refuses_records_past_a_jetton_amount() {
        use super::super::canonical::Reader;
        use super::super::ton::{MAX_JETTON_AMOUNT, TonAdapter};
        let (_, _, r) = setup();
        let mut record = move_record(&r, 3, 10);
        record.amount = MAX_JETTON_AMOUNT;
        let body = encode_message(&CONTRACT, 41_000_002, &record);
        assert!(
            TonAdapter
                .decode_inbound(&r, &mut Reader::new(&body))
                .is_ok()
        );
        record.amount = MAX_JETTON_AMOUNT + 1;
        let body = encode_message(&CONTRACT, 41_000_002, &record);
        assert!(
            TonAdapter
                .decode_inbound(&r, &mut Reader::new(&body))
                .is_err()
        );
        assert!(
            TonAdapter
                .decode_outbound(&r, &mut Reader::new(&encode_record(&record)))
                .is_err()
        );
    }

    #[test]
    fn ton_admits_nothing_without_its_light_client_proof() {
        let (f, mut s, r) = setup();
        send(&f, &mut s, CHAIN, 1_000, vec![0x47; 32]);
        let body = encode_message(&CONTRACT, 41_000_002, &move_record(&r, 3, 10));
        // The committee's signatures alone admit nothing, and neither does a
        // proof the light client cannot check (it is not bootstrapped).
        let d = deliver(&r, &signers(), 3, 3, EXPIRY, &body, &[]);
        refused(
            f.admit_inbound(&mut s, BridgeRouteAdapter::Contract, CHAIN, &d),
            "no proof",
        );
        let d = deliver(&r, &signers(), 3, 3, EXPIRY, &body, &[1, 2, 3]);
        refused(
            f.admit_inbound(&mut s, BridgeRouteAdapter::Contract, CHAIN, &d),
            "not bootstrapped",
        );
        // A route without its light client is not a valid route.
        let mut bare = r.clone();
        bare.light_client = None;
        assert!(bare.validate().is_err());
    }

    /// A synthetic TON chain in the real layouts: a key block whose
    /// configuration holds three validators, a masterchain block naming the
    /// basechain shard block, and in it the bridge contract's transfer.
    mod chain {
        use std::sync::Arc;

        use ed25519_dalek::{Signer, SigningKey};

        use super::super::super::move_event::MoveTransfer;
        use super::super::super::ton_cell::{Cell, serialize_boc};
        use super::super::super::ton_light_client::{Finalization, MASTERCHAIN_SHARD};

        #[derive(Default)]
        pub struct B {
            bits: Vec<bool>,
            refs: Vec<Arc<Cell>>,
        }

        impl B {
            pub fn uint(mut self, v: u64, n: usize) -> Self {
                self.bits
                    .extend((0..n).rev().map(|i| i < 64 && v >> i & 1 == 1));
                self
            }
            pub fn bytes(mut self, b: &[u8]) -> Self {
                self.bits.extend(
                    b.iter()
                        .flat_map(|x| (0..8).rev().map(move |i| x >> i & 1 == 1)),
                );
                self
            }
            pub fn r(mut self, c: Arc<Cell>) -> Self {
                self.refs.push(c);
                self
            }
            pub fn done(self) -> Arc<Cell> {
                let mut data = vec![0u8; self.bits.len().div_ceil(8)];
                for (i, b) in self.bits.iter().enumerate() {
                    if *b {
                        data[i / 8] |= 0x80 >> (i % 8);
                    }
                }
                Cell::new(false, data, self.bits.len(), self.refs).unwrap()
            }
        }

        /// A one-entry dictionary node: the whole key as a long label.
        fn entry(key: u64, n: usize, value: B) -> B {
            let width = usize::BITS as usize - n.leading_zeros() as usize;
            let mut b = B::default()
                .uint(0b10, 2)
                .uint(n as u64, width)
                .uint(key, n);
            b.bits.extend(value.bits);
            b.refs.extend(value.refs);
            b
        }

        /// An empty `CurrencyCollection`.
        fn currency(b: B) -> B {
            b.uint(0, 4).uint(0, 1)
        }

        pub fn keys() -> Vec<SigningKey> {
            (1..=3u8)
                .map(|i| SigningKey::from_bytes(&[i; 32]))
                .collect()
        }

        fn info(
            seq_no: u32,
            not_master: bool,
            key_block: bool,
            workchain: i32,
            prev_key: u32,
            prev: Option<(u32, [u8; 32])>,
        ) -> Arc<Cell> {
            let mut b = B::default()
                .uint(0x9bc7_a987, 32)
                .uint(0, 32)
                .uint(u64::from(not_master), 1)
                .uint(0, 1)
                .uint(0, 4)
                .uint(u64::from(key_block), 1)
                .uint(0, 1)
                .uint(0, 8)
                .uint(u64::from(seq_no), 32)
                .uint(0, 32)
                .uint(0, 2)
                .uint(0, 6)
                .uint(workchain as u32 as u64, 32)
                .uint(MASTERCHAIN_SHARD, 64)
                .uint(0, 32 + 64 + 64 + 32 + 32 + 32)
                .uint(u64::from(prev_key), 32);
            if not_master {
                b = b.r(B::default().uint(0, 64).done());
            }
            let (pseq, proot) = prev.unwrap_or((seq_no.saturating_sub(1), [0x44; 32]));
            b.r(B::default()
                .uint(9, 64)
                .uint(u64::from(pseq), 32)
                .bytes(&proot)
                .bytes(&[0x45; 32])
                .done())
                .done()
        }

        fn block(info: Arc<Cell>, extra: Arc<Cell>) -> Arc<Cell> {
            let empty = B::default().done();
            B::default()
                .uint(0x11ef_55aa, 32)
                .uint(0, 32)
                .r(info)
                .r(empty.clone())
                .r(empty)
                .r(extra)
                .done()
        }

        fn extra(account_blocks: Arc<Cell>, mc: Option<Arc<Cell>>) -> Arc<Cell> {
            let empty = B::default().done();
            let mut b = B::default()
                .uint(0x4a33_f6fd, 32)
                .r(empty.clone())
                .r(empty)
                .r(account_blocks)
                .bytes(&[0; 64]);
            b = match mc {
                Some(m) => b.uint(1, 1).r(m),
                None => b.uint(0, 1),
            };
            b.done()
        }

        fn no_accounts() -> Arc<Cell> {
            B::default().uint(0, 1).uint(0, 4).uint(0, 1).done()
        }

        /// A key block whose configuration's validator set is `keys`.
        pub fn key_block(seq_no: u32, prev_key: u32, keys: &[SigningKey]) -> Arc<Cell> {
            assert_eq!(keys.len(), 3, "the builder writes three validators");
            // A dictionary of the entries 0, 1 and 2: a 14-bit zero label,
            // then a fork over {0, 1} and {2}.
            let descr = |k: &SigningKey| {
                B::default()
                    .uint(0x53, 8)
                    .uint(0x8e81_278a, 32)
                    .bytes(&k.verifying_key().to_bytes())
                    .uint(100, 64)
            };
            let leaf = |n: usize, key: u64, v: B| entry(key, n, v).done();
            let left = B::default()
                .uint(0, 2)
                .r(leaf(0, 0, descr(&keys[0])))
                .r(leaf(0, 0, descr(&keys[1])))
                .done();
            let right = leaf(1, 0, descr(&keys[2]));
            let list = B::default()
                .uint(0b10, 2)
                .uint(14, 5)
                .uint(0, 14)
                .r(left)
                .r(right)
                .done();
            let vset = B::default()
                .uint(0x12, 8)
                .uint(0, 64)
                .uint(keys.len() as u64, 16)
                .uint(keys.len() as u64, 16)
                .uint(300, 64)
                .uint(1, 1)
                .r(list)
                .done();
            let config = entry(34, 32, B::default().r(vset)).done();
            let mc = B::default()
                .uint(0xcca5, 16)
                .uint(1, 1)
                .uint(0, 1)
                .uint(0, 1);
            let mc = currency(currency(mc))
                .r(B::default().done())
                .bytes(&[0; 32])
                .r(config)
                .done();
            block(
                info(seq_no, false, true, -1, prev_key, None),
                extra(no_accounts(), Some(mc)),
            )
        }

        /// A shard block holding `account`'s transaction at `lt`, whose
        /// external message carries `record`.
        pub fn shard_block(
            seq_no: u32,
            account: &[u8; 32],
            lt: u64,
            record: &MoveTransfer,
        ) -> Arc<Cell> {
            let tail = B::default()
                .bytes(&record.recipient)
                .uint((record.amount >> 64) as u64, 64)
                .uint(record.amount as u64, 64)
                .done();
            let body = B::default()
                .uint(record.sequence, 64)
                .uint(record.source_selector, 64)
                .uint(record.dest_selector, 64)
                .bytes(&record.sender)
                .bytes(&record.token)
                .bytes(&record.endpoint)
                .r(tail)
                .done();
            shard_block_with(seq_no, account, lt, body)
        }

        /// A shard block whose one transaction of `account` sends `body` out.
        pub fn shard_block_with(
            seq_no: u32,
            account: &[u8; 32],
            lt: u64,
            body: Arc<Cell>,
        ) -> Arc<Cell> {
            let msg = B::default()
                .uint(0b11, 2)
                .uint(0b10, 2)
                .uint(0, 1)
                .uint(0, 8)
                .bytes(account)
                .uint(0, 2)
                .uint(lt + 1, 64)
                .uint(0, 32)
                .uint(0, 1)
                .uint(1, 1)
                .r(body)
                .done();
            let out_msgs = entry(0, 15, B::default().r(msg)).done();
            let msgs = B::default().uint(0, 1).uint(1, 1).r(out_msgs).done();
            let tx = B::default()
                .uint(0b0111, 4)
                .bytes(account)
                .uint(lt, 64)
                .r(msgs)
                .done();
            let txs = currency(B::default().uint(0b10, 2).uint(64, 7).uint(lt, 64)).r(tx);
            let mut acc = B::default().uint(0x5, 4).bytes(account);
            acc.bits.extend(txs.bits);
            acc.refs.extend(txs.refs);
            let leaf = {
                let mut b = currency(B::default().uint(0b10, 2).uint(256, 9).bytes(account));
                b.bits.extend(acc.bits);
                b.refs.extend(acc.refs);
                b.done()
            };
            let blocks = currency(B::default().uint(1, 1).r(leaf)).done();
            block(info(seq_no, true, false, 0, 0, None), extra(blocks, None))
        }

        /// A masterchain block naming `shard` as the basechain's shard.
        pub fn mc_block(
            seq_no: u32,
            prev_key: u32,
            shard_seq: u32,
            shard_root: [u8; 32],
        ) -> Arc<Cell> {
            let descr = B::default()
                .uint(0, 1)
                .uint(0xa, 4)
                .uint(u64::from(shard_seq), 32)
                .uint(0, 32 + 64 + 64)
                .bytes(&shard_root)
                .bytes(&[0; 32])
                .done();
            let hashes = entry(0, 32, B::default().r(descr)).done();
            let mc = B::default()
                .uint(0xcca5, 16)
                .uint(0, 1)
                .uint(1, 1)
                .r(hashes)
                .uint(0, 1);
            let mc = currency(currency(mc)).r(B::default().done()).done();
            block(
                info(seq_no, false, false, -1, prev_key, None),
                extra(no_accounts(), Some(mc)),
            )
        }

        /// The finalization of masterchain block `block` by `signers` of
        /// `keys`.
        pub fn finalize(
            block: &Arc<Cell>,
            seqno: u32,
            keys: &[SigningKey],
            signers: &[u16],
        ) -> Finalization {
            let mut candidate = 0xe8f9_bcdcu32.to_le_bytes().to_vec();
            candidate.extend_from_slice(&(-1i32).to_le_bytes());
            candidate.extend_from_slice(&MASTERCHAIN_SHARD.to_le_bytes());
            candidate.extend_from_slice(&seqno.to_le_bytes());
            candidate.extend_from_slice(&block.hash(0));
            candidate.extend_from_slice(&[0x66; 32]);
            candidate.extend_from_slice(&[0x77; 36]);
            let mut f = Finalization {
                session_id: [0x5e; 32],
                slot: 3,
                candidate,
                signatures: vec![],
            };
            let m = f.signed_message();
            f.signatures = signers
                .iter()
                .map(|i| (*i, keys[*i as usize].sign(&m).to_bytes()))
                .collect();
            f
        }

        pub fn boc(c: &Arc<Cell>) -> Vec<u8> {
            serialize_boc(c)
        }
    }

    #[test]
    fn ton_admits_a_transfer_its_light_client_proves() {
        use super::super::ton_light_client::{account_out_message, relay};
        use chain::*;

        let keys = keys();
        let key = key_block(100, 90, &keys);
        let mut r = route(BridgeRouteAdapter::Contract, ChainFamily::Ton, CHAIN, 5);
        r.ramp = CONTRACT;
        r.light_client = Some(LightClientAnchor::TonKeyBlock {
            trusted_seqno: 100,
            trusted_root_hash: key.hash(0),
        });
        r.validate().unwrap();
        let f = RouteFramework::new().with_all_light_clients();
        let mut s = MemState::with(std::slice::from_ref(&r));
        f.advance_light_client(
            &mut s,
            BridgeRouteAdapter::Contract,
            CHAIN,
            &relay::bootstrap(&boc(&key)).unwrap(),
        )
        .unwrap();
        send(&f, &mut s, CHAIN, 1_000, vec![0x47; 32]);

        let record = move_record(&r, 4, 250);
        let lt = 55_000;
        let shard = shard_block(700, &CONTRACT, lt, &record);
        assert!(account_out_message(&shard, &CONTRACT, lt, 0).is_ok());
        let mc = mc_block(105, 100, 700, shard.hash(0));
        let body = encode_message(&CONTRACT, lt + 1, &record);
        let prove = |signers: &[u16]| {
            relay::message_proof(
                &finalize(&mc, 105, &keys, signers),
                &boc(&mc),
                &[boc(&shard)],
                &CONTRACT,
                lt,
                0,
            )
            .unwrap()
        };

        // One of three validators is not a two-thirds majority.
        let d = deliver(&r, &signers(), 3, 4, EXPIRY, &body, &prove(&[1]));
        refused(
            f.admit_inbound(&mut s, BridgeRouteAdapter::Contract, CHAIN, &d),
            "one validator",
        );
        // The proof of another body.
        let other = encode_message(&CONTRACT, lt + 1, &move_record(&r, 4, 251));
        let d = deliver(&r, &signers(), 3, 4, EXPIRY, &other, &prove(&[0, 1, 2]));
        refused(
            f.admit_inbound(&mut s, BridgeRouteAdapter::Contract, CHAIN, &d),
            "another body",
        );

        // Two of three equal weights is two thirds, not more.
        let d = deliver(&r, &signers(), 3, 4, EXPIRY, &body, &prove(&[0, 2]));
        refused(
            f.admit_inbound(&mut s, BridgeRouteAdapter::Contract, CHAIN, &d),
            "two of three",
        );

        let d = deliver(&r, &signers(), 3, 4, EXPIRY, &body, &prove(&[0, 1, 2]));
        let admitted = f
            .admit_inbound(&mut s, BridgeRouteAdapter::Contract, CHAIN, &d)
            .unwrap();
        assert_eq!(admitted.message.amount, 250);
        assert_eq!(read_supply(&s, &r).bridged, 750);
    }

    #[test]
    fn a_ton_lock_log_is_proven_only_from_the_routes_lock() {
        use super::super::ton_light_client::relay;
        use chain::*;

        const LOCK: [u8; 32] = [0x6c; 32];
        let keys = keys();
        let key = key_block(100, 90, &keys);
        let mut r = route(BridgeRouteAdapter::Contract, ChainFamily::Ton, CHAIN, 5);
        r.ramp = CONTRACT;
        r.settlement_lock = Some(LOCK);
        r.light_client = Some(LightClientAnchor::TonKeyBlock {
            trusted_seqno: 100,
            trusted_root_hash: key.hash(0),
        });
        r.validate().unwrap();
        let f = RouteFramework::new().with_all_light_clients();
        let mut s = MemState::with(std::slice::from_ref(&r));
        f.advance_light_client(
            &mut s,
            BridgeRouteAdapter::Contract,
            CHAIN,
            &relay::bootstrap(&boc(&key)).unwrap(),
        )
        .unwrap();

        let want = crate::route::receipt_proof::LockEvent {
            plan_id: [1; 32],
            leg_id: [2; 32],
            index: 1,
            payer: [3; 32],
            recipient: [4; 32],
            asset: [0; 32],
            amount: 3_000_000_000,
            escape_at_ms: 1_801_209_600_000,
        };
        let log = |tag: u64, account: &[u8; 32], signers: &[u16]| -> Vec<u8> {
            // 3_000_000_000 nanotons in coins form: 4 bytes.
            let tail = B::default()
                .bytes(&want.recipient)
                .uint(4, 4)
                .uint(3_000_000_000, 32)
                .uint(1_801_209_600, 64)
                .bytes(&want.asset)
                .done();
            let body = B::default()
                .uint(tag, 8)
                .bytes(&want.plan_id)
                .bytes(&want.leg_id)
                .uint(1, 8)
                .bytes(&want.payer)
                .r(tail)
                .done();
            let lt = 77_000;
            let shard = shard_block_with(700, account, lt, body);
            let mc = mc_block(105, 100, 700, shard.hash(0));
            relay::message_proof(
                &finalize(&mc, 105, &keys, signers),
                &boc(&mc),
                &[boc(&shard)],
                account,
                lt,
                0,
            )
            .unwrap()
        };
        let mut prove = |p: Vec<u8>| f.prove_lock(&mut s, BridgeRouteAdapter::Contract, CHAIN, &p);
        let (got, proven, _) = prove(log(0x61, &LOCK, &[0, 1, 2])).unwrap();
        assert!(proven);
        assert_eq!(
            got,
            crate::route::receipt_proof::LockRecord::Locked(want.clone())
        );
        assert!(prove(log(0x61, &LOCK, &[0, 2])).is_err(), "two of three");
        assert!(
            prove(log(0x62, &LOCK, &[0, 1, 2])).is_err(),
            "a Released log"
        );
        assert!(
            prove(log(0x61, &CONTRACT, &[0, 1, 2])).is_err(),
            "another account"
        );
    }

    #[test]
    fn a_ton_lock_checkpoint_is_proven_from_the_routes_lock() {
        use super::super::ton_light_client::relay;
        use chain::*;

        const LOCK: [u8; 32] = [0x6c; 32];
        let keys = keys();
        let key = key_block(100, 90, &keys);
        let mut r = route(BridgeRouteAdapter::Contract, ChainFamily::Ton, CHAIN, 5);
        r.ramp = CONTRACT;
        r.settlement_lock = Some(LOCK);
        r.light_client = Some(LightClientAnchor::TonKeyBlock {
            trusted_seqno: 100,
            trusted_root_hash: key.hash(0),
        });
        r.validate().unwrap();
        let f = RouteFramework::new().with_all_light_clients();
        let mut s = MemState::with(std::slice::from_ref(&r));
        f.advance_light_client(
            &mut s,
            BridgeRouteAdapter::Contract,
            CHAIN,
            &relay::bootstrap(&boc(&key)).unwrap(),
        )
        .unwrap();

        // The lock's Accumulator log after the shared reconciliation sequence.
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../sdk/fixtures/settlement_lock/ton_accumulator_log.hex"
        );
        let raw = hex::decode(std::fs::read_to_string(path).unwrap().trim()).unwrap();
        let count = u64::from_be_bytes(raw[1..9].try_into().unwrap());
        let acc: [u8; 32] = raw[9..].try_into().unwrap();
        let log = |tag: u64, extra: bool, account: &[u8; 32]| -> Vec<u8> {
            let mut b = B::default().uint(tag, 8).uint(count, 64).bytes(&acc);
            if extra {
                b = b.uint(0, 1);
            }
            let lt = 77_000;
            let shard = shard_block_with(700, account, lt, b.done());
            let mc = mc_block(105, 100, 700, shard.hash(0));
            relay::message_proof(
                &finalize(&mc, 105, &keys, &[0, 1, 2]),
                &boc(&mc),
                &[boc(&shard)],
                account,
                lt,
                0,
            )
            .unwrap()
        };
        let mut prove = |p: Vec<u8>| f.prove_lock(&mut s, BridgeRouteAdapter::Contract, CHAIN, &p);
        let (got, proven, _) = prove(log(raw[0].into(), false, &LOCK)).unwrap();
        assert!(proven);
        let mut want = [0u8; 32];
        want.copy_from_slice(
            &hex::decode("375111922b0be21f25ad54b505467229080fd12340e5b01e4f56220cb3ecb58a")
                .unwrap(),
        );
        let cp = crate::route::receipt_proof::LockCheckpoint {
            count: 6,
            acc: want,
        };
        assert_eq!(got, crate::route::receipt_proof::LockRecord::Checkpoint(cp));
        assert!(prove(log(0x63, false, &LOCK)).is_err(), "another tag");
        assert!(prove(log(0x64, true, &LOCK)).is_err(), "a longer log");
        assert!(
            prove(log(0x64, false, &CONTRACT)).is_err(),
            "another account"
        );
    }
}
