//! Bridge transfers and token-ledger operations as consensus transactions,
//! driven through `ledger::execute_in_block`, the path the node's block loop
//! uses.
//!
//! Each block ends with the ledger audit (stored balances sum to stored total
//! supply) and the block rule, so a bridge credit or a token operation that
//! created or destroyed TNZO would fail here. The determinism test runs the
//! same transactions over two stores and compares every committed entry.

use std::sync::Arc;

use k256::ecdsa::signature::hazmat::PrehashSigner;
use sha2::{Digest, Sha256};
use tenzro_bridge::route::attestation::{Delivery, MemberSignature, attestation_digest};
use tenzro_bridge::route::evm::{EVM_CHAINS, Evm2AnyMessage, Evm2AnyTokenTransfer, RampHeader};
use tenzro_storage::{CF_ACCOUNTS, CF_STATE, KvStore, MemoryStore};
use tenzro_types::bridge_route::{
    BridgeRoute, BridgeRouteAdapter, CcipLane, CcipLaneVersion, ChainFamily, LaneRateLimit,
    MintRateLimit, NetworkMintLimits, NetworkOutflowLimits, OutflowCap, VerifierMember,
    VerifierQuorum,
};
use tenzro_types::bridge_transfer::BridgeOp;
use tenzro_types::token_op::TokenOp;
use tenzro_vm::ledger::{
    self, BlockFees, TxOutcome, block_base_fee, execute_in_block, verify_block,
};
use tenzro_vm::native::bridge::{deposit_asset, route_vault};
use tenzro_vm::native::{SELECTOR_BRIDGE, SELECTOR_TOKEN};
use tenzro_vm::{MultiVmRuntime, StateAdapter, VmConfig, VmState, VmTransaction, VmType};

const ONE_TNZO: u128 = 1_000_000_000_000_000_000;
const GAS_PRICE: u128 = 20_000_000_000;
const CHAIN_ID: u64 = 1337;
const LOCAL_SELECTOR: u64 = 7_777;
const NOW_MS: i64 = 1_800_000_000_000;
const ENDPOINT: [u8; 32] = [0xCD; 32];
const POOL: [u8; 20] = [0x51; 20];
const ON_RAMP: [u8; 20] = [0x52; 20];
const REMOTE_TOKEN: [u8; 20] = [0x53; 20];

fn funded_store(balances: &[(&[u8], u128)]) -> Arc<dyn KvStore> {
    let store: Arc<dyn KvStore> = Arc::new(MemoryStore::new());
    let mut supply = 0u128;
    {
        let mut state = StateAdapter::with_storage(store.clone());
        for (addr, amount) in balances {
            state.set_balance(addr, *amount);
            supply += amount;
        }
        state.commit().unwrap();
    }
    store
        .put(CF_ACCOUNTS, b"total_supply", &supply.to_le_bytes())
        .unwrap();
    store
}

fn assert_ledger_balances(store: &Arc<dyn KvStore>) {
    let mut sum = 0u128;
    for (_, v) in store.scan_prefix(CF_ACCOUNTS, b"balance:").unwrap() {
        sum += u128::from_le_bytes(v.as_slice().try_into().unwrap());
    }
    let supply = store
        .get(CF_ACCOUNTS, b"total_supply")
        .unwrap()
        .map(|b| u128::from_le_bytes(b.as_slice().try_into().unwrap()))
        .unwrap_or(0);
    assert_eq!(sum, supply, "balances != total supply");
}

struct Chain {
    rt: MultiVmRuntime,
    store: Arc<dyn KvStore>,
    nonces: std::collections::HashMap<Vec<u8>, u64>,
    /// The next block's timestamp.
    now_ms: i64,
}

impl Chain {
    async fn new(balances: &[(&[u8], u128)]) -> Self {
        Self {
            rt: MultiVmRuntime::new(VmConfig::default()).await.unwrap(),
            store: funded_store(balances),
            nonces: Default::default(),
            now_ms: NOW_MS,
        }
    }

    fn state(&self) -> StateAdapter {
        StateAdapter::with_storage(self.store.clone())
    }

    /// Run one transaction in its own block; `Ok(output)` when it applied.
    async fn send(
        &mut self,
        from: &[u8],
        selector: [u8; 4],
        payload: Vec<u8>,
    ) -> Result<serde_json::Value, String> {
        let nonce = *self.nonces.entry(from.to_vec()).or_default();
        let mut data = selector.to_vec();
        data.extend(payload);
        let tx = VmTransaction::new(
            from.to_vec(),
            None,
            0,
            data,
            5_000_000,
            GAS_PRICE,
            nonce,
            VmType::Tenzro,
            CHAIN_ID,
        )
        .with_block_timestamp_ms(self.now_ms);
        let mut state = self.state();
        let base = block_base_fee(&state);
        let mut fees = BlockFees::default();
        let outcome = execute_in_block(&self.rt, &mut state, &tx, base, &mut fees).await;
        let result = match outcome {
            TxOutcome::Applied { result, .. } => {
                *self.nonces.get_mut(from).unwrap() += 1;
                Ok(serde_json::from_slice(&result.output).unwrap_or(serde_json::Value::Null))
            }
            TxOutcome::Reverted { reason, .. } => {
                *self.nonces.get_mut(from).unwrap() += 1;
                Err(reason)
            }
            TxOutcome::Rejected(e) => Err(e.to_string()),
        };
        ledger::settle_block(&mut state, &fees);
        verify_block(&state).expect("block conserves value");
        state.commit().unwrap();
        assert_ledger_balances(&self.store);
        result
    }

    async fn bridge(&mut self, from: &[u8], op: BridgeOp) -> Result<serde_json::Value, String> {
        self.send(from, SELECTOR_BRIDGE, serde_json::to_vec(&op).unwrap())
            .await
    }

    async fn token(&mut self, from: &[u8], op: TokenOp) -> Result<serde_json::Value, String> {
        self.send(from, SELECTOR_TOKEN, serde_json::to_vec(&op).unwrap())
            .await
    }

    fn balance(&self, a: &[u8]) -> u128 {
        self.state().get_balance(a)
    }

    /// Write `route` where an enacted `SetBridgeRoute` proposal writes it,
    /// with the network-wide mint limits genesis sets.
    fn install(&self, route: &BridgeRoute) {
        let mut state = self.state();
        state.set_storage(
            &tenzro_vm::native::GOVERNED_STATE_ADDRESS,
            route.storage_key().as_bytes(),
            serde_json::to_vec(route).unwrap(),
        );
        let wide = MintRateLimit {
            per_mint: 1_000_000 * ONE_TNZO,
            per_epoch: 1_000_000 * ONE_TNZO,
        };
        state.set_storage(
            &tenzro_vm::native::SYSTEM_ADDRESS,
            tenzro_vm::native::BRIDGE_MINT_LIMITS_KEY.as_bytes(),
            serde_json::to_vec(&NetworkMintLimits {
                proven: wide,
                attested: wide,
                classical: wide,
            })
            .unwrap(),
        );
        state.commit().unwrap();
        self.set_outflow(1_000_000 * ONE_TNZO);
    }

    /// Set the network-wide outflow caps: `tnzo` on TNZO, the same on every
    /// other unit the tests move.
    fn set_outflow(&self, tnzo: u128) {
        let mut state = self.state();
        let caps = ["TNZO", "USDC", "BTC"]
            .map(|unit| OutflowCap {
                unit: unit.into(),
                per_epoch: tnzo,
            })
            .to_vec();
        state.set_storage(
            &tenzro_vm::native::SYSTEM_ADDRESS,
            tenzro_vm::native::BRIDGE_OUTFLOW_LIMITS_KEY.as_bytes(),
            serde_json::to_vec(&NetworkOutflowLimits { caps }).unwrap(),
        );
        state.commit().unwrap();
    }

    /// Seat `addr` as a protocol guardian for a year.
    fn seat_guardian(&self, addr: &[u8]) {
        use tenzro_vm::governance::{GuardianRole, GuardianSeat, SeatKeyRoot};
        let mut state = self.state();
        let seat = GuardianSeat {
            did: "did:tenzro:human:exit-test".into(),
            role: GuardianRole::Protocol,
            term_ends_ms: NOW_MS + 365 * 24 * 60 * 60 * 1000,
            key_root: SeatKeyRoot::Device {
                credential_id: "exit-test".into(),
            },
        };
        tenzro_vm::native::guardian::write_seat(&mut state, addr, Some(&seat), &mut Vec::new());
        state.commit().unwrap();
    }

    /// Record a proven fault of `route`'s committee now, as an equivocation
    /// report does.
    fn note_committee_fault(&self, route: &BridgeRoute) {
        let mut state = self.state();
        state.set_storage(
            &tenzro_vm::native::SYSTEM_ADDRESS,
            tenzro_vm::native::bridge_committee::fault_key(&route.storage_key()).as_bytes(),
            serde_json::to_vec(&self.now_ms).unwrap(),
        );
        state.commit().unwrap();
    }
}

fn pad(a: &[u8; 20]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(a);
    w
}

fn member_key(seed: u8) -> k256::ecdsa::SigningKey {
    let mut b = [0u8; 32];
    b[0] = 0x21;
    b[31] = seed;
    k256::ecdsa::SigningKey::from_bytes((&b).into()).unwrap()
}

fn member_address(sk: &k256::ecdsa::SigningKey) -> [u8; 20] {
    let point = sk.verifying_key().to_sec1_point(false);
    let h = tenzro_crypto::hash::keccak256(&point.as_bytes()[1..]);
    h.as_bytes()[12..].try_into().unwrap()
}

fn sign(sk: &k256::ecdsa::SigningKey, digest: &[u8; 32]) -> MemberSignature {
    let (sig, rec): (k256::ecdsa::Signature, k256::ecdsa::RecoveryId) =
        sk.sign_prehash(digest).unwrap();
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(&sig.to_bytes());
    out[64] = rec.to_byte();
    (member_address(sk), out)
}

fn sign_pq(
    sk: &k256::ecdsa::SigningKey,
    digest: &[u8; 32],
) -> tenzro_bridge::route::attestation::PqMemberSignature {
    tenzro_bridge::route::attestation::testing::sign_leg(&sk.to_bytes(), member_address(sk), digest)
}

fn quorum(seed_base: u8, label: &str) -> (Vec<k256::ecdsa::SigningKey>, VerifierQuorum) {
    let keys: Vec<_> = (0..5).map(|i| member_key(seed_base + i)).collect();
    let q = VerifierQuorum {
        set_index: 0,
        size: keys.len() as u32,
        members: keys
            .iter()
            .enumerate()
            .map(|(i, k)| VerifierMember {
                address: member_address(k),
                pq_public_key: tenzro_bridge::route::attestation::testing::pq_key(&k.to_bytes()).verifying_key_bytes().to_vec(),
                operator: format!("{label}-op-{i}"),
                rpc_provider: format!("{label}-rpc-{i}"),
            })
            .collect(),
        threshold: 3,
    };
    (keys, q)
}

struct Committees {
    verifiers: Vec<k256::ecdsa::SigningKey>,
    blessing: Vec<k256::ecdsa::SigningKey>,
}

/// A CCIP route from Ethereum with a five-member committee and an
/// independent five-member blessing committee, both at threshold three.
fn ccip_route() -> (BridgeRoute, Committees) {
    let (verifiers, vq) = quorum(1, "verifier");
    let (blessing, bq) = quorum(40, "blessing");
    let ethereum = EVM_CHAINS.iter().find(|c| c.name == "ethereum").unwrap();
    let route = BridgeRoute {
        adapter: BridgeRouteAdapter::Ccip,
        family: ChainFamily::Evm,
        source_chain: "ethereum".into(),
        source_chain_id: ethereum.selector,
        local_selector: LOCAL_SELECTOR,
        peer: pad(&POOL),
        ramp: pad(&ON_RAMP),
        local_endpoint: ENDPOINT,
        remote_token: pad(&REMOTE_TOKEN),
        verifiers: vq,
        blessing: Some(bq),
        light_client: None,
        mint_limit: MintRateLimit {
            per_mint: 10_000,
            per_epoch: 10_000,
        },
        ibc: None,
        settlement_lock: None,
        native_asset: None,
        assets: Vec::new(),
        outflow: LaneRateLimit {
            capacity: 10_000,
            rate: 100,
        },
        lane_limits: Some(CcipLane {
            version: CcipLaneVersion::V1_6,
            off_ramp: [0u8; 20],
            ccv_and_executor_hash: [0u8; 32],
            inbound: LaneRateLimit {
                capacity: 10_000,
                rate: 100,
            },
        }),
    };
    route.validate().unwrap();
    (
        route,
        Committees {
            verifiers,
            blessing,
        },
    )
}

/// An Ethereum-side EVM2Any transfer of `amount` to `receiver`.
fn evm_body(route: &BridgeRoute, seq: u64, receiver: &[u8; 32], amount: u128) -> Vec<u8> {
    evm_body_from(route, seq, receiver, amount, POOL, ENDPOINT.to_vec())
}

fn evm_body_from(
    route: &BridgeRoute,
    seq: u64,
    receiver: &[u8; 32],
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
        receiver: receiver.to_vec(),
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

/// A delivery of `body` with nonce `nonce`, signed by the first `signers`
/// members of each committee.
fn deliver(
    route: &BridgeRoute,
    keys: &Committees,
    signers: usize,
    nonce: u64,
    body: Vec<u8>,
) -> Delivery {
    let mut d = Delivery {
        dest_chain_id: CHAIN_ID,
        nonce,
        expiry_ms: NOW_MS + 60_000,
        body,
        proof: vec![],
        committee: vec![],
        committee_pq: vec![],
        blessing: vec![],
        blessing_pq: vec![],
    };
    let digest = attestation_digest(route, &d);
    d.committee = keys
        .verifiers
        .iter()
        .take(signers)
        .map(|k| sign(k, &digest))
        .collect();
    d.blessing = keys
        .blessing
        .iter()
        .take(signers)
        .map(|k| sign(k, &digest))
        .collect();
    d.committee_pq = keys.verifiers.iter().take(signers).map(|k| sign_pq(k, &digest)).collect();
    d.blessing_pq = keys.blessing.iter().take(signers).map(|k| sign_pq(k, &digest)).collect();
    d
}

fn inbound(d: &Delivery) -> BridgeOp {
    BridgeOp::Inbound {
        adapter: BridgeRouteAdapter::Ccip,
        source_chain: "ethereum".into(),
        delivery: d.encode(),
    }
}

fn outbound(amount: u128) -> BridgeOp {
    BridgeOp::Outbound {
        target_chain: "ethereum".into(),
        recipient: vec![0x12; 20],
        amount,
        asset: None,
    }
}

#[tokio::test]
async fn an_outbound_transfer_locks_the_senders_tnzo_in_the_route_vault() {
    let user = [0xA1u8; 32];
    let mut chain = Chain::new(&[(&user, 10 * ONE_TNZO)]).await;
    let (route, _) = ccip_route();

    // No governed route yet.
    assert!(chain.bridge(&user, outbound(600)).await.is_err());
    chain.install(&route);

    // Over the route's per-mint cap: refused, and nothing moves.
    let err = chain.bridge(&user, outbound(20_000)).await.unwrap_err();
    assert!(err.contains("cap"), "{err}");
    assert_eq!(chain.balance(&route_vault(&route)), 0);

    let before = chain.balance(&user);
    let out = chain.bridge(&user, outbound(600)).await.unwrap();
    assert_eq!(out["sequence"], 1, "{out}");
    assert_eq!(out["supply"]["locked"], "600", "{out}");
    assert_eq!(chain.balance(&route_vault(&route)), 600);
    let fee = before - chain.balance(&user) - 600;
    assert!(fee > 0);

    // Each send is its own sequence.
    let out = chain.bridge(&user, outbound(100)).await.unwrap();
    assert_eq!(out["sequence"], 2, "{out}");
    assert_eq!(chain.balance(&route_vault(&route)), 700);
}

/// A route vault holding less than the route's supply record says is locked
/// freezes the bridge at the end of the first block that moves value through
/// it: the next transfer is refused and the vault is not drained further,
/// while the rest of the ledger goes on.
#[tokio::test]
async fn a_route_vault_short_of_its_locked_supply_freezes_the_bridge_only() {
    use tenzro_vm::invariant_monitor::{GuardedModule, frozen};
    let user = [0xA7u8; 32];
    let thief = [0xA8u8; 32];
    let mut chain = Chain::new(&[(&user, 10 * ONE_TNZO)]).await;
    let (route, _) = ccip_route();
    chain.install(&route);
    let vault = route_vault(&route);
    chain.bridge(&user, outbound(600)).await.unwrap();
    assert_eq!(chain.balance(&vault), 600);

    // A planted bug moves 300 out of the route vault without the supply
    // record changing. Supply is conserved, so the ledger audit passes.
    {
        let mut state = chain.state();
        state.set_balance(&vault, 300);
        state.set_balance(&thief, 300);
        state.commit().unwrap();
    }

    // The next transfer through the route applies, and its block ends with
    // the bridge frozen: 400 held against 700 locked.
    chain.bridge(&user, outbound(100)).await.unwrap();
    let freeze = frozen(&chain.state(), GuardedModule::Bridge).expect("bridge frozen");
    assert_eq!((freeze.held, freeze.owed), (400, 700));
    let err = chain.bridge(&user, outbound(100)).await.unwrap_err();
    assert!(err.contains("bridge is frozen"), "{err}");
    assert_eq!(chain.balance(&vault), 400);
    for m in [
        GuardedModule::Staking,
        GuardedModule::Escrow,
        GuardedModule::PaymentChannel,
    ] {
        assert!(frozen(&chain.state(), m).is_none(), "{}", m.name());
    }
}

#[tokio::test]
async fn an_exit_over_the_threshold_waits_and_a_guardian_may_cancel_it_until_released() {
    use tenzro_vm::governance::DEFAULT_BRIDGE_EXIT_DELAY_MS;
    let user = [0xC1u8; 32];
    let guardian = [0xC2u8; 32];
    let stranger = [0xC3u8; 32];
    let mut chain = Chain::new(&[
        (&user, 10 * ONE_TNZO),
        (&guardian, 10 * ONE_TNZO),
        (&stranger, 10 * ONE_TNZO),
    ])
    .await;
    let (route, _) = ccip_route();
    chain.install(&route);
    let escrow = tenzro_vm::native::bridge_exit::exit_escrow();

    // A quarter of the 10 000 outflow bucket leaves at once.
    let out = chain.bridge(&user, outbound(2_500)).await.unwrap();
    assert_eq!(out["sequence"], 1, "{out}");
    assert_eq!(chain.balance(&route_vault(&route)), 2_500);

    // More waits, its value held in escrow.
    let queued = chain.bridge(&user, outbound(3_000)).await.unwrap();
    let id = queued["id"].as_u64().unwrap();
    assert_eq!(chain.balance(&escrow), 3_000);
    assert_eq!(chain.balance(&route_vault(&route)), 2_500);
    let err = chain
        .bridge(&stranger, BridgeOp::ReleaseExit { id })
        .await
        .unwrap_err();
    assert!(err.contains("may be released"), "{err}");
    assert!(
        chain
            .bridge(&stranger, BridgeOp::CancelExit { id })
            .await
            .is_err()
    );

    // A seated guardian cancels it during the delay; the value returns.
    chain.seat_guardian(&guardian);
    let before = chain.balance(&user);
    let out = chain
        .bridge(&guardian, BridgeOp::CancelExit { id })
        .await
        .unwrap();
    assert_eq!(out["by"], "guardian", "{out}");
    assert_eq!(chain.balance(&user), before + 3_000);
    assert_eq!(chain.balance(&escrow), 0);
    assert!(
        chain
            .bridge(&user, BridgeOp::CancelExit { id })
            .await
            .is_err()
    );

    // Queued again: after the delay the guardian no longer can, and anyone
    // releases it as an immediate exit.
    let id = chain.bridge(&user, outbound(3_000)).await.unwrap()["id"]
        .as_u64()
        .unwrap();
    chain.now_ms += DEFAULT_BRIDGE_EXIT_DELAY_MS as i64;
    assert!(
        chain
            .bridge(&guardian, BridgeOp::CancelExit { id })
            .await
            .is_err()
    );
    let out = chain
        .bridge(&stranger, BridgeOp::ReleaseExit { id })
        .await
        .unwrap();
    assert_eq!(out["sequence"], 2, "{out}");
    assert_eq!(out["exit_id"], id, "{out}");
    assert_eq!(chain.balance(&escrow), 0);
    assert_eq!(chain.balance(&route_vault(&route)), 5_500);
    assert!(
        chain
            .bridge(&stranger, BridgeOp::ReleaseExit { id })
            .await
            .is_err()
    );
}

/// A queued exit stays the sender's to cancel when its route is taken
/// away: the escrow names its token itself, so the value never needs the
/// route back.
#[tokio::test]
async fn a_queued_exit_is_refundable_after_its_route_is_removed() {
    let user = [0xC6u8; 32];
    let mut chain = Chain::new(&[(&user, 10 * ONE_TNZO)]).await;
    let (route, _) = ccip_route();
    chain.install(&route);
    chain.bridge(&user, outbound(2_500)).await.unwrap();
    let id = chain.bridge(&user, outbound(3_000)).await.unwrap()["id"]
        .as_u64()
        .unwrap();
    chain.state().set_storage(
        &tenzro_vm::native::GOVERNED_STATE_ADDRESS,
        route.storage_key().as_bytes(),
        Vec::new(),
    );
    let escrow = tenzro_vm::native::bridge_exit::exit_escrow();
    assert_eq!(chain.balance(&escrow), 3_000);
    chain
        .bridge(&user, BridgeOp::CancelExit { id })
        .await
        .expect("the sender cancels without the route");
    assert_eq!(chain.balance(&escrow), 0, "the escrow paid the sender back");
}

#[tokio::test]
async fn a_committee_fault_lets_anyone_cancel_a_queued_exit_and_blocks_its_release() {
    use tenzro_vm::governance::DEFAULT_BRIDGE_EXIT_DELAY_MS;
    let user = [0xC4u8; 32];
    let stranger = [0xC5u8; 32];
    let mut chain = Chain::new(&[(&user, 10 * ONE_TNZO), (&stranger, 10 * ONE_TNZO)]).await;
    let (route, _) = ccip_route();
    chain.install(&route);
    let id = chain.bridge(&user, outbound(4_000)).await.unwrap()["id"]
        .as_u64()
        .unwrap();
    chain.now_ms += 1;
    chain.note_committee_fault(&route);
    chain.now_ms += DEFAULT_BRIDGE_EXIT_DELAY_MS as i64;
    let err = chain
        .bridge(&stranger, BridgeOp::ReleaseExit { id })
        .await
        .unwrap_err();
    assert!(err.contains("fault"), "{err}");
    let before = chain.balance(&user);
    let out = chain
        .bridge(&stranger, BridgeOp::CancelExit { id })
        .await
        .unwrap();
    assert_eq!(out["by"], "committee_fault", "{out}");
    assert_eq!(chain.balance(&user), before + 4_000);
}

#[tokio::test]
async fn exits_over_the_network_outflow_cap_queue_and_leave_when_an_epoch_has_room() {
    let user = [0xC6u8; 32];
    let stranger = [0xC7u8; 32];
    let mut chain = Chain::new(&[(&user, 10 * ONE_TNZO), (&stranger, 10 * ONE_TNZO)]).await;
    let (route, _) = ccip_route();
    chain.install(&route);
    chain.set_outflow(1_000);
    let escrow = tenzro_vm::native::bridge_exit::exit_escrow();
    {
        let mut state = chain.state();
        tenzro_vm::native::set_genesis_param(
            &mut state,
            tenzro_vm::native::security::QUEUE_MAX_EPOCHS_PARAM,
            1,
        );
        state.commit().unwrap();
    }
    chain.bridge(&user, outbound(600)).await.unwrap();
    // Over what the cap has left this epoch: queued, not refused.
    let queued = chain.bridge(&user, outbound(600)).await.unwrap();
    let id = queued["id"].as_u64().unwrap();
    assert_eq!(queued["unit"], "TNZO", "{queued}");
    assert_eq!(chain.balance(&escrow), 600);
    // What fits still leaves at once.
    chain.bridge(&user, outbound(400)).await.unwrap();
    assert_eq!(chain.balance(&route_vault(&route)), 1_000);
    // Nothing is left this epoch, so the queued exit cannot leave yet.
    let err = chain
        .bridge(&stranger, BridgeOp::ReleaseExit { id })
        .await
        .unwrap_err();
    assert!(err.contains("outflow cap"), "{err}");
    // The queue holds at most one epoch of the cap here.
    let err = chain.bridge(&user, outbound(401)).await.unwrap_err();
    assert!(err.contains("exit queue"), "{err}");
    let second = chain.bridge(&user, outbound(400)).await.unwrap()["id"]
        .as_u64()
        .unwrap();
    assert_eq!(
        tenzro_vm::native::bridge_exit::queued(&chain.state(), "TNZO"),
        1_000
    );
    // The next epoch has room: anyone releases the first.
    {
        let mut state = chain.state();
        tenzro_vm::native::rewards::begin_block(
            &mut state,
            1,
            &tenzro_types::primitives::Address::zero(),
            chain.now_ms,
        )
        .unwrap();
        state.commit().unwrap();
    }
    let out = chain
        .bridge(&stranger, BridgeOp::ReleaseExit { id })
        .await
        .unwrap();
    assert_eq!(out["exit_id"], id, "{out}");
    assert_eq!(chain.balance(&route_vault(&route)), 1_600);
    // The sender may still withdraw the other.
    chain
        .bridge(&user, BridgeOp::CancelExit { id: second })
        .await
        .unwrap();
    assert_eq!(chain.balance(&escrow), 0);
    assert_eq!(
        tenzro_vm::native::bridge_exit::queued(&chain.state(), "TNZO"),
        0
    );

    // A unit no cap names cannot leave at all.
    let mut state = chain.state();
    state.set_storage(
        &tenzro_vm::native::SYSTEM_ADDRESS,
        tenzro_vm::native::BRIDGE_OUTFLOW_LIMITS_KEY.as_bytes(),
        serde_json::to_vec(&NetworkOutflowLimits {
            caps: vec![OutflowCap {
                unit: "USDC".into(),
                per_epoch: 1_000,
            }],
        })
        .unwrap(),
    );
    state.commit().unwrap();
    let err = chain.bridge(&user, outbound(1)).await.unwrap_err();
    assert!(err.contains("no network outflow cap names TNZO"), "{err}");
}

#[tokio::test]
async fn an_inbound_delivery_releases_locked_tnzo_once_within_quorum_and_supply() {
    let user = [0xB1u8; 32];
    let relayer = [0xB2u8; 32];
    let mut chain = Chain::new(&[(&user, 10 * ONE_TNZO), (&relayer, 10 * ONE_TNZO)]).await;
    let (route, keys) = ccip_route();
    chain.install(&route);
    chain.bridge(&user, outbound(600)).await.unwrap();
    let held = chain.balance(&user);

    // Below quorum.
    let weak = deliver(&route, &keys, 2, 1, evm_body(&route, 1, &user, 250));
    assert!(chain.bridge(&relayer, inbound(&weak)).await.is_err());
    // More than the route has outstanding on Ethereum.
    let over = deliver(&route, &keys, 3, 1, evm_body(&route, 1, &user, 601));
    assert!(chain.bridge(&relayer, inbound(&over)).await.is_err());
    // For another chain.
    let mut foreign = deliver(&route, &keys, 3, 2, evm_body(&route, 2, &user, 10));
    foreign.dest_chain_id = CHAIN_ID + 1;
    assert!(chain.bridge(&relayer, inbound(&foreign)).await.is_err());
    assert_eq!(chain.balance(&user), held);

    // A valid delivery credits the recipient it names, whoever relays it.
    let good = deliver(&route, &keys, 3, 1, evm_body(&route, 1, &user, 250));
    let out = chain.bridge(&relayer, inbound(&good)).await.unwrap();
    assert_eq!(out["supply"]["locked"], "350", "{out}");
    assert_eq!(chain.balance(&user), held + 250);
    assert_eq!(chain.balance(&route_vault(&route)), 350);

    // Replaying it.
    let err = chain.bridge(&relayer, inbound(&good)).await.unwrap_err();
    assert!(err.contains("already used"), "{err}");
    assert_eq!(chain.balance(&user), held + 250);
}

#[tokio::test]
async fn a_carried_stablecoin_is_issued_one_to_one_and_redeemed_from_its_vault() {
    use tenzro_types::bridge_route::{AssetLane, AssetTransfer, CarriedAsset};
    let user = [0xC1u8; 32];
    let relayer = [0xC2u8; 32];
    let mut chain = Chain::new(&[(&user, ONE_TNZO), (&relayer, 10 * ONE_TNZO)]).await;
    let (mut route, keys) = ccip_route();
    let bucket = LaneRateLimit {
        capacity: 10_000,
        rate: 100,
    };
    route.assets = vec![CarriedAsset {
        symbol: "USDC".into(),
        name: "USD Coin (bridged)".into(),
        decimals: 6,
        pool: pad(&[0x61; 20]),
        remote_token: pad(&[0x62; 20]),
        caip19: "eip155:1/erc20:0x6262626262626262626262626262626262626262".into(),
        transfer: AssetTransfer::LockAndMint,
        mint_limit: MintRateLimit {
            per_mint: 5_000,
            per_epoch: 10_000,
        },
        outflow: bucket,
        lane: Some(AssetLane { inbound: bucket }),
        max_outstanding: 8_000,
        enabled: true,
    }];
    route.validate().unwrap();
    chain.install(&route);
    let id = route.assets[0].representation_id();

    let body = evm_body_from(&route, 1, &user, 5_000, [0x61; 20], id.to_vec());
    let out = chain
        .bridge(&relayer, inbound(&deliver(&route, &keys, 3, 1, body)))
        .await
        .unwrap();
    assert_eq!(out["asset"], hex::encode(id), "{out}");
    assert_eq!(out["supply"]["locked"], "5000", "{out}");
    let state = chain.state();
    assert_eq!(tenzro_vm::token_ledger::balance(&state, &id, &user), 5_000);
    assert_eq!(
        chain.balance(&route_vault(&route)),
        0,
        "no TNZO moves for a carried asset"
    );

    // The vault backs at most 8_000.
    let body = evm_body_from(&route, 2, &user, 4_000, [0x61; 20], id.to_vec());
    let err = chain
        .bridge(&relayer, inbound(&deliver(&route, &keys, 3, 2, body)))
        .await
        .unwrap_err();
    assert!(err.contains("above its cap"), "{err}");

    // Redeeming burns the representation and queues the vault's release.
    let redeem = |amount: u128| BridgeOp::Outbound {
        target_chain: "ethereum".into(),
        recipient: vec![0x12; 20],
        amount,
        asset: Some("USDC".into()),
    };
    let out = chain.bridge(&user, redeem(2_000)).await.unwrap();
    assert_eq!(out["asset"], "USDC", "{out}");
    assert_eq!(out["supply"]["locked"], "3000", "{out}");
    let state = chain.state();
    assert_eq!(tenzro_vm::token_ledger::balance(&state, &id, &user), 3_000);
    assert_eq!(
        tenzro_vm::token_ledger::read_token(&state, &id)
            .unwrap()
            .total_supply,
        3_000
    );
    assert!(
        chain.bridge(&user, redeem(3_001)).await.is_err(),
        "more than the vault backs"
    );
}

#[tokio::test]
async fn an_attested_message_is_admitted_once_and_published() {
    let relayer = [0xC1u8; 32];
    let mut chain = Chain::new(&[(&relayer, 10 * ONE_TNZO)]).await;
    let (route, keys) = ccip_route();
    chain.install(&route);
    let d = deliver(&route, &keys, 3, 9, b"<Document/>".to_vec());
    let op = BridgeOp::AdmitMessage {
        adapter: BridgeRouteAdapter::Ccip,
        source_chain: "ethereum".into(),
        delivery: d.encode(),
    };
    let out = chain.bridge(&relayer, op.clone()).await.unwrap();
    assert_eq!(out["body"], hex::encode(b"<Document/>"), "{out}");
    assert!(
        chain.bridge(&relayer, op).await.is_err(),
        "a message nonce is spent once"
    );
}

/// Publishing a delivery through the public message operation must not take
/// it away from the native consumer it is meant for (an order's fill proof,
/// an agent account report, a settlement lock): anyone can copy a delivery
/// from the mempool and publish it first.
#[tokio::test]
async fn a_published_message_still_reaches_its_consumer_once() {
    use tenzro_vm::native::bridge::{VmRouteState, route_framework};

    let relayer = [0xC1u8; 32];
    let mut chain = Chain::new(&[(&relayer, 10 * ONE_TNZO)]).await;
    let (route, keys) = ccip_route();
    chain.install(&route);
    let d = deliver(&route, &keys, 3, 9, b"fill-proof".to_vec()).encode();
    let publish = BridgeOp::AdmitMessage {
        adapter: BridgeRouteAdapter::Ccip,
        source_chain: "ethereum".into(),
        delivery: d.clone(),
    };
    chain.bridge(&relayer, publish.clone()).await.unwrap();

    let consume = |chain: &Chain| {
        let mut state = chain.state();
        let out = {
            let mut view = VmRouteState::new(&mut state, CHAIN_ID, chain.now_ms, 0);
            route_framework().admit_message(&mut view, BridgeRouteAdapter::Ccip, "ethereum", &d)
        };
        state.commit().unwrap();
        out.map(|(_, body)| body).map_err(|e| e.to_string())
    };
    assert_eq!(consume(&chain).unwrap(), b"fill-proof".to_vec());
    assert!(
        consume(&chain).is_err(),
        "a consumer acts on a delivery once"
    );
    assert!(
        chain.bridge(&relayer, publish).await.is_err(),
        "a consumed delivery is not published again"
    );
}

#[tokio::test]
async fn a_bitcoin_deposit_proven_by_spv_issues_the_deposit_asset_once() {
    use tenzro_bridge::route::bitcoin::{
        BlockHeader, Deposit, Transaction, TxIn, TxOut, deposit_marker,
    };
    use tenzro_types::bridge_route::LightClientAnchor;

    const HEIGHT: u64 = 2016 * 400;
    let mine = |prev: [u8; 32], merkle_root: [u8; 32], time: u32| {
        let mut h = BlockHeader {
            version: 0x2000_0000,
            prev,
            merkle_root,
            time,
            bits: 0x207f_ffff,
            nonce: 0,
        };
        while h.hash()[31] >= 0x7f {
            h.nonce += 1;
        }
        h
    };
    // Deposits go to a 2-of-3 descriptor (the x coordinates of G, 2G, 3G).
    let x = |h: &str| -> [u8; 32] { hex::decode(h).unwrap().try_into().unwrap() };
    let descriptor = tenzro_bridge::route::bitcoin_spend::DepositDescriptor {
        signers: vec![
            x("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
            x("c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"),
            x("f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"),
        ],
        threshold: 2,
    };
    let script = descriptor.script_pubkey().unwrap();
    let account = [0xD1u8; 32];
    let relayer = [0xD2u8; 32];
    let tx = Transaction {
        version: 2,
        inputs: vec![TxIn {
            prevout: [0x33; 36],
            script_sig: vec![],
            sequence: u32::MAX,
        }],
        outputs: vec![
            TxOut {
                value: 75_000,
                script: script.clone(),
            },
            TxOut {
                value: 0,
                script: deposit_marker(&account),
            },
        ],
        lock_time: 0,
    }
    .encode();
    let deposit = Deposit {
        height: HEIGHT + 1,
        index: 0,
        tx,
    };
    let anchor = mine([0x01; 32], [0x02; 32], 1_700_000_000);
    let mut headers = vec![mine(anchor.hash(), deposit.txid(), 1_700_000_600)];
    for i in 0..5u32 {
        let prev = headers.last().unwrap().hash();
        headers.push(mine(prev, [i as u8; 32], 1_700_001_200 + i * 600));
    }

    let mut chain = Chain::new(&[(&relayer, 10 * ONE_TNZO), (&account, ONE_TNZO)]).await;
    let (verifiers, vq) = quorum(1, "verifier");
    let route = BridgeRoute {
        adapter: BridgeRouteAdapter::Deposit,
        family: ChainFamily::Bitcoin,
        source_chain: "bitcoin".into(),
        source_chain_id: 1,
        local_selector: LOCAL_SELECTOR,
        peer: Sha256::digest(&script).into(),
        ramp: [0x52; 32],
        local_endpoint: ENDPOINT,
        remote_token: [0x53; 32],
        verifiers: vq,
        blessing: None,
        light_client: Some(LightClientAnchor::BitcoinHeaders {
            trusted_height: HEIGHT,
            trusted_header_hash: anchor.hash(),
            confirmations: 6,
            signers: descriptor.signers.clone(),
            threshold: descriptor.threshold,
            fee_rate: 2,
        }),
        mint_limit: MintRateLimit {
            per_mint: 1_000_000,
            per_epoch: 1_000_000,
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
    };
    route.validate().unwrap();
    chain.install(&route);

    let lc = |update: Vec<u8>| BridgeOp::LightClientUpdate {
        adapter: BridgeRouteAdapter::Deposit,
        source_chain: "bitcoin".into(),
        update,
    };
    chain
        .bridge(&relayer, lc([vec![0], anchor.encode().to_vec()].concat()))
        .await
        .unwrap();
    let mut extend = vec![1u8];
    extend.extend_from_slice(&HEIGHT.to_be_bytes());
    extend.extend_from_slice(&(headers.len() as u16).to_be_bytes());
    for h in &headers {
        extend.extend_from_slice(&h.encode());
    }
    chain.bridge(&relayer, lc(extend)).await.unwrap();

    let delivery = |signers: usize| {
        let mut proof = (deposit.encode().len() as u32).to_be_bytes().to_vec();
        proof.extend_from_slice(&deposit.encode());
        proof.extend_from_slice(&headers[0].encode());
        proof.push(0);
        let mut d = Delivery {
            dest_chain_id: CHAIN_ID,
            nonce: deposit.sequence(),
            expiry_ms: NOW_MS + 60_000,
            body: deposit.encode(),
            proof,
            committee: vec![],
            committee_pq: vec![],
            blessing: vec![],
            blessing_pq: vec![],
        };
        let digest = attestation_digest(&route, &d);
        d.committee = verifiers
            .iter()
            .take(signers)
            .map(|k| sign(k, &digest))
            .collect();
        d.committee_pq = verifiers
            .iter()
            .take(signers)
            .map(|k| sign_pq(k, &digest))
            .collect();
        BridgeOp::Inbound {
            adapter: BridgeRouteAdapter::Deposit,
            source_chain: "bitcoin".into(),
            delivery: d.encode(),
        }
    };
    assert!(
        chain.bridge(&relayer, delivery(2)).await.is_err(),
        "below quorum"
    );

    let out = chain.bridge(&relayer, delivery(3)).await.unwrap();
    assert_eq!(out["supply"]["locked"], "75000", "{out}");
    let asset = deposit_asset(ChainFamily::Bitcoin).unwrap();
    assert_eq!(out["asset"], hex::encode(asset.token_id), "{out}");
    let state = chain.state();
    assert_eq!(
        tenzro_vm::token_ledger::balance(&state, &asset.token_id, &account),
        75_000
    );
    assert_eq!(
        tenzro_vm::token_ledger::read_token(&state, &asset.token_id)
            .unwrap()
            .total_supply,
        75_000
    );
    assert_eq!(
        chain.balance(&account),
        ONE_TNZO,
        "no TNZO is credited for a deposit"
    );

    assert!(
        chain
            .bridge(&relayer, delivery(3))
            .await
            .unwrap_err()
            .contains("already used")
    );
    let state = chain.state();
    assert_eq!(
        tenzro_vm::token_ledger::balance(&state, &asset.token_id, &account),
        75_000
    );

    // A withdrawal retires the deposit asset and queues the transaction
    // spending the deposit; more than the holder has is refused.
    let pay_to = [vec![0x00, 0x14], vec![0x77; 20]].concat();
    let withdraw = |amount: u128| BridgeOp::Outbound {
        target_chain: "bitcoin".into(),
        recipient: pay_to.clone(),
        amount,
        asset: None,
    };
    assert!(
        chain.bridge(&account, withdraw(80_000)).await.is_err(),
        "more than the holder has"
    );
    let out = chain.bridge(&account, withdraw(50_000)).await.unwrap();
    assert_eq!(out["sequence"], 1, "{out}");
    let state = chain.state();
    assert_eq!(
        tenzro_vm::token_ledger::balance(&state, &asset.token_id, &account),
        25_000
    );
    assert_eq!(
        tenzro_vm::token_ledger::read_token(&state, &asset.token_id)
            .unwrap()
            .total_supply,
        25_000
    );
    let message = hex::decode(out["message"].as_str().unwrap()).unwrap();
    let w = tenzro_bridge::route::bitcoin_spend::Withdrawal::decode(&message).unwrap();
    assert_eq!(w.tx.outputs[0].script, pay_to);
    assert_eq!(w.tx.inputs.len(), 1);
}

fn create(mintable: bool, max_supply: Option<u128>, attestor_stake_tnzo: Option<u64>) -> TokenOp {
    use tenzro_types::token_policy::{Authority, PowerManifest, ReserveBacking, TokenPolicy};
    TokenOp::Create {
        name: "Gold".into(),
        symbol: "GLD".into(),
        decimals: 6,
        initial_supply: 1_000,
        max_supply,
        powers: PowerManifest {
            mint: if mintable {
                Authority::Issuer
            } else {
                Authority::Disabled
            },
            freeze: Authority::Issuer,
            halt: Authority::Issuer,
            force: Authority::Issuer,
            policy_change: Authority::Issuer,
        },
        policy: TokenPolicy {
            eligibility: Vec::new(),
            policy_timelock_ms: tenzro_vm::native::token::DEFAULT_POLICY_TIMELOCK_FLOOR_MS,
        },
        council: None,
        reserve_backing: attestor_stake_tnzo.map(|t| ReserveBacking {
            min_attestor_stake_tnzo: t,
        }),
    }
}

/// Register `did` with `signer`'s key and bond its account as an attestor
/// with the attestor role's floor, through a signed `Stake` transaction.
async fn bonded_attestor(
    chain: &mut Chain,
    did: &str,
    signer: &tenzro_crypto::composite::testing::TestHybridSigner,
) {
    use tenzro_crypto::composite::HybridSigner as _;
    let key = signer.public_key();
    let record = tenzro_types::identity::RegisterIdentityPayload {
        did: did.into(),
        identity_type: "machine".into(),
        display_name: String::new(),
        controller_pubkey: key.p256.clone(),
        key_type: "p256".into(),
        wallet_id: String::new(),
        wallet_address: tenzro_types::primitives::Address::new(key.account_slot()),
        pq_verifying_key: key.pq.clone().unwrap_or_default(),
        metadata: Default::default(),
        proof: tenzro_types::identity::RegistrationProof::Hardware {
            signature: tenzro_types::account_signature::CompositeSignature::classical(
                tenzro_types::account_signature::ClassicalProof::Raw {
                    signature: Vec::new(),
                },
            ),
        },
    };
    let mut state = chain.state();
    state.set_storage(
        &tenzro_vm::native::SYSTEM_ADDRESS,
        format!("identity:{did}").as_bytes(),
        serde_json::to_vec(&record).unwrap(),
    );
    state.commit().unwrap();
    let floor = tenzro_types::constants::MIN_ATTESTOR_STAKE;
    let op = tenzro_types::token::StakeOp::Bond {
        role: tenzro_types::network::NetworkRole::Attestor,
        amount: floor,
        capacity: tenzro_types::token::StakeCapacity::None,
    };
    chain
        .send(
            &key.account_slot(),
            tenzro_vm::native::SELECTOR_STAKE,
            serde_json::to_vec(&op).unwrap(),
        )
        .await
        .expect("attestor bond");
}

fn reason() -> tenzro_types::token_policy::IssuerAction {
    tenzro_types::token_policy::IssuerAction {
        reason_code: 1,
        evidence_hash: [0xEE; 32],
    }
}

fn token_id(out: &serde_json::Value) -> [u8; 32] {
    hex::decode(out["token_id"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

#[tokio::test]
async fn an_issuer_mints_within_its_maximum_and_only_the_issuer_mints() {
    let issuer = [0xE1u8; 32];
    let other = [0xE2u8; 32];
    let mut chain = Chain::new(&[(&issuer, 10 * ONE_TNZO), (&other, 10 * ONE_TNZO)]).await;
    let id = token_id(
        &chain
            .token(&issuer, create(true, Some(1_500), None))
            .await
            .unwrap(),
    );
    let mint = |amount| TokenOp::Mint {
        token_id: id,
        to: other.to_vec(),
        amount,
        reserves: Vec::new(),
    };
    assert!(
        chain
            .token(&other, mint(10))
            .await
            .unwrap_err()
            .contains("issuer")
    );
    chain.token(&issuer, mint(500)).await.unwrap();
    assert!(
        chain
            .token(&issuer, mint(1))
            .await
            .unwrap_err()
            .contains("maximum")
    );
    let state = chain.state();
    assert_eq!(tenzro_vm::token_ledger::balance(&state, &id, &other), 500);
    assert_eq!(
        tenzro_vm::token_ledger::read_token(&state, &id)
            .unwrap()
            .total_supply,
        1_500
    );

    // A fixed-supply token does not mint.
    let fixed = token_id(
        &chain
            .token(&issuer, create(false, None, None))
            .await
            .unwrap(),
    );
    let err = chain
        .token(
            &issuer,
            TokenOp::Mint {
                token_id: fixed,
                to: issuer.to_vec(),
                amount: 1,
                reserves: Vec::new(),
            },
        )
        .await
        .unwrap_err();
    assert!(err.contains("no Mint power"), "{err}");

    // Burning retires supply.
    chain
        .token(
            &other,
            TokenOp::Burn {
                token_id: id,
                amount: 200,
            },
        )
        .await
        .unwrap();
    let state = chain.state();
    assert_eq!(
        tenzro_vm::token_ledger::read_token(&state, &id)
            .unwrap()
            .total_supply,
        1_300
    );
}

#[tokio::test]
async fn a_reserve_backed_token_mints_only_against_bonded_attestors_reserves() {
    use tenzro_crypto::composite::testing::TestHybridSigner;
    use tenzro_crypto::composite::{HybridSigner as _, SignatureContext};
    use tenzro_types::reserve::{ReserveAttestation, ReserveSource};

    let issuer = [0xF1u8; 32];
    let attestor = TestHybridSigner::p256_only(0x2A);
    let stranger = TestHybridSigner::p256_only(0x2B);
    let floor = tenzro_types::constants::MIN_ATTESTOR_STAKE;
    let mut chain = Chain::new(&[
        (&issuer, 10 * ONE_TNZO),
        (&attestor.public_key().account_slot(), 2 * floor),
    ])
    .await;
    bonded_attestor(&mut chain, "did:tenzro:machine:custodian", &attestor).await;
    let whole = (floor / ONE_TNZO) as u64;
    let id = token_id(
        &chain
            .token(&issuer, create(true, None, Some(whole)))
            .await
            .unwrap(),
    );
    let attestation = |key: &TestHybridSigner, did: &str, reserves: u128| {
        let mut att = ReserveAttestation {
            asset_id: hex::encode(id),
            reserves,
            source: ReserveSource::Issuer,
            attestor_did: did.into(),
            attested_at: NOW_MS / 1000,
            signature: None,
        };
        att.signature = Some(
            key.sign(SignatureContext::ReserveAttestation, &att.signing_payload())
                .unwrap(),
        );
        att
    };
    let mint = |reserve: Option<ReserveAttestation>| TokenOp::Mint {
        token_id: id,
        to: issuer.to_vec(),
        amount: 500,
        reserves: reserve.into_iter().collect(),
    };
    assert!(
        chain.token(&issuer, mint(None)).await.is_err(),
        "no attestation"
    );
    assert!(
        chain
            .token(
                &issuer,
                mint(Some(attestation(
                    &stranger,
                    "did:tenzro:machine:custodian",
                    10_000
                )))
            )
            .await
            .is_err(),
        "a key other than the attestor's"
    );
    assert!(
        chain
            .token(
                &issuer,
                mint(Some(attestation(
                    &attestor,
                    "did:tenzro:machine:custodian",
                    1_499
                )))
            )
            .await
            .is_err()
    );
    chain
        .token(
            &issuer,
            mint(Some(attestation(
                &attestor,
                "did:tenzro:machine:custodian",
                1_500,
            ))),
        )
        .await
        .unwrap();
    let state = chain.state();
    assert_eq!(
        tenzro_vm::token_ledger::read_token(&state, &id)
            .unwrap()
            .total_supply,
        1_500
    );
}

#[tokio::test]
async fn the_issuers_freeze_and_halt_bind_holders_and_its_forced_transfer_does_not() {
    let issuer = [0x71u8; 32];
    let holder = [0x72u8; 32];
    let custodian = [0x73u8; 32];
    let mut chain = Chain::new(&[(&issuer, 10 * ONE_TNZO), (&holder, 10 * ONE_TNZO)]).await;
    let id = token_id(
        &chain
            .token(&issuer, create(false, None, None))
            .await
            .unwrap(),
    );
    let send = |to: &[u8], amount| TokenOp::Transfer {
        token_id: id,
        to: to.to_vec(),
        amount,
    };
    chain.token(&issuer, send(&holder, 100)).await.unwrap();

    let freeze = TokenOp::SetFrozen {
        token_id: id,
        account: holder.to_vec(),
        amount: 60,
        action: reason(),
    };
    assert!(
        chain.token(&holder, freeze.clone()).await.is_err(),
        "only the issuer freezes"
    );
    chain.token(&issuer, freeze).await.unwrap();
    assert!(
        chain
            .token(&holder, send(&custodian, 41))
            .await
            .unwrap_err()
            .contains("unfrozen")
    );
    chain.token(&holder, send(&custodian, 40)).await.unwrap();

    chain
        .token(
            &issuer,
            TokenOp::SetHalted {
                token_id: id,
                halted: true,
                action: reason(),
            },
        )
        .await
        .unwrap();
    assert!(
        chain
            .token(&issuer, send(&custodian, 1))
            .await
            .unwrap_err()
            .contains("halted")
    );

    let force = TokenOp::ForcedTransfer {
        token_id: id,
        from: holder.to_vec(),
        to: custodian.to_vec(),
        amount: 50,
        action: reason(),
    };
    assert!(
        chain.token(&holder, force.clone()).await.is_err(),
        "only the issuer forces"
    );
    chain.token(&issuer, force).await.unwrap();
    let state = chain.state();
    assert_eq!(
        tenzro_vm::token_ledger::balance(&state, &id, &custodian),
        90
    );
    assert_eq!(tenzro_vm::token_ledger::balance(&state, &id, &holder), 10);
    assert_eq!(
        tenzro_vm::token_ledger::frozen(&state, &id, &holder),
        10,
        "frozen clamps to what is left"
    );
}

#[tokio::test]
async fn a_policy_change_waits_for_its_eta_and_holders_exit_under_the_old_policy() {
    use tenzro_types::token_policy::{HolderKind, Rule, TokenPolicy};
    let issuer = [0x81u8; 32];
    let holder = [0x82u8; 32];
    let exit = [0x83u8; 32];
    let mut chain = Chain::new(&[(&issuer, 10 * ONE_TNZO), (&holder, 10 * ONE_TNZO)]).await;
    let id = token_id(
        &chain
            .token(&issuer, create(false, None, None))
            .await
            .unwrap(),
    );
    let send = |to: &[u8], amount| TokenOp::Transfer {
        token_id: id,
        to: to.to_vec(),
        amount,
    };
    chain.token(&issuer, send(&holder, 100)).await.unwrap();

    let floor = tenzro_vm::native::token::DEFAULT_POLICY_TIMELOCK_FLOOR_MS;
    let stricter = TokenPolicy {
        eligibility: vec![Rule::HolderKind {
            kind: HolderKind::HumanRoot,
        }],
        policy_timelock_ms: floor,
    };
    let short = TokenPolicy {
        eligibility: Vec::new(),
        policy_timelock_ms: floor - 1,
    };
    assert!(
        chain
            .token(
                &issuer,
                TokenOp::SetPolicy {
                    token_id: id,
                    policy: short
                }
            )
            .await
            .is_err()
    );
    chain
        .token(
            &issuer,
            TokenOp::SetPolicy {
                token_id: id,
                policy: stricter,
            },
        )
        .await
        .unwrap();
    let err = chain
        .token(&issuer, TokenOp::ExecutePolicy { token_id: id })
        .await
        .unwrap_err();
    assert!(err.contains("applies from"), "{err}");

    // The exit window: the queued policy binds no one yet.
    chain.token(&holder, send(&exit, 40)).await.unwrap();

    chain.now_ms = NOW_MS + floor as i64;
    chain
        .token(&issuer, TokenOp::ExecutePolicy { token_id: id })
        .await
        .unwrap();
    assert!(
        chain.token(&holder, send(&exit, 1)).await.is_err(),
        "the new policy binds after its ETA"
    );
}

#[tokio::test]
async fn a_forced_transfer_without_reason_or_evidence_is_refused() {
    let issuer = [0x91u8; 32];
    let holder = [0x92u8; 32];
    let mut chain = Chain::new(&[(&issuer, 10 * ONE_TNZO)]).await;
    let id = token_id(
        &chain
            .token(&issuer, create(false, None, None))
            .await
            .unwrap(),
    );
    chain
        .token(
            &issuer,
            TokenOp::Transfer {
                token_id: id,
                to: holder.to_vec(),
                amount: 10,
            },
        )
        .await
        .unwrap();
    for action in [
        tenzro_types::token_policy::IssuerAction {
            reason_code: 0,
            evidence_hash: [0xEE; 32],
        },
        tenzro_types::token_policy::IssuerAction {
            reason_code: 1,
            evidence_hash: [0; 32],
        },
    ] {
        let force = TokenOp::ForcedTransfer {
            token_id: id,
            from: holder.to_vec(),
            to: issuer.to_vec(),
            amount: 10,
            action,
        };
        assert!(chain.token(&issuer, force).await.is_err());
    }
    let state = chain.state();
    assert_eq!(tenzro_vm::token_ledger::balance(&state, &id, &holder), 10);
}

#[tokio::test]
async fn a_mint_short_of_the_backing_stake_is_refused() {
    use tenzro_crypto::composite::testing::TestHybridSigner;
    use tenzro_crypto::composite::{HybridSigner as _, SignatureContext};
    use tenzro_types::reserve::{ReserveAttestation, ReserveSource};

    let issuer = [0xA1u8; 32];
    let a = TestHybridSigner::p256_only(0x3A);
    let b = TestHybridSigner::p256_only(0x3B);
    let floor = tenzro_types::constants::MIN_ATTESTOR_STAKE;
    let mut chain = Chain::new(&[
        (&issuer, 10 * ONE_TNZO),
        (&a.public_key().account_slot(), 2 * floor),
        (&b.public_key().account_slot(), 2 * floor),
    ])
    .await;
    bonded_attestor(&mut chain, "did:tenzro:machine:a", &a).await;
    bonded_attestor(&mut chain, "did:tenzro:machine:b", &b).await;
    let whole = (floor / ONE_TNZO) as u64;
    let id = token_id(
        &chain
            .token(&issuer, create(true, None, Some(2 * whole)))
            .await
            .unwrap(),
    );
    let attestation = |key: &TestHybridSigner, did: &str| {
        let mut att = ReserveAttestation {
            asset_id: hex::encode(id),
            reserves: 10_000,
            source: ReserveSource::Issuer,
            attestor_did: did.into(),
            attested_at: NOW_MS / 1000,
            signature: None,
        };
        att.signature = Some(
            key.sign(SignatureContext::ReserveAttestation, &att.signing_payload())
                .unwrap(),
        );
        att
    };
    let mint = |reserves: Vec<ReserveAttestation>| TokenOp::Mint {
        token_id: id,
        to: issuer.to_vec(),
        amount: 500,
        reserves,
    };
    let one = attestation(&a, "did:tenzro:machine:a");
    assert!(
        chain.token(&issuer, mint(vec![one.clone()])).await.is_err(),
        "half the stake"
    );
    assert!(
        chain
            .token(&issuer, mint(vec![one.clone(), one.clone()]))
            .await
            .is_err(),
        "one attestor twice"
    );
    chain
        .token(
            &issuer,
            mint(vec![one, attestation(&b, "did:tenzro:machine:b")]),
        )
        .await
        .unwrap();
}

/// Every committed entry of the store, in key order.
fn committed(store: &Arc<dyn KvStore>) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut all = store.scan_prefix(CF_STATE, b"").unwrap();
    all.sort();
    let mut accounts = store.scan_prefix(CF_ACCOUNTS, b"").unwrap();
    accounts.sort();
    all.extend(accounts);
    all
}

#[tokio::test]
async fn the_same_transactions_on_two_states_reach_the_same_state() {
    let user = [0x81u8; 32];
    let relayer = [0x82u8; 32];
    let (route, keys) = ccip_route();
    let mut chains = Vec::new();
    for _ in 0..2 {
        let mut chain = Chain::new(&[(&user, 10 * ONE_TNZO), (&relayer, 10 * ONE_TNZO)]).await;
        chain.install(&route);
        chain.bridge(&user, outbound(600)).await.unwrap();
        let good = deliver(&route, &keys, 3, 1, evm_body(&route, 1, &user, 250));
        chain.bridge(&relayer, inbound(&good)).await.unwrap();
        let id = token_id(&chain.token(&user, create(true, None, None)).await.unwrap());
        chain
            .token(
                &user,
                TokenOp::Mint {
                    token_id: id,
                    to: relayer.to_vec(),
                    amount: 7,
                    reserves: Vec::new(),
                },
            )
            .await
            .unwrap();
        chains.push(chain);
    }
    let (a, b) = (committed(&chains[0].store), committed(&chains[1].store));
    let differing: Vec<String> = a
        .iter()
        .zip(&b)
        .filter(|(x, y)| x != y)
        .map(|(x, _)| String::from_utf8_lossy(&x.0).into_owned())
        .collect();
    assert_eq!(a.len(), b.len(), "both states hold the same entries");
    assert!(differing.is_empty(), "entries differ: {differing:?}");
}

/// IBC refunds as consensus transactions: a packet's TNZO leaves the route's
/// vault for its sender only on a proven error acknowledgement or a proven
/// timeout, once, and a relayer pays for the delivery.
mod ibc_refunds {
    use tenzro_bridge::route::ibc::{ack_commitment, ack_key, receipt_key};
    use tenzro_bridge::route::ibc_core::{
        EndState, channel_end, channel_path, connection_end, connection_path,
    };
    use tenzro_bridge::route::tendermint::fixtures::{
        StoreFixture, Validators, bootstrap, header, update,
    };
    use tenzro_types::bridge_route::{IbcRoute, IbcVersion, LightClientAnchor};
    use tenzro_types::bridge_transfer::IbcMsg;

    use super::*;

    const CHAIN: &str = "osmosis";
    const COSMOS_CHAIN_ID: &str = "osmosis-1";
    const CP_CLIENT: &str = "08-wasm-3";
    const CP_CONNECTION: &str = "connection-12";
    const CP_CHANNEL: &str = "channel-141";
    const NOW_S: u64 = (NOW_MS / 1000) as u64;
    const TIMEOUT_SECS: u64 = 3_600;
    const TRUSTED_HEIGHT: u64 = 100;

    struct Cosmos {
        vals: Validators,
        version: IbcVersion,
    }

    fn ibc_route(version: IbcVersion, vals: &Validators) -> BridgeRoute {
        let ibc = IbcRoute {
            version,
            counterparty_client_id: CP_CLIENT.into(),
            counterparty_connection_id: (version == IbcVersion::Classic)
                .then(|| CP_CONNECTION.into()),
            counterparty_channel_id: (version == IbcVersion::Classic).then(|| CP_CHANNEL.into()),
            packet_timeout_secs: TIMEOUT_SECS,
        };
        let trusted = header(
            COSMOS_CHAIN_ID,
            TRUSTED_HEIGHT,
            NOW_S - 1_000,
            vals.hash(),
            vals.hash(),
            [0x21; 32],
        );
        let mut ramp = [0u8; 32];
        ramp[..3].copy_from_slice(b"ibc");
        let route = BridgeRoute {
            adapter: BridgeRouteAdapter::Ibc,
            family: ChainFamily::Cosmos,
            source_chain: CHAIN.into(),
            source_chain_id: 118,
            local_selector: LOCAL_SELECTOR,
            peer: IbcRoute::end_hash(ibc.counterparty_packet_id()),
            ramp,
            local_endpoint: IbcRoute::end_hash(&ibc.tenzro_packet_id(CHAIN)),
            remote_token: Sha256::digest(ibc.tnzo_trace().as_bytes()).into(),
            verifiers: quorum(60, "ibc").1,
            blessing: None,
            light_client: Some(LightClientAnchor::Tendermint {
                chain_id: COSMOS_CHAIN_ID.into(),
                trusted_height: TRUSTED_HEIGHT,
                trusted_header_hash: trusted.hash(),
                trusting_period_secs: 14 * 24 * 3600,
            }),
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
        };
        route.validate().unwrap();
        route
    }

    impl Cosmos {
        fn cp_id(&self) -> &'static str {
            match self.version {
                IbcVersion::Classic => CP_CHANNEL,
                IbcVersion::V2 => CP_CLIENT,
            }
        }

        /// Follow the Cosmos chain to a block at `height` and `seconds`
        /// committing `entries`, through a light-client transaction, and
        /// return the proof of `key` in that block.
        async fn prove(
            &self,
            chain: &mut Chain,
            relayer: &[u8],
            height: u64,
            seconds: u64,
            entries: Vec<(Vec<u8>, Vec<u8>)>,
            key: &[u8],
        ) -> Vec<u8> {
            let store = StoreFixture::new("ibc", entries);
            let h = header(
                COSMOS_CHAIN_ID,
                height,
                seconds,
                self.vals.hash(),
                self.vals.hash(),
                store.app_hash,
            );
            let c = self.vals.commit(&h, 3);
            let set = self.vals.set();
            let op = BridgeOp::LightClientUpdate {
                adapter: BridgeRouteAdapter::Ibc,
                source_chain: CHAIN.into(),
                update: update(TRUSTED_HEIGHT, &h, &c, &set, &set),
            };
            chain.bridge(relayer, op).await.unwrap();
            store.proof(key, height).encode()
        }

        async fn ibc(
            &self,
            chain: &mut Chain,
            relayer: &[u8],
            msg: IbcMsg,
        ) -> Result<serde_json::Value, String> {
            chain
                .bridge(
                    relayer,
                    BridgeOp::Ibc {
                        source_chain: CHAIN.into(),
                        msg,
                    },
                )
                .await
        }

        /// The classic handshakes, each Cosmos end proven; nothing for v2.
        async fn open(&self, chain: &mut Chain, relayer: &[u8]) {
            if self.version == IbcVersion::V2 {
                return;
            }
            let client = IbcRoute::tenzro_client_id(CHAIN);
            let connection = IbcRoute::tenzro_connection_id(CHAIN);
            let channel = IbcRoute::tenzro_channel_id(CHAIN);
            let conn = connection_path(CP_CONNECTION);
            let chan = channel_path(CP_CHANNEL);
            let t = NOW_S - 500;
            let steps: [(Vec<u8>, Vec<u8>, fn(Vec<u8>) -> IbcMsg); 4] = [
                (
                    conn.clone(),
                    connection_end(EndState::Init, CP_CLIENT, &client, ""),
                    |proof| IbcMsg::ConnectionOpenTry { proof },
                ),
                (
                    conn.clone(),
                    connection_end(EndState::Open, CP_CLIENT, &client, &connection),
                    |proof| IbcMsg::ConnectionOpenConfirm { proof },
                ),
                (
                    chan.clone(),
                    channel_end(EndState::Init, "", CP_CONNECTION),
                    |proof| IbcMsg::ChannelOpenTry { proof },
                ),
                (
                    chan.clone(),
                    channel_end(EndState::Open, &channel, CP_CONNECTION),
                    |proof| IbcMsg::ChannelOpenConfirm { proof },
                ),
            ];
            for (i, (path, end, msg)) in steps.into_iter().enumerate() {
                let p = self
                    .prove(
                        chain,
                        relayer,
                        TRUSTED_HEIGHT + 1 + i as u64,
                        t,
                        vec![(path.clone(), end)],
                        &path,
                    )
                    .await;
                self.ibc(chain, relayer, msg(p)).await.unwrap();
            }
        }
    }

    fn outbound_ibc(amount: u128) -> BridgeOp {
        BridgeOp::Outbound {
            target_chain: CHAIN.into(),
            recipient: b"osmo1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5x".to_vec(),
            amount,
            asset: None,
        }
    }

    #[tokio::test]
    async fn an_error_acknowledgement_and_a_timeout_refund_the_sender_once_from_the_vault() {
        for version in [IbcVersion::Classic, IbcVersion::V2] {
            let user = [0xC1u8; 32];
            let relayer = [0xC2u8; 32];
            let mut chain = Chain::new(&[(&user, 10 * ONE_TNZO), (&relayer, 10 * ONE_TNZO)]).await;
            let cosmos = Cosmos {
                vals: Validators::new(3, 4),
                version,
            };
            let route = ibc_route(version, &cosmos.vals);
            chain.install(&route);
            let trusted = header(
                COSMOS_CHAIN_ID,
                TRUSTED_HEIGHT,
                NOW_S - 1_000,
                cosmos.vals.hash(),
                cosmos.vals.hash(),
                [0x21; 32],
            );
            let op = BridgeOp::LightClientUpdate {
                adapter: BridgeRouteAdapter::Ibc,
                source_chain: CHAIN.into(),
                update: bootstrap(&trusted),
            };
            chain.bridge(&relayer, op).await.unwrap();
            cosmos.open(&mut chain, &relayer).await;

            let vault = route_vault(&route);
            chain.bridge(&user, outbound_ibc(600)).await.unwrap();
            chain.bridge(&user, outbound_ibc(400)).await.unwrap();
            assert_eq!(chain.balance(&vault), 1_000, "{version:?}");
            let user_after_send = chain.balance(&user);

            // Packet 1: the Cosmos chain wrote an error acknowledgement.
            let error_ack = match version {
                IbcVersion::Classic => {
                    br#"{"error":"ABCI code: 1: error handling packet"}"#.to_vec()
                }
                IbcVersion::V2 => Sha256::digest(b"UNIVERSAL_ERROR_ACKNOWLEDGEMENT").to_vec(),
            };
            let ack1 = ack_key(version, "transfer", cosmos.cp_id(), 1);
            let entries = vec![(ack1.clone(), ack_commitment(version, &error_ack).to_vec())];
            let p = cosmos
                .prove(&mut chain, &relayer, 110, NOW_S - 400, entries, &ack1)
                .await;

            // An acknowledgement the Cosmos chain did not commit refunds nothing.
            let forged = IbcMsg::Acknowledge {
                sequence: 1,
                acknowledgement: br#"{"error":"forged"}"#.to_vec(),
                proof: p.clone(),
            };
            assert!(cosmos.ibc(&mut chain, &relayer, forged).await.is_err());
            assert_eq!(chain.balance(&user), user_after_send);

            let ack = IbcMsg::Acknowledge {
                sequence: 1,
                acknowledgement: error_ack,
                proof: p,
            };
            let out = cosmos.ibc(&mut chain, &relayer, ack.clone()).await.unwrap();
            assert_eq!(out["message"], "acknowledge", "{out}");
            assert_eq!(out["refund"]["amount"], "600", "{out}");
            assert_eq!(out["refund"]["to"], hex::encode(user), "{out}");
            assert_eq!(
                chain.balance(&user),
                user_after_send + 600,
                "the relayer pays the fee"
            );
            assert_eq!(chain.balance(&vault), 400);
            assert!(
                cosmos.ibc(&mut chain, &relayer, ack).await.is_err(),
                "refunded once"
            );
            assert_eq!(chain.balance(&user), user_after_send + 600);

            // Packet 2: no receipt on the Cosmos chain past its timeout.
            let receipt = receipt_key(version, "transfer", cosmos.cp_id(), 2);
            let other = (b"zz-unrelated".to_vec(), vec![9u8]);
            let early = cosmos
                .prove(
                    &mut chain,
                    &relayer,
                    111,
                    NOW_S - 300,
                    vec![other.clone()],
                    &receipt,
                )
                .await;
            let refused = IbcMsg::Timeout {
                sequence: 2,
                proof: early,
            };
            assert!(
                cosmos.ibc(&mut chain, &relayer, refused).await.is_err(),
                "not yet timed out"
            );

            chain.now_ms = NOW_MS + (TIMEOUT_SECS as i64 + 120) * 1000;
            let late = NOW_S + TIMEOUT_SECS + 60;
            let p = cosmos
                .prove(&mut chain, &relayer, 112, late, vec![other], &receipt)
                .await;
            let timeout = IbcMsg::Timeout {
                sequence: 2,
                proof: p,
            };
            let out = cosmos
                .ibc(&mut chain, &relayer, timeout.clone())
                .await
                .unwrap();
            assert_eq!(out["message"], "timeout", "{out}");
            assert_eq!(out["refund"]["amount"], "400", "{out}");
            assert_eq!(chain.balance(&user), user_after_send + 1_000);
            assert_eq!(chain.balance(&vault), 0);
            assert!(
                cosmos.ibc(&mut chain, &relayer, timeout).await.is_err(),
                "refunded once"
            );
            assert_eq!(chain.balance(&user), user_after_send + 1_000);
        }
    }
}
