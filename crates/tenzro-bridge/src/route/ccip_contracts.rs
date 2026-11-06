//! The published CCIP contracts (Router 1.2, OnRamp / OffRamp / FeeQuoter /
//! NonceManager / RMNRemote 1.6, TokenAdminRegistry 1.5, BurnMintTokenPool
//! 1.6.1 and the burn/mint ERC-20) deployed from their published bytecode on
//! a Tenzro EVM, playing the external chain of an EVM route.
//!
//! - **Receive.** The framework's outbound envelope is committed by an OCR
//!   commit report and executed by the OffRamp; the token pool mints the
//!   bridged representation to the recipient.
//! - **Send.** A `Router.ccipSend` burns the representation in the pool; the
//!   OnRamp's `CCIPMessageSent` payload is admitted by the framework as an
//!   inbound transfer, message id and all.
//!
//! After both legs the representation's total supply on the EVM equals the
//! route's outstanding supply in the framework's record.

use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{RecoveryId, Signature as K256Sig, SigningKey};
use sha3::{Digest, Keccak256};
use tenzro_vm::{
    EvmExecutor, ExecutionResult, GasOracle, PrecompileRegistry, StateAdapter, VmConfig, VmState,
    VmTransaction, VmType,
};

use super::evm::{EVM_CHAINS, Field, abi_array, abi_bytes, abi_tuple};
use super::lane::LaneDirection;
use super::state::read_supply;
use super::test_support::*;
use super::*;

const EVM_CHAIN_ID: u64 = 1337;
const TENZRO_SELECTOR: u64 = 7_777;
/// Tenzro's endpoint on the lane: a 20-byte address left-padded, so the EVM
/// side's address checks accept it as both the source pool and the token.
const ENDPOINT: [u8; 32] = {
    let mut w = [0u8; 32];
    let mut i = 12;
    while i < 32 {
        w[i] = 0x7e;
        i += 1;
    }
    w
};
const DEPLOYER: [u8; 20] = [0xd0; 20];
const EVM_HOLDER: [u8; 20] = [0xe1; 20];
const TENZRO_HOLDER: [u8; 20] = [0xa7; 20];
const ONE: u128 = 1_000_000_000_000_000_000;

fn bin(name: &str) -> Vec<u8> {
    let text = match name {
        "rmn_remote" => include_str!("../../tests/fixtures/ccip/rmn_remote.bin"),
        "router" => include_str!("../../tests/fixtures/ccip/router.bin"),
        "nonce_manager" => include_str!("../../tests/fixtures/ccip/nonce_manager.bin"),
        "fee_quoter" => include_str!("../../tests/fixtures/ccip/fee_quoter.bin"),
        "onramp" => include_str!("../../tests/fixtures/ccip/onramp.bin"),
        "offramp" => include_str!("../../tests/fixtures/ccip/offramp.bin"),
        "token_admin_registry" => {
            include_str!("../../tests/fixtures/ccip/token_admin_registry.bin")
        }
        "burn_mint_token_pool" => {
            include_str!("../../tests/fixtures/ccip/burn_mint_token_pool.bin")
        }
        "erc20" => include_str!("../../tests/fixtures/ccip/factory_burn_mint_erc20.bin"),
        other => panic!("no fixture {other}"),
    };
    hex::decode(text.trim().trim_start_matches("0x")).expect("fixture is hex")
}

fn keccak(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Keccak256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn sel(signature: &str) -> Vec<u8> {
    keccak(&[signature.as_bytes()])[..4].to_vec()
}

fn u(v: u128) -> Field {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&v.to_be_bytes());
    Field::Word(w)
}

fn word(v: u128) -> [u8; 32] {
    let Field::Word(w) = u(v) else { unreachable!() };
    w
}

fn addr_word(a: &[u8; 20]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(a);
    w
}

fn a(addr: &[u8; 20]) -> Field {
    Field::Word(addr_word(addr))
}

fn b4(v: [u8; 4]) -> Field {
    let mut w = [0u8; 32];
    w[..4].copy_from_slice(&v);
    Field::Word(w)
}

fn bytes(b: &[u8]) -> Field {
    Field::Tail(abi_bytes(b))
}

/// An array of static values (words, or static tuples flattened to words).
fn statics(count: usize, words: &[[u8; 32]]) -> Field {
    let mut out = word(count as u128).to_vec();
    for w in words {
        out.extend_from_slice(w);
    }
    Field::Tail(out)
}

fn empty() -> Field {
    statics(0, &[])
}

fn tuple(fields: &[Field]) -> Field {
    Field::Tail(abi_tuple(fields))
}

fn calldata(signature: &str, fields: &[Field]) -> Vec<u8> {
    let mut out = sel(signature);
    out.extend_from_slice(&abi_tuple(fields));
    out
}

fn addr20(v: &[u8]) -> [u8; 20] {
    v.try_into().expect("20-byte address")
}

/// A Tenzro EVM instance with its own state and clock.
struct Evm {
    exec: EvmExecutor,
    state: StateAdapter,
    now_ms: i64,
}

impl Evm {
    fn new() -> Self {
        let mut state = StateAdapter::new();
        for who in [DEPLOYER, EVM_HOLDER] {
            state.set_balance(&who, 1_000 * ONE);
        }
        Self {
            exec: EvmExecutor::new(
                VmConfig::default(),
                std::sync::Arc::new(GasOracle::new()),
                std::sync::Arc::new(PrecompileRegistry::new()),
            )
            .expect("executor"),
            state,
            now_ms: NOW_MS,
        }
    }

    fn send(&mut self, from: [u8; 20], to: Option<[u8; 20]>, data: Vec<u8>) -> ExecutionResult {
        let nonce = self.state.get_nonce(&from);
        let mut tx = VmTransaction::new(
            from.to_vec(),
            to.map(|t| t.to_vec()),
            0,
            data,
            15_000_000,
            1,
            nonce,
            VmType::Evm,
            EVM_CHAIN_ID,
        )
        .with_block_height(100);
        tx.block_timestamp_ms = Some(self.now_ms);
        self.exec
            .execute_with_revm(&tx, &mut self.state)
            .expect("transaction executes")
    }

    fn ok(&mut self, from: [u8; 20], to: [u8; 20], data: Vec<u8>, what: &str) -> ExecutionResult {
        let r = self.send(from, Some(to), data);
        assert!(r.success, "{what} reverted: 0x{}", hex::encode(&r.output));
        r
    }

    fn deploy(&mut self, name: &str, args: &[Field]) -> [u8; 20] {
        let mut code = bin(name);
        code.extend_from_slice(&abi_tuple(args));
        let r = self.send(DEPLOYER, None, code);
        assert!(
            r.success,
            "deploying {name} reverted: 0x{}",
            hex::encode(&r.output)
        );
        addr20(&r.contract_address.expect("created"))
    }

    fn view_word(&mut self, to: [u8; 20], data: Vec<u8>) -> u128 {
        let r = self.ok(DEPLOYER, to, data, "view");
        u128::from_be_bytes(r.output[16..32].try_into().unwrap())
    }

    fn balance_of(&mut self, token: [u8; 20], who: [u8; 20]) -> u128 {
        self.view_word(token, calldata("balanceOf(address)", &[a(&who)]))
    }

    fn total_supply(&mut self, token: [u8; 20]) -> u128 {
        self.view_word(token, calldata("totalSupply()", &[]))
    }
}

/// The deployed lane on the EVM side.
struct Lane {
    link: [u8; 20],
    token: [u8; 20],
    router: [u8; 20],
    onramp: [u8; 20],
    offramp: [u8; 20],
    pool: [u8; 20],
    commit_signers: Vec<SigningKey>,
}

const COMMIT_DIGEST: [u8; 32] = [0xc0; 32];
const EXEC_DIGEST: [u8; 32] = [0xe0; 32];

fn deploy_lane(evm: &mut Evm, eth_selector: u64, lanes: &CcipLane, outflow: LaneRateLimit) -> Lane {
    let erc20 = |evm: &mut Evm, name: &str, pre_mint: u128| {
        evm.deploy(
            "erc20",
            &[
                bytes(name.as_bytes()),
                bytes(name.as_bytes()),
                u(18),
                u(0),
                u(pre_mint),
                a(&DEPLOYER),
            ],
        )
    };
    let link = erc20(evm, "LINK", 1_000_000 * ONE);
    let token = erc20(evm, "TNZO", 0);
    let rmn = evm.deploy("rmn_remote", &[u(eth_selector as u128), a(&[0u8; 20])]);
    let router = evm.deploy("router", &[a(&link), a(&rmn)]);
    let registry = evm.deploy("token_admin_registry", &[]);
    let nonces = evm.deploy("nonce_manager", &[empty()]);

    let dest_chain_config: Vec<Field> = vec![
        u(1),                         // isEnabled
        u(1),                         // maxNumberOfTokensPerMsg
        u(30_000),                    // maxDataBytes
        u(3_000_000),                 // maxPerMsgGasLimit
        u(300_000),                   // destGasOverhead
        u(16),                        // destGasPerPayloadByteBase
        u(40),                        // destGasPerPayloadByteHigh
        u(3_000),                     // destGasPerPayloadByteThreshold
        u(0),                         // destDataAvailabilityOverheadGas
        u(0),                         // destGasPerDataAvailabilityByte
        u(0),                         // destDataAvailabilityMultiplierBps
        b4([0x28, 0x12, 0xd5, 0x2c]), // chainFamilySelector: EVM
        u(1),                         // enforceOutOfOrder
        u(25),                        // defaultTokenFeeUSDCents
        u(DEST_POOL_GAS_U128),        // defaultTokenDestGasOverhead
        u(200_000),                   // defaultTxGasLimit
        u(1_100_000_000_000_000_000), // gasMultiplierWeiPerEth
        u(0),                         // gasPriceStalenessThreshold
        u(10),                        // networkFeeUSDCents
    ];
    let mut dest_words = vec![word(TENZRO_SELECTOR as u128)];
    dest_words.extend(dest_chain_config.iter().map(|f| match f {
        Field::Word(w) => *w,
        Field::Tail(_) => unreachable!(),
    }));
    let fee_quoter = evm.deploy(
        "fee_quoter",
        &[
            u(1_000_000 * ONE),
            a(&link),
            u(86_400),
            statics(1, &[addr_word(&DEPLOYER)]),
            statics(1, &[addr_word(&link)]),
            empty(),
            empty(),
            statics(1, &[addr_word(&link), word(900_000_000_000_000_000)]),
            statics(1, &dest_words),
        ],
    );
    let onramp = evm.deploy(
        "onramp",
        &[
            u(eth_selector as u128),
            a(&rmn),
            a(&nonces),
            a(&registry),
            a(&fee_quoter),
            u(0),
            a(&[0u8; 20]),
            a(&DEPLOYER),
            a(&[0u8; 20]),
            statics(
                1,
                &[word(TENZRO_SELECTOR as u128), addr_word(&router), word(0)],
            ),
        ],
    );
    let source_chain = abi_tuple(&[
        a(&router),
        u(TENZRO_SELECTOR as u128),
        u(1),
        u(1), // RMN verification is off for this source: roots arrive unblessed.
        bytes(&ENDPOINT),
    ]);
    let offramp = evm.deploy(
        "offramp",
        &[
            u(eth_selector as u128),
            u(5_000),
            a(&rmn),
            a(&registry),
            a(&nonces),
            a(&fee_quoter),
            u(3_600),
            a(&[0u8; 20]),
            Field::Tail(abi_array(vec![source_chain])),
        ],
    );
    let commit_signers: Vec<SigningKey> = (0..4).map(|i| member_key(90 + i)).collect();
    let signer_words: Vec<[u8; 32]> = commit_signers
        .iter()
        .map(|k| addr_word(&member_address(k)))
        .collect();
    let commit_cfg = abi_tuple(&[
        Field::Word(COMMIT_DIGEST),
        u(0),
        u(1),
        u(1),
        statics(4, &signer_words),
        statics(1, &[addr_word(&DEPLOYER)]),
    ]);
    let exec_cfg = abi_tuple(&[
        Field::Word(EXEC_DIGEST),
        u(1),
        u(1),
        u(0),
        empty(),
        statics(1, &[addr_word(&DEPLOYER)]),
    ]);
    evm.ok(
        DEPLOYER,
        offramp,
        calldata(
            "setOCR3Configs((bytes32,uint8,uint8,bool,address[],address[])[])",
            &[Field::Tail(abi_array(vec![commit_cfg, exec_cfg]))],
        ),
        "setOCR3Configs",
    );

    let pool = evm.deploy(
        "burn_mint_token_pool",
        &[a(&token), u(18), empty(), a(&rmn), a(&router)],
    );
    // The pool's outbound is Tenzro's inbound and the other way round.
    let limit = |l: LaneRateLimit| [word(1), word(l.capacity), word(l.rate)];
    let mut chain_update = vec![
        u(TENZRO_SELECTOR as u128),
        Field::Tail(abi_array(vec![abi_bytes(&ENDPOINT)])),
        bytes(&ENDPOINT),
    ];
    chain_update.extend(limit(lanes.inbound).map(Field::Word));
    chain_update.extend(limit(outflow).map(Field::Word));
    evm.ok(
        DEPLOYER,
        pool,
        calldata(
            "applyChainUpdates(uint64[],(uint64,bytes[],bytes,(bool,uint128,uint128),(bool,uint128,uint128))[])",
            &[empty(), Field::Tail(abi_array(vec![abi_tuple(&chain_update)]))],
        ),
        "applyChainUpdates",
    );
    evm.ok(
        DEPLOYER,
        token,
        calldata("grantMintAndBurnRoles(address)", &[a(&pool)]),
        "grantMintAndBurnRoles",
    );
    evm.ok(
        DEPLOYER,
        registry,
        calldata(
            "proposeAdministrator(address,address)",
            &[a(&token), a(&DEPLOYER)],
        ),
        "proposeAdministrator",
    );
    evm.ok(
        DEPLOYER,
        registry,
        calldata("acceptAdminRole(address)", &[a(&token)]),
        "acceptAdminRole",
    );
    evm.ok(
        DEPLOYER,
        registry,
        calldata("setPool(address,address)", &[a(&token), a(&pool)]),
        "setPool",
    );
    evm.ok(
        DEPLOYER,
        router,
        calldata(
            "applyRampUpdates((uint64,address)[],(uint64,address)[],(uint64,address)[])",
            &[
                statics(1, &[word(TENZRO_SELECTOR as u128), addr_word(&onramp)]),
                empty(),
                statics(1, &[word(TENZRO_SELECTOR as u128), addr_word(&offramp)]),
            ],
        ),
        "applyRampUpdates",
    );
    evm.ok(
        DEPLOYER,
        fee_quoter,
        calldata(
            "updatePrices(((address,uint224)[],(uint64,uint224)[]))",
            &[tuple(&[
                statics(1, &[addr_word(&link), word(20 * ONE)]),
                statics(1, &[word(TENZRO_SELECTOR as u128), word(1_000_000_000)]),
            ])],
        ),
        "updatePrices",
    );
    Lane {
        link,
        token,
        router,
        onramp,
        offramp,
        pool,
        commit_signers,
    }
}

const DEST_POOL_GAS_U128: u128 = evm::DEST_POOL_GAS as u128;

const OUTFLOW: LaneRateLimit = LaneRateLimit {
    capacity: 500 * ONE,
    rate: ONE,
};

fn lane_limits() -> CcipLane {
    CcipLane {
        version: CcipLaneVersion::V1_6,
        off_ramp: [0u8; 20],
        ccv_and_executor_hash: [0u8; 32],
        inbound: LaneRateLimit {
            capacity: 400 * ONE,
            rate: ONE,
        },
    }
}

fn route_for(lane: &Lane, eth_selector: u64) -> BridgeRoute {
    BridgeRoute {
        adapter: BridgeRouteAdapter::Ccip,
        family: ChainFamily::Evm,
        source_chain: "ethereum".into(),
        source_chain_id: eth_selector,
        local_selector: TENZRO_SELECTOR,
        peer: addr_word(&lane.pool),
        ramp: addr_word(&lane.onramp),
        local_endpoint: ENDPOINT,
        remote_token: addr_word(&lane.token),
        verifiers: committee(1, 5, 3).1,
        blessing: Some(committee(40, 5, 3).1),
        light_client: None,
        mint_limit: MintRateLimit {
            per_mint: 100 * ONE,
            per_epoch: 1_000 * ONE,
        },
        outflow: OUTFLOW,
        lane_limits: Some(lane_limits()),
        ibc: None,
        settlement_lock: None,
        native_asset: None,
        assets: Vec::new(),
    }
}

/// The OffRamp's leaf for an `Any2EVMRampMessage` read back from the
/// framework's outbound bytes.
fn any2evm_leaf(route: &BridgeRoute, m: &RouteMessage) -> [u8; 32] {
    let metadata = keccak(&[
        &keccak(&[b"Any2EVMMessageHashV1"]),
        &word(route.local_selector as u128),
        &word(route.source_chain_id as u128),
        &keccak(&[&route.local_endpoint]),
    ]);
    let receiver = addr20(&m.receiver);
    let fixed = keccak(&[
        &m.message_id,
        &addr_word(&receiver),
        &word(m.sequence as u128),
        &word(0),
        &word(0),
    ]);
    let token = abi_tuple(&[
        bytes(&m.token_pool),
        Field::Word(m.token),
        u(DEST_POOL_GAS_U128),
        bytes(&[]),
        u(m.amount),
    ]);
    let tokens = abi_tuple(&[Field::Tail(abi_array(vec![token]))]);
    keccak(&[
        &[0u8; 32],
        &metadata,
        &fixed,
        &keccak(&[&m.sender]),
        &keccak(&[&[]]),
        &keccak(&[&tokens]),
    ])
}

fn ocr_sign(key: &SigningKey, digest: &[u8; 32]) -> ([u8; 32], [u8; 32], u8) {
    let (sig, rec): (K256Sig, RecoveryId) = key.sign_prehash(digest).expect("sign");
    let b = sig.to_bytes();
    (
        b[..32].try_into().unwrap(),
        b[32..].try_into().unwrap(),
        rec.to_byte(),
    )
}

/// Commit `leaf` as the unblessed root for sequence `seq` and execute the
/// framework's outbound `message` bytes against it.
fn commit_and_execute(evm: &mut Evm, lane: &Lane, leaf: [u8; 32], seq: u64, message: &[u8]) {
    let root = abi_tuple(&[
        u(TENZRO_SELECTOR as u128),
        bytes(&ENDPOINT),
        u(seq as u128),
        u(seq as u128),
        Field::Word(leaf),
    ]);
    let report = abi_tuple(&[tuple(&[
        tuple(&[empty(), empty()]),
        empty(),
        Field::Tail(abi_array(vec![root])),
        empty(),
    ])]);
    let ctx = word(seq as u128);
    let digest = keccak(&[&keccak(&[&report]), &COMMIT_DIGEST, &ctx]);
    let sigs: Vec<_> = lane.commit_signers[..2]
        .iter()
        .map(|k| ocr_sign(k, &digest))
        .collect();
    let mut raw_vs = [0u8; 32];
    for (i, s) in sigs.iter().enumerate() {
        raw_vs[i] = s.2;
    }
    let rs: Vec<[u8; 32]> = sigs.iter().map(|s| s.0).collect();
    let ss: Vec<[u8; 32]> = sigs.iter().map(|s| s.1).collect();
    evm.ok(
        DEPLOYER,
        lane.offramp,
        calldata(
            "commit(bytes32[2],bytes,bytes32[],bytes32[],bytes32)",
            &[
                Field::Word(COMMIT_DIGEST),
                Field::Word(ctx),
                bytes(&report),
                statics(rs.len(), &rs),
                statics(ss.len(), &ss),
                Field::Word(raw_vs),
            ],
        ),
        "commit",
    );

    // `message` is `abi.encode(Any2EVMRampMessage)`: an offset word, then the
    // tuple the execution report embeds.
    let exec = abi_tuple(&[
        u(TENZRO_SELECTOR as u128),
        Field::Tail(abi_array(vec![message[32..].to_vec()])),
        Field::Tail(abi_array(vec![abi_array(vec![abi_bytes(&[])])])),
        empty(),
        u(0),
    ]);
    let report = abi_tuple(&[Field::Tail(abi_array(vec![exec]))]);
    let r = evm.ok(
        DEPLOYER,
        lane.offramp,
        calldata(
            "execute(bytes32[2],bytes)",
            &[Field::Word(EXEC_DIGEST), Field::Word(ctx), bytes(&report)],
        ),
        "execute",
    );
    let topic =
        keccak(&[b"ExecutionStateChanged(uint64,uint64,bytes32,bytes32,uint8,bytes,uint256)"]);
    let log = r
        .logs
        .iter()
        .find(|l| l.topics.first().map(Vec::as_slice) == Some(&topic[..]))
        .expect("the OffRamp reports the execution");
    // data: messageHash, state, returnData offset, gasUsed; state 2 is
    // SUCCESS. The OffRamp's hash of the message is the committed leaf.
    assert_eq!(log.data[..32], leaf);
    assert_eq!(
        log.data[63],
        2,
        "message execution failed: 0x{}",
        hex::encode(&log.data)
    );
}

#[test]
fn published_ccip_contracts_carry_the_route_envelope_both_ways() {
    let eth = EVM_CHAINS.iter().find(|c| c.name == "ethereum").unwrap();
    let mut evm = Evm::new();
    let lane = deploy_lane(&mut evm, eth.selector, &lane_limits(), OUTFLOW);
    let route = route_for(&lane, eth.selector);
    route.validate().unwrap();

    // The pool enforces the route's lane limits, each direction mirrored.
    let pool_out = evm.ok(
        DEPLOYER,
        lane.pool,
        calldata(
            "getCurrentOutboundRateLimiterState(uint64)",
            &[u(TENZRO_SELECTOR as u128)],
        ),
        "outbound limiter",
    );
    assert_eq!(
        u128::from_be_bytes(pool_out.output[3 * 32 + 16..4 * 32].try_into().unwrap()),
        route.lane_limits.unwrap().inbound.capacity
    );

    // Receive: Tenzro locks 5 TNZO and the OffRamp executes the framework's
    // message; the pool mints 5 to the holder on the EVM.
    let f = RouteFramework::new();
    let mut s = MemState::with(std::slice::from_ref(&route));
    let out = f
        .send_outbound(
            &mut s,
            "ethereum",
            &OutboundTransfer {
                sender: [0x77; 32].to_vec(),
                recipient: EVM_HOLDER.to_vec(),
                amount: 5 * ONE,
                asset: None,
            },
        )
        .unwrap();
    let leaf = any2evm_leaf(&route, &out.message);
    commit_and_execute(&mut evm, &lane, leaf, out.message.sequence, &out.bytes);
    assert_eq!(evm.balance_of(lane.token, EVM_HOLDER), 5 * ONE);
    assert_eq!(
        evm.total_supply(lane.token),
        read_supply(&s, &route).bridged
    );

    // Send: the holder returns 2 through the Router; the OnRamp's message is
    // admitted by the framework, which releases 2 to the Tenzro recipient.
    evm.ok(
        DEPLOYER,
        lane.link,
        calldata(
            "transfer(address,uint256)",
            &[a(&EVM_HOLDER), u(1_000 * ONE)],
        ),
        "fund fees",
    );
    for token in [lane.link, lane.token] {
        evm.ok(
            EVM_HOLDER,
            token,
            calldata("approve(address,uint256)", &[a(&lane.router), u(u128::MAX)]),
            "approve",
        );
    }
    let mut extra_args = vec![0x18, 0x1d, 0xcf, 0x10];
    extra_args.extend_from_slice(&abi_tuple(&[u(0), u(1)]));
    let message = tuple(&[
        bytes(&addr_word(&TENZRO_HOLDER)),
        bytes(&[]),
        statics(1, &[addr_word(&lane.token), word(2 * ONE)]),
        a(&lane.link),
        bytes(&extra_args),
    ]);
    let sent = evm.ok(
        EVM_HOLDER,
        lane.router,
        calldata(
            "ccipSend(uint64,(bytes,bytes,(address,uint256)[],address,bytes))",
            &[u(TENZRO_SELECTOR as u128), message],
        ),
        "ccipSend",
    );
    let event = sent
        .logs
        .iter()
        .find(|l| l.address.as_slice() == lane.onramp && l.topics.len() == 3)
        .expect("CCIPMessageSent");
    let seq = u64::from_be_bytes(event.topics[2][24..].try_into().unwrap());
    let delivery = deliver(
        &route,
        &Signers {
            committee: committee(1, 5, 3).0,
            blessing: committee(40, 5, 3).0,
        },
        3,
        seq,
        NOW_MS + 60_000,
        &event.data,
        &[],
    );
    let admitted = f
        .admit_inbound(&mut s, BridgeRouteAdapter::Ccip, "ethereum", &delivery)
        .expect("the framework admits the OnRamp's message");
    assert_eq!(admitted.message.amount, 2 * ONE);
    assert_eq!(
        admitted.message.receiver,
        addr_word(&TENZRO_HOLDER).to_vec()
    );
    assert_eq!(evm.balance_of(lane.token, EVM_HOLDER), 3 * ONE);
    assert_eq!(evm.total_supply(lane.token), 3 * ONE);
    assert_eq!(read_supply(&s, &route).bridged, 3 * ONE);
    assert_eq!(
        lane::lane_bucket(&s, &route, LaneDirection::Inbound)
            .unwrap()
            .tokens,
        398 * ONE
    );

    // The same delivery again is a replay.
    assert!(
        f.admit_inbound(&mut s, BridgeRouteAdapter::Ccip, "ethereum", &delivery)
            .is_err()
    );
    // A payload altered after the OnRamp emitted it no longer carries the
    // OnRamp's message id.
    let mut r = canonical::Reader::new(&event.data);
    let mut altered = evm::Evm2AnyMessage::read(&mut r).unwrap();
    altered.header.sequence = seq + 1;
    altered.token_amounts[0].amount = 3 * ONE;
    let forged = altered.encode();
    let d = deliver(
        &route,
        &Signers {
            committee: committee(1, 5, 3).0,
            blessing: committee(40, 5, 3).0,
        },
        3,
        seq + 1,
        NOW_MS + 60_000,
        &forged,
        &[],
    );
    let refused = f
        .admit_inbound(&mut s, BridgeRouteAdapter::Ccip, "ethereum", &d)
        .unwrap_err();
    assert!(refused.to_string().contains("message id"), "{refused}");
}
