//! The ledger the simulated validators execute.
//!
//! Every ordered block runs through the VM's own block rules, in the order a
//! node runs them: governed parameter changes due by the block's epoch,
//! reward accounting, the scheduled begin-block duties, the transactions,
//! fee settlement, the block value rule, then the commit. State lives in an
//! in-memory store.
//!
//! Execution is deterministic, so the block at a height is executed once,
//! when the first validator orders it; every other validator that orders the
//! same content at that height gets the same block hash and state root, and
//! one that orders different content is a safety violation the world
//! records.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tenzro_storage::KvStore;
use tenzro_storage::kv::{CF_ACCOUNTS, MemoryStore};
use tenzro_types::primitives::Address;
use tenzro_vm::governance::ProposalAction;
use tenzro_vm::ledger::{BlockFees, TxOutcome};
use tenzro_vm::native::SYSTEM_ADDRESS;
use tenzro_vm::traits::{VmState, VmType};
use tenzro_vm::types::VmTransaction;
use tenzro_vm::{BlockStmConfig, MultiVmRuntime, StateAdapter, VmConfig};

/// Chain id the simulated network runs under.
pub const CHAIN_ID: u64 = 1337;

/// One TNZO in its smallest unit.
pub const TNZO: u128 = 1_000_000_000_000_000_000;

/// First account id of a user (non-validator) account.
pub const USER_BASE: u32 = 1_000_000;

/// Gas limit of a value transfer.
const TRANSFER_GAS: u64 = 21_000;

/// Gas limit of every other native operation.
const NATIVE_GAS: u64 = 2_000_000;

/// What a client asks the chain to do.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SimTx {
    /// A value transfer between two accounts.
    Transfer {
        /// Payer account id.
        from: u32,
        /// Payee account id.
        to: u32,
        /// Amount.
        amount: u128,
        /// Payer nonce.
        nonce: u64,
    },
    /// A governance proposal, as JSON of the proposal action.
    Propose {
        /// Proposing validator.
        from: u32,
        /// The action, JSON-encoded.
        action: Vec<u8>,
        /// Nonce.
        nonce: u64,
    },
    /// A ballot in favour.
    Vote {
        /// Voting validator.
        from: u32,
        /// Proposal id.
        proposal: Vec<u8>,
        /// Nonce.
        nonce: u64,
    },
    /// Moves a proposal on (closes voting, then enacts after the timelock).
    Execute {
        /// Sender.
        from: u32,
        /// Proposal id.
        proposal: Vec<u8>,
        /// Nonce.
        nonce: u64,
    },
    /// Adds to a registered validator's bond.
    IncreaseStake {
        /// Validator.
        from: u32,
        /// Amount.
        amount: u128,
        /// Nonce.
        nonce: u64,
    },
    /// Starts unbonding, or withdraws once the unbonding period has passed.
    Exit {
        /// Validator.
        from: u32,
        /// Nonce.
        nonce: u64,
    },
    /// Any transaction, passed to the VM as given: a native operation's
    /// selector and payload in `data`, and its own fee cap.
    Call {
        /// Sender.
        from: u32,
        /// Recipient address, if any.
        to: Option<[u8; 32]>,
        /// Value moved.
        value: u128,
        /// Selector and payload.
        data: Vec<u8>,
        /// Gas limit.
        gas: u64,
        /// Gas price; `None` pays twice the block's base fee.
        max_fee: Option<u128>,
        /// Nonce.
        nonce: u64,
    },
    /// Evidence of a validator signing two checkpoints at one index.
    Evidence {
        /// Reporter.
        from: u32,
        /// `bincode` of the evidence.
        evidence: Vec<u8>,
        /// Nonce.
        nonce: u64,
    },
}

impl SimTx {
    /// The account that pays for it.
    pub fn sender(&self) -> u32 {
        match self {
            SimTx::Transfer { from, .. }
            | SimTx::Propose { from, .. }
            | SimTx::Vote { from, .. }
            | SimTx::Execute { from, .. }
            | SimTx::IncreaseStake { from, .. }
            | SimTx::Exit { from, .. }
            | SimTx::Call { from, .. }
            | SimTx::Evidence { from, .. } => *from,
        }
    }

    /// The sender's nonce.
    pub fn nonce(&self) -> u64 {
        match self {
            SimTx::Transfer { nonce, .. }
            | SimTx::Propose { nonce, .. }
            | SimTx::Vote { nonce, .. }
            | SimTx::Execute { nonce, .. }
            | SimTx::IncreaseStake { nonce, .. }
            | SimTx::Exit { nonce, .. }
            | SimTx::Call { nonce, .. }
            | SimTx::Evidence { nonce, .. } => *nonce,
        }
    }
}

/// A transaction as it rides in a batch: the client's submit time travels
/// with it for latency accounting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    /// Submit time, simulated milliseconds.
    pub submitted_ms: u64,
    /// The transaction.
    pub tx: SimTx,
}

/// Account address of account id `id`: validators below [`USER_BASE`],
/// users from it.
pub fn account(id: u32) -> [u8; 32] {
    let mut a = [0u8; 32];
    if id < USER_BASE {
        a[..8].copy_from_slice(&(id as u64 + 1).to_be_bytes());
    } else {
        a[0] = 0xA0;
        a[8..16].copy_from_slice(&(id as u64).to_be_bytes());
    }
    a
}

/// The outcome of one transaction, for the clients that sent it.
#[derive(Debug, Clone)]
pub struct TxResult {
    /// What was sent.
    pub tx: SimTx,
    /// Submit time.
    pub submitted_ms: u64,
    /// Applied (true) or reverted/rejected.
    pub applied: bool,
    /// Output of an applied transaction.
    pub output: Vec<u8>,
    /// Why it did not apply.
    pub error: String,
}

/// One executed height.
#[derive(Debug, Clone, Copy)]
pub struct Executed {
    /// Digest of what was ordered at the height.
    pub content: [u8; 32],
    /// The anchor that ordered it.
    pub anchor: [u8; 32],
    /// Batches it carried: (author, sequence) of each, in order.
    pub batches: u64,
    /// Validator whose ordering executed it first.
    pub first_by: u32,
    /// Block hash reported to consensus.
    pub block: [u8; 32],
    /// State root after the block.
    pub root: [u8; 32],
}

/// Running totals of what the ledger did.
#[derive(Debug, Clone, Default, Serialize)]
pub struct LedgerStats {
    /// Blocks executed.
    pub blocks: u64,
    /// Transactions applied.
    pub applied: u64,
    /// Transactions reverted or rejected.
    pub failed: u64,
    /// Fees collected.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub fees_collected: u128,
    /// Fees burned.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub fees_burned: u128,
    /// Fees credited to the treasury.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub to_treasury: u128,
    /// Fees credited to the insurance pool.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub to_insurance: u128,
    /// Governed parameter changes that took effect.
    pub params_applied: u64,
    /// Blocks the value rule refused.
    pub refused_blocks: u64,
    /// Blocks whose begin-block duties failed.
    pub failed_duties: u64,
}

/// The chain's state machine.
pub struct Ledger {
    rt: tokio::runtime::Runtime,
    runtime: MultiVmRuntime,
    store: Arc<MemoryStore>,
    state: StateAdapter,
    heights: Vec<Executed>,
    first_height: u64,
    bonds: Vec<(u64, Vec<u128>)>,
    validators: u32,
    /// Calendar time of the last executed block.
    pub calendar_ms: i64,
    /// Results not yet handed to the clients.
    pub results: Vec<TxResult>,
    /// Totals.
    pub stats: LedgerStats,
    /// Value-rule breaches: (height, detail).
    pub conservation_failures: Vec<(u64, String)>,
    /// Sum of every balance, carried forward by each block's recorded
    /// balance change and recounted from the store every
    /// [`RECOUNT_EVERY`] blocks.
    held: u128,
    /// Total supply genesis allocated: no later block may exceed it.
    pub genesis_supply: u128,
}

/// Blocks between two recounts of every balance in the store. Each block
/// checks the balances it changed against the supply change it recorded;
/// the recount catches a balance written outside any block's record, and
/// costs as much as the store is large, so it runs once a simulated day
/// instead of every block.
pub const RECOUNT_EVERY: u64 = 24;

/// Genesis of the simulated chain.
#[derive(Debug, Clone)]
pub struct Genesis {
    /// Validators bonded at genesis (ids `0..active`).
    pub active: u32,
    /// Registered validators with no bond yet (ids `active..active+standby`).
    pub standby: u32,
    /// Users (ids from [`USER_BASE`]).
    pub users: u32,
    /// Bond of each active validator, whole TNZO.
    pub bond_tnzo: u64,
    /// Liquid balance of every account, whole TNZO.
    pub balance_tnzo: u64,
    /// Calendar milliseconds per block-time millisecond.
    pub calendar_scale: u64,
    /// Block time of one epoch, milliseconds.
    pub epoch_ms: u64,
    /// Starting values of governed network parameters; a key not listed
    /// starts at its registry value.
    pub network_params: std::collections::BTreeMap<String, u64>,
    /// Further accounts and their balances, in the smallest unit.
    pub accounts: Vec<([u8; 32], u128)>,
    /// Refuse a genesis above the maximum supply, as the node does.
    pub strict_supply: bool,
}

impl Ledger {
    /// Builds the genesis state.
    pub fn genesis(g: &Genesis) -> Self {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        let runtime = rt
            .block_on(MultiVmRuntime::new(VmConfig::default()))
            .expect("VM runtime");
        let store = Arc::new(MemoryStore::new());
        let mut state = StateAdapter::with_storage(store.clone() as Arc<dyn KvStore>);
        let validators = g.active + g.standby;
        let mut total: u128 = 0;
        let mut bonds = Vec::new();
        for v in 0..validators {
            let addr = account(v);
            let bal = g.balance_tnzo as u128 * TNZO;
            state.set_balance(&addr, bal);
            total += bal;
            // What RegisterValidator records, and the operator's identity.
            state.set_storage(
                &SYSTEM_ADDRESS,
                format!("validator_register:{}", hex::encode(addr)).as_bytes(),
                b"registered".to_vec(),
            );
            state.set_storage(
                &SYSTEM_ADDRESS,
                format!("identity_wallet:{}", hex::encode(addr)).as_bytes(),
                format!(
                    "{}{}",
                    tenzro_vm::governance::HUMAN_DID_PREFIX,
                    hex::encode(addr)
                )
                .into_bytes(),
            );
            if v < g.active {
                let key = crate::world::validator_key(v);
                bonds.push((
                    addr,
                    key.fingerprint(),
                    node_key(v),
                    g.bond_tnzo as u128 * TNZO,
                ));
            }
        }
        for u in 0..g.users {
            let addr = account(USER_BASE + u);
            let did = format!(
                "{}{}",
                tenzro_vm::governance::HUMAN_DID_PREFIX,
                hex::encode(addr)
            );
            state.set_storage(
                &SYSTEM_ADDRESS,
                format!("identity_wallet:{}", hex::encode(addr)).as_bytes(),
                did.clone().into_bytes(),
            );
            // Governance has approved every population account as a
            // grantee, so a simulated grant program can pay it.
            state.set_storage(
                &SYSTEM_ADDRESS,
                format!("approved_grantee:{}", hex::encode(addr)).as_bytes(),
                serde_json::to_vec(&serde_json::json!({
                    "class": "developer",
                    "criteria": { "summary": "simulated population", "link": "" },
                    "approved_ms": 0,
                    "proposal_id": "",
                    "revoked": false,
                }))
                .expect("approval record"),
            );
            // The identity record a registration writes, so a population
            // account can be named as an app, agent or tool.
            let record = tenzro_types::identity::RegisterIdentityPayload {
                did: did.clone(),
                identity_type: "human".into(),
                display_name: String::new(),
                controller_pubkey: Vec::new(),
                key_type: "p256".into(),
                wallet_id: String::new(),
                wallet_address: tenzro_types::primitives::Address::new(addr),
                pq_verifying_key: Vec::new(),
                metadata: Default::default(),
                proof: tenzro_types::identity::RegistrationProof::Hardware {
                    signature: tenzro_types::account_signature::CompositeSignature::classical(
                        tenzro_types::account_signature::ClassicalProof::Raw {
                            signature: Vec::new(),
                        },
                    ),
                },
            };
            state.set_storage(
                &SYSTEM_ADDRESS,
                format!("identity:{did}").as_bytes(),
                serde_json::to_vec(&record).expect("identity record"),
            );
            let bal = g.balance_tnzo as u128 * TNZO;
            state.set_balance(&addr, bal);
            total += bal;
        }
        for (addr, bal) in &g.accounts {
            state.set_balance(addr, state.get_balance(addr) + *bal);
            total += *bal;
        }
        // The network rewards pool, funded at genesis as the node funds it.
        let pool = tenzro_token::rewards_pool_address();
        state.set_balance(pool.as_bytes(), tenzro_token::NETWORK_REWARDS_POOL);
        total += tenzro_token::NETWORK_REWARDS_POOL;
        let (entries, bonded) =
            tenzro_vm::native::genesis_validator_bonds(&bonds).expect("genesis bonds");
        for (k, v) in entries {
            state.set_storage(&SYSTEM_ADDRESS, &k, v);
        }
        let vault = tenzro_vm::native::staking_vault_address();
        state.set_balance(&vault, bonded);
        total += bonded;
        let schedule = tenzro_vm::native::genesis_reward_schedule(
            g.epoch_ms.saturating_mul(g.calendar_scale.max(1)),
        )
        .expect("reward schedule");
        state.set_storage(
            &SYSTEM_ADDRESS,
            tenzro_vm::native::REWARD_SCHEDULE_KEY.as_bytes(),
            schedule,
        );
        if g.calendar_scale > 1 {
            let cal = tenzro_vm::native::genesis_calendar(1, g.calendar_scale).expect("calendar");
            state.set_storage(
                &SYSTEM_ADDRESS,
                tenzro_vm::native::CALENDAR_KEY.as_bytes(),
                cal,
            );
        }
        // The simulated governance has opened the yearly grant caps; a
        // scenario that tests them sets its own below.
        for key in [
            "grants.per_grantee_yearly_max_tnzo",
            "treasury.sponsorship_grants_yearly_max_tnzo",
            "sponsorship.yearly_max_tnzo",
        ] {
            tenzro_vm::native::set_genesis_param(&mut state, key, 1_000_000_000);
        }
        for (key, value) in &g.network_params {
            tenzro_vm::native::set_genesis_param(&mut state, key, *value);
        }
        if g.strict_supply {
            tenzro_token::tnzo::check_genesis_supply(total)
                .expect("genesis within the maximum supply");
        }
        state.record_supply_change(total, 0);
        tenzro_vm::ledger::verify_block(&state).expect("genesis conserves value");
        state.commit().expect("genesis commit");
        let mut ledger = Self {
            rt,
            runtime,
            store,
            state,
            heights: Vec::new(),
            first_height: 1,
            bonds: Vec::new(),
            validators,
            calendar_ms: 0,
            results: Vec::new(),
            stats: LedgerStats::default(),
            conservation_failures: Vec::new(),
            held: 0,
            genesis_supply: 0,
        };
        ledger.held = ledger.balances_total();
        ledger.genesis_supply = ledger.state.total_supply();
        let b = ledger.read_bonds();
        ledger.bonds.push((0, b));
        ledger
    }

    fn read_bonds(&self) -> Vec<u128> {
        (0..self.validators)
            .map(|v| tenzro_vm::native::bonded_stake_of(&self.state, &account(v)))
            .collect()
    }

    /// Governance has approved validator `v` as a sponsored operator, as
    /// the chain records an approval, with its machine identity attested.
    pub fn approve_operator(&mut self, v: u32) {
        let addr = account(v);
        let did = format!(
            "{}{}",
            tenzro_vm::governance::HUMAN_DID_PREFIX,
            hex::encode(addr)
        );
        let approval = tenzro_vm::native::payout_gates::OperatorApproval {
            class: tenzro_vm::governance::OperatorClass::Validator,
            criteria: tenzro_vm::governance::OperatorCriteria {
                provider_did: did,
                region: "simulated".into(),
                history_from_epoch: 0,
                history_to_epoch: 0,
                independence: "simulated operator".into(),
                link: String::new(),
            },
            verified_epochs: 0,
            hardware_attested: true,
            approved_ms: 0,
            proposal_id: String::new(),
            revoked: false,
        };
        self.state.set_storage(
            &SYSTEM_ADDRESS,
            format!("approved_operator:{}", hex::encode(addr)).as_bytes(),
            serde_json::to_vec(&approval).expect("approval record"),
        );
    }

    /// Validators attested validator `v` available in each hourly epoch of
    /// `from..=to`, the verdict the chain freezes for a verified hour.
    pub fn record_available(&mut self, v: u32, from: u64, to: u64) {
        let did = format!(
            "{}{}",
            tenzro_vm::governance::HUMAN_DID_PREFIX,
            hex::encode(account(v))
        );
        for epoch in from..=to {
            let verdict = tenzro_vm::native::SlaVerdict {
                available: true,
                up_stake: 100,
                down_stake: 0,
                attesters: 1,
                measured_capacity: None,
            };
            self.state.set_storage(
                &SYSTEM_ADDRESS,
                format!("sla:{epoch}:{did}").as_bytes(),
                serde_json::to_vec(&verdict).expect("verdict"),
            );
        }
    }

    /// The VM state, for readers of pools, bonds and records.
    pub fn state(&self) -> &StateAdapter {
        &self.state
    }

    /// Highest executed height (0 before the first block).
    pub fn height(&self) -> u64 {
        self.first_height + self.heights.len() as u64 - 1
    }

    /// What was executed at `height`, if it was.
    pub fn at(&self, height: u64) -> Option<Executed> {
        if height < self.first_height {
            return None;
        }
        self.heights
            .get((height - self.first_height) as usize)
            .copied()
    }

    /// Bonds of every validator as of the end of `height`.
    pub fn bonds_at(&self, height: u64) -> &[u128] {
        let i = self.bonds.partition_point(|(h, _)| *h <= height);
        &self.bonds[i.saturating_sub(1)].1
    }

    /// Bonds now.
    pub fn bonds_now(&self) -> &[u128] {
        &self.bonds.last().expect("genesis bonds").1
    }

    /// Bytes the ledger's executed-height index holds.
    pub fn index_bytes(&self) -> usize {
        self.heights.len() * std::mem::size_of::<Executed>()
    }

    /// Executes the block at the next height.
    pub fn execute(
        &mut self,
        height: u64,
        content: [u8; 32],
        anchor: [u8; 32],
        batches: u64,
        first_by: u32,
        epoch: u64,
        timestamp_ms: u64,
        proposer: u32,
        txs: Vec<Envelope>,
    ) -> Executed {
        debug_assert_eq!(height, self.height() + 1);
        let prev_root = self.heights.last().map(|e| e.root).unwrap_or([0; 32]);
        let proposer = Address::new(account(proposer));
        let base_fee = tenzro_vm::ledger::block_base_fee(&self.state);
        let cal = tenzro_vm::native::calendar_ms(&self.state, timestamp_ms as i64)
            .unwrap_or(timestamp_ms as i64);
        self.calendar_ms = cal;
        let gas_price = base_fee.saturating_mul(2).max(1);
        let duties = (|| -> tenzro_vm::Result<usize> {
            let applied = tenzro_vm::native::begin_block_params(&mut self.state, epoch)?;
            tenzro_vm::native::begin_block_treasury(&mut self.state, epoch, cal)?;
            tenzro_vm::native::begin_block_rewards(&mut self.state, epoch, &proposer, cal)?;
            tenzro_vm::native::begin_block_plans(&mut self.state, cal)?;
            tenzro_vm::native::begin_block_da_retention(&mut self.state, cal)?;
            Ok(applied.len())
        })();
        let mut fees = BlockFees::default();
        let mut settled = None;
        match duties {
            Err(e) => {
                self.state.rollback();
                self.stats.failed_duties += 1;
                self.conservation_failures
                    .push((height, format!("begin-block duties failed: {e}")));
            }
            Ok(params) => {
                self.stats.params_applied += params as u64;
                let vm_txs: Vec<VmTransaction> = txs
                    .iter()
                    .map(|e| vm_tx(&e.tx, gas_price, cal, height, base_fee))
                    .collect();
                let cfg = BlockStmConfig {
                    workers: 1,
                    ..BlockStmConfig::default()
                };
                let executed = self.rt.block_on(tenzro_vm::parallel::execute_block(
                    &self.runtime,
                    &mut self.state,
                    &vm_txs,
                    base_fee,
                    &mut fees,
                    &cfg,
                ));
                for (env, out) in txs.into_iter().zip(executed) {
                    let (applied, output, error) = match out.outcome {
                        TxOutcome::Applied { result, .. } => {
                            (result.success, result.output, String::new())
                        }
                        TxOutcome::Reverted { reason, .. } => (false, Vec::new(), reason),
                        TxOutcome::Rejected(e) => (false, Vec::new(), e.to_string()),
                    };
                    if applied {
                        self.stats.applied += 1;
                    } else {
                        self.stats.failed += 1;
                    }
                    self.results.push(TxResult {
                        tx: env.tx,
                        submitted_ms: env.submitted_ms,
                        applied,
                        output,
                        error,
                    });
                }
                let s = tenzro_vm::ledger::settle_block(&mut self.state, &fees);
                match tenzro_vm::ledger::verify_executed_block(&self.state) {
                    Ok(()) => settled = Some(s),
                    Err(e) => {
                        self.state.rollback();
                        self.stats.refused_blocks += 1;
                        self.conservation_failures.push((height, e.to_string()));
                    }
                }
            }
        }
        if let Some(s) = &settled {
            self.stats.fees_collected += s.collected;
            self.stats.fees_burned += s.burned;
            self.stats.to_treasury += s.to_treasury;
            self.stats.to_insurance += s.to_insurance;
        }
        let (changed, _) = self.state.pending_block_delta();
        self.state.commit().expect("in-memory commit");
        self.stats.blocks += 1;
        // The whole ledger holds the supply it records.
        self.held = (self.held as i128).saturating_add(changed).max(0) as u128;
        if height.is_multiple_of(RECOUNT_EVERY) {
            let counted = self.balances_total();
            if counted != self.held {
                self.conservation_failures.push((
                    height,
                    format!(
                        "balances recount to {counted} but the blocks recorded changes adding up to {}",
                        self.held
                    ),
                ));
                self.held = counted;
            }
        }
        let held = self.held;
        let supply = self.state.total_supply();
        if held != supply {
            self.conservation_failures.push((
                height,
                format!("balances total {held} but the recorded supply is {supply}"),
            ));
        }
        if supply > self.genesis_supply {
            self.conservation_failures.push((
                height,
                format!(
                    "total supply {supply} is above the genesis supply {}",
                    self.genesis_supply
                ),
            ));
        }
        let b = self.read_bonds();
        if b != *self.bonds_now() {
            self.bonds.push((height, b));
        }
        let mut h = blake3::Hasher::new();
        h.update(&height.to_be_bytes());
        h.update(&content);
        let block = *h.finalize().as_bytes();
        let mut h = blake3::Hasher::new();
        h.update(&prev_root);
        h.update(&block);
        h.update(&supply.to_le_bytes());
        h.update(&held.to_le_bytes());
        h.update(&self.stats.fees_collected.to_le_bytes());
        let root = *h.finalize().as_bytes();
        let e = Executed {
            content,
            anchor,
            batches,
            first_by,
            block,
            root,
        };
        self.heights.push(e);
        e
    }

    /// Sum of every balance the store holds.
    pub fn balances_total(&self) -> u128 {
        self.store
            .scan_prefix(CF_ACCOUNTS, b"balance:")
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(_, v)| <[u8; 16]>::try_from(v.as_slice()).ok())
            .map(u128::from_le_bytes)
            .sum()
    }

    /// Total supply the chain records.
    pub fn total_supply(&self) -> u128 {
        self.state.total_supply()
    }

    /// Balance of account id `id`.
    pub fn balance(&self, id: u32) -> u128 {
        self.state.get_balance(&account(id))
    }

    /// Nonce of account id `id`.
    pub fn nonce(&self, id: u32) -> u64 {
        self.state.get_nonce(&account(id))
    }

    /// A governed parameter's value now.
    pub fn param(&self, key: &str) -> u64 {
        tenzro_vm::native::network_param(&self.state, key)
    }
}

/// The node key a validator registers (any fixed 32 bytes per validator).
pub fn node_key(v: u32) -> [u8; 32] {
    *blake3::hash(&[b"node".as_slice(), &v.to_be_bytes()].concat()).as_bytes()
}

fn vm_tx(tx: &SimTx, gas_price: u128, cal: i64, height: u64, base_fee: u128) -> VmTransaction {
    use tenzro_vm::native as n;
    let (from, to, value, data, gas, nonce) = match tx {
        SimTx::Transfer {
            from,
            to,
            amount,
            nonce,
        } => (
            *from,
            Some(account(*to).to_vec()),
            *amount,
            Vec::new(),
            TRANSFER_GAS,
            *nonce,
        ),
        SimTx::Propose {
            from,
            action,
            nonce,
        } => {
            let mut d = n::SELECTOR_GOVERNANCE_PROPOSE.to_vec();
            d.extend_from_slice(action);
            (*from, None, 0, d, NATIVE_GAS, *nonce)
        }
        SimTx::Vote {
            from,
            proposal,
            nonce,
        } => {
            let me = account(*from);
            let mut d = n::SELECTOR_GOVERNANCE_VOTE.to_vec();
            d.extend_from_slice(proposal);
            d.push(1);
            d.push(me.len() as u8);
            d.extend_from_slice(&me);
            (*from, None, 0, d, NATIVE_GAS, *nonce)
        }
        SimTx::Execute {
            from,
            proposal,
            nonce,
        } => {
            let mut d = n::SELECTOR_GOVERNANCE_EXECUTE.to_vec();
            d.extend_from_slice(proposal);
            (*from, None, 0, d, NATIVE_GAS, *nonce)
        }
        SimTx::IncreaseStake {
            from,
            amount,
            nonce,
        } => {
            let mut d = n::SELECTOR_INCREASE_VALIDATOR_STAKE.to_vec();
            d.extend_from_slice(&amount.to_le_bytes());
            (*from, None, 0, d, NATIVE_GAS, *nonce)
        }
        SimTx::Exit { from, nonce } => (
            *from,
            None,
            0,
            n::SELECTOR_VALIDATOR_EXIT.to_vec(),
            NATIVE_GAS,
            *nonce,
        ),
        SimTx::Call {
            from,
            to,
            value,
            data,
            gas,
            max_fee,
            nonce,
        } => {
            let tx = VmTransaction::new(
                account(*from).to_vec(),
                to.map(|t| t.to_vec()),
                *value,
                data.clone(),
                *gas,
                max_fee.unwrap_or(gas_price),
                *nonce,
                VmType::Tenzro,
                CHAIN_ID,
            );
            return tx
                .with_block_timestamp_ms(cal)
                .with_block_height(height)
                .with_block_base_fee(base_fee);
        }
        SimTx::Evidence {
            from,
            evidence,
            nonce,
        } => {
            let mut d = n::SELECTOR_CHECKPOINT_EQUIVOCATION.to_vec();
            d.extend_from_slice(evidence);
            (*from, None, 0, d, NATIVE_GAS, *nonce)
        }
    };
    VmTransaction::new(
        account(from).to_vec(),
        to,
        value,
        data,
        gas,
        gas_price,
        nonce,
        VmType::Tenzro,
        CHAIN_ID,
    )
    .with_block_timestamp_ms(cal)
    .with_block_height(height)
    .with_block_base_fee(base_fee)
}

/// A governed parameter change, JSON-encoded for [`SimTx::Propose`].
pub fn parameter_change(key: &str, value: u64) -> Vec<u8> {
    serde_json::to_vec(&ProposalAction::ParameterChange {
        key: key.into(),
        value,
        memo: "simulated".into(),
    })
    .expect("action encodes")
}

/// A liquid treasury grant to account `to`, JSON-encoded.
pub fn treasury_grant(to: u32, amount: u128) -> Vec<u8> {
    serde_json::to_vec(&ProposalAction::TreasuryGrant {
        recipient: Address::new(account(to)),
        amount,
        memo: "simulated".into(),
        category: "operations".into(),
        link: String::new(),
        tranches: Vec::new(),
        milestones: vec!["milestone".into()],
        vesting: tenzro_vm::governance::GrantVesting::Liquid,
        asset: None,
        release: Default::default(),
    })
    .expect("action encodes")
}

/// A stable-asset running-cost sponsorship to account `to` for the verified
/// hours `from_epoch..=to_epoch`, JSON-encoded.
pub fn sponsor_stable(
    to: u32,
    from_epoch: u64,
    to_epoch: u64,
    token_id: &str,
    amount: u128,
    period_exception: bool,
) -> Vec<u8> {
    serde_json::to_vec(&ProposalAction::SponsorOperatorStable {
        operator: Address::new(account(to)),
        from_epoch,
        to_epoch,
        token_id: token_id.into(),
        amount,
        period_exception,
        memo: "simulated".into(),
    })
    .expect("action encodes")
}

/// A running-cost payment to account `to` from the reserve, JSON-encoded.
pub fn running_cost_payment(to: u32, amount: u128) -> Vec<u8> {
    serde_json::to_vec(&ProposalAction::RunningCostPayment {
        recipient: Address::new(account(to)),
        from_epoch: 0,
        to_epoch: 0,
        amount,
        memo: "simulated".into(),
        link: String::new(),
    })
    .expect("action encodes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn chain() -> Ledger {
        Ledger::genesis(&Genesis {
            active: 4,
            standby: 0,
            users: 2,
            bond_tnzo: 100_000,
            balance_tnzo: 1_000,
            calendar_scale: 1,
            epoch_ms: 3_600_000,
            network_params: BTreeMap::new(),
            accounts: Vec::new(),
            strict_supply: false,
        })
    }

    fn block(chain: &mut Ledger) {
        let h = chain.height() + 1;
        let mut content = [0u8; 32];
        content[..8].copy_from_slice(&h.to_be_bytes());
        chain.execute(h, content, content, 1, 0, 1, h * 3_600_000, 0, Vec::new());
    }

    #[test]
    fn a_balance_written_outside_any_block_is_found_by_the_recount() {
        let mut chain = chain();
        for _ in 0..RECOUNT_EVERY {
            block(&mut chain);
        }
        assert!(
            chain.conservation_failures.is_empty(),
            "{:?}",
            chain.conservation_failures
        );
        // Value from nowhere, straight into the store: no block records it.
        let key = tenzro_vm::state_adapter::tnzo_balance_key(&account(USER_BASE));
        let was = chain.balance(USER_BASE);
        chain
            .store
            .put(CF_ACCOUNTS, &key, &(was + 7).to_le_bytes())
            .unwrap();
        for _ in 0..RECOUNT_EVERY {
            block(&mut chain);
        }
        assert!(
            chain
                .conservation_failures
                .iter()
                .any(|(_, e)| e.contains("recount")),
            "{:?}",
            chain.conservation_failures
        );
    }

    #[test]
    fn the_carried_total_is_the_recount() {
        let mut chain = chain();
        for _ in 0..3 * RECOUNT_EVERY + 5 {
            block(&mut chain);
        }
        assert!(
            chain.conservation_failures.is_empty(),
            "{:?}",
            chain.conservation_failures
        );
        assert_eq!(chain.held, chain.balances_total());
        assert_eq!(chain.held, chain.total_supply());
    }
}

#[cfg(test)]
mod stats_encoding {
    use super::LedgerStats;

    /// Fee totals in wei pass u64 within decades; the report still encodes.
    #[test]
    fn fee_totals_beyond_u64_encode() {
        let stats = LedgerStats {
            fees_collected: u128::from(u64::MAX) * 1_000,
            ..LedgerStats::default()
        };
        let v = serde_json::to_value(&stats).expect("stats encode");
        assert_eq!(
            v["fees_collected"],
            serde_json::json!((u128::from(u64::MAX) * 1_000).to_string())
        );
    }
}
