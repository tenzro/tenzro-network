//! The chain the economy runs on: the simulated ledger, block by block.
//!
//! Every token movement goes through the VM's own block rules
//! ([`tenzro_sim::ledger::Ledger::execute`]): begin-block duties (governed
//! parameters, rewards, plans, retention), the transactions,
//! fee settlement and the value check. This module only builds blocks,
//! keeps nonces and reads state back.

use std::collections::{BTreeMap, HashMap};

use tenzro_sim::ledger::{self, Envelope, Genesis, Ledger, SimTx, TNZO, TxResult};
use tenzro_vm::traits::VmState;

/// Calendar milliseconds in one hour.
pub const HOUR_MS: i64 = 3_600_000;
/// Calendar milliseconds in one day.
pub const DAY_MS: i64 = 24 * HOUR_MS;

/// Gas a native operation is counted at when filling a block.
pub const NATIVE_GAS_USED: u64 = 150_000;

/// How blocks map onto calendar time.
#[derive(Debug, Clone, Copy)]
pub struct Clock {
    /// Block time between blocks, milliseconds.
    pub block_ms: u64,
    /// Calendar milliseconds per block-time millisecond.
    pub calendar_scale: u64,
    /// Blocks per consensus epoch.
    pub blocks_per_epoch: u64,
}

impl Clock {
    /// One block per calendar hour and one epoch per calendar day: the
    /// clock multi-year runs use.
    pub const HOURLY: Clock = Clock {
        block_ms: 10_000,
        calendar_scale: 360,
        blocks_per_epoch: 24,
    };
    /// Real block time with no compression: the clock fee-market runs use.
    pub const REAL: Clock = Clock {
        block_ms: 500,
        calendar_scale: 1,
        blocks_per_epoch: 7_200,
    };

    /// Calendar milliseconds one block spans.
    pub fn block_calendar_ms(&self) -> i64 {
        (self.block_ms * self.calendar_scale.max(1)) as i64
    }
}

/// What the genesis of a run holds beyond the validators.
#[derive(Debug, Clone)]
pub struct GenesisPlan {
    /// Bonded validators at genesis.
    pub validators: u32,
    /// Registered validators with no bond yet, free to join later.
    pub standby: u32,
    /// Each validator's bond, whole TNZO.
    pub bond_tnzo: u64,
    /// Liquid balance of every validator and every population account, whole TNZO.
    pub balance_tnzo: u64,
    /// Population accounts (ids from `USER_BASE`).
    pub users: u32,
    /// Starting balance of the treasury, whole TNZO.
    pub treasury_tnzo: u64,
    /// Starting balance of the insurance pool, whole TNZO.
    pub insurance_tnzo: u64,
    /// Starting balance of the running-cost reserve, whole TNZO; zero is a
    /// valid launch.
    pub reserve_tnzo: u64,
    /// Further accounts funded at genesis from the supply the treasury and
    /// the others leave: (account, whole TNZO), added to what the account
    /// already holds.
    pub opening_accounts: Vec<([u8; 32], u64)>,
    /// Starting values of governed parameters that differ from the registry.
    pub network_params: BTreeMap<String, u64>,
}

/// The account that holds the part of the fixed supply no simulated
/// participant holds, so genesis allocates exactly the maximum supply.
/// It is account [`RESERVE`], one past the population accounts, so it can
/// send: it stands for everyone outside the simulation who sells TNZO to
/// the people and agents in it.
pub fn reserve_account() -> [u8; 32] {
    ledger::account(RESERVE)
}

/// Account id of the reserve.
pub const RESERVE: u32 = 2_000_000;

/// The simulated chain.
pub struct Chain {
    /// The ledger.
    pub ledger: Ledger,
    /// The clock.
    pub clock: Clock,
    pending: Vec<Envelope>,
    /// The transactions as the populations wrote them, in block order.
    written: Vec<SimTx>,
    pending_gas: u64,
    nonces: HashMap<u32, u64>,
    validators: u32,
    /// Most gas one block carries; what a block builder stops at.
    pub block_gas_cap: u64,
}

impl Chain {
    /// Builds genesis.
    pub fn new(plan: &GenesisPlan, clock: Clock) -> Self {
        let max_supply: u128 = 1_000_000_000 * TNZO;
        let held = |n: u64| n as u128 * TNZO;
        let validators = plan.validators + plan.standby;
        let named = held(plan.balance_tnzo) * (validators as u128 + plan.users as u128)
            + held(plan.bond_tnzo) * plan.validators as u128
            + held(plan.treasury_tnzo)
            + held(plan.insurance_tnzo)
            + held(plan.reserve_tnzo)
            + plan
                .opening_accounts
                .iter()
                .map(|(_, n)| held(*n))
                .sum::<u128>()
            + tenzro_token::NETWORK_REWARDS_POOL;
        assert!(
            named <= max_supply,
            "genesis allocates more than the fixed supply"
        );
        let mut accounts = vec![(reserve_account(), max_supply - named)];
        if plan.treasury_tnzo > 0 {
            accounts.push((
                tenzro_vm::native::derive_treasury_address().0,
                held(plan.treasury_tnzo),
            ));
        }
        if plan.insurance_tnzo > 0 {
            accounts.push((
                tenzro_vm::native::insurance::pool_address().0,
                held(plan.insurance_tnzo),
            ));
        }
        if plan.reserve_tnzo > 0 {
            accounts.push((
                tenzro_vm::native::reserve_address().0,
                held(plan.reserve_tnzo),
            ));
        }
        for (addr, n) in &plan.opening_accounts {
            accounts.push((*addr, held(*n)));
        }
        let g = Genesis {
            active: plan.validators,
            standby: plan.standby,
            users: plan.users,
            bond_tnzo: plan.bond_tnzo,
            balance_tnzo: plan.balance_tnzo,
            calendar_scale: clock.calendar_scale,
            epoch_ms: clock.block_ms * clock.blocks_per_epoch,
            network_params: plan.network_params.clone(),
            accounts,
            strict_supply: true,
        };
        let ledger = Ledger::genesis(&g);
        let target = ledger.param(tenzro_vm::ledger::COMPUTE_TARGET_PARAM);
        Self {
            ledger,
            clock,
            pending: Vec::new(),
            written: Vec::new(),
            pending_gas: 0,
            nonces: HashMap::new(),
            validators,
            block_gas_cap: target.saturating_mul(2),
        }
    }

    /// Height of the last executed block.
    pub fn height(&self) -> u64 {
        self.ledger.height()
    }

    /// Consensus epoch of the next block.
    pub fn epoch(&self) -> u64 {
        (self.height() + 1) / self.clock.blocks_per_epoch.max(1)
    }

    /// Calendar time of the last executed block.
    pub fn now_ms(&self) -> i64 {
        self.ledger.calendar_ms
    }

    /// The next nonce of `id` for a transaction queued now.
    pub fn next_nonce(&mut self, id: u32) -> u64 {
        let ledger = &self.ledger;
        let n = self.nonces.entry(id).or_insert_with(|| ledger.nonce(id));
        let out = *n;
        *n += 1;
        out
    }

    /// Nonce of the last transaction queued for `id` this block.
    pub fn last_nonce(&self, id: u32) -> u64 {
        self.nonces.get(&id).map_or(0, |n| n.saturating_sub(1))
    }

    /// Queues a transaction built with the sender's next nonce. Returns
    /// false when the block is full (the builder would leave it out).
    pub fn submit(&mut self, from: u32, gas: u64, build: impl FnOnce(u64) -> SimTx) -> bool {
        // A builder fills a block by the gas transactions use, which for a
        // native operation is far below its limit.
        let used = gas.min(NATIVE_GAS_USED);
        if self.pending_gas.saturating_add(used) > self.block_gas_cap {
            return false;
        }
        let nonce = self.next_nonce(from);
        self.pending_gas += used;
        let tx = build(nonce);
        let priced = priced(tx.clone(), self.gas_price());
        self.written.push(tx);
        self.pending.push(Envelope {
            submitted_ms: self.ledger.calendar_ms.max(0) as u64,
            tx: priced,
        });
        true
    }

    /// Queues a native call.
    #[allow(clippy::too_many_arguments)]
    pub fn call(
        &mut self,
        from: u32,
        to: Option<[u8; 32]>,
        value: u128,
        selector: [u8; 4],
        payload: &[u8],
        gas: u64,
        max_fee: Option<u128>,
    ) -> bool {
        let mut data = selector.to_vec();
        data.extend_from_slice(payload);
        self.submit(from, gas, |nonce| SimTx::Call {
            from,
            to,
            value,
            data,
            gas,
            max_fee,
            nonce,
        })
    }

    /// Queues a value transfer.
    pub fn transfer(&mut self, from: u32, to: u32, amount: u128, max_fee: Option<u128>) -> bool {
        self.submit(from, 21_000, |nonce| SimTx::Call {
            from,
            to: Some(ledger::account(to)),
            value: amount,
            data: Vec::new(),
            gas: 21_000,
            max_fee,
            nonce,
        })
    }

    /// Executes the queued transactions as the next block and returns
    /// their results in order.
    pub fn produce(&mut self) -> Vec<TxResult> {
        let height = self.height() + 1;
        let epoch = height / self.clock.blocks_per_epoch.max(1);
        let ts = height * self.clock.block_ms;
        // Blocks rotate over the bonded validators, as the active set
        // proposes on chain; a validator that has left proposes nothing.
        let bonded: Vec<u32> = self
            .ledger
            .bonds_now()
            .iter()
            .enumerate()
            .filter(|(_, b)| **b > 0)
            .map(|(v, _)| v as u32)
            .collect();
        let proposer = if bonded.is_empty() {
            (height % self.validators.max(1) as u64) as u32
        } else {
            bonded[(height % bonded.len() as u64) as usize]
        };
        let mut content = [0u8; 32];
        content[..8].copy_from_slice(&height.to_be_bytes());
        let txs = std::mem::take(&mut self.pending);
        self.pending_gas = 0;
        self.ledger.execute(
            height, content, content, 1, proposer, epoch, ts, proposer, txs,
        );
        self.nonces.clear();
        let mut results = std::mem::take(&mut self.ledger.results);
        for (r, tx) in results.iter_mut().zip(std::mem::take(&mut self.written)) {
            r.tx = tx;
        }
        results
    }

    /// Read-only view of chain state.
    pub fn state(&self) -> &dyn VmState {
        self.ledger.state()
    }

    /// Balance of an address.
    pub fn balance_of(&self, addr: &[u8]) -> u128 {
        self.state().get_balance(addr)
    }

    /// The gas price a wallet bids: twice the base fee, and never below the
    /// VM's fixed minimum gas price, which a bid of the base fee alone falls
    /// under once the USD-priced base fee is worth less than it in TNZO.
    pub fn gas_price(&self) -> u128 {
        self.base_fee().saturating_mul(2).max(min_gas_price())
    }

    /// Base fee per unit of gas the next block charges, TNZO base units.
    pub fn base_fee(&self) -> u128 {
        tenzro_vm::ledger::block_base_fee(self.state())
    }

    /// A governed parameter's value in force.
    pub fn param(&self, key: &str) -> u64 {
        self.ledger.param(key)
    }
}

/// A snapshot of the economy at one instant.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct Snapshot {
    /// Calendar day.
    pub day: f64,
    /// Total supply, TNZO.
    pub supply: f64,
    /// Burned since genesis, TNZO.
    pub burned: f64,
    /// Treasury balance, TNZO.
    pub treasury: f64,
    /// Insurance pool balance, TNZO.
    pub insurance_pool: f64,
    /// Running-cost reserve balance, TNZO.
    pub reserve: f64,
    /// Rewards pool balance, TNZO.
    pub rewards_pool: f64,
    /// Total bonded validator stake, TNZO.
    pub bonded: f64,
    /// Validators with a bond.
    pub bonded_validators: u32,
    /// Base fee, TNZO per unit of gas.
    pub base_fee: f64,
    /// Insurance claims paid so far.
    pub claims_paid: u64,
    /// Insurance paid out so far, TNZO.
    pub claims_total: f64,
    /// Insurance credited from fees so far, TNZO.
    pub pool_from_fees: f64,
}

/// TNZO base units as a float of whole TNZO.
pub fn tnzo(x: u128) -> f64 {
    x as f64 / TNZO as f64
}

impl Chain {
    /// Reads a snapshot.
    pub fn snapshot(&self, genesis_supply: u128) -> Snapshot {
        let s = self.state();
        let supply = self.ledger.total_supply();
        let totals = tenzro_vm::native::insurance::read_totals(s);
        let bonds = self.ledger.bonds_now();
        Snapshot {
            day: self.now_ms() as f64 / DAY_MS as f64,
            supply: tnzo(supply),
            burned: tnzo(genesis_supply.saturating_sub(supply)),
            treasury: tnzo(s.get_balance(tenzro_vm::native::derive_treasury_address().as_bytes())),
            insurance_pool: tnzo(
                s.get_balance(tenzro_vm::native::insurance::pool_address().as_bytes()),
            ),
            reserve: tnzo(s.get_balance(tenzro_vm::native::reserve_address().as_bytes())),
            rewards_pool: tnzo(s.get_balance(tenzro_token::rewards_pool_address().as_bytes())),
            bonded: tnzo(bonds.iter().sum()),
            bonded_validators: bonds.iter().filter(|b| **b > 0).count() as u32,
            base_fee: tnzo(self.base_fee()),
            claims_paid: totals.claims_paid,
            claims_total: tnzo(totals.total_paid),
            pool_from_fees: tnzo(totals.from_fees),
        }
    }
}

/// Payload of a compute bond posting.
pub fn compute_bond_payload(provider_did: &str, amount: u128) -> Vec<u8> {
    #[derive(serde::Serialize)]
    struct P<'a> {
        provider_did: &'a str,
        amount: u128,
    }
    serde_json::to_vec(&P {
        provider_did,
        amount,
    })
    .expect("payload encodes")
}

/// Payload of a TNZO streaming escrow to `payee` paying `rate` per market
/// epoch for `hours`, created at calendar time `now_ms`.
pub fn stream_escrow_payload(payee: u32, rate: u128, hours: i64, now_ms: i64) -> Vec<u8> {
    #[derive(serde::Serialize)]
    struct P {
        payee: tenzro_types::primitives::Address,
        amount: u128,
        asset_id: tenzro_types::asset::AssetId,
        expires_at: i64,
        release_conditions: tenzro_types::settlement::ReleaseConditions,
    }
    serde_json::to_vec(&P {
        payee: tenzro_types::primitives::Address::new(ledger::account(payee)),
        amount: rate * hours as u128,
        asset_id: tenzro_types::asset::AssetId::tnzo(),
        expires_at: stream_expiry(now_ms, hours),
        release_conditions: tenzro_types::settlement::ReleaseConditions::Stream {
            rate_per_epoch: rate,
            epoch_ms: tenzro_vm::native::MARKET_EPOCH_MS as u64,
        },
    })
    .expect("payload encodes")
}

/// When a stream of `hours` opened at `now_ms` expires.
pub fn stream_expiry(now_ms: i64, hours: i64) -> i64 {
    now_ms + hours * HOUR_MS + HOUR_MS
}

/// The VM's fixed minimum gas price, TNZO base units.
pub fn min_gas_price() -> u128 {
    tenzro_vm::VmConfig::default().min_gas_price
}

/// `tx` as a native call carrying an explicit gas price: the simulated
/// ledger prices its other kinds at twice the base fee, which can fall
/// under the VM's minimum.
fn priced(tx: SimTx, price: u128) -> SimTx {
    use tenzro_vm::native as n;
    let call = |from: u32, data: Vec<u8>, nonce: u64| SimTx::Call {
        from,
        to: None,
        value: 0,
        data,
        gas: crate::economy::NATIVE_GAS,
        max_fee: Some(price),
        nonce,
    };
    match tx {
        SimTx::Call {
            from,
            to,
            value,
            data,
            gas,
            max_fee,
            nonce,
        } => SimTx::Call {
            from,
            to,
            value,
            data,
            gas,
            max_fee: Some(max_fee.unwrap_or(price)),
            nonce,
        },
        SimTx::Propose {
            from,
            action,
            nonce,
        } => {
            let mut d = n::SELECTOR_GOVERNANCE_PROPOSE.to_vec();
            d.extend_from_slice(&action);
            call(from, d, nonce)
        }
        SimTx::Vote {
            from,
            proposal,
            nonce,
        } => {
            let me = ledger::account(from);
            let mut d = n::SELECTOR_GOVERNANCE_VOTE.to_vec();
            d.extend_from_slice(&proposal);
            d.push(1);
            d.push(me.len() as u8);
            d.extend_from_slice(&me);
            call(from, d, nonce)
        }
        SimTx::Execute {
            from,
            proposal,
            nonce,
        } => {
            let mut d = n::SELECTOR_GOVERNANCE_EXECUTE.to_vec();
            d.extend_from_slice(&proposal);
            call(from, d, nonce)
        }
        SimTx::IncreaseStake {
            from,
            amount,
            nonce,
        } => {
            let mut d = n::SELECTOR_INCREASE_VALIDATOR_STAKE.to_vec();
            d.extend_from_slice(&amount.to_le_bytes());
            call(from, d, nonce)
        }
        SimTx::Exit { from, nonce } => call(from, n::SELECTOR_VALIDATOR_EXIT.to_vec(), nonce),
        other => other,
    }
}
