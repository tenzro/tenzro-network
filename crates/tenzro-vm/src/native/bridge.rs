//! Transfers and messages over governed bridge routes, in chain state.
//!
//! The route framework ([`tenzro_bridge::route::RouteFramework`]) runs here,
//! inside block execution, against [`VmRouteState`]: a delivery's nonce, a
//! route's epoch mint total and supply record, outbound sequences and light
//! client heads are all written under the governed-state address, and the
//! value they account for moves in the same transaction:
//!
//! - an outbound transfer locks the sender's TNZO in the route's vault
//!   ([`route_vault`]), the supply record's `locked` total;
//! - an inbound delivery on a TNZO route releases locked TNZO from that vault
//!   to the recipient, against representation returned from the external
//!   chain; on a deposit route it issues the route family's deposit asset
//!   ([`deposit_asset`]) in the token ledger;
//! - a route's carried asset (a listed external token such as USDC, held in
//!   the route's vault on the external chain) is issued 1:1 as its
//!   representation in the token ledger on the way in and burned on the way
//!   back ([`issue_representation`]); the token ledger is what the EVM and SVM
//!   views of the token read.
//!
//! Routes themselves, their circuit breakers and the network mint limits are
//! governance's; this module only reads them.

use std::sync::OnceLock;

use sha2::{Digest, Sha256};
use tenzro_bridge::BridgeError;
use tenzro_bridge::route::state::RouteState;
use tenzro_bridge::route::{BridgeRoute, MintRateLimit, OutboundTransfer, RouteFramework};
use tenzro_types::bridge_route::{BridgeRouteAdapter, CarriedAsset, ChainFamily};
use tenzro_types::bridge_transfer::BridgeOp;

use super::funding::{move_balance, refuse};
use super::*;

/// Selector of `Bridge`.
pub const SELECTOR_BRIDGE: [u8; 4] = [0x01, 0x00, 0x00, 0x82];
/// Gas for a bridge operation, before its payload.
pub const GAS_BRIDGE: u64 = 150_000;
/// Gas per payload byte (delivery, update or message body).
pub const GAS_BRIDGE_BYTE: u64 = 16;
/// Topic of the log every bridge operation emits.
pub const BRIDGE_TOPIC: &[u8] = b"Bridge";

/// Gas a bridge operation is charged.
pub fn bridge_gas(op: &BridgeOp) -> u64 {
    GAS_BRIDGE + GAS_BRIDGE_BYTE * op.payload_len() as u64
}

/// The route framework every validator runs: every transport family and
/// every light client, with no configuration of its own.
pub fn route_framework() -> &'static RouteFramework {
    static FRAMEWORK: OnceLock<RouteFramework> = OnceLock::new();
    FRAMEWORK.get_or_init(|| RouteFramework::new().with_all_light_clients())
}

/// The keyless account holding the TNZO locked for `route`.
pub fn route_vault(route: &BridgeRoute) -> Vec<u8> {
    Sha256::new()
        .chain_update(b"tenzro/bridge/route-vault")
        .chain_update(route.storage_key().as_bytes())
        .finalize()
        .to_vec()
}

/// The asset a deposit route of one family issues on Tenzro.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepositAsset {
    /// Token id in the token ledger.
    pub token_id: [u8; 32],
    /// Display name.
    pub name: &'static str,
    /// Ticker symbol.
    pub symbol: &'static str,
    /// Decimals: the external chain's smallest unit is one unit.
    pub decimals: u8,
}

const DEPOSIT_ASSETS: &[(ChainFamily, &str, &str, u8)] = &[(
    ChainFamily::Bitcoin,
    "Bitcoin (deposit route)",
    tenzro_types::bridge_route::BITCOIN_DEPOSIT_UNIT,
    8,
)];

/// The deposit asset of `family`, if deposit routes of that family exist. Its
/// id is fixed by the family, and only an admitted deposit issues it.
pub fn deposit_asset(family: ChainFamily) -> Option<DepositAsset> {
    let (_, name, symbol, decimals) = DEPOSIT_ASSETS.iter().find(|(f, ..)| *f == family)?;
    let token_id: [u8; 32] = Sha256::new()
        .chain_update(b"tenzro/bridge/deposit-asset/")
        .chain_update(family.as_str().as_bytes())
        .finalize()
        .into();
    Some(DepositAsset {
        token_id,
        name,
        symbol,
        decimals: *decimals,
    })
}

/// The deposit asset whose unit (ticker) is `unit`, if any family issues one.
pub fn deposit_asset_of_unit(unit: &str) -> Option<DepositAsset> {
    let (family, ..) = DEPOSIT_ASSETS
        .iter()
        .find(|(_, _, symbol, _)| *symbol == unit)?;
    deposit_asset(*family)
}

/// The account a deposit asset's ledger record names as issuer: an account
/// no key controls, since only an admitted deposit issues the asset.
pub(crate) fn deposit_issuer() -> Vec<u8> {
    Sha256::new()
        .chain_update(b"tenzro/bridge/deposit-issuer")
        .finalize()
        .to_vec()
}

/// Chain state as the route framework sees it, inside one transaction.
pub struct VmRouteState<'a> {
    state: &'a mut dyn VmState,
    chain_id: u64,
    now_ms: i64,
    epoch: u64,
    changes: Vec<StateChange>,
    ignore_network_outflow: bool,
}

impl<'a> VmRouteState<'a> {
    /// The view over `state` for chain `chain_id` at `now_ms` in `epoch`.
    pub fn new(state: &'a mut dyn VmState, chain_id: u64, now_ms: i64, epoch: u64) -> Self {
        Self {
            state,
            chain_id,
            now_ms,
            epoch,
            changes: Vec::new(),
            ignore_network_outflow: false,
        }
    }

    /// The same view with no network outflow cap: every other check of an
    /// exit, for one that queues because the cap is spent this epoch.
    pub fn ignoring_network_outflow(mut self) -> Self {
        self.ignore_network_outflow = true;
        self
    }

    /// The writes made through this view.
    pub fn into_changes(self) -> Vec<StateChange> {
        self.changes
    }
}

impl RouteState for VmRouteState<'_> {
    fn local_chain_id(&self) -> u64 {
        self.chain_id
    }

    fn now_ms(&self) -> i64 {
        self.now_ms
    }

    fn epoch(&self) -> u64 {
        self.epoch
    }

    fn route(&self, adapter: BridgeRouteAdapter, chain: &str) -> Option<BridgeRoute> {
        read_bridge_route(self.state, adapter, chain)
    }

    fn stopped(
        &self,
        route: &BridgeRoute,
    ) -> Option<(tenzro_types::bridge_route::BridgeRouteMode, String)> {
        super::bridge_circuit::bridge_route_stop_at(
            self.state,
            route.adapter,
            &route.source_chain,
            self.now_ms,
        )
    }

    fn network_limit(&self, route: &BridgeRoute) -> Option<MintRateLimit> {
        read_bridge_mint_limits(self.state).map(|l| l.for_route(route))
    }

    fn outflow_limits(&self) -> Option<tenzro_types::bridge_route::NetworkOutflowLimits> {
        let mut limits = super::security::outflow_limits_in_force(self.state)?;
        if self.ignore_network_outflow {
            for cap in &mut limits.caps {
                cap.per_epoch = u128::MAX;
            }
        }
        Some(limits)
    }

    fn get(&self, key: &str) -> Option<Vec<u8>> {
        self.state
            .get_storage(&GOVERNED_STATE_ADDRESS, key.as_bytes())
            .filter(|v| !v.is_empty())
    }

    fn apply(&mut self, writes: Vec<(String, Vec<u8>)>) -> std::result::Result<(), BridgeError> {
        if writes.iter().any(|(_, v)| v.is_empty()) {
            return Err(BridgeError::InvalidParameter(
                "an empty value reads as absent; route state never writes one".into(),
            ));
        }
        for (key, value) in writes {
            let prior = self
                .state
                .get_storage(&GOVERNED_STATE_ADDRESS, key.as_bytes());
            self.state
                .set_storage(&GOVERNED_STATE_ADDRESS, key.as_bytes(), value.clone());
            self.changes.push(StateChange::new(
                GOVERNED_STATE_ADDRESS.to_vec(),
                key.into_bytes(),
                prior,
                Some(value),
            ));
        }
        Ok(())
    }
}

fn route_refused(e: BridgeError) -> VmError {
    refuse(format!("refused by the route: {e}"))
}

fn supply_json(supply: &tenzro_bridge::route::state::SupplyRecord) -> serde_json::Value {
    serde_json::json!({
        "locked": supply.locked.to_string(),
        "bridged": supply.bridged.to_string(),
    })
}

/// Issue `amount` of the representation `id` to `receiver`, defining it on
/// first use as an asset only the bridge issues. A representation already
/// defined under other metadata is refused, so two routes cannot issue one
/// token id with different decimals.
#[allow(clippy::too_many_arguments)]
pub fn issue_representation(
    state: &mut dyn VmState,
    id: &[u8; 32],
    name: &str,
    symbol: &str,
    decimals: u8,
    receiver: &[u8],
    amount: u128,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    if let Some(existing) = crate::token_ledger::read_token(state, id)
        && (existing.symbol != symbol
            || existing.decimals != decimals
            || existing.creator != deposit_issuer())
    {
        return Err(refuse(format!(
            "token {} is not the bridge's {symbol} representation",
            hex::encode(id)
        )));
    }
    let record = crate::token_ledger::TokenRecord {
        name: name.to_string(),
        symbol: symbol.to_string(),
        decimals,
        total_supply: 0,
        creator: deposit_issuer(),
        max_supply: None,
        powers: tenzro_types::token_policy::PowerManifest {
            mint: tenzro_types::token_policy::Authority::Issuer,
            ..tenzro_types::token_policy::PowerManifest::NONE
        },
        policy: tenzro_types::token_policy::TokenPolicy::default(),
        council: None,
        reserve_backing: None,
        pending: None,
    };
    crate::token_ledger::define(state, id, &record, changes)?;
    crate::token_ledger::mint(state, id, receiver, amount, now_ms, changes)
}

/// Burn `amount` of the representation `id` from `sender`'s free balance.
fn retire_representation(
    state: &mut dyn VmState,
    id: &[u8; 32],
    sender: &[u8],
    amount: u128,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    crate::token_ledger::burn(state, id, sender, amount, changes)
}

/// Records what a TNZO route's vault owes: the TNZO its supply record says
/// is locked for the route, read after the transfer updated it.
fn record_route_owed(state: &mut dyn VmState, route: &BridgeRoute) {
    let locked = state
        .get_storage(
            &GOVERNED_STATE_ADDRESS,
            tenzro_bridge::route::state::supply_key(route).as_bytes(),
        )
        .and_then(|b| b.get(..16).and_then(|l| <[u8; 16]>::try_from(l).ok()))
        .map(u128::from_be_bytes)
        .unwrap_or(0);
    crate::invariant_monitor::record_owed(
        state,
        crate::invariant_monitor::GuardedModule::Bridge,
        &route_vault(route),
        &crate::token_ledger::tnzo_id(),
        locked,
    );
}

/// Credit an admitted inbound transfer: release locked TNZO on a TNZO route,
/// issue the deposit asset on a deposit route, or issue a carried asset's
/// representation. Returns the asset's id.
fn credit_inbound(
    state: &mut dyn VmState,
    route: &BridgeRoute,
    asset: Option<&CarriedAsset>,
    receiver: &[u8],
    amount: u128,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
) -> Result<[u8; 32]> {
    crate::invariant_monitor::require_unfrozen(
        state,
        crate::invariant_monitor::GuardedModule::Bridge,
    )?;
    if let Some(a) = asset {
        let id = a.representation_id();
        issue_representation(
            state, &id, &a.name, &a.symbol, a.decimals, receiver, amount, now_ms, changes,
        )?;
        return Ok(id);
    }
    if route.adapter != BridgeRouteAdapter::Deposit {
        move_balance(state, &route_vault(route), receiver, amount, changes)?;
        record_route_owed(state, route);
        return Ok(crate::token_ledger::tnzo_id());
    }
    let d = deposit_asset(route.family)
        .ok_or_else(|| refuse("the route's family has no deposit asset"))?;
    issue_representation(
        state,
        &d.token_id,
        d.name,
        d.symbol,
        d.decimals,
        receiver,
        amount,
        now_ms,
        changes,
    )?;
    Ok(d.token_id)
}

/// Debit an outbound transfer: lock TNZO in the route's vault, or retire the
/// deposit asset (deposit route) or carried asset's representation the
/// transfer pays out on the external chain.
fn debit_outbound(
    state: &mut dyn VmState,
    route: &BridgeRoute,
    asset: Option<&CarriedAsset>,
    sender: &[u8],
    amount: u128,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    crate::invariant_monitor::require_unfrozen(
        state,
        crate::invariant_monitor::GuardedModule::Bridge,
    )?;
    if let Some(a) = asset {
        return retire_representation(state, &a.representation_id(), sender, amount, changes);
    }
    if route.adapter != BridgeRouteAdapter::Deposit {
        move_balance(state, sender, &route_vault(route), amount, changes)?;
        record_route_owed(state, route);
        return Ok(());
    }
    let d = deposit_asset(route.family)
        .ok_or_else(|| refuse("the route's family has no deposit asset"))?;
    retire_representation(state, &d.token_id, sender, amount, changes)
}

/// Send an exit now: check it against its route, send it, and debit the
/// sender. `at` is the chain id, block time and epoch.
#[allow(clippy::too_many_arguments)]
fn exit_now(
    state: &mut dyn VmState,
    at: (u64, i64, u64),
    sender: &[u8],
    chain: &str,
    recipient: &[u8],
    amount: u128,
    asset: Option<&String>,
    changes: &mut Vec<StateChange>,
) -> Result<serde_json::Value> {
    let (chain_id, now, epoch) = at;
    let framework = route_framework();
    let mut view = VmRouteState::new(state, chain_id, now, epoch);
    match asset {
        Some(symbol) => framework.check_redeem(&view, chain, symbol, amount),
        None => framework.check_outbound(&view, chain, amount),
    }
    .map_err(route_refused)?;
    let sent = framework
        .send_outbound(
            &mut view,
            chain,
            &OutboundTransfer {
                sender: sender.to_vec(),
                recipient: recipient.to_vec(),
                amount,
                asset: asset.cloned(),
            },
        )
        .map_err(route_refused)?;
    changes.extend(view.into_changes());
    debit_outbound(
        state,
        &sent.route,
        sent.asset.as_ref(),
        sender,
        amount,
        changes,
    )?;
    Ok(serde_json::json!({
        "route": sent.route.storage_key(),
        "message_id": hex::encode(sent.message.message_id),
        "sequence": sent.message.sequence,
        "message": hex::encode(&sent.bytes),
        "from": hex::encode(sender),
        "amount": amount.to_string(),
        "target_chain": chain,
        "asset": sent.asset.as_ref().map(|a| a.symbol.clone()),
        "recipient": hex::encode(recipient),
        "supply": supply_json(&sent.supply),
    }))
}

impl NativeExecutor {
    /// Handle `Bridge`.
    pub(super) fn execute_bridge(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        let op: BridgeOp = serde_json::from_slice(&tx.data[4..])
            .map_err(|e| refuse(format!("Invalid Bridge payload: {e}")))?;
        op.validate().map_err(refuse)?;
        let gas = bridge_gas(&op);
        gas_meter.consume(gas)?;
        let cost = tx.gas_price.saturating_mul(u128::from(gas));
        let balance = state.get_balance(&tx.from);
        if balance < cost {
            return Err(VmError::InsufficientBalance {
                required: cost,
                available: balance,
            });
        }
        state.set_balance(&tx.from, balance - cost);
        let mut changes = vec![StateChange::new(
            tx.from.clone(),
            b"balance".to_vec(),
            Some(balance.to_le_bytes().to_vec()),
            Some((balance - cost).to_le_bytes().to_vec()),
        )];
        let now = deterministic_now_ms(tx);
        let epoch = read_reward_state(state)?.current_epoch;
        let framework = route_framework();

        let (kind, out) = match &op {
            BridgeOp::Inbound {
                adapter,
                source_chain,
                delivery,
            } => {
                let mut view = VmRouteState::new(state, tx.chain_id, now, epoch);
                let admitted = framework
                    .admit_inbound(
                        &mut view,
                        *adapter,
                        &source_chain.to_ascii_lowercase(),
                        delivery,
                    )
                    .map_err(route_refused)?;
                changes.extend(view.into_changes());
                let receiver: [u8; 32] =
                    admitted
                        .message
                        .receiver
                        .as_slice()
                        .try_into()
                        .map_err(|_| {
                            refuse("the message's receiver is not a 32-byte Tenzro account")
                        })?;
                let amount = admitted.message.amount;
                let asset = credit_inbound(
                    state,
                    &admitted.route,
                    admitted.asset.as_ref(),
                    &receiver,
                    amount,
                    deterministic_now_ms(tx),
                    &mut changes,
                )?;
                (
                    "inbound",
                    serde_json::json!({
                        "asset": hex::encode(asset),
                        "route": admitted.route.storage_key(),
                        "message_id": hex::encode(admitted.message.message_id),
                        "sequence": admitted.message.sequence,
                        "to": hex::encode(receiver),
                        "amount": amount.to_string(),
                        "sender": hex::encode(&admitted.message.sender),
                        "minted_this_epoch": admitted.usage.minted.to_string(),
                        "remaining_this_epoch": admitted.usage.remaining.to_string(),
                        "supply": supply_json(&admitted.supply),
                    }),
                )
            }
            BridgeOp::Outbound {
                target_chain,
                recipient,
                amount,
                asset,
            } => {
                let chain = target_chain.to_ascii_lowercase();
                let (route, carried, capacity, over_cap) = {
                    let view = VmRouteState::new(state, tx.chain_id, now, epoch);
                    let (route, carried) = match asset {
                        Some(symbol) => {
                            let (route, a) = framework
                                .route_for_asset(&view, &chain, symbol)
                                .map_err(route_refused)?;
                            (route, Some(a))
                        }
                        None => (
                            framework
                                .route_for_chain(&view, &chain)
                                .map_err(route_refused)?,
                            None,
                        ),
                    };
                    // An exit the network outflow cap cannot carry this epoch
                    // queues, after every other check, instead of failing.
                    let unit = tenzro_bridge::route::exit_unit(&route, carried.as_ref())
                        .map_err(route_refused)?;
                    let over_cap = tenzro_bridge::route::state::outflow_usage(&view, &unit)
                        .is_some_and(|u| u.remaining < *amount)
                        .then_some(unit);
                    let view = if over_cap.is_some() {
                        view.ignoring_network_outflow()
                    } else {
                        view
                    };
                    match asset {
                        Some(symbol) => framework.check_redeem(&view, &chain, symbol, *amount),
                        None => framework.check_outbound(&view, &chain, *amount),
                    }
                    .map_err(route_refused)?;
                    let capacity = carried
                        .as_ref()
                        .map_or(route.outflow.capacity, |a| a.outflow.capacity);
                    (route, carried, capacity, over_cap)
                };
                if let Some(unit) = over_cap {
                    super::bridge_exit::check_queue_room(state, &unit, *amount)?;
                    (
                        "exit_queued",
                        super::bridge_exit::queue(
                            state,
                            &route,
                            carried.as_ref(),
                            &tx.from,
                            &chain,
                            recipient,
                            *amount,
                            now,
                            false,
                            &mut changes,
                        )?,
                    )
                } else if super::bridge_exit::waits(state, *amount, capacity) {
                    (
                        "exit_queued",
                        super::bridge_exit::queue(
                            state,
                            &route,
                            carried.as_ref(),
                            &tx.from,
                            &chain,
                            recipient,
                            *amount,
                            now,
                            true,
                            &mut changes,
                        )?,
                    )
                } else {
                    (
                        "outbound",
                        exit_now(
                            state,
                            (tx.chain_id, now, epoch),
                            &tx.from,
                            &chain,
                            recipient,
                            *amount,
                            asset.as_ref(),
                            &mut changes,
                        )?,
                    )
                }
            }
            BridgeOp::ReleaseExit { id } => {
                let exit = super::bridge_exit::release(state, *id, now, &mut changes)?;
                let mut out = exit_now(
                    state,
                    (tx.chain_id, now, epoch),
                    &exit.sender,
                    &exit.target_chain,
                    &exit.recipient,
                    exit.amount,
                    exit.asset.as_ref(),
                    &mut changes,
                )?;
                out["exit_id"] = serde_json::json!(id);
                ("exit_released", out)
            }
            BridgeOp::CancelExit { id } => (
                "exit_cancelled",
                super::bridge_exit::cancel(state, *id, &tx.from, now, &mut changes)?,
            ),
            BridgeOp::LightClientUpdate {
                adapter,
                source_chain,
                update,
            } => {
                let chain = source_chain.to_ascii_lowercase();
                let mut view = VmRouteState::new(state, tx.chain_id, now, epoch);
                let head = framework
                    .advance_light_client(&mut view, *adapter, &chain, update)
                    .map_err(|e| refuse(format!("refused by the light client: {e}")))?;
                changes.extend(view.into_changes());
                (
                    "light_client",
                    serde_json::json!({
                        "route": tenzro_types::bridge_route::bridge_route_storage_key(*adapter, &chain),
                        "head": head,
                    }),
                )
            }
            BridgeOp::AdmitMessage {
                adapter,
                source_chain,
                delivery,
            } => {
                let mut view = VmRouteState::new(state, tx.chain_id, now, epoch);
                let (route, body) = framework
                    .publish_message(
                        &mut view,
                        *adapter,
                        &source_chain.to_ascii_lowercase(),
                        delivery,
                    )
                    .map_err(route_refused)?;
                changes.extend(view.into_changes());
                (
                    "message_in",
                    serde_json::json!({
                        "route": route.storage_key(),
                        "body": hex::encode(body),
                    }),
                )
            }
            BridgeOp::DrawCommittee {
                adapter,
                source_chain,
            } => (
                "draw_committee",
                super::bridge_committee::draw(
                    state,
                    *adapter,
                    &source_chain.to_ascii_lowercase(),
                    now,
                    &mut changes,
                )?,
            ),
            BridgeOp::ReportWrongHandover {
                adapter,
                source_chain,
                signed_by_set,
                set_index,
                members,
                threshold,
                expires_at_secs,
                signature,
            } => {
                let handover = super::bridge_committee::SignedHandover {
                    signed_by_set: *signed_by_set,
                    set_index: *set_index,
                    members: members.as_chunks::<20>().0.to_vec(),
                    threshold: *threshold,
                    expires_at_secs: *expires_at_secs,
                    signature: signature
                        .as_slice()
                        .try_into()
                        .map_err(|_| refuse("a handover signature is 65 bytes"))?,
                };
                (
                    "wrong_handover",
                    super::bridge_committee::report_wrong_handover(
                        state,
                        *adapter,
                        &source_chain.to_ascii_lowercase(),
                        tx.chain_id,
                        &handover,
                        now,
                        &mut changes,
                    )?,
                )
            }
            BridgeOp::ReportEquivocation {
                adapter,
                source_chain,
                member,
                first,
                second,
            } => {
                let member: [u8; 20] = member
                    .as_slice()
                    .try_into()
                    .map_err(|_| refuse("a committee member is a 20-byte address"))?;
                (
                    "equivocation",
                    super::bridge_committee::report_equivocation(
                        state,
                        *adapter,
                        &source_chain.to_ascii_lowercase(),
                        member,
                        first,
                        second,
                        now,
                        &mut changes,
                    )?,
                )
            }
            BridgeOp::Ibc { source_chain, msg } => {
                let mut view = VmRouteState::new(state, tx.chain_id, now, epoch);
                let (route, outcome) = framework
                    .handle_ibc(&mut view, &source_chain.to_ascii_lowercase(), msg)
                    .map_err(route_refused)?;
                changes.extend(view.into_changes());
                // A refunded packet's TNZO leaves the route's vault for its
                // sender, as returning TNZO does.
                if let Some((sender, amount)) = outcome.refund {
                    credit_inbound(
                        state,
                        &route,
                        None,
                        &sender,
                        amount,
                        deterministic_now_ms(tx),
                        &mut changes,
                    )?;
                }
                (
                    "ibc",
                    serde_json::json!({
                        "route": route.storage_key(),
                        "message": outcome.kind,
                        "path": hex::encode(&outcome.path),
                        "sequence": outcome.sequence,
                        "refund": outcome.refund.map(|(to, amount)| serde_json::json!({
                            "to": hex::encode(to),
                            "amount": amount.to_string(),
                        })),
                    }),
                )
            }
            BridgeOp::SendMessage {
                target_chain,
                payload,
            } => {
                let chain = target_chain.to_ascii_lowercase();
                let mut view = VmRouteState::new(state, tx.chain_id, now, epoch);
                let sent = framework
                    .send_message(&mut view, &chain, payload)
                    .map_err(route_refused)?;
                changes.extend(view.into_changes());
                (
                    "message_out",
                    serde_json::json!({
                        "route": sent.route.storage_key(),
                        "sequence": sent.sequence,
                        "message_id": hex::encode(sent.message_id),
                        "message": hex::encode(&sent.bytes),
                        "from": hex::encode(&tx.from),
                    }),
                )
            }
        };
        let data = serde_json::to_vec(&out)
            .map_err(|e| VmError::Internal(format!("encode bridge log: {e}")))?;
        let logs = vec![Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![BRIDGE_TOPIC.to_vec(), kind.as_bytes().to_vec()],
            data.clone(),
        )];
        Ok(ExecutionResult::success(gas, data, logs, changes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_adapter::StateAdapter;

    /// A carried asset's representation is one token-ledger asset, so the
    /// EVM facade and the SVM Token-2022 view both read it; a second route
    /// issuing it adds to the same token.
    #[test]
    fn a_representation_appears_in_every_vm_view() {
        let mut state = StateAdapter::new();
        let mut changes = Vec::new();
        let id = tenzro_types::bridge_route::representation_id("USDC");
        let holder = [0x42u8; 32];
        issue_representation(
            &mut state,
            &id,
            "USD Coin (bridged)",
            "USDC",
            6,
            &holder,
            700,
            0,
            &mut changes,
        )
        .unwrap();
        issue_representation(
            &mut state,
            &id,
            "USD Coin (bridged)",
            "USDC",
            6,
            &holder,
            300,
            0,
            &mut changes,
        )
        .unwrap();
        assert_eq!(crate::token_ledger::balance(&state, &id, &holder), 1_000);

        let facade = crate::evm::token_factory::facade_address(&id);
        let slot = crate::evm::token_factory::facade_slot(&facade);
        let word = crate::evm::precompile_host::state_word(
            &state,
            &crate::precompiles::PRECOMPILE_TOKEN_FACTORY,
            &slot,
        );
        assert_eq!(word, id, "the ERC-20 facade resolves to the representation");
        assert!(
            crate::svm::spl_adapter::mint_extensions(&state, &id).is_some(),
            "SVM mint view"
        );

        // Another decimals under the same symbol is not the representation.
        assert!(
            issue_representation(
                &mut state,
                &id,
                "USD Coin",
                "USDC",
                18,
                &holder,
                1,
                0,
                &mut changes
            )
            .is_err()
        );

        retire_representation(&mut state, &id, &holder, 400, &mut changes).unwrap();
        assert_eq!(crate::token_ledger::balance(&state, &id, &holder), 600);
        assert!(retire_representation(&mut state, &id, &holder, 601, &mut changes).is_err());
    }
}
