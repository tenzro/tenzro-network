//! Standardized compute claims in consensus state.
//!
//! A provider writes a claim against hour-aligned terms — hardware class,
//! region, first hour, number of hours, strike per hour — and posts
//! collateral. A buyer pays the total strike. Both amounts sit in a vault
//! derived from the claim id that nobody holds a key to.
//!
//! A claim names the compute bond (or, for storage, the storage stake) that
//! delivers it, which the writer must own. Each hour settles on the SLA
//! verdict validators froze for that bond and hour: available pays the writer
//! that hour's strike less the settlement fee, and records the hour as a
//! compute lease, or as storage served for a claim that keeps an object
//! retrievable; unavailable refunds it to the holder and makes them
//! whole for the hour from the writer's collateral; no verdict within
//! `MARKET_SUBMIT_WINDOW` hours refunds it with no penalty. Whatever
//! collateral is left returns to the writer once every hour is settled. A claim is the payment for capacity
//! a bonded provider delivers; trading, pledging or cash-settling claims is an
//! application built over them, not part of the protocol.
//!
//! Anyone may send `Settle`: the outcome is fixed by committed state, so it
//! does not matter who asks.

use super::*;
use tenzro_types::transaction::ComputeClaimOp;

/// Selector for every claim operation; the payload names which.
pub const SELECTOR_COMPUTE_CLAIM: [u8; 4] = [0x01, 0x00, 0x00, 0x75];

/// Gas for one claim operation.
pub const GAS_COMPUTE_CLAIM: u64 = 80_000;

/// Log topic for every claim transition; the data carries the claim.
pub const COMPUTE_CLAIM_TOPIC: &[u8] = b"ComputeClaim";

/// Most hours one claim may cover (a year).
pub const MAX_CLAIM_EPOCHS: u64 = 24 * 366;

/// Where a claim is in its life.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum ClaimState {
    /// Written, awaiting a buyer.
    Offered,
    /// Bought; settling.
    Held,
    /// Every hour settled.
    Delivered,
    /// Withdrawn before anyone bought it.
    Cancelled,
    /// Nobody bought it before delivery; the collateral returned.
    Lapsed,
}

/// A compute claim, as stored.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ClaimRecord {
    pub claim_id: String,
    /// Hex of the writer's address.
    pub writer: String,
    /// Hex of the holder's address, once bought.
    pub holder: Option<String>,
    pub hardware_class: u8,
    pub region: String,
    pub delivery_start_ms: i64,
    pub epochs: u64,
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub strike_per_epoch: u128,
    /// The compute bond or storage stake delivering the claim.
    pub provider_did: String,
    /// Hex SHA-256 of the object descriptor a storage claim keeps
    /// retrievable.
    #[serde(default)]
    pub storage_descriptor: Option<String>,
    /// The registered unit the reserved capacity is stated in, for a claim
    /// on metered capacity.
    #[serde(default)]
    pub unit: Option<String>,
    /// Units of `unit` reserved per hour.
    #[serde(default, with = "tenzro_types::primitives::u128_serde")]
    pub units_per_epoch: u128,
    /// Hours settled so far.
    pub epochs_settled: u64,
    /// Writer collateral still in the vault.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub collateral: u128,
    /// Holder payment still in the vault.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub payment: u128,
    pub state: ClaimState,
}

impl ClaimRecord {
    /// What a buyer pays.
    pub fn total_strike(&self) -> u128 {
        self.strike_per_epoch.saturating_mul(self.epochs as u128)
    }

    /// When delivery ends (unix ms).
    pub fn delivery_end_ms(&self) -> i64 {
        self.delivery_start_ms
            .saturating_add(MARKET_EPOCH_MS.saturating_mul(self.epochs as i64))
    }
}

fn claim_key(id: &str) -> String {
    format!("cclaim:{}", id)
}

fn party_key(addr_hex: &str) -> String {
    format!("cclaim_party:{}", addr_hex)
}

/// The address a claim's money sits at. Derived, so nobody holds its key.
pub fn claim_vault(claim_id: &str) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(b"tenzro/compute-claim/vault");
    h.update(claim_id.as_bytes());
    h.finalize().to_vec()
}

/// A claim's id: fixed by its writer and the nonce it was written at.
pub fn claim_id_for(writer: &[u8], nonce: u64) -> String {
    let mut h = Sha256::new();
    h.update(b"tenzro/compute-claim/id");
    h.update(writer);
    h.update(nonce.to_le_bytes());
    hex::encode(h.finalize())
}

/// Read a claim.
pub fn read_claim(state: &dyn VmState, claim_id: &str) -> Option<ClaimRecord> {
    serde_json::from_slice(&state.get_storage(&SYSTEM_ADDRESS, claim_key(claim_id).as_bytes())?)
        .ok()
}

/// Ids of the claims an address has written or held.
pub fn claims_of(state: &dyn VmState, addr: &[u8]) -> Vec<String> {
    state
        .get_storage(&SYSTEM_ADDRESS, party_key(&hex::encode(addr)).as_bytes())
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

/// The held storage claims the SLA subject `provider_did` (a compute bond or
/// a storage stake) delivers in the hour containing `now_ms`: the objects it
/// must prove it keeps retrievable to be found available this hour.
pub fn storage_claims_due(
    state: &dyn VmState,
    provider_did: &str,
    now_ms: i64,
) -> Vec<ClaimRecord> {
    let Some(writer) = super::sla_subject(state, provider_did).map(|s| s.owner) else {
        return Vec::new();
    };
    claims_of(state, &writer)
        .iter()
        .filter_map(|id| read_claim(state, id))
        .filter(|c| {
            c.storage_descriptor.is_some()
                && c.state == ClaimState::Held
                && c.provider_did == provider_did
                && c.delivery_start_ms <= now_ms
                && now_ms < c.delivery_end_ms()
        })
        .collect()
}

fn note_party(
    state: &mut dyn VmState,
    addr_hex: &str,
    claim_id: &str,
    changes: &mut Vec<StateChange>,
) {
    let key = party_key(addr_hex);
    let prior = state.get_storage(&SYSTEM_ADDRESS, key.as_bytes());
    let mut ids: Vec<String> = prior
        .as_ref()
        .and_then(|b| serde_json::from_slice(b).ok())
        .unwrap_or_default();
    if ids.iter().any(|i| i == claim_id) {
        return;
    }
    ids.push(claim_id.to_string());
    let blob = serde_json::to_vec(&ids).unwrap_or_default();
    state.set_storage(&SYSTEM_ADDRESS, key.as_bytes(), blob.clone());
    changes.push(StateChange::new(
        SYSTEM_ADDRESS.to_vec(),
        key.into_bytes(),
        prior,
        Some(blob),
    ));
}

fn write_claim(
    state: &mut dyn VmState,
    claim: &ClaimRecord,
    changes: &mut Vec<StateChange>,
) -> Result<Log> {
    let key = claim_key(&claim.claim_id);
    let prior = state.get_storage(&SYSTEM_ADDRESS, key.as_bytes());
    let blob = serde_json::to_vec(claim)
        .map_err(|e| VmError::Internal(format!("encode compute claim: {}", e)))?;
    state.set_storage(&SYSTEM_ADDRESS, key.as_bytes(), blob.clone());
    changes.push(StateChange::new(
        SYSTEM_ADDRESS.to_vec(),
        key.into_bytes(),
        prior,
        Some(blob.clone()),
    ));
    Ok(Log::new(
        SYSTEM_ADDRESS.to_vec(),
        vec![COMPUTE_CLAIM_TOPIC.to_vec()],
        blob,
    ))
}

/// Move TNZO, or fail without writing.
fn pay(state: &mut dyn VmState, from: &[u8], to: &[u8], amount: u128) -> Result<()> {
    if amount == 0 || from == to {
        return Ok(());
    }
    let from_bal = state.get_balance(from);
    if from_bal < amount {
        return Err(VmError::InsufficientBalance {
            required: amount,
            available: from_bal,
        });
    }
    let to_bal = state
        .get_balance(to)
        .checked_add(amount)
        .ok_or_else(|| VmError::Internal("balance overflow".to_string()))?;
    state.set_balance(from, from_bal - amount);
    state.set_balance(to, to_bal);
    Ok(())
}

fn unhex(addr_hex: &str) -> Vec<u8> {
    hex::decode(addr_hex).unwrap_or_default()
}

fn refuse(msg: impl Into<String>) -> VmError {
    VmError::InvalidTransaction(msg.into())
}

fn load(state: &dyn VmState, claim_id: &str) -> Result<ClaimRecord> {
    read_claim(state, claim_id).ok_or_else(|| refuse(format!("no compute claim '{}'", claim_id)))
}

/// Pay the writer an hour's strike `amount` from the vault as a settlement
/// from the holder: the fee comes out of it like any other settlement's, and
/// the hour is the writer's provider work. Returns the fee's burn part.
fn pay_writer(
    state: &mut dyn VmState,
    claim: &ClaimRecord,
    vault: &[u8],
    writer: &[u8],
    amount: u128,
    changes: &mut Vec<StateChange>,
) -> Result<u128> {
    if amount == 0 {
        return Ok(0);
    }
    let holder = unhex(claim.holder.as_deref().unwrap_or_default());
    let class = if claim.storage_descriptor.is_some() {
        tenzro_token::rewards::WorkClass::StorageServed
    } else {
        tenzro_token::rewards::WorkClass::ComputeLease
    };
    let earning = super::economy::Earning {
        provider: Some(class),
        ..Default::default()
    };
    let payout = super::economy::settle_payout(state, &holder, writer, amount, &earning, changes)?;
    pay(state, vault, writer, payout.credit)?;
    let held = state.get_balance(vault);
    let fee = amount - payout.credit;
    if held < fee {
        return Err(VmError::InsufficientBalance {
            required: fee,
            available: held,
        });
    }
    state.set_balance(vault, held - fee);
    super::economy::count_settlement(state, 1, changes)?;
    Ok(payout.burned)
}

/// Pay the holder.
fn pay_holder(
    state: &mut dyn VmState,
    claim: &ClaimRecord,
    vault: &[u8],
    amount: u128,
) -> Result<()> {
    let holder = unhex(claim.holder.as_deref().unwrap_or_default());
    pay(state, vault, &holder, amount)
}

/// Settle what committed state allows. Returns whether anything moved, and
/// the settlement fees it burned.
fn settle(
    state: &mut dyn VmState,
    claim: &mut ClaimRecord,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
) -> Result<(bool, u128)> {
    let vault = claim_vault(&claim.claim_id);
    let writer = unhex(&claim.writer);
    match claim.state {
        ClaimState::Offered if now_ms >= claim.delivery_start_ms => {
            pay(state, &vault, &writer, claim.collateral)?;
            claim.collateral = 0;
            claim.state = ClaimState::Lapsed;
            Ok((true, 0))
        }
        ClaimState::Held => settle_hours(state, claim, &vault, &writer, now_ms, changes),
        _ => Ok((false, 0)),
    }
}

fn settle_hours(
    state: &mut dyn VmState,
    claim: &mut ClaimRecord,
    vault: &[u8],
    writer: &[u8],
    now_ms: i64,
    changes: &mut Vec<StateChange>,
) -> Result<(bool, u128)> {
    let did = claim.provider_did.clone();
    let now_epoch = (now_ms.max(0) / MARKET_EPOCH_MS) as u64;
    let first = (claim.delivery_start_ms / MARKET_EPOCH_MS) as u64;
    let mut moved = false;
    let mut burned = 0u128;
    while claim.epochs_settled < claim.epochs {
        let hour = first + claim.epochs_settled;
        if hour >= now_epoch {
            break;
        }
        let slice = claim.strike_per_epoch.min(claim.payment);
        match read_sla_verdict(state, &did, hour) {
            Some(v) if v.available => {
                burned += pay_writer(state, claim, vault, writer, slice, changes)?;
            }
            Some(_) => {
                let penalty = claim.strike_per_epoch.min(claim.collateral);
                claim.collateral -= penalty;
                pay_holder(state, claim, vault, slice.saturating_add(penalty))?;
            }
            None if hour + MARKET_SUBMIT_WINDOW < now_epoch => {
                pay_holder(state, claim, vault, slice)?;
            }
            None => break,
        }
        claim.payment -= slice;
        claim.epochs_settled += 1;
        moved = true;
    }
    if claim.epochs_settled == claim.epochs {
        pay(state, vault, writer, claim.collateral)?;
        claim.collateral = 0;
        claim.state = ClaimState::Delivered;
    }
    Ok((moved, burned))
}

impl NativeExecutor {
    pub(super) async fn execute_compute_claim(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        let op: ComputeClaimOp = serde_json::from_slice(&tx.data[4..])
            .map_err(|e| refuse(format!("Invalid ComputeClaim payload: {}", e)))?;
        gas_meter.consume(GAS_COMPUTE_CLAIM)?;
        let gas_cost = tx.gas_price.saturating_mul(GAS_COMPUTE_CLAIM as u128);
        let payer = state.get_balance(&tx.from);
        if payer < gas_cost {
            return Err(VmError::InsufficientBalance {
                required: gas_cost,
                available: payer,
            });
        }
        state.set_balance(&tx.from, payer - gas_cost);

        let me = hex::encode(&tx.from);
        let now = deterministic_now_ms(tx);
        let mut changes = Vec::new();
        let mut burned = 0u128;

        let claim = match op {
            ComputeClaimOp::Offer {
                hardware_class,
                region,
                delivery_start_ms,
                epochs,
                strike_per_epoch,
                collateral,
                provider_did,
                storage_descriptor,
                unit,
                units_per_epoch,
            } => {
                match &unit {
                    Some(key) => {
                        tenzro_types::meter::parse_key(key).map_err(|e| refuse(e.to_string()))?;
                        if units_per_epoch == 0 {
                            return Err(refuse("a claim on a unit reserves a positive quantity"));
                        }
                    }
                    None if units_per_epoch != 0 => {
                        return Err(refuse("a quantity needs the unit it is counted in"));
                    }
                    None => {}
                }
                if let Some(d) = &storage_descriptor
                    && (d.len() != 64 || !d.bytes().all(|b| b.is_ascii_hexdigit()))
                {
                    return Err(refuse("storage_descriptor is a 32-byte hex digest"));
                }
                if hardware_class == 0 || hardware_class > 4 {
                    return Err(refuse("a claim must name a known hardware class"));
                }
                if region.len() > 8 || !region.chars().all(|c| c.is_ascii_uppercase()) {
                    return Err(refuse("region must be empty or an upper-case country code"));
                }
                if epochs == 0 || epochs > MAX_CLAIM_EPOCHS || strike_per_epoch == 0 {
                    return Err(refuse(format!(
                        "a claim covers 1 to {} hours at a positive strike",
                        MAX_CLAIM_EPOCHS
                    )));
                }
                if delivery_start_ms % MARKET_EPOCH_MS != 0 || delivery_start_ms <= now {
                    return Err(refuse(
                        "delivery must start on a future hour boundary, so each claim hour is a \
                         chain hour",
                    ));
                }
                let subject = super::sla_subject(state, &provider_did).ok_or_else(|| {
                    refuse(format!(
                        "no compute bond or bonded storage stake for '{}'",
                        provider_did
                    ))
                })?;
                match subject.kind {
                    super::SlaSubjectKind::ComputeBond => {}
                    super::SlaSubjectKind::RoleStake(
                        tenzro_types::network::NetworkRole::StorageProvider,
                    ) if storage_descriptor.is_some() => {}
                    super::SlaSubjectKind::RoleStake(_) => {
                        return Err(refuse(
                            "a role stake delivers storage claims only, from a storage stake; \
                             compute needs a compute bond",
                        ));
                    }
                }
                if subject.owner != tx.from {
                    return Err(refuse(format!(
                        "'{}' is not the sender's to deliver",
                        provider_did
                    )));
                }
                let claim_id = claim_id_for(&tx.from, tx.nonce);
                if read_claim(state, &claim_id).is_some() {
                    return Err(refuse("claim id already in use"));
                }
                pay(state, &tx.from, &claim_vault(&claim_id), collateral)?;
                note_party(state, &me, &claim_id, &mut changes);
                ClaimRecord {
                    claim_id,
                    writer: me.clone(),
                    holder: None,
                    hardware_class,
                    region,
                    delivery_start_ms,
                    epochs,
                    strike_per_epoch,
                    provider_did,
                    storage_descriptor: storage_descriptor.map(|d| d.to_ascii_lowercase()),
                    unit,
                    units_per_epoch,
                    epochs_settled: 0,
                    collateral,
                    payment: 0,
                    state: ClaimState::Offered,
                }
            }
            ComputeClaimOp::Cancel { claim_id } => {
                let mut c = load(state, &claim_id)?;
                if c.writer != me || c.state != ClaimState::Offered {
                    return Err(refuse(
                        "only the writer may cancel, and only before it is bought",
                    ));
                }
                pay(state, &claim_vault(&claim_id), &tx.from, c.collateral)?;
                c.collateral = 0;
                c.state = ClaimState::Cancelled;
                c
            }
            ComputeClaimOp::Accept {
                claim_id,
                max_total,
            } => {
                let mut c = load(state, &claim_id)?;
                if c.state != ClaimState::Offered || now >= c.delivery_start_ms {
                    return Err(refuse("the claim is not on offer"));
                }
                if c.writer == me {
                    return Err(refuse("a writer cannot buy its own claim"));
                }
                let total = c.total_strike();
                if total > max_total {
                    return Err(refuse(format!(
                        "the claim costs {} wei, above the {} this purchase allows",
                        total, max_total
                    )));
                }
                pay(state, &tx.from, &claim_vault(&claim_id), total)?;
                c.payment = total;
                c.holder = Some(me.clone());
                c.state = ClaimState::Held;
                note_party(state, &me, &claim_id, &mut changes);
                c
            }
            ComputeClaimOp::Settle { claim_id } => {
                let mut c = load(state, &claim_id)?;
                let (moved, fees_burned) = settle(state, &mut c, now, &mut changes)?;
                if !moved {
                    return Err(refuse("nothing on this claim is due yet"));
                }
                burned = fees_burned;
                c
            }
            ComputeClaimOp::Transfer { claim_id, to } => {
                let mut c = load(state, &claim_id)?;
                if c.state != ClaimState::Held || c.holder.as_deref() != Some(me.as_str()) {
                    return Err(refuse("only the holder of a held claim may transfer it"));
                }
                let to = to.trim_start_matches("0x").to_ascii_lowercase();
                if to.len() != 64 || !to.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(refuse("to must be a 32-byte hex address"));
                }
                if to == me || to == c.writer {
                    return Err(refuse(
                        "a claim moves to an account other than its holder and writer",
                    ));
                }
                // Hours already due settle to the holder who held them.
                burned = settle(state, &mut c, now, &mut changes)?.1;
                if c.state != ClaimState::Held {
                    return Err(refuse("every hour of the claim has settled"));
                }
                note_party(state, &to, &claim_id, &mut changes);
                c.holder = Some(to);
                c
            }
        };
        let log = write_claim(state, &claim, &mut changes)?;

        changes.insert(
            0,
            StateChange::new(
                tx.from.clone(),
                b"balance".to_vec(),
                Some(payer.to_le_bytes().to_vec()),
                Some(state.get_balance(&tx.from).to_le_bytes().to_vec()),
            ),
        );
        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);
        changes.push(StateChange::new(
            tx.from.clone(),
            b"nonce".to_vec(),
            Some(old_nonce.to_le_bytes().to_vec()),
            Some((old_nonce + 1).to_le_bytes().to_vec()),
        ));
        Ok(
            ExecutionResult::success(gas_meter.final_used(), Vec::new(), vec![log], changes)
                .with_burn(burned),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_adapter::StateAdapter;

    const H: i64 = MARKET_EPOCH_MS;
    const TNZO: u128 = 1_000_000_000_000_000_000;

    fn addr(b: u8) -> Vec<u8> {
        vec![b; 32]
    }

    fn tx(from: &[u8], op: ComputeClaimOp, nonce: u64, now_ms: i64) -> VmTransaction {
        let mut data = SELECTOR_COMPUTE_CLAIM.to_vec();
        data.extend_from_slice(&serde_json::to_vec(&op).unwrap());
        let mut t = VmTransaction::new(
            from.to_vec(),
            None,
            0,
            data,
            200_000,
            0,
            nonce,
            VmType::Tenzro,
            1337,
        );
        t.block_timestamp_ms = Some(now_ms);
        t
    }

    fn offer(provider_did: &str) -> ComputeClaimOp {
        ComputeClaimOp::Offer {
            hardware_class: 3,
            region: "SG".into(),
            delivery_start_ms: 10 * H,
            epochs: 3,
            strike_per_epoch: 100,
            collateral: 150,
            provider_did: provider_did.to_string(),
            storage_descriptor: None,
            unit: None,
            units_per_epoch: 0,
        }
    }

    fn unit_offer(unit: Option<&str>, units_per_epoch: u128) -> ComputeClaimOp {
        match offer("did:gpu") {
            ComputeClaimOp::Offer {
                hardware_class,
                region,
                delivery_start_ms,
                epochs,
                strike_per_epoch,
                collateral,
                provider_did,
                storage_descriptor,
                ..
            } => ComputeClaimOp::Offer {
                hardware_class,
                region,
                delivery_start_ms,
                epochs,
                strike_per_epoch,
                collateral,
                provider_did,
                storage_descriptor,
                unit: unit.map(str::to_string),
                units_per_epoch,
            },
            _ => unreachable!(),
        }
    }

    #[tokio::test]
    async fn a_claim_on_metered_capacity_names_a_unit_and_a_quantity() {
        let (exec, mut state, writer, _buyer) = setup();
        let now = 5 * H;
        for (n, bad) in [
            unit_offer(Some("Warp Drive"), 10),
            unit_offer(Some("output_tokens"), 0),
            unit_offer(None, 10),
        ]
        .into_iter()
        .enumerate()
        {
            assert!(
                exec.execute_transaction(&tx(&writer, bad, n as u64, now), &mut state)
                    .await
                    .is_err()
            );
        }
        exec.execute_transaction(
            &tx(
                &writer,
                unit_offer(Some("output_tokens@class3"), 3_600_000),
                0,
                now,
            ),
            &mut state,
        )
        .await
        .unwrap();
        let c = read_claim(&state, &claim_id_for(&writer, 0)).unwrap();
        assert_eq!(c.unit.as_deref(), Some("output_tokens@class3"));
        assert_eq!(c.units_per_epoch, 3_600_000);
    }

    #[tokio::test]
    async fn a_held_claim_moves_to_a_new_holder_who_is_paid_from_then_on() {
        let (exec, mut state, writer, buyer) = setup();
        let now = 5 * H;
        exec.execute_transaction(&tx(&writer, offer("did:gpu"), 0, now), &mut state)
            .await
            .unwrap();
        let id = claim_id_for(&writer, 0);
        exec.execute_transaction(
            &tx(
                &buyer,
                ComputeClaimOp::Accept {
                    claim_id: id.clone(),
                    max_total: 300,
                },
                0,
                now,
            ),
            &mut state,
        )
        .await
        .unwrap();
        let next = addr(7);
        let transfer = |to: &[u8]| ComputeClaimOp::Transfer {
            claim_id: id.clone(),
            to: hex::encode(to),
        };
        // Only the holder may move it, and not to the writer.
        let stranger = addr(9);
        state.set_balance(&stranger, TNZO);
        assert!(
            exec.execute_transaction(&tx(&stranger, transfer(&next), 0, now), &mut state)
                .await
                .is_err()
        );
        assert!(
            exec.execute_transaction(&tx(&buyer, transfer(&writer), 1, now), &mut state)
                .await
                .is_err()
        );
        exec.execute_transaction(&tx(&buyer, transfer(&next), 1, now), &mut state)
            .await
            .unwrap();
        assert_eq!(
            read_claim(&state, &id).unwrap().holder,
            Some(hex::encode(&next))
        );
        // A missed hour now makes the new holder whole.
        verdict(&mut state, 10, false);
        let before = state.get_balance(&next);
        exec.execute_transaction(
            &tx(
                &stranger,
                ComputeClaimOp::Settle {
                    claim_id: id.clone(),
                },
                0,
                11 * H,
            ),
            &mut state,
        )
        .await
        .unwrap();
        assert!(state.get_balance(&next) > before);
        // The old holder can no longer move it.
        assert!(
            exec.execute_transaction(&tx(&buyer, transfer(&stranger), 2, 11 * H), &mut state)
                .await
                .is_err()
        );
    }

    fn setup() -> (NativeExecutor, StateAdapter, Vec<u8>, Vec<u8>) {
        let exec = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let (writer, buyer) = (addr(1), addr(2));
        state.set_balance(&writer, TNZO);
        state.set_balance(&buyer, TNZO);
        let marker = serde_json::json!({ "provider_address": hex::encode(&writer) });
        state.set_storage(
            &SYSTEM_ADDRESS,
            compute_bond_storage_key("did:gpu").as_bytes(),
            serde_json::to_vec(&marker).unwrap(),
        );
        (exec, state, writer, buyer)
    }

    fn verdict(state: &mut StateAdapter, hour: u64, available: bool) {
        let v = SlaVerdict {
            available,
            up_stake: 1,
            down_stake: 0,
            attesters: 1,
            measured_capacity: None,
        };
        state.set_storage(
            &SYSTEM_ADDRESS,
            format!("sla:{}", sla_bucket("did:gpu", hour)).as_bytes(),
            serde_json::to_vec(&v).unwrap(),
        );
    }

    #[tokio::test]
    async fn a_physical_claim_settles_hour_by_hour_on_sla_verdicts() {
        let (exec, mut state, writer, buyer) = setup();
        let now = 5 * H;
        // Only the bond's owner may write against it.
        assert!(
            exec.execute_transaction(&tx(&buyer, offer("did:gpu"), 0, now), &mut state)
                .await
                .is_err()
        );
        exec.execute_transaction(&tx(&writer, offer("did:gpu"), 0, now), &mut state)
            .await
            .unwrap();
        let id = claim_id_for(&writer, 0);
        let vault = claim_vault(&id);
        assert_eq!(state.get_balance(&vault), 150);

        let accept = |max| ComputeClaimOp::Accept {
            claim_id: id.clone(),
            max_total: max,
        };
        assert!(
            exec.execute_transaction(&tx(&buyer, accept(299), 0, now), &mut state)
                .await
                .is_err()
        );
        exec.execute_transaction(&tx(&buyer, accept(300), 0, now), &mut state)
            .await
            .unwrap();
        assert_eq!(state.get_balance(&vault), 450);

        // Hour 10 up, hour 11 down, hour 12 not yet judged.
        verdict(&mut state, 10, true);
        verdict(&mut state, 11, false);
        let settle = ComputeClaimOp::Settle {
            claim_id: id.clone(),
        };
        let stranger = addr(9);
        exec.execute_transaction(&tx(&stranger, settle.clone(), 0, 13 * H), &mut state)
            .await
            .unwrap();
        let c = read_claim(&state, &id).unwrap();
        assert_eq!((c.epochs_settled, c.payment, c.collateral), (2, 100, 50));
        // The hour judged available pays the writer less the settlement fee.
        let fee = crate::native::economy::settlement_fee(&state, 100);
        assert_eq!(state.get_balance(&writer), TNZO - 150 + 100 - fee);
        assert_eq!(state.get_balance(&buyer), TNZO - 300 + 100 + 100);

        // Nothing more is due until hour 12 is judged, or its window passes.
        assert!(
            exec.execute_transaction(&tx(&stranger, settle.clone(), 1, 13 * H), &mut state)
                .await
                .is_err()
        );
        let late = (13 + MARKET_SUBMIT_WINDOW as i64) * H;
        exec.execute_transaction(&tx(&stranger, settle, 1, late), &mut state)
            .await
            .unwrap();
        let c = read_claim(&state, &id).unwrap();
        assert_eq!(c.state, ClaimState::Delivered);
        assert_eq!(state.get_balance(&vault), 0);
        // Unjudged hour refunded without penalty; leftover collateral back.
        assert_eq!(state.get_balance(&buyer), TNZO - 300 + 300);
        assert_eq!(state.get_balance(&writer), TNZO - 150 + 100 - fee + 50);
    }

    /// Each hour a claim pays its writer is a settlement: it pays the fee,
    /// and it is the writer's provider work, a compute lease, or storage
    /// served for a claim that keeps an object retrievable.
    #[tokio::test]
    async fn a_paid_claim_hour_pays_the_fee_and_records_its_provider_work() {
        use tenzro_token::rewards::WorkClass;
        for (storage, class) in [
            (false, WorkClass::ComputeLease),
            (true, WorkClass::StorageServed),
        ] {
            let (exec, mut state, writer, buyer) = setup();
            state.set_balance(&writer, 1_000 * TNZO);
            state.set_balance(&buyer, 1_000 * TNZO);
            for (who, did) in [
                (&writer, "did:tenzro:human:gpu"),
                (&buyer, "did:tenzro:human:buyer"),
            ] {
                state.set_storage(
                    &SYSTEM_ADDRESS,
                    identity_wallet_index_key(who).as_bytes(),
                    did.as_bytes().to_vec(),
                );
            }
            let mut op = offer("did:gpu");
            if let ComputeClaimOp::Offer {
                strike_per_epoch,
                collateral,
                storage_descriptor,
                ..
            } = &mut op
            {
                *strike_per_epoch = 10 * TNZO;
                *collateral = 15 * TNZO;
                *storage_descriptor = storage.then(|| "ab".repeat(32));
            }
            exec.execute_transaction(&tx(&writer, op, 0, 5 * H), &mut state)
                .await
                .unwrap();
            let id = claim_id_for(&writer, 0);
            let accept = ComputeClaimOp::Accept {
                claim_id: id.clone(),
                max_total: 30 * TNZO,
            };
            exec.execute_transaction(&tx(&buyer, accept, 0, 5 * H), &mut state)
                .await
                .unwrap();
            verdict(&mut state, 10, true);
            let before = state.get_balance(&writer);
            let settle = ComputeClaimOp::Settle { claim_id: id };
            let result = exec
                .execute_transaction(&tx(&addr(9), settle, 0, 11 * H), &mut state)
                .await
                .unwrap();
            let fee = crate::native::economy::settlement_fee(&state, 10 * TNZO);
            assert!(fee > 0);
            assert_eq!(state.get_balance(&writer) - before, 10 * TNZO - fee);
            assert!(result.supply_change < 0, "the fee's burn is declared");
            let rows = crate::native::rewards::pending_work(&state, 0);
            assert_eq!(rows.len(), 1, "{rows:?}");
            assert_eq!(rows[0].class, class);
            assert_eq!(
                rows[0].weight,
                tenzro_types::split::bps_of(fee, 4_000),
                "{rows:?}"
            );
        }
    }

    #[tokio::test]
    async fn an_unbought_claim_lapses_and_a_cancel_returns_collateral() {
        let (exec, mut state, writer, _buyer) = setup();
        exec.execute_transaction(&tx(&writer, offer("did:gpu"), 0, 5 * H), &mut state)
            .await
            .unwrap();
        exec.execute_transaction(&tx(&writer, offer("did:gpu"), 1, 5 * H), &mut state)
            .await
            .unwrap();
        let (a, b) = (claim_id_for(&writer, 0), claim_id_for(&writer, 1));
        exec.execute_transaction(
            &tx(
                &writer,
                ComputeClaimOp::Cancel {
                    claim_id: a.clone(),
                },
                2,
                6 * H,
            ),
            &mut state,
        )
        .await
        .unwrap();
        exec.execute_transaction(
            &tx(
                &addr(9),
                ComputeClaimOp::Settle {
                    claim_id: b.clone(),
                },
                0,
                10 * H,
            ),
            &mut state,
        )
        .await
        .unwrap();
        assert_eq!(read_claim(&state, &a).unwrap().state, ClaimState::Cancelled);
        assert_eq!(read_claim(&state, &b).unwrap().state, ClaimState::Lapsed);
        assert_eq!(state.get_balance(&writer), TNZO);
    }

    #[tokio::test]
    async fn offers_must_start_on_a_future_hour() {
        let (exec, mut state, writer, _) = setup();
        let mut bad = offer("did:gpu");
        if let ComputeClaimOp::Offer {
            delivery_start_ms, ..
        } = &mut bad
        {
            *delivery_start_ms = 10 * H + 1;
        }
        assert!(
            exec.execute_transaction(&tx(&writer, bad, 0, 5 * H), &mut state)
                .await
                .is_err()
        );
        assert!(
            exec.execute_transaction(&tx(&writer, offer("did:gpu"), 0, 11 * H), &mut state)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_storage_claim_is_delivered_by_its_bond() {
        let (exec, mut state, writer, buyer) = setup();
        let digest = "ab".repeat(32);
        let mut bad = offer("did:gpu");
        if let ComputeClaimOp::Offer {
            storage_descriptor, ..
        } = &mut bad
        {
            *storage_descriptor = Some("xyz".into());
        }
        assert!(
            exec.execute_transaction(&tx(&writer, bad, 0, 0), &mut state)
                .await
                .is_err()
        );
        let mut physical = offer("did:gpu");
        if let ComputeClaimOp::Offer {
            storage_descriptor, ..
        } = &mut physical
        {
            *storage_descriptor = Some(digest.to_uppercase());
        }
        exec.execute_transaction(&tx(&writer, physical, 0, 0), &mut state)
            .await
            .unwrap();
        let claim = read_claim(&state, &claim_id_for(&writer, 0)).unwrap();
        assert_eq!(claim.storage_descriptor.as_deref(), Some(digest.as_str()));
        let accept = ComputeClaimOp::Accept {
            claim_id: claim.claim_id.clone(),
            max_total: 300,
        };
        exec.execute_transaction(&tx(&buyer, accept, 0, 0), &mut state)
            .await
            .unwrap();
        assert!(storage_claims_due(&state, "did:gpu", 9 * H).is_empty());
        assert_eq!(storage_claims_due(&state, "did:gpu", 10 * H).len(), 1);
        assert!(storage_claims_due(&state, "did:other", 10 * H).is_empty());
        assert!(storage_claims_due(&state, "did:gpu", 13 * H).is_empty());
    }
}
