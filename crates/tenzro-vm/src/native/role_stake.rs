//! Stake per account per role, in consensus.
//!
//! An account bonds stake for each role it serves (`rpc`, `ai`, `storage`...)
//! with a `Stake` transaction. The bond after a `Bond` must meet the role's
//! required stake for the capacity declared; an `Unbond` moves stake into
//! unbonding, and a `Withdraw` returns it once the governed unbonding period
//! has passed. The validator role is bonded by `RegisterValidator` instead.
//! Bonded stake sits in the role-stake vault, so it is out of the account's
//! balance for as long as it backs the role.

use tenzro_types::network::{NetworkRole, StakeLadder};
use tenzro_types::token::{RoleStake, StakeCapacity, StakeOp};

use super::funding::{read_json, refuse, write_json};
use super::*;

/// Selector of `Stake`.
pub const SELECTOR_STAKE: [u8; 4] = [0x01, 0x00, 0x00, 0x01];
/// Gas for a stake operation.
pub const GAS_STAKE: u64 = 50_000;
/// Topic of the log every stake operation emits.
pub const ROLE_STAKE_TOPIC: &[u8] = b"RoleStake";
/// Governed unbonding period, ms.
pub const UNBONDING_MS_PARAM: &str = "stake.unbonding_ms";
/// Governed key: the TNZO/USD rate, nano-USD per TNZO, at which the bond
/// amounts keep their USD value for a new or raised bond. Below it, at the
/// safety rate, each amount rises so the bond is worth no less in USD; 0
/// turns the floor off.
pub const BOND_FLOOR_RATE_PARAM: &str = "stake.bond_floor_rate_nano_usd";
/// Genesis value of [`BOND_FLOOR_RATE_PARAM`]: the genesis fee rate, so the
/// bonds keep the USD value they start with.
pub const DEFAULT_BOND_FLOOR_RATE_NANO_USD: u64 = super::economy::DEFAULT_TNZO_USD_NANO;
/// Seven days.
pub const DEFAULT_UNBONDING_MS: u64 = 7 * 24 * 60 * 60 * 1000;

/// The vault every role stake is held in.
pub fn role_stake_vault() -> Address {
    let mut hasher = Sha256::new();
    hasher.update(b"tenzro/role-stake/vault");
    Address::new(hasher.finalize().into())
}

fn role_stake_key(account: &[u8], role: NetworkRole) -> String {
    format!("role_stake:{}:{}", hex::encode(account), role.as_str())
}

/// `account`'s stake for `role`, if it ever bonded one.
pub fn read_role_stake(
    state: &dyn VmState,
    account: &[u8],
    role: NetworkRole,
) -> Option<RoleStake> {
    read_json(state, &role_stake_key(account, role))
}

/// Path, under a wallet provider's domain, of the document naming the
/// accounts that bond for that domain: `{"accounts": ["0x<account hex>", ...]}`.
pub const WALLET_PROVIDER_DOCUMENT_PATH: &str = "/.well-known/tenzro-provider";

/// How many closed epochs back a frozen domain-check verdict still counts.
pub const WALLET_PROVIDER_VERDICT_EPOCHS: u64 = 3;

/// Longest RPC provider label a bridge signer declares.
pub const MAX_RPC_PROVIDER_LEN: usize = 128;

/// Refuse a capacity `role` does not declare for `account`: a wallet
/// provider must declare the domain its passkeys are bound to; an attestor
/// may declare a bridge signing key, proven by that key's signature over the
/// account with both its secp256k1 key and its ML-DSA-65 key; no other role
/// declares either.
fn check_capacity(role: NetworkRole, capacity: &StakeCapacity, account: &[u8]) -> Result<()> {
    match (role, capacity) {
        (NetworkRole::WalletProvider, StakeCapacity::Domain(d))
            if tenzro_types::keystore::valid_rp_id(d) =>
        {
            Ok(())
        }
        (NetworkRole::WalletProvider, _) => Err(refuse(
            "a wallet provider bonds for the domain its passkeys are bound to: declare it as a lowercase DNS name",
        )),
        (_, StakeCapacity::Domain(_)) => Err(refuse(format!("the {role} role declares no domain"))),
        (
            NetworkRole::Attestor,
            StakeCapacity::BridgeSigner {
                address,
                rpc_provider,
                proof,
                pq_public_key,
                pq_proof,
            },
        ) => {
            let label = rpc_provider.trim();
            if *address == [0u8; 20] || label.is_empty() || label.len() > MAX_RPC_PROVIDER_LEN {
                return Err(refuse(
                    "a bridge signer names a non-zero address and its RPC provider",
                ));
            }
            let sig: [u8; 65] = proof.as_slice().try_into().map_err(|_| {
                refuse("a bridge signer's proof is a 65-byte recoverable signature")
            })?;
            let digest = tenzro_types::token::bridge_signer_digest(account);
            let set = tenzro_bridge::secp256k1_multisig::ValidatorSet::new(
                vec![*address],
                1,
                "bridge signer",
            );
            if set.valid_signers(&digest, &[(*address, sig)]).is_empty() {
                return Err(refuse(
                    "the bridge signer's proof is not that key's signature over this account",
                ));
            }
            tenzro_crypto::pq::ml_dsa_verify(
                pq_public_key,
                tenzro_types::token::BRIDGE_SIGNER_PQ_CONTEXT,
                &digest,
                pq_proof,
            )
            .map_err(|_| {
                refuse(
                    "a bridge signer declares an ML-DSA-65 key and proves it with that key's signature over this account",
                )
            })?;
            Ok(())
        }
        (_, StakeCapacity::BridgeSigner { .. }) => {
            Err(refuse(format!("the {role} role declares no bridge signer")))
        }
        _ => Ok(()),
    }
}

/// A wallet provider bonded for a domain, with the validators' latest check
/// of that domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletProviderStatus {
    /// The bonding account.
    pub account: Vec<u8>,
    /// Its wallet provider stake.
    pub stake: RoleStake,
    /// The closed epoch of the latest frozen domain-check verdict within
    /// [`WALLET_PROVIDER_VERDICT_EPOCHS`], if there is one.
    pub verdict_epoch: Option<u64>,
    /// Whether that verdict found the domain naming the account. Only then
    /// is the account shown as the domain's staked provider.
    pub verified: bool,
}

/// Every account holding a wallet provider bond for `domain`, verified ones
/// first. Several accounts may declare one domain; the domain names the one
/// it belongs to, so at most the accounts it names verify.
pub fn wallet_providers_for_domain(
    state: &dyn VmState,
    domain: &str,
    now_ms: i64,
) -> Vec<WalletProviderStatus> {
    let role = NetworkRole::WalletProvider;
    let total: RoleStakeTotal = read_json(state, &role_total_key(role)).unwrap_or_default();
    let current = (now_ms.max(0) / MARKET_EPOCH_MS) as u64;
    let mut out: Vec<WalletProviderStatus> = total
        .stakers
        .iter()
        .filter_map(|hex_account| hex::decode(hex_account).ok())
        .filter_map(|account| {
            let stake = read_role_stake(state, &account, role)?;
            if stake.capacity != StakeCapacity::Domain(domain.to_string())
                || !role_bonded(state, &account, role)
            {
                return None;
            }
            let subject = role_stake_subject(&account, role);
            let latest = (1..=WALLET_PROVIDER_VERDICT_EPOCHS)
                .filter_map(|back| current.checked_sub(back))
                .find_map(|epoch| {
                    super::read_sla_verdict(state, &subject, epoch).map(|v| (epoch, v.available))
                });
            Some(WalletProviderStatus {
                account,
                stake,
                verdict_epoch: latest.map(|(e, _)| e),
                verified: latest.is_some_and(|(_, available)| available),
            })
        })
        .collect();
    out.sort_by_key(|s| !s.verified);
    out
}

/// Prefix of the SLA subject a role stake is probed and named under:
/// `did:tenzro:role:<role>:<account hex>`.
pub const ROLE_STAKE_SUBJECT_PREFIX: &str = "did:tenzro:role:";

/// Whether a stake for `role` owes the service it is bonded for, so the
/// validators' SLA probes measure it and an unavailable verdict slashes it.
/// Validators and attestors answer for their bonds through their own
/// evidence (equivocation, settlement disputes). A
/// wallet provider's probe is a check that its declared domain names the
/// bonding account, not a call to a node.
pub fn role_owes_sla(role: NetworkRole) -> bool {
    role.is_provider() || matches!(role, NetworkRole::WalletProvider | NetworkRole::Edge)
}

/// The SLA subject `account`'s stake for `role` is probed under. A storage
/// stake's subject is also the name a storage claim delivered by it carries.
pub fn role_stake_subject(account: &[u8], role: NetworkRole) -> String {
    format!(
        "{ROLE_STAKE_SUBJECT_PREFIX}{}:{}",
        role.as_str(),
        hex::encode(account)
    )
}

/// What can owe an SLA: a compute bond, or a bonded role stake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlaSubjectKind {
    /// A compute bond, by provider DID.
    ComputeBond,
    /// A role stake: the role the account is bonded for.
    RoleStake(NetworkRole),
}

/// One SLA subject as chain state holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlaSubject {
    /// What backs the subject.
    pub kind: SlaSubjectKind,
    /// The account that owns the bond or stake, which answers for it.
    pub owner: Vec<u8>,
    /// The hardware identity key its probe responses must be signed with:
    /// the key registered on chain for the bonded machine DID, or for the
    /// identity of the account that holds the storage stake. `None` while
    /// that identity is not registered: the subject cannot be probed.
    pub identity: Option<tenzro_crypto::CompositePublicKey>,
}

/// Resolve an SLA subject: a compute bond under `subject`, or the bonded
/// role stake [`role_stake_subject`] names. `None` for anything that cannot
/// owe an SLA.
pub fn sla_subject(state: &dyn VmState, subject: &str) -> Option<SlaSubject> {
    if let Some(rest) = subject.strip_prefix(ROLE_STAKE_SUBJECT_PREFIX) {
        let (name, account) = rest.split_once(':')?;
        // One name per subject: only the role's canonical spelling resolves.
        let role = NetworkRole::ALL.into_iter().find(|r| r.as_str() == name)?;
        let owner = hex::decode(account).ok()?;
        // A validator answers for its availability with its validator bond.
        let bonded = if role.is_validator() {
            super::bonded_stake_of(state, &owner) > 0
        } else {
            role_owes_sla(role) && role_bonded(state, &owner, role)
        };
        if !bonded {
            return None;
        }
        let identity = super::identity_did_of(state, &owner)
            .and_then(|did| super::registered_identity_key(state, &did).ok());
        return Some(SlaSubject {
            kind: SlaSubjectKind::RoleStake(role),
            identity,
            owner,
        });
    }
    let marker: serde_json::Value = state
        .get_storage(
            &SYSTEM_ADDRESS,
            compute_bond_storage_key(subject).as_bytes(),
        )
        .and_then(|b| serde_json::from_slice(&b).ok())?;
    let owner = hex::decode(marker.get("provider_address")?.as_str()?).ok()?;
    Some(SlaSubject {
        kind: SlaSubjectKind::ComputeBond,
        identity: super::registered_identity_key(state, subject).ok(),
        owner,
    })
}

/// Stake bonded for one role across every account.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RoleStakeTotal {
    /// Bonded, wei.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub bonded: u128,
    /// Accounts with a bond above zero, hex, in the order they bonded.
    pub stakers: Vec<String>,
}

fn role_total_key(role: NetworkRole) -> String {
    format!("role_stake_total:{}", role.as_str())
}

/// Totals for every role that takes a `Stake` bond.
pub fn role_stake_totals(state: &dyn VmState) -> Vec<(NetworkRole, RoleStakeTotal)> {
    NetworkRole::ALL
        .into_iter()
        .filter(|r| r.requires_bond() && !r.is_validator())
        .map(|r| (r, read_json(state, &role_total_key(r)).unwrap_or_default()))
        .collect()
}

/// Every role `account` has a stake record for.
pub fn role_stakes_of(state: &dyn VmState, account: &[u8]) -> Vec<(NetworkRole, RoleStake)> {
    NetworkRole::ALL
        .into_iter()
        .filter_map(|r| read_role_stake(state, account, r).map(|s| (r, s)))
        .collect()
}

/// A role bond the genesis configures for a non-validator role.
#[derive(Debug, Clone)]
pub struct GenesisRoleBond {
    /// The bonding account.
    pub account: [u8; 32],
    /// The role.
    pub role: NetworkRole,
    /// Bonded, wei.
    pub amount: u128,
    /// The capacity the bond backs.
    pub capacity: tenzro_types::token::StakeCapacity,
    /// The public URL the role is served at, as a `Stake` endpoint
    /// operation would publish it (an edge operator's relay URL).
    pub endpoint: Option<String>,
}

/// The system-storage entries for role stakes bonded at genesis, by the
/// rule a `Stake` bond follows, and the total they put in the role-stake
/// vault. A validator role, a role that takes no bond, a bond below the
/// role's required stake and a second bond for the same account and role are
/// refused.
pub fn genesis_role_bonds(bonds: &[GenesisRoleBond]) -> Result<(Vec<(Vec<u8>, Vec<u8>)>, u128)> {
    let mut state = crate::StateAdapter::new();
    let mut changes = Vec::new();
    let mut total: u128 = 0;
    for b in bonds {
        let role = b.role;
        if role.is_validator() {
            return Err(refuse(
                "the validator role is bonded by the genesis validators",
            ));
        }
        if !role.requires_bond() {
            return Err(refuse(format!("the {role} role takes no bond")));
        }
        check_capacity(role, &b.capacity, &b.account)?;
        if read_role_stake(&state, &b.account, role).is_some() {
            return Err(refuse(format!(
                "0x{} bonds the {role} role twice",
                hex::encode(b.account)
            )));
        }
        let required = role.required_stake(&b.capacity, &StakeLadder::genesis());
        if b.amount == 0 || b.amount < required {
            return Err(refuse(format!(
                "the {role} role requires {required} bonded for that capacity; the genesis bond is {}",
                b.amount
            )));
        }
        if let Some(url) = &b.endpoint {
            tenzro_types::token::check_role_endpoint(url)
                .map_err(|e| refuse(format!("the {role} endpoint: {e}")))?;
        }
        let stake = RoleStake {
            bonded: b.amount,
            capacity: b.capacity.clone(),
            endpoint: b.endpoint.clone(),
            ..Default::default()
        };
        write_role_stake(&mut state, &b.account, role, 0, &stake, &mut changes)?;
        total = total
            .checked_add(b.amount)
            .ok_or_else(|| refuse("the genesis role bonds overflow"))?;
    }
    let mut entries: std::collections::BTreeMap<Vec<u8>, Vec<u8>> =
        std::collections::BTreeMap::new();
    for c in changes {
        if c.address == SYSTEM_ADDRESS.to_vec()
            && let Some(v) = c.new_value
        {
            entries.insert(c.key, v);
        }
    }
    Ok((entries.into_iter().collect(), total))
}

/// Whether `account` holds a bond for `role` that meets the role's required
/// stake, under the bond amounts in force, for the capacity it declared.
pub fn role_bonded(state: &dyn VmState, account: &[u8], role: NetworkRole) -> bool {
    let ladder = stake_ladder(state);
    read_role_stake(state, account, role)
        .is_some_and(|s| s.bonded > 0 && s.bonded >= role.required_stake(&s.capacity, &ladder))
}

/// The bond amounts in force: the governed `stake.*` parameters. A raise
/// waits out the governed tightening grace before it applies, so bonds that
/// met the old amount keep serving while their owners top them up.
pub fn stake_ladder(state: &dyn VmState) -> StakeLadder {
    StakeLadder::from_whole_tnzo(|key| network_param(state, key))
}

/// The bond amounts a new or raised bond, and a validator joining the set,
/// must meet: each amount in force, raised when TNZO is worth less than
/// `stake.bond_floor_rate_nano_usd` at the safety rate, so that it is
/// worth no less in USD than at that rate. A price crash does not make
/// entry cheaper. Bonds already in place keep serving at [`stake_ladder`].
pub fn entry_stake_ladder(state: &dyn VmState) -> StakeLadder {
    let ladder = stake_ladder(state);
    let pin = u128::from(network_param(state, BOND_FLOOR_RATE_PARAM));
    let rate = super::economy::safety_rate(state).max(1);
    if pin <= rate {
        return ladder;
    }
    ladder.map(|v| {
        use revm::primitives::U256;
        let scaled = (U256::from(v) * U256::from(pin)).div_ceil(U256::from(rate));
        u128::try_from(scaled).unwrap_or(u128::MAX)
    })
}

fn move_balance(
    state: &mut dyn VmState,
    from: &[u8],
    to: &[u8],
    amount: u128,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let from_before = state.get_balance(from);
    if from_before < amount {
        return Err(VmError::InsufficientBalance {
            required: amount,
            available: from_before,
        });
    }
    state.set_balance(from, from_before - amount);
    let to_before = state.get_balance(to);
    let to_after = to_before
        .checked_add(amount)
        .ok_or_else(|| VmError::Internal("balance overflow".to_string()))?;
    state.set_balance(to, to_after);
    changes.push(StateChange::new(
        from.to_vec(),
        b"balance".to_vec(),
        Some(from_before.to_le_bytes().to_vec()),
        Some((from_before - amount).to_le_bytes().to_vec()),
    ));
    changes.push(StateChange::new(
        to.to_vec(),
        b"balance".to_vec(),
        Some(to_before.to_le_bytes().to_vec()),
        Some(to_after.to_le_bytes().to_vec()),
    ));
    Ok(())
}

/// Write `account`'s `role` stake and move the role's total by the change in
/// its bonded amount from `bonded_before`.
fn write_role_stake(
    state: &mut dyn VmState,
    account: &[u8],
    role: NetworkRole,
    bonded_before: u128,
    stake: &RoleStake,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    write_json(state, &role_stake_key(account, role), stake, changes)?;
    if stake.bonded != bonded_before {
        let total_key = role_total_key(role);
        let mut total: RoleStakeTotal = read_json(state, &total_key).unwrap_or_default();
        total.bonded = total
            .bonded
            .saturating_sub(bonded_before)
            .saturating_add(stake.bonded);
        let me = hex::encode(account);
        match (bonded_before == 0, stake.bonded == 0) {
            (true, false) => total.stakers.push(me),
            (false, true) => total.stakers.retain(|a| *a != me),
            _ => {}
        }
        write_json(state, &total_key, &total, changes)?;
    }
    Ok(())
}

/// Take `bps` basis points of `account`'s `role` stake, bonded and unbonding,
/// out of the role-stake vault. Returns the amount taken, which the slash
/// path credits to its destination.
pub(super) fn take_role_stake(
    state: &mut dyn VmState,
    account: &[u8],
    role: NetworkRole,
    bps: u16,
    changes: &mut Vec<StateChange>,
) -> Result<u128> {
    let Some(mut stake) = read_role_stake(state, account, role) else {
        return Ok(0);
    };
    let (from_bond, from_unbonding, total) =
        super::staking::slash_split(stake.bonded, stake.unbonding, bps)
            .ok_or_else(|| VmError::Internal("slashed role stake overflows".to_string()))?;
    if total == 0 {
        return Ok(0);
    }
    let vault = role_stake_vault().as_bytes().to_vec();
    let held = state.get_balance(&vault);
    let rest = held
        .checked_sub(total)
        .ok_or(VmError::InsufficientBalance {
            required: total,
            available: held,
        })?;
    state.set_balance(&vault, rest);
    changes.push(StateChange::new(
        vault,
        b"balance".to_vec(),
        Some(held.to_le_bytes().to_vec()),
        Some(rest.to_le_bytes().to_vec()),
    ));
    let bonded_before = stake.bonded;
    stake.bonded -= from_bond;
    stake.unbonding -= from_unbonding;
    write_role_stake(state, account, role, bonded_before, &stake, changes)?;
    Ok(total)
}

/// Take up to `amount` of `account`'s `role` stake, bonded first, then
/// unbonding, out of the role-stake vault. Returns the amount taken, which
/// the caller credits to its destination.
pub(super) fn take_role_stake_amount(
    state: &mut dyn VmState,
    account: &[u8],
    role: NetworkRole,
    amount: u128,
    changes: &mut Vec<StateChange>,
) -> Result<u128> {
    let Some(mut stake) = read_role_stake(state, account, role) else {
        return Ok(0);
    };
    let from_bond = amount.min(stake.bonded);
    let from_unbonding = (amount - from_bond).min(stake.unbonding);
    let total = from_bond + from_unbonding;
    if total == 0 {
        return Ok(0);
    }
    let vault = role_stake_vault().as_bytes().to_vec();
    let held = state.get_balance(&vault);
    let rest = held
        .checked_sub(total)
        .ok_or(VmError::InsufficientBalance {
            required: total,
            available: held,
        })?;
    state.set_balance(&vault, rest);
    changes.push(StateChange::new(
        vault,
        b"balance".to_vec(),
        Some(held.to_le_bytes().to_vec()),
        Some(rest.to_le_bytes().to_vec()),
    ));
    let bonded_before = stake.bonded;
    stake.bonded -= from_bond;
    stake.unbonding -= from_unbonding;
    write_role_stake(state, account, role, bonded_before, &stake, changes)?;
    Ok(total)
}

/// One operator of a role reachable at a published endpoint.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RoleEndpoint {
    /// The staking account, hex.
    pub account: String,
    /// The URL it published.
    pub url: String,
    /// Bonded for the role, wei.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub bonded: u128,
}

/// Every operator of `role` whose bond meets the role's required stake and
/// that published an endpoint, most bonded first (ties by account).
pub fn role_endpoints(state: &dyn VmState, role: NetworkRole) -> Vec<RoleEndpoint> {
    let Some((_, total)) = role_stake_totals(state)
        .into_iter()
        .find(|(r, _)| *r == role)
    else {
        return Vec::new();
    };
    let mut out: Vec<RoleEndpoint> = total
        .stakers
        .iter()
        .filter_map(|account| {
            let raw = hex::decode(account).ok()?;
            let stake = read_role_stake(state, &raw, role)?;
            let url = stake.endpoint.clone()?;
            (stake.bonded > 0
                && stake.bonded >= role.required_stake(&stake.capacity, &stake_ladder(state)))
            .then(|| RoleEndpoint {
                account: account.clone(),
                url,
                bonded: stake.bonded,
            })
        })
        .collect();
    out.sort_by(|a, b| {
        b.bonded
            .cmp(&a.bonded)
            .then_with(|| a.account.cmp(&b.account))
    });
    out
}

/// Bond `amount` of `account`'s `role` stake directly, for tests that need a
/// bonded role without running a `Stake` transaction.
#[cfg(test)]
pub(crate) fn bond_role_for_test(
    state: &mut dyn VmState,
    account: &[u8],
    role: NetworkRole,
    amount: u128,
) {
    let vault = role_stake_vault().as_bytes().to_vec();
    let held = state.get_balance(&vault);
    state.set_balance(&vault, held + amount);
    let stake = RoleStake {
        bonded: amount,
        ..Default::default()
    };
    write_role_stake(state, account, role, 0, &stake, &mut Vec::new()).unwrap();
}

impl NativeExecutor {
    /// Handle `Stake`.
    pub(super) fn execute_stake(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        let op: StakeOp = serde_json::from_slice(&tx.data[4..])
            .map_err(|e| refuse(format!("Invalid Stake payload: {e}")))?;
        gas_meter.consume(GAS_STAKE)?;
        let role = match &op {
            StakeOp::Bond { role, .. }
            | StakeOp::Unbond { role, .. }
            | StakeOp::Withdraw { role }
            | StakeOp::Endpoint { role, .. } => *role,
        };
        if role.is_validator() {
            return Err(refuse("the validator role is bonded by RegisterValidator"));
        }
        if !role.requires_bond() {
            return Err(refuse(format!("the {role} role takes no bond")));
        }
        let cost = tx.gas_price.saturating_mul(u128::from(GAS_STAKE));
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
        let key = role_stake_key(&tx.from, role);
        let mut stake: RoleStake = read_json(state, &key).unwrap_or_default();
        let bonded_before = stake.bonded;
        let vault = role_stake_vault().as_bytes().to_vec();
        let now_ms = deterministic_now_ms(tx);

        let kind = match op {
            StakeOp::Bond {
                amount, capacity, ..
            } => {
                if amount == 0 {
                    return Err(refuse("a bond adds a positive amount"));
                }
                if let Some(key) = crate::governance::role_status_key(role) {
                    super::require_lever_enabled(
                        state,
                        key,
                        &format!("bonding for the {role} role"),
                    )?;
                }
                check_capacity(role, &capacity, &tx.from)?;
                // The domain checks behind a wallet provider's standing were
                // made against the domain it declared, so the domain is fixed
                // for as long as any of the stake is bonded or unbonding.
                if role == NetworkRole::WalletProvider
                    && (stake.bonded > 0 || stake.unbonding > 0)
                    && stake.capacity != capacity
                {
                    return Err(refuse(
                        "a wallet provider's domain changes only once its stake is fully withdrawn",
                    ));
                }
                // A seated bridge committee member signs with the key it was
                // drawn for until its term ends.
                if role == NetworkRole::Attestor
                    && stake.capacity != capacity
                    && super::bridge_committee::seated(state, &tx.from, now_ms)
                {
                    return Err(refuse(
                        "a seated bridge committee member keeps its bridge signer until its term ends",
                    ));
                }
                let bonded = stake
                    .bonded
                    .checked_add(amount)
                    .ok_or_else(|| refuse("the bond overflows"))?;
                let required = role.required_stake(&capacity, &entry_stake_ladder(state));
                if bonded < required {
                    return Err(refuse(format!(
                        "the {role} role requires {required} bonded for that capacity; the bond would be {bonded}"
                    )));
                }
                move_balance(state, &tx.from, &vault, amount, &mut changes)?;
                stake.bonded = bonded;
                stake.capacity = capacity;
                stake.bonded_at_ms = now_ms;
                "bond"
            }
            StakeOp::Unbond { amount, .. } => {
                if role == NetworkRole::Attestor
                    && super::bridge_committee::seated(state, &tx.from, now_ms)
                {
                    return Err(refuse(
                        "a seated bridge committee member stays bonded until its term ends",
                    ));
                }
                if amount == 0 || amount > stake.bonded {
                    return Err(refuse(format!(
                        "unbond 1 to {} of the {role} bond",
                        stake.bonded
                    )));
                }
                let remaining = stake.bonded - amount;
                if remaining > 0
                    && remaining < role.required_stake(&stake.capacity, &stake_ladder(state))
                {
                    return Err(refuse(format!(
                        "what stays bonded for {role} must be zero or meet its required stake"
                    )));
                }
                let period = network_param(state, UNBONDING_MS_PARAM);
                stake.bonded = remaining;
                stake.unbonding = stake.unbonding.saturating_add(amount);
                stake.release_at_ms =
                    now_ms.saturating_add(i64::try_from(period).unwrap_or(i64::MAX));
                "unbond"
            }
            StakeOp::Withdraw { .. } => {
                if stake.unbonding == 0 {
                    return Err(refuse(format!("nothing of the {role} stake is unbonding")));
                }
                if now_ms < stake.release_at_ms {
                    return Err(refuse(format!(
                        "the {role} stake unbonds until {} ms",
                        stake.release_at_ms
                    )));
                }
                move_balance(state, &vault, &tx.from, stake.unbonding, &mut changes)?;
                stake.unbonding = 0;
                stake.release_at_ms = 0;
                "withdraw"
            }
            StakeOp::Endpoint { url, .. } => {
                if url.is_empty() {
                    stake.endpoint = None;
                } else {
                    if stake.bonded == 0 {
                        return Err(refuse(format!(
                            "publish a {role} endpoint after bonding the role"
                        )));
                    }
                    tenzro_types::token::check_role_endpoint(&url).map_err(refuse)?;
                    stake.endpoint = Some(url);
                }
                "endpoint"
            }
        };
        write_role_stake(state, &tx.from, role, bonded_before, &stake, &mut changes)?;
        let data = serde_json::to_vec(&serde_json::json!({
            "op": kind,
            "account": hex::encode(&tx.from),
            "role": role.as_str(),
            "bonded": stake.bonded.to_string(),
            "unbonding": stake.unbonding.to_string(),
            "release_at_ms": stake.release_at_ms,
            "endpoint": stake.endpoint,
        }))
        .map_err(|e| VmError::Internal(format!("encode stake log: {e}")))?;
        let logs = vec![Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![ROLE_STAKE_TOPIC.to_vec()],
            data.clone(),
        )];
        Ok(ExecutionResult::success(GAS_STAKE, data, logs, changes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::VmConfig;
    use crate::VmType;
    use crate::state_adapter::StateAdapter;
    use tenzro_types::constants::{
        MIN_RPC_OPERATOR_STAKE, MIN_STORAGE_PROVIDER_STAKE, STORAGE_STAKE_PER_TB,
    };
    use tenzro_types::token::StakeCapacity;

    const WHO: [u8; 32] = [4; 32];

    fn tx(op: &StakeOp, at: i64) -> VmTransaction {
        let mut data = SELECTOR_STAKE.to_vec();
        data.extend(serde_json::to_vec(op).unwrap());
        let mut t = VmTransaction::new(
            WHO.to_vec(),
            None,
            0,
            data,
            1_000_000,
            0,
            0,
            VmType::Tenzro,
            1337,
        );
        t.block_timestamp_ms = Some(at);
        t
    }

    async fn run(
        ex: &NativeExecutor,
        state: &mut StateAdapter,
        op: StakeOp,
        at: i64,
    ) -> Result<ExecutionResult> {
        ex.execute_transaction(&tx(&op, at), state).await
    }

    fn setup() -> (NativeExecutor, StateAdapter) {
        let mut state = StateAdapter::new();
        state.set_balance(&WHO, 10 * MIN_RPC_OPERATOR_STAKE);
        (NativeExecutor::new(VmConfig::default()).unwrap(), state)
    }

    /// A role governance paused takes no new bond, while a bond already
    /// held unbonds as usual; resumed, bonding is open again.
    #[tokio::test]
    async fn a_paused_role_takes_no_new_bonds() {
        let (ex, mut state) = setup();
        let rpc = NetworkRole::Rpc;
        let bond = || StakeOp::Bond {
            role: rpc,
            amount: MIN_RPC_OPERATOR_STAKE,
            capacity: StakeCapacity::None,
        };
        run(&ex, &mut state, bond(), 1).await.unwrap();
        crate::native::set_genesis_param(&mut state, "roles.rpc.status", 1);
        let err = run(&ex, &mut state, bond(), 2).await.unwrap_err();
        assert!(err.to_string().contains("paused by governance"), "{err}");
        run(
            &ex,
            &mut state,
            StakeOp::Unbond {
                role: rpc,
                amount: MIN_RPC_OPERATOR_STAKE,
            },
            3,
        )
        .await
        .unwrap();
        crate::native::set_genesis_param(&mut state, "roles.rpc.status", 0);
        run(&ex, &mut state, bond(), 4).await.unwrap();
    }

    #[tokio::test]
    async fn after_a_crash_entry_costs_its_usd_value_and_bonds_in_place_keep_serving() {
        let (ex, mut state) = setup();
        state.set_balance(&WHO, 40 * MIN_RPC_OPERATOR_STAKE);
        let rpc = NetworkRole::Rpc;
        let bond = |amount| StakeOp::Bond {
            role: rpc,
            amount,
            capacity: StakeCapacity::None,
        };
        run(&ex, &mut state, bond(MIN_RPC_OPERATOR_STAKE), 1)
            .await
            .unwrap();
        // TNZO falls to a twentieth of the floor rate.
        let pin = u128::from(DEFAULT_BOND_FLOOR_RATE_NANO_USD);
        super::super::economy::write_rate_for_tests(&mut state, 5, pin / 20, pin / 20);
        assert_eq!(
            entry_stake_ladder(&state).rpc,
            20 * stake_ladder(&state).rpc,
            "the USD floor binds"
        );
        assert!(
            role_bonded(&state, &WHO, rpc),
            "a bond in place keeps serving"
        );
        // A top-up must meet the entry amount.
        let short = run(&ex, &mut state, bond(1), 2).await.unwrap_err();
        assert!(short.to_string().contains("requires"), "{short}");
        run(&ex, &mut state, bond(19 * MIN_RPC_OPERATOR_STAKE), 3)
            .await
            .unwrap();
        // Off, or at a rate above the floor rate, the TNZO amounts apply.
        set_genesis_param(&mut state, BOND_FLOOR_RATE_PARAM, 0);
        assert_eq!(entry_stake_ladder(&state), stake_ladder(&state));
        set_genesis_param(&mut state, BOND_FLOOR_RATE_PARAM, 1);
        assert_eq!(entry_stake_ladder(&state), stake_ladder(&state));
    }

    #[tokio::test]
    async fn a_bonded_operator_publishes_its_endpoint_in_consensus() {
        let (ex, mut state) = setup();
        let rpc = NetworkRole::Rpc;
        let url = "https://rpc.operator.example".to_string();
        let early = run(
            &ex,
            &mut state,
            StakeOp::Endpoint {
                role: rpc,
                url: url.clone(),
            },
            1,
        )
        .await
        .unwrap_err();
        assert!(early.to_string().contains("after bonding"), "{early}");
        assert!(role_endpoints(&state, rpc).is_empty());

        run(
            &ex,
            &mut state,
            StakeOp::Bond {
                role: rpc,
                amount: MIN_RPC_OPERATOR_STAKE,
                capacity: StakeCapacity::None,
            },
            2,
        )
        .await
        .unwrap();
        let bad = run(
            &ex,
            &mut state,
            StakeOp::Endpoint {
                role: rpc,
                url: "http://10.0.0.1".into(),
            },
            3,
        )
        .await
        .unwrap_err();
        assert!(bad.to_string().contains("https"), "{bad}");
        run(
            &ex,
            &mut state,
            StakeOp::Endpoint {
                role: rpc,
                url: url.clone(),
            },
            4,
        )
        .await
        .unwrap();
        assert_eq!(
            role_endpoints(&state, rpc),
            vec![RoleEndpoint {
                account: hex::encode(WHO),
                url,
                bonded: MIN_RPC_OPERATOR_STAKE
            }]
        );

        // An operator that unbonds is no longer listed; clearing removes it.
        run(
            &ex,
            &mut state,
            StakeOp::Unbond {
                role: rpc,
                amount: MIN_RPC_OPERATOR_STAKE,
            },
            5,
        )
        .await
        .unwrap();
        assert!(role_endpoints(&state, rpc).is_empty());
        run(
            &ex,
            &mut state,
            StakeOp::Endpoint {
                role: rpc,
                url: String::new(),
            },
            6,
        )
        .await
        .unwrap();
        assert_eq!(read_role_stake(&state, &WHO, rpc).unwrap().endpoint, None);
    }

    #[tokio::test]
    async fn a_role_is_bonded_unbonded_and_withdrawn_in_consensus() {
        let (ex, mut state) = setup();
        let rpc = NetworkRole::Rpc;
        run(
            &ex,
            &mut state,
            StakeOp::Bond {
                role: rpc,
                amount: MIN_RPC_OPERATOR_STAKE,
                capacity: StakeCapacity::None,
            },
            1,
        )
        .await
        .unwrap();
        assert!(role_bonded(&state, &WHO, rpc));
        assert_eq!(
            state.get_balance(role_stake_vault().as_bytes()),
            MIN_RPC_OPERATOR_STAKE
        );
        let totals = role_stake_totals(&state);
        let rpc_total = &totals.iter().find(|(r, _)| *r == rpc).unwrap().1;
        assert_eq!(
            (rpc_total.bonded, rpc_total.stakers.clone()),
            (MIN_RPC_OPERATOR_STAKE, vec![hex::encode(WHO)])
        );
        assert_eq!(state.get_balance(&WHO), 9 * MIN_RPC_OPERATOR_STAKE);
        // Another role is a separate stake.
        assert!(!role_bonded(&state, &WHO, NetworkRole::StorageProvider));

        run(
            &ex,
            &mut state,
            StakeOp::Unbond {
                role: rpc,
                amount: MIN_RPC_OPERATOR_STAKE,
            },
            2,
        )
        .await
        .unwrap();
        assert!(!role_bonded(&state, &WHO, rpc));
        assert!(
            role_stake_totals(&state)
                .iter()
                .find(|(r, _)| *r == rpc)
                .unwrap()
                .1
                .stakers
                .is_empty()
        );
        let early = run(&ex, &mut state, StakeOp::Withdraw { role: rpc }, 3)
            .await
            .unwrap_err();
        assert!(early.to_string().contains("unbonds until"), "{early}");
        let at = 2 + DEFAULT_UNBONDING_MS as i64;
        run(&ex, &mut state, StakeOp::Withdraw { role: rpc }, at)
            .await
            .unwrap();
        assert_eq!(state.get_balance(&WHO), 10 * MIN_RPC_OPERATOR_STAKE);
        assert_eq!(state.get_balance(role_stake_vault().as_bytes()), 0);
        assert!(
            run(&ex, &mut state, StakeOp::Withdraw { role: rpc }, at + 1)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_bond_below_the_role_floor_is_refused() {
        let (ex, mut state) = setup();
        let err = run(
            &ex,
            &mut state,
            StakeOp::Bond {
                role: NetworkRole::Rpc,
                amount: MIN_RPC_OPERATOR_STAKE - 1,
                capacity: StakeCapacity::None,
            },
            1,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("requires"), "{err}");
        // Capacity raises the floor.
        let storage = NetworkRole::StorageProvider;
        let tb = (MIN_STORAGE_PROVIDER_STAKE / STORAGE_STAKE_PER_TB) as u32 + 2;
        assert!(
            run(
                &ex,
                &mut state,
                StakeOp::Bond {
                    role: storage,
                    amount: MIN_STORAGE_PROVIDER_STAKE,
                    capacity: StakeCapacity::Terabytes(tb)
                },
                1
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn a_partial_unbond_must_leave_the_floor_or_nothing() {
        let (ex, mut state) = setup();
        let rpc = NetworkRole::Rpc;
        run(
            &ex,
            &mut state,
            StakeOp::Bond {
                role: rpc,
                amount: MIN_RPC_OPERATOR_STAKE + 10,
                capacity: StakeCapacity::None,
            },
            1,
        )
        .await
        .unwrap();
        run(
            &ex,
            &mut state,
            StakeOp::Unbond {
                role: rpc,
                amount: 10,
            },
            2,
        )
        .await
        .unwrap();
        assert!(
            run(
                &ex,
                &mut state,
                StakeOp::Unbond {
                    role: rpc,
                    amount: 1
                },
                3
            )
            .await
            .is_err()
        );
        assert!(
            run(
                &ex,
                &mut state,
                StakeOp::Unbond {
                    role: rpc,
                    amount: MIN_RPC_OPERATOR_STAKE + 1
                },
                3
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn validator_and_unbonded_roles_are_refused() {
        let (ex, mut state) = setup();
        for role in [
            NetworkRole::Validator,
            NetworkRole::FullNode,
            NetworkRole::Archive,
        ] {
            assert!(
                run(
                    &ex,
                    &mut state,
                    StakeOp::Bond {
                        role,
                        amount: MIN_RPC_OPERATOR_STAKE,
                        capacity: StakeCapacity::None
                    },
                    1
                )
                .await
                .is_err(),
                "{role}"
            );
        }
        // A bond the account cannot pay is refused whole.
        let err = run(
            &ex,
            &mut state,
            StakeOp::Bond {
                role: NetworkRole::Rpc,
                amount: 11 * MIN_RPC_OPERATOR_STAKE,
                capacity: StakeCapacity::None,
            },
            1,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, VmError::InsufficientBalance { .. }), "{err}");
        assert!(read_role_stake(&state, &WHO, NetworkRole::Rpc).is_none());
    }

    fn wallet_bond(domain: &str) -> StakeOp {
        StakeOp::Bond {
            role: NetworkRole::WalletProvider,
            amount: tenzro_types::constants::MIN_WALLET_PROVIDER_STAKE,
            capacity: StakeCapacity::Domain(domain.into()),
        }
    }

    #[tokio::test]
    async fn a_wallet_provider_bonds_for_one_domain_and_no_other_role_declares_one() {
        let (ex, mut state) = setup();
        let wallet = NetworkRole::WalletProvider;
        let no_domain = StakeOp::Bond {
            role: wallet,
            amount: tenzro_types::constants::MIN_WALLET_PROVIDER_STAKE,
            capacity: StakeCapacity::None,
        };
        assert!(run(&ex, &mut state, no_domain, 1).await.is_err());
        assert!(
            run(&ex, &mut state, wallet_bond("Wallet.Example"), 1)
                .await
                .is_err()
        );
        assert!(
            run(&ex, &mut state, wallet_bond("wallet..example"), 1)
                .await
                .is_err()
        );
        let rpc_with_domain = StakeOp::Bond {
            role: NetworkRole::Rpc,
            amount: MIN_RPC_OPERATOR_STAKE,
            capacity: StakeCapacity::Domain("wallet.example".into()),
        };
        assert!(run(&ex, &mut state, rpc_with_domain, 1).await.is_err());

        run(&ex, &mut state, wallet_bond("wallet.example"), 1)
            .await
            .unwrap();
        assert!(role_bonded(&state, &WHO, wallet));
        assert!(role_owes_sla(wallet));
        assert!(sla_subject(&state, &role_stake_subject(&WHO, wallet)).is_some());

        // The domain stays fixed while anything is bonded or unbonding.
        assert!(
            run(&ex, &mut state, wallet_bond("other.example"), 2)
                .await
                .is_err()
        );
        let all = tenzro_types::constants::MIN_WALLET_PROVIDER_STAKE;
        run(
            &ex,
            &mut state,
            StakeOp::Unbond {
                role: wallet,
                amount: all,
            },
            3,
        )
        .await
        .unwrap();
        assert!(
            run(&ex, &mut state, wallet_bond("other.example"), 4)
                .await
                .is_err()
        );
        let at = 4 + DEFAULT_UNBONDING_MS as i64;
        run(&ex, &mut state, StakeOp::Withdraw { role: wallet }, at)
            .await
            .unwrap();
        run(&ex, &mut state, wallet_bond("other.example"), at + 1)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_wallet_provider_is_verified_only_by_a_recent_available_verdict() {
        let (ex, mut state) = setup();
        let wallet = NetworkRole::WalletProvider;
        run(&ex, &mut state, wallet_bond("wallet.example"), 1)
            .await
            .unwrap();
        let now = 10 * MARKET_EPOCH_MS + 5;
        let found = wallet_providers_for_domain(&state, "wallet.example", now);
        assert_eq!(found.len(), 1);
        assert!(!found[0].verified && found[0].verdict_epoch.is_none());
        assert!(wallet_providers_for_domain(&state, "other.example", now).is_empty());

        let subject = role_stake_subject(&WHO, wallet);
        let verdict = |available| {
            serde_json::to_vec(&super::super::SlaVerdict {
                available,
                up_stake: 0,
                down_stake: 0,
                attesters: 1,
                measured_capacity: None,
            })
            .unwrap()
        };
        state.set_storage(
            &SYSTEM_ADDRESS,
            format!("sla:8:{subject}").as_bytes(),
            verdict(true),
        );
        let found = wallet_providers_for_domain(&state, "wallet.example", now);
        assert!(found[0].verified);
        assert_eq!(found[0].verdict_epoch, Some(8));

        // A later verdict that the domain no longer names the account wins.
        state.set_storage(
            &SYSTEM_ADDRESS,
            format!("sla:9:{subject}").as_bytes(),
            verdict(false),
        );
        assert!(!wallet_providers_for_domain(&state, "wallet.example", now)[0].verified);

        // A verdict older than the lookback does not count.
        let later = (9 + WALLET_PROVIDER_VERDICT_EPOCHS as i64 + 1) * MARKET_EPOCH_MS;
        assert!(
            wallet_providers_for_domain(&state, "wallet.example", later)[0]
                .verdict_epoch
                .is_none()
        );
    }
}
