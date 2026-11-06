//! The generic registry in consensus state.
//!
//! One entry type for anything participants define and others discover:
//! units of metered work, service types, price cards, applications and
//! harness modules. The chain keeps each entry's versions, its owner and the
//! owner's bond, and never reads an entry's data; what an entry means lives
//! in the harness module its anchor names.
//!
//! - `reg:<id>` holds the latest version; `reg:<id>@<version>` every version,
//!   so a receipt naming an earlier one can still be opened.
//! - `regk:<kind>:<id>` indexes every standing entry by its kind (its
//!   service type), so a reader lists all entries of a type by prefix
//!   without anything curating them. Retirement removes the index key.
//! - The first put of an id locks the governed bond (`registry.bond_tnzo`)
//!   from the sender in the registry vault; later puts are the owner's and
//!   lock nothing more. An id `<account hex>/...` is reserved to that
//!   account.
//! - The owner retires an entry and gets its bond back. Governance retires an
//!   abusive one (`ProposalAction::RetireRegistryEntry`) and its bond goes to
//!   the insurance pool.
//! - Data is bounded by `registry.max_data_bytes`.
//! - Three kinds carry rules ([`tenzro_types::registry::RESERVED_KINDS`]):
//!   a `standard` needs a non-zero anchor (its bundle digest), and
//!   `regsd:<anchor>` records the first standard put with that digest so a
//!   digest names one standard; a `conformance` entry needs a non-zero anchor
//!   and lists 1..=`registry.conformance_max_digests` distinct bundle digests
//!   of standing standards; a `name` is a name of
//!   `registry.name_min_len..=registry.name_max_len` characters, its first put
//!   locks `registry.name_bond_tnzo`, and only governance retires it. Each has
//!   its own governed data limit under the general one. An entry of a reserved
//!   kind keeps its kind and none moves into one.

use tenzro_types::registry::{
    KIND_CONFORMANCE, KIND_NAME, KIND_STANDARD, RegistryEntry, check_anchor, check_id, check_kind,
    check_kind_change, check_name, check_nonzero_anchor, conformance_digests, reserved_owner,
};
use tenzro_types::transaction::RegistryOp;

use super::funding::{read_json, refuse, write_json};
use super::{
    ExecutionResult, GasMeter, Log, NativeExecutor, Result, SYSTEM_ADDRESS, StateChange, VmError,
    VmState, VmTransaction, deterministic_now_ms, network_param,
};
use tenzro_types::primitives::Address;

/// Selector of a [`RegistryOp`] call.
pub const SELECTOR_REGISTRY: [u8; 4] = [0x01, 0x00, 0x00, 0x91];
/// Gas for one registry operation.
pub const GAS_REGISTRY: u64 = 60_000;
/// Log topic of every registry operation.
pub const REGISTRY_TOPIC: &[u8] = b"Registry";

/// Governed key: bond an id's first put locks, whole TNZO.
pub const BOND_PARAM: &str = "registry.bond_tnzo";
/// Genesis bond: ten TNZO, enough that ids are not squatted for nothing.
pub const DEFAULT_BOND_TNZO: u64 = 10;
/// Governed key: most bytes of data one entry carries.
pub const MAX_DATA_PARAM: &str = "registry.max_data_bytes";
/// Genesis data limit: 16 KiB.
pub const DEFAULT_MAX_DATA_BYTES: u64 = 16 * 1024;

/// Governed key: bond the first put of a name locks, whole TNZO.
pub const NAME_BOND_PARAM: &str = "registry.name_bond_tnzo";
/// Genesis name bond: 25 TNZO, more than a generic id because a short name is
/// scarce and only governance releases it.
pub const DEFAULT_NAME_BOND_TNZO: u64 = 25;
/// Governed key: fewest characters in a name.
pub const NAME_MIN_LEN_PARAM: &str = "registry.name_min_len";
/// Genesis shortest name: 3 characters.
pub const DEFAULT_NAME_MIN_LEN: u64 = 3;
/// Governed key: most characters in a name.
pub const NAME_MAX_LEN_PARAM: &str = "registry.name_max_len";
/// Genesis longest name: 63 characters, one DNS label.
pub const DEFAULT_NAME_MAX_LEN: u64 = 63;
/// Governed key: most bytes of data a name entry carries (what it points to).
pub const NAME_MAX_DATA_PARAM: &str = "registry.name_max_data_bytes";
/// Genesis name data limit: 256 bytes.
pub const DEFAULT_NAME_MAX_DATA_BYTES: u64 = 256;
/// Governed key: most bytes of data a standard entry carries beside its
/// bundle digest (number, title, status).
pub const STANDARD_MAX_DATA_PARAM: &str = "registry.standard_max_data_bytes";
/// Genesis standard data limit: 1 KiB.
pub const DEFAULT_STANDARD_MAX_DATA_BYTES: u64 = 1024;
/// Governed key: most bundle digests one conformance entry lists.
pub const CONFORMANCE_MAX_DIGESTS_PARAM: &str = "registry.conformance_max_digests";
/// Genesis conformance limit: 64 standards.
pub const DEFAULT_CONFORMANCE_MAX_DIGESTS: u64 = 64;

const WEI_PER_TNZO: u128 = 1_000_000_000_000_000_000;

fn key(id: &str) -> String {
    format!("reg:{id}")
}

fn version_key(id: &str, version: u64) -> String {
    format!("reg:{id}@{version}")
}

/// The key recording which standard first put bundle digest `anchor`.
pub fn standard_digest_key(anchor: &str) -> String {
    format!("regsd:{anchor}")
}

/// The standard bundle digest `anchor` names, as `<id>@<version>`.
pub fn standard_for_digest(state: &dyn VmState, anchor: &str) -> Option<String> {
    state
        .get_storage(&SYSTEM_ADDRESS, standard_digest_key(anchor).as_bytes())
        .filter(|b| !b.is_empty())
        .and_then(|b| String::from_utf8(b).ok())
}

/// Whether bundle digest `anchor` names a standard that still stands.
fn standing_standard(state: &dyn VmState, anchor: &str) -> bool {
    standard_for_digest(state, anchor)
        .and_then(|at| at.rsplit_once('@').map(|(id, _)| id.to_string()))
        .and_then(|id| read_entry(state, &id))
        .is_some_and(|e| e.kind == KIND_STANDARD && e.retired_at_ms.is_none())
}

/// Check the rules of a reserved kind for a put of `id` with `bytes`.
fn check_reserved(
    state: &dyn VmState,
    id: &str,
    kind: &str,
    anchor: &str,
    bytes: &[u8],
) -> Result<()> {
    let limit = |param: &str| network_param(state, param) as usize;
    let over = |max: usize| {
        refuse(format!(
            "a {kind} entry's data is {} bytes, above the {max} allowed",
            bytes.len()
        ))
    };
    match kind {
        KIND_STANDARD => {
            check_nonzero_anchor(KIND_STANDARD, anchor).map_err(|e| refuse(e.to_string()))?;
            let max = limit(STANDARD_MAX_DATA_PARAM);
            if bytes.len() > max {
                return Err(over(max));
            }
            if let Some(at) = standard_for_digest(state, anchor)
                && at.rsplit_once('@').map(|(i, _)| i) != Some(id)
            {
                return Err(refuse(format!("bundle digest {anchor} already names {at}")));
            }
        }
        KIND_CONFORMANCE => {
            check_nonzero_anchor(KIND_CONFORMANCE, anchor).map_err(|e| refuse(e.to_string()))?;
            let digests = conformance_digests(bytes, limit(CONFORMANCE_MAX_DIGESTS_PARAM))
                .map_err(|e| refuse(e.to_string()))?;
            if let Some(d) = digests
                .iter()
                .map(hex::encode)
                .find(|d| !standing_standard(state, d))
            {
                return Err(refuse(format!("{d} names no standing standard")));
            }
        }
        KIND_NAME => {
            check_name(id, limit(NAME_MIN_LEN_PARAM), limit(NAME_MAX_LEN_PARAM))
                .map_err(|e| refuse(e.to_string()))?;
            let max = limit(NAME_MAX_DATA_PARAM);
            if bytes.len() > max {
                return Err(over(max));
            }
        }
        _ => {}
    }
    Ok(())
}

/// The vault every registry bond is held in.
pub fn registry_vault() -> Address {
    use sha2::{Digest, Sha256};
    Address::new(Sha256::digest(b"tenzro/registry/vault").into())
}

/// The latest version of entry `id`.
pub fn read_entry(state: &dyn VmState, id: &str) -> Option<RegistryEntry> {
    read_json(state, &key(id))
}

/// Version `version` of entry `id`.
pub fn read_entry_version(state: &dyn VmState, id: &str, version: u64) -> Option<RegistryEntry> {
    read_json(state, &version_key(id, version))
}

/// The index key of entry `id` under `kind`.
pub fn kind_key(kind: &str, id: &str) -> String {
    format!("regk:{kind}:{id}")
}

fn set_raw(state: &mut dyn VmState, key: &str, value: Vec<u8>, changes: &mut Vec<StateChange>) {
    let prior = state.get_storage(&SYSTEM_ADDRESS, key.as_bytes());
    state.set_storage(&SYSTEM_ADDRESS, key.as_bytes(), value.clone());
    changes.push(StateChange::new(
        SYSTEM_ADDRESS.to_vec(),
        key.as_bytes().to_vec(),
        prior,
        Some(value),
    ));
}

/// Write version `e`, keep the kind index in step with it, and drop the
/// index key of a previous version filed under another kind.
fn store(
    state: &mut dyn VmState,
    e: &RegistryEntry,
    previous_kind: Option<&str>,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    write_json(state, &key(&e.id), e, changes)?;
    write_json(state, &version_key(&e.id, e.version), e, changes)?;
    if let Some(k) = previous_kind.filter(|k| *k != e.kind) {
        set_raw(state, &kind_key(k, &e.id), Vec::new(), changes);
    }
    let index = if e.retired_at_ms.is_none() {
        e.version.to_le_bytes().to_vec()
    } else {
        Vec::new()
    };
    set_raw(state, &kind_key(&e.kind, &e.id), index, changes);
    Ok(())
}

fn move_balance(
    state: &mut dyn VmState,
    from: &[u8],
    to: &[u8],
    amount: u128,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    if amount == 0 {
        return Ok(());
    }
    let f = state.get_balance(from);
    if f < amount {
        return Err(VmError::InsufficientBalance {
            required: amount,
            available: f,
        });
    }
    state.set_balance(from, f - amount);
    let t = state.get_balance(to);
    state.set_balance(to, t.saturating_add(amount));
    changes.push(StateChange::new(
        from.to_vec(),
        b"balance".to_vec(),
        Some(f.to_le_bytes().to_vec()),
        Some((f - amount).to_le_bytes().to_vec()),
    ));
    changes.push(StateChange::new(
        to.to_vec(),
        b"balance".to_vec(),
        Some(t.to_le_bytes().to_vec()),
        Some(t.saturating_add(amount).to_le_bytes().to_vec()),
    ));
    Ok(())
}

/// Retire `id` by governance: the bond goes to the insurance pool.
pub(super) fn governance_retire(
    state: &mut dyn VmState,
    id: &str,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let mut e = read_entry(state, id)
        .filter(|e| e.retired_at_ms.is_none())
        .ok_or_else(|| refuse(format!("no standing registry entry '{id}'")))?;
    let pool = super::derive_insurance_pool_address();
    move_balance(
        state,
        registry_vault().as_bytes(),
        pool.as_bytes(),
        e.bond,
        changes,
    )?;
    e.bond = 0;
    e.retired_at_ms = Some(now_ms);
    store(state, &e, None, changes)
}

impl NativeExecutor {
    /// Handle a [`RegistryOp`].
    pub(super) async fn execute_registry(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        let op: RegistryOp = serde_json::from_slice(&tx.data[4..])
            .map_err(|e| refuse(format!("Invalid Registry payload: {e}")))?;
        gas_meter.consume(GAS_REGISTRY)?;
        let gas_cost = tx.gas_price.saturating_mul(GAS_REGISTRY as u128);
        let balance = state.get_balance(&tx.from);
        if balance < gas_cost {
            return Err(VmError::InsufficientBalance {
                required: gas_cost,
                available: balance,
            });
        }
        let sender =
            Address::from_bytes(&tx.from).ok_or_else(|| refuse("sender is not an address"))?;
        let now = deterministic_now_ms(tx);
        let mut changes = Vec::new();
        let detail = match op {
            RegistryOp::Put {
                id,
                kind,
                anchor,
                data,
            } => {
                check_id(&id).map_err(|e| refuse(e.to_string()))?;
                check_kind(&kind).map_err(|e| refuse(e.to_string()))?;
                check_anchor(&anchor).map_err(|e| refuse(e.to_string()))?;
                let bytes = hex::decode(&data).map_err(|_| refuse("data must be hex"))?;
                let max = network_param(state, MAX_DATA_PARAM) as usize;
                if bytes.len() > max {
                    return Err(refuse(format!(
                        "data is {} bytes, above the {max} allowed",
                        bytes.len()
                    )));
                }
                if reserved_owner(&id).is_some_and(|o| o != sender) {
                    return Err(refuse("this id is reserved to another account"));
                }
                let previous = read_entry(state, &id);
                let previous_kind = previous.as_ref().map(|p| p.kind.clone());
                let entry = match previous {
                    Some(prev) => {
                        if prev.owner != sender {
                            return Err(refuse("only the entry's owner may put a new version"));
                        }
                        if prev.retired_at_ms.is_some() {
                            return Err(refuse("a retired id is not reused"));
                        }
                        check_kind_change(&prev.kind, &kind).map_err(|e| refuse(e.to_string()))?;
                        check_reserved(state, &id, &kind, &anchor, &bytes)?;
                        RegistryEntry {
                            id,
                            kind,
                            owner: sender,
                            version: prev.version + 1,
                            anchor,
                            data: hex::encode(&bytes),
                            bond: prev.bond,
                            put_at_ms: now,
                            retired_at_ms: None,
                        }
                    }
                    None => {
                        check_reserved(state, &id, &kind, &anchor, &bytes)?;
                        let bond_param = if kind == KIND_NAME {
                            NAME_BOND_PARAM
                        } else {
                            BOND_PARAM
                        };
                        let bond = u128::from(network_param(state, bond_param)) * WEI_PER_TNZO;
                        move_balance(
                            state,
                            &tx.from,
                            registry_vault().as_bytes(),
                            bond,
                            &mut changes,
                        )?;
                        RegistryEntry {
                            id,
                            kind,
                            owner: sender,
                            version: 1,
                            anchor,
                            data: hex::encode(&bytes),
                            bond,
                            put_at_ms: now,
                            retired_at_ms: None,
                        }
                    }
                };
                if entry.kind == KIND_STANDARD
                    && standard_for_digest(state, &entry.anchor).is_none()
                {
                    set_raw(
                        state,
                        &standard_digest_key(&entry.anchor),
                        format!("{}@{}", entry.id, entry.version).into_bytes(),
                        &mut changes,
                    );
                }
                store(state, &entry, previous_kind.as_deref(), &mut changes)?;
                format!("put:{}@{}:{}", entry.id, entry.version, entry.digest())
            }
            RegistryOp::Retire { id } => {
                let mut e = read_entry(state, &id)
                    .filter(|e| e.retired_at_ms.is_none())
                    .ok_or_else(|| refuse(format!("no standing registry entry '{id}'")))?;
                if e.owner != sender {
                    return Err(refuse("only the entry's owner may retire it"));
                }
                if e.kind == KIND_NAME {
                    return Err(refuse("a name is retired by governance only"));
                }
                move_balance(
                    state,
                    registry_vault().as_bytes(),
                    &tx.from,
                    e.bond,
                    &mut changes,
                )?;
                e.bond = 0;
                e.retired_at_ms = Some(now);
                store(state, &e, None, &mut changes)?;
                format!("retire:{id}@{}", e.version)
            }
        };

        let balance = state.get_balance(&tx.from);
        state.set_balance(&tx.from, balance - gas_cost);
        changes.push(StateChange::new(
            tx.from.clone(),
            b"balance".to_vec(),
            Some(balance.to_le_bytes().to_vec()),
            Some((balance - gas_cost).to_le_bytes().to_vec()),
        ));
        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);
        changes.push(StateChange::new(
            tx.from.clone(),
            b"nonce".to_vec(),
            Some(old_nonce.to_le_bytes().to_vec()),
            Some((old_nonce + 1).to_le_bytes().to_vec()),
        ));
        let log = Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![REGISTRY_TOPIC.to_vec()],
            detail.into_bytes(),
        );
        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            Vec::new(),
            vec![log],
            changes,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::VmConfig;
    use crate::VmType;
    use crate::state_adapter::StateAdapter;
    use crate::traits::VmExecutor as _;
    use tenzro_types::registry::owned_id;

    const OWNER: [u8; 32] = [7u8; 32];
    const OTHER: [u8; 32] = [8u8; 32];
    const RICH: u128 = 1_000 * WEI_PER_TNZO;

    fn setup() -> (NativeExecutor, StateAdapter) {
        let mut state = StateAdapter::new();
        state.set_balance(&OWNER, RICH);
        state.set_balance(&OTHER, RICH);
        (NativeExecutor::new(VmConfig::default()).unwrap(), state)
    }

    fn tx(from: [u8; 32], op: &RegistryOp, nonce: u64, at: i64) -> VmTransaction {
        let mut data = SELECTOR_REGISTRY.to_vec();
        data.extend_from_slice(&serde_json::to_vec(op).unwrap());
        let mut t = VmTransaction::new(
            from.to_vec(),
            None,
            0,
            data,
            2_000_000,
            0,
            nonce,
            VmType::Tenzro,
            1337,
        );
        t.block_timestamp_ms = Some(at);
        t
    }

    async fn run(ex: &NativeExecutor, s: &mut StateAdapter, t: &VmTransaction) -> bool {
        matches!(ex.execute_transaction(t, s).await, Ok(r) if r.success)
    }

    fn put(id: &str, data: &[u8]) -> RegistryOp {
        RegistryOp::Put {
            id: id.into(),
            kind: "unit".into(),
            anchor: "ab".repeat(32),
            data: hex::encode(data),
        }
    }

    #[tokio::test]
    async fn the_first_put_bonds_the_id_to_its_owner_and_versions_follow() {
        let (ex, mut s) = setup();
        let bond = u128::from(DEFAULT_BOND_TNZO) * WEI_PER_TNZO;
        assert!(
            run(
                &ex,
                &mut s,
                &tx(OWNER, &put("bandwidth_bytes", b"v1"), 0, 10)
            )
            .await
        );
        assert_eq!(s.get_balance(&OWNER), RICH - bond);
        assert_eq!(s.get_balance(registry_vault().as_bytes()), bond);
        // Someone else cannot put over it.
        assert!(
            !run(
                &ex,
                &mut s,
                &tx(OTHER, &put("bandwidth_bytes", b"x"), 0, 11)
            )
            .await
        );
        // The owner versions it without a second bond, and both versions stay readable.
        assert!(
            run(
                &ex,
                &mut s,
                &tx(OWNER, &put("bandwidth_bytes", b"v2"), 1, 12)
            )
            .await
        );
        assert_eq!(s.get_balance(&OWNER), RICH - bond);
        let latest = read_entry(&s, "bandwidth_bytes").unwrap();
        assert_eq!(
            (latest.version, latest.data_bytes().unwrap()),
            (2, b"v2".to_vec())
        );
        let first = read_entry_version(&s, "bandwidth_bytes", 1).unwrap();
        assert_eq!(first.data_bytes().unwrap(), b"v1".to_vec());
        assert_ne!(first.digest(), latest.digest());
        // Filed under its kind; a new version under another kind moves it.
        let indexed = |s: &StateAdapter, k: &str| {
            s.get_storage(&SYSTEM_ADDRESS, kind_key(k, "bandwidth_bytes").as_bytes())
                .is_some_and(|b| !b.is_empty())
        };
        assert!(indexed(&s, "unit"));
        let moved = RegistryOp::Put {
            id: "bandwidth_bytes".into(),
            kind: "service".into(),
            anchor: "ab".repeat(32),
            data: String::new(),
        };
        assert!(run(&ex, &mut s, &tx(OWNER, &moved, 2, 13)).await);
        assert!(!indexed(&s, "unit") && indexed(&s, "service"));
        assert!(
            run(
                &ex,
                &mut s,
                &tx(
                    OWNER,
                    &RegistryOp::Retire {
                        id: "bandwidth_bytes".into()
                    },
                    3,
                    14
                )
            )
            .await
        );
        assert!(!indexed(&s, "service"), "a retired entry leaves the index");
    }

    #[tokio::test]
    async fn an_owned_id_is_reserved_and_bad_input_is_refused() {
        let (ex, mut s) = setup();
        let mine = owned_id(&Address::new(OWNER), "card/qwen3-0.6b");
        assert!(!run(&ex, &mut s, &tx(OTHER, &put(&mine, b"{}"), 0, 10)).await);
        assert!(run(&ex, &mut s, &tx(OWNER, &put(&mine, b"{}"), 0, 10)).await);
        let big = vec![0u8; DEFAULT_MAX_DATA_BYTES as usize + 1];
        assert!(!run(&ex, &mut s, &tx(OTHER, &put("big", &big), 0, 10)).await);
        assert!(!run(&ex, &mut s, &tx(OTHER, &put("Bad Id", b""), 0, 10)).await);
        let bad_anchor = RegistryOp::Put {
            id: "x".into(),
            kind: "unit".into(),
            anchor: "00".into(),
            data: String::new(),
        };
        assert!(!run(&ex, &mut s, &tx(OTHER, &bad_anchor, 0, 10)).await);
    }

    #[tokio::test]
    async fn the_owner_retires_and_gets_the_bond_back_governance_takes_it() {
        let (ex, mut s) = setup();
        assert!(run(&ex, &mut s, &tx(OWNER, &put("a", b"1"), 0, 10)).await);
        assert!(run(&ex, &mut s, &tx(OTHER, &put("b", b"1"), 0, 10)).await);
        let retire = |id: &str| RegistryOp::Retire { id: id.into() };
        assert!(!run(&ex, &mut s, &tx(OTHER, &retire("a"), 1, 20)).await);
        assert!(run(&ex, &mut s, &tx(OWNER, &retire("a"), 1, 20)).await);
        assert_eq!(s.get_balance(&OWNER), RICH);
        let a = read_entry(&s, "a").unwrap();
        assert!(a.standing_at(19) && !a.standing_at(20));
        assert!(
            !run(&ex, &mut s, &tx(OWNER, &put("a", b"2"), 2, 30)).await,
            "not reused"
        );
        let pool = super::super::derive_insurance_pool_address();
        let before = s.get_balance(pool.as_bytes());
        governance_retire(&mut s, "b", 40, &mut Vec::new()).unwrap();
        let bond = u128::from(DEFAULT_BOND_TNZO) * WEI_PER_TNZO;
        assert_eq!(s.get_balance(pool.as_bytes()), before + bond);
        assert!(!read_entry(&s, "b").unwrap().standing_at(40));
    }

    fn put_kind(id: &str, kind: &str, anchor: &str, data: &[u8]) -> RegistryOp {
        RegistryOp::Put {
            id: id.into(),
            kind: kind.into(),
            anchor: anchor.into(),
            data: hex::encode(data),
        }
    }

    fn digest(b: u8) -> String {
        hex::encode([b; 32])
    }

    #[tokio::test]
    async fn a_standard_needs_a_bundle_digest_that_names_only_it() {
        let (ex, mut s) = setup();
        let zero = "0".repeat(64);
        assert!(
            !run(
                &ex,
                &mut s,
                &tx(OWNER, &put_kind("tnip-0", "standard", &zero, b"{}"), 0, 10)
            )
            .await
        );
        let big = vec![b'x'; DEFAULT_STANDARD_MAX_DATA_BYTES as usize + 1];
        assert!(
            !run(
                &ex,
                &mut s,
                &tx(
                    OWNER,
                    &put_kind("tnip-0", "standard", &digest(1), &big),
                    0,
                    10
                )
            )
            .await
        );
        assert!(
            run(
                &ex,
                &mut s,
                &tx(
                    OWNER,
                    &put_kind("tnip-0", "standard", &digest(1), b"{}"),
                    0,
                    10
                )
            )
            .await
        );
        assert_eq!(
            standard_for_digest(&s, &digest(1)).as_deref(),
            Some("tnip-0@1")
        );
        // Another standard cannot claim the same bundle.
        assert!(
            !run(
                &ex,
                &mut s,
                &tx(
                    OTHER,
                    &put_kind("tnip-1", "standard", &digest(1), b"{}"),
                    0,
                    11
                )
            )
            .await
        );
        // A new version with a new bundle files the new digest under it; the first stays.
        assert!(
            run(
                &ex,
                &mut s,
                &tx(
                    OWNER,
                    &put_kind("tnip-0", "standard", &digest(2), b"{}"),
                    1,
                    12
                )
            )
            .await
        );
        assert_eq!(
            standard_for_digest(&s, &digest(2)).as_deref(),
            Some("tnip-0@2")
        );
        assert_eq!(
            standard_for_digest(&s, &digest(1)).as_deref(),
            Some("tnip-0@1")
        );
        // Its kind is fixed, and no other entry moves into it.
        assert!(
            !run(
                &ex,
                &mut s,
                &tx(OWNER, &put_kind("tnip-0", "unit", &digest(3), b""), 2, 13)
            )
            .await
        );
        assert!(run(&ex, &mut s, &tx(OTHER, &put("plain", b""), 0, 14)).await);
        assert!(
            !run(
                &ex,
                &mut s,
                &tx(
                    OTHER,
                    &put_kind("plain", "standard", &digest(4), b""),
                    1,
                    15
                )
            )
            .await
        );
    }

    #[tokio::test]
    async fn conformance_lists_distinct_digests_of_standing_standards() {
        let (ex, mut s) = setup();
        assert!(
            run(
                &ex,
                &mut s,
                &tx(
                    OWNER,
                    &put_kind("tnip-0", "standard", &digest(1), b""),
                    0,
                    10
                )
            )
            .await
        );
        assert!(
            run(
                &ex,
                &mut s,
                &tx(
                    OWNER,
                    &put_kind("tnip-2", "standard", &digest(2), b""),
                    1,
                    10
                )
            )
            .await
        );
        let claim = |d: &[u8], anchor: &str| put_kind("node-1.0/conf", "conformance", anchor, d);
        let both = [[1u8; 32], [2u8; 32]].concat();
        assert!(
            !run(
                &ex,
                &mut s,
                &tx(OTHER, &claim(&both, &"0".repeat(64)), 0, 11)
            )
            .await,
            "zero anchor"
        );
        assert!(
            !run(&ex, &mut s, &tx(OTHER, &claim(&[], &digest(9)), 0, 11)).await,
            "empty"
        );
        assert!(
            !run(
                &ex,
                &mut s,
                &tx(OTHER, &claim(&both[..40], &digest(9)), 0, 11)
            )
            .await,
            "ragged"
        );
        assert!(
            !run(
                &ex,
                &mut s,
                &tx(
                    OTHER,
                    &claim(&[[1u8; 32], [1u8; 32]].concat(), &digest(9)),
                    0,
                    11
                )
            )
            .await,
            "repeated"
        );
        assert!(
            !run(
                &ex,
                &mut s,
                &tx(OTHER, &claim(&[7u8; 32], &digest(9)), 0, 11)
            )
            .await,
            "unknown standard"
        );
        let over = vec![0u8; 32 * (DEFAULT_CONFORMANCE_MAX_DIGESTS as usize + 1)];
        assert!(
            !run(&ex, &mut s, &tx(OTHER, &claim(&over, &digest(9)), 0, 11)).await,
            "above the limit"
        );
        assert!(run(&ex, &mut s, &tx(OTHER, &claim(&both, &digest(9)), 0, 11)).await);
        // A retired standard can no longer be claimed.
        assert!(
            run(
                &ex,
                &mut s,
                &tx(
                    OWNER,
                    &RegistryOp::Retire {
                        id: "tnip-2".into()
                    },
                    2,
                    12
                )
            )
            .await
        );
        assert!(!run(&ex, &mut s, &tx(OTHER, &claim(&both, &digest(9)), 1, 13)).await);
        assert!(
            run(
                &ex,
                &mut s,
                &tx(OTHER, &claim(&[1u8; 32], &digest(9)), 1, 13)
            )
            .await
        );
    }

    #[tokio::test]
    async fn a_name_is_first_come_bonded_and_retired_by_governance_only() {
        let (ex, mut s) = setup();
        let zero = "0".repeat(64);
        let name = |id: &str, d: &[u8]| put_kind(id, "name", &zero, d);
        for bad in ["ab", "-alice", "Alice", "al.ice", "al_ice"] {
            assert!(
                !run(&ex, &mut s, &tx(OWNER, &name(bad, b""), 0, 10)).await,
                "{bad}"
            );
        }
        assert!(!run(&ex, &mut s, &tx(OWNER, &name(&"a".repeat(64), b""), 0, 10)).await);
        let far = vec![0u8; DEFAULT_NAME_MAX_DATA_BYTES as usize + 1];
        assert!(!run(&ex, &mut s, &tx(OWNER, &name("alice", &far), 0, 10)).await);
        assert!(
            run(
                &ex,
                &mut s,
                &tx(OWNER, &name("alice", b"did:tenzro:a"), 0, 10)
            )
            .await
        );
        let bond = u128::from(DEFAULT_NAME_BOND_TNZO) * WEI_PER_TNZO;
        assert_eq!(s.get_balance(&OWNER), RICH - bond);
        assert_eq!(read_entry(&s, "alice").unwrap().bond, bond);
        // First come: a second claim is refused.
        assert!(
            !run(
                &ex,
                &mut s,
                &tx(OTHER, &name("alice", b"did:tenzro:b"), 0, 11)
            )
            .await
        );
        // The owner repoints it but cannot retire it or change its kind.
        assert!(
            run(
                &ex,
                &mut s,
                &tx(OWNER, &name("alice", b"did:tenzro:c"), 1, 12)
            )
            .await
        );
        assert!(
            !run(
                &ex,
                &mut s,
                &tx(OWNER, &RegistryOp::Retire { id: "alice".into() }, 2, 13)
            )
            .await
        );
        assert!(
            !run(
                &ex,
                &mut s,
                &tx(OWNER, &put_kind("alice", "unit", &zero, b""), 2, 13)
            )
            .await
        );
        let pool = super::super::derive_insurance_pool_address();
        let before = s.get_balance(pool.as_bytes());
        governance_retire(&mut s, "alice", 20, &mut Vec::new()).unwrap();
        assert_eq!(s.get_balance(pool.as_bytes()), before + bond);
        assert!(!read_entry(&s, "alice").unwrap().standing_at(20));
        assert!(
            !run(&ex, &mut s, &tx(OTHER, &name("alice", b""), 0, 21)).await,
            "not reused"
        );
    }

    #[tokio::test]
    async fn reserved_kind_limits_follow_governance() {
        let (ex, mut s) = setup();
        let set = |s: &mut StateAdapter, k: &str, v: u64| {
            s.set_storage(
                &SYSTEM_ADDRESS,
                super::super::governed_param_key(k).as_bytes(),
                v.to_le_bytes().to_vec(),
            )
        };
        set(&mut s, NAME_MIN_LEN_PARAM, 6);
        set(&mut s, NAME_BOND_PARAM, 2);
        set(&mut s, CONFORMANCE_MAX_DIGESTS_PARAM, 1);
        let zero = "0".repeat(64);
        assert!(
            !run(
                &ex,
                &mut s,
                &tx(OWNER, &put_kind("alice", "name", &zero, b""), 0, 10)
            )
            .await
        );
        assert!(
            run(
                &ex,
                &mut s,
                &tx(OWNER, &put_kind("alice6", "name", &zero, b""), 0, 10)
            )
            .await
        );
        assert_eq!(s.get_balance(&OWNER), RICH - 2 * WEI_PER_TNZO);
        assert!(
            run(
                &ex,
                &mut s,
                &tx(OWNER, &put_kind("s1", "standard", &digest(1), b""), 1, 10)
            )
            .await
        );
        assert!(
            run(
                &ex,
                &mut s,
                &tx(OWNER, &put_kind("s2", "standard", &digest(2), b""), 2, 10)
            )
            .await
        );
        let both = [[1u8; 32], [2u8; 32]].concat();
        assert!(
            !run(
                &ex,
                &mut s,
                &tx(
                    OWNER,
                    &put_kind("c", "conformance", &digest(9), &both),
                    3,
                    10
                )
            )
            .await
        );
    }

    #[tokio::test]
    async fn the_same_puts_write_the_same_state() {
        async fn replay() -> (Vec<String>, Vec<Option<Vec<u8>>>) {
            let (ex, mut s) = setup();
            let zero = "0".repeat(64);
            let ops = [
                (OWNER, put_kind("tnip-0", "standard", &digest(1), b"{}")),
                (
                    OTHER,
                    put_kind("impl/conf", "conformance", &digest(9), &[1u8; 32]),
                ),
                (OWNER, put_kind("alice", "name", &zero, b"did:tenzro:a")),
                (OWNER, put_kind("tnip-0", "standard", &digest(2), b"{}")),
                (OTHER, put("bandwidth_bytes", b"v1")),
            ];
            let mut nonces = std::collections::HashMap::new();
            let mut changes = Vec::new();
            for (i, (from, op)) in ops.iter().enumerate() {
                let n = nonces.entry(*from).or_insert(0u64);
                let r = ex
                    .execute_transaction(&tx(*from, op, *n, 10 + i as i64), &mut s)
                    .await
                    .unwrap();
                assert!(r.success, "op {i}");
                *n += 1;
                changes.extend(r.state_changes.iter().map(|c| format!("{c:?}")));
            }
            let keys = [
                "reg:tnip-0".to_string(),
                "reg:tnip-0@1".into(),
                "reg:impl/conf".into(),
                "reg:alice".into(),
                kind_key("name", "alice"),
                kind_key("standard", "tnip-0"),
                standard_digest_key(&digest(1)),
                standard_digest_key(&digest(2)),
            ];
            let values = keys
                .iter()
                .map(|k| s.get_storage(&SYSTEM_ADDRESS, k.as_bytes()))
                .collect();
            (changes, values)
        }
        let (a, b) = (replay().await, replay().await);
        assert!(!a.0.is_empty() && a.1.iter().all(Option::is_some));
        assert_eq!(a, b);
    }
}
