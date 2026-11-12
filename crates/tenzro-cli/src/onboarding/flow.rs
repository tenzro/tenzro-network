//! The live side: read the chain and the website, settle on one state, keep
//! it, and gate the commands that need stake. The decisions are made by the
//! pure code in `state` and `message`; this file only gathers evidence.

use anyhow::{Result, anyhow};
use serde_json::{Value, json};

use super::message::{self, GapInput, MsgEnv};
use super::phase::Phase;
use super::role::JoinRole;
use super::state::{ApplicationState, Evidence, resolve};
use super::status_source::{HttpStatusSource, Lookup, StatusSource, StubStatusSource};
use crate::config::{self, ApplicationRecord};
use crate::rpc::RpcClient;

/// The real website, or a fixed answer when `TENZRO_JOIN_STATUS_STUB` names a
/// state (`approved`, `none`, `unavailable`, ...), for trying the flow
/// before the website serves the endpoint.
pub enum AnySource {
    Http(HttpStatusSource),
    Stub(StubStatusSource),
}

impl AnySource {
    pub fn from_env() -> Self {
        match std::env::var("TENZRO_JOIN_STATUS_STUB")
            .ok()
            .and_then(|n| StubStatusSource::from_name(&n))
        {
            Some(s) => AnySource::Stub(s),
            None => AnySource::Http(HttpStatusSource::from_env()),
        }
    }
}

impl StatusSource for AnySource {
    async fn lookup(&self, wallet: &str, role_slug: &str) -> Lookup {
        match self {
            AnySource::Http(h) => h.lookup(wallet, role_slug).await,
            AnySource::Stub(s) => s.lookup(wallet, role_slug).await,
        }
    }
}

/// What the chain says about one account and role. `None` is "could not
/// read"; it is never turned into a guess.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChainFacts {
    pub balance_wei: Option<u128>,
    pub staked: Option<bool>,
    pub serving: Option<bool>,
}

pub fn parse_balance(v: &Value) -> Option<u128> {
    u128::from_str_radix(v.as_str()?.trim_start_matches("0x"), 16).ok()
}

/// From `tenzro_getRoleStakes`: is `flag`'s stake bonded in full?
pub fn staked_from_role_stakes(v: &Value, flag: &str, our_required: u128) -> Option<bool> {
    let stakes = v.get("stakes")?.as_array()?;
    let wei = |s: &Value, k: &str| {
        s.get(k)
            .and_then(Value::as_str)
            .and_then(|x| x.parse::<u128>().ok())
    };
    Some(stakes.iter().any(|s| {
        s.get("role")
            .and_then(Value::as_str)
            .is_some_and(|r| r.eq_ignore_ascii_case(flag))
            && wei(s, "bonded").is_some_and(|b| {
                b > 0
                    && b >= wei(s, "required")
                        .unwrap_or(our_required)
                        .min(our_required.max(1))
            })
    }))
}

/// From `tenzro_getValidatorState`: (staked, serving).
pub fn validator_flags(v: &Value) -> (bool, bool) {
    match v.get("status").and_then(Value::as_str) {
        Some("Candidate" | "PendingActive" | "Jailed") => (true, false),
        Some("Active") => (true, true),
        _ => (false, false),
    }
}

/// Read what the chain says. Every failure becomes `None`.
pub async fn read_chain(
    rpc: &RpcClient,
    account: &str,
    role: Option<JoinRole>,
    required_wei: u128,
) -> ChainFacts {
    let balance_wei = rpc
        .call::<Value>("eth_getBalance", json!([account, "latest"]))
        .await
        .ok()
        .as_ref()
        .and_then(parse_balance);
    let mut f = ChainFacts {
        balance_wei,
        ..ChainFacts::default()
    };
    match role {
        Some(JoinRole::Validator) => {
            if let Ok(v) = rpc
                .call::<Value>("tenzro_getValidatorState", json!({ "address": account }))
                .await
            {
                let (s, sv) = if v.is_null() {
                    (false, false)
                } else {
                    validator_flags(&v)
                };
                f.staked = Some(s);
                f.serving = Some(sv);
            }
        }
        Some(r) => {
            if let (Some(flag), Ok(v)) = (
                r.bond_flag(),
                rpc.call::<Value>("tenzro_getRoleStakes", json!({ "address": account }))
                    .await,
            ) {
                f.staked = staked_from_role_stakes(&v, flag, required_wei);
                if f.staked == Some(true) {
                    f.serving = Some(node_serves(rpc, account, r).await);
                }
            }
        }
        None => {}
    }
    f
}

async fn node_serves(rpc: &RpcClient, account: &str, role: JoinRole) -> bool {
    let Ok(status) = rpc.call::<Value>("tenzro_getNodeStatus", json!([])).await else {
        return false;
    };
    if status
        .get("payee")
        .and_then(Value::as_str)
        .map(str::to_ascii_lowercase)
        != Some(account.to_ascii_lowercase())
    {
        return false;
    }
    let names: Vec<String> = match status.get("roles") {
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(|x| x.as_str().map(str::to_ascii_lowercase))
            .collect(),
        Some(Value::String(s)) => s
            .split(',')
            .map(|x| x.trim().to_ascii_lowercase())
            .collect(),
        _ => return false,
    };
    names.iter().any(|n| {
        Some(n.as_str()) == role.bond_flag()
            || n == role.slug()
            || (role == JoinRole::ModelProvider && n == "model-provider")
    })
}

/// The record kept from the last time, for this account and role only.
pub fn cached_state(account: &str, role_key: &str) -> Option<ApplicationState> {
    let rec = config::load_config().application?;
    (rec.account.eq_ignore_ascii_case(account) && rec.role == role_key)
        .then(|| ApplicationState::parse(&rec.state))
        .flatten()
}

fn keep(account: &str, role_key: &str, state: ApplicationState, application_id: Option<String>) {
    let mut cfg = config::load_config();
    let id = application_id.or_else(|| {
        cfg.application
            .as_ref()
            .filter(|r| r.account.eq_ignore_ascii_case(account) && r.role == role_key)
            .and_then(|r| r.application_id.clone())
    });
    cfg.application = Some(ApplicationRecord {
        account: account.to_string(),
        role: role_key.to_string(),
        state: state.as_str().to_string(),
        application_id: id,
    });
    let _ = config::save_config(&cfg); // best effort: the next run asks again
}

/// Where an account stands for a role.
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub account: String,
    pub required_wei: u128,
    pub balance_wei: Option<u128>,
    pub state: ApplicationState,
    /// The website could not be asked; the state leans on the last record.
    pub website_unavailable: bool,
}

/// Gather the evidence for one account and role, settle on the state, and
/// keep it for the next run. `role_key` names the role in the record and the
/// website query (a role slug; for non-roles such as the compute bond, any
/// stable label).
pub async fn snapshot(
    rpc: &RpcClient,
    source: &impl StatusSource,
    role_key: &str,
    role: Option<JoinRole>,
    account: &str,
    required_wei: u128,
) -> Snapshot {
    let chain = read_chain(rpc, account, role, required_wei).await;
    let remote = source.lookup(account, role_key).await;
    let (reported, website_unavailable, id) = match remote {
        Lookup::Found(r) => (Some(r.state), false, r.application_id),
        Lookup::NotFound => (None, false, None),
        Lookup::Unavailable => (cached_state(account, role_key), true, None),
    };
    let state = resolve(&Evidence {
        reported,
        balance_meets_minimum: chain.balance_wei.map(|b| b >= required_wei),
        chain_staked: chain.staked,
        chain_serving: chain.serving,
    });
    keep(account, role_key, state, id);
    Snapshot {
        account: account.to_string(),
        required_wei,
        balance_wei: chain.balance_wei,
        state,
        website_unavailable,
    }
}

/// Stop a command that needs stake the wallet does not hold, in the initial
/// phase, with the plain message. In any other phase this passes and the
/// chain's own checks apply.
pub async fn gate(
    rpc_url: &str,
    account: &str,
    role_label: &str,
    role: Option<JoinRole>,
    required_wei: u128,
) -> Result<()> {
    let env = MsgEnv::current();
    if env.phase != Phase::Foundation {
        return Ok(());
    }
    let key: &str = match role {
        Some(r) => r.slug(),
        None => role_label,
    };
    let snap = snapshot(
        &RpcClient::new(rpc_url),
        &AnySource::from_env(),
        key,
        role,
        account,
        required_wei,
    )
    .await;
    let input = GapInput {
        role_label,
        required_wei,
        balance_wei: snap.balance_wei,
        account,
        state: snap.state,
    };
    match message::stake_gap(&input, &env) {
        Some(lines) => Err(anyhow!("{}", message::to_text(&lines))),
        None => Ok(()),
    }
}

/// A failed send, told plainly when it failed for lack of funds in the
/// initial phase; any other failure is returned unchanged.
pub fn plain_send_error(
    err: anyhow::Error,
    role_label: &str,
    role: Option<JoinRole>,
    required_wei: u128,
    account: &str,
) -> anyhow::Error {
    let raw = format!("{err:#}");
    let env = MsgEnv::current();
    if env.phase != Phase::Foundation || !message::looks_like_insufficient_funds(&raw) {
        return err;
    }
    let key: &str = match role {
        Some(r) => r.slug(),
        None => role_label,
    };
    let state = cached_state(account, key).unwrap_or(ApplicationState::NotApplied);
    let input = GapInput {
        role_label,
        required_wei,
        balance_wei: None,
        account,
        state,
    };
    match message::stake_gap(&input, &env) {
        Some(lines) => anyhow!("{}", message::to_text(&lines)),
        None => err,
    }
}

/// `tenzro join --role <role>`: show where the application stands and the one
/// next step. Safe to run at any point, any number of times.
pub async fn run_join_role(role: JoinRole, rpc_url: &str, wallet: Option<String>) -> Result<()> {
    use crate::output;
    let cfg = config::load_config();
    let Some(account) = wallet.or(cfg.wallet_address) else {
        output::print_warning("No wallet yet for this machine.");
        output::print_info("Create one first, then run this command again:");
        println!("      tenzro join");
        return Ok(());
    };
    let env = MsgEnv::current();
    let required = role.stake_minimum_wei();
    let snap = snapshot(
        &RpcClient::new(rpc_url),
        &AnySource::from_env(),
        role.slug(),
        Some(role),
        &account,
        required,
    )
    .await;
    println!();
    let need = crate::commands::stake_options::StakeNeed {
        role: role.label().to_string(),
        required_wei: required,
        balance_wei: snap.balance_wei,
        account: account.clone(),
    };
    // Short of the stake: the initial-phase application message (or, in any
    // other phase, the general options). Holding it or having bonded it: the
    // next step.
    let lines = if need.is_met() || snap.state.stake_in_place() {
        message::next_step(role.label(), role.bond_flag(), required, snap.state)
    } else {
        need.lines_with(&env, snap.state)
    };
    for (k, t) in &lines {
        match k {
            message::LineKind::Heading => output::print_warning(t),
            message::LineKind::Text => output::print_info(t),
            message::LineKind::Command => println!("      {t}"),
        }
    }
    if snap.website_unavailable {
        output::print_info(
            "The application status could not be checked just now, so this is the last status this machine saw plus what the chain shows.",
        );
    }
    println!();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn balance_hex_parses_and_junk_is_none() {
        assert_eq!(parse_balance(&json!("0x10")), Some(16));
        assert_eq!(parse_balance(&json!(5)), None);
        assert_eq!(parse_balance(&json!("zz")), None);
    }

    #[test]
    fn validator_status_maps_to_staked_and_serving() {
        assert_eq!(
            validator_flags(&json!({"status": "PendingActive"})),
            (true, false)
        );
        assert_eq!(validator_flags(&json!({"status": "Active"})), (true, true));
        assert_eq!(
            validator_flags(&json!({"status": "Exited"})),
            (false, false)
        );
    }

    #[test]
    fn role_stakes_need_a_bond() {
        let v = json!({"stakes": [{"role": "ai", "bonded": "1000", "required": "1000"}, {"role": "rpc", "bonded": "0", "required": "5"}]});
        assert_eq!(staked_from_role_stakes(&v, "ai", 1000), Some(true));
        assert_eq!(staked_from_role_stakes(&v, "rpc", 5), Some(false));
        assert_eq!(staked_from_role_stakes(&v, "tee", 5), Some(false));
        assert_eq!(staked_from_role_stakes(&json!({}), "ai", 5), None);
    }
}
