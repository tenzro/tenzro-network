//! `tenzro_sponsoredInference`: a short inference a public page can offer
//! without holding a key, paid by a sponsoring agent.
//!
//! The sponsor is a delegated agent whose terms on chain name this machine
//! as a serving node. This node serves the call from its own runtime, then
//! pays itself out of the agent's wallet with an `AgentAct` it signs with
//! its hardware key for the agent; the chain checks that payment against
//! the agent's terms (its daily limit, its counterparties) like any other
//! agent action, and the node checks the call against those terms before it
//! serves it, so a call outside the grant the sponsor's controller signed is
//! refused up front (the method is payer-granted: the payer signed the grant,
//! not each call). The node adds its own bounds before it serves anything: a
//! per-source rate, a global rate, an output cap and a daily budget. Off
//! unless the operator configures it ([`SponsoredInferenceConfig`]).

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tenzro_storage::{CF_SETTLEMENTS, KvStore};

use crate::config::SponsoredInferenceConfig;
use crate::gcra::{GcraConfig, GcraDecision, GcraLimiter};
use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;

/// Longest input a sponsored call takes, bytes.
pub const MAX_INPUT_BYTES: usize = 4096;

const DAY_MS: u64 = 24 * 60 * 60 * 1000;

fn err(code: i32, message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code,
        message: message.into(),
        data: None,
    }
}

fn limited(retry_after: Duration) -> JsonRpcError {
    JsonRpcError {
        code: crate::ip_rate_limit::RPC_ERR_RATE_LIMITED,
        message: "sponsored calls are rate limited; retry later".into(),
        data: Some(json!({ "retry_after_ms": retry_after.as_millis() as u64 })),
    }
}

fn per_minute(n: u32) -> GcraConfig {
    let n = n.max(1);
    GcraConfig {
        period: Duration::from_millis(60_000 / u64::from(n)).max(Duration::from_millis(1)),
        burst: (n / 4).max(1),
    }
}

struct Gates {
    source: GcraLimiter,
    global: GcraLimiter,
}

static GATES: OnceLock<Gates> = OnceLock::new();
static BUDGET: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

/// Tracked source addresses past which fully replenished ones are dropped.
const EVICT_ABOVE: usize = 10_000;

/// Admit one call from `source`: its own rate first, then the global one.
fn admit(cfg: &SponsoredInferenceConfig, source: &str) -> Result<(), JsonRpcError> {
    let gates = GATES.get_or_init(|| Gates {
        source: GcraLimiter::new(per_minute(cfg.per_source_per_minute)),
        global: GcraLimiter::new(per_minute(cfg.global_per_minute)),
    });
    if gates.source.active_keys() > EVICT_ABOVE {
        gates.source.evict_replenished();
    }
    if let GcraDecision::Deny { retry_after } = gates.source.check(source) {
        return Err(limited(retry_after));
    }
    if let GcraDecision::Deny { retry_after } = gates.global.check("all") {
        return Err(limited(retry_after));
    }
    Ok(())
}

fn spent_key(day: u64) -> Vec<u8> {
    format!("sponsor:spent:{day}").into_bytes()
}

fn read_spent(store: &dyn KvStore, day: u64) -> Result<u128, JsonRpcError> {
    match store
        .get(CF_SETTLEMENTS, &spent_key(day))
        .map_err(|e| err(-32603, e.to_string()))?
    {
        None => Ok(0),
        Some(b) => <[u8; 16]>::try_from(b.as_slice())
            .map(u128::from_le_bytes)
            .map_err(|_| err(-32603, "the stored sponsored spend is not 16 bytes")),
    }
}

fn write_spent(store: &dyn KvStore, day: u64, spent: u128) -> Result<(), JsonRpcError> {
    store
        .put(CF_SETTLEMENTS, &spent_key(day), &spent.to_le_bytes())
        .map_err(|e| err(-32603, e.to_string()))
}

/// Hold `amount` of `day`'s budget, refused when it would pass `budget`.
fn reserve(store: &dyn KvStore, day: u64, amount: u128, budget: u128) -> Result<(), JsonRpcError> {
    let _held = BUDGET.lock();
    let spent = read_spent(store, day)?;
    if spent.saturating_add(amount) > budget {
        return Err(err(
            -32029,
            "today's sponsored budget is spent; try again tomorrow (UTC)",
        ));
    }
    write_spent(store, day, spent + amount)
}

/// Give back `amount` of what [`reserve`] held for `day`.
fn release(store: &dyn KvStore, day: u64, amount: u128) {
    let _held = BUDGET.lock();
    if let Ok(spent) = read_spent(store, day)
        && let Err(e) = write_spent(store, day, spent.saturating_sub(amount))
    {
        tracing::warn!(error = %e.message, "sponsored budget release not written");
    }
}

/// What the sponsor's payment says it paid for: the model, the input and
/// the output, each length-prefixed.
fn request_digest(model: &str, input: &str, output: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"tenzro/sponsored-inference");
    for part in [model, input, output] {
        h.update((part.len() as u64).to_le_bytes());
        h.update(part.as_bytes());
    }
    h.finalize().into()
}

/// The call's parameters, checked against the operator's terms.
#[derive(Debug, PartialEq, Eq)]
struct Request {
    model: String,
    input: String,
    max_tokens: u32,
}

fn parse(cfg: &SponsoredInferenceConfig, params: &Value) -> Result<Request, JsonRpcError> {
    let text = |k: &str| {
        params
            .get(k)
            .and_then(Value::as_str)
            .ok_or_else(|| err(-32602, format!("{k} is required")))
    };
    let sponsor = text("sponsor")?;
    if sponsor != cfg.sponsor {
        return Err(err(-32602, "this node sponsors calls for another sponsor"));
    }
    let model = text("model")?;
    if !cfg.models.iter().any(|m| m == model) {
        return Err(err(
            -32602,
            format!("{model} is not sponsored on this node"),
        ));
    }
    let input = text("input")?;
    if input.is_empty() || input.len() > MAX_INPUT_BYTES {
        return Err(err(
            -32602,
            format!("input must be 1 to {MAX_INPUT_BYTES} bytes"),
        ));
    }
    let max_tokens = match params.get("max_tokens") {
        None | Some(Value::Null) => cfg.max_tokens,
        Some(v) => v
            .as_u64()
            .filter(|n| *n >= 1 && *n <= u64::from(cfg.max_tokens))
            .ok_or_else(|| {
                err(
                    -32602,
                    format!("max_tokens must be 1 to {}", cfg.max_tokens),
                )
            })? as u32,
    };
    Ok(Request {
        model: model.to_string(),
        input: input.to_string(),
        max_tokens,
    })
}

/// `tenzro_sponsoredInference { model, input, max_tokens?, sponsor }`.
pub(crate) async fn handle(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let cfg = node
        .config()
        .sponsored_inference
        .clone()
        .ok_or_else(|| err(-32601, "this node does not offer sponsored inference"))?;
    let params = crate::rpc::unwrap_param_object(params);
    let req = parse(&cfg, &params)?;
    // Only a call that came in over HTTP has a source to hold to its rate.
    let source = crate::ip_rate_limit::arrival()
        .ok_or_else(|| err(-32600, "sponsored calls are taken over HTTP only"))?;
    admit(&cfg, &source.ip.to_string())?;

    let runtime = node
        .model_runtime
        .as_ref()
        .ok_or_else(|| err(-32000, "this node runs no models"))?;
    if !node.served_models.contains_key(&req.model) {
        return Err(err(
            -32000,
            format!("{} is not loaded on this node", req.model),
        ));
    }
    let payee = node
        .operator_payee()
        .ok_or_else(|| err(-32000, "this node has no payee to be paid at"))?;
    let store = node
        .storage()
        .cloned()
        .ok_or_else(|| err(-32603, "storage not initialized"))?;
    // The most the call can cost: every input byte a token, every output
    // token asked for.
    let ceiling = crate::rpc::price_local_units(
        node,
        &req.model,
        &tenzro_types::model::BillableUnits::tokens(req.input.len() as u32, req.max_tokens),
    )?;
    let chain = crate::rpc::chain_state_of(node)
        .ok_or_else(|| err(-32603, "chain state is not available"))?;
    let (_, _, machine_did) =
        crate::agent_delegation::this_machine().map_err(|e| err(-32603, e))?;
    within_grant(
        &chain,
        &cfg,
        &req,
        &machine_did,
        payee,
        ceiling,
        crate::calendar::now_ms(),
    )?;
    let day = crate::calendar::now_ms() / DAY_MS;
    reserve(store.as_ref(), day, ceiling, cfg.daily_budget)?;

    let served = serve_and_pay(node, &cfg, &req, runtime, payee).await;
    match &served {
        Ok((_, cost)) => release(store.as_ref(), day, ceiling.saturating_sub(*cost)),
        Err(_) => release(store.as_ref(), day, ceiling),
    }
    served.map(|(v, _)| v)
}

/// The payment `cfg.sponsor` makes to `payee` for one call, as this node
/// signs it for the sponsor.
fn sponsor_payment(
    cfg: &SponsoredInferenceConfig,
    req: &Request,
    machine_did: String,
    payee: tenzro_types::primitives::Address,
    amount: u128,
    payment_id: String,
    request_digest: [u8; 32],
    nonce: u64,
) -> tenzro_types::agent_terms::AgentAction {
    use tenzro_types::agent_terms::{AgentAction, AgentPayment, OP_PAY};
    AgentAction {
        asset: None,
        usd_e6: 0,
        payment: Some(AgentPayment {
            payment_id,
            request_digest,
            quote_digest: [0u8; 32],
        }),
        agent_did: cfg.sponsor.clone(),
        machine_did,
        operation: OP_PAY.to_string(),
        counterparty: hex::encode(payee.as_bytes()),
        amount,
        chain: "tenzro".to_string(),
        payment_protocol: None,
        model: Some(req.model.clone()),
        calls: Vec::new(),
        escrow: None,
        remote_grant: None,
        ballot: None,
        veto_signal: None,
        nonce,
        tainted: false,
        step_up: None,
    }
}

/// Refuse a call the sponsor's grant does not cover before anything is
/// served: the sponsor's approved terms on chain must let this machine pay
/// `payee` up to `ceiling` for `req.model` now, exactly as the chain will
/// check the payment (standing, renewal, bond, expiry, operation, model,
/// counterparty and every cap).
fn within_grant(
    chain: &dyn tenzro_vm::traits::VmState,
    cfg: &SponsoredInferenceConfig,
    req: &Request,
    machine_did: &str,
    payee: tenzro_types::primitives::Address,
    ceiling: u128,
    now_ms: u64,
) -> Result<(), JsonRpcError> {
    let action = sponsor_payment(
        cfg,
        req,
        machine_did.to_string(),
        payee,
        ceiling,
        "sponsored-check".to_string(),
        request_digest(&req.model, &req.input, ""),
        tenzro_vm::native::read_agent_act_nonce(chain, &cfg.sponsor),
    );
    tenzro_vm::native::check_agent_act(chain, &action, None, now_ms)
        .map(|_| ())
        .map_err(|e| err(-32003, format!("outside the sponsor's grant: {e}")))
}

async fn serve_and_pay(
    node: &Arc<TenzroNode>,
    cfg: &SponsoredInferenceConfig,
    req: &Request,
    runtime: &Arc<tenzro_model::ModelRuntime>,
    payee: tenzro_types::primitives::Address,
) -> Result<(Value, u128), JsonRpcError> {
    let config = tenzro_model::GenerationConfig {
        max_tokens: req.max_tokens,
        ..Default::default()
    };
    let served_at = crate::calendar::now_ms();
    let result = runtime
        .generate(&req.model, &req.input, &config)
        .await
        .map_err(|e| err(-32000, crate::rpc::sanitize_model_error(&e)))?;
    node.metrics().record_inference();
    let units =
        tenzro_types::model::BillableUnits::tokens(result.input_tokens, result.output_tokens);
    let cost = crate::rpc::price_local_units(node, &req.model, &units)?;
    let chain = crate::rpc::chain_state_of(node)
        .ok_or_else(|| err(-32603, "chain state is not available"))?;
    let (_, _, machine_did) =
        crate::agent_delegation::this_machine().map_err(|e| err(-32603, e))?;
    let action = sponsor_payment(
        cfg,
        req,
        machine_did,
        payee,
        cost,
        format!("sponsored-{}", uuid::Uuid::new_v4()),
        request_digest(&req.model, &req.input, &result.text),
        tenzro_vm::native::read_agent_act_nonce(&chain, &cfg.sponsor),
    );
    let paid = crate::agent_delegation::act_signed(node, &chain, action).await?;
    let tx_hash = paid["tx_hash"].as_str().map(str::to_string);
    let pay_ref = paid["pay_ref"].as_str().map(str::to_string);
    if let (Some(tx_hash), Some(pay_ref)) = (tx_hash.clone(), pay_ref.clone()) {
        crate::work_settlements::record_call(
            node,
            crate::work_settlements::Call {
                model_id: &req.model,
                units: &units,
                provider: payee,
                routed: false,
                payer: Some(tenzro_types::primitives::Address::new(
                    tenzro_types::agent_terms::agent_wallet(&cfg.sponsor),
                )),
                call_attribution: None,
                amount: cost,
                served_at_ms: served_at,
                paid: crate::work_settlements::Paid::Ledger { tx_hash, pay_ref },
            },
        )
        .await;
    }
    Ok((
        json!({
            "provider": format!("0x{}", hex::encode(payee.as_bytes())),
            "model": req.model,
            "output": result.text,
            "units": crate::rpc::units_to_json(&units),
            "cost": cost.to_string(),
            "sponsor": cfg.sponsor,
            "tx_hash": tx_hash,
            "pay_ref": pay_ref,
        }),
        cost,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> SponsoredInferenceConfig {
        SponsoredInferenceConfig {
            sponsor: "did:tenzro:agent:sponsor".into(),
            models: vec!["small".into()],
            max_tokens: 64,
            per_source_per_minute: 4,
            global_per_minute: 8,
            daily_budget: 1_000,
        }
    }

    #[test]
    fn a_call_names_the_sponsor_a_sponsored_model_and_stays_within_the_caps() {
        let c = cfg();
        let ok = json!({ "sponsor": c.sponsor, "model": "small", "input": "hi" });
        assert_eq!(
            parse(&c, &ok).unwrap(),
            Request {
                model: "small".into(),
                input: "hi".into(),
                max_tokens: 64
            }
        );
        let with = |k: &str, v: Value| {
            let mut p = ok.clone();
            p[k] = v;
            parse(&c, &p)
        };
        assert!(with("sponsor", json!("did:tenzro:agent:other")).is_err());
        assert!(with("model", json!("large")).is_err());
        assert!(with("input", json!("")).is_err());
        assert!(with("input", json!("x".repeat(MAX_INPUT_BYTES + 1))).is_err());
        assert!(with("max_tokens", json!(65)).is_err());
        assert!(with("max_tokens", json!(0)).is_err());
        assert_eq!(with("max_tokens", json!(10)).unwrap().max_tokens, 10);
    }

    #[test]
    fn the_daily_budget_holds_and_releases() {
        let dir = tempfile::tempdir().unwrap();
        let s = tenzro_storage::RocksDbStore::open_default(dir.path()).unwrap();
        reserve(&s, 1, 600, 1_000).unwrap();
        assert!(reserve(&s, 1, 500, 1_000).is_err());
        release(&s, 1, 200);
        reserve(&s, 1, 500, 1_000).unwrap();
        assert_eq!(read_spent(&s, 1).unwrap(), 900);
        // Another day starts from nothing.
        reserve(&s, 2, 1_000, 1_000).unwrap();
    }

    #[test]
    fn a_source_is_held_to_its_rate() {
        let c = cfg();
        let gate = GcraLimiter::new(per_minute(c.per_source_per_minute));
        assert!(matches!(gate.check("a"), GcraDecision::Admit { .. }));
        assert!(matches!(gate.check("a"), GcraDecision::Deny { .. }));
        assert!(matches!(gate.check("b"), GcraDecision::Admit { .. }));
    }

    /// Terms the sponsor's controller approved: paying for `small`, at most
    /// 1000 per payment, until `expires_at_ms`, served by `MACHINE`.
    fn seed_grant(state: &mut tenzro_vm::StateAdapter, expires_at_ms: Option<u64>) {
        use tenzro_types::agent_terms::{AgentTerms, RootKind, ServingNode, TermsScope};
        use tenzro_vm::traits::VmState as _;
        let stored = tenzro_vm::native::StoredAgentTerms {
            terms: AgentTerms {
                controller_did: "did:tenzro:human:controller".into(),
                agent_name: "sponsor".into(),
                delegation_scope: TermsScope {
                    max_transaction_value: Some("1000".into()),
                    allowed_operations: vec![tenzro_types::agent_terms::OP_PAY.into()],
                    allowed_models: vec!["small".into()],
                    ..Default::default()
                },
                capabilities: Vec::new(),
                serving_nodes: vec![ServingNode {
                    machine_did: MACHINE.into(),
                    operator_did: "did:tenzro:human:operator".into(),
                    ..Default::default()
                }],
                min_distinct_operators: 1,
                expires_at_ms,
                trifecta_exception: false,
                auto_approve: None,
                credentials: Vec::new(),
            },
            root: RootKind::Passkey,
            version: 1,
            approval_digest: String::new(),
            updated_at_ms: NOW as i64,
            renewed_at_ms: None,
        };
        state.set_storage(
            &tenzro_vm::native::SYSTEM_ADDRESS,
            tenzro_vm::native::agent_terms::terms_key(&cfg().sponsor).as_bytes(),
            serde_json::to_vec(&stored).unwrap(),
        );
        // 1 TNZO: above the bond the terms' 1000 micro-unit ceiling needs at
        // the default rate, so only the grant decides these calls.
        state.set_balance(
            tenzro_token::derive_bond_vault_address(&cfg().sponsor).as_bytes(),
            1_000_000_000_000_000_000,
        );
    }

    const MACHINE: &str = "did:tenzro:machine:sponsor-host";
    const NOW: u64 = 1_800_000_000_000;

    /// A sponsored call is served only inside the grant the sponsor's
    /// controller signed: a model it does not cover, a call that could cost
    /// more than its per-payment cap, a grant past its expiry, a revoked
    /// sponsor and a machine it does not name are all refused before
    /// anything is served.
    #[test]
    fn a_call_outside_the_sponsors_signed_grant_is_refused() {
        use tenzro_vm::traits::VmState as _;
        let dir = tempfile::tempdir().unwrap();
        let store =
            std::sync::Arc::new(tenzro_storage::RocksDbStore::open_default(dir.path()).unwrap());
        let mut state = tenzro_vm::StateAdapter::with_storage(store);
        seed_grant(&mut state, Some(NOW + DAY_MS));
        let c = cfg();
        let payee = tenzro_types::primitives::Address::new([0x33; 32]);
        let small = Request {
            model: "small".into(),
            input: "hi".into(),
            max_tokens: 8,
        };
        let check =
            |state: &tenzro_vm::StateAdapter, req: &Request, machine: &str, ceiling, now| {
                within_grant(state, &c, req, machine, payee, ceiling, now)
            };

        check(&state, &small, MACHINE, 1000, NOW).expect("inside the grant");

        let large = Request {
            model: "large".into(),
            input: "hi".into(),
            max_tokens: 8,
        };
        let refused = |r: Result<(), JsonRpcError>, what: &str| {
            let e = r.expect_err(what);
            assert!(e.message.contains("sponsor"), "{what}: {}", e.message);
        };
        refused(
            check(&state, &large, MACHINE, 10, NOW),
            "a model outside the grant",
        );
        // The grant's caps are in micro-units of account: 1000 is the
        // per-payment cap, and the smallest TNZO amount worth more is refused.
        let rate = tenzro_vm::native::read_fee_rate(&state).rate_nano_usd;
        let at_cap = tenzro_vm::native::settlement_asset::units_for_e6(1000, rate, 18);
        let over_cap = tenzro_vm::native::settlement_asset::units_for_e6(1001, rate, 18);
        check(&state, &small, MACHINE, at_cap, NOW).expect("at the per-payment cap");
        refused(
            check(&state, &small, MACHINE, over_cap, NOW),
            "over the per-payment cap",
        );
        refused(
            check(&state, &small, MACHINE, 10, NOW + DAY_MS),
            "past the grant's expiry",
        );
        refused(
            check(&state, &small, "did:tenzro:machine:other", 10, NOW),
            "a machine the grant does not name",
        );

        state.set_storage(
            &tenzro_vm::native::SYSTEM_ADDRESS,
            tenzro_vm::native::agent_audit::quarantine_key(&c.sponsor).as_bytes(),
            serde_json::to_vec(&tenzro_vm::native::AgentQuarantine {
                controller_did: "did:tenzro:human:controller".into(),
                by: "controller".into(),
                reason_code: 0,
                evidence_hash: None,
                at_ms: NOW as i64,
                revoked: true,
            })
            .unwrap(),
        );
        refused(check(&state, &small, MACHINE, 10, NOW), "a revoked sponsor");
    }

    #[test]
    fn the_payment_binds_model_input_and_output() {
        let d = request_digest("m", "in", "out");
        assert_ne!(d, request_digest("m", "in", "out2"));
        assert_ne!(d, request_digest("m", "inout", ""));
    }
}
