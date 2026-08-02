//! Declarative [`ExecutionStep`] interpreter.
//!
//! The executor walks an [`ExecutionSpec`] step list and dispatches
//! every variant to the appropriate Tenzro subsystem. Each dispatch is
//! routed through the **local node's JSON-RPC endpoint** rather than by
//! constructing bespoke subsystem instances inside the executor — the
//! node already has `MultiVmRuntime`, `BridgeRouter`, `MppClient`,
//! `X402Client`, and `DamlExecutor` wired up, and exposes them via the
//! 60+ RPC methods defined in `tenzro-node/src/rpc.rs`. This keeps the
//! executor small, stateless, and "zero hardcoding" compliant: it never
//! has to know about wallet services, Canton config, state adapters, etc.
//!
//! ## Dispatch map
//!
//! | Step variant      | RPC method / handler used                         |
//! |-------------------|---------------------------------------------------|
//! | `EvmDispatch`     | `tenzro_signAndSendTransaction` (DPoP-authed)     |
//! | `SvmDispatch`     | `tenzro_svmDispatch` (DPoP-authed)                |
//! | `BridgeTransfer`  | `tenzro_bridgeTokens` (or `tenzro_getBridgeRoutes`)|
//! | `MppPay`          | `tenzro_payMpp`                                   |
//! | `X402Pay`         | `tenzro_payX402`                                  |
//! | `DamlSubmit`      | `tenzro_submitDamlCommand`                        |
//! | `ToolInvoke`      | `tenzro_useTool`                                  |
//! | `SkillInvoke`     | `tenzro_useSkill`                                 |
//! | `ForEach`         | calls `tenzro_useTool`, iterates the JSON array   |
//! | `When`            | evaluates a JMESPath expression over the context  |
//!
//! ## Delegation gating
//!
//! Before dispatching any destructive step, the executor calls
//! [`IdentityRegistry::enforce_operation`] (which is **sync**, not async)
//! with the operation label and — where applicable — the u128 value.
//! A `DelegationViolation` causes the step to be recorded as
//! `StepStatus::SkippedByDelegation` and execution continues with the
//! next step. A transport or RPC error causes the step to be recorded
//! as `StepStatus::Failed` but execution also continues — we want a
//! partial run report rather than a hard abort, so the caller can see
//! which steps did execute.
//!
//! ## Dry-run mode
//!
//! When [`RunOptions::dry_run`] is `true`, every step is still gated by
//! delegation and still produces a [`StepResult`], but no dispatch RPC
//! is actually made. This is the recommended way to verify an agent
//! before turning it loose on real funds.

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::{Value, json};

use tenzro_identity::IdentityRegistry;
use tenzro_types::agent_template::{
    ExecutionBackend, ExecutionSpec, ExecutionStep, SvmAccountMeta,
};

use crate::error::AgentKitError;
use crate::registry::RegistryClient;
use crate::spawner::SpawnedAgent;
use crate::spec::{check_hard_cap, substitute};

/// Per-run configuration.
#[derive(Debug, Clone)]
pub struct RunOptions {
    /// Maximum number of times the top-level step list is walked.
    /// Defaults to `1`. For long-running agents callers typically set a
    /// higher bound and rely on delegation/hard-cap enforcement to
    /// bound total spend.
    pub max_iterations: usize,

    /// If `true`, gate every step through delegation + hard-cap checks
    /// but never actually make a dispatch RPC. Useful for verifying an
    /// agent before running it against real funds.
    pub dry_run: bool,

    /// Optional Canton participant `(host, port)` override. When unset,
    /// DAML steps fall through to whatever the local node has configured.
    pub canton_participant: Option<(String, u16)>,

    /// Optional chain id override for EVM dispatch. When unset, the
    /// executor reads it from the [`ExecutionBackend::Evm`] backend, or
    /// falls back to `1337`.
    pub chain_id_override: Option<u64>,
}

impl Default for RunOptions {
    fn default() -> Self {
        Self {
            max_iterations: 1,
            dry_run: false,
            canton_participant: None,
            chain_id_override: None,
        }
    }
}

impl RunOptions {
    /// Convenience constructor for a dry-run with a single iteration.
    pub fn dry_run() -> Self {
        Self {
            dry_run: true,
            ..Self::default()
        }
    }

    /// Sets the maximum iteration count.
    pub fn with_max_iterations(mut self, n: usize) -> Self {
        self.max_iterations = n;
        self
    }
}

/// Outcome of running a single [`ExecutionStep`].
#[derive(Debug, Clone)]
pub struct StepResult {
    /// Short tag describing the step variant (e.g. `"EvmDispatch"`).
    pub step_kind: String,

    /// Operation label passed to `enforce_operation` (e.g. `"bridge"`).
    pub operation: String,

    /// Status of the step.
    pub status: StepStatus,

    /// Free-form message (reason for skip/fail, output summary, etc.).
    pub message: String,

    /// Optional dispatch output as a JSON value (e.g. the body returned
    /// by `tenzro_useTool`).
    pub output: Option<Value>,
}

/// Per-step status flag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepStatus {
    /// Step was dispatched successfully.
    Executed,
    /// Step was skipped because delegation scope rejected it.
    SkippedByDelegation,
    /// Step was skipped because a `When` predicate was falsy.
    SkippedByPredicate,
    /// Step was skipped in dry-run mode.
    DryRun,
    /// Step failed during dispatch (transport or RPC error).
    Failed,
    /// Step was skipped because it exceeded the spec's hard caps.
    SkippedByHardCap,
}

/// Aggregate report returned by [`Executor::run`].
#[derive(Debug, Clone, Default)]
pub struct RunReport {
    /// Number of steps executed successfully.
    pub steps_executed: usize,

    /// Number of steps skipped by delegation scope enforcement.
    pub steps_skipped_by_delegation: usize,

    /// Number of steps skipped by a falsy `When` predicate.
    pub steps_skipped_by_predicate: usize,

    /// Number of steps skipped in dry-run mode.
    pub steps_skipped_by_dry_run: usize,

    /// Number of steps skipped due to hard caps.
    pub steps_skipped_by_hard_cap: usize,

    /// Number of steps that failed during dispatch.
    pub steps_failed: usize,

    /// Aggregate value dispatched across all EVM/bridge/payment steps,
    /// in base units (u128 saturating).
    pub total_value_dispatched: u128,

    /// Per-step result list, in the order steps were walked.
    pub step_results: Vec<StepResult>,
}

impl RunReport {
    fn push(&mut self, result: StepResult, value_dispatched: u128) {
        match result.status {
            StepStatus::Executed => self.steps_executed += 1,
            StepStatus::SkippedByDelegation => self.steps_skipped_by_delegation += 1,
            StepStatus::SkippedByPredicate => self.steps_skipped_by_predicate += 1,
            StepStatus::DryRun => self.steps_skipped_by_dry_run += 1,
            StepStatus::SkippedByHardCap => self.steps_skipped_by_hard_cap += 1,
            StepStatus::Failed => self.steps_failed += 1,
        }
        self.total_value_dispatched = self.total_value_dispatched.saturating_add(value_dispatched);
        self.step_results.push(result);
    }

    /// Total number of steps walked (successes + skips + fails).
    pub fn total_steps(&self) -> usize {
        self.step_results.len()
    }
}

/// Mutable execution context passed into each step.
///
/// Holds the free-form variable map (spawn context + accumulated step
/// output bindings) plus a running total of dispatched value for hard
/// cap enforcement.
#[derive(Debug, Clone)]
pub struct ExecutionContext {
    /// Variable map used for `{{var}}` substitution.
    pub vars: HashMap<String, String>,

    /// Accumulated output bindings so later steps can reference earlier
    /// results via `{{output.field}}` style substitutions.
    pub outputs: HashMap<String, Value>,

    /// Running total of value dispatched this run.
    pub running_total: u128,
}

impl ExecutionContext {
    /// Constructs a context from a spawn-time variable map.
    pub fn new(vars: HashMap<String, String>) -> Self {
        Self {
            vars,
            outputs: HashMap::new(),
            running_total: 0,
        }
    }

    /// Binds a key to a JSON value in the output map and also copies
    /// its string form into `vars` so subsequent `{{key}}` substitutions
    /// can reach it.
    pub fn bind_output(&mut self, key: impl Into<String>, value: Value) {
        let key = key.into();
        if let Some(s) = value.as_str() {
            self.vars.insert(key.clone(), s.to_string());
        } else {
            self.vars.insert(key.clone(), value.to_string());
        }
        self.outputs.insert(key, value);
    }

    /// Returns a [`serde_json::Value`] snapshot of the context suitable
    /// for JMESPath evaluation. Combines `vars` (as strings) and
    /// `outputs` (as raw JSON values).
    pub fn as_jmespath_target(&self) -> Value {
        let mut obj = serde_json::Map::new();
        for (k, v) in &self.vars {
            obj.insert(k.clone(), Value::String(v.clone()));
        }
        for (k, v) in &self.outputs {
            obj.insert(k.clone(), v.clone());
        }
        Value::Object(obj)
    }
}

/// The [`ExecutionStep`] interpreter.
///
/// Composed from a [`RegistryClient`] (to talk to the local node's RPC
/// endpoint) and a handle to the [`IdentityRegistry`] for delegation
/// enforcement. Statically a single instance can serve many runs; every
/// `run()` call produces a fresh [`ExecutionContext`] and [`RunReport`].
pub struct Executor {
    registry: Arc<RegistryClient>,
    identity_registry: Arc<IdentityRegistry>,
}

impl Executor {
    /// Constructs a new executor.
    pub fn new(registry: Arc<RegistryClient>, identity_registry: Arc<IdentityRegistry>) -> Self {
        Self {
            registry,
            identity_registry,
        }
    }

    /// Runs a spawned agent's [`ExecutionSpec`] to completion (or up to
    /// `run_opts.max_iterations` iterations).
    pub async fn run(
        &mut self,
        spawned: &SpawnedAgent,
        run_opts: RunOptions,
    ) -> Result<RunReport, AgentKitError> {
        let spec =
            spawned.template.execution_spec.as_ref().ok_or_else(|| {
                AgentKitError::MissingExecutionSpec(spawned.template.name.clone())
            })?;

        let mut ctx = ExecutionContext::new(spawned.context.clone());
        let mut report = RunReport::default();

        let iterations = run_opts.max_iterations.max(1);
        for iteration in 0..iterations {
            tracing::debug!(
                target: "tenzro_agent_kit::executor",
                iteration,
                max_iterations = iterations,
                "starting iteration"
            );
            self.run_steps(spawned, spec, &spec.steps, &mut ctx, &run_opts, &mut report)
                .await?;
        }

        tracing::info!(
            target: "tenzro_agent_kit::executor",
            agent_id = spawned.agent_id(),
            executed = report.steps_executed,
            skipped_delegation = report.steps_skipped_by_delegation,
            skipped_predicate = report.steps_skipped_by_predicate,
            skipped_dry_run = report.steps_skipped_by_dry_run,
            skipped_hard_cap = report.steps_skipped_by_hard_cap,
            failed = report.steps_failed,
            total_value = %report.total_value_dispatched,
            "run complete"
        );

        Ok(report)
    }

    /// Walks a step list sequentially.
    ///
    /// Recursive for `ForEach` and `When` bodies. Boxed future is used
    /// to keep the async recursion sound.
    fn run_steps<'a>(
        &'a mut self,
        spawned: &'a SpawnedAgent,
        spec: &'a ExecutionSpec,
        steps: &'a [ExecutionStep],
        ctx: &'a mut ExecutionContext,
        run_opts: &'a RunOptions,
        report: &'a mut RunReport,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), AgentKitError>> + Send + 'a>>
    {
        Box::pin(async move {
            for step in steps {
                self.run_step(spawned, spec, step, ctx, run_opts, report)
                    .await?;
            }
            Ok(())
        })
    }

    /// Dispatches a single step.
    async fn run_step(
        &mut self,
        spawned: &SpawnedAgent,
        spec: &ExecutionSpec,
        step: &ExecutionStep,
        ctx: &mut ExecutionContext,
        run_opts: &RunOptions,
        report: &mut RunReport,
    ) -> Result<(), AgentKitError> {
        match step {
            ExecutionStep::EvmDispatch {
                to,
                value,
                calldata_template,
                gas_limit,
            } => {
                self.dispatch_evm(
                    spawned,
                    spec,
                    to,
                    value,
                    calldata_template,
                    *gas_limit,
                    ctx,
                    run_opts,
                    report,
                )
                .await
            }
            ExecutionStep::SvmDispatch {
                program_id,
                accounts,
                instruction_data_template,
            } => {
                self.dispatch_svm(
                    spawned,
                    spec,
                    program_id,
                    accounts,
                    instruction_data_template,
                    ctx,
                    run_opts,
                    report,
                )
                .await
            }
            ExecutionStep::NodeRpc { method, params } => {
                self.dispatch_node_rpc(spawned, spec, method, params, ctx, run_opts, report)
                    .await
            }
            ExecutionStep::BridgeTransfer {
                from_chain,
                to_chain,
                asset,
                amount,
                strategy,
            } => {
                self.dispatch_bridge(
                    spawned, spec, from_chain, to_chain, asset, amount, strategy, ctx, run_opts,
                    report,
                )
                .await
            }
            ExecutionStep::MppPay {
                amount,
                asset,
                recipient,
                session_ttl_secs: _,
            } => {
                self.dispatch_mpp(
                    spawned, spec, amount, asset, recipient, ctx, run_opts, report,
                )
                .await
            }
            ExecutionStep::X402Pay {
                resource_url,
                amount,
                asset,
                recipient,
                facilitator: _,
            } => {
                let url = resource_url
                    .as_deref()
                    .or(recipient.as_deref())
                    .unwrap_or("");
                self.dispatch_x402(spawned, spec, url, amount, asset, ctx, run_opts, report)
                    .await
            }
            ExecutionStep::DamlSubmit {
                template_package,
                module,
                entity,
                command_variant,
                fields_json,
                template_id,
                choice,
                party: _,
                args_template,
            } => {
                // Support both old-style (template_package/module/entity/command_variant/fields_json)
                // and new-style (template_id/choice/args_template)
                let pkg = template_package
                    .as_deref()
                    .or(template_id.as_deref())
                    .unwrap_or("");
                let mod_name = module.as_deref().unwrap_or("");
                let ent = entity.as_deref().unwrap_or("");
                let cmd = command_variant
                    .as_deref()
                    .or(choice.as_deref())
                    .unwrap_or("Create");
                let fields = fields_json
                    .as_deref()
                    .or(args_template.as_deref())
                    .unwrap_or("{}");
                self.dispatch_daml(
                    spawned, spec, pkg, mod_name, ent, cmd, fields, ctx, run_opts, report,
                )
                .await
            }
            ExecutionStep::ToolInvoke {
                tool_tag,
                method: _,
                arguments_json,
                params_template,
            } => {
                let args = params_template
                    .as_deref()
                    .or(arguments_json.as_deref())
                    .unwrap_or("{}");
                self.dispatch_tool(spawned, tool_tag, args, ctx, run_opts, report)
                    .await
            }
            ExecutionStep::SkillInvoke {
                skill_tag,
                method: _,
                input_json,
                params_template,
            } => {
                let input = input_json
                    .as_deref()
                    .or(params_template.as_deref())
                    .unwrap_or("{}");
                self.dispatch_skill(spawned, skill_tag, input, ctx, run_opts, report)
                    .await
            }
            ExecutionStep::ForEach {
                source_tool_tag,
                body,
            } => {
                self.dispatch_for_each(spawned, spec, source_tool_tag, body, ctx, run_opts, report)
                    .await
            }
            ExecutionStep::When {
                jmespath_expr,
                body,
            } => {
                self.dispatch_when(spawned, spec, jmespath_expr, body, ctx, run_opts, report)
                    .await
            }
        }
    }

    // ──────────────────────────────────────────────────────────────────
    // Dispatch impls
    // ──────────────────────────────────────────────────────────────────

    #[allow(clippy::too_many_arguments)]
    async fn dispatch_evm(
        &self,
        spawned: &SpawnedAgent,
        spec: &ExecutionSpec,
        to: &str,
        value: &str,
        calldata_template: &str,
        gas_limit: u64,
        ctx: &mut ExecutionContext,
        run_opts: &RunOptions,
        report: &mut RunReport,
    ) -> Result<(), AgentKitError> {
        let operation = "evm_dispatch";

        // Interpolate template vars.
        let to_resolved = substitute(to, &ctx.vars)?;
        let value_resolved = substitute(value, &ctx.vars)?;
        let calldata_resolved = substitute(calldata_template, &ctx.vars)?;

        let value_u128 = parse_hex_u128(&value_resolved).unwrap_or(0);

        // Hard-cap gate.
        if let Err(e) = check_hard_cap(operation, value_u128, &spec.hard_caps) {
            report.push(
                StepResult {
                    step_kind: "EvmDispatch".into(),
                    operation: operation.into(),
                    status: StepStatus::SkippedByHardCap,
                    message: format!("hard cap: {e}"),
                    output: None,
                },
                0,
            );
            return Ok(());
        }

        // Delegation gate.
        if let Err(reason) = self.enforce(spawned, operation, Some(value_u128)) {
            report.push(
                StepResult {
                    step_kind: "EvmDispatch".into(),
                    operation: operation.into(),
                    status: StepStatus::SkippedByDelegation,
                    message: reason,
                    output: None,
                },
                0,
            );
            return Ok(());
        }

        // Running-total gate.
        if ctx.running_total.saturating_add(value_u128) > spec.hard_caps.per_day_value {
            report.push(
                StepResult {
                    step_kind: "EvmDispatch".into(),
                    operation: operation.into(),
                    status: StepStatus::SkippedByHardCap,
                    message: "per-day cap would be exceeded".into(),
                    output: None,
                },
                0,
            );
            return Ok(());
        }

        if run_opts.dry_run {
            let msg = format!(
                "dry-run: would dispatch EVM tx to={} value=0x{:x} gas_limit={} calldata_len={}",
                to_resolved,
                value_u128,
                gas_limit,
                calldata_resolved.len()
            );
            report.push(
                StepResult {
                    step_kind: "EvmDispatch".into(),
                    operation: operation.into(),
                    status: StepStatus::DryRun,
                    message: msg,
                    output: None,
                },
                0,
            );
            return Ok(());
        }

        // Real dispatch: route through `tenzro_signAndSendTransaction` with
        // the spawn-time DPoP-bound JWT. The agent's machine identity is the
        // bearer DID; the node's `resolve_auth_to_wallet` projects that to
        // the wallet bound at registration and signs hybrid (Ed25519 +
        // ML-DSA-65) under RAR-scoped authorization derived from the
        // template's `DelegationSpec`. If no `AuthIssuer` was wired at
        // spawn (`AgentKit::new` rather than `AgentKit::with_auth_issuer`),
        // we fail loudly here per `feedback_implement_dont_delete` — never
        // a silent unauthenticated fallback.
        let creds = match spawned.credentials.as_ref() {
            Some(c) => c,
            None => {
                report.push(
                    StepResult {
                        step_kind: "EvmDispatch".into(),
                        operation: operation.into(),
                        status: StepStatus::Failed,
                        message: format!(
                            "EVM dispatch requires DPoP credentials but the spawner was \
                             constructed without an AuthIssuer. Use AgentKit::with_auth_issuer \
                             at node startup. to={to_resolved} value={value_u128}"
                        ),
                        output: None,
                    },
                    0,
                );
                return Ok(());
            }
        };

        // `from` is the agent's machine wallet — the same address that
        // `register_machine_with_fee` bound a fresh MPC wallet to at spawn.
        let from_hex = format!(
            "0x{}",
            hex::encode(spawned.machine.wallet_address.as_bytes())
        );

        // Decode the template's calldata blob. Empty (or `"0x"`) means a
        // pure value transfer; anything else is a contract call where the
        // template has already encoded `selector ++ abi(args)`. We project
        // this into the `TransactionType` variants the node's typed-tx
        // signer understands.
        let raw_calldata = calldata_resolved
            .strip_prefix("0x")
            .unwrap_or(&calldata_resolved);
        let tx_type_json = if raw_calldata.is_empty() {
            json!({ "Transfer": { "amount": value_u128 } })
        } else {
            let bytes = match hex::decode(raw_calldata) {
                Ok(b) => b,
                Err(e) => {
                    report.push(
                        StepResult {
                            step_kind: "EvmDispatch".into(),
                            operation: operation.into(),
                            status: StepStatus::Failed,
                            message: format!(
                                "EVM dispatch: calldata is not valid hex: {e}. \
                                 calldata={calldata_resolved}"
                            ),
                            output: None,
                        },
                        0,
                    );
                    return Ok(());
                }
            };
            // `ContractCall { function, args }` — the event loop concatenates
            // `function.as_bytes() ++ args` and routes to the EVM. Pre-encoded
            // calldata goes entirely into `args` with `function: ""`.
            json!({
                "ContractCall": {
                    "function": "",
                    "args": bytes,
                }
            })
        };

        let mut params = json!({
            "from": from_hex,
            "to": to_resolved,
            "value": value_u128.to_string(),
            "gas_limit": gas_limit,
            "tx_type": tx_type_json,
        });
        // Chain id resolution: explicit `RunOptions` override beats the
        // template's `ExecutionBackend::Evm { chain_id }`, which in turn
        // beats the node default. We never silently fall through to 1337
        // here — if neither is set we omit the field and let the node fill
        // in its genesis chain_id.
        let chain_id_resolved = run_opts.chain_id_override.or(match &spec.backend {
            ExecutionBackend::Evm { chain_id } => Some(*chain_id),
            _ => None,
        });
        if let Some(chain_id) = chain_id_resolved {
            params["chain_id"] = json!(chain_id);
        }

        match self
            .registry
            .call_raw_with_auth("tenzro_signAndSendTransaction", params, creds)
            .await
        {
            Ok(output) => {
                ctx.running_total = ctx.running_total.saturating_add(value_u128);
                let tx_hash = output.get("tx_hash").and_then(|v| v.as_str()).unwrap_or("");
                report.push(
                    StepResult {
                        step_kind: "EvmDispatch".into(),
                        operation: operation.into(),
                        status: StepStatus::Executed,
                        message: format!(
                            "EVM tx signed and submitted: to={to_resolved} \
                             value={value_u128} tx_hash={tx_hash}"
                        ),
                        output: Some(output),
                    },
                    value_u128,
                );
            }
            Err(e) => {
                report.push(
                    StepResult {
                        step_kind: "EvmDispatch".into(),
                        operation: operation.into(),
                        status: StepStatus::Failed,
                        message: format!(
                            "EVM dispatch failed: {e}. to={to_resolved} value={value_u128}"
                        ),
                        output: None,
                    },
                    0,
                );
            }
        }

        Ok(())
    }

    /// Dispatches an [`ExecutionStep::SvmDispatch`] step.
    ///
    /// Mirrors [`Self::dispatch_evm`]: substitute template vars, gate
    /// through hard caps + delegation, honour dry-run, then call the
    /// node's `tenzro_svmDispatch` JSON-RPC handler with the spawn-time
    /// DPoP-bound JWT. The handler resolves the bearer DID to the
    /// agent's wallet, builds a Solana `Transaction` with the agent
    /// wallet as fee payer + first signer, signs with the wallet's
    /// Ed25519 leg, and routes the assembled tx through
    /// `MultiVmRuntime::execute(VmType::Svm)`.
    ///
    /// SVM instructions carry no native lamport-value field, so the
    /// hard-cap gate is invoked with `0` and the delegation enforcement
    /// runs against the `svm_dispatch` operation label only (no value
    /// component). Templates that need a per-instruction lamport ceiling
    /// must encode it in the instruction data itself.
    #[allow(clippy::too_many_arguments)]
    /// Dispatch an arbitrary node JSON-RPC method with the agent's DPoP
    /// credentials. The runtime's general bridge to node surfaces that have no
    /// bespoke step kind — saga `tenzro_workflow*`, task lifecycle,
    /// `tenzro_verifyDidEnvelope`, etc. `params_template` is `{{var}}`-resolved
    /// against the agent context (serialize → substitute → reparse).
    #[allow(clippy::too_many_arguments)]
    async fn dispatch_node_rpc(
        &self,
        spawned: &SpawnedAgent,
        spec: &ExecutionSpec,
        method: &str,
        params_template: &Value,
        ctx: &mut ExecutionContext,
        run_opts: &RunOptions,
        report: &mut RunReport,
    ) -> Result<(), AgentKitError> {
        let operation = "node_rpc";

        let tmpl = serde_json::to_string(params_template).unwrap_or_else(|_| "null".to_string());
        let resolved = substitute(&tmpl, &ctx.vars)?;
        let params: Value = serde_json::from_str(&resolved).unwrap_or(Value::Null);

        if let Err(e) = check_hard_cap(operation, 0, &spec.hard_caps) {
            report.push(
                StepResult {
                    step_kind: "NodeRpc".into(),
                    operation: operation.into(),
                    status: StepStatus::SkippedByHardCap,
                    message: format!("hard cap: {e}"),
                    output: None,
                },
                0,
            );
            return Ok(());
        }

        if let Err(reason) = self.enforce(spawned, operation, None) {
            report.push(
                StepResult {
                    step_kind: "NodeRpc".into(),
                    operation: operation.into(),
                    status: StepStatus::SkippedByDelegation,
                    message: reason,
                    output: None,
                },
                0,
            );
            return Ok(());
        }

        if run_opts.dry_run {
            report.push(
                StepResult {
                    step_kind: "NodeRpc".into(),
                    operation: operation.into(),
                    status: StepStatus::DryRun,
                    message: format!("dry-run: would call node RPC {method}"),
                    output: None,
                },
                0,
            );
            return Ok(());
        }

        let creds = match spawned.credentials.as_ref() {
            Some(c) => c,
            None => {
                report.push(
                    StepResult {
                        step_kind: "NodeRpc".into(),
                        operation: operation.into(),
                        status: StepStatus::Failed,
                        message: format!(
                            "node RPC {method} requires DPoP credentials but the spawner was \
                             constructed without an AuthIssuer. Use AgentKit::with_auth_issuer."
                        ),
                        output: None,
                    },
                    0,
                );
                return Ok(());
            }
        };

        match self
            .registry
            .call_raw_with_auth(method, params, creds)
            .await
        {
            Ok(output) => report.push(
                StepResult {
                    step_kind: "NodeRpc".into(),
                    operation: operation.into(),
                    status: StepStatus::Executed,
                    message: format!("node RPC {method} ok"),
                    output: Some(output),
                },
                0,
            ),
            Err(e) => report.push(
                StepResult {
                    step_kind: "NodeRpc".into(),
                    operation: operation.into(),
                    status: StepStatus::Failed,
                    message: format!("node RPC {method} failed: {e}"),
                    output: None,
                },
                0,
            ),
        }
        Ok(())
    }

    async fn dispatch_svm(
        &self,
        spawned: &SpawnedAgent,
        spec: &ExecutionSpec,
        program_id: &str,
        accounts: &[SvmAccountMeta],
        instruction_data_template: &str,
        ctx: &mut ExecutionContext,
        run_opts: &RunOptions,
        report: &mut RunReport,
    ) -> Result<(), AgentKitError> {
        let operation = "svm_dispatch";

        let program_id_resolved = substitute(program_id, &ctx.vars)?;
        let ix_data_resolved = substitute(instruction_data_template, &ctx.vars)?;
        let mut accounts_resolved: Vec<SvmAccountMeta> = Vec::with_capacity(accounts.len());
        for acct in accounts {
            accounts_resolved.push(SvmAccountMeta {
                pubkey: substitute(&acct.pubkey, &ctx.vars)?,
                is_signer: acct.is_signer,
                is_writable: acct.is_writable,
            });
        }

        // Hard-cap gate. SVM ix has no native value, but we still pass
        // through the standard per-op cap check so an spec author can
        // disable SVM dispatch entirely via `per_op_value_caps`.
        if let Err(e) = check_hard_cap(operation, 0, &spec.hard_caps) {
            report.push(
                StepResult {
                    step_kind: "SvmDispatch".into(),
                    operation: operation.into(),
                    status: StepStatus::SkippedByHardCap,
                    message: format!("hard cap: {e}"),
                    output: None,
                },
                0,
            );
            return Ok(());
        }

        // Delegation gate.
        if let Err(reason) = self.enforce(spawned, operation, None) {
            report.push(
                StepResult {
                    step_kind: "SvmDispatch".into(),
                    operation: operation.into(),
                    status: StepStatus::SkippedByDelegation,
                    message: reason,
                    output: None,
                },
                0,
            );
            return Ok(());
        }

        if run_opts.dry_run {
            let msg = format!(
                "dry-run: would dispatch SVM ix program={} accounts={} data_len={}",
                program_id_resolved,
                accounts_resolved.len(),
                ix_data_resolved
                    .strip_prefix("0x")
                    .unwrap_or(&ix_data_resolved)
                    .len()
                    / 2
            );
            report.push(
                StepResult {
                    step_kind: "SvmDispatch".into(),
                    operation: operation.into(),
                    status: StepStatus::DryRun,
                    message: msg,
                    output: None,
                },
                0,
            );
            return Ok(());
        }

        // DPoP credentials gate. Same contract as EVM: no AuthIssuer →
        // no SVM dispatch. Fail loudly per `feedback_implement_dont_delete`.
        let creds = match spawned.credentials.as_ref() {
            Some(c) => c,
            None => {
                report.push(
                    StepResult {
                        step_kind: "SvmDispatch".into(),
                        operation: operation.into(),
                        status: StepStatus::Failed,
                        message: format!(
                            "SVM dispatch requires DPoP credentials but the spawner was \
                             constructed without an AuthIssuer. Use AgentKit::with_auth_issuer \
                             at node startup. program={program_id_resolved}"
                        ),
                        output: None,
                    },
                    0,
                );
                return Ok(());
            }
        };

        // Decode instruction data from hex. Empty (or `"0x"`) means a
        // zero-data ping ix (rare but valid — e.g. system program
        // CreateAccount has a non-empty data; Memo with empty data is
        // pathological but legal).
        let raw_ix = ix_data_resolved
            .strip_prefix("0x")
            .unwrap_or(&ix_data_resolved);
        let ix_bytes = if raw_ix.is_empty() {
            Vec::new()
        } else {
            match hex::decode(raw_ix) {
                Ok(b) => b,
                Err(e) => {
                    report.push(
                        StepResult {
                            step_kind: "SvmDispatch".into(),
                            operation: operation.into(),
                            status: StepStatus::Failed,
                            message: format!(
                                "SVM dispatch: instruction_data is not valid hex: {e}. \
                                 data={ix_data_resolved}"
                            ),
                            output: None,
                        },
                        0,
                    );
                    return Ok(());
                }
            }
        };

        // Project `accounts_resolved` into the JSON shape the node's
        // `tenzro_svmDispatch` handler expects: a list of
        // `{ pubkey, is_signer, is_writable }` objects in the order the
        // program reads them. The agent's own wallet pubkey is supplied
        // by the handler as the fee-payer / first signer — templates
        // never need to list it themselves.
        let accounts_json: Vec<Value> = accounts_resolved
            .iter()
            .map(|a| {
                json!({
                    "pubkey": a.pubkey,
                    "is_signer": a.is_signer,
                    "is_writable": a.is_writable,
                })
            })
            .collect();

        let mut params = json!({
            "program_id": program_id_resolved,
            "accounts": accounts_json,
            "instruction_data": ix_bytes,
        });

        // Cluster identifier from the template's backend, if present.
        // Allows multi-cluster deployments to disambiguate
        // mainnet-beta / devnet / localhost without per-agent rewiring.
        if let ExecutionBackend::Svm { cluster } = &spec.backend {
            params["cluster"] = json!(cluster);
        }

        match self
            .registry
            .call_raw_with_auth("tenzro_svmDispatch", params, creds)
            .await
        {
            Ok(output) => {
                let signature = output
                    .get("signature")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                report.push(
                    StepResult {
                        step_kind: "SvmDispatch".into(),
                        operation: operation.into(),
                        status: StepStatus::Executed,
                        message: format!(
                            "SVM tx signed and submitted: program={program_id_resolved} \
                             accounts={} signature={signature}",
                            accounts_resolved.len()
                        ),
                        output: Some(output),
                    },
                    0,
                );
            }
            Err(e) => {
                report.push(
                    StepResult {
                        step_kind: "SvmDispatch".into(),
                        operation: operation.into(),
                        status: StepStatus::Failed,
                        message: format!("SVM dispatch failed: {e}. program={program_id_resolved}"),
                        output: None,
                    },
                    0,
                );
            }
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn dispatch_bridge(
        &self,
        spawned: &SpawnedAgent,
        spec: &ExecutionSpec,
        from_chain: &str,
        to_chain: &str,
        asset: &str,
        amount: &str,
        strategy: &str,
        ctx: &mut ExecutionContext,
        run_opts: &RunOptions,
        report: &mut RunReport,
    ) -> Result<(), AgentKitError> {
        let operation = "bridge";
        let from_resolved = substitute(from_chain, &ctx.vars)?;
        let to_resolved = substitute(to_chain, &ctx.vars)?;
        let asset_resolved = substitute(asset, &ctx.vars)?;
        let amount_resolved = substitute(amount, &ctx.vars)?;
        let amount_u128 = parse_u128(&amount_resolved).unwrap_or(0);

        if let Err(e) = check_hard_cap(operation, amount_u128, &spec.hard_caps) {
            report.push(
                StepResult {
                    step_kind: "BridgeTransfer".into(),
                    operation: operation.into(),
                    status: StepStatus::SkippedByHardCap,
                    message: format!("hard cap: {e}"),
                    output: None,
                },
                0,
            );
            return Ok(());
        }

        if let Err(reason) = self.enforce(spawned, operation, Some(amount_u128)) {
            report.push(
                StepResult {
                    step_kind: "BridgeTransfer".into(),
                    operation: operation.into(),
                    status: StepStatus::SkippedByDelegation,
                    message: reason,
                    output: None,
                },
                0,
            );
            return Ok(());
        }

        let adapters = match &spec.backend {
            ExecutionBackend::Bridge { adapters } => adapters.clone(),
            _ => Vec::new(),
        };

        if run_opts.dry_run {
            let msg = format!(
                "dry-run: would bridge {amount_resolved} {asset_resolved} from {from_resolved} to {to_resolved} via strategy={strategy} adapters={adapters:?}"
            );
            report.push(
                StepResult {
                    step_kind: "BridgeTransfer".into(),
                    operation: operation.into(),
                    status: StepStatus::DryRun,
                    message: msg,
                    output: None,
                },
                0,
            );
            return Ok(());
        }

        let rpc_params = json!({
            "from_chain": from_resolved,
            "to_chain": to_resolved,
            "asset": asset_resolved,
            "amount": amount_resolved,
            "strategy": strategy,
            "adapters": adapters,
            "agent_id": spawned.agent_id(),
        });

        match self
            .registry
            .call_raw("tenzro_bridgeTokens", rpc_params)
            .await
        {
            Ok(output) => {
                ctx.running_total = ctx.running_total.saturating_add(amount_u128);
                report.push(
                    StepResult {
                        step_kind: "BridgeTransfer".into(),
                        operation: operation.into(),
                        status: StepStatus::Executed,
                        message: format!("bridged {amount_resolved} {asset_resolved} {from_resolved}->{to_resolved}"),
                        output: Some(output),
                    },
                    amount_u128,
                );
            }
            Err(e) => report.push(
                StepResult {
                    step_kind: "BridgeTransfer".into(),
                    operation: operation.into(),
                    status: StepStatus::Failed,
                    message: format!("rpc error: {e}"),
                    output: None,
                },
                0,
            ),
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn dispatch_mpp(
        &self,
        spawned: &SpawnedAgent,
        spec: &ExecutionSpec,
        amount: &str,
        asset: &str,
        recipient: &str,
        ctx: &mut ExecutionContext,
        run_opts: &RunOptions,
        report: &mut RunReport,
    ) -> Result<(), AgentKitError> {
        let operation = "mpp_pay";
        let amount_resolved = substitute(amount, &ctx.vars)?;
        let asset_resolved = substitute(asset, &ctx.vars)?;
        let recipient_resolved = substitute(recipient, &ctx.vars)?;
        let amount_u128 = parse_u128(&amount_resolved).unwrap_or(0);

        if let Err(e) = check_hard_cap(operation, amount_u128, &spec.hard_caps) {
            report.push(
                StepResult {
                    step_kind: "MppPay".into(),
                    operation: operation.into(),
                    status: StepStatus::SkippedByHardCap,
                    message: format!("hard cap: {e}"),
                    output: None,
                },
                0,
            );
            return Ok(());
        }

        if let Err(reason) = self.enforce(spawned, operation, Some(amount_u128)) {
            report.push(
                StepResult {
                    step_kind: "MppPay".into(),
                    operation: operation.into(),
                    status: StepStatus::SkippedByDelegation,
                    message: reason,
                    output: None,
                },
                0,
            );
            return Ok(());
        }

        if run_opts.dry_run {
            report.push(
                StepResult {
                    step_kind: "MppPay".into(),
                    operation: operation.into(),
                    status: StepStatus::DryRun,
                    message: format!(
                        "dry-run: would pay {amount_resolved} {asset_resolved} to {recipient_resolved} via MPP"
                    ),
                    output: None,
                },
                0,
            );
            return Ok(());
        }

        let rpc_params = json!({
            "amount": amount_resolved,
            "asset": asset_resolved,
            "recipient": recipient_resolved,
            "agent_id": spawned.agent_id(),
            "machine_did": spawned.machine_did(),
        });

        match self.registry.call_raw("tenzro_payMpp", rpc_params).await {
            Ok(output) => {
                ctx.running_total = ctx.running_total.saturating_add(amount_u128);
                report.push(
                    StepResult {
                        step_kind: "MppPay".into(),
                        operation: operation.into(),
                        status: StepStatus::Executed,
                        message: format!(
                            "paid {amount_resolved} {asset_resolved} to {recipient_resolved}"
                        ),
                        output: Some(output),
                    },
                    amount_u128,
                );
            }
            Err(e) => report.push(
                StepResult {
                    step_kind: "MppPay".into(),
                    operation: operation.into(),
                    status: StepStatus::Failed,
                    message: format!("rpc error: {e}"),
                    output: None,
                },
                0,
            ),
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn dispatch_x402(
        &self,
        spawned: &SpawnedAgent,
        spec: &ExecutionSpec,
        resource_url: &str,
        amount: &str,
        asset: &str,
        ctx: &mut ExecutionContext,
        run_opts: &RunOptions,
        report: &mut RunReport,
    ) -> Result<(), AgentKitError> {
        let operation = "x402_pay";
        let url_resolved = substitute(resource_url, &ctx.vars)?;
        let amount_resolved = substitute(amount, &ctx.vars)?;
        let asset_resolved = substitute(asset, &ctx.vars)?;
        let amount_u128 = parse_u128(&amount_resolved).unwrap_or(0);

        if let Err(e) = check_hard_cap(operation, amount_u128, &spec.hard_caps) {
            report.push(
                StepResult {
                    step_kind: "X402Pay".into(),
                    operation: operation.into(),
                    status: StepStatus::SkippedByHardCap,
                    message: format!("hard cap: {e}"),
                    output: None,
                },
                0,
            );
            return Ok(());
        }

        if let Err(reason) = self.enforce(spawned, operation, Some(amount_u128)) {
            report.push(
                StepResult {
                    step_kind: "X402Pay".into(),
                    operation: operation.into(),
                    status: StepStatus::SkippedByDelegation,
                    message: reason,
                    output: None,
                },
                0,
            );
            return Ok(());
        }

        if run_opts.dry_run {
            report.push(
                StepResult {
                    step_kind: "X402Pay".into(),
                    operation: operation.into(),
                    status: StepStatus::DryRun,
                    message: format!(
                        "dry-run: would pay {amount_resolved} {asset_resolved} for resource {url_resolved} via x402"
                    ),
                    output: None,
                },
                0,
            );
            return Ok(());
        }

        let rpc_params = json!({
            "url": url_resolved,
            "amount": amount_resolved,
            "asset": asset_resolved,
            "agent_id": spawned.agent_id(),
            "machine_did": spawned.machine_did(),
        });

        match self.registry.call_raw("tenzro_payX402", rpc_params).await {
            Ok(output) => {
                ctx.running_total = ctx.running_total.saturating_add(amount_u128);
                report.push(
                    StepResult {
                        step_kind: "X402Pay".into(),
                        operation: operation.into(),
                        status: StepStatus::Executed,
                        message: format!(
                            "paid {amount_resolved} {asset_resolved} for {url_resolved}"
                        ),
                        output: Some(output),
                    },
                    amount_u128,
                );
            }
            Err(e) => report.push(
                StepResult {
                    step_kind: "X402Pay".into(),
                    operation: operation.into(),
                    status: StepStatus::Failed,
                    message: format!("rpc error: {e}"),
                    output: None,
                },
                0,
            ),
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn dispatch_daml(
        &self,
        spawned: &SpawnedAgent,
        _spec: &ExecutionSpec,
        template_package: &str,
        module: &str,
        entity: &str,
        command_variant: &str,
        fields_json: &str,
        ctx: &mut ExecutionContext,
        run_opts: &RunOptions,
        report: &mut RunReport,
    ) -> Result<(), AgentKitError> {
        let operation = "daml_submit";

        if let Err(reason) = self.enforce(spawned, operation, None) {
            report.push(
                StepResult {
                    step_kind: "DamlSubmit".into(),
                    operation: operation.into(),
                    status: StepStatus::SkippedByDelegation,
                    message: reason,
                    output: None,
                },
                0,
            );
            return Ok(());
        }

        // Bind `agent_party` to the spawn-time-allocated Canton party so
        // template `{{agent_party}}` placeholders resolve correctly. When
        // the template's backend is non-DAML this is `None` and the
        // substitution will fail loudly on first use of `{{agent_party}}` —
        // which is the right failure mode (DAML steps in a non-DAML
        // template are a config bug).
        if let Some(party) = spawned.canton_party_id() {
            ctx.vars
                .entry("agent_party".to_string())
                .or_insert_with(|| party.to_string());
        }

        let fields_resolved = substitute(fields_json, &ctx.vars)?;
        let fields_value: Value = serde_json::from_str(&fields_resolved)
            .map_err(|e| AgentKitError::Other(format!("daml fields not valid json: {e}")))?;

        // Compose Canton's `template_id` string from the constituent parts.
        // Canton 3.x JSON Ledger API expects `PackageId:Module:Entity`.
        let composed_template_id = format!("{template_package}:{module}:{entity}");

        // Map the executor's `command_variant` ("Create" | "Exercise" | a
        // choice name) to the RPC handler's `command_type` ("create" |
        // "exercise") + parameter shape. A "Create" submission carries
        // `create_arguments`; anything else is an exercise that needs a
        // `contract_id` and a `choice_argument`.
        let command_type = if command_variant.eq_ignore_ascii_case("create") {
            "create"
        } else {
            "exercise"
        };

        if run_opts.dry_run {
            report.push(
                StepResult {
                    step_kind: "DamlSubmit".into(),
                    operation: operation.into(),
                    status: StepStatus::DryRun,
                    message: format!(
                        "dry-run: would submit DAML {command_variant} on {composed_template_id} as {}",
                        spawned.canton_party_id().unwrap_or("<participant-default>"),
                    ),
                    output: None,
                },
                0,
            );
            return Ok(());
        }

        let mut rpc_params = serde_json::Map::new();
        rpc_params.insert("command_type".into(), json!(command_type));
        rpc_params.insert("template_id".into(), json!(composed_template_id));

        if command_type == "create" {
            rpc_params.insert("create_arguments".into(), fields_value);
        } else {
            // For exercise, the fields payload must include `contract_id`
            // (the target contract) and `choice_argument` (the choice
            // parameters). Pull `contract_id` out of the resolved fields
            // and use `command_variant` as the choice name.
            let contract_id = fields_value
                .get("contract_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    AgentKitError::Other(
                        "DAML exercise requires `contract_id` in fields_json".to_string(),
                    )
                })?
                .to_string();
            let choice_argument = fields_value
                .get("choice_argument")
                .cloned()
                .unwrap_or(Value::Null);
            rpc_params.insert("contract_id".into(), json!(contract_id));
            rpc_params.insert("choice".into(), json!(command_variant));
            rpc_params.insert("choice_argument".into(), choice_argument);
        }

        // Per-agent `actAs` override — the participant signs the command
        // on the agent's allocated party (not the operator's default).
        if let Some(party) = spawned.canton_party_id() {
            rpc_params.insert("act_as".into(), json!(party));
        }

        let rpc_params = Value::Object(rpc_params);

        match self
            .registry
            .call_raw("tenzro_submitDamlCommand", rpc_params)
            .await
        {
            Ok(output) => {
                ctx.bind_output("daml_last_result", output.clone());
                report.push(
                    StepResult {
                        step_kind: "DamlSubmit".into(),
                        operation: operation.into(),
                        status: StepStatus::Executed,
                        message: format!(
                            "submitted DAML {command_variant} on {composed_template_id} as {}",
                            spawned.canton_party_id().unwrap_or("<participant-default>"),
                        ),
                        output: Some(output),
                    },
                    0,
                );
            }
            Err(e) => report.push(
                StepResult {
                    step_kind: "DamlSubmit".into(),
                    operation: operation.into(),
                    status: StepStatus::Failed,
                    message: format!("rpc error: {e}"),
                    output: None,
                },
                0,
            ),
        }

        Ok(())
    }

    async fn dispatch_tool(
        &self,
        spawned: &SpawnedAgent,
        tool_tag: &str,
        arguments_json: &str,
        ctx: &mut ExecutionContext,
        run_opts: &RunOptions,
        report: &mut RunReport,
    ) -> Result<(), AgentKitError> {
        let operation = "tool_invoke";

        // Delegation gate — tool calls may have side effects.
        if let Err(reason) = self.enforce(spawned, operation, None) {
            report.push(
                StepResult {
                    step_kind: "ToolInvoke".into(),
                    operation: operation.into(),
                    status: StepStatus::SkippedByDelegation,
                    message: reason,
                    output: None,
                },
                0,
            );
            return Ok(());
        }

        let tool = match spawned.discovered.tool_by_tag(tool_tag) {
            Some(t) => t.clone(),
            None => {
                report.push(
                    StepResult {
                        step_kind: "ToolInvoke".into(),
                        operation: operation.into(),
                        status: StepStatus::Failed,
                        message: format!("tool tag '{tool_tag}' not discovered"),
                        output: None,
                    },
                    0,
                );
                return Ok(());
            }
        };

        let args_resolved = substitute(arguments_json, &ctx.vars)?;
        let args_value: Value = serde_json::from_str(&args_resolved)
            .map_err(|e| AgentKitError::Other(format!("tool arguments not valid json: {e}")))?;

        if run_opts.dry_run {
            report.push(
                StepResult {
                    step_kind: "ToolInvoke".into(),
                    operation: operation.into(),
                    status: StepStatus::DryRun,
                    message: format!("dry-run: would invoke tool '{tool_tag}' ({})", tool.tool_id),
                    output: None,
                },
                0,
            );
            return Ok(());
        }

        match self
            .registry
            .use_tool(&tool.tool_id, Some(&tool.name), args_value)
            .await
        {
            Ok(output) => {
                ctx.bind_output(format!("tool_{tool_tag}"), output.clone());
                report.push(
                    StepResult {
                        step_kind: "ToolInvoke".into(),
                        operation: operation.into(),
                        status: StepStatus::Executed,
                        message: format!("invoked tool '{tool_tag}' ({})", tool.tool_id),
                        output: Some(output),
                    },
                    0,
                );
            }
            Err(e) => report.push(
                StepResult {
                    step_kind: "ToolInvoke".into(),
                    operation: operation.into(),
                    status: StepStatus::Failed,
                    message: format!("use_tool rpc error: {e}"),
                    output: None,
                },
                0,
            ),
        }

        Ok(())
    }

    async fn dispatch_skill(
        &self,
        spawned: &SpawnedAgent,
        skill_tag: &str,
        input_json: &str,
        ctx: &mut ExecutionContext,
        run_opts: &RunOptions,
        report: &mut RunReport,
    ) -> Result<(), AgentKitError> {
        let operation = "skill_invoke";

        if let Err(reason) = self.enforce(spawned, operation, None) {
            report.push(
                StepResult {
                    step_kind: "SkillInvoke".into(),
                    operation: operation.into(),
                    status: StepStatus::SkippedByDelegation,
                    message: reason,
                    output: None,
                },
                0,
            );
            return Ok(());
        }

        let skill = match spawned.discovered.skill_by_tag(skill_tag) {
            Some(s) => s.clone(),
            None => {
                report.push(
                    StepResult {
                        step_kind: "SkillInvoke".into(),
                        operation: operation.into(),
                        status: StepStatus::Failed,
                        message: format!("skill tag '{skill_tag}' not discovered"),
                        output: None,
                    },
                    0,
                );
                return Ok(());
            }
        };

        let input_resolved = substitute(input_json, &ctx.vars)?;
        let input_value: Value = serde_json::from_str(&input_resolved)
            .map_err(|e| AgentKitError::Other(format!("skill input not valid json: {e}")))?;

        if run_opts.dry_run {
            report.push(
                StepResult {
                    step_kind: "SkillInvoke".into(),
                    operation: operation.into(),
                    status: StepStatus::DryRun,
                    message: format!(
                        "dry-run: would invoke skill '{skill_tag}' ({})",
                        skill.skill_id
                    ),
                    output: None,
                },
                0,
            );
            return Ok(());
        }

        // Pin what discovery resolved: a republish between discovery and
        // invocation should fail the step, not silently run different bytes.
        match self
            .registry
            .use_skill(
                &skill.skill_id,
                input_value,
                Some(&skill.version),
                skill.bundle.as_ref().map(|b| b.sha256.as_str()),
            )
            .await
        {
            Ok(output) => {
                ctx.bind_output(format!("skill_{skill_tag}"), output.clone());
                report.push(
                    StepResult {
                        step_kind: "SkillInvoke".into(),
                        operation: operation.into(),
                        status: StepStatus::Executed,
                        message: format!("invoked skill '{skill_tag}' ({})", skill.skill_id),
                        output: Some(output),
                    },
                    0,
                );
            }
            Err(e) => report.push(
                StepResult {
                    step_kind: "SkillInvoke".into(),
                    operation: operation.into(),
                    status: StepStatus::Failed,
                    message: format!("use_skill rpc error: {e}"),
                    output: None,
                },
                0,
            ),
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn dispatch_for_each(
        &mut self,
        spawned: &SpawnedAgent,
        spec: &ExecutionSpec,
        source_tool_tag: &str,
        body: &[ExecutionStep],
        ctx: &mut ExecutionContext,
        run_opts: &RunOptions,
        report: &mut RunReport,
    ) -> Result<(), AgentKitError> {
        let operation = "for_each";

        // Delegation gate for the iteration source itself.
        if let Err(reason) = self.enforce(spawned, operation, None) {
            report.push(
                StepResult {
                    step_kind: "ForEach".into(),
                    operation: operation.into(),
                    status: StepStatus::SkippedByDelegation,
                    message: reason,
                    output: None,
                },
                0,
            );
            return Ok(());
        }

        let tool = match spawned.discovered.tool_by_tag(source_tool_tag) {
            Some(t) => t.clone(),
            None => {
                report.push(
                    StepResult {
                        step_kind: "ForEach".into(),
                        operation: operation.into(),
                        status: StepStatus::Failed,
                        message: format!("source tool tag '{source_tool_tag}' not discovered"),
                        output: None,
                    },
                    0,
                );
                return Ok(());
            }
        };

        // Fetch the opportunity set. Even in dry-run we still make this
        // call — it's read-only — so the body can be walked against real
        // data.
        let items = match self
            .registry
            .use_tool(&tool.tool_id, Some(&tool.name), json!({}))
            .await
        {
            Ok(v) => {
                if let Some(arr) = v.as_array() {
                    arr.clone()
                } else if v.is_object() {
                    // Tolerate `{"items": [...]}` wrapper shape.
                    v.get("items")
                        .and_then(|i| i.as_array())
                        .cloned()
                        .unwrap_or_default()
                } else {
                    Vec::new()
                }
            }
            Err(e) => {
                report.push(
                    StepResult {
                        step_kind: "ForEach".into(),
                        operation: operation.into(),
                        status: StepStatus::Failed,
                        message: format!("use_tool rpc error: {e}"),
                        output: None,
                    },
                    0,
                );
                return Ok(());
            }
        };

        report.push(
            StepResult {
                step_kind: "ForEach".into(),
                operation: operation.into(),
                status: StepStatus::Executed,
                message: format!(
                    "fetched {} items from tool '{source_tool_tag}' ({})",
                    items.len(),
                    tool.tool_id
                ),
                output: Some(Value::Array(items.clone())),
            },
            0,
        );

        // Walk the body once per item, binding the item under
        // `opportunity` for substitution and JMESPath eval.
        for (i, item) in items.iter().enumerate() {
            ctx.bind_output("opportunity", item.clone());
            ctx.bind_output("opportunity_index", Value::Number(i.into()));

            // Flatten top-level string fields of the item into `vars`
            // so `{{amount}}`, `{{chain}}`, etc. work naturally.
            if let Some(obj) = item.as_object() {
                for (k, v) in obj {
                    match v {
                        Value::String(s) => {
                            ctx.vars.insert(k.clone(), s.clone());
                        }
                        Value::Number(n) => {
                            ctx.vars.insert(k.clone(), n.to_string());
                        }
                        Value::Bool(b) => {
                            ctx.vars.insert(k.clone(), b.to_string());
                        }
                        _ => {}
                    }
                }
            }

            self.run_steps(spawned, spec, body, ctx, run_opts, report)
                .await?;
        }

        Ok(())
    }

    async fn dispatch_when(
        &mut self,
        spawned: &SpawnedAgent,
        spec: &ExecutionSpec,
        jmespath_expr: &str,
        body: &[ExecutionStep],
        ctx: &mut ExecutionContext,
        run_opts: &RunOptions,
        report: &mut RunReport,
    ) -> Result<(), AgentKitError> {
        let operation = "when";
        let expr_resolved = substitute(jmespath_expr, &ctx.vars)?;

        // Convert the execution context to a jmespath_community Value via JSON.
        let target_json = ctx.as_jmespath_target();
        let target_str = serde_json::to_string(&target_json)
            .map_err(|e| AgentKitError::JmesPath(format!("serialize context: {e}")))?;
        let jmes_value = jmespath::Value::from_json(&target_str)
            .map_err(|e| AgentKitError::JmesPath(format!("parse context: {e}")))?;

        let result = jmespath::search(&expr_resolved, &jmes_value)
            .map_err(|e| AgentKitError::JmesPath(format!("evaluate '{expr_resolved}': {e}")))?;

        let truthy = result.is_truthy();

        if !truthy {
            report.push(
                StepResult {
                    step_kind: "When".into(),
                    operation: operation.into(),
                    status: StepStatus::SkippedByPredicate,
                    message: format!("predicate '{expr_resolved}' was falsy"),
                    output: None,
                },
                0,
            );
            return Ok(());
        }

        report.push(
            StepResult {
                step_kind: "When".into(),
                operation: operation.into(),
                status: StepStatus::Executed,
                message: format!("predicate '{expr_resolved}' passed"),
                output: None,
            },
            0,
        );

        self.run_steps(spawned, spec, body, ctx, run_opts, report)
            .await?;
        Ok(())
    }

    // ──────────────────────────────────────────────────────────────────
    // Shared helpers
    // ──────────────────────────────────────────────────────────────────

    /// Delegation gate wrapper. Returns `Ok(())` if the operation is
    /// allowed, or `Err(reason)` if it is not.
    fn enforce(
        &self,
        spawned: &SpawnedAgent,
        operation: &str,
        value: Option<u128>,
    ) -> Result<(), String> {
        self.identity_registry
            .enforce_operation(&spawned.machine_did(), operation, value)
            .map_err(|e| e.to_string())
    }
}

// ──────────────────────────────────────────────────────────────────────
// Free functions
// ──────────────────────────────────────────────────────────────────────

/// Parses a hex-encoded u128 (with or without `0x` prefix).
fn parse_hex_u128(s: &str) -> Option<u128> {
    let trimmed = s.trim_start_matches("0x").trim_start_matches("0X");
    u128::from_str_radix(trimmed, 16).ok()
}

/// Parses a decimal u128.
fn parse_u128(s: &str) -> Option<u128> {
    s.parse::<u128>().ok()
}

// `is_jmespath_truthy` is not needed — `jmespath_community::Value::is_truthy()`
// provides the same semantics natively.

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_options_defaults_to_single_iteration_no_dry_run() {
        let opts = RunOptions::default();
        assert_eq!(opts.max_iterations, 1);
        assert!(!opts.dry_run);
    }

    #[test]
    fn run_options_dry_run_sets_flag() {
        let opts = RunOptions::dry_run().with_max_iterations(5);
        assert!(opts.dry_run);
        assert_eq!(opts.max_iterations, 5);
    }

    #[test]
    fn execution_context_binds_string_value_into_vars() {
        let mut ctx = ExecutionContext::new(HashMap::new());
        ctx.bind_output("k", Value::String("hello".to_string()));
        assert_eq!(ctx.vars.get("k").map(String::as_str), Some("hello"));
        assert_eq!(ctx.outputs.get("k").and_then(|v| v.as_str()), Some("hello"));
    }

    #[test]
    fn execution_context_jmespath_target_includes_vars_and_outputs() {
        let mut ctx = ExecutionContext::new(HashMap::new());
        ctx.vars.insert("amount".to_string(), "100".to_string());
        ctx.bind_output("opportunity", json!({ "apy": 6.5 }));
        let target = ctx.as_jmespath_target();
        assert_eq!(target.get("amount").unwrap(), &Value::String("100".into()));
        assert_eq!(
            target
                .get("opportunity")
                .and_then(|o| o.get("apy"))
                .and_then(|n| n.as_f64()),
            Some(6.5)
        );
    }

    #[test]
    fn parse_hex_u128_accepts_with_and_without_prefix() {
        assert_eq!(parse_hex_u128("0x10"), Some(16));
        assert_eq!(parse_hex_u128("10"), Some(16));
        assert_eq!(parse_hex_u128("0xff"), Some(255));
        assert_eq!(parse_hex_u128("garbage"), None);
    }

    #[test]
    fn parse_u128_accepts_decimal() {
        assert_eq!(parse_u128("1000"), Some(1000));
        assert_eq!(parse_u128("0"), Some(0));
        assert_eq!(parse_u128(""), None);
    }

    #[test]
    fn jmespath_value_truthiness_follows_spec() {
        use jmespath::Value as JV;
        assert!(JV::Null.is_falsy());
        assert!(JV::Boolean(false).is_falsy());
        assert!(JV::Boolean(true).is_truthy());
        assert!(JV::String(String::new()).is_falsy());
        assert!(JV::String("x".to_string()).is_truthy());
    }

    #[test]
    fn jmespath_search_evaluates_expression() {
        let data = jmespath::Value::from_json(r#"{"apy": 6.5}"#).unwrap();
        let result = jmespath::search("apy > `5.0`", &data).unwrap();
        assert!(result.is_truthy());
    }

    #[test]
    fn run_report_accumulates_counts() {
        let mut report = RunReport::default();
        report.push(
            StepResult {
                step_kind: "EvmDispatch".into(),
                operation: "evm_dispatch".into(),
                status: StepStatus::Executed,
                message: "ok".into(),
                output: None,
            },
            1_000,
        );
        report.push(
            StepResult {
                step_kind: "EvmDispatch".into(),
                operation: "evm_dispatch".into(),
                status: StepStatus::SkippedByDelegation,
                message: "nope".into(),
                output: None,
            },
            0,
        );
        report.push(
            StepResult {
                step_kind: "When".into(),
                operation: "when".into(),
                status: StepStatus::SkippedByPredicate,
                message: "false".into(),
                output: None,
            },
            0,
        );
        assert_eq!(report.steps_executed, 1);
        assert_eq!(report.steps_skipped_by_delegation, 1);
        assert_eq!(report.steps_skipped_by_predicate, 1);
        assert_eq!(report.total_value_dispatched, 1_000);
        assert_eq!(report.total_steps(), 3);
    }

    #[test]
    fn _hard_caps_type_is_reachable() {
        // Ensures HardCaps symbol is used under cfg(test).
        use tenzro_types::agent_template::HardCaps;
        let caps = HardCaps {
            per_operation_value: 1,
            per_day_value: 1,
        };
        assert_eq!(caps.per_operation_value, 1);
    }
}
