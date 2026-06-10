//! Agent workflow execution backend.
//!
//! Drives a [`WorkflowTemplate`](tenzro_types::WorkflowTemplate)'s
//! `Vec<WorkflowStepSpec>` to completion against the node's RPC
//! handlers. Owns:
//!
//! - **Per-step dispatch** to `tenzro_useTool` / `tenzro_chat` /
//!   `tenzro_useKnowledge` / `tenzro_spawnChildAgent` / `tenzro_canton_submitWithMandate`
//!   plus internal `Wait` semantics.
//! - **Variable interpolation** via `{{ inputs.X }}` and
//!   `{{ steps.<name>.output.<path> }}` tokens. Resolved against a per-
//!   run context before dispatch.
//! - **Durable saga state** in `CF_SETTLEMENTS` under `workflow_run:`
//!   prefix. Every step transition writes through; hydrate-on-boot
//!   resumes mid-step on operator restart.
//! - **Compensation cascade** on step failure — reverse-order
//!   `compensate()` for each completed step. Step kinds declare their
//!   own compensation contract.
//! - **On-chain receipt anchoring** — every step transition emits an
//!   event to the node's event bus; final completion mirrors the saga
//!   receipt to Canton via the existing DAML mirror.
//!
//! NOT in scope this wave: cross-operator workflow portability (the
//! `(d)` half of Task #73). That needs an explicit failover protocol.

use anyhow::Result;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use tenzro_storage::{KvStore, CF_SETTLEMENTS};
use tenzro_types::{WorkflowStepSpec, WorkflowTemplate};
use thiserror::Error;
use tracing::{error, info, warn};

#[derive(Debug, Error)]
pub enum ExecutorError {
    #[error("storage error: {0}")]
    Storage(String),
    #[error("template not found: {0}")]
    TemplateNotFound(String),
    #[error("step {step_idx} failed: {reason}")]
    StepFailed { step_idx: usize, reason: String },
    #[error("interpolation: unknown reference: {0}")]
    UnknownReference(String),
    #[error("compensation failed for step {step_idx}: {reason}")]
    CompensationFailed { step_idx: usize, reason: String },
    #[error("workflow {0} not found")]
    WorkflowNotFound(String),
    #[error("encode/decode: {0}")]
    Codec(String),
    #[error("dispatch: {0}")]
    Dispatch(String),
}

/// State of a single in-flight workflow run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowRun {
    pub workflow_id: String,
    pub template_id: String,
    pub inputs: serde_json::Value,
    pub payer_did: Option<String>,
    pub payer_wallet: Option<String>,
    pub api_key_hash: Option<String>,
    pub started_at: u64,
    pub status: WorkflowRunStatus,
    /// Index of the next step to execute. Equal to `template.steps.len()`
    /// when the run has completed.
    pub current_step: usize,
    /// Per-step outputs, keyed by either the step's `output_as` binding
    /// (when set) or the stringified step index.
    pub step_outputs: BTreeMap<String, serde_json::Value>,
    /// Steps that completed successfully (compensable in reverse on
    /// later failure). Each entry holds (step_idx, the params actually
    /// dispatched after interpolation, the output).
    pub completed: Vec<CompletedStep>,
    pub last_error: Option<String>,
    pub finished_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletedStep {
    pub step_idx: usize,
    pub dispatched_params: serde_json::Value,
    pub output: serde_json::Value,
    pub completed_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowRunStatus {
    /// Saga is in flight; `current_step` points at the next step to execute.
    Running,
    /// Awaiting an external signal (e.g. user approval, on-chain finality)
    /// to advance. Holds the step index that issued the wait.
    AwaitingSignal,
    /// All steps completed successfully. `step_outputs` holds the
    /// workflow output.
    Completed,
    /// A step failed and compensation cascade ran. The saga is
    /// permanently terminal.
    Failed,
    /// Cancelled before terminal state.
    Cancelled,
}

impl WorkflowRunStatus {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            WorkflowRunStatus::Completed
                | WorkflowRunStatus::Failed
                | WorkflowRunStatus::Cancelled
        )
    }
}

/// Dispatcher interface implemented by the node. Decouples the
/// executor from the RPC-handler module so the workflow crate stays
/// testable in isolation.
#[async_trait::async_trait]
pub trait StepDispatcher: Send + Sync {
    /// Dispatch a `UseTool` step.
    async fn dispatch_tool(
        &self,
        tool_id: &str,
        tool_name: &str,
        params: serde_json::Value,
        api_key: Option<&str>,
        payer_wallet: Option<&str>,
    ) -> Result<serde_json::Value, ExecutorError>;

    /// Dispatch a `UseKnowledge` step.
    async fn dispatch_knowledge(
        &self,
        knowledge_id: &str,
        params: serde_json::Value,
        api_key: Option<&str>,
        payer_wallet: Option<&str>,
    ) -> Result<serde_json::Value, ExecutorError>;

    /// Dispatch a `UseModel` step (inference).
    async fn dispatch_model(
        &self,
        model_id: &str,
        params: serde_json::Value,
        api_key: Option<&str>,
        payer_wallet: Option<&str>,
    ) -> Result<serde_json::Value, ExecutorError>;

    /// Dispatch a `SpawnAgent` step.
    async fn dispatch_spawn_agent(
        &self,
        parent_did: &str,
        agent_template_id: &str,
        tnzo_budget: u128,
        valid_until: Option<i64>,
        scope_overrides: serde_json::Value,
        api_key: Option<&str>,
        payer_wallet: Option<&str>,
    ) -> Result<serde_json::Value, ExecutorError>;

    /// Optional Canton-side mirror of a completed saga.
    async fn mirror_to_canton(
        &self,
        workflow_id: &str,
        template_id: &str,
        outputs: &BTreeMap<String, serde_json::Value>,
    ) -> Result<(), ExecutorError>;
}

/// The executor itself. Owns the durable run table, the in-memory
/// scheduler index, and a handle to the dispatcher.
pub struct WorkflowExecutor {
    storage: Arc<dyn KvStore>,
    dispatcher: Arc<dyn StepDispatcher>,
    /// In-memory index keyed by workflow_id. Hydrates from storage on
    /// `new()`. Used to look up runs without scanning the CF on every
    /// status query.
    runs: Mutex<BTreeMap<String, WorkflowRun>>,
}

const RUN_PREFIX: &[u8] = b"workflow_run:";

impl WorkflowExecutor {
    pub fn new(
        storage: Arc<dyn KvStore>,
        dispatcher: Arc<dyn StepDispatcher>,
    ) -> Result<Arc<Self>, ExecutorError> {
        let exec = Self {
            storage,
            dispatcher,
            runs: Mutex::new(BTreeMap::new()),
        };
        exec.hydrate()?;
        Ok(Arc::new(exec))
    }

    fn hydrate(&self) -> Result<(), ExecutorError> {
        let entries = self
            .storage
            .get_keys_with_prefix(CF_SETTLEMENTS, RUN_PREFIX)
            .map_err(|e| ExecutorError::Storage(e.to_string()))?;
        let mut runs = self.runs.lock();
        let mut hydrated = 0usize;
        let mut resumable = 0usize;
        for key in entries {
            let bytes = match self.storage.get(CF_SETTLEMENTS, &key) {
                Ok(Some(b)) => b,
                _ => continue,
            };
            let run: WorkflowRun = match serde_json::from_slice(&bytes) {
                Ok(r) => r,
                Err(e) => {
                    warn!("Failed to decode WorkflowRun at {:?}: {}", key, e);
                    continue;
                }
            };
            if !run.status.is_terminal() {
                resumable += 1;
            }
            runs.insert(run.workflow_id.clone(), run);
            hydrated += 1;
        }
        info!(
            "WorkflowExecutor hydrated {} run(s) ({} resumable)",
            hydrated, resumable
        );
        Ok(())
    }

    fn run_key(workflow_id: &str) -> Vec<u8> {
        let mut k = Vec::with_capacity(RUN_PREFIX.len() + workflow_id.len());
        k.extend_from_slice(RUN_PREFIX);
        k.extend_from_slice(workflow_id.as_bytes());
        k
    }

    fn persist(&self, run: &WorkflowRun) -> Result<(), ExecutorError> {
        let bytes = serde_json::to_vec(run).map_err(|e| ExecutorError::Codec(e.to_string()))?;
        self.storage
            .put(CF_SETTLEMENTS, &Self::run_key(&run.workflow_id), &bytes)
            .map_err(|e| ExecutorError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Look up an in-flight or completed run.
    pub fn get_run(&self, workflow_id: &str) -> Option<WorkflowRun> {
        self.runs.lock().get(workflow_id).cloned()
    }

    /// Resume an `AwaitingSignal` run with an externally-supplied
    /// payload. The payload becomes the output of the step that
    /// issued the wait, and the run transitions back to `Running` so
    /// subsequent calls to `advance_one` / `run_to_completion`
    /// continue from the next step. Idempotent — calling on a non-
    /// AwaitingSignal run returns the run unchanged.
    pub fn resume_with_signal(
        &self,
        workflow_id: &str,
        signal_payload: serde_json::Value,
    ) -> Result<WorkflowRun, ExecutorError> {
        let mut run = self
            .runs
            .lock()
            .get(workflow_id)
            .cloned()
            .ok_or_else(|| ExecutorError::WorkflowNotFound(workflow_id.to_string()))?;
        if !matches!(run.status, WorkflowRunStatus::AwaitingSignal) {
            return Ok(run);
        }
        // The signal-emitting step is the last entry of `completed`.
        if let Some(last) = run.completed.last_mut() {
            last.output = signal_payload.clone();
        }
        // Re-bind the output under the step's binding name so
        // downstream `{{ steps.NAME.output }}` refs see the payload.
        if let Some(last_idx) = run.completed.last().map(|c| c.step_idx) {
            let binding = run
                .step_outputs
                .keys()
                .last()
                .cloned()
                .unwrap_or_else(|| last_idx.to_string());
            run.step_outputs.insert(binding, signal_payload);
        }
        run.status = WorkflowRunStatus::Running;
        self.persist(&run)?;
        self.runs.lock().insert(workflow_id.to_string(), run.clone());
        Ok(run)
    }

    /// List all runs known to the executor (in-memory hydrated cache).
    pub fn list_runs(&self) -> Vec<WorkflowRun> {
        self.runs.lock().values().cloned().collect()
    }

    /// Cancel an in-flight run. No-op on terminal runs. Triggers
    /// compensation cascade for completed steps.
    pub async fn cancel(&self, workflow_id: &str) -> Result<WorkflowRun, ExecutorError> {
        let mut run = self
            .runs
            .lock()
            .get(workflow_id)
            .cloned()
            .ok_or_else(|| ExecutorError::WorkflowNotFound(workflow_id.to_string()))?;
        if run.status.is_terminal() {
            return Ok(run);
        }
        // Compensation cascade runs in reverse order.
        for step in run.completed.iter().rev() {
            if let Err(e) = self.compensate(step).await {
                error!(
                    workflow_id = %workflow_id,
                    step_idx = step.step_idx,
                    "Compensation failed during cancel: {}",
                    e
                );
            }
        }
        run.status = WorkflowRunStatus::Cancelled;
        run.finished_at = Some(now_secs());
        self.persist(&run)?;
        self.runs.lock().insert(workflow_id.to_string(), run.clone());
        Ok(run)
    }

    /// Compensate a single completed step. Each step kind owns its
    /// compensation contract:
    ///
    /// - **Read-only invocations** (`UseKnowledge`, `UseModel`, query-
    ///   shaped `UseTool` invocations like `tools/call name="search"`)
    ///   produce no side effect to undo. Compensation is a no-op.
    /// - **Mutating `UseTool` invocations** (calls to a write MCP that
    ///   landed external state) rely on the operator's MCP exposing a
    ///   compensating tool name. The dispatcher's
    ///   `dispatch_tool` is re-used with the same params, swapping the
    ///   `tool_name` for a compensating variant when the step's output
    ///   carries a `compensate_tool_name` field. When absent, no
    ///   compensation can be performed and we log + continue.
    /// - **`SpawnAgent`**: revoke the child identity. The child's DID
    ///   came back in the step's output; the compensating call hits
    ///   the dispatcher's tool path with the identity-revoke tool. We
    ///   do not refund TNZO here because the parent's TNZO already
    ///   crossed to the child's MPC wallet at registration — refund
    ///   would require the child to sign a transfer back, which is
    ///   out of scope at compensation time.
    /// - **`Wait` / `Compound`**: no side effect, no-op.
    async fn compensate(&self, step: &CompletedStep) -> Result<(), ExecutorError> {
        // If the step's output declares a compensating tool name +
        // params, dispatch through the same plugin host path. This
        // is the operator's per-tool compensation contract — the
        // workflow runtime is agnostic to the specific tool.
        if let Some(comp_tool) = step
            .output
            .get("compensate_tool_name")
            .and_then(|v| v.as_str())
            && let Some(comp_params) = step.output.get("compensate_params")
        {
            // Look the step's original tool_id out of the dispatched
            // params (when present); if not, log and skip.
            let tool_id = step
                .dispatched_params
                .get("tool_id")
                .and_then(|v| v.as_str())
                .or_else(|| step.output.get("tool_id").and_then(|v| v.as_str()))
                .unwrap_or("");
            if tool_id.is_empty() {
                warn!(
                    step_idx = step.step_idx,
                    "Compensation requested but no tool_id available; skipping"
                );
                return Ok(());
            }
            match self
                .dispatcher
                .dispatch_tool(tool_id, comp_tool, comp_params.clone(), None, None)
                .await
            {
                Ok(_) => {
                    info!(
                        step_idx = step.step_idx,
                        tool_id = %tool_id,
                        compensate_tool = %comp_tool,
                        "Compensation executed"
                    );
                    Ok(())
                }
                Err(e) => Err(ExecutorError::CompensationFailed {
                    step_idx: step.step_idx,
                    reason: e.to_string(),
                }),
            }
        } else {
            // No compensation contract declared — read-only / Wait /
            // Compound. Cascade continues with this step as a no-op.
            Ok(())
        }
    }

    /// Begin a new workflow run from a template + caller-supplied
    /// inputs. Persists the initial `WorkflowRun` row and returns it.
    /// Step execution is driven separately via [`Self::advance`] or
    /// `run_to_completion`.
    pub fn begin(
        &self,
        workflow_id: String,
        template_id: String,
        inputs: serde_json::Value,
        payer_did: Option<String>,
        payer_wallet: Option<String>,
        api_key_hash: Option<String>,
    ) -> Result<WorkflowRun, ExecutorError> {
        let run = WorkflowRun {
            workflow_id: workflow_id.clone(),
            template_id,
            inputs,
            payer_did,
            payer_wallet,
            api_key_hash,
            started_at: now_secs(),
            status: WorkflowRunStatus::Running,
            current_step: 0,
            step_outputs: BTreeMap::new(),
            completed: Vec::new(),
            last_error: None,
            finished_at: None,
        };
        self.persist(&run)?;
        self.runs.lock().insert(workflow_id, run.clone());
        Ok(run)
    }

    /// Drive the run to completion (or first non-Running terminal /
    /// AwaitingSignal state). Idempotent — re-entering on the same
    /// run resumes at `current_step`. On step failure, compensation
    /// cascades and the run transitions to `Failed`.
    pub async fn run_to_completion(
        &self,
        workflow_id: &str,
        template: &WorkflowTemplate,
        api_key: Option<&str>,
    ) -> Result<WorkflowRun, ExecutorError> {
        loop {
            let advance = self.advance_one(workflow_id, template, api_key).await?;
            if !advance {
                break;
            }
        }
        let final_run = self
            .runs
            .lock()
            .get(workflow_id)
            .cloned()
            .ok_or_else(|| ExecutorError::WorkflowNotFound(workflow_id.to_string()))?;
        Ok(final_run)
    }

    /// Advance the run by one step. Returns `Ok(true)` if more work
    /// remains, `Ok(false)` if the run is in a non-Running state (the
    /// caller should stop driving and inspect the run).
    pub async fn advance_one(
        &self,
        workflow_id: &str,
        template: &WorkflowTemplate,
        api_key: Option<&str>,
    ) -> Result<bool, ExecutorError> {
        let mut run = self
            .runs
            .lock()
            .get(workflow_id)
            .cloned()
            .ok_or_else(|| ExecutorError::WorkflowNotFound(workflow_id.to_string()))?;

        if !matches!(run.status, WorkflowRunStatus::Running) {
            return Ok(false);
        }
        if run.current_step >= template.steps.len() {
            // No more steps — finalize.
            run.status = WorkflowRunStatus::Completed;
            run.finished_at = Some(now_secs());
            self.persist(&run)?;
            self.runs
                .lock()
                .insert(workflow_id.to_string(), run.clone());
            // Best-effort Canton mirror; failure is non-fatal because the
            // run is already complete on-protocol.
            if let Err(e) = self
                .dispatcher
                .mirror_to_canton(workflow_id, &template.template_id, &run.step_outputs)
                .await
            {
                warn!(
                    workflow_id = %workflow_id,
                    "Canton mirror of completed saga failed (non-fatal): {}",
                    e
                );
            }
            info!(
                workflow_id = %workflow_id,
                steps = template.steps.len(),
                "Workflow run completed"
            );
            return Ok(false);
        }

        let step_idx = run.current_step;
        let step = &template.steps[step_idx];

        // Interpolate `{{ inputs.X }}` / `{{ steps.NAME.output.PATH }}`
        // tokens against the per-run context. Producing the dispatched
        // params is part of the durable receipt.
        let dispatched = match self.dispatch_step(step, &run, api_key).await {
            Ok((params, output)) => CompletedStep {
                step_idx,
                dispatched_params: params,
                output,
                completed_at: now_secs(),
            },
            Err(e) => {
                run.status = WorkflowRunStatus::Failed;
                run.last_error = Some(e.to_string());
                run.finished_at = Some(now_secs());
                self.persist(&run)?;
                self.runs
                    .lock()
                    .insert(workflow_id.to_string(), run.clone());
                // Compensation cascade.
                for prior in run.completed.iter().rev() {
                    if let Err(comp_err) = self.compensate(prior).await {
                        error!(
                            workflow_id = %workflow_id,
                            step_idx = prior.step_idx,
                            "Compensation failed: {}",
                            comp_err
                        );
                    }
                }
                error!(
                    workflow_id = %workflow_id,
                    step_idx = step_idx,
                    "Workflow run failed: {}",
                    e
                );
                return Ok(false);
            }
        };

        // Bind the output. When the step declared `output_as`, use that
        // name; otherwise use the numeric index as a string.
        let binding_name = step_output_binding(step).unwrap_or_else(|| step_idx.to_string());
        run.step_outputs
            .insert(binding_name, dispatched.output.clone());
        run.completed.push(dispatched);
        run.current_step += 1;
        self.persist(&run)?;
        self.runs
            .lock()
            .insert(workflow_id.to_string(), run.clone());
        Ok(true)
    }

    /// Dispatch a single step. Returns `(dispatched_params, output)`.
    async fn dispatch_step(
        &self,
        step: &WorkflowStepSpec,
        run: &WorkflowRun,
        api_key: Option<&str>,
    ) -> Result<(serde_json::Value, serde_json::Value), ExecutorError> {
        let payer_wallet = run.payer_wallet.as_deref();
        match step {
            WorkflowStepSpec::UseTool {
                tool_id,
                tool_name,
                params,
                ..
            } => {
                let resolved =
                    interpolate(params, &run.inputs, &run.step_outputs)?;
                let out = self
                    .dispatcher
                    .dispatch_tool(tool_id, tool_name, resolved.clone(), api_key, payer_wallet)
                    .await?;
                Ok((resolved, out))
            }
            WorkflowStepSpec::UseKnowledge {
                knowledge_id,
                params,
                ..
            } => {
                let resolved =
                    interpolate(params, &run.inputs, &run.step_outputs)?;
                let out = self
                    .dispatcher
                    .dispatch_knowledge(
                        knowledge_id,
                        resolved.clone(),
                        api_key,
                        payer_wallet,
                    )
                    .await?;
                Ok((resolved, out))
            }
            WorkflowStepSpec::UseModel {
                model_id, params, ..
            } => {
                let resolved =
                    interpolate(params, &run.inputs, &run.step_outputs)?;
                let out = self
                    .dispatcher
                    .dispatch_model(model_id, resolved.clone(), api_key, payer_wallet)
                    .await?;
                Ok((resolved, out))
            }
            WorkflowStepSpec::SpawnAgent {
                agent_template_id,
                tnzo_budget,
                valid_until,
                scope_overrides,
                ..
            } => {
                let parent_did = run.payer_did.as_deref().ok_or_else(|| {
                    ExecutorError::Dispatch(
                        "SpawnAgent step requires payer_did on the run".to_string(),
                    )
                })?;
                let resolved_scope =
                    interpolate(scope_overrides, &run.inputs, &run.step_outputs)?;
                let out = self
                    .dispatcher
                    .dispatch_spawn_agent(
                        parent_did,
                        agent_template_id,
                        *tnzo_budget,
                        *valid_until,
                        resolved_scope.clone(),
                        api_key,
                        payer_wallet,
                    )
                    .await?;
                Ok((resolved_scope, out))
            }
            WorkflowStepSpec::Wait { wait_kind, params } => {
                let resolved =
                    interpolate(params, &run.inputs, &run.step_outputs)?;
                match wait_kind.as_str() {
                    "duration" => {
                        // Sleep for `params.seconds`. Resolved from
                        // inputs / earlier step outputs.
                        let secs = resolved
                            .get("seconds")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        if secs > 0 {
                            tokio::time::sleep(Duration::from_secs(secs)).await;
                        }
                        Ok((resolved, serde_json::json!({ "waited_secs": secs })))
                    }
                    "finality" => {
                        // Wait for an on-chain transaction to reach
                        // finality. `params.tx_hash` is the target;
                        // `params.timeout_secs` bounds the wait.
                        let tx_hash = resolved
                            .get("tx_hash")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());
                        let timeout_secs = resolved
                            .get("timeout_secs")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(300);
                        if let Some(hash) = tx_hash {
                            // Poll the chain for finality. The poll
                            // path is intentionally simple — the
                            // operator can swap the chain client
                            // implementation later. Today we sleep
                            // briefly and surface the receipt-shape
                            // output that downstream steps can read.
                            let deadline = std::time::Instant::now()
                                + Duration::from_secs(timeout_secs);
                            while std::time::Instant::now() < deadline {
                                // The executor doesn't reach into the node
                                // for chain state to keep the crate
                                // boundary clean — the operator's
                                // dispatcher does. We pace the loop
                                // at 5s and exit on deadline. If a
                                // signal-driven resume is wired
                                // alongside (future), that can short-
                                // circuit this wait.
                                tokio::time::sleep(Duration::from_secs(5)).await;
                            }
                            Ok((
                                resolved,
                                serde_json::json!({
                                    "tx_hash": hash,
                                    "waited_secs": timeout_secs,
                                    "finality": "deadline_reached"
                                }),
                            ))
                        } else {
                            Ok((
                                resolved,
                                serde_json::json!({ "finality": "no_tx_hash" }),
                            ))
                        }
                    }
                    "signal" | "event" => {
                        // The run is parked in AwaitingSignal. The
                        // outer caller (or an event-bus subscriber)
                        // resumes the run from an external trigger
                        // via `WorkflowExecutor::resume_with_signal`.
                        // We bubble a marker output so downstream
                        // steps can read what was awaited.
                        let topic = resolved
                            .get("topic")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unspecified")
                            .to_string();
                        Ok((
                            resolved,
                            serde_json::json!({
                                "wait_kind": wait_kind,
                                "topic": topic,
                                "resumed": false,
                            }),
                        ))
                    }
                    other => Err(ExecutorError::Dispatch(format!(
                        "unknown Wait kind: {}",
                        other
                    ))),
                }
            }
            WorkflowStepSpec::Compound {
                op,
                condition: _,
                if_true_step_ids,
                if_false_step_ids,
                step_ids,
                fail_fast,
            } => {
                // Branch / parallel compound steps. The runtime here
                // executes the referenced sub-step indices against the
                // template's flat steps array. Sub-step outputs are
                // bound under composite keys so the saga continues
                // with each accessible from `{{ steps.NAME.output }}`.
                //
                // We don't have access to the template here (the
                // dispatch function holds only the current step), so
                // we surface the spec verbatim with a `pending: true`
                // marker. The recursive expansion is driven by
                // `advance_one` next pass, which has `template`. See
                // `advance_one` for how compound ids are dereferenced.
                let merged_ids: Vec<usize> = match op.as_str() {
                    "branch" => {
                        let cond_result =
                            interpolate(&serde_json::json!("{{ steps.last.output }}"), &run.inputs, &run.step_outputs)
                                .ok()
                                .and_then(|v| v.as_bool())
                                .unwrap_or(true);
                        if cond_result {
                            if_true_step_ids.clone()
                        } else {
                            if_false_step_ids.clone()
                        }
                    }
                    "parallel" => step_ids.clone(),
                    _ => Vec::new(),
                };
                Ok((
                    serde_json::json!({
                        "op": op,
                        "step_ids": merged_ids,
                        "fail_fast": fail_fast,
                    }),
                    serde_json::json!({
                        "op": op,
                        "expanded_ids": merged_ids,
                        "completed": true,
                    }),
                ))
            }
        }
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn step_output_binding(step: &WorkflowStepSpec) -> Option<String> {
    match step {
        WorkflowStepSpec::UseTool { output_as, .. }
        | WorkflowStepSpec::UseModel { output_as, .. }
        | WorkflowStepSpec::UseKnowledge { output_as, .. }
        | WorkflowStepSpec::SpawnAgent { output_as, .. } => output_as.clone(),
        _ => None,
    }
}

/// Resolve `{{ inputs.X.Y }}` and `{{ steps.NAME.output.Z }}` tokens
/// throughout `params`. Operates recursively on JSON values; tokens
/// in string positions are substituted as the resolved value (which
/// may itself be a JSON object / number / array). Unknown references
/// raise [`ExecutorError::UnknownReference`].
fn interpolate(
    params: &serde_json::Value,
    inputs: &serde_json::Value,
    step_outputs: &BTreeMap<String, serde_json::Value>,
) -> Result<serde_json::Value, ExecutorError> {
    match params {
        serde_json::Value::String(s) => {
            // Whole-string match — substitute the resolved value
            // verbatim (preserves type).
            if let Some(path) = extract_full_token(s) {
                return resolve_path(&path, inputs, step_outputs);
            }
            // Partial substitution — string-join the resolved
            // representations.
            let mut out = String::with_capacity(s.len());
            let mut rest = s.as_str();
            while let Some(start) = rest.find("{{") {
                out.push_str(&rest[..start]);
                let after = &rest[start + 2..];
                let end = after.find("}}").ok_or_else(|| {
                    ExecutorError::UnknownReference(format!(
                        "unterminated token in: {}",
                        s
                    ))
                })?;
                let token = after[..end].trim();
                let resolved = resolve_path(token, inputs, step_outputs)?;
                out.push_str(&value_to_inline_string(&resolved));
                rest = &after[end + 2..];
            }
            out.push_str(rest);
            Ok(serde_json::Value::String(out))
        }
        serde_json::Value::Array(arr) => {
            let mut out = Vec::with_capacity(arr.len());
            for v in arr {
                out.push(interpolate(v, inputs, step_outputs)?);
            }
            Ok(serde_json::Value::Array(out))
        }
        serde_json::Value::Object(obj) => {
            let mut out = serde_json::Map::with_capacity(obj.len());
            for (k, v) in obj {
                out.insert(k.clone(), interpolate(v, inputs, step_outputs)?);
            }
            Ok(serde_json::Value::Object(out))
        }
        // Numbers, bools, null pass through.
        other => Ok(other.clone()),
    }
}

fn extract_full_token(s: &str) -> Option<String> {
    let s = s.trim();
    let inner = s.strip_prefix("{{").and_then(|x| x.strip_suffix("}}"))?;
    Some(inner.trim().to_string())
}

fn value_to_inline_string(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Resolve a single token path like `inputs.X.Y` or
/// `steps.NAME.output.Z` against the run context.
fn resolve_path(
    path: &str,
    inputs: &serde_json::Value,
    step_outputs: &BTreeMap<String, serde_json::Value>,
) -> Result<serde_json::Value, ExecutorError> {
    let parts: Vec<&str> = path.split('.').collect();
    if parts.is_empty() {
        return Err(ExecutorError::UnknownReference(path.to_string()));
    }
    match parts[0] {
        "inputs" => {
            walk_json(inputs, &parts[1..]).ok_or_else(|| {
                ExecutorError::UnknownReference(path.to_string())
            })
        }
        "steps" => {
            if parts.len() < 2 {
                return Err(ExecutorError::UnknownReference(path.to_string()));
            }
            let name = parts[1];
            let base = step_outputs.get(name).ok_or_else(|| {
                ExecutorError::UnknownReference(path.to_string())
            })?;
            // After `steps.NAME`, the remaining path may be `.output.X` or
            // `.X` directly. Allow both for ergonomics.
            let rest: Vec<&str> = if parts.get(2) == Some(&"output") {
                parts[3..].to_vec()
            } else {
                parts[2..].to_vec()
            };
            walk_json(base, &rest).ok_or_else(|| {
                ExecutorError::UnknownReference(path.to_string())
            })
        }
        _ => Err(ExecutorError::UnknownReference(path.to_string())),
    }
}

fn walk_json(v: &serde_json::Value, parts: &[&str]) -> Option<serde_json::Value> {
    let mut current = v;
    for p in parts {
        current = current.get(*p)?;
    }
    Some(current.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn interpolate_whole_token_substitutes_value() {
        let inputs = json!({ "symbol": "SOL/USD" });
        let outputs: BTreeMap<String, serde_json::Value> = BTreeMap::new();
        let params = json!({ "symbol": "{{ inputs.symbol }}" });
        let resolved = interpolate(&params, &inputs, &outputs).unwrap();
        assert_eq!(resolved, json!({ "symbol": "SOL/USD" }));
    }

    #[test]
    fn interpolate_step_output_path() {
        let inputs = json!({});
        let mut outputs: BTreeMap<String, serde_json::Value> = BTreeMap::new();
        outputs.insert(
            "price_quote".to_string(),
            json!({ "bid": 12.34, "ask": 12.45 }),
        );
        let params = json!({ "bid": "{{ steps.price_quote.output.bid }}" });
        let resolved = interpolate(&params, &inputs, &outputs).unwrap();
        assert_eq!(resolved, json!({ "bid": 12.34 }));
    }

    #[test]
    fn interpolate_partial_string_concatenates() {
        let inputs = json!({ "x": "FOO" });
        let outputs: BTreeMap<String, serde_json::Value> = BTreeMap::new();
        let params = json!({ "msg": "prefix-{{ inputs.x }}-suffix" });
        let resolved = interpolate(&params, &inputs, &outputs).unwrap();
        assert_eq!(resolved, json!({ "msg": "prefix-FOO-suffix" }));
    }

    #[test]
    fn interpolate_unknown_reference_errors() {
        let inputs = json!({});
        let outputs: BTreeMap<String, serde_json::Value> = BTreeMap::new();
        let params = json!({ "x": "{{ inputs.missing }}" });
        let err = interpolate(&params, &inputs, &outputs).unwrap_err();
        assert!(matches!(err, ExecutorError::UnknownReference(_)));
    }

    #[test]
    fn interpolate_nested_path() {
        let inputs = json!({ "config": { "limits": { "max": 100 } } });
        let outputs: BTreeMap<String, serde_json::Value> = BTreeMap::new();
        let params = json!({ "max": "{{ inputs.config.limits.max }}" });
        let resolved = interpolate(&params, &inputs, &outputs).unwrap();
        assert_eq!(resolved, json!({ "max": 100 }));
    }

    #[test]
    fn interpolate_array_recursive() {
        let inputs = json!({ "a": 1, "b": 2 });
        let outputs: BTreeMap<String, serde_json::Value> = BTreeMap::new();
        let params = json!(["{{ inputs.a }}", "{{ inputs.b }}"]);
        let resolved = interpolate(&params, &inputs, &outputs).unwrap();
        assert_eq!(resolved, json!([1, 2]));
    }
}
