//! Job queue, worker registry, and status machine for generative-media jobs.
//!
//! [`MediaGenRuntime`] is the single admission point for the subsystem. A job
//! enters through [`MediaGenRuntime::post_job`], is picked up by an enrolled
//! worker through [`MediaGenRuntime::claim_job`], and leaves through
//! [`MediaGenRuntime::submit_receipt`], [`MediaGenRuntime::fail_job`], or
//! [`MediaGenRuntime::cancel_job`]. Every status change is checked against
//! [`MediaGenStatus::can_transition_to`], so no caller can move a job
//! backwards or resurrect a terminal one.
//!
//! A job whose model splits denoising across two experts is posted with a
//! [`MediaGenExpertRole`] for each half. Each half is claimed separately and
//! the job stays [`MediaGenStatus::Pending`] until both are covered. The
//! high-noise worker publishes the intermediate latent through
//! [`MediaGenRuntime::record_handoff`]; the low-noise worker submits the
//! receipt. Payment splits on the steps each side actually ran.
//!
//! Jobs, receipts, and enrolled workers all write through to RocksDB and are
//! restored by [`MediaGenRuntime::hydrate`] on boot. Terminal jobs are kept in
//! storage for audit but are not re-admitted to the in-memory queue.

use std::sync::Arc;

use bytes::Bytes;
use dashmap::DashMap;

use tenzro_storage::kv::{CF_MEDIA_GEN_RECEIPTS, CF_MEDIA_GEN_RUNS, CF_MEDIA_GEN_WORKERS, KvStore};
use tenzro_types::media_gen::{
    MediaGenAssignment, MediaGenExpertRole, MediaGenHandoff, MediaGenJob, MediaGenReceipt,
    MediaGenStatus, MediaGenTaskSpec, MediaGenWorkerCapability,
};
use tenzro_types::primitives::Timestamp;

use crate::commitments::expected_job_id;
use crate::error::{MediaGenError, Result};
use crate::gossip::MediaGenClaim;
use crate::output_store::MediaGenOutputStore;
use crate::pricing::{MediaGenPricing, enforce_ceiling};

/// Counts restored by [`MediaGenRuntime::hydrate`]: non-terminal jobs, then
/// enrolled workers.
pub type HydratedCounts = (usize, usize);

/// Off-chain state for the generative-media subsystem.
#[derive(Default)]
pub struct MediaGenRuntime {
    jobs: DashMap<String, MediaGenJob>,
    workers: DashMap<String, MediaGenWorkerCapability>,
    pricing: MediaGenPricing,
    output_store: Option<Arc<dyn MediaGenOutputStore>>,
    storage: Option<Arc<dyn KvStore>>,
}

impl MediaGenRuntime {
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach durable storage. Without it the runtime is in-memory only and
    /// loses its queue on restart.
    pub fn with_storage(storage: Arc<dyn KvStore>) -> Self {
        Self {
            storage: Some(storage),
            ..Self::default()
        }
    }

    /// Override the default rate card.
    pub fn with_pricing(mut self, pricing: MediaGenPricing) -> Self {
        self.pricing = pricing;
        self
    }

    /// Attach the content-addressed store the runtime fetches outputs from.
    pub fn with_output_store(mut self, store: Arc<dyn MediaGenOutputStore>) -> Self {
        self.output_store = Some(store);
        self
    }

    pub fn pricing(&self) -> &MediaGenPricing {
        &self.pricing
    }

    pub fn output_store(&self) -> Option<&Arc<dyn MediaGenOutputStore>> {
        self.output_store.as_ref()
    }

    /// Restore jobs and workers from storage. Terminal jobs stay on disk for
    /// audit and are not returned to the queue.
    pub fn hydrate(&self) -> Result<HydratedCounts> {
        let Some(storage) = &self.storage else {
            return Ok((0, 0));
        };

        let mut jobs = 0usize;
        for (_, value) in storage
            .scan_prefix(CF_MEDIA_GEN_RUNS, b"job:")
            .map_err(|e| MediaGenError::Storage(e.to_string()))?
        {
            let job: MediaGenJob = serde_json::from_slice(&value)
                .map_err(|e| MediaGenError::Serialization(e.to_string()))?;
            if job.status.is_terminal() {
                continue;
            }
            self.jobs.insert(job.job_id.clone(), job);
            jobs += 1;
        }

        let mut workers = 0usize;
        for (_, value) in storage
            .scan_prefix(CF_MEDIA_GEN_WORKERS, b"worker:")
            .map_err(|e| MediaGenError::Storage(e.to_string()))?
        {
            let worker: MediaGenWorkerCapability = serde_json::from_slice(&value)
                .map_err(|e| MediaGenError::Serialization(e.to_string()))?;
            self.workers.insert(worker.worker_did.clone(), worker);
            workers += 1;
        }

        Ok((jobs, workers))
    }

    // -----------------------------------------------------------------------
    // Workers
    // -----------------------------------------------------------------------

    /// Enroll a worker. A worker announces the models, resolution, and frame
    /// count it can actually serve; [`MediaGenWorkerCapability::can_serve`]
    /// reads that announcement at claim time.
    /// Announce a worker's capabilities, replacing any it announced before.
    ///
    /// Re-announcement is the normal case, not an error: a worker that
    /// restarts — after a crash, a reboot, or an operator changing which
    /// models it holds — comes back and says what it can do now. Refusing the
    /// second announcement meant a worker could never restart without an
    /// operator first removing it by hand, and the `serve` path enrolls before
    /// it renders, so the refusal made restarting a worker impossible rather
    /// than merely awkward.
    ///
    /// The announcement is signature-checked before it reaches here, so a
    /// re-announcement is the same worker by construction. Taking the newest
    /// one is also the only correct choice: capabilities change across a
    /// restart, and keeping the stale set would route jobs to a worker for
    /// models it no longer holds.
    pub fn enroll_worker(&self, capability: MediaGenWorkerCapability) -> Result<()> {
        self.persist_worker(&capability)?;
        self.workers
            .insert(capability.worker_did.clone(), capability);
        Ok(())
    }

    /// Withdraw a worker's enrollment.
    ///
    /// Enrollment is keyed by `worker_did` and re-announcing under the *same*
    /// DID replaces the entry, which covers a worker restarting. It does not
    /// cover a worker changing identity: that announces under a new key and
    /// leaves the old one enrolled, still advertising models nothing is
    /// serving. The same reasoning that makes the newest announcement win —
    /// a stale set routes jobs to a worker for models it no longer holds —
    /// is why there has to be a way to take one out.
    ///
    /// Returns whether an enrollment was actually removed, so a caller can
    /// tell "withdrawn" from "was never there".
    pub fn remove_worker(&self, worker_did: &str) -> Result<bool> {
        let existed = self.workers.remove(worker_did).is_some();
        if let Some(storage) = &self.storage {
            let key = format!("worker:{worker_did}");
            storage
                .delete(CF_MEDIA_GEN_WORKERS, key.as_bytes())
                .map_err(|e| MediaGenError::Storage(e.to_string()))?;
        }
        Ok(existed)
    }

    pub fn get_worker(&self, worker_did: &str) -> Option<MediaGenWorkerCapability> {
        self.workers.get(worker_did).map(|w| w.value().clone())
    }

    pub fn list_workers(&self) -> Vec<MediaGenWorkerCapability> {
        self.workers.iter().map(|w| w.value().clone()).collect()
    }

    // -----------------------------------------------------------------------
    // Jobs
    // -----------------------------------------------------------------------

    /// Admit a job that one worker serves from end to end.
    ///
    /// The spec's parameters are validated against its kind, the job id is
    /// derived from the spec contents (a caller-supplied id must match, an
    /// empty one is filled in), and the price ceiling is checked against this
    /// node's quote so a job that could never be served is rejected on the way
    /// in rather than sitting in the queue forever.
    pub fn post_job(&self, spec: MediaGenTaskSpec) -> Result<MediaGenJob> {
        self.admit(spec, Vec::new())
    }

    /// Admit a job whose model splits denoising across two experts, so it can
    /// be served by two workers holding one expert each.
    ///
    /// Same admission checks as [`Self::post_job`]. The job additionally
    /// requires both halves to be claimed before it can run — whether a model
    /// splits is a property of the catalog entry, so the caller decides which
    /// of the two entry points to use.
    pub fn post_split_job(&self, spec: MediaGenTaskSpec) -> Result<MediaGenJob> {
        self.admit(
            spec,
            vec![MediaGenExpertRole::HighNoise, MediaGenExpertRole::LowNoise],
        )
    }

    fn admit(
        &self,
        mut spec: MediaGenTaskSpec,
        required_roles: Vec<MediaGenExpertRole>,
    ) -> Result<MediaGenJob> {
        spec.params
            .validate_for(spec.kind)
            .map_err(|e| MediaGenError::InvalidTaskSpec(e.to_string()))?;

        let derived = expected_job_id(&spec);
        if spec.job_id.is_empty() {
            spec.job_id = derived;
        } else if spec.job_id != derived {
            return Err(MediaGenError::InvalidTaskSpec(format!(
                "job_id {} does not bind the spec contents (expected {})",
                spec.job_id, derived
            )));
        }

        if self.jobs.contains_key(&spec.job_id) {
            return Err(MediaGenError::JobAlreadyExists {
                job_id: spec.job_id,
            });
        }

        let quote = self.pricing.quote(spec.kind, &spec.params);
        enforce_ceiling(&spec.job_id, quote, spec.max_price)?;

        let now = Timestamp::now();
        let job = MediaGenJob {
            job_id: spec.job_id.clone(),
            task_spec: spec,
            status: MediaGenStatus::Pending,
            required_roles,
            assignments: Vec::new(),
            handoff: None,
            receipt: None,
            error: None,
            created_at: now,
            last_update: now,
        };
        self.persist_job(&job)?;
        self.jobs.insert(job.job_id.clone(), job.clone());
        Ok(job)
    }

    /// Claim a pending job, or one half of a split one, for an enrolled worker.
    ///
    /// `role` names which half of the schedule the worker is taking; it must be
    /// `None` for a job served whole and `Some` for a split one. A split job
    /// stays [`MediaGenStatus::Pending`] until both halves are claimed, so
    /// other workers can still see and take the open half.
    pub fn claim_job(
        &self,
        job_id: &str,
        worker_did: &str,
        role: Option<MediaGenExpertRole>,
    ) -> Result<MediaGenJob> {
        let worker = self
            .get_worker(worker_did)
            .ok_or_else(|| MediaGenError::WorkerNotEnrolled(worker_did.to_string()))?;

        let claimed = {
            let mut entry = self
                .jobs
                .get_mut(job_id)
                .ok_or_else(|| MediaGenError::JobNotFound(job_id.to_string()))?;
            let job = entry.value_mut();

            // Only a pending job can be claimed, whole or in halves.
            require_transition(job, MediaGenStatus::Claimed)?;

            let serves = match role {
                Some(role) => {
                    if !job.required_roles.contains(&role) {
                        return Err(MediaGenError::RoleNotRequired {
                            job_id: job_id.to_string(),
                            role,
                        });
                    }
                    if let Some(existing) = job.assignment_of_role(role) {
                        return Err(MediaGenError::RoleAlreadyClaimed {
                            job_id: job_id.to_string(),
                            role,
                            holder: existing.worker_did.clone(),
                        });
                    }
                    worker.can_serve_expert(&job.task_spec, role)
                }
                None => {
                    if job.is_split() {
                        return Err(MediaGenError::RoleRequired {
                            job_id: job_id.to_string(),
                        });
                    }
                    worker.can_serve(&job.task_spec)
                }
            };
            if !serves {
                return Err(MediaGenError::WorkerCannotServe {
                    worker_did: worker_did.to_string(),
                    job_id: job_id.to_string(),
                });
            }

            let now = Timestamp::now();
            job.assignments.push(MediaGenAssignment {
                worker_did: worker.worker_did.clone(),
                worker_address: worker.worker_address,
                role,
                claimed_at: now,
                share_bps: 0,
            });
            if job.is_fully_assigned() {
                job.status = MediaGenStatus::Claimed;
            }
            job.last_update = now;
            job.clone()
        };

        self.persist_job(&claimed)?;
        Ok(claimed)
    }

    /// Mark a claimed job as running, once the worker has the model loaded and
    /// the denoising loop underway.
    pub fn mark_running(&self, job_id: &str, worker_did: &str) -> Result<MediaGenJob> {
        let running = {
            let mut entry = self
                .jobs
                .get_mut(job_id)
                .ok_or_else(|| MediaGenError::JobNotFound(job_id.to_string()))?;
            let job = entry.value_mut();
            require_holder(job, worker_did)?;
            require_transition(job, MediaGenStatus::Running)?;
            job.status = MediaGenStatus::Running;
            job.last_update = Timestamp::now();
            job.clone()
        };
        self.persist_job(&running)?;
        Ok(running)
    }

    /// Publish the intermediate latent from the high-noise expert of a running
    /// split job, handing the schedule over to the low-noise expert.
    ///
    /// The latent itself lives in the content-addressed media store; what is
    /// recorded here is the commitment to it plus the step count that splits
    /// the payment. Signature verification is the caller's responsibility —
    /// the preimage is [`crate::commitments::handoff_signing_bytes`].
    pub fn record_handoff(&self, handoff: MediaGenHandoff) -> Result<MediaGenJob> {
        let updated = {
            let mut entry = self
                .jobs
                .get_mut(&handoff.job_id)
                .ok_or_else(|| MediaGenError::JobNotFound(handoff.job_id.clone()))?;
            let job = entry.value_mut();

            require_role_holder(job, MediaGenExpertRole::HighNoise, &handoff.from_worker_did)?;
            if job.status != MediaGenStatus::Running {
                return Err(MediaGenError::IllegalTransition {
                    job_id: handoff.job_id.clone(),
                    from: job.status,
                    to: MediaGenStatus::Running,
                });
            }
            if let Some(existing) = &job.handoff {
                return Err(MediaGenError::HandoffAlreadyRecorded {
                    job_id: handoff.job_id.clone(),
                    holder: existing.from_worker_did.clone(),
                });
            }

            let total = job.task_spec.params.steps;
            if handoff.steps_completed == 0 || handoff.steps_completed >= total {
                return Err(MediaGenError::HandoffStepsOutOfRange {
                    job_id: handoff.job_id.clone(),
                    completed: handoff.steps_completed,
                    total,
                });
            }

            job.handoff = Some(handoff.clone());
            job.last_update = Timestamp::now();
            job.clone()
        };
        self.persist_job(&updated)?;
        Ok(updated)
    }

    /// Complete a job with the finishing worker's signed receipt.
    ///
    /// The receipt must come from the worker that ran the final steps — the
    /// sole holder of a whole job, or the low-noise expert of a split one —
    /// reference the same job, carry the spec that was posted, and charge no
    /// more than the ceiling. A split job must already have its handoff
    /// recorded; the step counts on either side of it set each worker's share
    /// of the price. Signature verification is the caller's responsibility —
    /// the runtime is key-agnostic and the preimage is
    /// [`crate::commitments::receipt_signing_bytes`].
    pub fn submit_receipt(&self, receipt: MediaGenReceipt) -> Result<MediaGenJob> {
        let completed = {
            let mut entry = self
                .jobs
                .get_mut(&receipt.job_id)
                .ok_or_else(|| MediaGenError::JobNotFound(receipt.job_id.clone()))?;
            let job = entry.value_mut();

            if job.is_split() {
                require_role_holder(job, MediaGenExpertRole::LowNoise, &receipt.worker_did)?;
            } else {
                require_holder(job, &receipt.worker_did)?;
            }
            require_transition(job, MediaGenStatus::Completed)?;

            if receipt.task_spec != job.task_spec {
                return Err(MediaGenError::ReceiptSpecMismatch {
                    job_id: receipt.job_id.clone(),
                    reason: "the spec in the receipt differs from the posted spec".to_string(),
                });
            }
            enforce_ceiling(&receipt.job_id, receipt.price_paid, job.task_spec.max_price)?;

            apply_shares(job)?;
            job.status = MediaGenStatus::Completed;
            job.receipt = Some(receipt.clone());
            job.last_update = Timestamp::now();
            job.clone()
        };

        self.persist_receipt(&receipt)?;
        self.persist_job(&completed)?;
        Ok(completed)
    }

    /// Record a worker-side failure. Keeps the job for audit rather than
    /// dropping it, so a requester can see why nothing was produced.
    pub fn fail_job(&self, job_id: &str, worker_did: &str, error: String) -> Result<MediaGenJob> {
        let failed = {
            let mut entry = self
                .jobs
                .get_mut(job_id)
                .ok_or_else(|| MediaGenError::JobNotFound(job_id.to_string()))?;
            let job = entry.value_mut();
            require_holder(job, worker_did)?;
            require_transition(job, MediaGenStatus::Failed)?;
            job.status = MediaGenStatus::Failed;
            job.error = Some(error);
            job.last_update = Timestamp::now();
            job.clone()
        };
        self.persist_job(&failed)?;
        Ok(failed)
    }

    /// Cancel a job that no worker has claimed yet. Only the requester who
    /// posted it may cancel.
    pub fn cancel_job(&self, job_id: &str, requester_did: &str) -> Result<MediaGenJob> {
        let cancelled = {
            let mut entry = self
                .jobs
                .get_mut(job_id)
                .ok_or_else(|| MediaGenError::JobNotFound(job_id.to_string()))?;
            let job = entry.value_mut();
            if job.task_spec.requester_did != requester_did {
                return Err(MediaGenError::NotJobHolder {
                    job_id: job_id.to_string(),
                    holder: job.task_spec.requester_did.clone(),
                    caller: requester_did.to_string(),
                });
            }
            require_transition(job, MediaGenStatus::Cancelled)?;
            job.status = MediaGenStatus::Cancelled;
            job.last_update = Timestamp::now();
            job.clone()
        };
        self.persist_job(&cancelled)?;
        Ok(cancelled)
    }

    // -----------------------------------------------------------------------
    // Observed state
    // -----------------------------------------------------------------------
    //
    // A node holds two kinds of job state in the same map: jobs its own
    // workers act on, and jobs it only watches so those workers know what is
    // already taken. The methods above are the authority path — they check
    // that the caller is enrolled here, can serve this spec, and holds the
    // part of the job it is acting on. None of that is checkable for work
    // happening on another machine.
    //
    // The methods below are the mirror path. They keep every invariant that
    // is a property of the job itself (a role must be one the job needs, a
    // handoff must land inside the schedule, a receipt must carry the spec
    // that was posted) and drop every invariant that is a property of *this*
    // node. Each is idempotent on re-delivery, because a publisher is
    // subscribed to its own topic and neighbours re-announce.

    /// Record a claim made on another node.
    ///
    /// Re-delivery of a claim already recorded for the same worker is a no-op.
    /// A second worker claiming a part that is already held is a conflict, not
    /// a duplicate, and is reported as one.
    pub fn observe_claim(&self, claim: &MediaGenClaim) -> Result<MediaGenJob> {
        let updated = {
            let mut entry = self
                .jobs
                .get_mut(&claim.job_id)
                .ok_or_else(|| MediaGenError::JobNotFound(claim.job_id.clone()))?;
            let job = entry.value_mut();

            match claim.role {
                Some(role) if !job.required_roles.contains(&role) => {
                    return Err(MediaGenError::RoleNotRequired {
                        job_id: claim.job_id.clone(),
                        role,
                    });
                }
                Some(_) => {}
                None if job.is_split() => {
                    return Err(MediaGenError::RoleRequired {
                        job_id: claim.job_id.clone(),
                    });
                }
                None => {}
            }

            let held = match claim.role {
                Some(role) => job.assignment_of_role(role),
                None => job.assignments.first(),
            };
            if let Some(existing) = held {
                if existing.worker_did == claim.worker_did {
                    return Ok(job.clone());
                }
                return Err(MediaGenError::RoleAlreadyClaimed {
                    job_id: claim.job_id.clone(),
                    role: claim.role.unwrap_or(MediaGenExpertRole::HighNoise),
                    holder: existing.worker_did.clone(),
                });
            }

            job.assignments.push(MediaGenAssignment {
                worker_did: claim.worker_did.clone(),
                worker_address: claim.worker_address,
                role: claim.role,
                claimed_at: claim.claimed_at,
                share_bps: 0,
            });
            if job.is_fully_assigned() && job.status == MediaGenStatus::Pending {
                job.status = MediaGenStatus::Claimed;
            }
            job.last_update = Timestamp::now();
            job.clone()
        };
        self.persist_job(&updated)?;
        Ok(updated)
    }

    /// Record a handoff published on another node.
    ///
    /// Unlike [`Self::record_handoff`] this does not require the job to be
    /// running locally: a watcher never saw the high-noise worker start, only
    /// that it finished its half. Re-delivery of the same commitment is a
    /// no-op; a second, different commitment for the same job is a conflict.
    pub fn observe_handoff(&self, handoff: MediaGenHandoff) -> Result<MediaGenJob> {
        let updated = {
            let mut entry = self
                .jobs
                .get_mut(&handoff.job_id)
                .ok_or_else(|| MediaGenError::JobNotFound(handoff.job_id.clone()))?;
            let job = entry.value_mut();

            require_role_holder(job, MediaGenExpertRole::HighNoise, &handoff.from_worker_did)?;

            if let Some(existing) = &job.handoff {
                if existing.latent_hash == handoff.latent_hash {
                    return Ok(job.clone());
                }
                return Err(MediaGenError::HandoffAlreadyRecorded {
                    job_id: handoff.job_id.clone(),
                    holder: existing.from_worker_did.clone(),
                });
            }

            let total = job.task_spec.params.steps;
            if handoff.steps_completed == 0 || handoff.steps_completed >= total {
                return Err(MediaGenError::HandoffStepsOutOfRange {
                    job_id: handoff.job_id.clone(),
                    completed: handoff.steps_completed,
                    total,
                });
            }

            job.handoff = Some(handoff);
            job.last_update = Timestamp::now();
            job.clone()
        };
        self.persist_job(&updated)?;
        Ok(updated)
    }

    /// Record a completion reported on another node.
    ///
    /// Re-delivery of a receipt committing to the same output is a no-op. A
    /// second receipt committing to different bytes for the same job is a
    /// conflict — two workers rendered the same job, and the requester is
    /// owed only one of them.
    pub fn observe_receipt(&self, receipt: MediaGenReceipt) -> Result<MediaGenJob> {
        let completed = {
            let mut entry = self
                .jobs
                .get_mut(&receipt.job_id)
                .ok_or_else(|| MediaGenError::JobNotFound(receipt.job_id.clone()))?;
            let job = entry.value_mut();

            if let Some(existing) = &job.receipt {
                if existing.output_hash == receipt.output_hash {
                    return Ok(job.clone());
                }
                return Err(MediaGenError::ReceiptSpecMismatch {
                    job_id: receipt.job_id.clone(),
                    reason: format!(
                        "job already completed with output {}, a second receipt commits to {}",
                        existing.output_hash, receipt.output_hash
                    ),
                });
            }

            if receipt.task_spec != job.task_spec {
                return Err(MediaGenError::ReceiptSpecMismatch {
                    job_id: receipt.job_id.clone(),
                    reason: "the spec in the receipt differs from the posted spec".to_string(),
                });
            }
            enforce_ceiling(&receipt.job_id, receipt.price_paid, job.task_spec.max_price)?;

            apply_shares(job)?;
            job.status = MediaGenStatus::Completed;
            job.receipt = Some(receipt.clone());
            job.last_update = Timestamp::now();
            job.clone()
        };
        self.persist_receipt(&receipt)?;
        self.persist_job(&completed)?;
        Ok(completed)
    }

    pub fn get_job(&self, job_id: &str) -> Option<MediaGenJob> {
        self.jobs.get(job_id).map(|j| j.value().clone())
    }

    pub fn list_jobs(&self) -> Vec<MediaGenJob> {
        self.jobs.iter().map(|j| j.value().clone()).collect()
    }

    /// Jobs in a given status — the queue view a worker polls for
    /// [`MediaGenStatus::Pending`].
    pub fn list_jobs_by_status(&self, status: MediaGenStatus) -> Vec<MediaGenJob> {
        self.jobs
            .iter()
            .filter(|j| j.value().status == status)
            .map(|j| j.value().clone())
            .collect()
    }

    /// Receipt for a completed job, read from storage so it survives the
    /// terminal-job eviction that [`Self::hydrate`] applies to the queue.
    pub fn get_receipt(&self, job_id: &str) -> Result<Option<MediaGenReceipt>> {
        if let Some(job) = self.get_job(job_id)
            && let Some(receipt) = job.receipt
        {
            return Ok(Some(receipt));
        }
        let Some(storage) = &self.storage else {
            return Ok(None);
        };
        let key = format!("receipt:{}", job_id);
        let raw = storage
            .get(CF_MEDIA_GEN_RECEIPTS, key.as_bytes())
            .map_err(|e| MediaGenError::Storage(e.to_string()))?;
        match raw {
            Some(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|e| MediaGenError::Serialization(e.to_string())),
            None => Ok(None),
        }
    }

    /// Fetch the generated bytes a receipt commits to, verifying size and hash.
    pub async fn fetch_output(&self, receipt: &MediaGenReceipt) -> Result<Bytes> {
        let store = self
            .output_store
            .as_ref()
            .ok_or(MediaGenError::NoOutputStore)?;
        store.fetch(receipt).await
    }

    /// Fetch the intermediate latent for a split job, verifying size and hash
    /// against the handoff the high-noise expert published.
    ///
    /// This is what the low-noise worker calls to start: the two halves of a
    /// split job run on different machines, so the second one has to pull the
    /// first one's partly-denoised state over the network rather than read it
    /// out of shared memory.
    pub async fn fetch_latent(&self, job_id: &str) -> Result<Bytes> {
        let handoff = {
            let entry = self
                .jobs
                .get(job_id)
                .ok_or_else(|| MediaGenError::JobNotFound(job_id.to_string()))?;
            entry
                .value()
                .handoff
                .clone()
                .ok_or_else(|| MediaGenError::HandoffMissing {
                    job_id: job_id.to_string(),
                })?
        };
        let store = self
            .output_store
            .as_ref()
            .ok_or(MediaGenError::NoOutputStore)?;
        store.fetch_latent(&handoff).await
    }

    /// Fetch the conditioning image an editing or image-conditioned job names,
    /// verifying it against the hash the spec committed to.
    ///
    /// The requester publishes the image before posting the job, so by the time
    /// a worker claims one the hash is already bound into the job id. A worker
    /// on another machine cannot read the requester's disk, so this is how it
    /// obtains the frame it conditions on.
    pub async fn fetch_input(&self, job_id: &str) -> Result<Bytes> {
        let hash = {
            let entry = self
                .jobs
                .get(job_id)
                .ok_or_else(|| MediaGenError::JobNotFound(job_id.to_string()))?;
            entry
                .value()
                .task_spec
                .params
                .input_image_hash
                .ok_or_else(|| MediaGenError::InputImageMissing {
                    job_id: job_id.to_string(),
                })?
        };
        let store = self
            .output_store
            .as_ref()
            .ok_or(MediaGenError::NoOutputStore)?;
        store.fetch_input(&hash).await
    }

    // -----------------------------------------------------------------------
    // Persistence
    // -----------------------------------------------------------------------

    fn persist_job(&self, job: &MediaGenJob) -> Result<()> {
        let Some(storage) = &self.storage else {
            return Ok(());
        };
        let key = format!("job:{}", job.job_id);
        let value =
            serde_json::to_vec(job).map_err(|e| MediaGenError::Serialization(e.to_string()))?;
        storage
            .put(CF_MEDIA_GEN_RUNS, key.as_bytes(), &value)
            .map_err(|e| MediaGenError::Storage(e.to_string()))
    }

    fn persist_receipt(&self, receipt: &MediaGenReceipt) -> Result<()> {
        let Some(storage) = &self.storage else {
            return Ok(());
        };
        let key = format!("receipt:{}", receipt.job_id);
        let value =
            serde_json::to_vec(receipt).map_err(|e| MediaGenError::Serialization(e.to_string()))?;
        storage
            .put(CF_MEDIA_GEN_RECEIPTS, key.as_bytes(), &value)
            .map_err(|e| MediaGenError::Storage(e.to_string()))
    }

    fn persist_worker(&self, worker: &MediaGenWorkerCapability) -> Result<()> {
        let Some(storage) = &self.storage else {
            return Ok(());
        };
        let key = format!("worker:{}", worker.worker_did);
        let value =
            serde_json::to_vec(worker).map_err(|e| MediaGenError::Serialization(e.to_string()))?;
        storage
            .put(CF_MEDIA_GEN_WORKERS, key.as_bytes(), &value)
            .map_err(|e| MediaGenError::Storage(e.to_string()))
    }
}

fn require_transition(job: &MediaGenJob, next: MediaGenStatus) -> Result<()> {
    if !job.status.can_transition_to(next) {
        return Err(MediaGenError::IllegalTransition {
            job_id: job.job_id.clone(),
            from: job.status,
            to: next,
        });
    }
    Ok(())
}

/// The caller must hold some part of the job.
fn require_holder(job: &MediaGenJob, caller: &str) -> Result<()> {
    if job.assignment_for(caller).is_some() {
        return Ok(());
    }
    Err(MediaGenError::NotJobHolder {
        job_id: job.job_id.clone(),
        holder: holder_label(job),
        caller: caller.to_string(),
    })
}

/// The caller must hold one specific half of a split job.
fn require_role_holder(job: &MediaGenJob, role: MediaGenExpertRole, caller: &str) -> Result<()> {
    if !job.required_roles.contains(&role) {
        return Err(MediaGenError::RoleNotRequired {
            job_id: job.job_id.clone(),
            role,
        });
    }
    match job.assignment_of_role(role) {
        Some(a) if a.worker_did == caller => Ok(()),
        Some(a) => Err(MediaGenError::NotJobHolder {
            job_id: job.job_id.clone(),
            holder: a.worker_did.clone(),
            caller: caller.to_string(),
        }),
        None => Err(MediaGenError::NotJobHolder {
            job_id: job.job_id.clone(),
            holder: format!("{role} unclaimed"),
            caller: caller.to_string(),
        }),
    }
}

fn holder_label(job: &MediaGenJob) -> String {
    if job.assignments.is_empty() {
        return "unclaimed".to_string();
    }
    job.assignments
        .iter()
        .map(|a| a.worker_did.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Fix each worker's share of the price at completion.
///
/// A whole job pays its single holder in full. A split job pays on the steps
/// each expert actually ran, which the handoff records: the high-noise worker
/// gets `steps_completed / steps`, the low-noise worker the remainder. Rounding
/// goes to the low-noise worker so the two shares always sum to 10000.
fn apply_shares(job: &mut MediaGenJob) -> Result<()> {
    if !job.is_split() {
        for a in &mut job.assignments {
            a.share_bps = 10_000;
        }
        return Ok(());
    }

    let handoff = job
        .handoff
        .as_ref()
        .ok_or_else(|| MediaGenError::HandoffMissing {
            job_id: job.job_id.clone(),
        })?;
    let total = u64::from(job.task_spec.params.steps);
    let high_bps = (u64::from(handoff.steps_completed) * 10_000 / total) as u32;

    for a in &mut job.assignments {
        a.share_bps = match a.role {
            Some(MediaGenExpertRole::HighNoise) => high_bps,
            Some(MediaGenExpertRole::LowNoise) => 10_000 - high_bps,
            None => 0,
        };
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use tenzro_storage::kv::MemoryStore;
    use tenzro_types::media_gen::{MediaGenExpertHolding, MediaGenKind, MediaGenParams};
    use tenzro_types::primitives::{Address, Hash, Signature};

    const CEILING: u128 = 100_000_000_000_000_000_000;

    fn params(kind: MediaGenKind) -> MediaGenParams {
        MediaGenParams {
            prompt: "a fox in a plaster diorama".to_string(),
            negative_prompt: None,
            width: 1024,
            height: 1024,
            num_frames: if kind.is_video() { Some(81) } else { None },
            fps: if kind.is_video() { Some(16) } else { None },
            steps: 30,
            guidance_scale: 4.5,
            voxel_resolution: None,
            seed: Some(42),
            input_image_hash: if kind.requires_input_image() {
                Some(Hash::new([7u8; 32]))
            } else {
                None
            },
            metadata: HashMap::new(),
        }
    }

    fn spec(kind: MediaGenKind) -> MediaGenTaskSpec {
        MediaGenTaskSpec {
            job_id: String::new(),
            requester_did: "did:tenzro:human:req".to_string(),
            requester_address: Address::zero(),
            model_id: "qwen-image".to_string(),
            kind,
            params: params(kind),
            max_price: CEILING,
            created_at: Timestamp::new(1_700_000_000_000),
            metadata: HashMap::new(),
        }
    }

    fn worker() -> MediaGenWorkerCapability {
        MediaGenWorkerCapability {
            worker_did: "did:tenzro:machine:worker".to_string(),
            worker_address: Address::new([2u8; 32]),
            supported_models: vec!["qwen-image".to_string()],
            expert_holdings: Vec::new(),
            max_resolution: 2048,
            max_frames: Some(121),
            gpu_vram_gb: 48.0,
            registered_at: Timestamp::new(0),
        }
    }

    /// A worker that holds one half of the split video model, and nothing whole.
    fn expert_worker(tag: &str, role: MediaGenExpertRole) -> MediaGenWorkerCapability {
        MediaGenWorkerCapability {
            worker_did: format!("did:tenzro:machine:{tag}"),
            worker_address: Address::new([3u8; 32]),
            supported_models: Vec::new(),
            expert_holdings: vec![MediaGenExpertHolding {
                model_id: "wan2.2-t2v-a14b".to_string(),
                role,
            }],
            max_resolution: 2048,
            max_frames: Some(121),
            gpu_vram_gb: 48.0,
            registered_at: Timestamp::new(0),
        }
    }

    fn split_spec() -> MediaGenTaskSpec {
        let mut s = spec(MediaGenKind::Text2Video);
        s.model_id = "wan2.2-t2v-a14b".to_string();
        s.job_id = String::new();
        s
    }

    /// A runtime with both halves of the split video model enrolled, plus the
    /// whole-model worker.
    fn split_runtime() -> MediaGenRuntime {
        let rt = runtime();
        rt.enroll_worker(expert_worker("high", MediaGenExpertRole::HighNoise))
            .unwrap();
        rt.enroll_worker(expert_worker("low", MediaGenExpertRole::LowNoise))
            .unwrap();
        rt
    }

    fn handoff_for(job: &MediaGenJob, steps_completed: u32) -> MediaGenHandoff {
        let high = expert_worker("high", MediaGenExpertRole::HighNoise);
        MediaGenHandoff {
            job_id: job.job_id.clone(),
            from_worker_did: high.worker_did,
            from_worker_address: high.worker_address,
            latent_hash: Hash::new([5u8; 32]),
            latent_bytes: 8_388_608,
            steps_completed,
            handed_off_at: Timestamp::new(1_700_000_020_000),
            worker_signature: Signature::default(),
        }
    }

    fn receipt_for(job: &MediaGenJob) -> MediaGenReceipt {
        MediaGenReceipt {
            job_id: job.job_id.clone(),
            task_spec: job.task_spec.clone(),
            worker_did: worker().worker_did,
            worker_address: worker().worker_address,
            output_hash: Hash::new([9u8; 32]),
            output_mime: "image/png".to_string(),
            output_bytes: 4096,
            seed_used: 42,
            generation_time_ms: 7_100,
            price_paid: 1_000,
            completed_at: Timestamp::new(1_700_000_030_000),
            worker_signature: Signature::default(),
        }
    }

    fn runtime() -> MediaGenRuntime {
        let rt = MediaGenRuntime::with_storage(Arc::new(MemoryStore::new()));
        rt.enroll_worker(worker()).unwrap();
        rt
    }

    #[test]
    fn post_derives_the_job_id() {
        let rt = runtime();
        let job = rt.post_job(spec(MediaGenKind::Text2Image)).unwrap();
        assert_eq!(job.job_id.len(), 64);
        assert_eq!(job.status, MediaGenStatus::Pending);
        assert_eq!(job.job_id, job.task_spec.job_id);
    }

    #[test]
    fn post_rejects_a_mismatched_job_id() {
        let rt = runtime();
        let mut s = spec(MediaGenKind::Text2Image);
        s.job_id = "not-the-real-id".to_string();
        let err = rt.post_job(s).unwrap_err();
        assert!(matches!(err, MediaGenError::InvalidTaskSpec(_)));
    }

    #[test]
    fn post_rejects_a_duplicate() {
        let rt = runtime();
        rt.post_job(spec(MediaGenKind::Text2Image)).unwrap();
        let err = rt.post_job(spec(MediaGenKind::Text2Image)).unwrap_err();
        assert!(matches!(err, MediaGenError::JobAlreadyExists { .. }));
    }

    #[test]
    fn post_rejects_invalid_params() {
        let rt = runtime();
        let mut s = spec(MediaGenKind::Text2Image);
        s.params.prompt = String::new();
        assert!(matches!(
            rt.post_job(s).unwrap_err(),
            MediaGenError::InvalidTaskSpec(_)
        ));
    }

    #[test]
    fn post_rejects_a_ceiling_below_the_quote() {
        let rt = runtime();
        let mut s = spec(MediaGenKind::Text2Image);
        s.max_price = 1;
        assert!(matches!(
            rt.post_job(s).unwrap_err(),
            MediaGenError::PriceCeilingExceeded { .. }
        ));
    }

    #[test]
    fn re_enrolling_replaces_the_previous_capabilities() {
        let rt = runtime();
        // A worker that restarts announces itself again. That has to succeed,
        // or it can never come back without operator intervention.
        let mut second = worker();
        second.supported_models = vec!["qwen-image".to_string()];
        rt.enroll_worker(second).expect("re-enrollment is allowed");

        let held = rt.get_worker(&worker().worker_did).expect("still enrolled");
        assert_eq!(
            held.supported_models,
            vec!["qwen-image".to_string()],
            "the newest announcement wins; a stale set would route jobs to \
             models the worker no longer holds"
        );
        assert_eq!(rt.list_workers().len(), 1, "re-enrolment must not duplicate");
    }

    /// A worker that changes identity announces under a new key, so the old
    /// enrollment has to be withdrawable — otherwise it advertises models
    /// nothing is serving, for as long as the node lives.
    #[test]
    fn a_withdrawn_worker_stops_being_enrolled() {
        let rt = runtime();
        let w = worker();
        rt.enroll_worker(w.clone()).unwrap();
        assert_eq!(rt.list_workers().len(), 1);

        assert!(
            rt.remove_worker(&w.worker_did).unwrap(),
            "removing an enrolled worker reports that it was there"
        );
        assert!(rt.list_workers().is_empty());
        assert!(rt.get_worker(&w.worker_did).is_none());

        assert!(
            !rt.remove_worker(&w.worker_did).unwrap(),
            "removing it twice is not an error, but reports nothing was removed"
        );
        assert!(
            !rt.remove_worker("did:tenzro:machine:never-enrolled").unwrap(),
            "removing an unknown worker reports nothing was removed"
        );
    }

    #[test]
    fn claim_requires_enrollment() {
        let rt = runtime();
        let job = rt.post_job(spec(MediaGenKind::Text2Image)).unwrap();
        let err = rt
            .claim_job(&job.job_id, "did:tenzro:machine:stranger", None)
            .unwrap_err();
        assert!(matches!(err, MediaGenError::WorkerNotEnrolled(_)));
    }

    #[test]
    fn claim_requires_matching_capability() {
        let rt = runtime();
        let mut s = spec(MediaGenKind::Text2Image);
        s.model_id = "flux2-klein".to_string();
        s.job_id = String::new();
        let job = rt.post_job(s).unwrap();
        let err = rt
            .claim_job(&job.job_id, &worker().worker_did, None)
            .unwrap_err();
        assert!(matches!(err, MediaGenError::WorkerCannotServe { .. }));
    }

    #[test]
    fn claim_then_run_then_complete() {
        let rt = runtime();
        let job = rt.post_job(spec(MediaGenKind::Text2Image)).unwrap();
        let did = worker().worker_did;

        let claimed = rt.claim_job(&job.job_id, &did, None).unwrap();
        assert_eq!(claimed.status, MediaGenStatus::Claimed);
        assert!(!claimed.is_split());
        assert_eq!(claimed.assignments.len(), 1);
        assert_eq!(claimed.assignment_for(&did).unwrap().role, None);

        let running = rt.mark_running(&job.job_id, &did).unwrap();
        assert_eq!(running.status, MediaGenStatus::Running);

        let done = rt.submit_receipt(receipt_for(&running)).unwrap();
        assert_eq!(done.status, MediaGenStatus::Completed);
        assert!(done.receipt.is_some());
        assert_eq!(done.assignments[0].share_bps, 10_000);
        assert_eq!(
            rt.get_receipt(&job.job_id).unwrap().unwrap().output_bytes,
            4096
        );
    }

    #[test]
    fn double_claim_is_rejected() {
        let rt = runtime();
        let job = rt.post_job(spec(MediaGenKind::Text2Image)).unwrap();
        let did = worker().worker_did;
        rt.claim_job(&job.job_id, &did, None).unwrap();
        assert!(matches!(
            rt.claim_job(&job.job_id, &did, None).unwrap_err(),
            MediaGenError::IllegalTransition { .. }
        ));
    }

    #[test]
    fn receipt_from_another_worker_is_rejected() {
        let rt = runtime();
        let job = rt.post_job(spec(MediaGenKind::Text2Image)).unwrap();
        rt.claim_job(&job.job_id, &worker().worker_did, None)
            .unwrap();

        let mut r = receipt_for(&job);
        r.worker_did = "did:tenzro:machine:other".to_string();
        assert!(matches!(
            rt.submit_receipt(r).unwrap_err(),
            MediaGenError::NotJobHolder { .. }
        ));
    }

    #[test]
    fn receipt_carrying_a_different_spec_is_rejected() {
        let rt = runtime();
        let job = rt.post_job(spec(MediaGenKind::Text2Image)).unwrap();
        rt.claim_job(&job.job_id, &worker().worker_did, None)
            .unwrap();

        let mut r = receipt_for(&job);
        r.task_spec.params.steps = 4;
        assert!(matches!(
            rt.submit_receipt(r).unwrap_err(),
            MediaGenError::ReceiptSpecMismatch { .. }
        ));
    }

    #[test]
    fn receipt_over_the_ceiling_is_rejected() {
        let rt = runtime();
        let job = rt.post_job(spec(MediaGenKind::Text2Image)).unwrap();
        rt.claim_job(&job.job_id, &worker().worker_did, None)
            .unwrap();

        let mut r = receipt_for(&job);
        r.price_paid = CEILING + 1;
        assert!(matches!(
            rt.submit_receipt(r).unwrap_err(),
            MediaGenError::PriceCeilingExceeded { .. }
        ));
    }

    #[test]
    fn cancel_is_requester_only_and_pending_only() {
        let rt = runtime();
        let job = rt.post_job(spec(MediaGenKind::Text2Image)).unwrap();
        assert!(matches!(
            rt.cancel_job(&job.job_id, "did:tenzro:human:someone-else")
                .unwrap_err(),
            MediaGenError::NotJobHolder { .. }
        ));

        rt.claim_job(&job.job_id, &worker().worker_did, None)
            .unwrap();
        assert!(matches!(
            rt.cancel_job(&job.job_id, &job.task_spec.requester_did)
                .unwrap_err(),
            MediaGenError::IllegalTransition { .. }
        ));
    }

    #[test]
    fn failure_records_the_reason() {
        let rt = runtime();
        let job = rt.post_job(spec(MediaGenKind::Text2Image)).unwrap();
        let did = worker().worker_did;
        rt.claim_job(&job.job_id, &did, None).unwrap();
        let failed = rt
            .fail_job(&job.job_id, &did, "out of VRAM".to_string())
            .unwrap();
        assert_eq!(failed.status, MediaGenStatus::Failed);
        assert_eq!(failed.error.as_deref(), Some("out of VRAM"));
    }

    #[test]
    fn hydrate_restores_open_jobs_and_workers_but_not_terminal_jobs() {
        let storage = Arc::new(MemoryStore::new());

        let first = MediaGenRuntime::with_storage(storage.clone());
        first.enroll_worker(worker()).unwrap();
        let open = first.post_job(spec(MediaGenKind::Text2Image)).unwrap();

        let mut other = spec(MediaGenKind::Text2Image);
        other.params.prompt = "a second prompt".to_string();
        let closed = first.post_job(other).unwrap();
        first
            .cancel_job(&closed.job_id, &closed.task_spec.requester_did)
            .unwrap();

        let restored = MediaGenRuntime::with_storage(storage);
        assert_eq!(restored.hydrate().unwrap(), (1, 1));
        assert!(restored.get_job(&open.job_id).is_some());
        assert!(restored.get_job(&closed.job_id).is_none());
        assert!(restored.get_worker(&worker().worker_did).is_some());
    }

    #[test]
    fn pending_jobs_are_listable_for_workers() {
        let rt = runtime();
        let job = rt.post_job(spec(MediaGenKind::Text2Image)).unwrap();
        assert_eq!(rt.list_jobs_by_status(MediaGenStatus::Pending).len(), 1);
        rt.claim_job(&job.job_id, &worker().worker_did, None)
            .unwrap();
        assert!(rt.list_jobs_by_status(MediaGenStatus::Pending).is_empty());
        assert_eq!(rt.list_jobs().len(), 1);
    }

    // ---------------------------------------------------------------------
    // Jobs whose denoising schedule splits across two experts
    // ---------------------------------------------------------------------

    fn high_did() -> String {
        expert_worker("high", MediaGenExpertRole::HighNoise).worker_did
    }

    fn low_did() -> String {
        expert_worker("low", MediaGenExpertRole::LowNoise).worker_did
    }

    /// The receipt a split job's low-noise holder submits.
    fn split_receipt_for(job: &MediaGenJob) -> MediaGenReceipt {
        let low = expert_worker("low", MediaGenExpertRole::LowNoise);
        MediaGenReceipt {
            worker_did: low.worker_did,
            worker_address: low.worker_address,
            output_mime: "video/mp4".to_string(),
            ..receipt_for(job)
        }
    }

    /// Drive a split job to Running with both halves claimed.
    fn running_split(rt: &MediaGenRuntime) -> MediaGenJob {
        let job = rt.post_split_job(split_spec()).unwrap();
        rt.claim_job(
            &job.job_id,
            &high_did(),
            Some(MediaGenExpertRole::HighNoise),
        )
        .unwrap();
        rt.claim_job(&job.job_id, &low_did(), Some(MediaGenExpertRole::LowNoise))
            .unwrap();
        rt.mark_running(&job.job_id, &high_did()).unwrap()
    }

    #[test]
    fn a_split_job_stays_pending_until_both_halves_are_claimed() {
        let rt = split_runtime();
        let job = rt.post_split_job(split_spec()).unwrap();
        assert!(job.is_split());
        assert_eq!(
            job.unclaimed_roles(),
            vec![MediaGenExpertRole::HighNoise, MediaGenExpertRole::LowNoise]
        );

        let half = rt
            .claim_job(
                &job.job_id,
                &high_did(),
                Some(MediaGenExpertRole::HighNoise),
            )
            .unwrap();
        assert_eq!(half.status, MediaGenStatus::Pending);
        assert_eq!(half.unclaimed_roles(), vec![MediaGenExpertRole::LowNoise]);

        let full = rt
            .claim_job(&job.job_id, &low_did(), Some(MediaGenExpertRole::LowNoise))
            .unwrap();
        assert_eq!(full.status, MediaGenStatus::Claimed);
        assert!(full.is_fully_assigned());
    }

    #[test]
    fn a_split_job_cannot_be_claimed_whole() {
        let rt = split_runtime();
        let job = rt.post_split_job(split_spec()).unwrap();
        assert!(matches!(
            rt.claim_job(&job.job_id, &high_did(), None).unwrap_err(),
            MediaGenError::RoleRequired { .. }
        ));
    }

    #[test]
    fn a_whole_job_has_no_roles_to_claim() {
        let rt = split_runtime();
        let job = rt.post_job(spec(MediaGenKind::Text2Image)).unwrap();
        assert!(matches!(
            rt.claim_job(
                &job.job_id,
                &worker().worker_did,
                Some(MediaGenExpertRole::HighNoise)
            )
            .unwrap_err(),
            MediaGenError::RoleNotRequired { .. }
        ));
    }

    #[test]
    fn a_claimed_half_is_not_reclaimable() {
        let rt = split_runtime();
        let job = rt.post_split_job(split_spec()).unwrap();
        rt.claim_job(
            &job.job_id,
            &high_did(),
            Some(MediaGenExpertRole::HighNoise),
        )
        .unwrap();
        assert!(matches!(
            rt.claim_job(&job.job_id, &low_did(), Some(MediaGenExpertRole::HighNoise))
                .unwrap_err(),
            MediaGenError::RoleAlreadyClaimed { .. }
        ));
    }

    #[test]
    fn a_worker_holding_the_wrong_half_cannot_claim() {
        let rt = split_runtime();
        let job = rt.post_split_job(split_spec()).unwrap();
        assert!(matches!(
            rt.claim_job(&job.job_id, &low_did(), Some(MediaGenExpertRole::HighNoise))
                .unwrap_err(),
            MediaGenError::WorkerCannotServe { .. }
        ));
    }

    #[test]
    fn a_worker_without_the_model_cannot_claim_a_half() {
        let rt = split_runtime();
        let job = rt.post_split_job(split_spec()).unwrap();
        assert!(matches!(
            rt.claim_job(
                &job.job_id,
                &worker().worker_did,
                Some(MediaGenExpertRole::HighNoise)
            )
            .unwrap_err(),
            MediaGenError::WorkerCannotServe { .. }
        ));
    }

    #[test]
    fn a_whole_model_worker_qualifies_for_either_half() {
        let rt = split_runtime();
        let mut both = worker();
        both.worker_did = "did:tenzro:machine:both".to_string();
        both.supported_models = vec!["wan2.2-t2v-a14b".to_string()];
        rt.enroll_worker(both.clone()).unwrap();

        let job = rt.post_split_job(split_spec()).unwrap();
        rt.claim_job(
            &job.job_id,
            &both.worker_did,
            Some(MediaGenExpertRole::HighNoise),
        )
        .unwrap();
        let full = rt
            .claim_job(
                &job.job_id,
                &both.worker_did,
                Some(MediaGenExpertRole::LowNoise),
            )
            .unwrap();
        assert_eq!(full.status, MediaGenStatus::Claimed);
        assert_eq!(full.assignments.len(), 2);
    }

    #[test]
    fn handoff_is_the_high_noise_holders_to_publish() {
        let rt = split_runtime();
        let job = running_split(&rt);

        let mut wrong = handoff_for(&job, 26);
        wrong.from_worker_did = low_did();
        assert!(matches!(
            rt.record_handoff(wrong).unwrap_err(),
            MediaGenError::NotJobHolder { .. }
        ));

        let handed = rt.record_handoff(handoff_for(&job, 26)).unwrap();
        assert_eq!(handed.handoff.unwrap().steps_completed, 26);
    }

    #[test]
    fn handoff_needs_a_running_job() {
        let rt = split_runtime();
        let job = rt.post_split_job(split_spec()).unwrap();
        rt.claim_job(
            &job.job_id,
            &high_did(),
            Some(MediaGenExpertRole::HighNoise),
        )
        .unwrap();
        assert!(matches!(
            rt.record_handoff(handoff_for(&job, 26)).unwrap_err(),
            MediaGenError::IllegalTransition { .. }
        ));
    }

    #[test]
    fn handoff_is_recorded_once() {
        let rt = split_runtime();
        let job = running_split(&rt);
        rt.record_handoff(handoff_for(&job, 26)).unwrap();
        assert!(matches!(
            rt.record_handoff(handoff_for(&job, 20)).unwrap_err(),
            MediaGenError::HandoffAlreadyRecorded { .. }
        ));
    }

    #[test]
    fn handoff_must_leave_work_for_both_experts() {
        let rt = split_runtime();
        let job = running_split(&rt);
        for completed in [0, job.task_spec.params.steps] {
            assert!(matches!(
                rt.record_handoff(handoff_for(&job, completed)).unwrap_err(),
                MediaGenError::HandoffStepsOutOfRange { .. }
            ));
        }
    }

    #[test]
    fn the_low_noise_holder_submits_the_receipt() {
        let rt = split_runtime();
        let job = running_split(&rt);
        rt.record_handoff(handoff_for(&job, 26)).unwrap();

        let mut from_high = split_receipt_for(&job);
        from_high.worker_did = high_did();
        assert!(matches!(
            rt.submit_receipt(from_high).unwrap_err(),
            MediaGenError::NotJobHolder { .. }
        ));

        let done = rt.submit_receipt(split_receipt_for(&job)).unwrap();
        assert_eq!(done.status, MediaGenStatus::Completed);
    }

    #[test]
    fn a_receipt_without_a_handoff_is_rejected() {
        let rt = split_runtime();
        let job = running_split(&rt);
        assert!(matches!(
            rt.submit_receipt(split_receipt_for(&job)).unwrap_err(),
            MediaGenError::HandoffMissing { .. }
        ));
    }

    #[test]
    fn payment_splits_on_the_steps_each_expert_ran() {
        let rt = split_runtime();
        let job = running_split(&rt);
        rt.record_handoff(handoff_for(&job, 26)).unwrap();
        let done = rt.submit_receipt(split_receipt_for(&job)).unwrap();

        // 26 of 30 steps ran on the high-noise expert.
        let high = done
            .assignment_of_role(MediaGenExpertRole::HighNoise)
            .unwrap();
        let low = done
            .assignment_of_role(MediaGenExpertRole::LowNoise)
            .unwrap();
        assert_eq!(high.share_bps, 8_666);
        assert_eq!(low.share_bps, 1_334);
        assert_eq!(high.share_bps + low.share_bps, 10_000);
    }

    #[tokio::test]
    async fn fetch_output_needs_a_store() {
        let rt = runtime();
        let job = rt.post_job(spec(MediaGenKind::Text2Image)).unwrap();
        let err = rt.fetch_output(&receipt_for(&job)).await.unwrap_err();
        assert!(matches!(err, MediaGenError::NoOutputStore));
    }

    #[tokio::test]
    async fn fetch_output_verifies_the_receipt_commitment() {
        use crate::output_store::{InMemoryOutputStore, MediaGenOutputStore, compute_output_hash};

        let store = Arc::new(InMemoryOutputStore::new());
        let bytes = Bytes::from_static(b"generated-png-bytes");
        store.publish(bytes.clone()).await.unwrap();

        let rt = MediaGenRuntime::with_storage(Arc::new(MemoryStore::new()))
            .with_output_store(store.clone());
        rt.enroll_worker(worker()).unwrap();
        let job = rt.post_job(spec(MediaGenKind::Text2Image)).unwrap();

        let mut r = receipt_for(&job);
        r.output_hash = compute_output_hash(&bytes);
        r.output_bytes = bytes.len() as u64;
        assert_eq!(rt.fetch_output(&r).await.unwrap(), bytes);

        r.output_bytes += 1;
        assert!(matches!(
            rt.fetch_output(&r).await.unwrap_err(),
            MediaGenError::OutputSizeMismatch { .. }
        ));
    }
}
