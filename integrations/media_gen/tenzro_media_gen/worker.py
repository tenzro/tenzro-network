"""The worker loop: claim a job, render it, seal the result.

One worker process serves one GPU. It enrolls its capability with a node, polls
for pending jobs it can actually run, and for each one walks the lifecycle the
node enforces:

    claim → markRunning → render → publishOutput → recordHandoff | submitReceipt

A split job takes two passes through that lifecycle on two machines. The
high-noise expert ends at ``recordHandoff``; the low-noise expert starts by
fetching the latent that handoff committed to and ends at ``submitReceipt``. A
worker holding both experts of a split model claims each half separately and so
runs the same two passes locally — the protocol makes no exception for it,
which keeps the payment split and the signed step counts identical either way.

Failures are reported rather than swallowed. ``failJob`` is terminal — it does
not put the job back in the queue — so it records why nothing was produced and
lets the requester decide whether to repost. A worker that has claimed a half of
a split job therefore does not abandon it silently: it waits for its partner up
to ``partner_timeout_secs`` and fails the job explicitly if none appears.
"""

from __future__ import annotations

import gc
import logging
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .commitments import WorkerKey, sign_handoff, sign_receipt
from .pipelines import (
    CatalogEntry,
    DenoiseResult,
    LoadedPipeline,
    decode_latents,
    denoise_split,
    denoise_whole,
    encode_latents,
    find_entry,
    load_pipeline,
)
from .rpc_bridge import RpcClient, RpcError
from .types import (
    MediaGenExpertHolding,
    MediaGenExpertRole,
    MediaGenHandoff,
    MediaGenJob,
    MediaGenKind,
    MediaGenParams,
    MediaGenReceipt,
    MediaGenStatus,
    MediaGenWorkerCapability,
    Signature,
)

log = logging.getLogger("tenzro.media_gen.worker")


def now_millis() -> int:
    return int(time.time() * 1000)


@dataclass
class Claim:
    """A piece of a job this worker qualifies for.

    ``role`` is ``None`` on a whole job. Wrapping it means "no role" and "no
    work available" stay distinguishable.
    """

    role: MediaGenExpertRole | None


@dataclass
class WorkerConfig:
    """What this worker is and what it will accept.

    ``served_models`` are models it holds whole; ``expert_holdings`` are single
    halves of a split model. A model may appear in both only if the worker
    holds both transformers, in which case it qualifies for either half.
    """

    worker_did: str
    worker_address: bytes
    served_models: list[str] = field(default_factory=list)
    expert_holdings: list[tuple[str, MediaGenExpertRole]] = field(default_factory=list)
    max_resolution: int = 2048
    max_frames: int | None = None
    gpu_vram_gb: float = 24.0
    device: str = "cuda"
    dtype: str = "bfloat16"
    #: Transformer weight format. ``None`` means "same as ``dtype``", which is
    #: what an operator who has not thought about quantization wants. Setting
    #: it to one of the sub-8-bit tiers (``nf4`` / ``int4`` / ``int8``) trades
    #: some output fidelity for roughly a quarter to a half of the VRAM, which
    #: is what makes a large video model fit on a single card at all.
    precision: str | None = None
    cache_dir: str | None = None
    poll_interval_secs: float = 5.0
    partner_timeout_secs: float = 900.0

    def capability(self) -> MediaGenWorkerCapability:
        return MediaGenWorkerCapability(
            worker_did=self.worker_did,
            worker_address=self.worker_address,
            supported_models=list(self.served_models),
            expert_holdings=[
                MediaGenExpertHolding(model_id=m, role=r) for m, r in self.expert_holdings
            ],
            max_resolution=self.max_resolution,
            max_frames=self.max_frames,
            gpu_vram_gb=self.gpu_vram_gb,
            registered_at=now_millis(),
        )

    def roles_for(self, model_id: str) -> list[MediaGenExpertRole]:
        if model_id in self.served_models:
            return [MediaGenExpertRole.HIGH_NOISE, MediaGenExpertRole.LOW_NOISE]
        return [r for m, r in self.expert_holdings if m == model_id]

    def serves(self, model_id: str) -> bool:
        return bool(self.roles_for(model_id))


class MediaGenWorker:
    """Renders media-gen jobs for one node.

    Pipelines are cached by ``(model_id, kind, role)`` because loading a
    transformer expert is the single most expensive thing the worker does; a
    worker that keeps claiming the same half of the same model pays that cost
    once.
    """

    def __init__(self, config: WorkerConfig, client: RpcClient, key: WorkerKey):
        self.config = config
        self.client = client
        self.key = key
        self._catalog: list[dict[str, Any]] = []
        # OrderedDict, not dict: eviction is LRU and needs move_to_end.
        # Oldest-first iteration order is what `_evict_until_fits` relies on.
        self._pipelines: OrderedDict[tuple[str, str, str | None], LoadedPipeline] = OrderedDict()

    # ── enrollment and discovery ──────────────────────────────────────

    def enroll(self) -> None:
        """Announce this worker to the node and cache the catalog.

        The catalog is what decides whether a model splits — the worker reads
        the expert pair from it rather than inferring anything from the job, so
        both halves agree on the boundary without coordinating.
        """
        self._catalog = self.client.list_catalog()
        known = {entry.get("id") for entry in self._catalog}
        for model_id in self.config.served_models + [m for m, _ in self.config.expert_holdings]:
            if model_id not in known:
                raise ValueError(f"model {model_id!r} is not in the node's catalog")
        self.client.enroll_worker(self.config.capability())
        log.info(
            "enrolled %s: %d whole model(s), %d expert holding(s)",
            self.config.worker_did,
            len(self.config.served_models),
            len(self.config.expert_holdings),
        )

    def entry_for(self, model_id: str) -> CatalogEntry:
        return find_entry(self._catalog, model_id)

    def claimable(self, job: MediaGenJob) -> Claim | None:
        """Which piece of ``job``, if any, this worker can take.

        A split job in ``claimed`` state still has work available when only one
        of its two halves is held, so both states are candidates.
        """
        spec = job.task_spec
        if job.status not in (MediaGenStatus.PENDING, MediaGenStatus.CLAIMED):
            return None
        if not self.config.serves(spec.model_id):
            return None
        if not self.config.capability().fits_output(spec):
            return None

        if not job.is_split:
            return Claim(role=None) if job.status is MediaGenStatus.PENDING else None

        mine = set(self.config.roles_for(spec.model_id))
        for role in job.unclaimed_roles():
            if role in mine:
                return Claim(role=role)
        return None

    # ── the loop ──────────────────────────────────────────────────────

    def run_once(self) -> bool:
        """Claim and render at most one job. ``True`` if work was done."""
        candidates = self.client.list_jobs(MediaGenStatus.PENDING) + self.client.list_jobs(
            MediaGenStatus.CLAIMED
        )
        for job in candidates:
            claim = self.claimable(job)
            if claim is None:
                continue
            try:
                self.execute(job.job_id, claim.role)
            except Exception as exc:
                log.exception("job %s failed", job.job_id)
                self._report_failure(job.job_id, str(exc))
            return True
        return False

    def run(self) -> None:
        """Poll until interrupted."""
        self.enroll()
        while True:
            try:
                if not self.run_once():
                    time.sleep(self.config.poll_interval_secs)
            except KeyboardInterrupt:
                log.info("stopping")
                return
            except RpcError as exc:
                log.warning("node rejected a call: %s", exc)
                time.sleep(self.config.poll_interval_secs)

    def _report_failure(self, job_id: str, reason: str) -> None:
        try:
            self.client.fail_job(job_id, self.config.worker_did, reason)
        except RpcError as exc:
            log.warning("could not report failure on %s: %s", job_id, exc)

    # ── one job, one role ─────────────────────────────────────────────

    def execute(self, job_id: str, role: MediaGenExpertRole | None) -> None:
        job = self.client.claim_job(job_id, self.config.worker_did, role)
        entry = self.entry_for(job.task_spec.model_id)
        spec = job.task_spec

        if job.is_split and role is None:
            raise ValueError(f"job {job_id} splits its schedule; claimed without a role")

        # A split job cannot start until both halves are held: the low-noise
        # expert has nothing to resume from until the high-noise one has run,
        # and the node refuses the handoff until the schedule is fully owned.
        if job.is_split and not job.is_fully_assigned():
            job = self._await(job_id, "its other expert", lambda j: j.is_fully_assigned())

        if role is MediaGenExpertRole.LOW_NOISE:
            job = self._await(job_id, "the handoff", lambda j: j.handoff is not None)

        self.client.mark_running(job_id, self.config.worker_did)
        started = now_millis()

        input_image = self.client.fetch_input(job_id) if spec.kind.requires_input_image else None

        loaded = self._pipeline(entry, spec.kind, role)
        if role is None:
            result = denoise_whole(loaded, spec.params, input_image)
        else:
            inbound = None
            if role is MediaGenExpertRole.LOW_NOISE:
                latent_bytes = self.client.fetch_latent(job_id)
                inbound, _ = decode_latents(latent_bytes)
            result = denoise_split(
                loaded,
                spec.params,
                input_image=input_image,
                inbound_latents=inbound,
            )

        if role is MediaGenExpertRole.HIGH_NOISE:
            self._hand_off(job_id, result, spec.params)
            return

        assert result.media is not None
        self._seal(job, result, started)

    def _pipeline(
        self,
        entry: CatalogEntry,
        kind: MediaGenKind,
        role: MediaGenExpertRole | None,
    ) -> LoadedPipeline:
        # Precision is part of the key. The same model at nf4 and at bf16 are
        # different objects with different VRAM costs and different outputs;
        # keying on the model alone would hand a caller who asked for bf16
        # whichever precision happened to be loaded first.
        cache_key = (
            entry.id,
            kind.value,
            role.value if role else None,
            self.config.precision or self.config.dtype,
        )
        cached = self._pipelines.get(cache_key)
        if cached is not None:
            # Refresh recency: this is an LRU, and the whole point is that the
            # pipeline a worker keeps claiming is the one it keeps.
            self._pipelines.move_to_end(cache_key)
            return cached

        self._evict_until_fits(entry)
        loaded = load_pipeline(
            entry,
            kind,
            role,
            device=self.config.device,
            dtype=self.config.dtype,
            precision=self.config.precision,
            cache_dir=self.config.cache_dir,
        )
        self._pipelines[cache_key] = loaded
        return loaded

    def _entry_vram_gb(self, entry: CatalogEntry) -> float:
        """What holding this pipeline costs, in GB.

        The catalog's ``min_vram_gb`` is the model author's own floor for
        running it, which is the closest thing to a truthful number available
        without loading it first. Falls back to the on-disk size when absent.
        """
        declared = getattr(entry, "min_vram_gb", None)
        if declared:
            return float(declared)
        size_bytes = getattr(entry, "size_bytes", 0) or 0
        return float(size_bytes) / 1e9

    def _resident_vram_gb(self) -> float:
        return sum(self._entry_vram_gb(p.entry) for p in self._pipelines.values())

    def _evict_until_fits(self, entry: CatalogEntry) -> None:
        """Free least-recently-used pipelines until ``entry`` fits.

        Without this the cache is unbounded: a worker that renders one image
        job with a 33 GB pipeline and then a video job with a 34 GB one holds
        both, and 67 GB does not fit in a budget sized for one at a time. The
        symptom is an OOM kill on the second job, which looks like a video bug
        rather than a cache bug.

        Eviction is best-effort by design — a worker that cannot free enough
        still attempts the load, because the catalog's VRAM figures are
        estimates and refusing on an estimate would make a worker decline jobs
        it could actually have rendered. The real ceiling is enforced by the
        node's memory budget on the Rust side.
        """
        budget = float(self.config.gpu_vram_gb)
        needed = self._entry_vram_gb(entry)

        while self._pipelines and (self._resident_vram_gb() + needed) > budget:
            victim_key, victim = next(iter(self._pipelines.items()))
            del self._pipelines[victim_key]
            self._release(victim)
            log.info(
                "evicted pipeline %s to make room for %s (%.1f GB needed, %.1f GB budget)",
                victim_key[0],
                entry.id,
                needed,
                budget,
            )

    @staticmethod
    def _release(loaded: LoadedPipeline) -> None:
        """Actually give the memory back.

        Dropping the dict entry only drops a Python reference; the weights stay
        in VRAM until the allocator's cache is emptied too. Skipping the
        ``empty_cache`` leaves an eviction that frees nothing, which is worse
        than no eviction because it also loses the pipeline.
        """
        try:
            pipe = loaded.pipe
            if hasattr(pipe, "to"):
                try:
                    pipe.to("cpu")
                except Exception:  # noqa: BLE001 - best effort, never fatal
                    pass
            del pipe
            del loaded
            gc.collect()
            try:
                import torch

                if torch.cuda.is_available():
                    torch.cuda.empty_cache()
            except ImportError:
                pass
        except Exception as exc:  # noqa: BLE001 - eviction must never kill the worker
            log.warning("pipeline release did not complete cleanly: %s", exc)

    def _await(
        self,
        job_id: str,
        what: str,
        ready: Callable[[MediaGenJob], bool],
    ) -> MediaGenJob:
        """Poll the job until ``ready``, or give up and let the caller fail it.

        Bounded because the other half of a split job is a different machine
        that may never arrive; an unbounded wait would pin this worker's GPU on
        a job that cannot complete.
        """
        deadline = time.monotonic() + self.config.partner_timeout_secs
        while True:
            job = self.client.get_job(job_id)
            if job is None:
                raise ValueError(f"job {job_id} disappeared while waiting for {what}")
            if job.status.is_terminal:
                raise ValueError(f"job {job_id} ended as {job.status.value}")
            if ready(job):
                return job
            if time.monotonic() >= deadline:
                raise TimeoutError(f"job {job_id}: {what} did not arrive in time")
            log.info("job %s: waiting for %s", job_id, what)
            time.sleep(self.config.poll_interval_secs)

    def _hand_off(self, job_id: str, result: DenoiseResult, params: MediaGenParams) -> None:
        """Publish the intermediate latent and sign the commitment to it."""
        payload = encode_latents(result, params)
        published = self.client.publish_output(payload)
        handoff = MediaGenHandoff(
            job_id=job_id,
            from_worker_did=self.config.worker_did,
            from_worker_address=self.config.worker_address,
            latent_hash=published.output_hash,
            latent_bytes=published.byte_len,
            steps_completed=result.steps_completed,
            handed_off_at=now_millis(),
            worker_signature=Signature.empty(),
        )
        handoff.worker_signature = sign_handoff(handoff, self.key)
        self.client.record_handoff(handoff)
        log.info(
            "job %s: handed over after %d/%d steps (%d bytes)",
            job_id,
            result.steps_completed,
            result.total_steps,
            published.byte_len,
        )

    def _seal(self, job: MediaGenJob, result: DenoiseResult, started_at: int) -> None:
        """Publish the render and submit the receipt that completes the job."""
        assert result.media is not None
        published = self.client.publish_output(result.media)
        quote = self.client.quote(job.task_spec.kind, job.task_spec.params)
        receipt = MediaGenReceipt(
            job_id=job.job_id,
            task_spec=job.task_spec,
            worker_did=self.config.worker_did,
            worker_address=self.config.worker_address,
            output_hash=published.output_hash,
            output_mime=result.mime,
            output_bytes=published.byte_len,
            seed_used=result.seed_used,
            generation_time_ms=now_millis() - started_at,
            price_paid=quote.quote,
            completed_at=now_millis(),
            worker_signature=Signature.empty(),
        )
        receipt.worker_signature = sign_receipt(receipt, self.key)
        sealed = self.client.submit_receipt(receipt)
        log.info(
            "job %s: completed, %d bytes of %s",
            job.job_id,
            published.byte_len,
            result.mime,
        )
        if sealed.settlement is not None:
            mine = sealed.settlement.payout_for(self.config.worker_did)
            log.info(
                "job %s: paid %s attoTNZO of %d at %d bps",
                job.job_id,
                mine.amount if mine is not None else 0,
                sealed.settlement.price_paid,
                mine.share_bps if mine is not None else 0,
            )
