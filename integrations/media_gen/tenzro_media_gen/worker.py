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
import os
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
    backend_adapter,
    backend_is_available,
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

# JSON-RPC code the node returns when a receipt is well-formed and accepted but
# the payer cannot cover the payout. Distinct from a rejected receipt: the job
# is already complete and its output published, so this is an unpaid render,
# not a failed one.
SETTLEMENT_ERROR_CODE = -32023


def now_millis() -> int:
    return int(time.time() * 1000)


@dataclass
class Claim:
    """A piece of a job this worker qualifies for.

    ``role`` is ``None`` on a whole job. Wrapping it means "no role" and "no
    work available" stay distinguishable.
    """

    role: MediaGenExpertRole | None


#: Fraction of a shared CPU/GPU pool a worker may budget for pipelines.
#:
#: Mirrors the `total_ram_gb * 0.7` rule the Rust side already applies in
#: `tenzro-cli/src/commands/join.rs` when sizing a model memory budget. The
#: remaining 30% is not slack — it is the node process, the OS, and the
#: activation working set of whichever pipeline is mid-render.
SAFE_SHARED_POOL_FRACTION = 0.7


def _system_ram_gb() -> float:
    """Total system RAM in GB (10^9), or 0.0 when it cannot be determined."""
    try:
        return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") / 1e9
    except (OSError, ValueError, AttributeError):
        return 0.0


def _accelerator_pool_gb() -> float:
    """Accelerator memory in GB (10^9), or 0.0 when there is no CUDA device.

    Deliberately tolerant: a worker must not fail to start because a memory
    probe raised. An unknown pool degrades to the system-RAM rule below, which
    is the conservative direction.
    """
    try:
        import torch

        if not torch.cuda.is_available():
            return 0.0
        return float(torch.cuda.get_device_properties(0).total_memory) / 1e9
    except Exception:  # noqa: BLE001 - probing must never be fatal
        return 0.0


def shared_memory_pool_gb(vram_gb: float, ram_gb: float) -> float | None:
    """Python twin of ``tenzro_types::hardware::shared_memory_pool``.

    Returns the effective pool size when the accelerator shares system memory,
    or ``None`` when it has memory of its own. Kept numerically identical to the
    Rust rule (the ``vram * 8 >= ram * 7`` comparison) so a node and its
    media-gen worker cannot disagree about what kind of machine they are on.
    """
    if ram_gb <= 0:
        return None
    # Shape 1: the tool reports the shared pool, so the figures coincide.
    if vram_gb > 0 and vram_gb * 8 >= ram_gb * 7:
        return vram_gb
    # Shape 2: the tool reports nothing, because there is nothing separate.
    if vram_gb <= 0:
        return ram_gb
    return None


def resolve_vram_budget_gb(requested_gb: float) -> float:
    """Clamp an operator-supplied ``--gpu-vram-gb`` to what the machine has.

    ``--gpu-vram-gb`` is the only thing bounding the pipeline cache: eviction in
    :meth:`MediaGenWorker._evict_until_fits` runs while
    ``resident + needed > budget``, so a budget larger than the machine disables
    the cache bound entirely and every pipeline ever loaded stays resident.

    **On a discrete card that is survivable and on a coherent-memory part it is
    not.** Overshooting discrete VRAM raises a CUDA OOM, which fails one job and
    leaves the process alive. On Grace-Blackwell (GB10), Apple Silicon and AMD
    APUs the GPU pool *is* system memory, so the same overshoot is served by the
    kernel until the machine runs out and the global OOM killer picks victims
    across every cgroup — the node, and anything else resident. This is not
    hypothetical: on 2026-08-03 a worker configured with ``--gpu-vram-gb 100`` on
    a 121 GB GB10 held a 14 GB image pipeline and a 21 GB video pipeline
    simultaneously, because 35 never exceeded 100.

    Returns the smaller of the requested budget and the safe ceiling, logging a
    warning when it clamps. Clamping rather than refusing is deliberate — the
    catalog's VRAM figures are estimates, and a worker that refused to start on
    an estimate would be worse than one that ran with a smaller cache.
    """
    ram_gb = _system_ram_gb()
    vram_gb = _accelerator_pool_gb()
    pool_gb = shared_memory_pool_gb(vram_gb, ram_gb)

    if pool_gb is not None:
        ceiling = pool_gb * SAFE_SHARED_POOL_FRACTION
        kind = "shared CPU/GPU pool"
    elif vram_gb > 0:
        ceiling = vram_gb
        kind = "discrete VRAM"
    else:
        # Nothing could be probed. Leave the operator's figure alone rather than
        # inventing a ceiling from a measurement that was never taken.
        return requested_gb

    if requested_gb > ceiling:
        log.warning(
            "--gpu-vram-gb %.1f exceeds this machine's %s (%.1f GB usable of "
            "%.1f GB); clamping to %.1f GB. An unclamped budget disables the "
            "pipeline cache bound, and on a shared pool that ends in a global "
            "OOM rather than a recoverable CUDA OOM.",
            requested_gb,
            kind,
            ceiling,
            pool_gb if pool_gb is not None else vram_gb,
            ceiling,
        )
        return ceiling
    return requested_gb


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

    Pipelines are cached by ``(model_id, kind, role, precision)`` because
    loading a transformer expert is the single most expensive thing the worker
    does; a worker that keeps claiming the same half of the same model pays that
    cost once. The cache is bounded by ``config.gpu_vram_gb``, which
    :func:`resolve_vram_budget_gb` clamps to what the machine actually has.
    """

    def __init__(self, config: WorkerConfig, client: RpcClient, key: WorkerKey):
        self.config = config
        # Clamp before anything reads the budget. `capability()` advertises
        # `gpu_vram_gb` to the node, so clamping here also stops the worker
        # announcing a capacity the machine cannot honour — a worker that
        # claims 100 GB gets routed jobs sized for 100 GB.
        self.config.gpu_vram_gb = resolve_vram_budget_gb(config.gpu_vram_gb)
        self.client = client
        self.key = key
        self._catalog: list[dict[str, Any]] = []
        # OrderedDict, not dict: eviction is LRU and needs move_to_end.
        # Oldest-first iteration order is what `_evict_until_fits` relies on.
        #
        # Key is (model_id, kind, role, precision) — precision joined the key
        # when the nf4/int4/int8 tiers landed, because keying on the model alone
        # would hand a caller who asked for bf16 whichever precision happened to
        # be loaded first. The annotation is spelled out in full so it stays in
        # step with `_load` rather than drifting behind it again.
        self._pipelines: OrderedDict[tuple[str, str, str | None, str], LoadedPipeline] = (
            OrderedDict()
        )
        # One warning per process, not one per job, when the worker has no
        # token to write the ledger with.
        self._warned_no_admin_token = False

    # ── enrollment and discovery ──────────────────────────────────────

    def enroll(self) -> None:
        """Announce this worker to the node and cache the catalog.

        The catalog is what decides whether a model splits — the worker reads
        the expert pair from it rather than inferring anything from the job, so
        both halves agree on the boundary without coordinating.
        """
        self._catalog = self.client.list_catalog()
        known = {entry.get("id") for entry in self._catalog}
        by_id = {entry.get("id"): entry for entry in self._catalog}
        for model_id in self.config.served_models + [m for m, _ in self.config.expert_holdings]:
            if model_id not in known:
                raise ValueError(f"model {model_id!r} is not in the node's catalog")
            # Refuse at enrolment, not at claim time. A worker that advertises
            # a backend it cannot import looks healthy, wins the job, and then
            # fails during render — the requester waited for nothing and the
            # job has to be re-posted. Checking here means the model is simply
            # never offered by this worker.
            backend = str(by_id[model_id].get("backend", "diffusers"))
            if not backend_is_available(backend):
                adapter = backend_adapter(backend)
                pkg = adapter.required_package if adapter is not None else backend
                raise ValueError(
                    f"model {model_id!r} needs the {backend!r} backend, which this worker "
                    f"cannot load: install {pkg!r} (and its peers) or drop the model from "
                    "--model"
                )
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
        self._admit_with_node(cache_key, entry)
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

    @staticmethod
    def _commitment_key(cache_key: tuple[Any, ...]) -> str:
        """Ledger key for one cached pipeline.

        Carries the whole cache key, not just the model id: the same model at
        two precisions is two resident objects with two costs, and collapsing
        them onto one ledger entry would under-count the pool by exactly the
        amount that makes the difference.
        """
        return "media-gen:" + ":".join(str(part) for part in cache_key)

    def _admit_with_node(self, cache_key: tuple[Any, ...], entry: CatalogEntry) -> None:
        """Record this pipeline against the node's pool before loading it.

        The local LRU in :meth:`_evict_until_fits` bounds this worker against
        its own budget. It cannot see the language model the node is serving
        in another process, so on its own it will happily load a pipeline into
        memory the node has already promised elsewhere. The node's ledger is
        the only place both are visible, so admission has to happen there.

        Eviction and retry live here rather than in the node: the node knows
        the pool is full, but only the worker knows which pipeline it is
        willing to give up.
        """
        if not self.client.admin_token:
            # Fail open, loudly. A worker without the operator's token cannot
            # write to the ledger, and refusing every job would be a worse
            # failure than the unaccounted load this replaces.
            if not self._warned_no_admin_token:
                log.warning(
                    "TENZRO_ADMIN_TOKEN unset: pipeline memory will not be recorded "
                    "against the node's budget, so the node cannot account for this "
                    "worker's %.1f GB when admitting its own models",
                    self._entry_vram_gb(entry),
                )
                self._warned_no_admin_token = True
            return

        key = self._commitment_key(cache_key)
        needed_bytes = int(self._entry_vram_gb(entry) * 1e9)

        while True:
            try:
                # `min_vram_gb` is the author's floor for *running* the model,
                # so it already covers activations; applying the node's load
                # headroom on top would double-count it.
                self.client.memory_admit(key, "on-demand", needed_bytes, apply_headroom=False)
                return
            except RpcError as exc:
                if not self._pipelines:
                    raise RuntimeError(
                        f"node refused {self._entry_vram_gb(entry):.1f} GB for "
                        f"{entry.id} and this worker holds nothing to evict: {exc}"
                    ) from exc
                victim_key, victim = self._pipelines.popitem(last=False)
                self._release(victim)
                self.client.memory_release(self._commitment_key(victim_key))
                log.info(
                    "evicted pipeline %s after the node refused %s: %s",
                    victim_key[0],
                    entry.id,
                    exc,
                )

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
        node's memory budget on the Rust side, which `_admit_with_node` calls
        immediately after this returns.
        """
        budget = float(self.config.gpu_vram_gb)
        needed = self._entry_vram_gb(entry)

        while self._pipelines and (self._resident_vram_gb() + needed) > budget:
            victim_key, victim = next(iter(self._pipelines.items()))
            del self._pipelines[victim_key]
            self._release(victim)
            # Give the bytes back on the node's ledger too, or the pool leaks
            # a commitment for every eviction and the tier fills with claims
            # nothing holds.
            if self.client.admin_token:
                self.client.memory_release(self._commitment_key(victim_key))
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
                except Exception:
                    # Not fatal — the pipeline is being discarded either way —
                    # but it means the VRAM is not coming back on this path,
                    # so the next OOM wants this line in the journal.
                    log.debug("could not move %s off the GPU", type(pipe).__name__, exc_info=True)
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
        try:
            sealed = self.client.submit_receipt(receipt)
        except RpcError as exc:
            if exc.code != SETTLEMENT_ERROR_CODE:
                raise
            # The render is done and the output is published, so the job is
            # already terminal on the node — reporting this as a job failure
            # asks for `completed -> failed`, which the state machine rightly
            # refuses, and buries the real cause under that refusal. The node
            # has already recorded the unpaid settlement; the operator's
            # remedy is funding the payer, not re-running the render.
            log.error(
                "job %s: rendered and published, but unpaid — %s. The output "
                "stands; settle by funding the requester.",
                job.job_id,
                exc.message,
            )
            return
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
