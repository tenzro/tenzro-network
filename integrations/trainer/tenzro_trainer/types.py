"""Python mirrors of the Rust ``tenzro_types::training`` enums and structs.

Every type here serializes to the *exact* JSON shape the Rust syncer expects.
Wire conventions worth pinning down:

* ``Hash`` and ``Address`` are tuple structs over ``[u8; 32]`` — they serialize
  as a bare 32-element JSON array of integers (0–255), *not* as a hex string.
* ``Timestamp(pub i64)`` is a newtype over ``i64`` — it serializes as a bare
  integer (Unix milliseconds), not as ``{"0": ...}``.
* ``Signature`` is ``{"bytes": [...], "public_key": [...]}`` where both fields
  are byte arrays of integers.
* Enum variants serialize using serde's default rules — unit variants as the
  string name (e.g. ``"Mean"``, ``"Open"``, ``"Timeseries"``); variants with
  fields as ``{"VariantName": {...}}`` (we only emit ``Mean`` in Phase 1).

These dataclasses provide ``to_json()`` / ``from_json()`` helpers that round-trip
through ``serde_json`` on the Rust side — the integration tests in
``tests/test_types_roundtrip.py`` lock the wire format.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

# ---------------------------------------------------------------------------
# Primitive helpers
# ---------------------------------------------------------------------------


def hash_to_json(h: bytes) -> list[int]:
    """Encode a 32-byte hash as a 32-int JSON array (matches Rust ``Hash``)."""
    if len(h) != 32:
        raise ValueError(f"hash must be 32 bytes, got {len(h)}")
    return list(h)


def hash_from_json(arr: list[int]) -> bytes:
    """Decode a 32-int JSON array into 32 bytes."""
    if len(arr) != 32:
        raise ValueError(f"hash array must be 32 elements, got {len(arr)}")
    return bytes(arr)


def address_to_json(a: bytes) -> list[int]:
    """Encode a 32-byte address as a 32-int JSON array (matches Rust ``Address``)."""
    if len(a) != 32:
        raise ValueError(f"address must be 32 bytes, got {len(a)}")
    return list(a)


def address_from_json(arr: list[int]) -> bytes:
    if len(arr) != 32:
        raise ValueError(f"address array must be 32 elements, got {len(arr)}")
    return bytes(arr)


def hash_hex(h: bytes) -> str:
    """Hex-encode a hash for ``tenzro_training_finalizeRound`` ``post_step_hashes``."""
    if len(h) != 32:
        raise ValueError(f"hash must be 32 bytes, got {len(h)}")
    return h.hex()


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class TrainingTier(str, Enum):
    OPEN = "Open"
    VERIFIED = "Verified"
    CONFIDENTIAL = "Confidential"


class TrainingModality(str, Enum):
    LANGUAGE = "Language"
    TIMESERIES = "Timeseries"
    VISION = "Vision"
    MULTIMODAL = "Multimodal"


class AggregationRule:
    """JSON wire-format helpers mirroring ``tenzro_types::training::AggregationRule``.

    Serde encodes unit variants as bare strings (``"Mean"``,
    ``"CoordinateMedian"``) and variants-with-fields as a single-key object
    (``{"TrimmedMean": {"alpha_bps": 1000}}``).

    Tier policy (enforced by the Rust runtime at task registration):
    ``Mean`` and ``LoraAlternating`` admit at all tiers; ``TrimmedMean`` /
    ``CoordinateMedian`` / ``Krum`` require ``TrainingTier.VERIFIED`` or higher.
    """

    @staticmethod
    def mean() -> str:
        return "Mean"

    @staticmethod
    def lora_alternating() -> str:
        return "LoraAlternating"

    @staticmethod
    def trimmed_mean(alpha_bps: int) -> dict[str, Any]:
        return {"TrimmedMean": {"alpha_bps": alpha_bps}}

    @staticmethod
    def coordinate_median() -> str:
        return "CoordinateMedian"

    @staticmethod
    def krum(f: int) -> dict[str, Any]:
        return {"Krum": {"f": f}}


# ---------------------------------------------------------------------------
# Gradient quantization
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GradientQuantization:
    """Mirror of ``tenzro_types::training::GradientQuantization``.

    Serde encodes the unit variant as the bare string ``"None"`` and the
    struct variants as single-key objects — ``{"Int8": {"block_size": 64}}``
    / ``{"Int4": {"block_size": 64}}``. The byte-level codec lives in
    :mod:`tenzro_trainer.quantization`.
    """

    kind: str  # "None" | "Int8" | "Int4"
    block_size: int = 0

    @classmethod
    def none(cls) -> GradientQuantization:
        return cls(kind="None")

    @classmethod
    def int8(cls, block_size: int) -> GradientQuantization:
        return cls(kind="Int8", block_size=int(block_size))

    @classmethod
    def int4(cls, block_size: int) -> GradientQuantization:
        return cls(kind="Int4", block_size=int(block_size))

    @property
    def is_none(self) -> bool:
        return self.kind == "None"

    def label(self) -> str:
        """Rust ``Display`` string: ``none`` / ``int8/N`` / ``int4/N``."""
        if self.kind == "None":
            return "none"
        if self.kind == "Int8":
            return f"int8/{self.block_size}"
        return f"int4/{self.block_size}"

    def to_json(self) -> str | dict[str, Any]:
        if self.kind == "None":
            return "None"
        return {self.kind: {"block_size": self.block_size}}

    @classmethod
    def from_json(cls, j: str | dict[str, Any]) -> GradientQuantization:
        if j == "None":
            return cls.none()
        if isinstance(j, dict):
            if "Int8" in j:
                return cls.int8(int(j["Int8"]["block_size"]))
            if "Int4" in j:
                return cls.int4(int(j["Int4"]["block_size"]))
        raise ValueError(f"unrecognized GradientQuantization wire value: {j!r}")


# ---------------------------------------------------------------------------
# Payload kind (chunked top-k) + outer-update mode
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SparseTopKParams:
    """Mirror of ``tenzro_types::training::SparseTopKParams``.

    Chunked top-k sparsification: the flattened fragment is split into
    ``chunk_size``-coordinate chunks and the ``min(k, chunk_len)`` largest-
    magnitude coordinates are kept per chunk. Serde serializes this as
    ``{"chunk_size": N, "k": M}``. The byte codec lives in
    :mod:`tenzro_trainer.gradient` and is byte-identical to the Rust
    ``sparse`` module.
    """

    chunk_size: int = 4096
    k: int = 64

    def chunk_count(self, length: int) -> int:
        cs = max(self.chunk_size, 1)
        return (length + cs - 1) // cs

    def kept_for_chunk(self, chunk_len: int) -> int:
        return min(max(self.k, 1), chunk_len)

    def label(self) -> str:
        """Rust ``Display`` string: ``topk/<chunk_size>/<k>``."""
        return f"topk/{self.chunk_size}/{self.k}"

    def to_json(self) -> dict[str, Any]:
        return {"chunk_size": self.chunk_size, "k": self.k}

    @classmethod
    def from_json(cls, j: dict[str, Any]) -> SparseTopKParams:
        return cls(chunk_size=int(j["chunk_size"]), k=int(j["k"]))


@dataclass(frozen=True)
class PayloadKind:
    """Mirror of ``tenzro_types::training::PayloadKind``.

    Serde encodes the ``Dense`` unit variant as the bare string ``"Dense"``
    and the ``SparseTopK`` variant as ``{"SparseTopK": {"chunk_size": N,
    "k": M}}``. The syncer dispatches decode + aggregation on this
    discriminant; a submission whose declared kind disagrees with the task
    spec is rejected (slashable, same class as a quantization mismatch).
    """

    kind: str = "Dense"  # "Dense" | "SparseTopK"
    sparse: SparseTopKParams | None = None

    @classmethod
    def dense(cls) -> PayloadKind:
        return cls(kind="Dense", sparse=None)

    @classmethod
    def sparse_topk(cls, params: SparseTopKParams) -> PayloadKind:
        return cls(kind="SparseTopK", sparse=params)

    @property
    def is_dense(self) -> bool:
        return self.kind == "Dense"

    def label(self) -> str:
        """Rust ``Display`` string: ``dense`` / ``sparse-topk/<cs>/<k>``."""
        if self.kind == "Dense" or self.sparse is None:
            return "dense"
        return f"sparse-{self.sparse.label()}"

    def to_json(self) -> str | dict[str, Any]:
        if self.kind == "Dense" or self.sparse is None:
            return "Dense"
        return {"SparseTopK": self.sparse.to_json()}

    @classmethod
    def from_json(cls, j: str | dict[str, Any]) -> PayloadKind:
        if j == "Dense":
            return cls.dense()
        if isinstance(j, dict) and "SparseTopK" in j:
            return cls.sparse_topk(SparseTopKParams.from_json(j["SparseTopK"]))
        raise ValueError(f"unrecognized PayloadKind wire value: {j!r}")


@dataclass(frozen=True)
class OuterUpdateMode:
    """Mirror of ``tenzro_types::training::OuterUpdateMode``.

    ``Nesterov`` is the Nesterov-SGD outer optimizer (syncer holds momentum);
    ``SparseEf`` is the sparse error-feedback update where the momentum-equivalent
    state is the trainer-local error-feedback accumulator and the syncer holds no
    momentum. Serde encodes each as a single-key object:
    ``{"Nesterov": {"lr": 0.7, "momentum": 0.9}}`` /
    ``{"SparseEf": {"lr": 0.7}}``.
    """

    kind: str = "Nesterov"  # "Nesterov" | "SparseEf"
    lr: float = 0.7
    momentum: float = 0.9

    @classmethod
    def nesterov(cls, lr: float = 0.7, momentum: float = 0.9) -> OuterUpdateMode:
        return cls(kind="Nesterov", lr=float(lr), momentum=float(momentum))

    @classmethod
    def sparse_ef(cls, lr: float = 0.7) -> OuterUpdateMode:
        return cls(kind="SparseEf", lr=float(lr), momentum=0.0)

    @property
    def carries_momentum(self) -> bool:
        return self.kind == "Nesterov"

    def to_json(self) -> dict[str, Any]:
        if self.kind == "SparseEf":
            return {"SparseEf": {"lr": self.lr}}
        return {"Nesterov": {"lr": self.lr, "momentum": self.momentum}}

    @classmethod
    def from_json(cls, j: dict[str, Any]) -> OuterUpdateMode:
        if isinstance(j, dict):
            if "SparseEf" in j:
                return cls.sparse_ef(float(j["SparseEf"]["lr"]))
            if "Nesterov" in j:
                n = j["Nesterov"]
                return cls.nesterov(float(n["lr"]), float(n["momentum"]))
        raise ValueError(f"unrecognized OuterUpdateMode wire value: {j!r}")


# ---------------------------------------------------------------------------
# Sync strategy (streaming shard rotation)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SyncStrategy:
    """Mirror of ``tenzro_types::training::SyncStrategy``.

    ``num_shards is None`` means the ``Full`` unit variant (every fragment
    syncs every round). Otherwise this is the streaming shard-rotation
    variant: fragments are partitioned into ``num_shards`` contiguous shards
    and only shard ``round % num_shards`` syncs each round.
    """

    num_shards: int | None = None

    @classmethod
    def full(cls) -> SyncStrategy:
        return cls(num_shards=None)

    @classmethod
    def streaming(cls, num_shards: int) -> SyncStrategy:
        return cls(num_shards=int(num_shards))

    def shard_count(self) -> int:
        if self.num_shards is None:
            return 1
        return max(self.num_shards, 1)

    def active_shard(self, round_index: int) -> int:
        if self.num_shards is None:
            return 0
        return round_index % self.shard_count()

    def shard_of_fragment(self, fragment: int, fragment_count: int) -> int:
        """Contiguous partition — matches ``SyncStrategy::shard_of_fragment``."""
        return (fragment * self.shard_count()) // max(fragment_count, 1)

    def fragment_active(
        self, fragment: int, fragment_count: int, round_index: int
    ) -> bool:
        return self.shard_of_fragment(fragment, fragment_count) == self.active_shard(
            round_index
        )

    def to_json(self) -> str | dict[str, Any]:
        if self.num_shards is None:
            return "Full"
        return {"Streaming": {"num_shards": self.num_shards}}

    @classmethod
    def from_json(cls, j: str | dict[str, Any]) -> SyncStrategy:
        if j == "Full":
            return cls.full()
        if isinstance(j, dict) and "Streaming" in j:
            return cls.streaming(int(j["Streaming"]["num_shards"]))
        raise ValueError(f"unrecognized SyncStrategy wire value: {j!r}")


# ---------------------------------------------------------------------------
# Pipeline groups
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PipelineConfig:
    """Mirror of ``tenzro_types::training::PipelineConfig``.

    A group of ``num_stages`` trainers jointly holds one model replica; each
    stage owns the contiguous fragment slice
    ``stage = fragment * num_stages / fragment_count``.
    """

    num_stages: int

    def stage_of_fragment(self, fragment: int, fragment_count: int) -> int:
        return (fragment * max(self.num_stages, 1)) // max(fragment_count, 1)

    def to_json(self) -> dict[str, Any]:
        return {"num_stages": self.num_stages}

    @classmethod
    def from_json(cls, j: dict[str, Any]) -> PipelineConfig:
        return cls(num_stages=int(j["num_stages"]))


@dataclass(frozen=True)
class PipelineAssignment:
    """Mirror of ``tenzro_types::training::PipelineAssignment``.

    Bound at enrollment by the Rust runtime (enrollment order:
    ``group_id = idx // num_stages``, ``stage = idx % num_stages``) and
    surfaced on ``TrainingRun.pipeline_assignments`` keyed by trainer DID.
    """

    group_id: int
    stage: int

    def to_json(self) -> dict[str, Any]:
        return {"group_id": self.group_id, "stage": self.stage}

    @classmethod
    def from_json(cls, j: dict[str, Any]) -> PipelineAssignment:
        return cls(group_id=int(j["group_id"]), stage=int(j["stage"]))


# ---------------------------------------------------------------------------
# Architecture spec
# ---------------------------------------------------------------------------


@dataclass
class ArchitectureSpec:
    family: str
    param_count: int
    modality: TrainingModality
    fragment_count: int
    dtype: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {
            "family": self.family,
            "param_count": self.param_count,
            "modality": self.modality.value,
            "fragment_count": self.fragment_count,
            "dtype": self.dtype,
            "metadata": self.metadata,
        }

    @classmethod
    def from_json(cls, j: dict[str, Any]) -> ArchitectureSpec:
        return cls(
            family=j["family"],
            param_count=int(j["param_count"]),
            modality=TrainingModality(j["modality"]),
            fragment_count=int(j["fragment_count"]),
            dtype=j.get("dtype"),
            metadata=j.get("metadata") or {},
        )


# ---------------------------------------------------------------------------
# Training objective
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RlConfig:
    """Mirror of ``tenzro_types::training::RlConfig``.

    GRPO-style RL post-training hyperparameters. On the wire the objective is
    the Rust enum ``TrainingObjective``: the string ``"Supervised"`` or the
    single-key object ``{"RlPostTraining": {...}}``.
    """

    group_size: int
    kl_coeff: float
    clip_epsilon: float
    max_new_tokens: int
    temperature: float
    reward_ref: str

    def to_json(self) -> dict[str, Any]:
        return {
            "group_size": self.group_size,
            "kl_coeff": self.kl_coeff,
            "clip_epsilon": self.clip_epsilon,
            "max_new_tokens": self.max_new_tokens,
            "temperature": self.temperature,
            "reward_ref": self.reward_ref,
        }

    @classmethod
    def from_json(cls, j: dict[str, Any]) -> RlConfig:
        return cls(
            group_size=int(j["group_size"]),
            kl_coeff=float(j["kl_coeff"]),
            clip_epsilon=float(j["clip_epsilon"]),
            max_new_tokens=int(j["max_new_tokens"]),
            temperature=float(j["temperature"]),
            reward_ref=j["reward_ref"],
        )


def objective_to_json(rl: RlConfig | None) -> str | dict[str, Any]:
    """Serialize the objective to the Rust ``TrainingObjective`` wire form."""
    if rl is None:
        return "Supervised"
    return {"RlPostTraining": rl.to_json()}


def objective_from_json(j: str | dict[str, Any] | None) -> RlConfig | None:
    """Parse the Rust ``TrainingObjective`` wire form; absent key = Supervised."""
    if j is None or j == "Supervised":
        return None
    if isinstance(j, dict) and "RlPostTraining" in j:
        return RlConfig.from_json(j["RlPostTraining"])
    raise ValueError(f"unrecognized TrainingObjective wire value: {j!r}")


# ---------------------------------------------------------------------------
# Task spec
# ---------------------------------------------------------------------------


@dataclass
class TrainingTaskSpec:
    """Mirror of ``tenzro_types::training::TrainingTaskSpec``.

    Field order matches the Rust struct. ``aggregation`` carries the raw wire
    value produced by :class:`AggregationRule` (bare string for unit variants,
    single-key object for variants with fields).
    """

    task_id: str
    sponsor_did: str
    sponsor_address: bytes  # 32 bytes
    architecture: ArchitectureSpec
    tier: TrainingTier
    aggregation: str | dict[str, Any]
    clip_l2_norm: float | None
    sync_strategy: SyncStrategy
    quantization: GradientQuantization
    delayed_apply: bool
    pipeline: PipelineConfig | None
    trainer_count: int
    quorum: int
    inner_steps: int
    max_rounds: int
    grace_window_ms: int
    reward_pool: int
    dataset_ref: str
    dataset_hash: bytes  # 32 bytes
    min_throughput: int | None
    created_at: int  # Unix millis (matches Rust Timestamp)
    objective: RlConfig | None = None  # None = Supervised
    payload_kind: PayloadKind = field(default_factory=PayloadKind.dense)
    outer_update: OuterUpdateMode = field(default_factory=OuterUpdateMode.nesterov)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "sponsor_did": self.sponsor_did,
            "sponsor_address": address_to_json(self.sponsor_address),
            "architecture": self.architecture.to_json(),
            "tier": self.tier.value,
            "aggregation": self.aggregation,
            "clip_l2_norm": self.clip_l2_norm,
            "sync_strategy": self.sync_strategy.to_json(),
            "quantization": self.quantization.to_json(),
            "delayed_apply": self.delayed_apply,
            "pipeline": self.pipeline.to_json() if self.pipeline else None,
            "trainer_count": self.trainer_count,
            "quorum": self.quorum,
            "inner_steps": self.inner_steps,
            "max_rounds": self.max_rounds,
            "grace_window_ms": self.grace_window_ms,
            "reward_pool": self.reward_pool,
            "dataset_ref": self.dataset_ref,
            "dataset_hash": hash_to_json(self.dataset_hash),
            "min_throughput": self.min_throughput,
            "created_at": self.created_at,
            "objective": objective_to_json(self.objective),
            "payload_kind": self.payload_kind.to_json(),
            "outer_update": self.outer_update.to_json(),
            "metadata": self.metadata,
        }

    @classmethod
    def from_json(cls, j: dict[str, Any]) -> TrainingTaskSpec:
        return cls(
            task_id=j["task_id"],
            sponsor_did=j["sponsor_did"],
            sponsor_address=address_from_json(j["sponsor_address"]),
            architecture=ArchitectureSpec.from_json(j["architecture"]),
            tier=TrainingTier(j["tier"]),
            aggregation=j["aggregation"],
            clip_l2_norm=(
                float(j["clip_l2_norm"])
                if j.get("clip_l2_norm") is not None
                else None
            ),
            sync_strategy=SyncStrategy.from_json(j["sync_strategy"]),
            quantization=GradientQuantization.from_json(j["quantization"]),
            delayed_apply=bool(j["delayed_apply"]),
            pipeline=(
                PipelineConfig.from_json(j["pipeline"]) if j.get("pipeline") else None
            ),
            trainer_count=int(j["trainer_count"]),
            quorum=int(j["quorum"]),
            inner_steps=int(j["inner_steps"]),
            max_rounds=int(j["max_rounds"]),
            grace_window_ms=int(j["grace_window_ms"]),
            reward_pool=int(j["reward_pool"]),
            dataset_ref=j["dataset_ref"],
            dataset_hash=hash_from_json(j["dataset_hash"]),
            min_throughput=(
                int(j["min_throughput"]) if j.get("min_throughput") is not None else None
            ),
            created_at=int(j["created_at"]),
            objective=objective_from_json(j.get("objective")),
            payload_kind=(
                PayloadKind.from_json(j["payload_kind"])
                if j.get("payload_kind") is not None
                else PayloadKind.dense()
            ),
            outer_update=(
                OuterUpdateMode.from_json(j["outer_update"])
                if j.get("outer_update") is not None
                else OuterUpdateMode.nesterov()
            ),
            metadata=j.get("metadata") or {},
        )


# ---------------------------------------------------------------------------
# Outer gradient + attestation
# ---------------------------------------------------------------------------


@dataclass
class TrainingAttestation:
    vendor: str
    report_hex: str
    program_hash: bytes
    shard_hash: bytes

    def to_json(self) -> dict[str, Any]:
        return {
            "vendor": self.vendor,
            "report_hex": self.report_hex,
            "program_hash": hash_to_json(self.program_hash),
            "shard_hash": hash_to_json(self.shard_hash),
        }

    @classmethod
    def from_json(cls, j: dict[str, Any]) -> TrainingAttestation:
        return cls(
            vendor=j["vendor"],
            report_hex=j["report_hex"],
            program_hash=hash_from_json(j["program_hash"]),
            shard_hash=hash_from_json(j["shard_hash"]),
        )


# Domain tag prefixing the canonical activation-commitment serialization.
# Byte-identical to Rust ``ACTIVATION_COMMITMENT_DOMAIN_TAG``.
ACTIVATION_COMMITMENT_DOMAIN_TAG = b"tenzro/train/activation-commitment"

#: Default number of delta probes recorded per fragment.
DEFAULT_PROBE_K = 16

#: Upper bound on ``k`` accepted by verifiers.
MAX_PROBE_K = 64


@dataclass
class DeltaProbe:
    """One probe into the flattened fragment delta.

    ``index`` addresses the trainer-side canonical flattening
    (``flatten_fragment_values``: tensor keys sorted by name, each tensor cast
    to float32 and made C-contiguous, then concatenated); ``value`` is the
    float32 delta at that coordinate.
    """

    index: int
    value: float

    def to_json(self) -> dict[str, Any]:
        return {"index": self.index, "value": self.value}

    @classmethod
    def from_json(cls, j: dict[str, Any]) -> DeltaProbe:
        return cls(index=int(j["index"]), value=float(j["value"]))


@dataclass
class ActivationCommitment:
    """TOPLOC-class activation commitment for Open-tier training.

    Carries the per-inner-step loss trajectory (length must equal the task
    spec's ``inner_steps``) plus the ``k`` largest-magnitude coordinates of
    the flattened fragment delta, ordered by descending ``|value|`` with ties
    broken by ascending index. ``canonical_bytes()`` is byte-identical to the
    Rust ``ActivationCommitment::canonical_bytes`` so both sides compute the
    same ``commitment_hash``, which is bound into the outer-gradient signing
    preimage (see ``gradient.gradient_signing_bytes``).
    """

    k: int
    loss_trajectory: list[float]
    probes: list[DeltaProbe]

    def canonical_bytes(self) -> bytes:
        """Domain tag, ``k`` byte, LE u32 loss count, per-loss LE f32 bits,
        LE u32 probe count, per-probe LE u64 index + LE f32 value bits."""
        buf = bytearray(ACTIVATION_COMMITMENT_DOMAIN_TAG)
        buf += struct.pack("<B", self.k)
        buf += struct.pack("<I", len(self.loss_trajectory))
        for loss in self.loss_trajectory:
            buf += struct.pack("<f", loss)
        buf += struct.pack("<I", len(self.probes))
        for probe in self.probes:
            buf += struct.pack("<Qf", probe.index, probe.value)
        return bytes(buf)

    def commitment_hash(self) -> bytes:
        """SHA-256 over :meth:`canonical_bytes` — the value bound into the
        outer-gradient signing preimage."""
        return hashlib.sha256(self.canonical_bytes()).digest()

    def to_json(self) -> dict[str, Any]:
        return {
            "k": self.k,
            "loss_trajectory": list(self.loss_trajectory),
            "probes": [p.to_json() for p in self.probes],
        }

    @classmethod
    def from_json(cls, j: dict[str, Any]) -> ActivationCommitment:
        return cls(
            k=int(j["k"]),
            loss_trajectory=[float(v) for v in j["loss_trajectory"]],
            probes=[DeltaProbe.from_json(p) for p in j["probes"]],
        )


@dataclass
class Signature:
    bytes_: bytes
    public_key: bytes

    def to_json(self) -> dict[str, Any]:
        return {
            "bytes": list(self.bytes_),
            "public_key": list(self.public_key),
        }

    @classmethod
    def from_json(cls, j: dict[str, Any]) -> Signature:
        return cls(bytes_=bytes(j["bytes"]), public_key=bytes(j["public_key"]))


@dataclass
class OuterGradient:
    """A trainer's outer-gradient submission for one fragment in one round.

    The actual safetensors payload lives off-chain; only its 32-byte SHA-256
    digest is referenced here. The Rust syncer pulls the payload by that hash
    from the gossip network or content-addressed store.
    """

    task_id: str
    round: int
    fragment: int
    trainer_did: str
    trainer_address: bytes  # 32 bytes
    safetensors_hash: bytes  # 32 bytes
    payload_bytes: int
    quantization: GradientQuantization
    inner_step_count: int
    submitted_at: int  # Unix millis (matches Rust Timestamp)
    signature: Signature
    payload_kind: PayloadKind = field(default_factory=PayloadKind.dense)
    attestation: TrainingAttestation | None = None
    commitment: ActivationCommitment | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "round": self.round,
            "fragment": self.fragment,
            "trainer_did": self.trainer_did,
            "trainer_address": address_to_json(self.trainer_address),
            "safetensors_hash": hash_to_json(self.safetensors_hash),
            "payload_bytes": self.payload_bytes,
            "quantization": self.quantization.to_json(),
            "payload_kind": self.payload_kind.to_json(),
            "inner_step_count": self.inner_step_count,
            "submitted_at": self.submitted_at,
            "signature": self.signature.to_json(),
            "attestation": self.attestation.to_json() if self.attestation else None,
            "commitment": self.commitment.to_json() if self.commitment else None,
        }

    @classmethod
    def from_json(cls, j: dict[str, Any]) -> OuterGradient:
        return cls(
            task_id=j["task_id"],
            round=int(j["round"]),
            fragment=int(j["fragment"]),
            trainer_did=j["trainer_did"],
            trainer_address=address_from_json(j["trainer_address"]),
            safetensors_hash=hash_from_json(j["safetensors_hash"]),
            payload_bytes=int(j["payload_bytes"]),
            quantization=GradientQuantization.from_json(j["quantization"]),
            payload_kind=(
                PayloadKind.from_json(j["payload_kind"])
                if j.get("payload_kind") is not None
                else PayloadKind.dense()
            ),
            inner_step_count=int(j["inner_step_count"]),
            submitted_at=int(j["submitted_at"]),
            signature=Signature.from_json(j["signature"]),
            attestation=(
                TrainingAttestation.from_json(j["attestation"])
                if j.get("attestation")
                else None
            ),
            commitment=(
                ActivationCommitment.from_json(j["commitment"])
                if j.get("commitment")
                else None
            ),
        )
