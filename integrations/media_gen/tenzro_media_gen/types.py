"""Python mirrors of the Rust ``tenzro_types::media_gen`` enums and structs.

Every type here serializes to the *exact* JSON shape the Rust node expects.
Wire conventions worth pinning down:

* ``Hash`` and ``Address`` are tuple structs over ``[u8; 32]`` — they serialize
  as a bare 32-element JSON array of integers (0–255), *not* as a hex string.
* ``Timestamp(pub i64)`` is a newtype over ``i64`` — it serializes as a bare
  integer (Unix milliseconds).
* ``Signature`` is ``{"bytes": [...], "public_key": [...]}`` where both fields
  are byte arrays of integers.
* ``max_price`` and ``price_paid`` are ``u128`` with no string codec attached,
  so they cross the wire as bare JSON numbers. Python ints serialize as-is.
* ``MediaGenKind`` / ``MediaGenStatus`` / ``MediaGenExpertRole`` carry pinned
  serde labels, so the JSON label and the display label are the same string.

``tests/test_types_roundtrip.py`` locks the wire format.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

# Protocol bounds, mirroring the ``MAX_MEDIA_GEN_*`` consts in Rust. Enforced
# node-side at admission; checked here so a worker's own posted job fails
# locally with a readable message instead of an RPC error.
MAX_MEDIA_GEN_DIMENSION = 8192
MAX_MEDIA_GEN_STEPS = 500
MAX_MEDIA_GEN_FRAMES = 3600
MAX_MEDIA_GEN_PROMPT_BYTES = 8192


# ---------------------------------------------------------------------------
# Primitive helpers
# ---------------------------------------------------------------------------


def hash_to_json(h: bytes) -> list[int]:
    """Encode a 32-byte hash as a 32-int JSON array (matches Rust ``Hash``)."""
    if len(h) != 32:
        raise ValueError(f"hash must be 32 bytes, got {len(h)}")
    return list(h)


def hash_from_json(arr: list[int]) -> bytes:
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


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class MediaGenKind(str, Enum):
    TEXT2IMAGE = "text2image"
    IMAGE2IMAGE = "image2image"
    TEXT2VIDEO = "text2video"
    IMAGE2VIDEO = "image2video"

    @property
    def requires_input_image(self) -> bool:
        return self in (MediaGenKind.IMAGE2IMAGE, MediaGenKind.IMAGE2VIDEO)

    @property
    def is_video(self) -> bool:
        return self in (MediaGenKind.TEXT2VIDEO, MediaGenKind.IMAGE2VIDEO)


class MediaGenStatus(str, Enum):
    PENDING = "pending"
    CLAIMED = "claimed"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

    @property
    def is_terminal(self) -> bool:
        return self in (
            MediaGenStatus.COMPLETED,
            MediaGenStatus.FAILED,
            MediaGenStatus.CANCELLED,
        )


class MediaGenExpertRole(str, Enum):
    HIGH_NOISE = "high_noise"
    LOW_NOISE = "low_noise"

    @property
    def partner(self) -> "MediaGenExpertRole":
        return (
            MediaGenExpertRole.LOW_NOISE
            if self is MediaGenExpertRole.HIGH_NOISE
            else MediaGenExpertRole.HIGH_NOISE
        )


# ---------------------------------------------------------------------------
# Signature
# ---------------------------------------------------------------------------


@dataclass
class Signature:
    """Mirrors ``tenzro_types::primitives::Signature``."""

    bytes_: bytes
    public_key: bytes

    def to_json(self) -> dict[str, Any]:
        return {"bytes": list(self.bytes_), "public_key": list(self.public_key)}

    @classmethod
    def from_json(cls, obj: dict[str, Any]) -> "Signature":
        return cls(
            bytes_=bytes(obj.get("bytes") or []),
            public_key=bytes(obj.get("public_key") or []),
        )

    @classmethod
    def empty(cls) -> "Signature":
        return cls(bytes_=b"", public_key=b"")


# ---------------------------------------------------------------------------
# Params
# ---------------------------------------------------------------------------


@dataclass
class MediaGenParams:
    prompt: str
    width: int
    height: int
    steps: int
    guidance_scale: float
    negative_prompt: str | None = None
    num_frames: int | None = None
    fps: int | None = None
    seed: int | None = None
    input_image_hash: bytes | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def validate_for(self, kind: MediaGenKind) -> None:
        """Mirror of Rust ``MediaGenParams::validate_for``.

        Raises ``ValueError`` on the first violation. The node re-checks all of
        this at admission; running it locally turns a wasted round-trip into an
        immediate error.
        """
        if not self.prompt.strip():
            raise ValueError("prompt must not be empty")
        if len(self.prompt.encode("utf-8")) > MAX_MEDIA_GEN_PROMPT_BYTES:
            raise ValueError("prompt exceeds the maximum length")
        if self.width <= 0 or self.height <= 0:
            raise ValueError("width and height must be greater than zero")
        if self.width > MAX_MEDIA_GEN_DIMENSION or self.height > MAX_MEDIA_GEN_DIMENSION:
            raise ValueError("width and height exceed the maximum dimension")
        if self.steps <= 0:
            raise ValueError("steps must be greater than zero")
        if self.steps > MAX_MEDIA_GEN_STEPS:
            raise ValueError("steps exceeds the maximum")
        # The guidance scale is folded into the signing preimage as raw
        # IEEE-754 bytes, so a NaN would break preimage determinism.
        if self.guidance_scale != self.guidance_scale or self.guidance_scale in (
            float("inf"),
            float("-inf"),
        ):
            raise ValueError("guidance_scale must be a finite non-negative number")
        if self.guidance_scale < 0.0:
            raise ValueError("guidance_scale must be a finite non-negative number")
        if kind.requires_input_image and self.input_image_hash is None:
            raise ValueError("input_image_hash is required for this media-gen kind")
        if kind.is_video:
            if self.num_frames is None or self.fps is None:
                raise ValueError(
                    "num_frames and fps are required for video media-gen kinds"
                )
            if self.num_frames <= 0 or self.fps <= 0:
                raise ValueError("num_frames and fps must be greater than zero")
            if self.num_frames > MAX_MEDIA_GEN_FRAMES:
                raise ValueError("num_frames exceeds the maximum")

    def to_json(self) -> dict[str, Any]:
        return {
            "prompt": self.prompt,
            "negative_prompt": self.negative_prompt,
            "width": self.width,
            "height": self.height,
            "num_frames": self.num_frames,
            "fps": self.fps,
            "steps": self.steps,
            "guidance_scale": self.guidance_scale,
            "seed": self.seed,
            "input_image_hash": (
                hash_to_json(self.input_image_hash) if self.input_image_hash else None
            ),
            "metadata": self.metadata,
        }

    @classmethod
    def from_json(cls, obj: dict[str, Any]) -> "MediaGenParams":
        raw_input_hash = obj.get("input_image_hash")
        return cls(
            prompt=obj["prompt"],
            negative_prompt=obj.get("negative_prompt"),
            width=int(obj["width"]),
            height=int(obj["height"]),
            num_frames=(
                int(obj["num_frames"]) if obj.get("num_frames") is not None else None
            ),
            fps=int(obj["fps"]) if obj.get("fps") is not None else None,
            steps=int(obj["steps"]),
            guidance_scale=float(obj["guidance_scale"]),
            seed=int(obj["seed"]) if obj.get("seed") is not None else None,
            input_image_hash=(
                hash_from_json(raw_input_hash) if raw_input_hash is not None else None
            ),
            metadata=obj.get("metadata") or {},
        )


# ---------------------------------------------------------------------------
# Task spec
# ---------------------------------------------------------------------------


@dataclass
class MediaGenTaskSpec:
    job_id: str
    requester_did: str
    requester_address: bytes
    model_id: str
    kind: MediaGenKind
    params: MediaGenParams
    max_price: int
    created_at: int
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "requester_did": self.requester_did,
            "requester_address": address_to_json(self.requester_address),
            "model_id": self.model_id,
            "kind": self.kind.value,
            "params": self.params.to_json(),
            "max_price": self.max_price,
            "created_at": self.created_at,
            "metadata": self.metadata,
        }

    @classmethod
    def from_json(cls, obj: dict[str, Any]) -> "MediaGenTaskSpec":
        return cls(
            job_id=obj["job_id"],
            requester_did=obj["requester_did"],
            requester_address=address_from_json(obj["requester_address"]),
            model_id=obj["model_id"],
            kind=MediaGenKind(obj["kind"]),
            params=MediaGenParams.from_json(obj["params"]),
            max_price=int(obj["max_price"]),
            created_at=int(obj["created_at"]),
            metadata=obj.get("metadata") or {},
        )


# ---------------------------------------------------------------------------
# Worker capability
# ---------------------------------------------------------------------------


@dataclass
class MediaGenExpertHolding:
    model_id: str
    role: MediaGenExpertRole

    def to_json(self) -> dict[str, Any]:
        return {"model_id": self.model_id, "role": self.role.value}

    @classmethod
    def from_json(cls, obj: dict[str, Any]) -> "MediaGenExpertHolding":
        return cls(model_id=obj["model_id"], role=MediaGenExpertRole(obj["role"]))


@dataclass
class MediaGenWorkerCapability:
    worker_did: str
    worker_address: bytes
    supported_models: list[str]
    max_resolution: int
    gpu_vram_gb: float
    registered_at: int
    expert_holdings: list[MediaGenExpertHolding] = field(default_factory=list)
    max_frames: int | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "worker_did": self.worker_did,
            "worker_address": address_to_json(self.worker_address),
            "supported_models": list(self.supported_models),
            "expert_holdings": [h.to_json() for h in self.expert_holdings],
            "max_resolution": self.max_resolution,
            "max_frames": self.max_frames,
            "gpu_vram_gb": self.gpu_vram_gb,
            "registered_at": self.registered_at,
        }

    @classmethod
    def from_json(cls, obj: dict[str, Any]) -> "MediaGenWorkerCapability":
        return cls(
            worker_did=obj["worker_did"],
            worker_address=address_from_json(obj["worker_address"]),
            supported_models=list(obj.get("supported_models") or []),
            expert_holdings=[
                MediaGenExpertHolding.from_json(h)
                for h in (obj.get("expert_holdings") or [])
            ],
            max_resolution=int(obj["max_resolution"]),
            max_frames=(
                int(obj["max_frames"]) if obj.get("max_frames") is not None else None
            ),
            gpu_vram_gb=float(obj["gpu_vram_gb"]),
            registered_at=int(obj["registered_at"]),
        )

    def roles_for(self, model_id: str) -> list[MediaGenExpertRole]:
        """Which halves of ``model_id``'s schedule this worker can run.

        A worker that lists the model in ``supported_models`` holds both
        transformers and qualifies for either half; one that only declares an
        expert holding qualifies for that half alone.
        """
        if model_id in self.supported_models:
            return [MediaGenExpertRole.HIGH_NOISE, MediaGenExpertRole.LOW_NOISE]
        return [h.role for h in self.expert_holdings if h.model_id == model_id]

    def fits_output(self, spec: MediaGenTaskSpec) -> bool:
        if max(spec.params.width, spec.params.height) > self.max_resolution:
            return False
        if spec.kind.is_video:
            if self.max_frames is None:
                return False
            return (spec.params.num_frames or 0) <= self.max_frames
        return True


# ---------------------------------------------------------------------------
# Handoff
# ---------------------------------------------------------------------------


@dataclass
class MediaGenHandoff:
    job_id: str
    from_worker_did: str
    from_worker_address: bytes
    latent_hash: bytes
    latent_bytes: int
    steps_completed: int
    handed_off_at: int
    worker_signature: Signature

    def to_json(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "from_worker_did": self.from_worker_did,
            "from_worker_address": address_to_json(self.from_worker_address),
            "latent_hash": hash_to_json(self.latent_hash),
            "latent_bytes": self.latent_bytes,
            "steps_completed": self.steps_completed,
            "handed_off_at": self.handed_off_at,
            "worker_signature": self.worker_signature.to_json(),
        }

    @classmethod
    def from_json(cls, obj: dict[str, Any]) -> "MediaGenHandoff":
        return cls(
            job_id=obj["job_id"],
            from_worker_did=obj["from_worker_did"],
            from_worker_address=address_from_json(obj["from_worker_address"]),
            latent_hash=hash_from_json(obj["latent_hash"]),
            latent_bytes=int(obj["latent_bytes"]),
            steps_completed=int(obj["steps_completed"]),
            handed_off_at=int(obj["handed_off_at"]),
            worker_signature=Signature.from_json(obj.get("worker_signature") or {}),
        )


# ---------------------------------------------------------------------------
# Receipt
# ---------------------------------------------------------------------------


@dataclass
class MediaGenReceipt:
    job_id: str
    task_spec: MediaGenTaskSpec
    worker_did: str
    worker_address: bytes
    output_hash: bytes
    output_mime: str
    output_bytes: int
    seed_used: int
    generation_time_ms: int
    price_paid: int
    completed_at: int
    worker_signature: Signature

    def to_json(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "task_spec": self.task_spec.to_json(),
            "worker_did": self.worker_did,
            "worker_address": address_to_json(self.worker_address),
            "output_hash": hash_to_json(self.output_hash),
            "output_mime": self.output_mime,
            "output_bytes": self.output_bytes,
            "seed_used": self.seed_used,
            "generation_time_ms": self.generation_time_ms,
            "price_paid": self.price_paid,
            "completed_at": self.completed_at,
            "worker_signature": self.worker_signature.to_json(),
        }

    @classmethod
    def from_json(cls, obj: dict[str, Any]) -> "MediaGenReceipt":
        return cls(
            job_id=obj["job_id"],
            task_spec=MediaGenTaskSpec.from_json(obj["task_spec"]),
            worker_did=obj["worker_did"],
            worker_address=address_from_json(obj["worker_address"]),
            output_hash=hash_from_json(obj["output_hash"]),
            output_mime=obj["output_mime"],
            output_bytes=int(obj["output_bytes"]),
            seed_used=int(obj["seed_used"]),
            generation_time_ms=int(obj["generation_time_ms"]),
            price_paid=int(obj["price_paid"]),
            completed_at=int(obj["completed_at"]),
            worker_signature=Signature.from_json(obj.get("worker_signature") or {}),
        )


# ---------------------------------------------------------------------------
# Assignment and job
# ---------------------------------------------------------------------------


@dataclass
class MediaGenAssignment:
    worker_did: str
    worker_address: bytes
    role: MediaGenExpertRole | None
    claimed_at: int
    share_bps: int

    @classmethod
    def from_json(cls, obj: dict[str, Any]) -> "MediaGenAssignment":
        raw_role = obj.get("role")
        return cls(
            worker_did=obj["worker_did"],
            worker_address=address_from_json(obj["worker_address"]),
            role=MediaGenExpertRole(raw_role) if raw_role is not None else None,
            claimed_at=int(obj["claimed_at"]),
            share_bps=int(obj.get("share_bps") or 0),
        )


@dataclass
class MediaGenJob:
    job_id: str
    task_spec: MediaGenTaskSpec
    status: MediaGenStatus
    required_roles: list[MediaGenExpertRole]
    assignments: list[MediaGenAssignment]
    handoff: MediaGenHandoff | None
    receipt: MediaGenReceipt | None
    error: str | None
    created_at: int
    last_update: int

    @classmethod
    def from_json(cls, obj: dict[str, Any]) -> "MediaGenJob":
        return cls(
            job_id=obj["job_id"],
            task_spec=MediaGenTaskSpec.from_json(obj["task_spec"]),
            status=MediaGenStatus(obj["status"]),
            required_roles=[
                MediaGenExpertRole(r) for r in (obj.get("required_roles") or [])
            ],
            assignments=[
                MediaGenAssignment.from_json(a) for a in (obj.get("assignments") or [])
            ],
            handoff=(
                MediaGenHandoff.from_json(obj["handoff"])
                if obj.get("handoff") is not None
                else None
            ),
            receipt=(
                MediaGenReceipt.from_json(obj["receipt"])
                if obj.get("receipt") is not None
                else None
            ),
            error=obj.get("error"),
            created_at=int(obj["created_at"]),
            last_update=int(obj["last_update"]),
        )

    @property
    def is_split(self) -> bool:
        return bool(self.required_roles)

    def assignment_of_role(
        self, role: MediaGenExpertRole
    ) -> MediaGenAssignment | None:
        return next((a for a in self.assignments if a.role is role), None)

    def assignment_for(self, worker_did: str) -> MediaGenAssignment | None:
        return next((a for a in self.assignments if a.worker_did == worker_did), None)

    def unclaimed_roles(self) -> list[MediaGenExpertRole]:
        return [r for r in self.required_roles if self.assignment_of_role(r) is None]

    def is_fully_assigned(self) -> bool:
        if self.is_split:
            return not self.unclaimed_roles()
        return bool(self.assignments)
