"""Outer-gradient packaging.

Decoupled DiLoCo decomposes training into:

* **Inner loop** — H steps of local SGD on a shard. Run per trainer per round.
* **Outer step** — the syncer aggregates ``Δθᵢ = θᵢ⁽ᴴ⁾ − θ⁽⁰⁾`` from K-of-M
  trainers and applies a (Nesterov) outer optimizer step.

The Python trainer's job in this module is to take ``θ⁽⁰⁾`` (the round's
starting weights, broadcast by the syncer) and ``θ⁽ᴴ⁾`` (the locally trained
weights), compute the per-fragment delta, encode each fragment as a separate
safetensors blob, hash each blob with SHA-256, and emit one ``OuterGradient``
per fragment.

Fragment partitioning (Phase 1): contiguous, name-sorted parameter buckets.
The architecture spec carries ``fragment_count``; we shard the model's
state-dict keys (sorted lexicographically) into that many roughly-equal-byte
buckets. Both the trainer and the syncer must agree on this partition — it is
deterministic per (architecture.family, architecture.fragment_count) and
documented in TRAIN.md §5.2.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import Iterable

import nacl.signing

# Heavy ML deps are imported lazily so the lightweight helpers
# (``fragment_indices``, signing) remain importable without torch /
# safetensors installed (e.g. in CI image builds and unit tests).
try:
    import torch  # noqa: F401
except ImportError:  # pragma: no cover - torch is a runtime dep for serialization
    torch = None  # type: ignore[assignment]

from tenzro_trainer.types import OuterGradient, Signature


# ---------------------------------------------------------------------------
# Fragment partitioning
# ---------------------------------------------------------------------------


def fragment_indices(num_params: int, fragment_count: int) -> list[tuple[int, int]]:
    """Return half-open ``[start, end)`` index ranges over a sorted name list.

    Splits ``num_params`` keys into ``fragment_count`` contiguous buckets.
    The split is deterministic, balanced to within ±1 element, and
    independent of any tensor shape — only the *count* matters here.
    """
    if fragment_count <= 0:
        raise ValueError("fragment_count must be positive")
    if fragment_count > num_params:
        raise ValueError(
            f"cannot split {num_params} parameters into {fragment_count} fragments"
        )
    base, extra = divmod(num_params, fragment_count)
    spans: list[tuple[int, int]] = []
    cursor = 0
    for f in range(fragment_count):
        size = base + (1 if f < extra else 0)
        spans.append((cursor, cursor + size))
        cursor += size
    return spans


def partition_state_dict(
    state_dict: dict[str, "torch.Tensor"],
    fragment_count: int,
) -> list[dict[str, "torch.Tensor"]]:
    """Split a torch ``state_dict`` into ``fragment_count`` sub-state-dicts."""
    sorted_keys = sorted(state_dict.keys())
    spans = fragment_indices(len(sorted_keys), fragment_count)
    return [
        {k: state_dict[k] for k in sorted_keys[start:end]} for (start, end) in spans
    ]


# ---------------------------------------------------------------------------
# Outer gradient construction
# ---------------------------------------------------------------------------


@dataclass
class FragmentBlob:
    """One fragment's serialized outer gradient.

    ``payload`` is the safetensors-encoded bytes (already on disk or in memory);
    ``digest`` is its SHA-256. The digest is what gets baked into the
    ``OuterGradient`` and committed to the on-chain state root via
    ``compute_state_root``.
    """

    fragment: int
    payload: bytes
    digest: bytes

    @property
    def size_bytes(self) -> int:
        return len(self.payload)


def serialize_fragment(
    fragment_index: int,
    delta_state_dict: dict[str, "torch.Tensor"],
) -> FragmentBlob:
    """Serialize a delta state-dict for one fragment as safetensors + SHA-256."""
    if torch is None:
        raise RuntimeError("PyTorch is required to serialize fragments")
    try:
        from safetensors.torch import save as safetensors_save
    except ImportError as e:  # pragma: no cover - hard runtime dep
        raise RuntimeError(
            "safetensors is required to serialize fragments "
            "(pip install 'tenzro-trainer')"
        ) from e
    payload = safetensors_save(delta_state_dict)
    digest = hashlib.sha256(payload).digest()
    return FragmentBlob(fragment=fragment_index, payload=payload, digest=digest)


def compute_outer_delta(
    pre_step_state: dict[str, "torch.Tensor"],
    post_step_state: dict[str, "torch.Tensor"],
) -> dict[str, "torch.Tensor"]:
    """Compute ``Δθ = θ⁽ᴴ⁾ − θ⁽⁰⁾`` element-wise.

    Both dicts must have identical keys and tensor shapes.
    """
    if torch is None:
        raise RuntimeError("PyTorch is required")
    if pre_step_state.keys() != post_step_state.keys():
        missing = pre_step_state.keys() ^ post_step_state.keys()
        raise ValueError(f"state-dict key mismatch: {missing}")
    delta: dict[str, "torch.Tensor"] = {}
    for k in sorted(pre_step_state.keys()):
        a = pre_step_state[k]
        b = post_step_state[k]
        if a.shape != b.shape:
            raise ValueError(f"shape mismatch on key '{k}': {a.shape} vs {b.shape}")
        # Move to CPU to avoid pinning a GPU tensor in the safetensors blob.
        delta[k] = (b.detach().to("cpu") - a.detach().to("cpu")).contiguous()
    return delta


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------


@dataclass
class TrainerKey:
    """Ed25519 signing key for outer-gradient submissions.

    The public key bytes also serve as the trainer's TDIP machine identity.
    The Rust syncer in Phase 1 (Open tier) does *not* enforce gradient
    signatures, but the wire format already carries them so Phase 2 can
    light up signature verification without a protocol change.
    """

    signing: nacl.signing.SigningKey

    @classmethod
    def generate(cls) -> "TrainerKey":
        return cls(signing=nacl.signing.SigningKey.generate())

    @classmethod
    def from_seed(cls, seed: bytes) -> "TrainerKey":
        if len(seed) != 32:
            raise ValueError("Ed25519 seed must be 32 bytes")
        return cls(signing=nacl.signing.SigningKey(seed))

    @property
    def public_key_bytes(self) -> bytes:
        return bytes(self.signing.verify_key)

    def sign(self, msg: bytes) -> bytes:
        return self.signing.sign(msg).signature


def gradient_signing_bytes(
    task_id: str,
    round_index: int,
    fragment: int,
    trainer_did: str,
    safetensors_hash: bytes,
    payload_bytes: int,
    inner_step_count: int,
    submitted_at: int,
) -> bytes:
    """Canonical preimage signed by the trainer.

    Mirrors the Rust convention of domain-prefixed BE-encoded fields. Order
    matches the field order on ``OuterGradient`` minus the signature itself.
    """
    buf = bytearray()
    buf.extend(b"tenzro/train/outer-gradient")
    buf.extend(task_id.encode("utf-8"))
    buf.extend(round_index.to_bytes(4, "big"))
    buf.extend(fragment.to_bytes(4, "big"))
    buf.extend(trainer_did.encode("utf-8"))
    buf.extend(safetensors_hash)
    buf.extend(payload_bytes.to_bytes(8, "big"))
    buf.extend(inner_step_count.to_bytes(8, "big"))
    # Two's-complement encoding of i64 millis to match Rust's i64 timestamp.
    buf.extend(submitted_at.to_bytes(8, "big", signed=True))
    return bytes(buf)


def build_outer_gradient(
    *,
    task_id: str,
    round_index: int,
    blob: FragmentBlob,
    trainer_did: str,
    trainer_address: bytes,
    inner_step_count: int,
    key: TrainerKey,
    submitted_at_ms: int | None = None,
) -> OuterGradient:
    """Assemble + sign an ``OuterGradient`` for one fragment."""
    submitted = (
        submitted_at_ms if submitted_at_ms is not None else int(time.time() * 1000)
    )
    msg = gradient_signing_bytes(
        task_id=task_id,
        round_index=round_index,
        fragment=blob.fragment,
        trainer_did=trainer_did,
        safetensors_hash=blob.digest,
        payload_bytes=blob.size_bytes,
        inner_step_count=inner_step_count,
        submitted_at=submitted,
    )
    sig_bytes = key.sign(msg)
    sig = Signature(bytes_=sig_bytes, public_key=key.public_key_bytes)
    return OuterGradient(
        task_id=task_id,
        round=round_index,
        fragment=blob.fragment,
        trainer_did=trainer_did,
        trainer_address=trainer_address,
        safetensors_hash=blob.digest,
        payload_bytes=blob.size_bytes,
        inner_step_count=inner_step_count,
        submitted_at=submitted,
        signature=sig,
        attestation=None,
    )


def build_round_gradients(
    *,
    task_id: str,
    round_index: int,
    blobs: Iterable[FragmentBlob],
    trainer_did: str,
    trainer_address: bytes,
    inner_step_count: int,
    key: TrainerKey,
) -> list[OuterGradient]:
    """Convenience: build one ``OuterGradient`` per fragment in a round."""
    submitted = int(time.time() * 1000)
    return [
        build_outer_gradient(
            task_id=task_id,
            round_index=round_index,
            blob=b,
            trainer_did=trainer_did,
            trainer_address=trainer_address,
            inner_step_count=inner_step_count,
            key=key,
            submitted_at_ms=submitted,
        )
        for b in blobs
    ]
