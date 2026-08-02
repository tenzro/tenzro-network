"""Outer-gradient packaging.

Decoupled outer aggregation decomposes training into:

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
documented in docs/AI.md §7.4 (per-modality fragment partitioning).
"""

from __future__ import annotations

import hashlib
import struct
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

import nacl.signing
import numpy as np

# Heavy ML deps are imported lazily so the lightweight helpers
# (``fragment_indices``, signing) remain importable without torch /
# safetensors installed (e.g. in CI image builds and unit tests).
# numpy is a hard dependency (the quantization codec runs on it).
try:
    import torch
except ImportError:  # pragma: no cover - torch is a runtime dep for serialization
    torch = None  # type: ignore[assignment]

from tenzro_trainer.quantization import dequantize, quantize
from tenzro_trainer.types import (
    DEFAULT_PROBE_K,
    MAX_PROBE_K,
    ActivationCommitment,
    DeltaProbe,
    GradientQuantization,
    OuterGradient,
    PayloadKind,
    Signature,
    SparseTopKParams,
)

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
    state_dict: dict[str, torch.Tensor],
    fragment_count: int,
) -> list[dict[str, torch.Tensor]]:
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

    Under ``GradientQuantization.none()`` the ``payload`` is the
    safetensors-encoded bytes; under ``Int8`` / ``Int4`` it is the raw
    quantized encoding of the fragment's flattened float32 values
    (name-sorted key order, C-contiguous per tensor). ``digest`` is the
    SHA-256 of the payload — i.e. of the *quantized* bytes when quantization
    is active, so the hash commits to exactly what travels the wire.
    """

    fragment: int
    payload: bytes
    digest: bytes

    @property
    def size_bytes(self) -> int:
        return len(self.payload)


def flatten_fragment_values(
    delta_state_dict: dict[str, torch.Tensor],
) -> np.ndarray:
    """Flatten a fragment's tensors into one float32 numpy vector.

    Name-sorted key order, each tensor C-contiguous — the canonical layout
    both sides of the quantized wire format agree on.
    """
    if torch is None:
        raise RuntimeError("PyTorch is required")
    parts = [
        delta_state_dict[k]
        .detach()
        .to("cpu", torch.float32)
        .contiguous()
        .reshape(-1)
        .numpy()
        for k in sorted(delta_state_dict.keys())
    ]
    if not parts:
        return np.zeros(0, dtype=np.float32)
    return np.concatenate(parts).astype(np.float32, copy=False)


def split_flat_to_fragment(
    flat: np.ndarray,
    reference_state: dict[str, torch.Tensor],
) -> dict[str, torch.Tensor]:
    """Inverse of :func:`flatten_fragment_values`.

    Reshapes a flat float32 vector back into per-key tensors, consuming the
    vector in the same name-sorted, C-contiguous order the flatten produced.
    ``reference_state`` supplies the key set and tensor shapes. Used to turn a
    decoded sparse (or otherwise flattened) delta back into a state-dict the
    local apply step consumes.
    """
    if torch is None:
        raise RuntimeError("PyTorch is required")
    values = np.asarray(flat, dtype=np.float32).reshape(-1)
    total = sum(int(t.numel()) for t in reference_state.values())
    if values.size != total:
        raise ValueError(
            f"flat length {values.size} != fragment element count {total}"
        )
    out: dict[str, torch.Tensor] = {}
    cursor = 0
    for k in sorted(reference_state.keys()):
        ref = reference_state[k]
        n = int(ref.numel())
        chunk = values[cursor : cursor + n]
        cursor += n
        out[k] = torch.from_numpy(chunk.copy()).reshape(ref.shape)
    return out


def top_k_delta_probes(delta: np.ndarray, k: int) -> list[DeltaProbe]:
    """Select the top-k probes from a flattened fragment delta.

    The ``k`` largest-magnitude coordinates, ordered by descending
    ``|value|`` with ties broken by ascending index — the identical
    selection to the Rust challenger's
    ``tenzro_training::activation::top_k_delta_probes``. Non-finite values
    sort last so a delta containing NaN/Inf never contributes probes.
    """
    flat = np.asarray(delta, dtype=np.float32).reshape(-1)
    k = min(int(k), flat.size)
    if k <= 0:
        return []
    magnitude = np.abs(flat)
    magnitude[~np.isfinite(flat)] = -np.inf
    # lexsort's last key is primary: ascending -|value| (i.e. descending
    # |value|), ties broken by ascending index.
    order = np.lexsort((np.arange(flat.size), -magnitude))[:k]
    return [DeltaProbe(index=int(i), value=float(flat[i])) for i in order]


def build_activation_commitment(
    loss_trajectory: Sequence[float],
    flat_delta: np.ndarray,
    k: int = DEFAULT_PROBE_K,
) -> ActivationCommitment:
    """Build the Open-tier activation commitment for one fragment.

    ``loss_trajectory`` is the round's per-inner-step losses — its length
    must equal the task spec's ``inner_steps`` or the syncer's structural
    validator rejects the submission. ``flat_delta`` is the
    :func:`flatten_fragment_values` output for the fragment being
    committed. ``k`` is clamped to ``MAX_PROBE_K`` and the fragment size.
    """
    probes = top_k_delta_probes(flat_delta, min(int(k), MAX_PROBE_K))
    if not probes:
        raise ValueError("cannot build a commitment over an empty fragment delta")
    return ActivationCommitment(
        k=len(probes),
        loss_trajectory=[float(loss) for loss in loss_trajectory],
        probes=probes,
    )


# ---------------------------------------------------------------------------
# Chunked top-k + 2-bit codec
#
# Byte-identical to ``crates/tenzro-training/src/sparse.rs``. The wire layout
# per chunk is: f32 LE ``scale``, ``kept`` u16 LE ascending chunk-local
# indices, then ``ceil(kept/4)`` packed code bytes (2 bits each, low pair
# first). The 2-bit code is sign-magnitude: ``00→0, 01→+1, 11→-1`` (``10``
# reserved → 0). ``scale`` is the max magnitude of the kept coordinates.
# ---------------------------------------------------------------------------


def _sparse_top_k_indices(chunk: np.ndarray, kept: int) -> np.ndarray:
    """Chunk-local indices of the ``kept`` largest-magnitude coordinates,
    ascending (wire order). Ties break toward the lower index — the identical
    deterministic ordering to the Rust ``top_k_indices``."""
    n = chunk.size
    if kept >= n:
        return np.arange(n, dtype=np.int64)
    if kept <= 0:
        return np.zeros(0, dtype=np.int64)
    magnitude = np.abs(chunk.astype(np.float32, copy=False))
    # Descending |value|, ties broken by ascending index. lexsort's last key
    # is primary.
    order = np.lexsort((np.arange(n), -magnitude))[:kept]
    order.sort()
    return order.astype(np.int64, copy=False)


def _encode_2bit(value: float, scale: float) -> int:
    if scale == 0.0 or value == 0.0:
        return 0b00
    return 0b01 if value > 0.0 else 0b11


def _decode_2bit(code: int) -> float:
    code &= 0b11
    if code == 0b01:
        return 1.0
    if code == 0b11:
        return -1.0
    return 0.0  # 0b00 and reserved 0b10


def sparse_encoded_len(length: int, params: SparseTopKParams) -> int:
    """Total byte length of the sparse encoding of a length-``length``
    fragment under ``params`` — mirrors Rust ``sparse_encoded_len``."""
    cs = max(params.chunk_size, 1)
    total = 0
    rem = length
    while rem > 0:
        chunk_len = min(rem, cs)
        kept = params.kept_for_chunk(chunk_len)
        total += 4 + kept * 2 + (kept + 3) // 4
        rem -= chunk_len
    return total


def sparse_encode(values: np.ndarray, params: SparseTopKParams) -> bytes:
    """Encode a flattened fragment (the *transmit* vector) into the sparse
    top-k + 2-bit wire format. Byte-identical to Rust ``sparse_encode``."""
    flat = np.asarray(values, dtype=np.float32).reshape(-1)
    cs = max(params.chunk_size, 1)
    out = bytearray()
    for start in range(0, flat.size, cs):
        chunk = flat[start : start + cs]
        kept = params.kept_for_chunk(chunk.size)
        top = _sparse_top_k_indices(chunk, kept)
        max_abs = float(np.abs(chunk[top]).max()) if top.size else 0.0
        out += struct.pack("<f", max_abs)
        for i in top:
            out += struct.pack("<H", int(i))
        # Pack 2-bit codes, 4 per byte, low pair first.
        cur = 0
        filled = 0
        for i in top:
            code = _encode_2bit(float(chunk[int(i)]), max_abs)
            cur |= (code & 0b11) << (filled * 2)
            filled += 1
            if filled == 4:
                out.append(cur)
                cur = 0
                filled = 0
        if filled > 0:
            out.append(cur)
    return bytes(out)


def sparse_decode(
    data: bytes, params: SparseTopKParams, expected_len: int
) -> np.ndarray:
    """Decode a sparse wire payload into a dense length-``expected_len`` float32
    vector with dropped coordinates zero-filled. Mirrors Rust
    ``sparse_decode``, including the malformed-length and out-of-range-index
    rejections."""
    expected_bytes = sparse_encoded_len(expected_len, params)
    if len(data) != expected_bytes:
        raise ValueError(
            f"sparse {params.label()} payload is {len(data)} bytes, "
            f"expected {expected_bytes} for {expected_len} values"
        )
    cs = max(params.chunk_size, 1)
    out = np.zeros(expected_len, dtype=np.float32)
    cursor = 0
    base = 0
    while base < expected_len:
        chunk_len = min(expected_len - base, cs)
        kept = params.kept_for_chunk(chunk_len)
        (scale,) = struct.unpack_from("<f", data, cursor)
        cursor += 4
        indices: list[int] = []
        for _ in range(kept):
            (idx,) = struct.unpack_from("<H", data, cursor)
            if idx >= chunk_len:
                raise ValueError(
                    f"sparse {params.label()}: chunk-local index {idx} out of "
                    f"range for chunk length {chunk_len}"
                )
            indices.append(int(idx))
            cursor += 2
        code_bytes = (kept + 3) // 4
        for n, idx in enumerate(indices):
            byte = data[cursor + n // 4]
            code = (byte >> ((n % 4) * 2)) & 0b11
            out[base + idx] = _decode_2bit(code) * scale
        cursor += code_bytes
        base += chunk_len
    return out


def select_transmitted(
    values: np.ndarray, params: SparseTopKParams
) -> list[tuple[int, float]]:
    """The exact ``(global_index, transmitted_value)`` pairs
    :func:`sparse_encode` would send for ``values``. Used to subtract the
    transmitted mass from the error-feedback accumulator. Mirrors Rust
    ``select_transmitted``."""
    flat = np.asarray(values, dtype=np.float32).reshape(-1)
    cs = max(params.chunk_size, 1)
    sent: list[tuple[int, float]] = []
    base = 0
    for start in range(0, flat.size, cs):
        chunk = flat[start : start + cs]
        kept = params.kept_for_chunk(chunk.size)
        top = _sparse_top_k_indices(chunk, kept)
        max_abs = float(np.abs(chunk[top]).max()) if top.size else 0.0
        for i in top:
            i = int(i)
            q = _decode_2bit(_encode_2bit(float(chunk[i]), max_abs)) * max_abs
            sent.append((base + i, q))
        base += chunk.size
    return sent


class ErrorFeedback:
    """Trainer-local error-feedback accumulator.

    Replaces the syncer's outer momentum. Each round:

    1. compute the raw outer pseudo-gradient ``g = θ_before − θ_after``;
    2. :meth:`prepare_transmit` returns ``t = decay·acc + g`` (the vector
       actually sparsified and sent);
    3. encode ``t`` with :func:`sparse_encode`;
    4. :meth:`commit_transmitted` sets ``acc ← t`` with the transmitted
       coordinates subtracted — the residual carries into the next round.

    The accumulator is persisted next to the optimizer checkpoint via
    :meth:`state_dict` / :meth:`load_state_dict`. Byte-for-byte equivalent to
    the Rust ``ErrorFeedback`` so a Rust-side (Confidential-tier) syncer
    reproduces the same discipline.
    """

    def __init__(self, length: int, decay: float) -> None:
        self._decay = float(min(max(decay, 0.0), 1.0))
        self._acc = np.zeros(int(length), dtype=np.float32)

    @property
    def decay(self) -> float:
        return self._decay

    @property
    def accumulator(self) -> np.ndarray:
        return self._acc

    def prepare_transmit(self, grad: np.ndarray) -> np.ndarray:
        """Return the transmit vector ``t = decay·acc + grad``."""
        g = np.asarray(grad, dtype=np.float32).reshape(-1)
        if g.size != self._acc.size:
            raise ValueError(
                f"error-feedback grad length {g.size} != accumulator length "
                f"{self._acc.size}"
            )
        return (self._decay * self._acc + g).astype(np.float32, copy=False)

    def commit_transmitted(
        self, transmit: np.ndarray, transmitted: list[tuple[int, float]]
    ) -> None:
        """Set ``acc ← transmit`` then subtract the transmitted mass at the
        exact coordinates that were sent (error feedback)."""
        t = np.asarray(transmit, dtype=np.float32).reshape(-1)
        if t.size != self._acc.size:
            raise ValueError(
                f"error-feedback transmit length {t.size} != accumulator "
                f"length {self._acc.size}"
            )
        self._acc = t.copy()
        for idx, value in transmitted:
            if 0 <= idx < self._acc.size:
                self._acc[idx] -= value

    def state_dict(self) -> dict[str, object]:
        """Serializable snapshot for checkpointing beside the optimizer."""
        return {"decay": self._decay, "accumulator": self._acc.tolist()}

    @classmethod
    def load_state_dict(cls, state: dict[str, object]) -> ErrorFeedback:
        acc = np.asarray(state["accumulator"], dtype=np.float32)
        ef = cls(acc.size, float(state["decay"]))
        ef._acc = acc
        return ef


def serialize_fragment(
    fragment_index: int,
    delta_state_dict: dict[str, torch.Tensor],
    quantization: GradientQuantization,
    payload_kind: PayloadKind | None = None,
) -> FragmentBlob:
    """Serialize one fragment's delta state-dict + SHA-256 digest.

    Under ``PayloadKind.dense()`` (the default): ``none()`` keeps the
    safetensors container; ``Int8`` / ``Int4`` encode the flattened values
    with the blockwise codec from :mod:`tenzro_trainer.quantization` (the
    format the Rust syncer's ``dequantize`` consumes).

    Under ``PayloadKind.sparse_topk(params)``: the flattened fragment values
    (already error-feedback-adjusted by the caller) are encoded with the
    chunked top-k + 2-bit codec via :func:`sparse_encode`. Sparse and
    dense-quantization are mutually exclusive — the syncer rejects a sparse
    payload that also declares a blockwise ``GradientQuantization``.
    """
    if torch is None:
        raise RuntimeError("PyTorch is required to serialize fragments")
    kind = payload_kind or PayloadKind.dense()
    if not kind.is_dense:
        if kind.sparse is None:  # pragma: no cover - guarded by dataclass
            raise ValueError("SparseTopK payload kind requires params")
        payload = sparse_encode(flatten_fragment_values(delta_state_dict), kind.sparse)
    elif quantization.is_none:
        try:
            from safetensors.torch import save as safetensors_save
        except ImportError as e:  # pragma: no cover - hard runtime dep
            raise RuntimeError(
                "safetensors is required to serialize fragments "
                "(pip install 'tenzro-trainer')"
            ) from e
        payload = safetensors_save(delta_state_dict)
    else:
        payload = quantize(flatten_fragment_values(delta_state_dict), quantization)
    digest = hashlib.sha256(payload).digest()
    return FragmentBlob(fragment=fragment_index, payload=payload, digest=digest)


def deserialize_fragment_delta(
    payload: bytes,
    reference_state: dict[str, torch.Tensor],
    quantization: GradientQuantization,
) -> dict[str, torch.Tensor]:
    """Decode a fragment payload back into a per-key delta state-dict.

    ``reference_state`` supplies the key set and tensor shapes (any state
    dict restricted to the fragment's keys works — e.g. the round's
    ``θ⁽⁰⁾`` snapshot). Under quantization this is the *lossy* delta the
    syncer will aggregate, which is what the trainer must apply locally to
    stay bit-consistent with its peers.
    """
    if torch is None:
        raise RuntimeError("PyTorch is required")
    if quantization.is_none:
        try:
            from safetensors.torch import load as safetensors_load
        except ImportError as e:  # pragma: no cover - hard runtime dep
            raise RuntimeError(
                "safetensors is required to deserialize fragments "
                "(pip install 'tenzro-trainer')"
            ) from e
        return safetensors_load(payload)
    total = sum(int(t.numel()) for t in reference_state.values())
    values = dequantize(payload, quantization, total)
    out: dict[str, torch.Tensor] = {}
    cursor = 0
    for k in sorted(reference_state.keys()):
        ref = reference_state[k]
        n = int(ref.numel())
        chunk = values[cursor : cursor + n]
        cursor += n
        out[k] = torch.from_numpy(chunk.copy()).reshape(ref.shape)
    return out


def compute_outer_delta(
    pre_step_state: dict[str, torch.Tensor],
    post_step_state: dict[str, torch.Tensor],
) -> dict[str, torch.Tensor]:
    """Compute ``Δθ = θ⁽ᴴ⁾ − θ⁽⁰⁾`` element-wise.

    Both dicts must have identical keys and tensor shapes.
    """
    if torch is None:
        raise RuntimeError("PyTorch is required")
    if pre_step_state.keys() != post_step_state.keys():
        missing = pre_step_state.keys() ^ post_step_state.keys()
        raise ValueError(f"state-dict key mismatch: {missing}")
    delta: dict[str, torch.Tensor] = {}
    for k in sorted(pre_step_state.keys()):
        a = pre_step_state[k]
        b = post_step_state[k]
        if a.shape != b.shape:
            raise ValueError(f"shape mismatch on key '{k}': {a.shape} vs {b.shape}")
        # Move to CPU to avoid pinning a GPU tensor in the safetensors blob.
        delta[k] = (b.detach().to("cpu") - a.detach().to("cpu")).contiguous()
    return delta


def global_l2_norm(delta_state_dict: dict[str, torch.Tensor]) -> float:
    """L2 norm of a full outer delta, taken over the concatenation of every
    fragment's flattened values (the same quantity the syncer's ``clip_l2_norm``
    budget bounds)."""
    if torch is None:
        raise RuntimeError("PyTorch is required")
    acc = 0.0
    for k in sorted(delta_state_dict.keys()):
        t = delta_state_dict[k].detach().to("cpu", torch.float32)
        acc += float(torch.sum(t * t).item())
    return acc**0.5


def clip_outer_delta(
    delta_state_dict: dict[str, torch.Tensor],
    cap: float | None,
) -> tuple[dict[str, torch.Tensor], bool]:
    """Scale a full outer delta so its global L2 norm is at most ``cap``.

    This is the trainer-side twin of the syncer's per-contributor norm budget
    (``TrainingTaskSpec.clip_l2_norm``). Applying the identical cap here means
    an honest trainer submits a gradient the syncer never has to clip; a
    trainer that skips this step (or lies about it) is the one the syncer's
    own clip catches. Returns the (possibly rescaled) delta plus a flag that is
    ``True`` when the input exceeded ``cap``. ``None`` / non-positive ``cap``
    disables clipping.
    """
    if torch is None:
        raise RuntimeError("PyTorch is required")
    if cap is None or cap <= 0.0:
        return delta_state_dict, False
    norm = global_l2_norm(delta_state_dict)
    if norm <= cap or norm == 0.0:
        return delta_state_dict, False
    scale = cap / norm
    scaled = {
        k: (delta_state_dict[k].detach().to("cpu", torch.float32) * scale).contiguous()
        for k in delta_state_dict
    }
    return scaled, True


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------


@dataclass
class TrainerKey:
    """Ed25519 signing key for outer-gradient submissions.

    The public key bytes are the trainer's on-wire identity: the syncer
    requires ``trainer_address`` to equal ``signature.public_key`` and
    verifies the Ed25519 signature over the canonical preimage on every
    submission, so gradients must be built with
    ``trainer_address=key.public_key_bytes``.
    """

    signing: nacl.signing.SigningKey

    @classmethod
    def generate(cls) -> TrainerKey:
        return cls(signing=nacl.signing.SigningKey.generate())

    @classmethod
    def from_seed(cls, seed: bytes) -> TrainerKey:
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
    quantization: GradientQuantization,
    inner_step_count: int,
    submitted_at: int,
    commitment: ActivationCommitment | None = None,
) -> bytes:
    """Canonical preimage signed by the trainer.

    Mirrors the Rust convention of domain-prefixed BE-encoded fields. Order
    matches the field order on ``OuterGradient`` minus the signature itself;
    the quantization is bound as its canonical display label
    (``none`` / ``int8/N`` / ``int4/N``). The trailing byte binds the
    activation commitment: ``0x01`` + 32-byte ``commitment_hash`` when
    present, ``0x00`` when absent — byte-identical to the Rust
    ``outer_gradient_signing_bytes``, so a trainer cannot swap the
    commitment after signing.
    """
    buf = bytearray()
    buf.extend(b"tenzro/train/outer-gradient")
    buf.extend(task_id.encode("utf-8"))
    buf.extend(round_index.to_bytes(4, "big"))
    buf.extend(fragment.to_bytes(4, "big"))
    buf.extend(trainer_did.encode("utf-8"))
    buf.extend(safetensors_hash)
    buf.extend(payload_bytes.to_bytes(8, "big"))
    buf.extend(quantization.label().encode("utf-8"))
    buf.extend(inner_step_count.to_bytes(8, "big"))
    # Two's-complement encoding of i64 millis to match Rust's i64 timestamp.
    buf.extend(submitted_at.to_bytes(8, "big", signed=True))
    if commitment is not None:
        buf.append(1)
        buf.extend(commitment.commitment_hash())
    else:
        buf.append(0)
    return bytes(buf)


def build_outer_gradient(
    *,
    task_id: str,
    round_index: int,
    blob: FragmentBlob,
    trainer_did: str,
    trainer_address: bytes,
    quantization: GradientQuantization,
    inner_step_count: int,
    key: TrainerKey,
    submitted_at_ms: int | None = None,
    commitment: ActivationCommitment | None = None,
    payload_kind: PayloadKind | None = None,
) -> OuterGradient:
    """Assemble + sign an ``OuterGradient`` for one fragment.

    ``commitment`` is required for Open-tier tasks — the syncer's accept
    gate rejects Open-tier submissions without one.

    ``payload_kind`` declares dense (default) vs SparseTopK layout of
    ``blob.payload``; it must match the payload the caller passed to
    :func:`serialize_fragment`, and the syncer rejects a mismatch against the
    task spec. It is deliberately NOT part of the signed preimage — the Rust
    ``outer_gradient_signing_bytes`` does not bind it, so adding it here would
    diverge the wire signature.
    """
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
        quantization=quantization,
        inner_step_count=inner_step_count,
        submitted_at=submitted,
        commitment=commitment,
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
        quantization=quantization,
        payload_kind=payload_kind or PayloadKind.dense(),
        inner_step_count=inner_step_count,
        submitted_at=submitted,
        signature=sig,
        attestation=None,
        commitment=commitment,
    )


def build_round_gradients(
    *,
    task_id: str,
    round_index: int,
    blobs: Iterable[FragmentBlob],
    trainer_did: str,
    trainer_address: bytes,
    quantization: GradientQuantization,
    inner_step_count: int,
    key: TrainerKey,
    commitments: dict[int, ActivationCommitment] | None = None,
    payload_kind: PayloadKind | None = None,
) -> list[OuterGradient]:
    """Convenience: build one ``OuterGradient`` per fragment in a round.

    ``commitments`` maps fragment index → activation commitment; fragments
    without an entry are submitted commitment-free (Verified/Confidential
    tiers, where the TEE attestation carries the trust instead).

    ``payload_kind`` applies to every fragment in the round — dense (default)
    or SparseTopK. It must match the layout the fragments were serialized
    with; the syncer rejects a submission whose declared kind disagrees with
    the task spec.
    """
    submitted = int(time.time() * 1000)
    return [
        build_outer_gradient(
            task_id=task_id,
            round_index=round_index,
            blob=b,
            trainer_did=trainer_did,
            trainer_address=trainer_address,
            quantization=quantization,
            inner_step_count=inner_step_count,
            key=key,
            submitted_at_ms=submitted,
            commitment=(commitments or {}).get(b.fragment),
            payload_kind=payload_kind,
        )
        for b in blobs
    ]
