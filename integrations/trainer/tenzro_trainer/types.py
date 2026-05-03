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
    """Phase 1 only emits ``Mean``. Other variants are placeholders for Phase 2."""

    @staticmethod
    def mean() -> dict[str, Any] | str:
        # Rust serde tags unit enum variants by name as bare strings.
        return "Mean"


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
    def from_json(cls, j: dict[str, Any]) -> "ArchitectureSpec":
        return cls(
            family=j["family"],
            param_count=int(j["param_count"]),
            modality=TrainingModality(j["modality"]),
            fragment_count=int(j["fragment_count"]),
            dtype=j.get("dtype"),
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
    def from_json(cls, j: dict[str, Any]) -> "TrainingAttestation":
        return cls(
            vendor=j["vendor"],
            report_hex=j["report_hex"],
            program_hash=hash_from_json(j["program_hash"]),
            shard_hash=hash_from_json(j["shard_hash"]),
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
    def from_json(cls, j: dict[str, Any]) -> "Signature":
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
    inner_step_count: int
    submitted_at: int  # Unix millis (matches Rust Timestamp)
    signature: Signature
    attestation: TrainingAttestation | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "round": self.round,
            "fragment": self.fragment,
            "trainer_did": self.trainer_did,
            "trainer_address": address_to_json(self.trainer_address),
            "safetensors_hash": hash_to_json(self.safetensors_hash),
            "payload_bytes": self.payload_bytes,
            "inner_step_count": self.inner_step_count,
            "submitted_at": self.submitted_at,
            "signature": self.signature.to_json(),
            "attestation": self.attestation.to_json() if self.attestation else None,
        }

    @classmethod
    def from_json(cls, j: dict[str, Any]) -> "OuterGradient":
        return cls(
            task_id=j["task_id"],
            round=int(j["round"]),
            fragment=int(j["fragment"]),
            trainer_did=j["trainer_did"],
            trainer_address=address_from_json(j["trainer_address"]),
            safetensors_hash=hash_from_json(j["safetensors_hash"]),
            payload_bytes=int(j["payload_bytes"]),
            inner_step_count=int(j["inner_step_count"]),
            submitted_at=int(j["submitted_at"]),
            signature=Signature.from_json(j["signature"]),
            attestation=(
                TrainingAttestation.from_json(j["attestation"])
                if j.get("attestation")
                else None
            ),
        )
