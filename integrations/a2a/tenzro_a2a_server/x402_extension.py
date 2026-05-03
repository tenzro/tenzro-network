"""A2A x402 extension — wire format and dispatcher contract.

This module mirrors `crates/tenzro-node/src/a2a/x402_extension.rs`. It defines
the four reserved metadata keys, the six PaymentStatus wire strings, and the
helper functions a JSON-RPC dispatcher uses to hold a task in
``input-required`` while the caller produces an ``x402.payment.payload``.

Wire-shape rules (must stay in lock-step with Rust):

* metadata is a free-form dict; the four reserved keys below carry the x402
  payload, requirements, status, and receipts.
* No version field anywhere — Tenzro-owned shapes are content-addressed by
  scheme name (``exact-eip3009``, ``exact-permit2``, ``exact-erc7710``).
* PaymentStatus values are kebab-case strings.

Slice (a) ships the dispatcher state machine plus a verifier that rejects
every payload with ``payment-rejected`` because no scheme backends are wired
yet. Slice (c) replaces ``UnimplementedSchemeVerifier`` with concrete
backends.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Reserved metadata keys
# ---------------------------------------------------------------------------

KEY_PAYMENT_REQUIRED = "x402.payment.required"
KEY_PAYMENT_PAYLOAD = "x402.payment.payload"
KEY_PAYMENT_RECEIPTS = "x402.payment.receipts"
KEY_PAYMENT_STATUS = "x402.payment.status"


# ---------------------------------------------------------------------------
# PaymentStatus — kebab-case wire strings
# ---------------------------------------------------------------------------

class PaymentStatus:
    """Wire-format payment status strings."""

    PAYMENT_REQUIRED = "payment-required"
    PAYMENT_SUBMITTED = "payment-submitted"
    PAYMENT_VERIFIED = "payment-verified"
    PAYMENT_SETTLING = "payment-settling"
    PAYMENT_COMPLETED = "payment-completed"
    PAYMENT_REJECTED = "payment-rejected"

    ALL = (
        PAYMENT_REQUIRED,
        PAYMENT_SUBMITTED,
        PAYMENT_VERIFIED,
        PAYMENT_SETTLING,
        PAYMENT_COMPLETED,
        PAYMENT_REJECTED,
    )


# ---------------------------------------------------------------------------
# Verifier failure reasons
# ---------------------------------------------------------------------------

class VerifyFailure(Exception):
    """A payment verification or settlement failure.

    Always maps to terminal ``payment-rejected`` for slice (a). Slice (c) may
    introduce non-terminal retry states; preserve that knob via
    ``terminal_status``.
    """

    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind
        self._message = message

    def terminal_status(self) -> str:
        return PaymentStatus.PAYMENT_REJECTED

    def message(self) -> str:
        return self._message

    @classmethod
    def task_id_mismatch(cls, expected: str, got: str) -> "VerifyFailure":
        return cls(
            "task_id_mismatch",
            f"payload task_id {got!r} does not match held task {expected!r}",
        )

    @classmethod
    def scheme_not_offered(cls, scheme: str, network: str) -> "VerifyFailure":
        return cls(
            "scheme_not_offered",
            f"scheme {scheme!r} on network {network!r} is not in payment requirements",
        )

    @classmethod
    def scheme_not_implemented(cls, scheme: str) -> "VerifyFailure":
        return cls(
            "scheme_not_implemented",
            f"scheme {scheme!r} has no backend on this server",
        )


# ---------------------------------------------------------------------------
# Metadata helpers — read
# ---------------------------------------------------------------------------

def get_payment_required(metadata: dict) -> Optional[dict]:
    """Return the held payment requirements, if any."""
    if not isinstance(metadata, dict):
        return None
    val = metadata.get(KEY_PAYMENT_REQUIRED)
    return val if isinstance(val, dict) else None


def get_payment_payload(metadata: dict) -> Optional[dict]:
    """Return the inbound payment payload, if any."""
    if not isinstance(metadata, dict):
        return None
    val = metadata.get(KEY_PAYMENT_PAYLOAD)
    return val if isinstance(val, dict) else None


# ---------------------------------------------------------------------------
# Metadata helpers — write
# ---------------------------------------------------------------------------

def set_status(metadata: dict, status: str) -> None:
    """Stamp the current wire-format status onto a metadata dict."""
    metadata[KEY_PAYMENT_STATUS] = status


def submit_x402(metadata: dict, payload: dict) -> None:
    """Record a submitted payment payload. Sets status to ``payment-submitted``."""
    metadata[KEY_PAYMENT_PAYLOAD] = payload
    set_status(metadata, PaymentStatus.PAYMENT_SUBMITTED)


def complete_x402(metadata: dict, receipts: list) -> None:
    """Record settlement receipts and mark the payment ``payment-completed``."""
    metadata[KEY_PAYMENT_RECEIPTS] = receipts
    set_status(metadata, PaymentStatus.PAYMENT_COMPLETED)


def fail_x402(metadata: dict, terminal: str) -> None:
    """Stamp a terminal failure status (e.g. ``payment-rejected``)."""
    if terminal not in PaymentStatus.ALL:
        raise ValueError(f"unknown terminal status: {terminal!r}")
    set_status(metadata, terminal)


# ---------------------------------------------------------------------------
# Verifier
# ---------------------------------------------------------------------------

@dataclass
class _RequirementMatch:
    scheme: str
    network: str


def _payload_requires_match(requirements: dict, payload: dict) -> Optional[_RequirementMatch]:
    """Return the offered (scheme, network) tuple if it appears in ``accepts``."""
    accepts = requirements.get("accepts") or []
    payload_scheme = payload.get("scheme")
    payload_network = payload.get("network")
    if not isinstance(payload_scheme, str) or not isinstance(payload_network, str):
        return None
    for req in accepts:
        if not isinstance(req, dict):
            continue
        if req.get("scheme") == payload_scheme and req.get("network") == payload_network:
            return _RequirementMatch(payload_scheme, payload_network)
    return None


class PaymentVerifier:
    """Abstract verify+settle hook. Returns receipts on success, raises VerifyFailure on failure."""

    def verify_and_settle(
        self,
        task_id: str,
        requirements: dict,
        payload: dict,
    ) -> list:
        raise NotImplementedError


class UnimplementedSchemeVerifier(PaymentVerifier):
    """Slice (a) verifier — does the structural checks then rejects every payload.

    Order of checks matches the Rust ``UnimplementedSchemeVerifier``:
      1. Payload's ``taskId`` must match the held task (replay guard).
      2. Payload's ``scheme``/``network`` must appear in ``requirements.accepts``.
      3. No backend is wired → terminal ``payment-rejected``.
    """

    def verify_and_settle(
        self,
        task_id: str,
        requirements: dict,
        payload: dict,
    ) -> list:
        payload_task_id = payload.get("taskId")
        if payload_task_id != task_id:
            raise VerifyFailure.task_id_mismatch(task_id, str(payload_task_id))

        match = _payload_requires_match(requirements, payload)
        if match is None:
            raise VerifyFailure.scheme_not_offered(
                str(payload.get("scheme")),
                str(payload.get("network")),
            )

        # Slice (a): no scheme backend wired. Slice (c) replaces this verifier.
        raise VerifyFailure.scheme_not_implemented(match.scheme)
