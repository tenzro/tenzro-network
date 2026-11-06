"""Payee payment operations (refunds and standing split rules), built as the
network decodes them (checked against ``sdk/fixtures/payment-ops``) and signed
with the caller's hardware key."""

from __future__ import annotations

import re
from typing import Any

from ..rpc import RpcClient
from ..typed_tx import TypedTransaction, TypedTxClient
from ..wallet import HybridSigner

_REF = re.compile(r"^[0-9a-f]{64}$")


def _strip(h: str) -> str:
    return h[2:] if h.startswith("0x") else h


def refund_op(pay_ref: str, amount: int) -> dict[str, Any]:
    """The ``Payment`` operation by which a payee refunds ``amount`` of the record ``pay_ref`` (32-byte hex)."""
    ref = _strip(pay_ref).lower()
    if not _REF.match(ref):
        raise ValueError("pay_ref must be 32 bytes of hex")
    if amount <= 0:
        raise ValueError("amount must be positive")
    return {"refund": {"pay_ref": ref, "amount": str(amount)}}


def set_split_op(rule: dict[str, Any] | None) -> dict[str, Any]:
    """The ``Payment`` operation that sets (or, with ``None``, clears) the payee's standing split rule."""
    return {"set_split": {"rule": rule}}


def refund_payment(rpc: RpcClient, signer: HybridSigner, pay_ref: str, amount: int) -> Any:
    """Refund ``amount`` of the payment record ``pay_ref``, as its payee."""
    return TypedTxClient(rpc).send(signer, TypedTransaction(kind="Payment", fields={"op": refund_op(pay_ref, amount)}))


def set_payee_split(rpc: RpcClient, signer: HybridSigner, rule: dict[str, Any] | None) -> Any:
    """Set (or clear) the split rule every payment to the signer's account is divided by."""
    return TypedTxClient(rpc).send(signer, TypedTransaction(kind="Payment", fields={"op": set_split_op(rule)}))
