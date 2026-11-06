"""AP2 v0.2 open Payment Mandate constraints, checked the way the node checks
them before it holds the payment to the paying agent's Terms. An agent uses
this to know, before it presents a mandate, whether a payment is one the
mandate allows. Every constraint is checked or refused; none is skipped."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class MandatePayment:
    """The payment a mandate is checked against: payee DID, minor units, currency."""

    payee: str
    amount: int
    currency: str


class MandateRefusal(Exception):
    """Why a mandate does not allow a payment."""


def _amount_of(v: Any) -> int | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, int) and v >= 0:
        return v
    if isinstance(v, str) and v.isdigit():
        return int(v)
    return None


def _at(c: dict, k: str) -> int | None:
    v = c.get(k)
    if not isinstance(v, str):
        return None
    try:
        return int(datetime.fromisoformat(v.replace("Z", "+00:00")).timestamp())
    except ValueError:
        return None


def check_mandate_constraints(
    constraints: Any,
    payment: MandatePayment,
    transaction_id: str,
    instrument: dict | None,
    now_secs: int,
) -> None:
    """Check the open mandate's ``constraints`` against ``payment``, made under
    the checkout ``transaction_id`` with ``instrument``, at ``now_secs``.

    Raises :class:`MandateRefusal` naming the first constraint that refuses.
    ``payment.budget`` and ``payment.agent_recurrence`` are refused: they need a
    record of earlier payments and are expressed as a period limit in the
    agent's Terms instead.
    """
    if not isinstance(constraints, list):
        raise MandateRefusal("constraints is not a list")
    referenced = False
    for c in constraints:
        c = c if isinstance(c, dict) else {}
        ty = c.get("type") if isinstance(c.get("type"), str) else ""
        if ty == "payment.reference":
            if c.get("conditional_transaction_id") != transaction_id:
                raise MandateRefusal("the open mandate references another checkout")
            referenced = True
        elif ty == "payment.amount_range":
            cur = c.get("currency") if isinstance(c.get("currency"), str) else ""
            if cur.lower() != payment.currency.lower():
                raise MandateRefusal("the amount range is in another currency")
            hi = _amount_of(c.get("max"))
            if hi is None:
                raise MandateRefusal("amount_range.max")
            lo = _amount_of(c.get("min")) or 0
            if payment.amount < lo or payment.amount > hi:
                raise MandateRefusal("the amount is outside the mandate's range")
        elif ty == "payment.allowed_payees":
            allowed = c.get("allowed") if isinstance(c.get("allowed"), list) else []
            if not any(p == payment.payee or (isinstance(p, dict) and p.get("id") == payment.payee) for p in allowed):
                raise MandateRefusal("the payee is not one the mandate allows")
        elif ty == "payment.allowed_payment_instruments":
            allowed = c.get("allowed") if isinstance(c.get("allowed"), list) else None
            ok = allowed is not None and instrument is not None and any(
                json.dumps(a, sort_keys=True) == json.dumps(instrument, sort_keys=True)
                or (isinstance(a, dict) and a.get("id") is not None and a.get("id") == instrument.get("id"))
                or (isinstance(a, str) and a == instrument.get("type"))
                for a in allowed
            )
            if not ok:
                raise MandateRefusal("the payment instrument is not one the mandate allows")
        elif ty == "payment.allowed_pisps":
            # A payment on this network is initiated by no PISP; the constraint
            # only narrows card and bank initiation.
            pass
        elif ty == "payment.execution_date":
            nb, na = _at(c, "not_before"), _at(c, "not_after")
            if (nb is not None and now_secs < nb) or (na is not None and now_secs > na):
                raise MandateRefusal("the payment is outside the mandate's execution dates")
        elif ty in ("payment.budget", "payment.agent_recurrence"):
            raise MandateRefusal(
                f"{ty} needs a record of earlier payments; express it as a period limit in the agent's Terms"
            )
        else:
            raise MandateRefusal(f"unknown constraint {ty}")
    if not referenced:
        raise MandateRefusal("an open Payment Mandate must contain payment.reference")


__all__ = ["MandatePayment", "MandateRefusal", "check_mandate_constraints"]
