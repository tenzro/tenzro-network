"""Settlement plans: several value legs, one Commit-or-Abort decision, the division fixed by the quote.

:func:`preview_split` is the network's split engine computed locally: the
protocol fee once on the gross (burn, treasury, insurance), payee-borne network
fees, then the rule's lines by largest remainder. It is checked against the
shared vectors in ``sdk/fixtures/split``, so a payer sees exactly the division
the chain will make.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from ..rpc import RpcClient
from ..typed_tx import TypedTransaction, TypedTxClient
from ..wallet import HybridSigner

ROLES = ("payee", "publisher", "licensor", "referrer", "facilitator", "relayer", "solver", "prover", "refund")

#: The x402 wire version this network speaks.
X402_VERSION = 2

BPS = 10_000

SplitRule = dict[str, Any]
FeeParams = dict[str, Any]


def _bps_of(v: int, b: int) -> int:
    return (v // BPS) * b + ((v % BPS) * b) // BPS


def _strip(h: str) -> str:
    return h[2:] if h.startswith("0x") else h


def _basis(line: dict[str, Any]) -> tuple[str, Any]:
    b = line["basis"]
    if b == "remainder":
        return "remainder", None
    if "bps" in b:
        return "bps", int(b["bps"])
    return "fixed", int(b["fixed"])


def validate_split_rule(rule: SplitRule) -> None:
    """The checks the chain applies to a rule. Raises on a malformed rule."""
    if rule.get("version") != 1:
        raise ValueError("unknown split rule version")
    lines = rule.get("lines") or []
    if not 1 <= len(lines) <= 16:
        raise ValueError("a split rule has 1 to 16 lines")
    remainders = 0
    bps = 0
    for line in lines:
        kind, value = _basis(line)
        if kind == "remainder":
            remainders += 1
            if line.get("cap") is not None:
                raise ValueError("the remainder line has no cap")
        elif kind == "bps":
            if value <= 0:
                raise ValueError("a basis-point line takes a positive share")
            bps += value
        elif value == 0:
            raise ValueError("a fixed line takes a positive amount")
        r = line["recipient"]
        if isinstance(r, dict) and "address" in r and len(_strip(r["address"])) != 64:
            raise ValueError("an address is 32 bytes of hex")
    if remainders != 1:
        raise ValueError("a split rule has exactly one remainder line")
    if bps > BPS:
        raise ValueError("basis-point lines sum to at most 10000")


def check_intermediary_share(rule: SplitRule, gross: int, max_bps: int) -> None:
    """Refuse a rule whose facilitator and relayer lines can take more than ``max_bps`` of ``gross``.

    As the network checks an agent's plan against its Terms
    (``max_split_fee_bps``): each line at the most it can take (a basis-point
    line its exact share, a fixed line its amount, the remainder the whole
    gross), each bounded by its cap and the gross.
    """
    most = 0
    for line in rule["lines"]:
        if line["role"] not in ("facilitator", "relayer"):
            continue
        kind, value = _basis(line)
        if kind == "remainder":
            share = gross * BPS
        elif kind == "bps":
            share = gross * value
        else:
            share = min(value, gross) * BPS
        if line.get("cap") is not None:
            share = min(share, min(int(line["cap"]), gross) * BPS)
        most += share
    if most > gross * max_bps:
        raise ValueError(f"facilitator and relayer lines can take more than {max_bps} bps of the gross")


def fee_allocation(gross: int, p: FeeParams) -> dict[str, int]:
    """The protocol fee on ``gross`` and its parts."""
    fee = min(max(_bps_of(gross, min(int(p["fee_bps"]), BPS)), int(p["min_fee"])), gross)
    burn = _bps_of(fee, min(int(p["burn_bps"]), BPS))
    insurance = _bps_of(fee - burn, min(int(p["insurance_bps"]), BPS))
    return {"fee": fee, "burn": burn, "treasury": fee - burn - insurance, "insurance": insurance}


def preview_split(gross: int, rule: SplitRule, params: FeeParams, network_fees: int = 0) -> dict[str, Any]:
    """The division the chain makes of ``gross`` under ``rule``."""
    validate_split_rule(rule)
    f = fee_allocation(gross, params)
    if f["fee"] + network_fees > gross:
        raise ValueError("fees exceed the gross")
    net = gross - f["fee"] - network_fees
    lines = rule["lines"]
    credits = [0] * len(lines)
    left = net
    for i, line in enumerate(lines):
        kind, value = _basis(line)
        if kind == "fixed":
            take = value
            if line.get("cap") is not None:
                take = min(take, int(line["cap"]))
            take = min(take, left)
            credits[i] = take
            left -= take
    pool = left
    sum_bps = 0
    floors = 0
    fractions: list[tuple[int, int]] = []
    for i, line in enumerate(lines):
        kind, value = _basis(line)
        if kind == "bps":
            sum_bps += value
            credits[i] = _bps_of(pool, value)
            floors += credits[i]
            fractions.append((((pool % BPS) * value) % BPS, i))
    fractions.sort(key=lambda t: (-t[0], t[1]))
    extra = _bps_of(pool, sum_bps) - floors
    for _, i in fractions:
        if extra == 0:
            break
        credits[i] += 1
        extra -= 1
    for i, line in enumerate(lines):
        kind, _ = _basis(line)
        if kind == "bps" and line.get("cap") is not None:
            credits[i] = min(credits[i], int(line["cap"]))
    remainder = next(i for i, line in enumerate(lines) if line["basis"] == "remainder")
    credits[remainder] = net - (sum(credits) - credits[remainder])
    return {
        "gross": str(gross),
        "fee": {k: str(f[k]) for k in ("fee", "burn", "treasury", "insurance")},
        "network_fees": str(network_fees),
        "net": str(net),
        "credits": [str(c) for c in credits],
    }


def split_rule_hash(rule: SplitRule) -> str:
    """The hash a quote signs and a plan binds, hex."""
    out = bytearray(b"tenzro/split-rule/v1")
    out += int(rule["version"]).to_bytes(2, "big")
    out.append(len(rule["lines"]))
    for line in rule["lines"]:
        out.append(ROLES.index(line["role"]))
        r = line["recipient"]
        if r == "leg_submitter":
            out.append(2)
        elif "address" in r:
            out.append(0)
            out += bytes.fromhex(_strip(r["address"]))
        else:
            d = r["did_derived"].encode()
            out.append(1)
            out += len(d).to_bytes(2, "big") + d
        kind, value = _basis(line)
        if kind == "remainder":
            out.append(2)
        elif kind == "bps":
            out.append(0)
            out += value.to_bytes(2, "big")
        else:
            out.append(1)
            out += value.to_bytes(16, "big")
        if line.get("cap") is not None:
            out.append(1)
            out += int(line["cap"]).to_bytes(16, "big")
        else:
            out.append(0)
    return hashlib.sha256(bytes(out)).hexdigest()


def plan_payment_payload(
    accepted: dict[str, Any], signed_tx: dict[str, Any], resource: dict[str, Any] | None = None
) -> dict[str, Any]:
    """The x402 payment payload for a ``plan`` requirement: the payer's signed ``SettlementPlan`` open transaction."""
    if accepted.get("scheme") != "plan":
        raise ValueError(f"requirement scheme is {accepted.get('scheme')}, not plan")
    tx_type = signed_tx.get("transaction", {}).get("tx_type")
    op = tx_type.get("SettlementPlan", {}).get("op") if isinstance(tx_type, dict) else None
    if not isinstance(op, dict) or "open" not in op:
        raise ValueError("the transaction does not open a settlement plan")
    out: dict[str, Any] = {"x402Version": X402_VERSION}
    if resource:
        out["resource"] = resource
    out["accepted"] = accepted
    out["payload"] = {"signed_tx": signed_tx}
    return out


def plan_payment_header(payload: dict[str, Any]) -> str:
    """:func:`plan_payment_payload` encoded for the ``PAYMENT-SIGNATURE`` header (base64 JSON)."""
    text = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    return base64.b64encode(text.encode()).decode()


class PlanBuilder:
    """Builds the ``open`` operation a payer signs."""

    def __init__(self, nonce: int, quote_digest: str, split: SplitRule, decide_deadline_ms: int):
        self._nonce = nonce
        self._quote_digest = quote_digest
        self._split = split
        self._deadline = decide_deadline_ms
        self._legs: list[dict[str, Any]] = []

    def native(self, amount: int, escrow_id: str | None = None) -> PlanBuilder:
        """A Tenzro leg paid from the payer's balance, or from its funded escrow."""
        self._legs.append(
            {
                "kind": {"native_transfer": {"amount": str(amount), "escrow_id": _strip(escrow_id) if escrow_id else None}},
                "class_required": "native",
            }
        )
        return self

    def build(self) -> dict[str, Any]:
        """The ``open`` operation's fields."""
        validate_split_rule(self._split)
        if not 1 <= len(self._legs) <= 16:
            raise ValueError("a plan has 1 to 16 legs")
        return {
            "nonce": self._nonce,
            "quote_digest": _strip(self._quote_digest),
            "split_hash": split_rule_hash(self._split),
            "split": self._split,
            "legs": self._legs,
            "decide_deadline_ms": self._deadline,
        }


def open_plan_tx(plan: dict[str, Any]) -> dict[str, Any]:
    """The transaction type that opens ``plan`` (:meth:`PlanBuilder.build`'s output)."""
    return {"SettlementPlan": {"op": {"open": plan}}}


def prove_leg_tx(plan_id: str, index: int, evidence: str | None = None, network_fee: int = 0) -> dict[str, Any]:
    """The transaction type recording that leg ``index`` reached its evidence class, for any signer."""
    prove: dict[str, Any] = {"plan_id": _strip(plan_id), "index": index, "network_fee": str(network_fee)}
    if evidence:
        prove["evidence"] = _strip(evidence)
    return {"SettlementPlan": {"op": {"prove_leg": prove}}}


def dispute_rail_tx(plan_id: str, index: int, evidence: str) -> dict[str, Any]:
    """The transaction type a rail leg's payee sends to dispute the leg its attestor confirmed."""
    return {
        "SettlementPlan": {"op": {"dispute_rail": {"plan_id": _strip(plan_id), "index": index, "evidence": _strip(evidence)}}}
    }


def collateral_tx(asset: str, amount: int, post: bool, agent: dict[str, Any] | None = None) -> dict[str, Any]:
    """The transaction type that posts (``post=True``) or withdraws collateral for netted plans."""
    body: dict[str, Any] = {"asset": _strip(asset), "amount": str(amount)}
    if agent:
        body["agent"] = agent
    return {"SettlementPlan": {"op": {"post_collateral" if post else "withdraw_collateral": body}}}


def settlement_plan_tx(tx_type: dict[str, Any]) -> TypedTransaction:
    """A ``SettlementPlan`` transaction type as a :class:`TypedTransaction` for a signer."""
    return TypedTransaction(kind="SettlementPlan", fields=tx_type["SettlementPlan"])


def sign_plan_payment(
    rpc: RpcClient,
    signer: HybridSigner,
    plan: dict[str, Any],
    accepted: dict[str, Any],
    resource: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], str]:
    """Pay an x402 ``plan`` requirement: sign the transaction opening ``plan`` locally and wrap it.

    Returns the payload and its ``PAYMENT-SIGNATURE`` header value; nothing is
    submitted here, the facilitator opens the plan when it settles the payment.
    """
    signed = TypedTxClient(rpc).sign(signer, settlement_plan_tx(open_plan_tx(plan)))
    payload = plan_payment_payload(accepted, signed, resource)
    return payload, plan_payment_header(payload)
