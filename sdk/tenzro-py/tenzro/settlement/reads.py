"""Settlement plan reads: a plan, its decision, one leg's receipt and
evidence, and plans by payer and status. Each record comes with the
state-proof key (``{"namespace", "key"}``, hex) a light client proves it under.
"""

from __future__ import annotations

from typing import Any, Optional, TypedDict

from ..rpc import RpcClient

PLAN_STATUSES = ("open", "committed", "aborted")
MAX_PLAN_LEGS = 16


class ProofKey(TypedDict):
    """Where a record lives in state: the column family and the hex key."""

    namespace: str
    key: str


class PlanView(TypedDict):
    """``tenzro_getPlan``: the plan, its split rule hash, the id of each leg,
    the plan's vault address and the plan's state-proof key."""

    plan: dict[str, Any]
    split_hash: str
    leg_ids: list[str]
    vault: str
    proof: ProofKey


class PlanDecision(TypedDict):
    """``tenzro_getPlanDecision``: the decision, and the fixed-size commitment
    a lock on another chain proves."""

    decision: dict[str, Any]
    commitment: str
    proof: ProofKey


class LegReceipt(TypedDict):
    """``tenzro_getLegReceipt``: the leg's receipt once its plan is decided
    and the evidence recorded for it, each with its state-proof key;
    ``commitment`` is the receipt as stored."""

    leg_id: str
    receipt: Optional[dict[str, Any]]
    commitment: Optional[str]
    proof: ProofKey
    evidence: Optional[dict[str, Any]]
    evidence_proof: ProofKey


class PlanList(TypedDict):
    """``tenzro_listPlans``: plans in key order."""

    plans: list[PlanView]


def get_plan(rpc: RpcClient, plan_id: str) -> PlanView:
    """A plan by its 32-byte hex id. The node answers -32004 when there is none."""
    return rpc.call("tenzro_getPlan", {"plan_id": plan_id})


def get_plan_decision(rpc: RpcClient, plan_id: str) -> PlanDecision:
    """A plan's decision. The node answers -32004 while the plan is undecided."""
    return rpc.call("tenzro_getPlanDecision", {"plan_id": plan_id})


def get_leg_receipt(
    rpc: RpcClient,
    *,
    leg_id: Optional[str] = None,
    plan_id: Optional[str] = None,
    index: Optional[int] = None,
) -> LegReceipt:
    """One leg's receipt and evidence, by ``leg_id``, or by ``plan_id`` and ``index`` (0 to 15)."""
    if leg_id is not None:
        if plan_id is not None or index is not None:
            raise ValueError("give leg_id, or plan_id and index")
        return rpc.call("tenzro_getLegReceipt", {"leg_id": leg_id})
    if plan_id is None or index is None:
        raise ValueError("give leg_id, or plan_id and index")
    if not 0 <= index < MAX_PLAN_LEGS:
        raise ValueError("index is 0 to 15")
    return rpc.call("tenzro_getLegReceipt", {"plan_id": plan_id, "index": index})


def list_plans(
    rpc: RpcClient,
    *,
    payer: Optional[str] = None,
    status: Optional[str] = None,
    limit: Optional[int] = None,
) -> PlanList:
    """Plans, optionally those ``payer`` (32-byte hex) opened and those in one ``status``."""
    if status is not None and status not in PLAN_STATUSES:
        raise ValueError(f"status is one of {', '.join(PLAN_STATUSES)}")
    fields = {"payer": payer, "status": status, "limit": limit}
    return rpc.call("tenzro_listPlans", {k: v for k, v in fields.items() if v is not None})


__all__ = [
    "LegReceipt",
    "PLAN_STATUSES",
    "PlanDecision",
    "PlanList",
    "PlanView",
    "ProofKey",
    "get_leg_receipt",
    "get_plan",
    "get_plan_decision",
    "list_plans",
]
