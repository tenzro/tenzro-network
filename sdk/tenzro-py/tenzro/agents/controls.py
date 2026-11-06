"""Agent controls a controller and anyone else can read: the kill-switch
receipts written when a controller freezes, pauses or revokes an agent, and
an agent's quarantine state."""

from __future__ import annotations

from typing import Any, Optional, TypedDict

from ..rpc import RpcClient


class KillSwitchReceipt(TypedDict):
    """A kill-switch receipt as the node stores it. ``timestamp`` is Unix
    milliseconds; ``frozen_at_block`` is the height it took effect at."""

    receipt_id: str
    action: str
    agent_did: str
    controller_did: str
    reason_code: int
    reason_text: Optional[str]
    evidence_hash: Optional[str]
    slash_bps: Optional[int]
    cascade: Optional[bool]
    frozen_at_block: int
    timestamp: int


class ListedKillSwitchReceipt(KillSwitchReceipt):
    """A receipt in a list, with the event cursor of the log that created it."""

    cursor: str


class KillSwitchPage(TypedDict, total=False):
    """One page of receipts in chain order. Pass ``cursor`` back as
    ``from_cursor`` to continue with no gap; it is ``None`` at the end of
    what the node holds. The page also names the ``agent_did`` or
    ``controller_did`` it was asked for."""

    agent_did: str
    controller_did: str
    receipts: list[ListedKillSwitchReceipt]
    cursor: Optional[str]


class AgentQuarantine(TypedDict):
    """``tenzro_getAgentQuarantine``: whether the chain holds the agent in
    quarantine (``on_chain`` is the record, or ``None``) and the node's
    guardrail status for it."""

    agent_did: str
    quarantined: bool
    on_chain: Optional[dict[str, Any]]
    guardrails: Any


def _page(
    *,
    from_cursor: Optional[str],
    from_height: Optional[int],
    to_cursor: Optional[str],
    limit: Optional[int],
) -> dict[str, Any]:
    if from_cursor is not None and from_height is not None:
        raise ValueError("give from_cursor or from_height, not both")
    fields = {"from_cursor": from_cursor, "from_height": from_height, "to_cursor": to_cursor, "limit": limit}
    return {k: v for k, v in fields.items() if v is not None}


def kill_switch_receipt(rpc: RpcClient, receipt_id: str) -> Optional[KillSwitchReceipt]:
    """One receipt (32-byte hex id), or ``None`` when the chain holds none."""
    return rpc.call("tenzro_getKillSwitchReceipt", {"receipt_id": receipt_id})


def kill_switches_by_agent(
    rpc: RpcClient,
    agent_did: str,
    *,
    from_cursor: Optional[str] = None,
    from_height: Optional[int] = None,
    to_cursor: Optional[str] = None,
    limit: Optional[int] = None,
) -> KillSwitchPage:
    """Every kill-switch receipt naming ``agent_did``, in chain order, a page at a time."""
    params = {"agent_did": agent_did, **_page(from_cursor=from_cursor, from_height=from_height, to_cursor=to_cursor, limit=limit)}
    return rpc.call("tenzro_listKillSwitchByAgent", params)


def kill_switches_by_controller(
    rpc: RpcClient,
    controller_did: str,
    *,
    from_cursor: Optional[str] = None,
    from_height: Optional[int] = None,
    to_cursor: Optional[str] = None,
    limit: Optional[int] = None,
) -> KillSwitchPage:
    """Every kill-switch receipt ``controller_did`` wrote, in chain order, a page at a time."""
    params = {
        "controller_did": controller_did,
        **_page(from_cursor=from_cursor, from_height=from_height, to_cursor=to_cursor, limit=limit),
    }
    return rpc.call("tenzro_listKillSwitchByController", params)


def agent_quarantine(rpc: RpcClient, agent_did: str) -> AgentQuarantine:
    """Whether ``agent_did`` is quarantined, and its guardrail status."""
    return rpc.call("tenzro_getAgentQuarantine", {"agent_did": agent_did})


__all__ = [
    "AgentQuarantine",
    "KillSwitchPage",
    "KillSwitchReceipt",
    "ListedKillSwitchReceipt",
    "agent_quarantine",
    "kill_switch_receipt",
    "kill_switches_by_agent",
    "kill_switches_by_controller",
]
