"""Typed reads: the admin audit log, agent controls and settlement plans send
the params the node reads and return its answer unchanged; a light-build
refusal is recognised."""

import json

import httpx
import pytest

from tenzro import RpcClient, RpcError
from tenzro.admin import audit_filter, audit_log, verify_audit_log
from tenzro.agents import agent_quarantine, kill_switch_receipt, kill_switches_by_agent, kill_switches_by_controller
from tenzro.settlement import get_leg_receipt, get_plan, get_plan_decision, list_plans

ID = "ab" * 32


def node(answer):
    """A client whose node records each request and answers ``answer``."""
    seen = []

    def handle(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        seen.append(body)
        if isinstance(answer, dict) and "error" in answer:
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "error": answer["error"]})
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": answer})

    return RpcClient("http://node.test", transport=httpx.MockTransport(handle)), seen


def test_audit_log_sends_only_the_filter_given():
    page = {"count": 1, "records": [{"record": {"seq": 0, "entry": {"kind": "opened", "data": {}}}, "hash": "aa"}]}
    rpc, seen = node(page)
    assert audit_log(rpc, method="tenzro_stopModel", since=1700000000000, limit=5) == page
    assert seen[0]["method"] == "tenzro_listAdminAudit"
    assert seen[0]["params"] == {"method": "tenzro_stopModel", "since": 1700000000000, "limit": 5}
    assert audit_filter() == {}
    with pytest.raises(ValueError):
        audit_filter(limit=1001)


def test_verify_audit_log_returns_the_verification():
    v = {
        "ok": True,
        "records": 3,
        "segments": ["audit.log"],
        "first_seq": 0,
        "last_seq": 2,
        "head_hash": "cc",
        "checkpoints": 1,
        "signed_checkpoints": 1,
        "unsigned_checkpoints": 0,
        "problems": [],
    }
    rpc, seen = node(v)
    assert verify_audit_log(rpc)["ok"] is True
    assert seen[0]["method"] == "tenzro_verifyAdminAudit" and seen[0]["params"] == {}


RECEIPT = {
    "receipt_id": ID,
    "action": "freeze",
    "agent_did": "did:tenzro:agent:a",
    "controller_did": "did:tenzro:human:c",
    "reason_code": 3,
    "reason_text": None,
    "evidence_hash": None,
    "slash_bps": None,
    "cascade": None,
    "frozen_at_block": 12,
    "timestamp": 1700000000000,
}


def test_kill_switch_reads_page_with_from_cursor():
    rpc, seen = node({"agent_did": "did:tenzro:agent:a", "receipts": [dict(RECEIPT, cursor="12:0:1")], "cursor": "12:0:1"})
    page = kill_switches_by_agent(rpc, "did:tenzro:agent:a", from_cursor="10:0:0", limit=10)
    assert page["receipts"][0]["frozen_at_block"] == 12
    assert seen[0]["method"] == "tenzro_listKillSwitchByAgent"
    assert seen[0]["params"] == {"agent_did": "did:tenzro:agent:a", "from_cursor": "10:0:0", "limit": 10}
    kill_switches_by_controller(rpc, "did:tenzro:human:c", from_height=5)
    assert seen[1]["method"] == "tenzro_listKillSwitchByController"
    assert seen[1]["params"] == {"controller_did": "did:tenzro:human:c", "from_height": 5}
    with pytest.raises(ValueError):
        kill_switches_by_agent(rpc, "did:tenzro:agent:a", from_cursor="1:0:0", from_height=1)


def test_kill_switch_receipt_and_quarantine():
    rpc, seen = node(RECEIPT)
    assert kill_switch_receipt(rpc, ID)["action"] == "freeze"
    assert seen[0]["method"] == "tenzro_getKillSwitchReceipt" and seen[0]["params"] == {"receipt_id": ID}
    rpc, seen = node({"agent_did": "did:tenzro:agent:a", "quarantined": False, "on_chain": None, "guardrails": {}})
    assert agent_quarantine(rpc, "did:tenzro:agent:a")["quarantined"] is False
    assert seen[0]["method"] == "tenzro_getAgentQuarantine" and seen[0]["params"] == {"agent_did": "did:tenzro:agent:a"}


def test_plan_reads_send_the_node_params():
    proof = {"namespace": "state", "key": "00"}
    rpc, seen = node({"plan": {}, "split_hash": "11", "leg_ids": [], "vault": "22", "proof": proof})
    get_plan(rpc, ID)
    get_plan_decision(rpc, ID)
    get_leg_receipt(rpc, plan_id=ID, index=2)
    get_leg_receipt(rpc, leg_id=ID)
    list_plans(rpc, status="open", limit=3)
    assert [s["method"] for s in seen] == [
        "tenzro_getPlan",
        "tenzro_getPlanDecision",
        "tenzro_getLegReceipt",
        "tenzro_getLegReceipt",
        "tenzro_listPlans",
    ]
    assert [s["params"] for s in seen] == [
        {"plan_id": ID},
        {"plan_id": ID},
        {"plan_id": ID, "index": 2},
        {"leg_id": ID},
        {"status": "open", "limit": 3},
    ]
    for bad in ({}, {"plan_id": ID}, {"plan_id": ID, "index": 16}, {"leg_id": ID, "index": 0}):
        with pytest.raises(ValueError):
            get_leg_receipt(rpc, **bad)
    with pytest.raises(ValueError):
        list_plans(rpc, status="pending")


def test_the_light_build_refusal_is_recognised():
    rpc, _ = node({"error": {"code": -32004, "message": "tenzro_chat needs a model on this node", "data": {"build": "light"}}})
    with pytest.raises(RpcError) as e:
        rpc.call("tenzro_chat", {"model_id": "m"})
    assert e.value.light_build
    rpc, _ = node({"error": {"code": -32004, "message": "no escrow 0x01"}})
    with pytest.raises(RpcError) as e:
        rpc.call("tenzro_getEscrow", {"escrow_id": ID})
    assert not e.value.light_build
