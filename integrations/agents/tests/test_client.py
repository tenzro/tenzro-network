"""TenzroClient transport tests using a stub httpx transport (no network)."""

from __future__ import annotations

import json

import httpx

from tenzro_agents.core import ReputationHook, TenzroClient


def _stub_client(handler):
    transport = httpx.MockTransport(handler)
    return httpx.Client(transport=transport)


def test_call_sends_jsonrpc_and_returns_result():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {"ok": True}})

    client = TenzroClient(
        rpc_url="https://node.example/rpc", client=_stub_client(handler)
    )
    result = client.post_task({"kind": "research"})
    assert result == {"ok": True}
    assert seen["body"]["method"] == "tenzro_postTask"
    assert seen["body"]["jsonrpc"] == "2.0"
    assert seen["body"]["params"] == {"kind": "research"}


def test_validate_mandate_pair_uses_dispatched_wire_name():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {"valid": True}})

    client = TenzroClient(client=_stub_client(handler))
    client.validate_mandate_pair({"mandate_id": "c"}, {"mandate_id": "p"})
    # Must be the name the node actually dispatches in rpc.rs.
    assert seen["body"]["method"] == "tenzro_ap2ValidateMandatePair"


def test_reputation_hook_submits_feedback():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": "0xfeedback"})

    client = TenzroClient(client=_stub_client(handler))
    hook = ReputationHook(client, subject_agent_id=0x4A2)
    hook.on_finish("success", context_uri="run-1")

    body = seen["body"]
    assert body["method"] == "tenzro_erc8004EncodeFeedback"
    assert body["params"]["subject_agent_id"] == 0x4A2
    assert body["params"]["rating"] == 1
    assert body["params"]["context_uri"] == "run-1"


def test_rpc_error_raises():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"jsonrpc": "2.0", "id": 1, "error": {"code": -32001, "message": "nope"}},
        )

    client = TenzroClient(client=_stub_client(handler))
    raised = False
    try:
        client.post_task({})
    except Exception as exc:  # TenzroRpcError
        raised = True
        assert "nope" in str(exc)
    assert raised


def test_call_signed_attaches_envelope():
    import nacl.signing

    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": "ok"})

    sk = nacl.signing.SigningKey.generate()
    client = TenzroClient(
        client=_stub_client(handler),
        signing_key=sk,
        did="did:tenzro:machine:0x1",
    )
    client.call_signed("tenzro_postTask", {"kind": "x"})
    env = seen["body"]["params"]["tenzro_did_envelope"]
    assert env["did"] == "did:tenzro:machine:0x1"
    assert env["method"] == "tenzro_postTask"
    assert len(bytes.fromhex(env["signature"])) == 64
