"""The client carries every method the node serves, generated from its method table."""

import importlib.util
import json
from pathlib import Path

import httpx
import pytest

import tenzro
from tenzro import METHODS, AccessCredential, AsyncRpcClient, RpcClient, RpcError

ROOT = Path(__file__).resolve().parents[1]


def _generator():
    spec = importlib.util.spec_from_file_location("generate_methods", ROOT / "tools" / "generate_methods.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_the_generated_module_is_current():
    gen = _generator()
    assert (ROOT / "tenzro" / "_methods.py").read_text(encoding="utf-8") == gen.generate(), "run python tools/generate_methods.py"


def test_every_method_has_a_typed_binding_on_both_clients():
    gen = _generator()
    assert len(METHODS) > 400
    for method in METHODS:
        name = gen.snake(method)
        assert callable(getattr(RpcClient, name)), method
        assert callable(getattr(AsyncRpcClient, name)), method


def _transport(seen, answer):
    def handle(request: httpx.Request) -> httpx.Response:
        seen.append((dict(request.headers), json.loads(request.content)))
        return httpx.Response(200, json=answer)

    return handle


def test_a_typed_method_calls_its_rpc_method_with_the_params_unchanged(monkeypatch):
    monkeypatch.delenv("TENZRO_BEARER_JWT", raising=False)
    monkeypatch.delenv("TENZRO_DPOP_PROOF", raising=False)
    seen = []
    client = RpcClient("http://node.test", transport=httpx.MockTransport(_transport(seen, {"jsonrpc": "2.0", "id": 1, "result": "0x5"})))
    assert client.get_balance(["0xab"]) == "0x5"
    headers, body = seen[0]
    assert body["method"] == "tenzro_getBalance" and body["params"] == ["0xab"]
    assert "authorization" not in headers
    assert client.solana_get_slot() == "0x5"
    assert seen[1][1]["method"] == "getSlot" and seen[1][1]["params"] == []


def test_an_rpc_error_is_raised_with_its_code():
    seen = []
    answer = {"jsonrpc": "2.0", "id": 1, "error": {"code": -32601, "message": "no such method", "data": {"x": 1}}}
    client = RpcClient("http://node.test", transport=httpx.MockTransport(_transport(seen, answer)))
    with pytest.raises(RpcError) as e:
        client.call("tenzro_nothing")
    assert e.value.code == -32601 and e.value.data == {"x": 1}


def test_a_credential_carries_a_fresh_dpop_proof_per_request():
    class Prover:
        def __init__(self):
            self.calls = []

        def jkt(self):
            return "jkt"

        def proof(self, htm, htu, token):
            self.calls.append((htm, htu, token))
            return f"proof-{len(self.calls)}"

    prover = Prover()
    seen = []
    client = RpcClient(
        "http://node.test/rpc?x=1",
        credential=AccessCredential(token="tok", prover=prover),
        transport=httpx.MockTransport(_transport(seen, {"jsonrpc": "2.0", "id": 1, "result": None})),
    )
    client.chat({"x": 1})
    client.chat({"x": 2})
    assert [h["authorization"] for h, _ in seen] == ["DPoP tok", "DPoP tok"]
    assert [h["dpop"] for h, _ in seen] == ["proof-1", "proof-2"]
    assert prover.calls[0] == ("POST", "http://node.test/rpc", "tok")


def test_the_async_client_calls_the_same_method():
    import asyncio

    seen = []

    async def run():
        async with AsyncRpcClient(
            "http://node.test",
            transport=httpx.MockTransport(_transport(seen, {"jsonrpc": "2.0", "id": 1, "result": 7})),
        ) as client:
            return await client.get_finalized_block()

    assert asyncio.run(run()) == 7
    assert seen[0][1]["method"] == "tenzro_getFinalizedBlock"


def test_the_update_notice_read_sends_its_etag():
    seen = []
    answer = {"jsonrpc": "2.0", "id": 1, "result": {"unchanged": True, "etag": "ab"}}
    client = RpcClient("http://node.test", transport=httpx.MockTransport(_transport(seen, answer)))
    assert client.get_update_notice([{"if_none_match": "ab"}])["unchanged"] is True
    assert seen[0][1]["method"] == "tenzro_getUpdateNotice"
    assert seen[0][1]["params"] == [{"if_none_match": "ab"}]


def test_the_package_exports_its_surface():
    for name in tenzro.__all__:
        assert hasattr(tenzro, name), name


def test_a_refresh_proves_its_key_and_presents_no_token():
    """``call_with_proof`` carries a DPoP proof and no Authorization header."""
    import httpx

    from tenzro.rpc import AccessCredential, RpcClient

    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {"refresh_token": "next"}})

    class Prover:
        def jkt(self) -> str:
            return "jkt"

        def proof(self, htm: str, htu: str, access_token: str) -> str:
            return f"{htm} {htu} {access_token}"

    client = RpcClient(
        "http://node.test/",
        credential=AccessCredential(token="signed-in", prover=Prover()),
        transport=httpx.MockTransport(handler),
    )
    out = client.call_with_proof("tenzro_refreshToken", {"refresh_token": "r1"}, Prover())
    assert out == {"refresh_token": "next"}
    assert "authorization" not in seen[0].headers
    assert seen[0].headers["dpop"] == "POST http://node.test/ "
