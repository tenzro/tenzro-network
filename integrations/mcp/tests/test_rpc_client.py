"""Tests for tenzro_mcp_server.rpc_client — request shaping, auth headers,
error propagation, and the REST wrapper. httpx.AsyncClient is fully mocked;
no network calls are made."""

from unittest.mock import AsyncMock, MagicMock

import pytest

import tenzro_mcp_server.rpc_client as rpc_client
from tenzro_mcp_server.rpc_client import api_call, rpc_call

AUTH_ENV_VARS = ("TENZRO_BEARER_JWT", "TENZRO_DPOP_PROOF", "TENZRO_API_KEY")


class FakeAsyncClient:
    """Stands in for httpx.AsyncClient; records post/get calls."""

    last_instance = None

    def __init__(self, response_payload, **kwargs):
        self.init_kwargs = kwargs
        response = MagicMock()
        response.json = MagicMock(return_value=response_payload)
        self.post = AsyncMock(return_value=response)
        self.get = AsyncMock(return_value=response)
        FakeAsyncClient.last_instance = self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc_info):
        return False


@pytest.fixture
def clean_auth_env(monkeypatch):
    for var in AUTH_ENV_VARS:
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def fake_http(monkeypatch, clean_auth_env):
    """Patch httpx.AsyncClient inside rpc_client; returns a setter for the
    canned response payload and exposes the captured client."""

    state = {"payload": {"jsonrpc": "2.0", "id": 1, "result": "0x1"}}

    def factory(**kwargs):
        return FakeAsyncClient(state["payload"], **kwargs)

    monkeypatch.setattr(rpc_client.httpx, "AsyncClient", factory)

    def set_payload(payload):
        state["payload"] = payload

    return set_payload


def _post_call():
    client = FakeAsyncClient.last_instance
    assert client is not None
    return client.post.await_args


# ---------------------------------------------------------------------------
# rpc_call — JSON-RPC 2.0 envelope shaping
# ---------------------------------------------------------------------------


async def test_rpc_call_sends_jsonrpc2_envelope(fake_http):
    await rpc_call("eth_blockNumber")
    args, kwargs = _post_call()
    assert args[0] == rpc_client.TENZRO_RPC_URL
    body = kwargs["json"]
    assert body["jsonrpc"] == "2.0"
    assert body["method"] == "eth_blockNumber"
    assert body["params"] == []
    assert isinstance(body["id"], int)


async def test_rpc_call_passes_list_params(fake_http):
    await rpc_call("eth_getBalance", ["0xabc", "latest"])
    _, kwargs = _post_call()
    assert kwargs["json"]["params"] == ["0xabc", "latest"]


async def test_rpc_call_passes_dict_params(fake_http):
    params = {"address": "0xabc", "amount": "100"}
    await rpc_call("tenzro_faucet", params)
    _, kwargs = _post_call()
    assert kwargs["json"]["params"] == params


async def test_rpc_call_none_params_become_empty_list(fake_http):
    await rpc_call("tenzro_totalSupply", None)
    _, kwargs = _post_call()
    assert kwargs["json"]["params"] == []


async def test_rpc_call_request_id_increments(fake_http):
    await rpc_call("eth_blockNumber")
    _, kwargs1 = _post_call()
    await rpc_call("eth_blockNumber")
    _, kwargs2 = _post_call()
    assert kwargs2["json"]["id"] == kwargs1["json"]["id"] + 1


async def test_rpc_call_returns_result_field(fake_http):
    fake_http({"jsonrpc": "2.0", "id": 7, "result": {"height": 42}})
    assert await rpc_call("tenzro_getNodeStatus") == {"height": 42}


async def test_rpc_call_missing_result_returns_none(fake_http):
    fake_http({"jsonrpc": "2.0", "id": 7})
    assert await rpc_call("tenzro_getNodeStatus") is None


# ---------------------------------------------------------------------------
# rpc_call — error propagation
# ---------------------------------------------------------------------------


async def test_rpc_call_raises_on_error_with_message(fake_http):
    fake_http({"jsonrpc": "2.0", "id": 1,
               "error": {"code": -32003, "message": "invalid signature"}})
    with pytest.raises(Exception, match="RPC error: invalid signature"):
        await rpc_call("eth_sendRawTransaction", ["0xdead"])


async def test_rpc_call_raises_unknown_on_error_without_message(fake_http):
    fake_http({"jsonrpc": "2.0", "id": 1, "error": {"code": -32600}})
    with pytest.raises(Exception, match="RPC error: unknown"):
        await rpc_call("eth_blockNumber")


async def test_rpc_call_null_error_is_not_an_error(fake_http):
    fake_http({"jsonrpc": "2.0", "id": 1, "error": None, "result": "0x2a"})
    assert await rpc_call("eth_blockNumber") == "0x2a"


# ---------------------------------------------------------------------------
# rpc_call — auth header handling
# ---------------------------------------------------------------------------


async def test_rpc_call_default_headers_no_auth(fake_http):
    await rpc_call("eth_blockNumber")
    _, kwargs = _post_call()
    headers = kwargs["headers"]
    assert headers == {"Content-Type": "application/json"}


async def test_rpc_call_bearer_jwt_header(fake_http, monkeypatch):
    monkeypatch.setenv("TENZRO_BEARER_JWT", "jwt-abc")
    await rpc_call("tenzro_signMessage", {"message_hex": "00"})
    _, kwargs = _post_call()
    assert kwargs["headers"]["Authorization"] == "DPoP jwt-abc"


async def test_rpc_call_dpop_proof_header(fake_http, monkeypatch):
    monkeypatch.setenv("TENZRO_DPOP_PROOF", "proof-xyz")
    await rpc_call("tenzro_signMessage", {"message_hex": "00"})
    _, kwargs = _post_call()
    assert kwargs["headers"]["DPoP"] == "proof-xyz"


async def test_rpc_call_api_key_header(fake_http, monkeypatch):
    monkeypatch.setenv("TENZRO_API_KEY", "tnz_key123")
    await rpc_call("tenzro_listCantonDomains", {})
    _, kwargs = _post_call()
    assert kwargs["headers"]["X-Tenzro-Api-Key"] == "tnz_key123"


async def test_rpc_call_all_auth_headers_together(fake_http, monkeypatch):
    monkeypatch.setenv("TENZRO_BEARER_JWT", "jwt-abc")
    monkeypatch.setenv("TENZRO_DPOP_PROOF", "proof-xyz")
    monkeypatch.setenv("TENZRO_API_KEY", "tnz_key123")
    await rpc_call("tenzro_canton_health", {})
    _, kwargs = _post_call()
    headers = kwargs["headers"]
    assert headers["Content-Type"] == "application/json"
    assert headers["Authorization"] == "DPoP jwt-abc"
    assert headers["DPoP"] == "proof-xyz"
    assert headers["X-Tenzro-Api-Key"] == "tnz_key123"


async def test_rpc_call_empty_env_values_omit_headers(fake_http, monkeypatch):
    monkeypatch.setenv("TENZRO_BEARER_JWT", "")
    monkeypatch.setenv("TENZRO_DPOP_PROOF", "")
    monkeypatch.setenv("TENZRO_API_KEY", "")
    await rpc_call("eth_blockNumber")
    _, kwargs = _post_call()
    assert kwargs["headers"] == {"Content-Type": "application/json"}


# ---------------------------------------------------------------------------
# api_call — REST wrapper
# ---------------------------------------------------------------------------


async def test_api_call_get(fake_http):
    fake_http({"status": "healthy"})
    result = await api_call("/health")
    client = FakeAsyncClient.last_instance
    args, _ = client.get.await_args
    assert args[0] == f"{rpc_client.TENZRO_API_URL}/health"
    client.post.assert_not_awaited()
    assert result == {"status": "healthy"}


async def test_api_call_post_with_body(fake_http):
    fake_http({"valid": True})
    body = {"proof_bytes": "00ff", "circuit_id": "inference"}
    result = await api_call("/verify/zk-proof", "POST", body)
    client = FakeAsyncClient.last_instance
    args, kwargs = client.post.await_args
    assert args[0] == f"{rpc_client.TENZRO_API_URL}/verify/zk-proof"
    assert kwargs["json"] == body
    client.get.assert_not_awaited()
    assert result == {"valid": True}


async def test_api_call_post_without_body_sends_none(fake_http):
    await api_call("/faucet", "POST")
    client = FakeAsyncClient.last_instance
    _, kwargs = client.post.await_args
    assert kwargs["json"] is None


async def test_api_call_non_post_method_falls_back_to_get(fake_http):
    fake_http({"ok": True})
    await api_call("/status", "DELETE")
    client = FakeAsyncClient.last_instance
    client.get.assert_awaited_once()
    client.post.assert_not_awaited()
