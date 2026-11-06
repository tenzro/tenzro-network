"""Discovery keeps only endpoints that agree on the chain's history."""

import httpx
import pytest

from tenzro.network import NetworkRpcClient, discover_endpoints

CHAIN = 1337


def node(digest: str, latest: int = 9, listed: list[dict] | None = None, chain: int = CHAIN):
    def handler(request: httpx.Request) -> httpx.Response:
        body = __import__("json").loads(request.content)
        method, params = body["method"], body["params"]
        if method == "tenzro_listRoleEndpoints":
            result = {"role": "rpc", "endpoints": listed or []}
        elif method == "eth_chainId":
            result = hex(chain)
        elif method == "tenzro_getCheckpointCertificate":
            index = params.get("index", latest)
            result = {"index": index, "digest": f"{digest}-{index}"}
        else:
            result = None
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": result})

    return handler


def test_an_endpoint_with_another_history_or_chain_is_dropped(monkeypatch):
    listed = [
        {"account": "0x01", "url": "https://a.example", "bonded": "2"},
        {"account": "0x02", "url": "https://b.example", "bonded": "1"},
        {"account": "0x03", "url": "https://liar.example", "bonded": "1"},
        {"account": "0x04", "url": "https://other.example", "bonded": "1"},
    ]
    nodes = {
        "https://seed.example": node("good", listed=listed),
        "https://a.example": node("good", latest=12),
        "https://b.example": node("good"),
        "https://liar.example": node("forged"),
        "https://other.example": node("good", chain=1),
    }

    def route(request: httpx.Request) -> httpx.Response:
        return nodes[f"{request.url.scheme}://{request.url.host}"](request)

    real = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda **kw: real(transport=httpx.MockTransport(route), **kw))
    found = discover_endpoints(["https://seed.example"], CHAIN)
    assert [e.url for e in found] == ["https://a.example", "https://b.example", "https://seed.example"]
    assert {e.checkpoint_index for e in found} == {9}


def test_the_first_seed_down_discovery_succeeds_through_the_next(monkeypatch):
    nodes = {"https://live.example": node("good")}

    def route(request: httpx.Request) -> httpx.Response:
        url = f"{request.url.scheme}://{request.url.host}"
        if url not in nodes:
            raise httpx.ConnectError("unreachable", request=request)
        return nodes[url](request)

    real = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda **kw: real(transport=httpx.MockTransport(route), **kw))
    found = discover_endpoints(["https://down.example", "https://live.example"], CHAIN)
    assert [e.url for e in found] == ["https://live.example"]
    with pytest.raises(ConnectionError):
        discover_endpoints(["https://down.example"], CHAIN)


def test_a_network_client_needs_an_endpoint():
    with pytest.raises(ValueError):
        NetworkRpcClient([])
