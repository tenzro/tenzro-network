"""Every generated binding, on the synchronous and the asynchronous client,
calls its own RPC method with the params it is given."""

import asyncio
import importlib.util
import json
from pathlib import Path

import httpx
import pytest

from tenzro import METHODS, AsyncRpcClient, RpcClient

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("generate_methods", ROOT / "tools" / "generate_methods.py")
_gen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_gen)

PARAMS = {"probe": [1, "two", None]}


def _recorder(seen):
    def handle(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        seen.append(body)
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": {"echo": body["method"]}})

    return handle


@pytest.mark.parametrize("method", sorted(METHODS))
def test_the_binding_calls_its_method(method):
    name = _gen.snake(method)
    seen = []
    client = RpcClient("http://node.test", transport=httpx.MockTransport(_recorder(seen)))
    assert getattr(client, name)(PARAMS) == {"echo": method}
    assert seen[-1]["method"] == method and seen[-1]["params"] == PARAMS

    async def run():
        seen_async = []
        async_client = AsyncRpcClient("http://node.test", transport=httpx.MockTransport(_recorder(seen_async)))
        assert await getattr(async_client, name)(PARAMS) == {"echo": method}
        assert seen_async[-1]["method"] == method and seen_async[-1]["params"] == PARAMS

    asyncio.run(run())
