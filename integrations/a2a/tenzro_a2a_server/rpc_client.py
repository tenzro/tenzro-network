"""Async JSON-RPC and REST client for Tenzro node communication."""

import httpx
import os

TENZRO_RPC_URL = os.environ.get("TENZRO_RPC_URL", "https://rpc.tenzro.network")
TENZRO_API_URL = os.environ.get("TENZRO_API_URL", "https://api.tenzro.network")
_REQUEST_ID = 0


async def rpc_call(method: str, params=None):
    """Send a JSON-RPC 2.0 request to the Tenzro node."""
    global _REQUEST_ID
    _REQUEST_ID += 1
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(
            TENZRO_RPC_URL,
            json={
                "jsonrpc": "2.0",
                "id": _REQUEST_ID,
                "method": method,
                "params": params or [],
            },
        )
        data = r.json()
        if "error" in data and data["error"]:
            raise Exception(
                f"RPC error: {data['error'].get('message', 'unknown')}"
            )
        return data.get("result")


async def api_call(path: str, method: str = "GET", body: dict = None):
    """Send an HTTP request to the Tenzro Web API."""
    async with httpx.AsyncClient(timeout=30) as client:
        url = f"{TENZRO_API_URL}{path}"
        if method == "POST":
            r = await client.post(url, json=body)
        else:
            r = await client.get(url)
        return r.json()
