"""Async JSON-RPC and REST client for Tenzro node communication."""

import os

import httpx

TENZRO_RPC_URL = os.environ.get("TENZRO_RPC_URL", "https://rpc.tenzro.xyz")
TENZRO_API_URL = os.environ.get("TENZRO_API_URL", "https://api.tenzro.xyz")
_REQUEST_ID = 0


def _is_canton_method(method: str) -> bool:
    """Whether a JSON-RPC method carries a Canton scope.

    Matches how the node decides: any `tenzro_` method naming Canton or
    DAML, in either the CamelCase (`tenzro_listCantonDomains`) or
    snake-case (`tenzro_canton_health`) form.
    """
    return method.startswith("tenzro_") and (
        "Canton" in method
        or "canton" in method
        or "Daml" in method
        or "daml" in method
    )


async def rpc_call(method: str, params=None):
    """Send a JSON-RPC 2.0 request to the Tenzro node.

    Auth-sensitive RPCs (signing, escrow, settlement) require an OAuth/DPoP
    bearer JWT. Set TENZRO_BEARER_JWT and TENZRO_DPOP_PROOF; both are
    forwarded as `Authorization: DPoP <jwt>` and `DPoP: <proof>` headers.
    Public RPCs work without auth.

    Scope-gated RPCs (currently `tenzro_*Canton*`) require an operator-
    issued API key. Set TENZRO_API_KEY to the `tnz_<base64url>` key; it is
    forwarded as the `X-Tenzro-Api-Key` header. The RPC node holds the
    upstream credentials (Auth0 for Canton devnet) and proxies on the
    caller's behalf.

    Operator-only RPCs (e.g. MPC keygen) require the node admin token. Set
    TENZRO_ADMIN_TOKEN; it is forwarded as the `X-Tenzro-Admin-Token` header.

    Canton-scoped RPCs additionally take a network. Set
    TENZRO_CANTON_NETWORK to `devnet` or `mainnet` and it is merged into
    the params as `canton_network` — the node reads the choice from the
    params rather than a header. A key authorizing exactly one network
    needs no setting; a key authorizing several does, and the node names
    the authorized set when the choice is missing.
    """
    global _REQUEST_ID
    _REQUEST_ID += 1
    headers = {"Content-Type": "application/json"}
    bearer = os.environ.get("TENZRO_BEARER_JWT")
    if bearer:
        headers["Authorization"] = f"DPoP {bearer}"
    dpop = os.environ.get("TENZRO_DPOP_PROOF")
    if dpop:
        headers["DPoP"] = dpop
    api_key = os.environ.get("TENZRO_API_KEY")
    if api_key:
        headers["X-Tenzro-Api-Key"] = api_key
    admin_token = os.environ.get("TENZRO_ADMIN_TOKEN")
    if admin_token:
        headers["X-Tenzro-Admin-Token"] = admin_token
    call_params = params if params is not None else []
    canton_network = os.environ.get("TENZRO_CANTON_NETWORK")
    if (
        canton_network
        and _is_canton_method(method)
        and isinstance(call_params, dict)
        and "canton_network" not in call_params
    ):
        call_params = {**call_params, "canton_network": canton_network}
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(
            TENZRO_RPC_URL,
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": _REQUEST_ID,
                "method": method,
                "params": call_params,
            },
        )
        data = r.json()
        if data.get("error"):
            raise Exception(
                f"RPC error: {data['error'].get('message', 'unknown')}"
            )
        return data.get("result")


async def api_call(path: str, method: str = "GET", body: dict | None = None):
    """Send an HTTP request to the Tenzro Web API."""
    async with httpx.AsyncClient(timeout=30) as client:
        url = f"{TENZRO_API_URL}{path}"
        if method == "POST":
            r = await client.post(url, json=body)
        else:
            r = await client.get(url)
        return r.json()
