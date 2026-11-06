"""Reaching the network rather than one node.

RPC operators bond the ``rpc`` role and publish the public URL they serve it
at in consensus state, so every node answers the same list
(``tenzro_listRoleEndpoints``). :func:`discover_endpoints` asks a few seeds for
that list and keeps the operators that answer for the expected chain and agree
on its history; :class:`NetworkRpcClient` moves between them when one cannot
be reached. A seed is only a way in, never an authority.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any

import httpx

from ._methods import Params
from .rpc import RpcClient, RpcError


@dataclass(frozen=True)
class NetworkPreset:
    """A named Tenzro network: its chain id and the public endpoints it serves."""

    name: str
    chain_id: int
    rpc: str
    api: str
    mcp: str
    a2a: str
    relay: str


#: The Tenzro preview network.
PREVIEW_NETWORK = NetworkPreset(
    name="preview",
    chain_id=13380,
    rpc="https://rpc.tenzro.com",
    api="https://api.tenzro.com",
    mcp="https://mcp.tenzro.com/mcp",
    a2a="https://a2a.tenzro.com",
    relay="https://relay.tenzro.com",
)

#: The chain id the SDK expects by default: :data:`PREVIEW_NETWORK`'s.
NETWORK_CHAIN_ID = PREVIEW_NETWORK.chain_id

#: Bootstrap hints for finding the network's staked RPC operators. A seed is a
#: way in, never an authority: the client asks every seed for the on-chain
#: operator list, keeps only the endpoints that report :data:`NETWORK_CHAIN_ID`
#: and agree on a checkpoint digest, and from then on talks to those operators.
#: Pass your own ``seeds`` to start from any node.
NETWORK_SEEDS: tuple[str, ...] = (PREVIEW_NETWORK.rpc,)


@dataclass(frozen=True)
class CheckedEndpoint:
    """An endpoint that passed the checks."""

    url: str
    account: str | None
    checkpoint_index: int
    checkpoint_digest: str


def _post(http: httpx.Client, url: str, method: str, params: Any) -> Any:
    response = http.post(url, json={"jsonrpc": "2.0", "method": method, "params": params, "id": 1})
    response.raise_for_status()
    body = response.json()
    if body.get("error"):
        err = body["error"]
        raise RpcError(err.get("code", 0), err.get("message", ""), err.get("data"))
    return body.get("result")


def discover_endpoints(
    seeds: list[str] | tuple[str, ...] = NETWORK_SEEDS,
    chain_id: int = NETWORK_CHAIN_ID,
    *,
    role: str = "rpc",
    timeout: float = 10.0,
) -> list[CheckedEndpoint]:
    """Find the staked operators of ``role`` and keep those that agree.

    Every seed is asked for the operator list and the lists are merged; each
    candidate (and each seed) must report ``chain_id``; all are compared at
    the lowest checkpoint they all hold, and only those reporting the most
    common digest there are kept. Most bonded first, seeds last.
    """
    candidates: dict[str, str | None] = {}
    with httpx.Client(timeout=timeout) as http:
        for seed in seeds:
            try:
                listed = _post(http, seed, "tenzro_listRoleEndpoints", {"role": role})
            except (httpx.HTTPError, RpcError, ValueError):
                continue
            for e in listed.get("endpoints", []):
                candidates.setdefault(e["url"], e.get("account"))
        for seed in seeds:
            candidates.setdefault(seed, None)

        expected = hex(chain_id)
        latest: dict[str, int] = {}
        for url in candidates:
            try:
                if str(_post(http, url, "eth_chainId", [])).lower() != expected:
                    continue
                latest[url] = int(_post(http, url, "tenzro_getCheckpointCertificate", {})["index"])
            except (httpx.HTTPError, RpcError, ValueError, KeyError, TypeError):
                continue
        if not latest:
            raise ConnectionError(f"no endpoint answered for chain {chain_id}")
        index = min(latest.values())

        groups: dict[str, list[CheckedEndpoint]] = defaultdict(list)
        for url in latest:
            try:
                digest = _post(http, url, "tenzro_getCheckpointCertificate", {"index": index})["digest"]
            except (httpx.HTTPError, RpcError, ValueError, KeyError, TypeError):
                continue
            groups[digest].append(CheckedEndpoint(url, candidates[url], index, digest))
    if not groups:
        raise ConnectionError(f"no endpoint could be compared at checkpoint {index}")
    order = list(candidates)
    return sorted(max(groups.values(), key=len), key=lambda e: order.index(e.url))


class NetworkRpcClient(RpcClient):
    """A client over several endpoints of one network.

    Each call goes to the current endpoint and moves to the next when it
    cannot be reached, times out or answers with an HTTP error. A JSON-RPC
    error is the node's answer and is raised as is. It carries no access
    credential, so it serves open methods and signed transactions.
    """

    def __init__(self, endpoints: list[str], *, timeout: float = 30.0):
        if not endpoints:
            raise ValueError("NetworkRpcClient needs at least one endpoint")
        super().__init__(endpoints[0], timeout=timeout)
        self.endpoints = list(endpoints)

    def call(self, method: str, params: Params = None) -> Any:
        last: Exception | None = None
        for _ in range(len(self.endpoints)):
            try:
                return super().call(method, params)
            except httpx.HTTPError as e:
                last = e
                i = self.endpoints.index(self.endpoint)
                self.endpoint = self.endpoints[(i + 1) % len(self.endpoints)]
        assert last is not None
        raise last

    @classmethod
    def connect(
        cls,
        seeds: list[str] | tuple[str, ...] = NETWORK_SEEDS,
        chain_id: int = NETWORK_CHAIN_ID,
        *,
        role: str = "rpc",
        timeout: float = 10.0,
    ) -> NetworkRpcClient:
        """Discover the network's operators and connect to those that agree.

        With no arguments, the preview network through :data:`NETWORK_SEEDS`.
        """
        found = discover_endpoints(seeds, chain_id, role=role, timeout=timeout)
        return cls([e.url for e in found], timeout=timeout)


__all__ = [
    "NETWORK_CHAIN_ID",
    "NETWORK_SEEDS",
    "PREVIEW_NETWORK",
    "CheckedEndpoint",
    "NetworkPreset",
    "NetworkRpcClient",
    "discover_endpoints",
]
