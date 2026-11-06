"""JSON-RPC clients for one node.

:class:`RpcClient` (synchronous) and :class:`AsyncRpcClient` carry every
method the node serves as a typed method (generated from the node's method
table, see :mod:`tenzro._methods`) plus :meth:`call` for any method by name.

A client carries at most one access credential: a DPoP-bound access token and
the prover that mints a fresh DPoP proof for every request with a key held in
hardware (:class:`tenzro.signer.HardwareDpopProver`). Without one, the
``TENZRO_BEARER_JWT`` and ``TENZRO_DPOP_PROOF`` environment variables are
forwarded when set.
"""

from __future__ import annotations

import itertools
import os
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass
from typing import Any, Protocol

import httpx

from ._methods import METHODS, AsyncMethods, Methods, Params

class RpcError(Exception):
    """A JSON-RPC error the node answered with."""

    def __init__(self, code: int, message: str, data: Any = None):
        super().__init__(f"RPC Error {code}: {message}")
        self.code = code
        self.message = message
        self.data = data

    @property
    def light_build(self) -> bool:
        """True when the node is the light build of tenzro-node, which runs no
        model: it refuses a call that needs a local model with code -32004 and
        ``data["build"] == "light"``. Send such a call to a provider node instead."""
        return self.code == -32004 and isinstance(self.data, dict) and self.data.get("build") == "light"


class ApiError(Exception):
    """An error the node reports in its ``{"error":{message,type,code}}`` shape,
    as an HTTP body or as a frame inside a stream."""

    def __init__(self, message: str, type: str, code: str | None):
        super().__init__(message)
        self.message = message
        #: Error class, such as ``invalid_request_error`` or ``server_error``.
        self.type = type
        #: Machine-readable code, such as ``model_not_found``.
        self.code = code

    @classmethod
    def from_body(cls, body: Any) -> ApiError | None:
        """The error an ``{"error":{..}}`` body carries, if it carries one."""
        e = body.get("error") if isinstance(body, dict) else None
        if not isinstance(e, dict):
            return None
        message, type_, code = e.get("message"), e.get("type"), e.get("code")
        return cls(
            message if isinstance(message, str) else "",
            type_ if isinstance(type_, str) else "",
            code if isinstance(code, str) else None,
        )

    def to_json(self) -> dict[str, Any]:
        """The wire shape: ``{message, type, code}``."""
        return {"message": self.message, "type": self.type, "code": self.code}


class DpopProver(Protocol):
    """Mints DPoP proofs (RFC 9449) with a key the caller holds in hardware."""

    def jkt(self) -> str: ...

    def proof(self, htm: str, htu: str, access_token: str) -> str: ...


@dataclass(frozen=True)
class AccessCredential:
    """An access token and the DPoP key it is bound to."""

    token: str
    prover: DpopProver


def _htu(url: str) -> str:
    """The `htu` of a DPoP proof for `url` (RFC 9449): no query or fragment, and the
    empty path of an endpoint like ``http://host:8545`` as ``/``, the path the
    request is sent to and the node checks against."""
    url = url.split("#")[0].split("?")[0]
    scheme, sep, rest = url.partition("://")
    if sep and "/" not in rest:
        url += "/"
    return url


def _auth_headers(credential: AccessCredential | None, htm: str, htu: str) -> dict[str, str]:
    if credential is not None:
        return {
            "Authorization": f"DPoP {credential.token}",
            "DPoP": credential.prover.proof(htm, _htu(htu), credential.token),
        }
    headers: dict[str, str] = {}
    bearer = os.environ.get("TENZRO_BEARER_JWT")
    if bearer:
        headers["Authorization"] = f"DPoP {bearer}"
    dpop = os.environ.get("TENZRO_DPOP_PROOF")
    if dpop:
        headers["DPoP"] = dpop
    return headers


def _result(body: Any) -> Any:
    if not isinstance(body, dict):
        raise RpcError(-32700, "the node answered with something other than a JSON-RPC response")
    err = body.get("error")
    if err is not None:
        raise RpcError(int(err.get("code", 0)), str(err.get("message", "")), err.get("data"))
    return body.get("result")


def _stream_error(response: httpx.Response) -> Exception:
    try:
        body = response.json()
    except ValueError:
        body = None
    return ApiError.from_body(body) or httpx.HTTPStatusError(
        f"HTTP {response.status_code}: {response.reason_phrase}", request=response.request, response=response
    )


def _request(method: str, params: Params, request_id: int) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "method": method, "params": [] if params is None else params, "id": request_id}


class RpcClient(Methods):
    """Synchronous JSON-RPC client for one node."""

    def __init__(
        self,
        endpoint: str,
        *,
        credential: AccessCredential | None = None,
        timeout: float = 30.0,
        transport: httpx.BaseTransport | None = None,
    ):
        self.endpoint = endpoint
        self.credential = credential
        self._ids = itertools.count(1)
        self._http = httpx.Client(timeout=timeout, transport=transport)

    def call(self, method: str, params: Params = None) -> Any:
        """Call ``method`` with ``params`` (a JSON object or array)."""
        headers = {"Content-Type": "application/json", **_auth_headers(self.credential, "POST", self.endpoint)}
        response = self._http.post(self.endpoint, json=_request(method, params, next(self._ids)), headers=headers)
        if response.status_code >= 400 and not response.content:
            response.raise_for_status()
        return _result(response.json())

    def call_with_proof(self, method: str, params: Params, prover: DpopProver) -> Any:
        """Call ``method`` proving possession of ``prover``'s key with a DPoP
        proof and no access token, as a token endpoint is called
        (``tenzro_refreshToken``)."""
        headers = {"Content-Type": "application/json", "DPoP": prover.proof("POST", _htu(self.endpoint), "")}
        response = self._http.post(self.endpoint, json=_request(method, params, next(self._ids)), headers=headers)
        if response.status_code >= 400 and not response.content:
            response.raise_for_status()
        return _result(response.json())

    @contextmanager
    def post_stream(self, path: str, body: Any) -> Iterator[httpx.Response]:
        """POST ``body`` to ``path`` on the node and stream the answer; an error body raises :class:`ApiError`."""
        url = self.endpoint.rstrip("/") + path
        headers = {"Content-Type": "application/json", "Accept": "text/event-stream", **_auth_headers(self.credential, "POST", url)}
        with self._http.stream("POST", url, json=body, headers=headers) as response:
            if response.status_code >= 400:
                response.read()
                raise _stream_error(response)
            yield response

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> RpcClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


class AsyncRpcClient(AsyncMethods):
    """Asynchronous JSON-RPC client for one node."""

    def __init__(
        self,
        endpoint: str,
        *,
        credential: AccessCredential | None = None,
        timeout: float = 30.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        self.endpoint = endpoint
        self.credential = credential
        self._ids = itertools.count(1)
        self._http = httpx.AsyncClient(timeout=timeout, transport=transport)

    async def call(self, method: str, params: Params = None) -> Any:
        """Call ``method`` with ``params`` (a JSON object or array)."""
        headers = {"Content-Type": "application/json", **_auth_headers(self.credential, "POST", self.endpoint)}
        response = await self._http.post(self.endpoint, json=_request(method, params, next(self._ids)), headers=headers)
        if response.status_code >= 400 and not response.content:
            response.raise_for_status()
        return _result(response.json())

    async def call_with_proof(self, method: str, params: Params, prover: DpopProver) -> Any:
        """Call ``method`` proving possession of ``prover``'s key with a DPoP
        proof and no access token, as a token endpoint is called
        (``tenzro_refreshToken``)."""
        headers = {"Content-Type": "application/json", "DPoP": prover.proof("POST", _htu(self.endpoint), "")}
        response = await self._http.post(self.endpoint, json=_request(method, params, next(self._ids)), headers=headers)
        if response.status_code >= 400 and not response.content:
            response.raise_for_status()
        return _result(response.json())

    @asynccontextmanager
    async def post_stream(self, path: str, body: Any) -> AsyncIterator[httpx.Response]:
        """POST ``body`` to ``path`` on the node and stream the answer; an error body raises :class:`ApiError`."""
        url = self.endpoint.rstrip("/") + path
        headers = {"Content-Type": "application/json", "Accept": "text/event-stream", **_auth_headers(self.credential, "POST", url)}
        async with self._http.stream("POST", url, json=body, headers=headers) as response:
            if response.status_code >= 400:
                await response.aread()
                raise _stream_error(response)
            yield response

    async def aclose(self) -> None:
        await self._http.aclose()

    async def __aenter__(self) -> AsyncRpcClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()


__all__ = ["METHODS", "AccessCredential", "ApiError", "AsyncRpcClient", "DpopProver", "RpcClient", "RpcError"]
