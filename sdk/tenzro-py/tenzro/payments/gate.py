"""The publisher gate: answers a paid path with 402 and the requirements, and
serves it only after a facilitator has settled the payment. The handler never
runs for an unpaid request, so nothing it does can be had for free.

The decision is framework-neutral: :meth:`PublisherGate.decide` (synchronous)
and :meth:`AsyncPublisherGate.decide` take the request URL and headers and
return a :data:`GateDecision`, which :mod:`tenzro.payments.asgi` and
:mod:`tenzro.payments.wsgi` apply around an application. Both gates run one
decision procedure; they differ only in how they reach the quote and the
facilitator.
"""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import Awaitable, Callable, Generator, Mapping
from dataclasses import dataclass
from typing import Any, Union
from urllib.parse import urlsplit

import httpx

from ..rpc import AsyncRpcClient, RpcClient
from .policy import PaidRoute, PublisherPolicy, match_route
from .x402 import (
    PAYMENT_REQUIRED_HEADER,
    PAYMENT_RESPONSE_HEADER,
    PAYMENT_SIGNATURE_HEADER,
    X402_VERSION,
    PaymentRequirement,
    challenge_id_of,
    decode_header_text,
    encode_header_text,
    tenzro_network,
)

#: Prices USD micro-units in the asset's base units at the consensus rate (``tenzro_quotePayment``).
Quote = Callable[[int], Union[int, str]]
AsyncQuote = Callable[[int], Awaitable[Union[int, str]]]
#: Settles a payment: takes the facilitator's ``/settle`` request body, returns its answer.
Settle = Callable[[str], Mapping[str, Any]]
AsyncSettle = Callable[[str], Awaitable[Mapping[str, Any]]]


# ------------------------------------------------------------------ decisions


@dataclass(frozen=True)
class Serve:
    """Serve the request: the path is free, or the request is a person's."""

    content_usage: str | None = None

    def response_headers(self) -> list[tuple[str, str]]:
        return _usage(self.content_usage)


@dataclass(frozen=True)
class Paid:
    """Serve the request: it was paid. ``payment_response`` is the ``PAYMENT-RESPONSE`` value."""

    payment_response: str
    content_usage: str | None = None

    def response_headers(self) -> list[tuple[str, str]]:
        return [(PAYMENT_RESPONSE_HEADER, self.payment_response), *_usage(self.content_usage)]


@dataclass(frozen=True)
class RequirePayment:
    """Answer 402 with ``body`` and ``PAYMENT-REQUIRED: header``; the handler does not run."""

    body: str
    header: str
    content_usage: str | None = None
    status: int = 402

    def response_headers(self) -> list[tuple[str, str]]:
        return [("content-type", "application/json"), (PAYMENT_REQUIRED_HEADER, self.header), *_usage(self.content_usage)]


@dataclass(frozen=True)
class Unavailable:
    """No price is available now: answer 503; the handler does not run."""

    body: str = "payment required, but no price is available"
    status: int = 503

    def response_headers(self) -> list[tuple[str, str]]:
        return [("content-type", "text/plain;charset=UTF-8")]


GateDecision = Union[Serve, Paid, RequirePayment, Unavailable]


def _usage(content_usage: str | None) -> list[tuple[str, str]]:
    return [("Content-Usage", content_usage)] if content_usage else []


def is_signed_request(headers: Mapping[str, str]) -> bool:
    """Whether a request carries an agent's HTTP message signature (RFC 9421)."""
    names = {k.lower() for k in headers}
    return "signature-input" in names and "signature" in names


def _header(headers: Mapping[str, str], name: str) -> str | None:
    name = name.lower()
    for k, v in headers.items():
        if k.lower() == name:
            return v
    return None


# ------------------------------------------------------------- the procedure


@dataclass(frozen=True)
class _Quote:
    usd_e6: int


@dataclass(frozen=True)
class _Settle:
    body: str


_Step = Generator[Union[_Quote, _Settle], Any, Any]


class _Procedure:
    """The gate's decision procedure. It asks for a quote or a settlement by
    yielding a request, and the gate driving it answers; no I/O happens here."""

    def __init__(self, policy: PublisherPolicy, quote_ttl_seconds: float, clock: Callable[[], float], has_quote: bool):
        self.policy = policy
        self.ttl = quote_ttl_seconds
        self.clock = clock
        self.has_quote = has_quote
        # Per route, the last two quotes (amount, when), newest first.
        self.prices: dict[str, list[tuple[int, float]]] = {}

    def decide(self, url: str, headers: Mapping[str, str]) -> _Step:
        route = match_route(self.policy.routes, urlsplit(url).path or "/")
        if route is None:
            return Serve()
        header = _header(headers, PAYMENT_SIGNATURE_HEADER)
        if not header and not self.policy.charge_unsigned and not is_signed_request(headers):
            return Serve(route.content_usage)
        if not header:
            return (yield from self.required(url, route))
        try:
            text = decode_header_text(header)
            parsed = json.loads(text)
            if parsed is None:
                raise ValueError("the payload is null")
            accepted = parsed.get("accepted") if isinstance(parsed, dict) else None
        except (ValueError, UnicodeDecodeError):
            return (yield from self.required(url, route, "invalid_payload"))
        if not (yield from self.offers(route, accepted)):
            return (yield from self.required(url, route, "requirement_not_offered"))

        # Settle before the handler runs; the payload is forwarded as sent.
        body = (
            f'{{"x402Version":{X402_VERSION},"paymentPayload":{text},'
            f'"paymentRequirements":{json.dumps(accepted, separators=(",", ":"), ensure_ascii=False)}}}'
        )
        try:
            settled = yield _Settle(body)
        except Exception:
            return (yield from self.required(url, route, "facilitator_unreachable"))
        if not isinstance(settled, Mapping) or not settled.get("success"):
            reason = settled.get("errorReason") if isinstance(settled, Mapping) else None
            return (yield from self.required(url, route, reason or "settlement_failed"))
        response = encode_header_text(json.dumps(dict(settled), separators=(",", ":"), ensure_ascii=False))
        return Paid(response, route.content_usage)

    def requirements(self, route: PaidRoute) -> _Step:
        amount = str((yield from self.price(route)))
        challenge_id = str(uuid.uuid4())
        return [
            {
                "scheme": scheme,
                "network": tenzro_network(self.policy.chain_id),
                "amount": amount,
                "asset": route.paid_asset(),
                "payTo": self.policy.pay_to,
                "maxTimeoutSeconds": 300 if self.policy.max_timeout_seconds is None else self.policy.max_timeout_seconds,
                "extra": {"challengeId": challenge_id, "chain_id": self.policy.chain_id, "usd_e6": route.usd_e6},
            }
            for scheme in route.accepted_schemes()
        ]

    def required(self, url: str, route: PaidRoute, error: str | None = None) -> _Step:
        try:
            accepts = yield from self.requirements(route)
        except Exception:
            return Unavailable()
        resource: dict[str, Any] = {"url": url}
        if route.description:
            resource["description"] = route.description
        required: dict[str, Any] = {"x402Version": X402_VERSION}
        if error:
            required["error"] = error
        required["resource"] = resource
        required["accepts"] = accepts
        body = json.dumps(required, separators=(",", ":"), ensure_ascii=False)
        return RequirePayment(body, encode_header_text(body), route.content_usage)

    def offers(self, route: PaidRoute, r: Any) -> _Step:
        """Whether ``r`` is what ``route`` offers: scheme, network, payee and
        asset, at no less than a price quoted recently."""
        if not isinstance(r, dict) or not challenge_id_of(r):
            return False
        if not any(s.lower() == str(r.get("scheme")).lower() for s in route.accepted_schemes()):
            return False
        if r.get("network") != tenzro_network(self.policy.chain_id):
            return False
        if _account(str(r.get("payTo"))) != _account(self.policy.pay_to):
            return False
        if str(r.get("asset")).lower() != route.paid_asset().lower():
            return False
        paid = _base_units(r.get("amount"))
        if paid is None:
            return False
        try:
            current = yield from self.price(route)
        except Exception:
            return False
        if route.amount is not None:
            return paid >= current
        return any(paid >= amount for amount, _ in self.prices.get(route.path, []))

    def price(self, route: PaidRoute) -> _Step:
        """The route's current price, quoted at most once per TTL; the last two quotes stay acceptable."""
        if route.amount is not None:
            return int(route.amount)
        now = self.clock()
        seen = self.prices.get(route.path, [])
        for amount, at in seen:
            if now - at < self.ttl:
                return amount
        if not self.has_quote:
            raise LookupError(f"route {route.path} is priced in USD and the gate has no quote")
        amount = int((yield _Quote(route.usd_e6)))
        self.prices[route.path] = [(amount, now), *seen][:2]
        return amount


def _account(hex_address: str) -> str:
    return hex_address.removeprefix("0x").lower()


def _base_units(v: Any) -> int | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, str) and v.isascii() and v.isdigit():
        return int(v)
    return None


# ------------------------------------------------------------------- the gates


class PublisherGate:
    """The gate for synchronous servers (WSGI)."""

    def __init__(
        self,
        policy: PublisherPolicy,
        *,
        quote: Quote | None = None,
        settle: Settle | None = None,
        quote_ttl_seconds: float = 60,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.policy = policy
        self._quote = quote
        self._settle = settle or HttpFacilitator(policy.facilitator)
        self._procedure = _Procedure(policy, quote_ttl_seconds, clock, quote is not None)

    def decide(self, url: str, headers: Mapping[str, str]) -> GateDecision:
        """Decide for a request to ``url``: free, paid (settled before this returns), or pay first."""
        return self._run(self._procedure.decide(url, headers))

    def requirements(self, route: PaidRoute) -> list[PaymentRequirement]:
        """The requirements ``route`` offers now, one per accepted scheme."""
        return self._run(self._procedure.requirements(route))

    def _run(self, step: _Step) -> Any:
        try:
            request = next(step)
            while True:
                try:
                    if isinstance(request, _Quote):
                        assert self._quote is not None
                        answer: Any = self._quote(request.usd_e6)
                    else:
                        answer = self._settle(request.body)
                except Exception as e:
                    request = step.throw(e)
                else:
                    request = step.send(answer)
        except StopIteration as done:
            return done.value


class AsyncPublisherGate:
    """The gate for asynchronous servers (ASGI)."""

    def __init__(
        self,
        policy: PublisherPolicy,
        *,
        quote: AsyncQuote | None = None,
        settle: AsyncSettle | None = None,
        quote_ttl_seconds: float = 60,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.policy = policy
        self._quote = quote
        self._settle = settle or AsyncHttpFacilitator(policy.facilitator)
        self._procedure = _Procedure(policy, quote_ttl_seconds, clock, quote is not None)

    async def decide(self, url: str, headers: Mapping[str, str]) -> GateDecision:
        """Decide for a request to ``url``: free, paid (settled before this returns), or pay first."""
        return await self._run(self._procedure.decide(url, headers))

    async def requirements(self, route: PaidRoute) -> list[PaymentRequirement]:
        """The requirements ``route`` offers now, one per accepted scheme."""
        return await self._run(self._procedure.requirements(route))

    async def _run(self, step: _Step) -> Any:
        try:
            request = next(step)
            while True:
                try:
                    if isinstance(request, _Quote):
                        assert self._quote is not None
                        answer: Any = await self._quote(request.usd_e6)
                    else:
                        answer = await self._settle(request.body)
                except Exception as e:
                    request = step.throw(e)
                else:
                    request = step.send(answer)
        except StopIteration as done:
            return done.value


# ------------------------------------------------- the facilitator and quotes


class HttpFacilitator:
    """A facilitator over HTTP: posts the body to its ``/settle``."""

    def __init__(self, base: str, http: httpx.Client | None = None):
        self._url = base.rstrip("/") + "/settle"
        self._http = http or httpx.Client()

    def __call__(self, body: str) -> Mapping[str, Any]:
        res = self._http.post(self._url, content=body, headers={"content-type": "application/json"})
        return res.json()


class AsyncHttpFacilitator:
    """A facilitator over HTTP, asynchronously."""

    def __init__(self, base: str, http: httpx.AsyncClient | None = None):
        self._url = base.rstrip("/") + "/settle"
        self._http = http or httpx.AsyncClient()

    async def __call__(self, body: str) -> Mapping[str, Any]:
        res = await self._http.post(self._url, content=body, headers={"content-type": "application/json"})
        return res.json()


def node_quote(rpc: RpcClient) -> Quote:
    """A quote at a node's consensus rate (``tenzro_quotePayment``)."""

    def quote(usd_e6: int) -> int:
        return _quoted(rpc.call("tenzro_quotePayment", {"usd_e6": usd_e6}))

    return quote


def async_node_quote(rpc: AsyncRpcClient) -> AsyncQuote:
    """A quote at a node's consensus rate (``tenzro_quotePayment``), asynchronously."""

    async def quote(usd_e6: int) -> int:
        return _quoted(await rpc.call("tenzro_quotePayment", {"usd_e6": usd_e6}))

    return quote


def _quoted(result: Any) -> int:
    assets = result.get("assets") if isinstance(result, dict) else None
    first = assets[0] if isinstance(assets, list) and assets else {}
    if isinstance(first, dict) and first.get("error"):
        raise ValueError(f"quotePayment refused TNZO: {first['error'].get('code')}")
    amount = first.get("amount") if isinstance(first, dict) else None
    if not isinstance(amount, str) or not amount.isdigit():
        raise ValueError("quotePayment returned no amount")
    return int(amount)


__all__ = [
    "AsyncHttpFacilitator",
    "AsyncPublisherGate",
    "AsyncQuote",
    "AsyncSettle",
    "GateDecision",
    "HttpFacilitator",
    "Paid",
    "RequirePayment",
    "PublisherGate",
    "Quote",
    "Serve",
    "Settle",
    "Unavailable",
    "async_node_quote",
    "is_signed_request",
    "node_quote",
]
