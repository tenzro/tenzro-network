"""The publisher gate, as WSGI and ASGI middleware, against the shared vectors
in sdk/fixtures/payments/x402_gate.json and a facilitator that keeps voucher
accounting the way the ledger does."""

import asyncio
import base64
import json
import re

import httpx
import pytest
from conftest import fixture

from tenzro.payments import (
    AgentChannelPayer,
    AsyncPublisherGate,
    PayingClient,
    Paid,
    PublisherGate,
    PublisherPolicy,
    RequirePayment,
    Serve,
    Unavailable,
    decode_header_text,
    encode_header_text,
    match_route,
    payment_header,
    robots_license_line,
    rsl_xml,
)
from tenzro.payments import asgi, wsgi

G = fixture("payments", "x402_gate.json")
POLICY = PublisherPolicy.from_dict(G["policy"])
CHANNEL = "ab" * 32


def _normalized(body: str) -> str:
    return re.sub(r'"challengeId":"[^"]*"', '"challengeId":"CHALLENGE"', body)


class Unreachable(Exception):
    pass


class ScriptedFacilitator:
    """Answers /settle as the case scripts it and records every body."""

    def __init__(self, script):
        self.script = script or {}
        self.bodies = []

    def __call__(self, body):
        self.bodies.append(body)
        if self.script.get("unreachable"):
            raise Unreachable("connection refused")
        return self.script["respond"]


def _quote(usd_e6):
    return usd_e6 * G["quote_rate"]


async def _aquote(usd_e6):
    return usd_e6 * G["quote_rate"]


def _headers(case):
    h = dict(case["headers"])
    if "payment_text" in case:
        h["PAYMENT-SIGNATURE"] = encode_header_text(case["payment_text"])
    return h


def _check(case, status, headers, served, fac):
    e = case["expect"]
    assert status == e["status"], case["name"]
    assert served == e["served"], case["name"]
    if "content_usage" in e:
        assert headers.get("content-usage") == e["content_usage"], case["name"]
    assert (fac.bodies[0] if fac.bodies else None) == e["settled"], case["name"]
    assert len(fac.bodies) <= 1
    if "payment_response" in e:
        assert decode_header_text(headers["payment-response"]) == e["payment_response"], case["name"]
    if status == 402:
        required = decode_header_text(headers["payment-required"])
        assert json.loads(required).get("error") == e["error"], case["name"]
        assert headers["content-type"] == "application/json"
        if e["error"] is None:
            assert _normalized(required) == G["required_body"]


def _wsgi_app(served):
    def app(environ, start_response):
        served.append(environ["PATH_INFO"])
        start_response("200 OK", [("Content-Type", "text/plain")])
        return [b"the article"]

    return app


@pytest.mark.parametrize("case", G["cases"], ids=[c["name"] for c in G["cases"]])
def test_the_wsgi_gate_decides_every_shared_case(case):
    fac = ScriptedFacilitator(case.get("facilitator"))
    gate = PublisherGate(POLICY, quote=_quote if case.get("quote", True) else None, settle=fac)
    served = []
    with httpx.Client(transport=httpx.WSGITransport(app=wsgi.PublisherGateMiddleware(_wsgi_app(served), gate))) as http:
        res = http.get(G["origin"].rstrip("/") + case["path"], headers=_headers(case))
    _check(case, res.status_code, res.headers, bool(served), fac)


def _asgi_app(served):
    async def app(scope, receive, send):
        served.append(scope["path"])
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"text/plain")]})
        await send({"type": "http.response.body", "body": b"the article"})

    return app


@pytest.mark.parametrize("case", G["cases"], ids=[c["name"] for c in G["cases"]])
def test_the_asgi_gate_decides_every_shared_case(case):
    fac = ScriptedFacilitator(case.get("facilitator"))

    async def settle(body):
        return fac(body)

    gate = AsyncPublisherGate(POLICY, quote=_aquote if case.get("quote", True) else None, settle=settle)
    served = []

    async def run():
        transport = httpx.ASGITransport(app=asgi.PublisherGateMiddleware(_asgi_app(served), gate))
        async with httpx.AsyncClient(transport=transport) as http:
            return await http.get(G["origin"].rstrip("/") + case["path"], headers=_headers(case))

    res = asyncio.run(run())
    _check(case, res.status_code, res.headers, bool(served), fac)


def test_the_decision_names_what_to_do():
    fac = ScriptedFacilitator({"respond": {"success": True, "transaction": "t", "network": "tenzro:1337"}})
    gate = PublisherGate(POLICY, quote=_quote, settle=fac)
    signed = G["cases"][1]["headers"]
    assert gate.decide("https://pub.example/about", signed) == Serve()
    assert isinstance(gate.decide("https://pub.example/articles/1", signed), RequirePayment)
    assert isinstance(PublisherGate(POLICY, settle=fac).decide("https://pub.example/articles/1", signed), Unavailable)
    ok = next(c for c in G["cases"] if c.get("facilitator", {}).get("respond", {}).get("success"))
    paid = gate.decide("https://pub.example" + ok["path"], _headers(ok))
    assert isinstance(paid, Paid) and paid.content_usage == "train-ai=n"


def test_the_licence_document_robots_line_and_route_matching():
    assert rsl_xml(POLICY, G["origin"]) == G["rsl_xml"]
    assert robots_license_line(G["origin"]) == G["robots_line"]
    for path, want in G["matches"]:
        got = match_route(POLICY.routes, path)
        assert (got.path if got else None) == want, path


def test_a_quote_is_reused_within_its_ttl_and_the_last_two_stay_acceptable():
    now = [0.0]
    rates = iter([1000, 1100, 1200])
    quotes = []

    def quote(usd_e6):
        quotes.append(usd_e6)
        return usd_e6 * next(rates)

    fac = ScriptedFacilitator({"respond": {"success": True, "transaction": "t", "network": "tenzro:1337"}})
    gate = PublisherGate(POLICY, quote=quote, settle=fac, quote_ttl_seconds=60, clock=lambda: now[0])
    route = POLICY.routes[0]
    assert gate.requirements(route)[0]["amount"] == "2000000"
    now[0] = 59
    assert gate.requirements(route)[0]["amount"] == "2000000"
    now[0] = 61
    assert gate.requirements(route)[0]["amount"] == "2200000"
    assert len(quotes) == 2

    def pay(amount):
        r = {**gate.requirements(route)[0], "amount": str(amount)}
        text = json.dumps({"x402Version": 2, "resource": {"url": "u"}, "accepted": r, "payload": {}})
        return gate.decide("https://pub.example/articles/1", {"PAYMENT-SIGNATURE": encode_header_text(text)})

    assert isinstance(pay(2_000_000), Paid)  # the previous quote is still accepted
    now[0] = 122
    assert isinstance(pay(2_200_000), Paid)  # a third quote (2_400_000) leaves the second acceptable
    assert isinstance(pay(2_000_000), RequirePayment)  # but no longer the first


# ------------------------------------------- the TypeScript gate's scenarios


SIGNED = {"signature-input": 'sig1=("@authority");tag="web-bot-auth"', "signature": "sig1=:AAAA:"}


class Ledger:
    """A facilitator with ledger-style voucher accounting per channel."""

    def __init__(self):
        self.settles = 0
        self.channels = {}

    def __call__(self, body):
        self.settles += 1
        req = json.loads(body)
        cred = req["paymentPayload"]["payload"]
        cid = cred["extra"]["escrow_id"]
        cumulative = int(cred["extra"]["cumulative_amount"])
        charge = int(req["paymentRequirements"]["amount"])
        highest, spent = self.channels.get(cid, (0, 0))
        network = req["paymentRequirements"]["network"]
        if cumulative < highest or spent + charge > cumulative:
            return {"success": False, "errorReason": "invalid_payload", "transaction": "", "network": network}
        self.channels[cid] = (cumulative, spent + charge)
        return {"success": True, "transaction": f"escrow:{cid}:{cumulative}", "network": network, "amount": str(charge)}


class AgentRpc:
    def call(self, method, params=None):
        assert method == "tenzro_agentVoucher"
        return {
            "voucher": {
                "escrow_id": params["channel_id"],
                "cumulative_amount": params["cumulative_amount"],
                "signature": "11" * 64,
                "agent": {"agent_did": "did:tenzro:agent:a", "machine_did": "did:tenzro:machine:m", "as_of_ms": 1_800_000_000_000},
            }
        }


def _harness():
    ledger = Ledger()
    served = []
    gate = PublisherGate(POLICY, quote=_quote, settle=ledger)
    http = httpx.Client(transport=httpx.WSGITransport(app=wsgi.PublisherGateMiddleware(_wsgi_app(served), gate)), headers=SIGNED)
    return ledger, served, http


def test_ten_thousand_sub_cent_requests_ride_one_channel_and_leave_one_voucher_to_claim():
    ledger, served, http = _harness()
    payer = AgentChannelPayer(AgentRpc(), 1337, CHANNEL, POLICY.pay_to)
    client = PayingClient(payer, 10_000_000, http=http)
    for i in range(10_000):
        res = client.get(f"https://pub.example/articles/{i % 7}")
        assert res.status_code == 200, f"request {i}"
        assert res.headers.get("PAYMENT-RESPONSE")
    assert len(served) == 10_000
    assert ledger.settles == 10_000
    assert ledger.channels[CHANNEL] == (10_000 * 2_000_000, 10_000 * 2_000_000)
    assert len(ledger.channels) == 1


def test_a_replayed_payment_serves_nothing():
    ledger, served, http = _harness()
    payer = AgentChannelPayer(AgentRpc(), 1337, CHANNEL, POLICY.pay_to)
    first = http.get("https://pub.example/articles/1")
    required = json.loads(decode_header_text(first.headers["PAYMENT-REQUIRED"]))
    header = payment_header(payer, required, required["accepts"][0])
    assert http.get("https://pub.example/articles/1", headers={"PAYMENT-SIGNATURE": header}).status_code == 200
    assert http.get("https://pub.example/articles/1", headers={"PAYMENT-SIGNATURE": header}).status_code == 402
    assert len(served) == 1


def test_the_headers_are_base64_json():
    body = '{"a":1}'
    assert encode_header_text(body) == base64.b64encode(body.encode()).decode()
