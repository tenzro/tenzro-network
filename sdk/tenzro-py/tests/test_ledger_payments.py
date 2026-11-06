"""Ledger payments in any permitted asset, against the shared vectors under sdk/fixtures/payments."""

import copy

import pytest
from conftest import fixture

from tenzro.payments.ledger import (
    ExpectedPayment,
    LedgerPayments,
    PaymentError,
    check_receipt,
    choose_asset,
    ledger_authorization_message,
    parse_price_e6,
    payment_id,
    read_quote_assets,
    request_digest,
)

V = fixture("payments", "payment_abstraction.json")


def test_prices_parse_to_micro_units_exactly():
    for s, e6 in V["prices"]:
        assert parse_price_e6(s) == e6
    for s in V["bad_prices"]:
        with pytest.raises(PaymentError) as e:
            parse_price_e6(s)
        assert e.value.code == "invalid_price"


def test_payment_id_and_request_digest():
    p = V["payment_id"]
    assert request_digest("https://api.example/v1/infer").hex() == p["request_digest"]
    got = payment_id(p["idempotency_key"], bytes.fromhex(p["payer"]), bytes.fromhex(p["payee"]), bytes.fromhex(p["request_digest"]))
    assert got == p["payment_id"]


def test_authorization_preimage_is_the_chains():
    a = V["authorization"]
    m = ledger_authorization_message(
        chain_id=a["chain_id"],
        payment_id=a["payment_id"],
        payer=bytes.fromhex(a["payer"]),
        payee=bytes.fromhex(a["payee"]),
        max_amount=int(a["max_amount"]),
        asset=a["asset"],
        request_digest=bytes.fromhex(a["request_digest"]),
        quote_digest=bytes.fromhex(a["quote_digest"]),
        usd_e6=a["usd_e6"],
    )
    assert m.hex() == a["preimage"]


def test_first_accepted_asset_that_can_settle_is_chosen():
    q = V["quote"]
    assets = read_quote_assets(q["response"])
    assert choose_asset(assets, q["accept"]).asset == q["chosen"]
    with pytest.raises(PaymentError) as e:
        choose_asset(assets, q["accept_none"])
    assert e.value.code == q["none_code"]


def test_suspended_asset_is_passed_over_for_the_next_accepted_asset():
    q = V["quote_suspended"]
    assets = read_quote_assets(q["response"])
    assert choose_asset(assets, q["accept"]).asset == q["chosen"]
    with pytest.raises(PaymentError) as e:
        choose_asset(assets, q["accept_none"])
    assert e.value.code == "asset_suspended"


def test_full_inflow_cap_asset_is_passed_over_for_the_next_accepted_asset():
    q = V["quote_inflow_full"]
    assets = read_quote_assets(q["response"])
    assert choose_asset(assets, q["accept"]).asset == q["chosen"]
    with pytest.raises(PaymentError) as e:
        choose_asset(assets, q["accept_none"])
    assert e.value.code == "asset_inflow_full"


def _expected(request=None):
    e = V["receipt"]["expected"]
    return ExpectedPayment(e["payment_id"], e["payee"], e["asset"], int(e["amount"]), request or e["request"])


def test_receipt_checks_two_identical_records_with_every_field():
    rec = V["receipt"]["record"]
    assert check_receipt(_expected(), rec, copy.deepcopy(rec))["fee_asset"] == V["receipt"]["expected"]["asset"]
    with pytest.raises(PaymentError) as e:
        check_receipt(_expected(V["receipt"]["other_request"]), rec, rec)
    assert e.value.code == "receipt_mismatch" and "request" in e.value.reason
    for a, b, code in [
        (None, rec, "receipt_missing"),
        (rec, {**rec, "amount": "1"}, "receipt_mismatch"),
        ({**rec, "value_units": ""}, {**rec, "value_units": ""}, "receipt_mismatch"),
    ]:
        with pytest.raises(PaymentError) as e:
            check_receipt(_expected(), a, b)
        assert e.value.code == code


class FakeNode:
    def __init__(self, record):
        self.record = record
        self.calls = []

    def call(self, method, params=None):
        self.calls.append((method, params))
        if method == "tenzro_quotePayment":
            return V["quote"]["response"]
        if method == "tenzro_getPayment":
            return self.record
        if method == "eth_chainId":
            return "0x539"
        if method == "tenzro_settle":
            self.record = V["receipt"]["record"]
            return {"status": "settled"}
        raise AssertionError(method)


class Signer:
    def p256_public_key(self):
        return bytes([3]) * 64

    def ml_dsa_public_key(self):
        return None

    def sign_composite(self, m_prime):
        return bytes([1]) * 64, None


def test_pay_signs_the_chosen_asset_relays_and_verifies():
    node = FakeNode(None)
    pay = LedgerPayments([node, node], backoff_s=0)
    q = pay.quote(V["payment_id"]["payee"], "1", "https://api.example/v1/infer", V["quote"]["accept"])
    assert q.chosen.asset == V["quote"]["chosen"]
    assert node.calls[0] == ("tenzro_quotePayment", {"usd_e6": 1_000_000, "accept": V["quote"]["accept"]})
    paid = pay.pay(q, Signer(), "order-7f3a", account=V["payment_id"]["payer"])
    settle = next(p for m, p in node.calls if m == "tenzro_settle")
    assert settle["amount"] == V["authorization"]["max_amount"]
    assert settle["payment"]["payment_id"] == V["payment_id"]["payment_id"]
    assert settle["payment"]["authorization"]["asset"] == V["quote"]["chosen"]
    pay.verify_receipt(paid.expected)


def test_a_retry_never_pays_twice():
    node = FakeNode(V["receipt"]["record"])
    pay = LedgerPayments([node, node], backoff_s=0)
    q = pay.quote(V["payment_id"]["payee"], "1", "https://api.example/v1/infer", V["quote"]["accept"])
    pay.pay(q, Signer(), "order-7f3a", account=V["payment_id"]["payer"])
    assert not any(m == "tenzro_settle" for m, _ in node.calls)


def test_charge_serves_only_a_paid_request():
    node = FakeNode(V["receipt"]["record"])
    pay = LedgerPayments([node, node])
    pid = V["payment_id"]["payment_id"]
    payee = V["payment_id"]["payee"]
    req = "https://api.example/v1/infer"
    assert pay.charge(req, None, payee, "1") is None
    assert pay.charge("https://other.example", pid, payee, "1") is None
    assert pay.charge(req, pid, payee, "2") is None
    assert pay.charge(req, pid, payee, "1") is not None
    # The same payment presented again unlocks nothing.
    assert pay.charge(req, pid, payee, "1") is None


def test_a_resold_payment_signs_each_commission_and_its_receipt_shows_every_leg():
    a = V["authorization_resold"]
    m = ledger_authorization_message(
        chain_id=a["chain_id"],
        payment_id=a["payment_id"],
        payer=bytes.fromhex(a["payer"]),
        payee=bytes.fromhex(a["payee"]),
        max_amount=int(a["max_amount"]),
        asset=a["asset"],
        request_digest=bytes.fromhex(a["request_digest"]),
        quote_digest=bytes.fromhex(a["quote_digest"]),
        usd_e6=a["usd_e6"],
        resellers=[(bytes.fromhex(r["reseller"]), r["commission_bps"]) for r in a["resellers"]],
    )
    assert m.hex() == a["preimage"]
    q = read_quote_assets(V["quote_resold"]["response"])[0]
    assert q.operator_amount == int(V["quote_resold"]["operator_amount"])
    assert q.legs[0]["amount"] == V["quote_resold"]["commission"]
    r = V["receipt_resold"]
    e = r["expected"]
    exp = ExpectedPayment(e["payment_id"], e["payee"], e["asset"], int(e["amount"]), e["request"],
                          [(bytes.fromhex(x["reseller"]), x["commission_bps"]) for x in e["resellers"]])
    assert len(check_receipt(exp, r["record"], r["record"])["legs"]) == 2
    undisclosed = {**r["record"], "legs": r["record"]["legs"][:1]}
    with pytest.raises(PaymentError) as err:
        check_receipt(exp, undisclosed, undisclosed)
    assert err.value.code == "receipt_mismatch"
