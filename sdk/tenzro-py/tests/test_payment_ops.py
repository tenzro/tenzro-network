"""Bridge-send and payee payment operations match sdk/fixtures/payment-ops/vectors.json."""

import pytest
from conftest import fixture

from tenzro.bridge import bridge_send, outbound_fields
from tenzro.settlement import refund_op, refund_payment, set_payee_split, set_split_op

V = fixture("payment-ops", "vectors.json")


def test_outbound_fields_match_the_vectors():
    for v in V["bridge_outbound"]:
        a = v["args"]
        assert outbound_fields(a["target_chain"], a["recipient"], int(a["amount"]), a["asset"]) == v["fields"]
    with pytest.raises(ValueError):
        outbound_fields("base", "zz", 1)
    with pytest.raises(ValueError):
        outbound_fields("base", "01", 0)


def test_refund_and_set_split_match_the_vectors():
    for v in V["payment_refund"]:
        assert refund_op(v["args"]["pay_ref"], int(v["args"]["amount"])) == v["op"]
    for v in V["payment_set_split"]:
        assert set_split_op(v["args"]["rule"]) == v["op"]
    with pytest.raises(ValueError):
        refund_op("abcd", 1)
    with pytest.raises(ValueError):
        refund_op("ab" * 32, 0)


def test_send_refund_and_split_submit_signed_bridge_and_payment_transactions(rpc, signer):
    for run in (
        lambda: bridge_send(rpc, signer, "base", "0xabcd", 5, "usdc"),
        lambda: refund_payment(rpc, signer, "ab" * 32, 5),
        lambda: set_payee_split(rpc, signer, None),
    ):
        with pytest.raises(RuntimeError, match="stop before signing"):
            run()
    assert rpc.signing_types() == [
        {"Bridge": {"op": {"outbound": {"target_chain": "base", "recipient": "abcd", "amount": "5", "asset": "USDC"}}}},
        {"Payment": {"op": {"refund": {"pay_ref": "ab" * 32, "amount": "5"}}}},
        {"Payment": {"op": {"set_split": {"rule": None}}}},
    ]
