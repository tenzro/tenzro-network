"""Split vectors (sdk/fixtures/split), intermediary shares, plans and the composite signature forms."""

import base64
import json

import pytest
from conftest import fixture

from tenzro.settlement import (
    PlanBuilder,
    check_intermediary_share,
    collateral_tx,
    open_plan_tx,
    plan_payment_header,
    plan_payment_payload,
    preview_split,
    prove_leg_tx,
    sign_plan_payment,
    split_rule_hash,
)
from tenzro.wallet import WebAuthnAssertion, composite_signature_json, webauthn_challenge_of


def test_every_split_vector_divides_and_hashes_as_the_chain_does():
    vectors = fixture("split", "vectors.json")
    assert vectors
    for v in vectors:
        got = preview_split(int(v["gross"]), v["rule"], v["params"], int(v["network_fees"]))
        assert got == v["expect"], v["name"]
        assert split_rule_hash(v["rule"]) == v["rule_hash"], v["name"]


def _rule(lines):
    return {"version": 1, "lines": [{"role": "payee", "recipient": {"address": "1" * 64}, "basis": "remainder"}, *lines]}


def test_facilitator_and_relayer_lines_are_held_to_an_agents_terms():
    fees = _rule([
        {"role": "facilitator", "recipient": {"address": "2" * 64}, "basis": {"bps": 100}},
        {"role": "relayer", "recipient": {"address": "3" * 64}, "basis": {"bps": 50}},
    ])
    check_intermediary_share(fees, 1_000_000, 150)
    with pytest.raises(ValueError, match="more than 149 bps"):
        check_intermediary_share(fees, 1_000_000, 149)
    fixed = _rule([{"role": "facilitator", "recipient": {"address": "2" * 64}, "basis": {"fixed": "200"}}])
    check_intermediary_share(fixed, 10_000, 200)
    with pytest.raises(ValueError):
        check_intermediary_share(fixed, 10_000, 199)
    capped = _rule([{"role": "facilitator", "recipient": {"address": "2" * 64}, "basis": {"bps": 5000}, "cap": "10"}])
    check_intermediary_share(capped, 10_000, 10)
    check_intermediary_share(_rule([{"role": "referrer", "recipient": {"address": "4" * 64}, "basis": {"bps": 3000}}]), 10_000, 0)


def test_a_passkey_assertion_is_the_webauthn_form_of_the_p256_leg():
    sig = composite_signature_json(WebAuthnAssertion(b"\x01\x02", b"\x03", b"\x04\x05"), None)
    assert sig == {"classical": {"form": "web_authn", "authenticator_data": "0102", "client_data_json": "03", "signature": "0405"}}
    assert composite_signature_json(b"\x09", b"\x07") == {"classical": {"form": "raw", "signature": "09"}, "pq": "07"}
    assert webauthn_challenge_of(b"abc") == "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0"


def test_a_plan_binds_its_split_and_pays_an_x402_plan_requirement(rpc, signer):
    rule = _rule([])
    plan = PlanBuilder(1, "0x" + "ab" * 32, rule, 60_000).native(5).native(7, "0x" + "cd" * 32).build()
    assert plan["split_hash"] == split_rule_hash(rule)
    assert plan["legs"][1] == {"kind": {"native_transfer": {"amount": "7", "escrow_id": "cd" * 32}}, "class_required": "native"}
    with pytest.raises(ValueError):
        PlanBuilder(1, "00", rule, 1).build()
    accepted = {"scheme": "plan", "network": "tenzro:1337", "amount": "5", "asset": "TNZO", "payTo": "09" * 32, "maxTimeoutSeconds": 60}
    signed = {"transaction": {"tx_type": open_plan_tx(plan)}}
    payload = plan_payment_payload(accepted, signed, {"url": "https://x.example/a"})
    assert json.loads(base64.b64decode(plan_payment_header(payload))) == payload
    with pytest.raises(ValueError):
        plan_payment_payload({**accepted, "scheme": "exact"}, signed)
    with pytest.raises(ValueError):
        plan_payment_payload(accepted, {"transaction": {"tx_type": prove_leg_tx("00", 0)}})
    with pytest.raises(RuntimeError, match="stop before signing"):
        sign_plan_payment(rpc, signer, plan, accepted)
    assert rpc.signing_types() == [open_plan_tx(plan)]
    assert collateral_tx("0x" + "11" * 32, 3, False) == {"SettlementPlan": {"op": {"withdraw_collateral": {"asset": "11" * 32, "amount": "3"}}}}
