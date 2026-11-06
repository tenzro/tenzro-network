"""Paying a node-issued challenge against the shared vector under sdk/fixtures/payments."""

import pytest
from conftest import fixture

from tenzro.wallet import composite_message_representative
from tenzro.payments import (
    PAYMENT_AUTHORIZATION_CONTEXT,
    challenge_authorization_message,
    sign_challenge_credential,
)

VECTOR = fixture("payments", "challenge_authorization.json")
CHALLENGE = VECTOR["challenge"]
PUBLIC_KEY = bytes.fromhex(VECTOR["public_key"])


class RecordingSigner:
    def __init__(self):
        self.signed = []

    def p256_public_key(self):
        return PUBLIC_KEY

    def ml_dsa_public_key(self):
        return None

    def sign_composite(self, m_prime):
        self.signed.append(m_prime)
        return bytes([1]) * 64, None


class RecordingRpc:
    def __init__(self):
        self.calls = []

    def call(self, method, params=None):
        self.calls.append((method, params))
        return {"receipt_id": "r"}


def test_the_authorization_message_matches_the_nodes():
    message = challenge_authorization_message(
        CHALLENGE, bytes.fromhex(VECTOR["payer_address"]), int(VECTOR["max_amount"])
    )
    assert message.hex() == VECTOR["message"]


def test_a_challenge_without_a_chain_id_is_refused():
    extra = {k: v for k, v in CHALLENGE["extra"].items() if k != "chain_id"}
    with pytest.raises(ValueError):
        challenge_authorization_message({**CHALLENGE, "extra": extra}, bytes(32), 1)


def test_the_credential_signs_that_message_and_names_the_keys_account():
    signer = RecordingSigner()
    credential = sign_challenge_credential(CHALLENGE, signer, "did:tenzro:human:p", int(VECTOR["max_amount"]))
    expected = composite_message_representative(PAYMENT_AUTHORIZATION_CONTEXT, bytes.fromhex(VECTOR["message"]))
    assert signer.signed[0] == expected
    assert credential["challenge_id"] == CHALLENGE["challenge_id"]
    assert credential["protocol"] == "mpp"
    assert credential["payer_address"] == VECTOR["payer_address"]
    assert credential["amount"] == CHALLENGE["amount"]
    assert credential["extra"] == {"public_key": VECTOR["public_key"], "upto_max": VECTOR["max_amount"]}
    assert "pq" not in credential["signature"]


def test_a_ceiling_below_the_charge_is_refused_and_an_exact_credential_has_none():
    with pytest.raises(ValueError):
        sign_challenge_credential(CHALLENGE, RecordingSigner(), "", 999)
    assert "upto_max" not in sign_challenge_credential(CHALLENGE, RecordingSigner())["extra"]
