"""x402 payers against the shared vectors under sdk/fixtures/payments."""

import json

import httpx
from conftest import fixture

from tenzro.wallet import account_address, composite_message_representative
from tenzro.payments import (
    PAYMENT_AUTHORIZATION_CONTEXT,
    PAYMENT_REQUIRED_HEADER,
    PAYMENT_SIGNATURE_HEADER,
    HybridPayer,
    PayingClient,
    agent_voucher_credential,
    decode_header_text,
    encode_header_text,
    hybrid_authorization_message,
    stringify_exact,
)

HYBRID = fixture("payments", "x402_hybrid_authorization.json")
VOUCHER = fixture("payments", "x402_agent_voucher.json")
PUBLIC_KEY = bytes.fromhex(HYBRID["public_key"])


class RecordingSigner:
    def __init__(self):
        self.signed = []

    def p256_public_key(self):
        return PUBLIC_KEY

    def ml_dsa_public_key(self):
        return None

    def sign_composite(self, m_prime):
        self.signed.append(m_prime)
        return bytes([1]) * 64, bytes([2]) * 3309


def test_the_payer_derives_the_account_the_facilitator_debits():
    assert account_address(PUBLIC_KEY).hex() == HYBRID["payer_address"]


def test_the_authorization_message_matches_the_nodes():
    message = hybrid_authorization_message(
        HYBRID["requirement"], HYBRID["resource"]["url"], bytes.fromhex(HYBRID["payer_address"]), int(HYBRID["max_amount"])
    )
    assert message.hex() == HYBRID["message"]


def test_pay_signs_the_composite_representative_and_names_the_key():
    signer = RecordingSigner()
    payer = HybridPayer(signer, "did:tenzro:human:p")
    r = HYBRID["requirement"]
    assert payer.supports(r)
    assert not payer.supports({**r, "scheme": "batch-settlement"})
    credential = payer.pay(r, HYBRID["resource"])
    assert signer.signed[0] == composite_message_representative(PAYMENT_AUTHORIZATION_CONTEXT, bytes.fromhex(HYBRID["message"]))
    assert credential["challenge_id"] == r["extra"]["challengeId"]
    assert credential["payer_address"] == HYBRID["payer_address"]
    assert credential["extra"]["public_key"] == HYBRID["public_key"]
    assert credential["amount"] == int(r["amount"])
    assert credential["payer_did"] == "did:tenzro:human:p"
    assert credential["signature"]["pq"] == "02" * 3309


def test_the_agent_voucher_payload_matches_the_shared_vector_the_node_decodes():
    v = VOUCHER
    cred = agent_voucher_credential(
        v["requirement"], v["channel_id"], int(v["cumulative_amount"]), int(v["requirement"]["amount"]), v["voucher"], v["credential_id"]
    )
    text = stringify_exact({"x402Version": 2, "resource": v["resource"], "accepted": v["requirement"], "payload": cred})
    assert encode_header_text(text) == v["payment_signature"]


def test_the_paying_client_pays_once_then_pays_up_front():
    r = HYBRID["requirement"]
    required = {"x402Version": 2, "resource": HYBRID["resource"], "accepts": [r]}
    seen = []

    def handle(request: httpx.Request) -> httpx.Response:
        paid = request.headers.get(PAYMENT_SIGNATURE_HEADER)
        seen.append(paid)
        if paid is None:
            return httpx.Response(402, headers={PAYMENT_REQUIRED_HEADER: encode_header_text(json.dumps(required))})
        return httpx.Response(200, text="article")

    client = PayingClient(HybridPayer(RecordingSigner()), int(r["amount"]), httpx.Client(transport=httpx.MockTransport(handle)))
    assert client.get("https://pub.example/articles/2").text == "article"
    assert client.get("https://pub.example/articles/2?page=2").text == "article"
    assert seen[0] is None and seen[1] and seen[2]
    second = json.loads(decode_header_text(seen[2]))
    assert second["accepted"]["extra"]["challengeId"] != r["extra"]["challengeId"]
    poor = PayingClient(HybridPayer(RecordingSigner()), int(r["amount"]) - 1, httpx.Client(transport=httpx.MockTransport(handle)))
    assert poor.get("https://pub.example/articles/2").status_code == 402
