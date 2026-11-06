"""A typed transaction is signed only over the transaction it was built as."""

import hashlib
import struct

import pytest

from tenzro.account_keys import PQ_KEY_ENROLLMENT_SIGNATURE_CONTEXT, enroll_pq_key_op, pq_enrollment_message
from tenzro.typed_tx import (
    TX_KINDS,
    ChainReadError,
    Envelope,
    SigningPayloadMismatch,
    TypedTransaction,
    TypedTxClient,
    check_signing_payload,
    parse_quantity,
    tx_type,
)

ENV = Envelope(
    chain_id=1337,
    from_=bytes([1]) * 32,
    to=bytes([2]) * 32,
    nonce=7,
    gas_limit=500000,
    gas_price=1,
    timestamp=1000,
    valid_until=2000,
)


def _plain_digest(encoded: str) -> str:
    return hashlib.sha256(
        struct.pack("<Q", 1337) + ENV.from_ + ENV.to + struct.pack("<QQQqq", 7, 500000, 1, 1000, 2000) + encoded.encode()
    ).hexdigest()


def test_a_plain_payload_is_checked_against_the_built_type():
    type_ = tx_type(TypedTransaction(kind="Transfer", fields={"amount": 5}))
    encoded = '{"Transfer":{"amount":5}}'
    digest = _plain_digest(encoded)
    assert check_signing_payload(ENV, type_, {"kind": "plain", "tx_type_json": encoded, "digest": digest}).hex() == digest
    with pytest.raises(SigningPayloadMismatch, match="tx_type"):
        check_signing_payload(ENV, type_, {"kind": "plain", "tx_type_json": '{"Transfer":{"amount":6}}', "digest": digest})
    with pytest.raises(SigningPayloadMismatch, match="tx_type"):
        check_signing_payload(ENV, {"T": {"a": 1}}, {"kind": "plain", "tx_type_json": '{"T":{"a":true}}', "digest": digest})
    with pytest.raises(SigningPayloadMismatch, match="digest"):
        check_signing_payload(ENV, type_, {"kind": "plain", "tx_type_json": encoded, "digest": "00" * 32})


def test_a_typed_action_preimage_must_carry_the_envelope():
    import json

    type_ = {"Payment": {"op": {"set_split": {"rule": None}}}}
    pre = {
        "chain_id": 1337, "from": ENV.from_.hex(), "to": ENV.to.hex(), "nonce": 7, "gas_limit": 500000,
        "gas_price": 1, "timestamp": 1000, "valid_until": 2000, "action": type_,
    }
    text = json.dumps(pre)
    digest = hashlib.sha256(text.encode()).hexdigest()
    assert check_signing_payload(ENV, type_, {"kind": "typed_action", "preimage": text, "digest": digest}).hex() == digest
    bad = json.dumps({**pre, "nonce": 8})
    with pytest.raises(SigningPayloadMismatch, match="nonce"):
        check_signing_payload(ENV, type_, {"kind": "typed_action", "preimage": bad, "digest": hashlib.sha256(bad.encode()).hexdigest()})


def test_every_kind_and_exit_validator():
    assert len(TX_KINDS) == len(set(TX_KINDS)) > 50
    assert tx_type(TypedTransaction(kind="ExitValidator", fields=None)) == "ExitValidator"
    with pytest.raises(ValueError):
        tx_type(TypedTransaction(kind="ExitValidator", fields={}))
    with pytest.raises(ValueError):
        tx_type(TypedTransaction(kind="NotAKind", fields={}))
    for kind in TX_KINDS:
        if kind != "ExitValidator":
            assert tx_type(TypedTransaction(kind=kind, fields={"x": 1})) == {kind: {"x": 1}}


def test_send_asks_for_the_payload_of_the_signers_account(rpc, signer):
    with pytest.raises(RuntimeError, match="stop before signing"):
        TypedTxClient(rpc).send(signer, TypedTransaction(kind="Transfer", fields={"amount": 1}))
    method, params = rpc.sent[-1]
    assert method == "tenzro_getSigningPayload"
    assert params["chain_id"] == 1337 and params["nonce"] == 0
    assert params["valid_until"] - params["timestamp"] == 300_000
    assert params["from"].endswith("0" * 24)


def test_pq_enrollment_builders():
    assert PQ_KEY_ENROLLMENT_SIGNATURE_CONTEXT == b"tenzro/account/pq-key-enrollment"
    assert pq_enrollment_message(bytes(32), b"\x01\x02") == bytes(32) + b"\x01\x02"
    with pytest.raises(ValueError):
        pq_enrollment_message(bytes(31), b"\x01")
    op = enroll_pq_key_op(bytes(1952), b"\x09")
    assert op["enroll_pq_key"]["possession"] == "09"
    with pytest.raises(ValueError):
        enroll_pq_key_op(bytes(10), b"\x09")


class _Node:
    """Answers each method from ``answers``: a value, or an exception raised."""

    endpoint = "http://node.test"

    def __init__(self, answers):
        self.answers = answers
        self.sent = []

    def call(self, method, params=None):
        self.sent.append((method, params))
        a = self.answers.get(method)
        if isinstance(a, Exception):
            raise a
        return a


class _CountingSigner:
    def __init__(self):
        self.signed = 0

    def p256_public_key(self):
        return bytes([7]) * 64

    def ml_dsa_public_key(self):
        return None

    def sign_composite(self, m_prime):
        self.signed += 1
        return bytes(64), None


@pytest.mark.parametrize(
    "answers, what",
    [
        ({"tenzro_getNonce": "0x5", "eth_chainId": RuntimeError("unavailable")}, "chain id"),
        ({"tenzro_getNonce": RuntimeError("unavailable"), "eth_chainId": "0x20aa9"}, "nonce"),
        ({"tenzro_getNonce": "0x5", "eth_chainId": "0xzz"}, "chain id"),
        ({"tenzro_getNonce": "1_0", "eth_chainId": "0x20aa9"}, "nonce"),
        ({"tenzro_getNonce": "0x5", "eth_chainId": None}, "chain id"),
    ],
)
def test_a_failed_or_malformed_read_is_an_error_not_a_signed_transaction(answers, what):
    node = _Node({**answers, "eth_gasPrice": "0x3b9aca00"})
    signer = _CountingSigner()
    with pytest.raises(ChainReadError, match=f"^could not read the {what} from http://node.test: "):
        TypedTxClient(node).send(signer, TypedTransaction(kind="Transfer", fields={"amount": 1}))
    assert signer.signed == 0
    assert "tenzro_getSigningPayload" not in [m for m, _ in node.sent]


def test_the_envelope_carries_the_nonce_and_chain_id_the_node_reports():
    node = _Node({"tenzro_getNonce": "0x5", "eth_chainId": "0x20aa9", "eth_gasPrice": "0x3b9aca00"})
    node.answers["tenzro_getSigningPayload"] = RuntimeError("stop before signing")
    with pytest.raises(RuntimeError, match="stop before signing"):
        TypedTxClient(node).send(_CountingSigner(), TypedTransaction(kind="Transfer", fields={"amount": 1}))
    _, params = node.sent[-1]
    assert params["nonce"] == 5 and params["chain_id"] == 133801


def test_a_quantity_is_hex_or_an_error():
    assert parse_quantity("0x20aa9") == 133801
    assert parse_quantity("ff") == 255
    for bad in ["", "0x", "0x+1", "0x1g", " 0x1", "1_0", None, 5]:
        with pytest.raises(ValueError):
            parse_quantity(bad)


def test_a_keystore_change_does_not_name_a_chain_the_node_did_not_report():
    from tenzro.keystore import KeystoreClient

    node = _Node(
        {
            "tenzro_getKeystore": {"account": "0x01", "keystore": {"roots": []}, "commitment": "0x02", "on_chain": True},
            "eth_chainId": RuntimeError("unavailable"),
        }
    )
    with pytest.raises(ChainReadError, match="could not read the chain id from http://node.test: unavailable"):
        KeystoreClient(node).prepare("0x01", {"Freeze": {}})



class _EnrollingSigner(_CountingSigner):
    def ml_dsa_public_key(self):
        return bytes(1952)

    def sign_composite(self, m_prime):
        return bytes(64), bytes(3309)


def _stub_send(monkeypatch, answers):
    sent = []

    def send(self, signer, tx):
        sent.append(tx.kind)
        a = answers.pop(0)
        if isinstance(a, Exception):
            raise a
        return a

    monkeypatch.setattr(TypedTxClient, "send", send)
    return sent


NOT_ENROLLED_ANSWER = "invalid signature: ML-DSA-65 leg present for a key with no ML-DSA-65 key enrolled"


def test_send_enrolling_sends_once_when_the_node_accepts(monkeypatch):
    from tenzro.account_keys import AccountKeysClient

    sent = _stub_send(monkeypatch, ["0xabc"])
    tx = TypedTransaction(kind="Transfer", fields={"amount": 1})
    assert AccountKeysClient(_Node({})).send_enrolling(_EnrollingSigner(), tx) == "0xabc"
    assert sent == ["Transfer"]


def test_send_enrolling_enrolls_then_sends_again(monkeypatch):
    from tenzro.account_keys import AccountKeysClient

    sent = _stub_send(monkeypatch, [RuntimeError(NOT_ENROLLED_ANSWER), "0xenrol", "0xabc"])
    tx = TypedTransaction(kind="Transfer", fields={"amount": 1})
    assert AccountKeysClient(_Node({})).send_enrolling(_EnrollingSigner(), tx) == "0xabc"
    assert sent == ["Transfer", "AccountKeys", "Transfer"]


def test_send_enrolling_raises_any_other_refusal_without_enrolling(monkeypatch):
    from tenzro.account_keys import AccountKeysClient

    sent = _stub_send(monkeypatch, [RuntimeError("insufficient balance")])
    tx = TypedTransaction(kind="Transfer", fields={"amount": 1})
    with pytest.raises(RuntimeError, match="insufficient balance"):
        AccountKeysClient(_Node({})).send_enrolling(_EnrollingSigner(), tx)
    assert sent == ["Transfer"]


def test_an_enrolment_refused_for_no_key_is_not_retried(monkeypatch):
    from tenzro.account_keys import AccountKeysClient

    sent = _stub_send(monkeypatch, [RuntimeError(NOT_ENROLLED_ANSWER)])
    with pytest.raises(RuntimeError):
        AccountKeysClient(_Node({})).send_enrolling(
            _EnrollingSigner(), TypedTransaction(kind="AccountKeys", fields={"op": {}})
        )
    assert sent == ["AccountKeys"]
