"""A controller's DID envelope over a machine registration, pinned to the
shared vector the node's envelope code is checked against."""

import hashlib
import json
from pathlib import Path

from tenzro.did_envelope import (
    DID_ENVELOPE_CONTEXT,
    DidEnvelopeFields,
    request_binding,
    with_request_envelope,
)
from tenzro.wallet import composite_message_representative

VECTOR = json.loads(
    (Path(__file__).parents[2] / "fixtures" / "did_envelope" / "machine_registration.json").read_text("utf-8")
)


class VectorSigner:
    """Answers only for the vector's message representative."""

    def p256_public_key(self) -> bytes:
        return bytes.fromhex(VECTOR["controller_public_key"])

    def sign_composite(self, m_prime: bytes):
        assert m_prime.hex() == VECTOR["m_prime"]
        return bytes.fromhex(VECTOR["signature"]["classical"]["signature"]), None


def test_the_binding_preimage_and_header_match_the_node():
    binding = request_binding(VECTOR["request"])
    assert binding.decode() == VECTOR["request_binding"]
    assert request_binding({**VECTOR["request"], "did_envelope": "ff"}) == binding
    fields = DidEnvelopeFields(
        did=VECTOR["did"],
        method=VECTOR["method"],
        params_hash=hashlib.sha256(binding).digest(),
        timestamp_ms=VECTOR["timestamp_ms"],
        nonce=bytes.fromhex(VECTOR["nonce"]),
    )
    assert fields.params_hash.hex() == VECTOR["params_hash"]
    assert fields.preimage().hex() == VECTOR["preimage"]
    assert composite_message_representative(DID_ENVELOPE_CONTEXT, fields.preimage()).hex() == VECTOR["m_prime"]
    assert fields.header(VECTOR["signature"]) == VECTOR["did_envelope"]


def test_the_signer_signs_the_vector_envelope():
    signed = with_request_envelope(
        VectorSigner(),
        VECTOR["did"],
        VECTOR["method"],
        VECTOR["request"],
        timestamp_ms=VECTOR["timestamp_ms"],
        nonce=bytes.fromhex(VECTOR["nonce"]),
    )
    assert signed["did_envelope"] == VECTOR["did_envelope"]
    assert {k: v for k, v in signed.items() if k != "did_envelope"} == VECTOR["request"]
