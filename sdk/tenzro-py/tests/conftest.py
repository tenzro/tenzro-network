"""Shared helpers: the fixture directory and a recording RPC stand-in."""

import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"


def fixture(*parts: str):
    return json.loads(FIXTURES.joinpath(*parts).read_text(encoding="utf-8"))


class RecordingRpc:
    """Answers the envelope reads and stops before signing, recording every call."""

    def __init__(self):
        self.sent = []

    def call(self, method, params=None):
        self.sent.append((method, params))
        if method == "tenzro_getNonce":
            return "0x0"
        if method == "eth_chainId":
            return "0x539"
        if method == "eth_gasPrice":
            return "0x3b9aca00"
        if method == "tenzro_getSigningPayload":
            raise RuntimeError("stop before signing")
        return None

    def signing_types(self):
        return [p["tx_type"] for m, p in self.sent if m == "tenzro_getSigningPayload"]


class UnreachableSigner:
    """A signer whose key is never reached in these tests."""

    def p256_public_key(self):
        return bytes([7]) * 64

    def ml_dsa_public_key(self):
        return None

    def sign_composite(self, m_prime):
        raise AssertionError("unreachable")


@pytest.fixture
def rpc():
    return RecordingRpc()


@pytest.fixture
def signer():
    return UnreachableSigner()
