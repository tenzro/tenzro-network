"""The hardware signer: no hardware, no key; a device key signs composites and DPoP proofs."""

import base64
import hashlib
import json
import sys

import pytest

from tenzro.signer import DeviceKeySigner, HardwareDpopProver, NoHardwareSigner, jwk_thumbprint, open_hardware_signer
from tenzro.wallet import HybridSigner


class FakeDeviceKey:
    """Stands in for the native binding's DeviceKey: fixed public key, fixed signature."""

    backend = "tpm"
    label = "test"

    def __init__(self):
        self.digests = []

    def public_key(self):
        return b"\x04" + bytes([1]) * 32 + bytes([2]) * 32

    def sign_digest(self, digest):
        self.digests.append(digest)
        return bytes([9]) * 64

    def attest(self):
        return "tpm", b"evidence", self.public_key()


def _b64(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def test_without_hardware_there_is_no_key(monkeypatch):
    monkeypatch.setitem(sys.modules, "tenzro_device_key", None)
    with pytest.raises(NoHardwareSigner, match="no software key"):
        open_hardware_signer("agent")
    with pytest.raises(ValueError):
        open_hardware_signer("")


def test_a_device_key_signs_the_p256_leg_over_sha256_of_m_prime():
    key = FakeDeviceKey()
    signer = DeviceKeySigner(key)
    assert isinstance(signer, HybridSigner)
    assert signer.p256_public_key() == bytes([1]) * 32 + bytes([2]) * 32
    classical, pq = signer.sign_composite(b"m-prime")
    assert classical == bytes([9]) * 64 and pq is None
    assert key.digests == [hashlib.sha256(b"m-prime").digest()]
    assert signer.attest().evidence == b"evidence"
    with pytest.raises(ValueError):
        signer.sign_digest(b"short")


def test_a_dpop_proof_is_es256_over_the_hardware_key_and_bound_to_the_token():
    key = FakeDeviceKey()
    prover = HardwareDpopProver(DeviceKeySigner(key))
    proof = prover.proof("POST", "https://node.example", "token")
    header, payload, sig = proof.split(".")
    h = json.loads(_b64(header))
    p = json.loads(_b64(payload))
    assert h["typ"] == "dpop+jwt" and h["alg"] == "ES256" and h["jwk"]["kty"] == "EC"
    assert p["htm"] == "POST" and p["htu"] == "https://node.example"
    assert _b64(p["ath"]) == hashlib.sha256(b"token").digest()
    assert _b64(sig) == bytes([9]) * 64
    assert key.digests[-1] == hashlib.sha256(f"{header}.{payload}".encode()).digest()
    assert prover.jkt() == jwk_thumbprint(h["jwk"])
