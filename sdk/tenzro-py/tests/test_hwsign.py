"""Hardware signing vectors (sdk/fixtures/hwsign): address, composite representative and the P-256 leg."""

from conftest import fixture

from tenzro.wallet import account_address, composite_message_representative

V = fixture("hwsign", "vectors.json")
XY = bytes.fromhex(V["p256_public_key_xy_hex"])


def test_the_account_address_commits_to_the_p256_key():
    assert account_address(XY)[:20].hex() == V["account_address_hex"]
    assert account_address(XY)[20:] == bytes(12)


def test_every_case_builds_the_representative_the_node_verifies():
    import hashlib

    for c in V["cases"]:
        m_prime = composite_message_representative(c["context"].encode(), bytes.fromhex(c["message_hex"]))
        assert m_prime.hex() == c["m_prime_hex"], c["context"]
        assert hashlib.sha256(m_prime).hexdigest() == c["signing_digest_hex"], c["context"]


def test_the_raw_p256_leg_verifies_under_the_hardware_key():
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, encode_dss_signature

    key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + XY)
    for c in V["cases"]:
        raw = bytes.fromhex(c["raw_signature_hex"])
        der = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
        key.verify(der, bytes.fromhex(c["signing_digest_hex"]), ec.ECDSA(Prehashed(hashes.SHA256())))
