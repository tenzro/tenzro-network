"""Envelope canonical-preimage + signature round-trip tests.

Pins the canonical preimage layout that the Rust ``tenzro-identity``
envelope module (``crates/tenzro-identity/src/envelope.rs``) matches
byte-for-byte:

    DOMAIN_TAG || u32_be(len(did)) || did_utf8
      || u32_be(len(method)) || method_utf8
      || params_hash(32) || timestamp_u64_be(8) || nonce(16)
"""

from __future__ import annotations

import nacl.signing

from tenzro_agents.core import (
    DOMAIN_TAG,
    TenzroDidEnvelope,
    canonical_params_hash,
    canonical_preimage,
)


def test_canonical_params_hash_is_sorted_compact_json():
    # Key order must not matter; encoding is sort_keys + compact.
    a = canonical_params_hash({"b": 2, "a": 1})
    b = canonical_params_hash({"a": 1, "b": 2})
    assert a == b
    # 32-byte SHA-256 -> 64 hex chars.
    assert len(a) == 64


def test_preimage_layout_is_stable():
    did = "did:tenzro:machine:0xabc"
    method = "ap2.cart.complete"
    ph = canonical_params_hash({"amount": 100})
    ts = 1_700_000_000_000
    nonce = bytes(range(16))

    msg = canonical_preimage(did, method, ph, ts, nonce)

    # Domain tag first.
    assert msg.startswith(DOMAIN_TAG)
    rest = msg[len(DOMAIN_TAG):]
    # u32_be length prefix + did (UTF-8).
    did_b = did.encode()
    method_b = method.encode()
    assert rest[:4] == len(did_b).to_bytes(4, "big")
    rest = rest[4:]
    assert rest[:len(did_b)] == did_b
    rest = rest[len(did_b):]
    # u32_be length prefix + method (UTF-8).
    assert rest[:4] == len(method_b).to_bytes(4, "big")
    rest = rest[4:]
    assert rest[:len(method_b)] == method_b
    rest = rest[len(method_b):]
    # 32-byte params hash.
    assert rest[:32] == bytes.fromhex(ph)
    rest = rest[32:]
    # timestamp big-endian u64 (milliseconds).
    assert rest[:8] == ts.to_bytes(8, "big")
    rest = rest[8:]
    # 16-byte nonce, nothing trailing.
    assert rest == nonce


def test_envelope_round_trip_verifies_with_public_key():
    sk = nacl.signing.SigningKey.generate()
    vk = sk.verify_key
    did = "did:tenzro:machine:0xfeed"

    env = TenzroDidEnvelope.sign(
        sk,
        did,
        "tenzro_postTask",
        {"kind": "research", "budget": 500},
    )

    # The envelope's signature verifies against the public key.
    assert env.verify(vk) is True

    # And a raw NaCl verify over the recomputed preimage also passes.
    vk.verify(env.preimage(), bytes.fromhex(env.signature))

    # Wire serialisation has all six fields.
    d = env.to_dict()
    assert set(d) == {
        "did", "method", "params_hash", "timestamp", "nonce", "signature"
    }
    assert len(bytes.fromhex(d["nonce"])) == 16


def test_tampered_params_fails_verification():
    sk = nacl.signing.SigningKey.generate()
    vk = sk.verify_key
    env = TenzroDidEnvelope.sign(sk, "did:tenzro:machine:0x1", "m", {"x": 1})

    # Tamper with the params hash -> signature must no longer verify.
    tampered = TenzroDidEnvelope(
        did=env.did,
        method=env.method,
        params_hash=canonical_params_hash({"x": 2}),
        timestamp=env.timestamp,
        nonce=env.nonce,
        signature=env.signature,
    )
    assert tampered.verify(vk) is False


def test_wrong_key_fails_verification():
    sk = nacl.signing.SigningKey.generate()
    other_vk = nacl.signing.SigningKey.generate().verify_key
    env = TenzroDidEnvelope.sign(sk, "did:tenzro:machine:0x1", "m", {"x": 1})
    assert env.verify(other_vk) is False


def test_deterministic_preimage_given_fixed_ts_and_nonce():
    sk = nacl.signing.SigningKey(bytes([7] * 32))
    nonce = bytes([9] * 16)
    e1 = TenzroDidEnvelope.sign(
        sk, "did:tenzro:machine:0x1", "m", {"a": 1}, timestamp=42, nonce=nonce
    )
    e2 = TenzroDidEnvelope.sign(
        sk, "did:tenzro:machine:0x1", "m", {"a": 1}, timestamp=42, nonce=nonce
    )
    # Ed25519 is deterministic; identical inputs -> identical signature.
    assert e1.signature == e2.signature
    assert e1.preimage() == e2.preimage()
