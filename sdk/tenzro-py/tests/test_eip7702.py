"""The EIP-7702 reference vector under sdk/fixtures/eip7702 was signed by an
independent wallet library; the builders reproduce its digests and bytes."""

import json
from pathlib import Path

import pytest

from tenzro.bridge import eip7702

VECTORS = json.loads(
    (Path(__file__).resolve().parents[3] / "sdk" / "fixtures" / "eip7702" / "vectors.json").read_text(encoding="utf-8")
)
A = VECTORS["authorization"]
T = VECTORS["transaction"]


def _tx(auths):
    return {
        "chain_id": T["chain_id"],
        "nonce": T["nonce"],
        "max_priority_fee_per_gas": int(T["max_priority_fee_per_gas"]),
        "max_fee_per_gas": int(T["max_fee_per_gas"]),
        "gas_limit": T["gas_limit"],
        "to": T["to"],
        "value": int(T["value"]),
        "data": T["data"],
        "access_list": T["access_list"],
        "authorization_list": auths,
    }


AUTH = {
    "chain_id": A["chain_id"],
    "address": A["address"],
    "nonce": A["nonce"],
    "signature": {"y_parity": A["y_parity"], "r": A["r"], "s": A["s"]},
}


def test_keccak_matches_its_reference():
    assert eip7702.keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    assert eip7702.keccak256(b"\x00" * 200).hex() == eip7702.keccak256(bytes(200)).hex()


def test_authorization_digest_matches_the_wallet():
    assert eip7702.authorization_signing_hash(A["chain_id"], A["address"], A["nonce"]) == A["signing_hash"]


def test_transaction_digest_raw_and_hash_match_the_wallet():
    tx = _tx([AUTH])
    assert eip7702.set_code_transaction_signing_hash(tx) == T["signing_hash"]
    raw = eip7702.encode_signed_set_code_transaction(tx, {"y_parity": T["y_parity"], "r": T["r"], "s": T["s"]})
    assert raw == T["raw"]
    assert eip7702.raw_transaction_hash(raw) == T["hash"]


def test_a_transaction_without_authorizations_is_refused():
    with pytest.raises(ValueError):
        eip7702.set_code_transaction_signing_hash(_tx([]))


def test_designator():
    assert eip7702.delegation_designator(A["address"]) == "0xef0100" + A["address"][2:]
