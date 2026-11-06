"""Every account this SDK derives is the one Tenzro derives (sdk/fixtures/remote_grant)."""

import pytest
from conftest import fixture

from tenzro.bridge import (
    act_digest,
    channel_voucher_digest,
    encode_action,
    grant_tree_key,
    omni_address,
    omni_salt,
    pay_data,
    proven_payment_tx,
    remote_grant_settle_tx,
    to_caip10,
    to_erc7930,
)
from tenzro.hashes import blake2b256, keccak256

V = fixture("remote_grant", "vectors.json")


def test_keccak_and_blake2b_match_their_reference_vectors():
    assert keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    assert blake2b256(b"abc").hex() == "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"


def test_every_account_and_digest_matches_the_vectors():
    for c in V["chains"]:
        a = omni_address(V["did"], c["chain"], c["deployment"])
        assert a.address == c["account"], c["chain"]
        assert a.raw.hex() == c["account_raw"], c["chain"]
        assert to_caip10(a) == c["caip10"], c["chain"]
        erc = to_erc7930(a)
        assert (erc.hex() if erc is not None else None) == c["erc7930"], c["chain"]
        assert omni_salt(V["did"]).hex() == c["salt"]
        assert grant_tree_key(V["did"], c["chain"]).hex() == c["tree_key"]
        action = encode_action(c["action"])
        assert action.hex() == c["action"]["encoded"]
        assert act_digest(c["chain"], bytes.fromhex(c["account_word"]), 1, 0, action).hex() == c["action_digest"]


def test_a_deployment_of_another_family_is_refused():
    with pytest.raises(ValueError):
        omni_address("did:x", "eip155:1", {"family": "solana", "program_id": [7] * 32})


def test_settle_and_proven_payment_transactions_carry_the_delivery():
    assert remote_grant_settle_tx("did:x", "eip155:1", b"\x01\x02") == {
        "RemoteGrantSettle": {"agent_did": "did:x", "chain": "eip155:1", "delivery": "0102"}
    }
    assert proven_payment_tx("did:x", "eip155:1", b"\x01\x02") == {
        "Payment": {"op": {"proven": {"agent_did": "did:x", "chain": "eip155:1", "delivery": "0102"}}}
    }


def test_a_channel_voucher_digest_and_pay_data_match_the_account_layout():
    account = bytes(12) + bytes([0x11]) * 20
    assert channel_voucher_digest("eip155:8453", account, 7, 1000).hex() == "046c669c72b5951a78639fc0849f070e8a5c2a8d0ddc0760d631aac95a2523d9"
    d = pay_data(bytes([1]) * 32, bytes([2]) * 32, bytes([3]) * 32, 30)
    assert len(d) == 104 and d[96:].hex() == "000000000000001e"
    with pytest.raises(ValueError):
        pay_data(bytes(31), bytes(32), bytes(32), 1)
