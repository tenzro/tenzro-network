"""The keystore change digest, from the vector every SDK and the node share."""

import json
from pathlib import Path

from tenzro.keystore import KeystoreClient, keystore_digest, recovery_code_claim, recovery_code_commitment
from tenzro.typed_tx import TX_KINDS

VECTOR = json.loads((Path(__file__).resolve().parents[2] / "fixtures" / "keystore" / "digest.json").read_text(encoding="utf-8"))


def test_the_digest_matches_the_networks_for_every_change():
    assert len(VECTOR["cases"]) == 11
    for case in VECTOR["cases"]:
        got = keystore_digest(VECTOR["chain_id"], VECTOR["account"], VECTOR["previous_commitment"], case["op"]).hex()
        assert got == case["digest"], case["op"]


def test_the_digest_names_the_chain_the_change_is_for():
    op = VECTOR["cases"][2]["op"]
    here = keystore_digest(VECTOR["chain_id"], VECTOR["account"], VECTOR["previous_commitment"], op)
    there = keystore_digest(VECTOR["chain_id"] + 1, VECTOR["account"], VECTOR["previous_commitment"], op)
    assert here != there


def test_a_change_is_approved_over_its_chains_digest():
    class Signer:
        def __init__(self) -> None:
            self.signed: list[bytes] = []

        def p256_public_key(self) -> bytes:
            return bytes([9]) * 64

        def sign_composite(self, m: bytes):
            self.signed.append(m)
            return bytes([1]) * 64, None

    from tenzro.keystore import ACCOUNT_OWNER_SIGNATURE_CONTEXT
    from tenzro.wallet import composite_message_representative

    signer = Signer()
    update = {
        "chain_id": VECTOR["chain_id"],
        "account": VECTOR["account"],
        "anchor": None,
        "previous_commitment": VECTOR["previous_commitment"],
        "op": VECTOR["cases"][2]["op"],
        "approvals": [],
        "possession": None,
    }
    approved = KeystoreClient.approve(update, signer)
    assert len(approved["approvals"]) == 1
    digest = bytes.fromhex(VECTOR["cases"][2]["digest"])
    assert signer.signed[0] == composite_message_representative(ACCOUNT_OWNER_SIGNATURE_CONTEXT, digest)


def test_the_recovery_code_helpers_agree_with_the_networks():
    code = "77" * 32
    credential = VECTOR["cases"][10]["op"]["recover_with_code"]["credential"]
    commitment = recovery_code_commitment(VECTOR["chain_id"], VECTOR["account"], code).hex()
    assert commitment == VECTOR["cases"][8]["op"]["set_recovery_code"]["commitment"]
    claim = recovery_code_claim(VECTOR["chain_id"], VECTOR["account"], code, credential).hex()
    assert claim == VECTOR["cases"][9]["op"]["claim_recovery_code"]["claim"]


def test_keystore_changes_are_a_transaction_kind():
    assert "KeystoreUpdate" in TX_KINDS


def test_a_change_is_sent_as_the_network_encodes_it():
    from tenzro.typed_tx import TypedTransaction, tx_type

    encoding = json.loads((Path(__file__).resolve().parents[2] / "fixtures" / "keystore" / "encoding.json").read_text(encoding="utf-8"))
    for case in encoding["cases"]:
        tx = TypedTransaction(kind="KeystoreUpdate", fields={"update": case["update"]})
        assert tx_type(tx) == {"KeystoreUpdate": {"update": case["encoded"]}}
