"""The pricing rule and the voucher preimage, against the node's vectors."""

import pytest

from tenzro.inference import (
    RESERVED_REGISTRY_KINDS,
    card_entry_id,
    charge_in_denom,
    charge_wei,
    escrow_voucher_preimage,
    receipt_chain_next,
    registry_retire_tx,
)


def card(denom, lines, minimum=0):
    return {"denom": denom, "lines": {k: {"price": str(p), "per_exp": e} for k, p, e in lines}, "min_charge": str(minimum)}


A = card("nano_usd", [("input_tokens", 200000000, 6), ("output_tokens", 1000000000, 6)])


def test_the_charge_vectors_hold():
    assert charge_in_denom(A, {"input_tokens": 1000, "output_tokens": 500}) == 700000
    assert charge_wei(A, {"input_tokens": 1000000}, 500000000) == 400000000000000000
    assert charge_wei(card("wei", [("pixel_steps", 2000000, 0)]), {"pixel_steps": 31719424}, 0) == 63438848000000
    assert charge_in_denom(card("nano_usd", [("bandwidth_bytes", 10000000, 9)]), {"bandwidth_bytes": 1000000006}) == 10000001
    with pytest.raises(ValueError, match="prices none"):
        charge_in_denom(A, {"output_tokens@priority": 1})
    assert charge_in_denom(A, {"input_tokens": 1000, "ttft_ms": 250}) == 200000


def test_the_voucher_preimage_binds_the_receipt_chain():
    z, e = bytes(32), bytes([1]) * 32
    a = escrow_voucher_preimage(1337, e, 5, z)
    assert len(a) == len(b"tenzro/escrow-voucher") + 8 + 32 + 16 + 32
    assert a[21:29].hex() == "3905000000000000" and a[61] == 5
    assert a != escrow_voucher_preimage(1337, e, 5, bytes([2]) * 32)
    h1 = receipt_chain_next(z, e)
    assert receipt_chain_next(h1, bytes([2]) * 32) != receipt_chain_next(receipt_chain_next(z, bytes([2]) * 32), e)


def test_registry_helpers():
    assert card_entry_id("0xab", "m") == "ab/card/m"
    assert registry_retire_tx("x") == {"Registry": {"op": {"retire": {"id": "x"}}}}
    assert RESERVED_REGISTRY_KINDS == ("standard", "conformance", "name")
