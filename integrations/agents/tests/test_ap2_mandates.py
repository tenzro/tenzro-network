"""AP2 mandate-helper tests (no network)."""

from __future__ import annotations

from tenzro_agents.core import (
    cart_item,
    checkout_hash,
    checkout_mandate,
    payment_mandate,
)


def test_checkout_mandate_vct_variants():
    closed = checkout_mandate(
        principal_did="did:tenzro:human:cfo",
        agent_did="did:tenzro:machine:bot",
        description="buy widgets",
        max_amount=1000,
    )
    assert closed["vct"] == "mandate.checkout.1"
    assert closed["presence"] == "HumanPresent"
    open_m = checkout_mandate(
        principal_did="did:tenzro:human:cfo",
        agent_did="did:tenzro:machine:bot",
        description="buy widgets",
        max_amount=1000,
        human_present=False,
        cnf={"jwk": {"kty": "OKP"}},
    )
    assert open_m["vct"] == "mandate.checkout.open.1"
    assert "cnf" in open_m


def test_payment_totals_sum_line_items():
    checkout = checkout_mandate(
        principal_did="did:tenzro:human:cfo",
        agent_did="did:tenzro:machine:bot",
        description="buy widgets",
        max_amount=1000,
    )
    items = [
        cart_item(sku="A", description="a", quantity=2, unit_price=150),
        cart_item(sku="B", description="b", quantity=1, unit_price=400),
    ]
    payment = payment_mandate(
        checkout=checkout,
        agent_did="did:tenzro:machine:bot",
        merchant_did="did:tenzro:machine:vendor",
        items=items,
        chain="tenzro",
    )
    assert payment["total_amount"] == 2 * 150 + 400
    assert payment["items"][0]["total"] == 300


def test_payment_mandate_binds_checkout_hash_and_id():
    checkout = checkout_mandate(
        principal_did="did:tenzro:human:cfo",
        agent_did="did:tenzro:machine:bot",
        description="procurement",
        max_amount=3400,
        accepted_chains=["solana:mainnet"],
        human_present=False,
    )
    assert checkout["vct"] == "mandate.checkout.open.1"
    assert checkout["presence"] == "HumanNotPresent"

    items = [cart_item(sku="C", description="c", quantity=1, unit_price=3400)]
    payment = payment_mandate(
        checkout=checkout,
        agent_did="did:tenzro:machine:bot",
        merchant_did="did:tenzro:machine:vendorC",
        items=items,
        chain="solana:mainnet",
        human_present=False,
    )
    assert payment["checkout_mandate_id"] == checkout["mandate_id"]
    assert payment["checkout_hash"] == checkout_hash(checkout)
    assert payment["total_amount"] == 3400
    assert payment["vct"] == "mandate.payment.open.1"
