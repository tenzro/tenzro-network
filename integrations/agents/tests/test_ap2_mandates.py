"""AP2 mandate-helper tests (no network)."""

from __future__ import annotations

from tenzro_agents.core import (
    cart_item,
    cart_mandate,
    checkout_hash,
    checkout_mandate,
    intent_mandate,
    payment_mandate,
)


def test_intent_mandate_vct_variants():
    closed = intent_mandate(
        principal_did="did:tenzro:human:cfo",
        agent_did="did:tenzro:machine:bot",
        description="buy widgets",
        max_amount=1000,
    )
    assert closed["vct"] == "mandate.intent.1"
    open_m = intent_mandate(
        principal_did="did:tenzro:human:cfo",
        agent_did="did:tenzro:machine:bot",
        description="buy widgets",
        max_amount=1000,
        open_mandate=True,
        cnf={"jwk": {"kty": "OKP"}},
    )
    assert open_m["vct"] == "mandate.intent.open.1"
    assert "cnf" in open_m


def test_cart_totals_sum_line_items():
    items = [
        cart_item(sku="A", description="a", quantity=2, unit_price=150),
        cart_item(sku="B", description="b", quantity=1, unit_price=400),
    ]
    cart = cart_mandate(
        agent_did="did:tenzro:machine:bot",
        merchant_did="did:tenzro:machine:vendor",
        items=items,
    )
    assert cart["total_amount"] == 2 * 150 + 400
    assert cart["items"][0]["total"] == 300


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
