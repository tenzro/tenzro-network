"""Metered work, price cards and the generic registry.

The pricing rule the node charges the calls it serves with, so a caller can
quote and check a charge itself; the registry ids of price cards; and what a
streaming payer binds and signs (the receipt chain and the voucher preimage).
The registry reads themselves are typed methods on :class:`tenzro.RpcClient`
(``tenzro_list_registry``, ``tenzro_get_registry_entry``,
``tenzro_get_price_card``, ``tenzro_price_card_to_publish``).
"""

from __future__ import annotations

import hashlib
from typing import Callable, Mapping, Optional, Union

Quantity = Union[int, str]

#: Units the network records but never charges.
RECORDED_ONLY_UNITS = ("ttft_ms", "decode_ms")


def default_billable(unit: str) -> Optional[bool]:
    """Billable by default: every unit but the recorded-only ones."""
    return unit not in RECORDED_ONLY_UNITS


def _ceil_div(a: int, b: int) -> int:
    return -(-a // b)


def charge_in_denom(
    card: Mapping, units: Mapping[str, Quantity], billable: Callable[[str], Optional[bool]] = default_billable
) -> int:
    """The charge for ``units`` in the card's denomination: each priced key
    ``ceil(q * price / 10**per_exp)``, an unpriced key nothing, at least the
    minimum. Raises when billable work exists and the card prices none of it,
    or a unit is unknown to ``billable``."""
    total, priced, unpriced = 0, False, []
    for key in sorted(units):
        q = int(units[key])
        if q == 0:
            continue
        unit = key.split("@", 1)[0]
        b = billable(unit)
        if b is None:
            raise ValueError(f"unit '{unit}' is not registered")
        if not b:
            continue
        line = card.get("lines", {}).get(key)
        if line is None:
            unpriced.append(key)
            continue
        priced = True
        total += _ceil_div(q * int(line["price"]), 10 ** int(line.get("per_exp", 0)))
    if not priced and unpriced:
        raise ValueError(f"the card prices none of the billable work metered ({', '.join(unpriced)})")
    return max(total, int(card.get("min_charge", 0)))


def charge_wei(
    card: Mapping,
    units: Mapping[str, Quantity],
    tnzo_usd_nano: int,
    billable: Callable[[str], Optional[bool]] = default_billable,
) -> int:
    """The charge in TNZO base units; a USD card converts at ``tnzo_usd_nano``
    (billionths of a dollar per TNZO, from ``tenzro_getFeeRate``), rounding up."""
    amount = charge_in_denom(card, units, billable)
    if amount == 0 or card.get("denom", "nano_usd") == "wei":
        return amount
    if tnzo_usd_nano == 0:
        raise ValueError("no TNZO/USD rate")
    return _ceil_div(amount * 10**18, tnzo_usd_nano)


def card_entry_id(provider: str, model_id: str) -> str:
    """The registry id of ``provider``'s card for ``model_id``."""
    return f"{provider.removeprefix('0x')}/card/{model_id}"


def receipt_chain_next(previous: bytes, receipt_digest: bytes) -> bytes:
    """The next head of a voucher's receipt chain."""
    return hashlib.sha256(b"tenzro/receipt-chain" + previous + receipt_digest).digest()


def escrow_voucher_preimage(chain_id: int, escrow_id: bytes, cumulative: int, binding: bytes = bytes(32)) -> bytes:
    """The bytes a payer signs for an escrow voucher: the domain, the chain,
    the escrow, the cumulative amount and the receipt-chain binding (all zero
    for a voucher signed ahead of delivery)."""
    return (
        b"tenzro/escrow-voucher"
        + chain_id.to_bytes(8, "little")
        + escrow_id
        + cumulative.to_bytes(16, "little")
        + binding
    )


#: Registry kind of a standard: the anchor is the digest of its bundle.
REGISTRY_KIND_STANDARD = "standard"
#: Registry kind of a conformance claim: the anchor is the implementation's
#: digest, the data the 32-byte bundle digests of the standards it passes.
REGISTRY_KIND_CONFORMANCE = "conformance"
#: Registry kind of a name: first come, bonded, retired by governance only.
REGISTRY_KIND_NAME = "name"
#: The registry kinds whose rules the chain enforces.
RESERVED_REGISTRY_KINDS = (REGISTRY_KIND_STANDARD, REGISTRY_KIND_CONFORMANCE, REGISTRY_KIND_NAME)


def registry_put_tx(entry_id: str, kind: str, anchor_hex: str, data: bytes) -> dict:
    """The transaction type that puts a registry entry."""
    return {"Registry": {"op": {"put": {"id": entry_id, "kind": kind, "anchor": anchor_hex, "data": data.hex()}}}}


def registry_retire_tx(entry_id: str) -> dict:
    """The transaction type that retires a registry entry."""
    return {"Registry": {"op": {"retire": {"id": entry_id}}}}
