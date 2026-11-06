"""Bridge sends over a governed route, built as the network decodes them
(checked against ``sdk/fixtures/payment-ops``) and signed with the caller's
hardware key."""

from __future__ import annotations

import re
from typing import Any

from ..rpc import RpcClient
from ..typed_tx import TypedTransaction, TypedTxClient
from ..wallet import HybridSigner

_HEX = re.compile(r"^[0-9a-f]+$")


def _strip(h: str) -> str:
    return h[2:] if h.startswith("0x") else h


def outbound_fields(target_chain: str, recipient: str, amount: int, asset: str | None = None) -> dict[str, Any]:
    """The ``Bridge`` transaction fields that send ``amount`` base units to ``recipient`` (hex) on ``target_chain``.

    ``asset`` names a carried asset (``USDC``), whose representation is burned
    here and released from the route's vault there; omit it to move TNZO, or
    the deposit asset over a deposit route.
    """
    to = _strip(recipient).lower()
    if not to or len(to) % 2 or not _HEX.match(to):
        raise ValueError("recipient must be non-empty hex")
    if amount <= 0:
        raise ValueError("amount must be positive")
    return {
        "op": {
            "outbound": {
                "target_chain": target_chain.lower(),
                "recipient": to,
                "amount": str(amount),
                "asset": asset.upper() if asset else None,
            }
        }
    }


def bridge_send(
    rpc: RpcClient, signer: HybridSigner, target_chain: str, recipient: str, amount: int, asset: str | None = None
) -> Any:
    """Send ``amount`` out over the governed route to ``target_chain`` as a ``Bridge`` transaction ``signer`` signs."""
    fields = outbound_fields(target_chain, recipient, amount, asset)
    return TypedTxClient(rpc).send(signer, TypedTransaction(kind="Bridge", fields=fields))
