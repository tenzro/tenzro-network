"""Compute rental: provider bonds, compute claims, the observed price feed and
renting capacity.

A provider posts a compute bond for its machine DID. Validators probe every
bonded provider and freeze one SLA verdict per provider and hour; those
availability verdicts are what every payment here settles on.

- Renting capacity now is a stream escrow: a signed ``CreateEscrow`` whose
  release is ``Stream {rate_per_epoch, epoch_ms}`` and whose payee is the
  provider's bonded address (:meth:`ComputeClient.rent`). It accrues one epoch
  at a time; an hour the validators judged the provider unavailable is never
  paid out of it and returns to the renter when the stream is stopped.
- Buying capacity ahead is a compute claim, written and bought with the
  ``ComputeClaim`` transaction and read here (:meth:`ComputeClient.get_claim`).
  A storage claim is the same record with ``storage_descriptor`` set.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Any, TypedDict

from ..rpc import RpcClient
from ..typed_tx import TypedTransaction, TypedTxClient
from ..wallet import HybridSigner

#: The hour validators freeze one SLA verdict for, in ms: the epoch a rental
#: streams over by default.
SLA_EPOCH_MS = 3_600_000

_U64_MAX = 2**64 - 1
_U128_MAX = 2**128 - 1
_HEX32 = re.compile(r"^[0-9a-f]{64}$")

#: A u128 as the node writes it: a JSON number up to ``u64::MAX``, a decimal
#: string above it.
WireU128 = int | str


class ComputeBond(TypedDict):
    """A provider's compute bond. ``provider_address`` posted it: the payee of a
    rental. ``amount`` and ``effective_amount`` are wei, decimal; ``status`` is
    ``Active``, ``Cooldown``, ``Returned`` or ``Slashed``."""

    provider_did: str
    provider_address: str
    amount: str
    status: str
    cooldown_until: int | None
    vault: str
    is_eligible: bool
    effective_amount: str


class ComputeBondParams(TypedDict):
    """The governed compute bond minimum (wei, decimal) and withdrawal cooldown (ms)."""

    min_bond_wei: str
    cooldown_ms: int


class ClaimStateTag(TypedDict):
    """``{"state": "offered" | "held" | "delivered" | "cancelled" | "lapsed"}``."""

    state: str


class ComputeClaim(TypedDict):
    """A compute claim: capacity a bonded provider promised for hour-aligned terms,
    settled each hour on the SLA verdict for its bond. ``hardware_class`` is the
    writer's statement (1 cpu, 2 consumer GPU, 3 datacenter GPU, 4
    multi-accelerator); ``storage_descriptor`` is set on a storage claim."""

    claim_id: str
    writer: str
    holder: str | None
    hardware_class: int
    region: str
    delivery_start_ms: int
    epochs: int
    strike_per_epoch: WireU128
    provider_did: str
    storage_descriptor: str | None
    unit: str | None
    units_per_epoch: WireU128
    epochs_settled: int
    collateral: WireU128
    payment: WireU128
    state: ClaimStateTag
    total_strike: str
    delivery_end_ms: int
    vault: str


class ComputeClaimList(TypedDict):
    """The claims of one party, oldest first, and how many it has in all."""

    total: int
    claims: list[ComputeClaim]


class PriceFeedEntry(TypedDict):
    """One provider and model: ``hardware_class`` and ``region`` are its announced
    claims; the rest are validator observations."""

    provider: str
    model_id: str
    hardware_class: str
    region: str
    observations: int
    distinct_observers: int
    attested: bool
    success_rate_bps: int
    latency_p50_ms: int | None
    latency_p90_ms: int | None
    price_per_1k_output_tokens_wei: str | None
    price_per_compute_second_wei: str | None
    last_observed_ms: int


class PriceFeed(TypedDict):
    """``tenzro_computePriceFeed``."""

    window_ms: int
    min_distinct_observers: int
    total: int
    entries: list[PriceFeedEntry]
    claims_note: str


def _wire_u128(v: int) -> WireU128:
    return v if v <= _U64_MAX else str(v)


def _hex32(value: str, what: str) -> str:
    h = (value.removeprefix("0x")).lower()
    if not _HEX32.match(h):
        raise ValueError(f"{what} must be 32 bytes of hex")
    return h


@dataclass
class RentRequest:
    """The terms of a rental."""

    #: The provider's bonded address (32-byte hex): the account that posted its compute bond.
    provider_address: str
    #: Paid per elapsed epoch, smallest unit of ``asset_id``.
    rate_per_epoch: int
    #: Epochs rented; the escrow locks ``rate_per_epoch * epochs``.
    epochs: int
    epoch_ms: int = SLA_EPOCH_MS
    #: ``TNZO`` or a token id, ``0x``-prefixed hex.
    asset_id: str = "TNZO"
    #: USD price of the amount in micro-units; required for an asset other than TNZO.
    usd_e6: int = 0
    #: An opaque 32-byte hex reference, so the application can find the rental again.
    reference: str | None = None

    @classmethod
    def for_bond(
        cls, bond: ComputeBond, rate_per_epoch: int, epochs: int, **terms: Any
    ) -> RentRequest:
        """A rental from the provider that posted ``bond``."""
        return cls(bond["provider_address"], rate_per_epoch, epochs, **terms)


def rent_transaction(request: RentRequest, now_ms: int) -> TypedTransaction:
    """The ``CreateEscrow`` transaction for ``request`` signed at ``now_ms``.

    The stream accrues from the block that funds it, not from ``now_ms``, so the
    escrow expires one epoch after the term would end if it were funded now:
    the funding block has that long to land and the whole term still accrues.
    Accrual never exceeds the locked amount, so the extra epoch pays nothing more.
    """
    if request.rate_per_epoch <= 0 or request.epochs <= 0 or request.epoch_ms <= 0:
        raise ValueError(
            "a rental pays a positive rate over a positive number of positive epochs"
        )
    amount = request.rate_per_epoch * request.epochs
    if amount > _U128_MAX:
        raise ValueError("rate_per_epoch * epochs overflows")
    expires_at = now_ms + (request.epochs + 1) * request.epoch_ms
    if expires_at > _U64_MAX:
        raise ValueError("the rental term overflows")
    return TypedTransaction(
        kind="CreateEscrow",
        fields={
            "payee": list(
                bytes.fromhex(_hex32(request.provider_address, "provider_address"))
            ),
            "amount": _wire_u128(amount),
            "asset_id": request.asset_id,
            "usd_e6": request.usd_e6,
            "expires_at": expires_at,
            "release_conditions": {
                "Stream": {
                    "rate_per_epoch": _wire_u128(request.rate_per_epoch),
                    "epoch_ms": request.epoch_ms,
                }
            },
            "reference": None
            if request.reference is None
            else _hex32(request.reference, "reference"),
        },
    )


class ComputeClient:
    """Compute bonds, claims, the price feed and renting."""

    def __init__(self, rpc: RpcClient):
        self._rpc = rpc

    def bond_params(self) -> ComputeBondParams:
        """The governed compute bond minimum and withdrawal cooldown."""
        return self._rpc.call("tenzro_computeBondParams", [])

    def get_bond(self, provider_did: str) -> ComputeBond | None:
        """The compute bond posted for ``provider_did``, or ``None`` when it has never posted one."""
        return self._rpc.call("tenzro_getComputeBond", [{"provider_did": provider_did}])

    def list_bonds(self) -> list[ComputeBond]:
        """Every compute bond on chain."""
        return self._rpc.call("tenzro_listComputeBonds", [])["bonds"]

    def get_claim(self, claim_id: str) -> ComputeClaim:
        """One compute claim from chain state; the node answers an error when there is none."""
        return self._rpc.call("tenzro_computeGetClaim", {"claim_id": claim_id})

    def list_claims(self, party: str, limit: int | None = None) -> ComputeClaimList:
        """The claims ``party`` (hex address) has written, held or been pledged, oldest
        first; the node defaults ``limit`` to 100, at most 1000."""
        params: dict[str, Any] = {"party": party}
        if limit is not None:
            params["limit"] = limit
        return self._rpc.call("tenzro_computeListClaims", params)

    def price_feed(
        self,
        *,
        model_id: str | None = None,
        hardware_class: str | None = None,
        region: str | None = None,
        attested_only: bool = False,
        limit: int | None = None,
    ) -> PriceFeed:
        """What validators observed each provider charge, how fast it served and how
        often it failed. ``hardware_class`` is ``cpu``, ``consumer_gpu``,
        ``datacenter_gpu`` or ``multi_accelerator``."""
        fields = {
            "model_id": model_id,
            "hardware_class": hardware_class,
            "region": region,
            "limit": limit,
        }
        params: dict[str, Any] = {k: v for k, v in fields.items() if v is not None}
        if attested_only:
            params["attested_only"] = True
        return self._rpc.call("tenzro_computePriceFeed", params)

    def rent(self, signer: HybridSigner, request: RentRequest) -> Any:
        """Rent capacity from a bonded provider: sign and submit the stream escrow
        :func:`rent_transaction` builds. The provider draws each accrued epoch with
        ``ClaimEscrowStream``; the renter stops the rental with ``RefundEscrow``."""
        return TypedTxClient(self._rpc).send(
            signer, rent_transaction(request, int(time.time() * 1000))
        )


__all__ = [
    "SLA_EPOCH_MS",
    "ClaimStateTag",
    "ComputeBond",
    "ComputeBondParams",
    "ComputeClaim",
    "ComputeClaimList",
    "ComputeClient",
    "PriceFeed",
    "PriceFeedEntry",
    "RentRequest",
    "WireU128",
    "rent_transaction",
]
