"""Decentralized storage on a node serving the ``storage`` role.

The provider erasure-codes each object and publishes its shards over the
content-addressed transport. It prices storage at a fixed rate per byte-epoch
that never follows demand (:meth:`StorageClient.set_fixed_rate`).

Storage is held to proofs of retrievability: a renter pays for keeping an
object through a storage compute claim that commits the object's descriptor
digest (``descriptor_digest`` in :class:`StoredObject`), and each hour the
claim pays the provider only if validators found its bond available, which
requires a possession proof of the object. The claim is written and bought with
the ``ComputeClaim`` transaction and read with
:meth:`tenzro.chain.compute.ComputeClient.get_claim`, where
``storage_descriptor`` names the object.

These calls target the provider node directly; they succeed only when that
node is serving the storage role.
"""

from __future__ import annotations

import base64
from typing import Any, TypedDict

from ..did_envelope import with_request_envelope
from ..rpc import RpcClient
from ..wallet import HybridSigner


class StoredObject(TypedDict):
    """``tenzro_storageStoreObject``: the stored size and shard layout, and the
    hex SHA-256 of the object descriptor a storage compute claim commits to."""

    object_id: str
    size_bytes: int
    data_shards: int
    parity_shards: int
    descriptor_digest: str | None


class Placement(TypedDict, total=False):
    """Where an object's shards may be held: in one of ``jurisdiction`` (country codes,
    by the region each holder declares), by one of ``operators`` (provider accounts,
    hex), or both."""

    jurisdiction: list[str]
    operators: list[str]


class StorageStatus(TypedDict):
    """``tenzro_storageStatus``: the effective byte-epoch rate in wei (decimal)
    and the number of objects this provider holds."""

    is_storage_provider: bool
    effective_rate_wei: str
    object_count: int


class StorageClient:
    """Stores and reads back objects on a storage provider."""

    def __init__(self, rpc: RpcClient):
        self._rpc = rpc

    def store_object(
        self,
        object_id: str,
        owner: str,
        data: bytes,
        owner_did: str,
        signer: HybridSigner,
        *,
        data_shards: int = 4,
        parity_shards: int = 2,
        placement: Placement | None = None,
        storage_class: str | None = None,
    ) -> StoredObject:
        """Store ``data`` owned by ``owner_did`` (only it may read the object back),
        erasure-coded into ``data_shards`` + ``parity_shards``. ``signer`` holds the
        key ``owner_did`` resolves to and signs the request's envelope. ``placement``
        limits which holders may take its shards; the storing node must itself be
        inside it. ``storage_class`` (``hot``, ``warm`` or ``cold``) is the class the
        object is bought under, which prices its reads."""
        method = "tenzro_storageStoreObject"
        request: dict[str, Any] = {
            "object_id": object_id,
            "owner": owner,
            "data": base64.b64encode(data).decode(),
            "data_shards": data_shards,
            "parity_shards": parity_shards,
            "owner_did": owner_did,
        }
        if placement is not None:
            request["placement"] = placement
        if storage_class is not None:
            if storage_class not in ("hot", "warm", "cold"):
                raise ValueError("storage_class is hot, warm or cold")
            request["class"] = storage_class
        params = with_request_envelope(signer, owner_did, method, request)
        return self._rpc.call(method, params)

    def retrieve_object(
        self,
        object_id: str,
        reader_did: str,
        signer: HybridSigner,
        *,
        voucher: dict[str, Any] | None = None,
    ) -> bytes:
        """The object's bytes, rebuilt from its shards for ``reader_did``, whom its access
        policy must admit; ``signer`` holds the key ``reader_did`` resolves to. An object
        stored under a priced class is paid with ``voucher``, a channel voucher to the
        node covering the read."""
        method = "tenzro_storageRetrieveObject"
        request: dict[str, Any] = {"object_id": object_id}
        if voucher is not None:
            request["voucher"] = voucher
        params = with_request_envelope(signer, reader_did, method, request)
        out = self._rpc.call(method, params)
        return base64.b64decode(out["data"], validate=True)

    def set_fixed_rate(self, rate: int) -> dict[str, Any]:
        """Set the provider's fixed byte-epoch rate in wei, what deals opened from now on
        pay (operator only)."""
        if rate < 0:
            raise ValueError("rate is a non-negative amount of wei")
        return self._rpc.call(
            "tenzro_storageSetPricing", [{"mode": "fixed", "rate": str(rate)}]
        )

    def holding_receipt(self, object_id: str) -> dict[str, Any] | None:
        """This node's signed receipt for the shards of ``object_id`` it holds now under
        a placement constraint, or ``None`` when it holds none."""
        return self._rpc.call("tenzro_getStorageHoldingReceipt", [{"object_id": object_id}])

    def providers(self) -> dict[str, Any]:
        """The storage providers the node has heard announce, best record first, each
        with its standing read from consensus state and whether any verdict judged it."""
        return self._rpc.call("tenzro_listStorageProviders", {})

    def set_read_rates(self, rate: int, hot: int, warm: int, cold: int) -> dict[str, Any]:
        """Set the byte-epoch rate and what reading each class costs, wei per gibibyte
        read, each under its governed ceiling (operator only)."""
        if min(rate, hot, warm, cold) < 0:
            raise ValueError("rates are non-negative amounts of wei")
        return self._rpc.call(
            "tenzro_storageSetPricing",
            [
                {
                    "mode": "fixed",
                    "rate": str(rate),
                    "read_rates": {"hot": str(hot), "warm": str(warm), "cold": str(cold)},
                }
            ],
        )

    def status(self) -> StorageStatus:
        """This node's storage-provider status."""
        return self._rpc.call("tenzro_storageStatus", [])


__all__ = ["Placement", "StorageClient", "StorageStatus", "StoredObject"]
