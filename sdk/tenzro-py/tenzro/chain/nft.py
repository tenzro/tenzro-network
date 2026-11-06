"""NFTs: the network's NFT factory precompile at ``0x…1006``, which keeps
ERC-721 and ERC-1155 collections in consensus state.

Writes are EVM calls inside a ``ContractCall`` transaction signed by the
account that acts: the collection's creator creates, mints and registers
pointers, a token's owner transfers it, and anyone fulfils a random mint two
blocks after its request. :func:`nft_transaction` builds that transaction for
:class:`~tenzro.TypedTxClient`. Reads are ``eth_call`` through
:class:`NftClient`. Every calldata builder and decoder here is offline.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any, Literal

from ..typed_tx import TypedTransaction
from .abi import abi_decode, encode_with_selector, event_topic

__all__ = [
    "NFT_FACTORY_ADDRESS",
    "NFT_MAX_BATCH",
    "NFT_MAX_ID",
    "NFT_MAX_TEXT",
    "NFT_SELECTORS",
    "NFT_TRANSFER_TOPIC",
    "NftClient",
    "NftCollection",
    "NftTransfer",
    "decode_nft_transfer",
    "nft_call",
    "nft_calldata",
    "nft_collection_id",
    "nft_decode",
    "nft_transaction",
]

NFT_FACTORY_ADDRESS = "0x0000000000000000000000000000000000001006"

#: The factory's function selectors (fixed values, not all the hash of their signature).
NFT_SELECTORS = {
    "createCollection": "0xe9c3ab8b",
    "getCollection": "0xf5c1f76e",
    "mint": "0x40c10f19",
    "mintBatch": "0xb48ab8b6",
    "transferNft": "0x26a75453",
    "ownerOf": "0x6352211e",
    "balanceOf": "0x00fdd58e",
    "tokenUri": "0x0e89341c",
    "registerEvmPointer": "0x1a6d2e4f",
    "registerSvmPointer": "0x2b7ce500",
    "mintMulti": "0x731133e9",
    "balanceOfMulti": "0x4e1273f4",
    "mintRandom": "0xd3622f7b",
    "fulfillRandom": "0xdd68a4e3",
}

NFT_TRANSFER_TOPIC = event_topic("NftTransfer(bytes32,address,address,uint256)")
NFT_MAX_TEXT = 512
NFT_MAX_BATCH = 256
NFT_MAX_ID = (1 << 128) - 1

NftStandard = Literal["erc721", "erc1155"]
_STANDARD = {"erc721": 0, "erc1155": 1}


def _fixed(h: str | bytes, n: int, what: str) -> bytes:
    if isinstance(h, (bytes, bytearray)):
        b = bytes(h)
    else:
        s = h[2:] if h.startswith("0x") else h
        if not re.fullmatch(r"[0-9a-fA-F]*", s) or len(s) != 2 * n:
            raise ValueError(f"{what} must be {n} bytes of hex")
        b = bytes.fromhex(s)
    if len(b) != n:
        raise ValueError(f"{what} must be {n} bytes of hex")
    return b


def _id(v: str | bytes) -> bytes:
    return _fixed(v, 32, "collection id")


def _addr(v: str | bytes, what: str = "address") -> bytes:
    return _fixed(v, 20, what)


def _to(v: str | bytes) -> bytes:
    b = _addr(v, "recipient")
    if not any(b):
        raise ValueError("the recipient may not be the zero address")
    return b


def _tok(v: int | str, what: str = "token id") -> int:
    n = int(v)
    if not 0 <= n <= NFT_MAX_ID:
        raise ValueError(f"{what} must fit 128 bits")
    return n


def _text(s: str, what: str) -> str:
    if len(s.encode()) > NFT_MAX_TEXT:
        raise ValueError(f"{what} is longer than {NFT_MAX_TEXT} bytes")
    return s


class _Calldata:
    """Calldata for each factory function."""

    @staticmethod
    def create_collection(name: str, symbol: str, standard: NftStandard = "erc721") -> bytes:
        if name == "":
            raise ValueError("a collection needs a name")
        return encode_with_selector(
            NFT_SELECTORS["createCollection"], ["string", "string", "uint8"],
            [_text(name, "name"), _text(symbol, "symbol"), _STANDARD[standard]],
        )

    @staticmethod
    def get_collection(collection_id: str | bytes) -> bytes:
        return encode_with_selector(NFT_SELECTORS["getCollection"], ["bytes32"], [_id(collection_id)])

    @staticmethod
    def mint(collection_id: str | bytes, to: str | bytes, token: int | str, uri: str = "") -> bytes:
        return encode_with_selector(
            NFT_SELECTORS["mint"], ["bytes32", "address", "uint256", "string"],
            [_id(collection_id), _to(to), _tok(token), _text(uri, "token URI")],
        )

    @staticmethod
    def mint_batch(collection_id: str | bytes, to: str | bytes, tokens: list[int | str], uris: list[str] | None = None) -> bytes:
        uris = uris or []
        if not 1 <= len(tokens) <= NFT_MAX_BATCH:
            raise ValueError(f"a batch holds 1 to {NFT_MAX_BATCH} tokens")
        if len(uris) > len(tokens):
            raise ValueError("more URIs than tokens")
        return encode_with_selector(
            NFT_SELECTORS["mintBatch"], ["bytes32", "address", "uint256[]", "string[]"],
            [_id(collection_id), _to(to), [_tok(t) for t in tokens], [_text(u, "token URI") for u in uris]],
        )

    @staticmethod
    def transfer(collection_id: str | bytes, to: str | bytes, token: int | str) -> bytes:
        return encode_with_selector(
            NFT_SELECTORS["transferNft"], ["bytes32", "address", "uint256"], [_id(collection_id), _to(to), _tok(token)]
        )

    @staticmethod
    def owner_of(collection_id: str | bytes, token: int | str) -> bytes:
        return encode_with_selector(NFT_SELECTORS["ownerOf"], ["bytes32", "uint256"], [_id(collection_id), _tok(token)])

    @staticmethod
    def balance_of(collection_id: str | bytes, owner: str | bytes) -> bytes:
        return encode_with_selector(NFT_SELECTORS["balanceOf"], ["bytes32", "address"], [_id(collection_id), _addr(owner, "owner")])

    @staticmethod
    def token_uri(collection_id: str | bytes, token: int | str) -> bytes:
        return encode_with_selector(NFT_SELECTORS["tokenUri"], ["bytes32", "uint256"], [_id(collection_id), _tok(token)])

    @staticmethod
    def register_evm_pointer(collection_id: str | bytes, evm_contract: str | bytes) -> bytes:
        return encode_with_selector(
            NFT_SELECTORS["registerEvmPointer"], ["bytes32", "address"], [_id(collection_id), _addr(evm_contract, "EVM contract")]
        )

    @staticmethod
    def register_svm_pointer(collection_id: str | bytes, svm_mint: str | bytes) -> bytes:
        return encode_with_selector(
            NFT_SELECTORS["registerSvmPointer"], ["bytes32", "bytes32"], [_id(collection_id), _fixed(svm_mint, 32, "SVM mint")]
        )

    @staticmethod
    def mint_multi(collection_id: str | bytes, to: str | bytes, token: int | str, amount: int | str) -> bytes:
        n = _tok(amount, "amount")
        if n == 0:
            raise ValueError("amount must be positive")
        return encode_with_selector(
            NFT_SELECTORS["mintMulti"], ["bytes32", "address", "uint256", "uint256"], [_id(collection_id), _to(to), _tok(token), n]
        )

    @staticmethod
    def balance_of_multi(collection_id: str | bytes, owner: str | bytes, token: int | str) -> bytes:
        return encode_with_selector(
            NFT_SELECTORS["balanceOfMulti"], ["bytes32", "address", "uint256"],
            [_id(collection_id), _addr(owner, "owner"), _tok(token)],
        )

    @staticmethod
    def mint_random(collection_id: str | bytes, to: str | bytes, id_space: int | str) -> bytes:
        n = _tok(id_space, "id space")
        if n == 0:
            raise ValueError("id space must be positive")
        return encode_with_selector(NFT_SELECTORS["mintRandom"], ["bytes32", "address", "uint256"], [_id(collection_id), _to(to), n])

    @staticmethod
    def fulfill_random(request_id: str | bytes) -> bytes:
        return encode_with_selector(NFT_SELECTORS["fulfillRandom"], ["bytes32"], [_fixed(request_id, 32, "request id")])


nft_calldata = _Calldata()


@dataclass(frozen=True)
class NftCollection:
    name: str
    symbol: str
    creator: str
    total_supply: int
    standard: NftStandard


def _raw(d: bytes | str) -> bytes:
    if isinstance(d, (bytes, bytearray)):
        return bytes(d)
    return bytes.fromhex(d[2:] if d.startswith("0x") else d)


class _Decode:
    """Decoders for the factory's return data."""

    @staticmethod
    def id(data: bytes | str) -> str:
        """``createCollection`` and ``mintRandom`` return a raw 32-byte id."""
        b = _raw(data)
        if len(b) != 32:
            raise ValueError("expected a 32-byte id")
        return "0x" + b.hex()

    @staticmethod
    def collection(data: bytes | str) -> NftCollection:
        name, symbol, creator, supply, standard = abi_decode(["string", "string", "address", "uint256", "uint8"], _raw(data))
        if standard not in (0, 1):
            raise ValueError(f"unknown NFT standard {standard}")
        return NftCollection(name, symbol, creator, supply, "erc721" if standard == 0 else "erc1155")

    @staticmethod
    def address(data: bytes | str) -> str:
        return abi_decode(["address"], _raw(data))[0]

    @staticmethod
    def uint(data: bytes | str) -> int:
        return abi_decode(["uint256"], _raw(data))[0]

    @staticmethod
    def string(data: bytes | str) -> str:
        return abi_decode(["string"], _raw(data))[0]

    @staticmethod
    def bool(data: bytes | str) -> bool:
        return abi_decode(["bool"], _raw(data))[0]


nft_decode = _Decode()


@dataclass(frozen=True)
class NftTransfer:
    collection_id: str
    from_address: str
    to: str
    token_id: int


def decode_nft_transfer(log: dict[str, Any]) -> NftTransfer | None:
    """Decode an ``NftTransfer`` log (``from`` is the zero address for a mint); ``None`` for any other log."""
    address = log.get("address")
    if address is not None and address.lower() != NFT_FACTORY_ADDRESS:
        return None
    topics = log.get("topics") or []
    if len(topics) != 4 or topics[0].lower() != NFT_TRANSFER_TOPIC:
        return None
    return NftTransfer(
        "0x" + _id(topics[1]).hex(),
        abi_decode(["address"], topics[2])[0],
        abi_decode(["address"], topics[3])[0],
        nft_decode.uint(log["data"]),
    )


def nft_collection_id(creator: str | bytes, nonce: int) -> str:
    """The id ``createCollection`` gives the ``nonce``-th collection of ``creator``: SHA-256(creator ‖ nonce, 8 bytes little-endian)."""
    if not 0 <= nonce < 1 << 64:
        raise ValueError("nonce must fit 64 bits")
    return "0x" + hashlib.sha256(_addr(creator, "creator") + nonce.to_bytes(8, "little")).hexdigest()


def nft_call(calldata: bytes) -> dict[str, Any]:
    """One EVM call of the factory, as a ``ContractCall`` transaction carries it."""
    return {"vm": "evm", "to": list(_addr(NFT_FACTORY_ADDRESS)), "value": 0, "data": list(calldata)}


def nft_transaction(*calldata: bytes) -> TypedTransaction:
    """A ``ContractCall`` transaction running the factory calls in order, all or nothing."""
    if not calldata:
        raise ValueError("a transaction needs at least one call")
    return TypedTransaction(kind="ContractCall", fields={"calls": [nft_call(c) for c in calldata]})


class NftClient:
    """Reads from the factory through ``eth_call``."""

    def __init__(self, rpc: Any) -> None:
        self._rpc = rpc

    def _read(self, data: bytes) -> str:
        return self._rpc.call("eth_call", [{"to": NFT_FACTORY_ADDRESS, "data": "0x" + data.hex()}, "latest"])

    def collection(self, collection_id: str) -> NftCollection:
        return nft_decode.collection(self._read(nft_calldata.get_collection(collection_id)))

    def owner_of(self, collection_id: str, token: int) -> str:
        return nft_decode.address(self._read(nft_calldata.owner_of(collection_id, token)))

    def balance_of(self, collection_id: str, owner: str) -> int:
        return nft_decode.uint(self._read(nft_calldata.balance_of(collection_id, owner)))

    def balance_of_multi(self, collection_id: str, owner: str, token: int) -> int:
        return nft_decode.uint(self._read(nft_calldata.balance_of_multi(collection_id, owner, token)))

    def token_uri(self, collection_id: str, token: int) -> str:
        return nft_decode.string(self._read(nft_calldata.token_uri(collection_id, token)))
